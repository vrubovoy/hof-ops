// Fast-suite coverage for target-mutate.mjs's own script-building and
// response-parsing logic, with a mocked `run` (like
// target-inspector.test.mjs's own ssh-mode tests) - real execution
// (a genuine sudo-enabled ephemeral container, real noclobber exclusive
// create, a real atomic rename) is covered separately by
// test/apply-acceptance.mjs (`pnpm test:apply-ssh`), not reproduced
// here. ONE deliberate exception below (the orphaned-hard-link
// regression test): a further, 2026-08-31 review found a real
// filesystem/inode-level corruption path that only a genuine `sh`
// execution against a real scratch directory can actually exercise -
// capture the real script acquireLockAndJournal() would send over SSH
// (via the same mockRun() capture every other test here already uses),
// path-substitute the real /var/lib/hof/state prefix for a scratch
// directory, and run that exact script for real. Never touches the
// real target path, needs no root.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { link, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { acquireExecutionLease, acquireLock, acquireLockAndJournal, appendEvent, readCurrentState, readEvents, readGenerationSnapshot, readGenerationSnapshotReleaseLock, readGenerationSnapshotTopology, readJournal, readLock, readTopology, releaseLock, updateJournalStatus, writeJournal } from "../scripts/target-mutate.mjs";

const exec = promisify(execFile);

const FAKE_PUBKEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIKPZsomeFakeButValidBase64Blob==";
const HOST_KEY_SHA256 = "SHA256:" + createHash("sha256").update(Buffer.from(FAKE_PUBKEY_B64, "base64")).digest("base64").replace(/=+$/, "");

const SSH_TARGET = {
  mode: "ssh", host: "target.example", port: 2222, user: "hof",
  hostKeySha256: HOST_KEY_SHA256, identityFile: "/id/key", connectTimeoutSeconds: 5,
};
const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000000";

// Records every call made through `run`, and answers ssh-keyscan/ssh
// calls according to a small script the test provides.
function mockRun({ sshStdout }) {
  const calls = [];
  const run = async (command, args, opts) => {
    calls.push({ command, args, input: opts?.input });
    if (command === "ssh-keyscan") {
      return { stdout: `target.example ssh-ed25519 ${FAKE_PUBKEY_B64}\n`, stderr: "" };
    }
    if (command === "ssh" || command === "sudo") {
      return { stdout: sshStdout, stderr: "" };
    }
    throw new Error(`mockRun: unexpected command ${command}`);
  };
  return { run, calls };
}

test("acquireLock (ssh): connects with sudo -n sh -s as the remote command, pinned known_hosts, and parses HOF_MUTATE_CREATED", async () => {
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
  const lockDoc = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID };
  const result = await acquireLock({ ...SSH_TARGET, run }, lockDoc);
  assert.deepEqual(result, { acquired: true });

  const sshCall = calls.find((c) => c.command === "ssh");
  assert.ok(sshCall, "ssh was invoked");
  assert.ok(sshCall.args.includes("--"));
  assert.equal(sshCall.args.at(-1), "-s");
  assert.equal(sshCall.args.at(-2), "sh");
  assert.equal(sshCall.args.at(-3), "-n");
  assert.equal(sshCall.args.at(-4), "sudo");
  assert.equal(sshCall.args.at(-5), "hof@target.example");
  assert.ok(sshCall.args.includes("-o"), "carries hardening options");
  assert.match(sshCall.args.join(" "), /UserKnownHostsFile=\/tmp\/hof-mutate-known-hosts-/);
  // The lock document, base64-encoded, is embedded directly in the
  // script sent over stdin - never a second round-trip or a separate
  // channel.
  assert.match(sshCall.input, /payload='[A-Za-z0-9+/=]+'/);
  const embedded = sshCall.input.match(/payload='([A-Za-z0-9+/=]+)'/)[1];
  assert.deepEqual(JSON.parse(Buffer.from(embedded, "base64").toString("utf8")), lockDoc);
});

test("acquireLock (ssh): a real host-key mismatch refuses before any mutation is attempted", async () => {
  const { run } = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
  await assert.rejects(
    () => acquireLock({ ...SSH_TARGET, hostKeySha256: "SHA256:" + "wrong".repeat(9), run }, { operationId: OPERATION_ID }),
    /no host key offered by target\.example:2222 matches the pinned fingerprint/,
  );
});

test("acquireLock: HOF_MUTATE_EXISTS reports the already-held lock document, not just a bare failure", async () => {
  const existing = { apiVersion: "hof.dev/operation-lock/v1", operationId: "11111111-1111-1111-1111-111111111111" };
  const { run } = mockRun({ sshStdout: `HOF_MUTATE_EXISTS\n${JSON.stringify(existing)}` });
  const result = await acquireLock({ ...SSH_TARGET, run }, { operationId: OPERATION_ID });
  assert.deepEqual(result, { acquired: false, lock: existing });
});

// acquireLockAndJournal: creates both the lock AND the journal in ONE
// remote script invocation - a further, 2026-08-31 review found the
// previous two-separate-round-trip sequence (acquireLock, then
// writeJournal) left a real window where a crash of the LOCAL apply.mjs
// process itself (not the SSH session) between the two calls left a
// durable lock with no journal at all, which resume then had nothing to
// do but refuse forever.

test("acquireLockAndJournal: a single ssh call creates both documents, embedding each exactly", async () => {
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
  const lockDoc = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID };
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "in-progress" };
  const result = await acquireLockAndJournal({ ...SSH_TARGET, run }, lockDoc, journalDoc);
  assert.deepEqual(result, { acquired: true });

  const sshCalls = calls.filter((c) => c.command === "ssh");
  assert.equal(sshCalls.length, 1, "lock and journal are created in exactly one remote round trip, not two");
  const script = sshCalls[0].input;
  assert.match(script, /journal\/[0-9a-f-]+\.json/, "the journal's own fixed path is part of the same script");
  const embeddedPayloads = [...script.matchAll(/'([A-Za-z0-9+/=]+)'/g)].map((m) => JSON.parse(Buffer.from(m[1], "base64").toString("utf8")));
  assert.ok(embeddedPayloads.some((p) => JSON.stringify(p) === JSON.stringify(lockDoc)));
  assert.ok(embeddedPayloads.some((p) => JSON.stringify(p) === JSON.stringify(journalDoc)));
});

test("acquireLockAndJournal: an already-held lock reports the existing document, without ever writing a journal", async () => {
  const existing = { apiVersion: "hof.dev/operation-lock/v1", operationId: "11111111-1111-1111-1111-111111111111" };
  const { run } = mockRun({ sshStdout: `HOF_MUTATE_EXISTS\n${JSON.stringify(existing)}` });
  const result = await acquireLockAndJournal({ ...SSH_TARGET, run }, { operationId: OPERATION_ID }, { operationId: OPERATION_ID, status: "in-progress" });
  assert.deepEqual(result, { acquired: false, lock: existing });
});

test("acquireLockAndJournal: a structurally-impossible journal conflict (lock absent, journal already present) throws, never silently succeeds", async () => {
  const { run } = mockRun({ sshStdout: "HOF_MUTATE_JOURNAL_CONFLICT\n" });
  await assert.rejects(
    () => acquireLockAndJournal({ ...SSH_TARGET, run }, { operationId: OPERATION_ID }, { operationId: OPERATION_ID }),
    /structurally impossible/,
  );
});

test("acquireLockAndJournal: an orphaned hard-linked temp file left by a crashed prior attempt never corrupts an already-live lock", async () => {
  // A further, 2026-08-31 review found the fixed `targetPath.tmp` name
  // this used to reuse was itself a real corruption path: if a PRIOR,
  // crashed attempt's own `ln` had already succeeded but its own `rm`
  // never ran (dying in exactly that gap), the fixed tmp name and the
  // real lock.json were left as two hard links to the SAME inode - a
  // LATER attempt's own `printf ... > lock.json.tmp` would then
  // truncate that shared inode, corrupting the already-live lock, even
  // though the later attempt's own `ln` would (correctly) then refuse
  // with EEXIST. Fixed with a genuinely unique `mktemp` name every
  // call, plus an opportunistic cleanup of any orphaned prior one.
  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-lock-atomicity-"));
  try {
    const lockDoc = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID };
    const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "in-progress" };
    const first = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
    await acquireLockAndJournal({ ...SSH_TARGET, run: first.run }, lockDoc, journalDoc);
    const firstScript = first.calls.find((c) => c.command === "ssh").input.replaceAll("/var/lib/hof/state", scratchDir);
    await exec("sh", ["-c", firstScript]);

    const lockPath = path.join(scratchDir, "lock.json");
    assert.equal(await readFile(lockPath, "utf8"), JSON.stringify(lockDoc));

    // Simulate the exact crash state: an orphaned tmp hard-linked to
    // the now-live lock.json (what a crashed prior attempt's own
    // successful `ln`, followed by a death before its own `rm`, would
    // leave behind).
    await link(lockPath, `${lockPath}.aB3xY9`);

    // A brand new attempt, a different operationId - must never corrupt
    // the still-live lock via the shared inode, and must clean the
    // orphan up along the way.
    const lockDoc2 = { apiVersion: "hof.dev/operation-lock/v1", operationId: "22222222-2222-2222-2222-222222222222" };
    const journalDoc2 = { apiVersion: "hof.dev/operation-journal/v1", operationId: "22222222-2222-2222-2222-222222222222", status: "in-progress" };
    const second = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
    await acquireLockAndJournal({ ...SSH_TARGET, run: second.run }, lockDoc2, journalDoc2);
    const secondScript = second.calls.find((c) => c.command === "ssh").input.replaceAll("/var/lib/hof/state", scratchDir);
    await exec("sh", ["-c", secondScript]);

    assert.equal(await readFile(lockPath, "utf8"), JSON.stringify(lockDoc), "the live lock must still be the ORIGINAL operation's own document, never overwritten via the shared-inode orphan");
    const remaining = await readdir(scratchDir);
    assert.ok(!remaining.some((name) => name.startsWith("lock.json.") && name !== "lock.json"), `no stray lock tmp files should remain: ${remaining.join(", ")}`);
  } finally {
    await rm(scratchDir, { recursive: true, force: true });
  }
});

test("readLock: present/unreadable/absent all parse distinctly", async () => {
  const lock = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID };
  const present = await readLock({ ...SSH_TARGET, run: mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(lock)}` }).run });
  assert.deepEqual(present, { status: "present", lock });
  const unreadable = await readLock({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_UNREADABLE\n" }).run });
  assert.deepEqual(unreadable, { status: "unreadable", lock: null });
  const absent = await readLock({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run });
  assert.deepEqual(absent, { status: "absent", lock: null });
});

test("releaseLock: released vs mismatch both parse, never throw for the ordinary mismatch case", async () => {
  const released = await releaseLock({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_RELEASED\n" }).run }, OPERATION_ID);
  assert.deepEqual(released, { released: true });
  const mismatch = await releaseLock({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_MISMATCH\n" }).run }, OPERATION_ID);
  assert.deepEqual(mismatch, { released: false });
});

test("releaseLock: rejects a malformed operationId before ever building a script", async () => {
  await assert.rejects(() => releaseLock({ ...SSH_TARGET, run: async () => { throw new Error("must not be called"); } }, "not-a-uuid; rm -rf /"), /is not a valid operationId/);
});

test("writeJournal: throws a clear error when the target already has a journal for this operationId (never silently overwrites)", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "in-progress" };
  await assert.rejects(
    () => writeJournal({ ...SSH_TARGET, run: mockRun({ sshStdout: `HOF_MUTATE_EXISTS\n${JSON.stringify(journalDoc)}` }).run }, journalDoc),
    /a journal for operation .* already exists on the target - refusing to overwrite/,
  );
});

test("writeJournal: succeeds and embeds the exact document on a fresh create", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "in-progress" };
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_CREATED\n" });
  await writeJournal({ ...SSH_TARGET, run }, journalDoc);
  const sshCall = calls.find((c) => c.command === "ssh");
  assert.match(sshCall.input, new RegExp(`journal/${OPERATION_ID}\\.json`));
});

test("readJournal: parses present/absent", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded" };
  const present = await readJournal({ ...SSH_TARGET, run: mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(journalDoc)}` }).run }, OPERATION_ID);
  assert.deepEqual(present, { status: "present", journal: journalDoc });
  const absent = await readJournal({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, OPERATION_ID);
  assert.deepEqual(absent, { status: "absent", journal: null });
});

test("updateJournalStatus: writes via a temp-file-then-rename script, embedding the full updated document", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_UPDATED\n" });
  await updateJournalStatus({ ...SSH_TARGET, run }, journalDoc);
  const sshCall = calls.find((c) => c.command === "ssh");
  assert.match(sshCall.input, /mv -f "\$tmp"/);
  const embedded = sshCall.input.match(/payload='([A-Za-z0-9+/=]+)'/)[1];
  assert.deepEqual(JSON.parse(Buffer.from(embedded, "base64").toString("utf8")), journalDoc);
});

test("updateJournalStatus: rejects an unexpected response instead of assuming success", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  await assert.rejects(
    () => updateJournalStatus({ ...SSH_TARGET, run: mockRun({ sshStdout: "SOMETHING_ELSE\n" }).run }, journalDoc),
    /unexpected target-mutate response/,
  );
});

test("appendEvent: embeds the event and targets the fixed .events.ndjson path", async () => {
  const event = { apiVersion: "hof.dev/operation-event/v1", operationId: OPERATION_ID, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T10:00:00Z" };
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_APPENDED\n" });
  await appendEvent({ ...SSH_TARGET, run }, OPERATION_ID, event);
  const sshCall = calls.find((c) => c.command === "ssh");
  assert.match(sshCall.input, new RegExp(`journal/${OPERATION_ID}\\.events\\.ndjson`));
  assert.match(sshCall.input, />>/, "appends, never truncates/overwrites");
});

test("readEvents: absent (never appended to yet) returns an empty array, not an error", async () => {
  const events = await readEvents({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, OPERATION_ID);
  assert.deepEqual(events, []);
});

test("readEvents: parses every NDJSON line in order, in the exact recorded shape", async () => {
  const e1 = { apiVersion: "hof.dev/operation-event/v1", operationId: OPERATION_ID, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T10:00:00Z" };
  const e2 = { apiVersion: "hof.dev/operation-event/v1", operationId: OPERATION_ID, step: "001.host.prepare", attempt: 1, phase: "succeeded", at: "2026-08-27T10:00:05Z" };
  const stdout = `HOF_MUTATE_PRESENT\n${JSON.stringify(e1)}\n${JSON.stringify(e2)}\n`;
  const events = await readEvents({ ...SSH_TARGET, run: mockRun({ sshStdout: stdout }).run }, OPERATION_ID);
  assert.deepEqual(events, [e1, e2]);
});

test("readCurrentState: present/absent both parse, targeting the fixed current.json path", async () => {
  const current = { apiVersion: "hof.dev/state/v1", installationId: OPERATION_ID, generation: 1 };
  const { run, calls } = mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(current)}` });
  const present = await readCurrentState({ ...SSH_TARGET, run });
  assert.deepEqual(present, { status: "present", current });
  assert.match(calls.find((c) => c.command === "ssh").input, /\/var\/lib\/hof\/state\/current\.json/);
  const absent = await readCurrentState({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run });
  assert.deepEqual(absent, { status: "absent", current: null });
});

test("readTopology: present/absent both parse, targeting the fixed topology.json path", async () => {
  const topology = { compose: {}, caddyfile: "", topology: {}, backup: {} };
  const { run, calls } = mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(topology)}` });
  const present = await readTopology({ ...SSH_TARGET, run });
  assert.deepEqual(present, { status: "present", topology });
  assert.match(calls.find((c) => c.command === "ssh").input, /\/var\/lib\/hof\/state\/topology\.json/);
  const absent = await readTopology({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run });
  assert.deepEqual(absent, { status: "absent", topology: null });
});

// Item 9 (ADR 0005): readGenerationSnapshot - the state role's own
// immutable per-generation snapshot, zero-padded to 6 digits, the
// SAME path the Ansible state role writes to (see
// ansible/roles/state/tasks/main.yml).
test("readGenerationSnapshot: present/absent both parse, targeting the zero-padded generations/NNNNNN/state.json path", async () => {
  const snapshot = { apiVersion: "hof.dev/state/v1", installationId: OPERATION_ID, generation: 3 };
  const { run, calls } = mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(snapshot)}` });
  const present = await readGenerationSnapshot({ ...SSH_TARGET, run }, 3);
  assert.deepEqual(present, { status: "present", snapshot });
  assert.match(calls.find((c) => c.command === "ssh").input, /\/var\/lib\/hof\/state\/generations\/000003\/state\.json/);
  const absent = await readGenerationSnapshot({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, 3);
  assert.deepEqual(absent, { status: "absent", snapshot: null });
});

test("readGenerationSnapshot: refuses a non-positive-integer generation before ever building a script", async () => {
  await assert.rejects(() => readGenerationSnapshot({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, 0), /positive integer/);
  await assert.rejects(() => readGenerationSnapshot({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, 1.5), /positive integer/);
  await assert.rejects(() => readGenerationSnapshot({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, "3; rm -rf /"), /positive integer/);
});

// Item 9 review fix (finding 8): the same generation snapshot directory's
// other two files - a corrupt/missing topology.json or release-lock.json
// used to pass unnoticed when only state.json was ever confirmed.
test("readGenerationSnapshotTopology/readGenerationSnapshotReleaseLock: present/absent both parse, targeting the same generation directory's other two files", async () => {
  const topology = { compose: { services: {} }, caddyfile: "", topology: {}, backup: {} };
  const { run: topoRun, calls: topoCalls } = mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(topology)}` });
  const presentTopology = await readGenerationSnapshotTopology({ ...SSH_TARGET, run: topoRun }, 3);
  assert.deepEqual(presentTopology, { status: "present", topology });
  assert.match(topoCalls.find((c) => c.command === "ssh").input, /\/var\/lib\/hof\/state\/generations\/000003\/topology\.json/);
  const absentTopology = await readGenerationSnapshotTopology({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, 3);
  assert.deepEqual(absentTopology, { status: "absent", topology: null });

  const releaseLock = { apiVersion: "hof.dev/release-lock/v1", release: "1.0.0" };
  const { run: lockRun, calls: lockCalls } = mockRun({ sshStdout: `HOF_MUTATE_PRESENT\n${JSON.stringify(releaseLock)}` });
  const presentLock = await readGenerationSnapshotReleaseLock({ ...SSH_TARGET, run: lockRun }, 3);
  assert.deepEqual(presentLock, { status: "present", releaseLock });
  assert.match(lockCalls.find((c) => c.command === "ssh").input, /\/var\/lib\/hof\/state\/generations\/000003\/release-lock\.json/);
  const absentLock = await readGenerationSnapshotReleaseLock({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_ABSENT\n" }).run }, 3);
  assert.deepEqual(absentLock, { status: "absent", releaseLock: null });
});

// Item 9 review fix (finding 3): acquireExecutionLease's own shape and
// branching, with a fake, in-memory `spawnFn` (this function talks to a
// long-lived streaming child, not the shared one-shot `run` seam every
// other function here uses - see its own comment on why it takes its own
// seam). The mechanism this was actually redesigned around three times
// over (stdin-EOF release, then a heartbeat with a bounded remote
// timeout, after sudo's own session-isolation of signals and a slow real
// transport teardown were both found live against a genuine sudo-enabled
// sshd target - not something a fake spawn could ever have caught) is
// deliberately NOT re-asserted here; that real behavior is the transport
// layer's job, exercised for real, not mocked twice.
// scriptedStdout is delivered the instant something actually subscribes
// to "data" on stdout, not before - acquireExecutionLease() is async and
// reaches that subscription only after its own await chain (pinning
// known_hosts via a real ssh-keyscan round trip, in ssh mode) resolves,
// so firing eagerly (immediately after calling acquireExecutionLease())
// races that setup and can arrive before anyone is listening - a real
// bug this file's own first draft hit, the response silently lost and
// the test hanging until the runner cancelled it.
// emitExit(code, signal)/emitError(error)/emitStdinError(error) let a
// test drive this fake's own lifecycle AFTER acquisition too (a second
// review's own "post-acquisition lease loss", "stdin error", and
// "confirmation timeout" cases all need the fake child to keep behaving
// like a real one well past the point acquireExecutionLease()'s own
// returned promise has already resolved).
function fakeChild(scriptedStdout) {
  const listeners = { stdout: [], stderr: [], error: [], exit: [] };
  const stdinListeners = { error: [] };
  const child = {
    stdin: {
      written: [], ended: false,
      write(chunk) { this.written.push(chunk); },
      // A real `sh -s` reaching real end-of-input exits on its own too -
      // fired on a microtask (item 9 THIRD review fix: was fully
      // synchronous, which let a call to end() emit "exit" before a
      // listener registered immediately AFTER that same end() call - in
      // particular release()'s own internal `child.once("exit", ...)`,
      // registered the line right after it calls child.stdin.end() -
      // could ever see it, silently falling all the way through to the
      // 5s/3s SIGTERM/SIGKILL fallback below instead. A microtask still
      // never makes a test wait out any real timer (it fires before this
      // same turn's I/O/timer phases run at all), but - like a real
      // process's own genuinely async exit - it fires AFTER the
      // synchronous call to end() has fully returned, so a listener
      // registered by the very next line of caller code (exactly
      // release()'s own pattern) is already in place in time.
      end() { this.ended = true; queueMicrotask(() => child.emitExit(0, null)); },
      on(event, fn) { if (event === "error") stdinListeners.error.push(fn); },
      emitError(error) { for (const fn of stdinListeners.error) fn(error); },
    },
    stdout: {
      on(event, fn) {
        if (event !== "data") return;
        listeners.stdout.push(fn);
        if (scriptedStdout) fn(Buffer.from(scriptedStdout));
      },
      // Lets a test deliver a chunk of its own choosing, at a moment of
      // its own choosing (unlike the constructor's own scriptedStdout,
      // fired once, synchronously, during on() registration itself) -
      // needed to simulate a HOF_LEASE_HELD chunk that was already
      // buffered/in flight, arriving AFTER some other event a test wants
      // to fire first (see the item 9 fourth review's own stdin-error-
      // before-acquisition test below).
      emitStdout(chunk) { for (const fn of listeners.stdout) fn(Buffer.from(chunk)); },
    },
    stderr: { on(event, fn) { if (event === "data") listeners.stderr.push(fn); } },
    on(event, fn) { listeners[event]?.push(fn); },
    once(event, fn) { listeners[event]?.push(fn); },
    // A real kill() eventually produces a real "exit" event too - fired
    // synchronously here for the same reason .end() above is, so a test
    // exercising release()'s own SIGTERM/SIGKILL fallback (a child that
    // never exits any other way) never has to wait out a real timer.
    kill(signal) { if (child.exitCode === null && child.signalCode === null) child.emitExit(null, signal ?? "SIGTERM"); },
    exitCode: null, signalCode: null,
    emitExit(code, signal) {
      if (child.exitCode !== null || child.signalCode !== null) return; // a real process only ever exits once
      child.exitCode = code;
      child.signalCode = signal ?? null;
      for (const fn of listeners.exit) fn(code, signal ?? null);
    },
    emitError(error) { for (const fn of listeners.error) fn(error); },
  };
  return child;
}

test("acquireExecutionLease: HOF_LEASE_HELD resolves with a release() that ends the child's own stdin (never a signal - see this function's own comment on why a signal alone is not trustworthy under sudo)", async () => {
  let spawnedArgs;
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = (command, args) => { spawnedArgs = { command, args }; return child; };
  const { run } = mockRun({ sshStdout: "" }); // only ssh-keyscan is ever routed through run() here - the long-lived child goes through spawnFn
  const { release } = await acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn);
  assert.equal(spawnedArgs.command, "ssh");
  assert.ok(spawnedArgs.args.includes("sudo") && spawnedArgs.args.includes("sh") && spawnedArgs.args.includes("-s"));
  assert.match(child.stdin.written.join(""), /flock -n -x 9/);
  assert.equal(child.stdin.ended, false, "stdin is deliberately left open while the lease is held");
  // The fake child never exits on its own, so release()'s own internal
  // wait-for-exit would otherwise hang for its full fallback timeout -
  // racing it against a short timer is enough to confirm the one thing
  // this test cares about: release() ends stdin immediately, well before
  // any fallback signal.
  await Promise.race([release(), new Promise((resolve) => setTimeout(resolve, 50))]);
  assert.equal(child.stdin.ended, true, "release() ends stdin");
});

test("acquireExecutionLease: HOF_LEASE_BUSY rejects with a clear message and releases (ends stdin) rather than leaving the busy child dangling", async () => {
  const child = fakeChild("HOF_LEASE_BUSY\n");
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  await assert.rejects(acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn), /already holds the execution lease/);
  assert.equal(child.stdin.ended, true, "the busy branch's own release still ends stdin, even though the remote side already exited on its own");
});

test("acquireExecutionLease: local mode runs `sudo -n sh -s` directly, no SSH/known_hosts machinery", async () => {
  let spawnedArgs;
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = (command, args) => { spawnedArgs = { command, args }; return child; };
  await acquireExecutionLease({ mode: "local" }, spawnFn);
  assert.deepEqual(spawnedArgs, { command: "sudo", args: ["-n", "sh", "-s"] });
});

// A second review found the original version of this function fail-OPEN
// after acquisition: HOF_LEASE_HELD resolved the promise, `settled`
// latched true, and the SAME child's own later exit/error - a genuine
// loss of the lease - was silently discarded by the guard built only to
// stop the acquisition promise settling twice. Fixed: isLost()/
// lostReason()/onLost() surface exactly that, for a caller (apply.mjs's
// own dispatch loop) to check before every further mutation.
test("acquireExecutionLease: a lease loss discovered AFTER acquisition (the child exits unexpectedly, never through release()) is recorded and broadcast, not silently discarded", async () => {
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  const lease = await acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn);
  assert.equal(lease.isLost(), false, "not lost immediately after a clean acquisition");

  const observed = [];
  lease.onLost((reason) => observed.push(reason));
  child.emitExit(1, null); // the remote helper died on its own - never released
  assert.equal(lease.isLost(), true);
  assert.match(lease.lostReason(), /exited unexpectedly/);
  assert.equal(observed.length, 1);
  assert.equal(observed[0], lease.lostReason());
});

test("acquireExecutionLease: a lease loss discovered via a child-level error event (not just exit) is recorded the same way", async () => {
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  const lease = await acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn);
  child.emitError(new Error("ECONNRESET"));
  assert.equal(lease.isLost(), true);
  assert.match(lease.lostReason(), /ECONNRESET/);
});

test("acquireExecutionLease: release() is never mistaken for an unexpected loss - the exit release() itself triggers must not call onLost", async () => {
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  const lease = await acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn);
  const observed = [];
  lease.onLost((reason) => observed.push(reason));
  // release() itself ends stdin, which this fake treats as a real clean
  // shutdown and fires a real "exit" event for, same as a real `sh -s`
  // reaching end-of-input would - exactly the exit release() itself
  // must never mistake for an unexpected loss.
  await lease.release();
  assert.equal(lease.isLost(), false, "a voluntary release is never reported as a loss");
  assert.equal(observed.length, 0);
});

// A second review found child.stdin.write(".") inside the heartbeat's
// own try/catch could not actually catch an EPIPE - a write failure on
// a stream surfaces asynchronously as an 'error' EVENT on that stream,
// never a thrown exception from .write() itself, so an unhandled one
// there was free to crash the whole process.
test("acquireExecutionLease: an error event on the child's own stdin is handled, never left to crash the process, and stops release() from double-ending it", async () => {
  const child = fakeChild("HOF_LEASE_HELD\n");
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  const lease = await acquireExecutionLease({ ...SSH_TARGET, run }, spawnFn);
  child.stdin.emitError(new Error("EPIPE")); // must not throw, must not crash the process
  // release() itself is deliberately NOT awaited here - once stdin has
  // already errored, it can no longer end cleanly, so release() falls
  // through to its own real SIGTERM/SIGKILL fallback timers (seconds,
  // by design - a genuine grace period for a real remote process, not
  // shortened for this test's own convenience). What this test actually
  // checks is synchronous: the decision to skip a second .end() on an
  // already-errored stream is made before release()'s own first await.
  void lease.release();
  assert.equal(child.stdin.ended, false, "once stdin has already errored, release() never calls .end() on it again");
});

// Item 9 FOURTH review fix (finding 1): a further review found a stdin
// error arriving BEFORE acquisition is confirmed used to only call
// markLost() - recording a loss, but never claiming or rejecting the
// still-open acquisition promise itself. A HOF_LEASE_HELD chunk that was
// already buffered/in flight could then still arrive right after, win
// claim() in the stdout handler (never yet claimed by anything), and
// resolve successfully - handing the caller a lease whose very first
// isLost() check already reports true. `mode: "local"` is used
// specifically because it has no `await` at all before the child is
// spawned and every listener registered (unlike ssh mode's own
// `await pinnedKnownHosts()`), so the two synchronous calls below land on
// listeners that are already in place, in the exact order this test
// writes them - deterministically reproducing the race rather than
// hoping to catch it.
// Item 9 FIFTH review fix (finding 2): a further review found the
// previous version of this test asserted only /stdin error/ - a bare
// substring match, present in BOTH the specific claim()-based handler
// fix this test means to isolate AND the separate, more general
// post-`await acquirePromise` safety net (see acquireExecutionLease()'s
// own comment on why that second layer exists) - that safety net's own
// message is `execution lease resolved already lost (${lostReason()})
// - ...`, and lostReason() itself is the exact same "stdin error..."
// string, so it ALSO satisfies a bare /stdin error/ match. Removing only
// the claim()-based handler fix left this test green, silently testing
// the safety net instead of the mechanism it claims to. Anchored to the
// START of the message instead: the handler-level rejection's own
// message begins with "stdin error..." directly; the safety net's own
// message begins with "execution lease resolved already lost (..." -
// only the specific fix this test names produces the former.
test("acquireExecutionLease: a stdin error arriving BEFORE acquisition is confirmed rejects acquisition outright, even when a buffered HOF_LEASE_HELD chunk arrives right after (item 9 fourth review, finding 1)", async () => {
  const child = fakeChild(); // no scripted stdout - acquisition is still genuinely pending
  const spawnFn = () => child;
  const acquiring = acquireExecutionLease({ mode: "local" }, spawnFn);
  child.stdin.emitError(new Error("EPIPE")); // arrives first, before any HELD/BUSY
  child.stdout.emitStdout("HOF_LEASE_HELD\n"); // a chunk that was already in flight, arriving right after
  // A custom validator function (never a bare RegExp) - assert.rejects()
  // tests a RegExp against String(error) ("Error: <message>"), which a
  // `^`-anchored pattern can never match past the "Error: " prefix.
  // error.message itself is checked directly here instead, with
  // .startsWith() rather than another regex, for the same reason.
  await assert.rejects(
    acquiring,
    (error) => error instanceof Error && error.message.startsWith("stdin error on the execution-lease helper's own connection:"),
    "the stdin error alone must decide this acquisition, via the handler-level claim()+reject fix specifically - not merely end up rejected some OTHER way (e.g. only the separate post-await safety net) - a HOF_LEASE_HELD arriving after it must never be allowed to win",
  );
});

// A second review found no bound at all on how long acquisition itself
// may take - a hung connection (no HOF_LEASE_HELD/BUSY, no exit, no
// error) left this function awaiting forever.
test("acquireExecutionLease: a hung acquisition (neither HELD nor BUSY nor exit/error ever arrives) is bounded by executionLeaseAcquireTimeoutMs, never awaited forever", async () => {
  const child = fakeChild(); // no scripted stdout at all - genuinely hangs
  const spawnFn = () => child;
  const { run } = mockRun({ sshStdout: "" });
  const startedAt = Date.now();
  // Bounded, not a specific wording: the timeout firing races the
  // release() it itself triggers (which, once stdin ends, this fake
  // treats as a real exit) - either "neither held nor busy" (the
  // timeout's own message winning) or "exited before the lease was
  // confirmed" (the resulting exit event winning instead) is a
  // genuinely correct outcome of the SAME real property this test
  // actually cares about: acquisition gave up, on its own, near the
  // configured bound, rather than hanging forever.
  await assert.rejects(acquireExecutionLease({ ...SSH_TARGET, run, executionLeaseAcquireTimeoutMs: 20 }, spawnFn));
  assert.ok(Date.now() - startedAt < 2000, "must give up near the configured bound, not hang for a real, unbounded amount of time");
});

test("local mode: runs `sudo -n sh -s` directly, with no SSH/known_hosts machinery at all", async () => {
  const calls = [];
  const run = async (command, args, opts) => {
    calls.push({ command, args, input: opts?.input });
    return { stdout: "HOF_MUTATE_ABSENT\n", stderr: "" };
  };
  await readLock({ mode: "local", run });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "sudo");
  assert.deepEqual(calls[0].args, ["-n", "sh", "-s"]);
});
