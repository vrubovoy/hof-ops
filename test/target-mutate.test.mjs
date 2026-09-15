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

import { acquireExecutionLease, acquireLock, acquireLockAndJournal, acquireMutex, appendEvent, readCurrentState, readEvents, readGenerationSnapshot, readGenerationSnapshotReleaseLock, readGenerationSnapshotTopology, readJournal, readLock, readTopology, releaseLock, updateJournalStatus, writeJournal } from "../scripts/target-mutate.mjs";

const exec = promisify(execFile);

const FAKE_PUBKEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIKPZsomeFakeButValidBase64Blob==";
const HOST_KEY_SHA256 = "SHA256:" + createHash("sha256").update(Buffer.from(FAKE_PUBKEY_B64, "base64")).digest("base64").replace(/=+$/, "");

const SSH_TARGET = {
  mode: "ssh", host: "target.example", port: 2222, user: "hof",
  hostKeySha256: HOST_KEY_SHA256, identityFile: "/id/key", connectTimeoutSeconds: 5,
};
const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000000";
const EXECUTION_LEASE_PATH_ESCAPED = "/var/lib/hof/state/exec\\.lease";

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

// Like mockRun above, but answers each successive ssh/sudo (mutate)
// round trip with the NEXT entry from `responses`, in order - needed for
// acquireMutex()'s own tests, which make more than one such round trip
// per test (acquire, then assertOwnership()/release() separately) and
// need each one to answer differently. An entry that is an Error is
// thrown instead of returned, simulating a genuine transport failure for
// that one round trip. The last entry repeats for any call beyond the
// end of the list (most tests only care about the calls they explicitly
// scripted).
function mockSequencedRun(responses) {
  const calls = [];
  let index = 0;
  const run = async (command, args, opts) => {
    calls.push({ command, args, input: opts?.input });
    if (command === "ssh-keyscan") {
      return { stdout: `target.example ssh-ed25519 ${FAKE_PUBKEY_B64}\n`, stderr: "" };
    }
    if (command === "ssh" || command === "sudo") {
      const response = responses[Math.min(index, responses.length - 1)];
      index += 1;
      if (response instanceof Error) throw response;
      return { stdout: response, stderr: "" };
    }
    throw new Error(`mockSequencedRun: unexpected command ${command}`);
  };
  return { run, calls, mutateCallCount: () => calls.filter((c) => c.command === "ssh" || c.command === "sudo").length };
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

// PR 2 (item 10) review: updateJournalStatus() used to write via a
// FIXED targetPath.tmp name, with no serialization against a concurrent
// writer at all - the same class of bug acquireLockAndJournalScript()'s
// own mktemp+ln fix already closed for lock/journal CREATION (see that
// function's own comment). Both gaps are closed the same way here:
// a genuinely unique mktemp name (never the fixed old one), and the
// whole write now runs inside the SAME target-side flock guard
// acquireLockAndJournal() itself uses, serializing every journal-status
// update and event append against each other and against lock/journal
// creation.
test("updateJournalStatus: serializes through the same target-side flock guard as acquireLockAndJournal, and never reuses a fixed temp file name", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_UPDATED\n" });
  await updateJournalStatus({ ...SSH_TARGET, run }, journalDoc);
  const script = calls.find((c) => c.command === "ssh").input;
  assert.match(script, /flock -x 9/, "must run inside the same flock guard as lock/journal creation");
  assert.match(script, /tmp=\$\(mktemp /, "must use a genuinely unique tmp name, never a fixed one");
  assert.doesNotMatch(script, /tmp='.*\.tmp'/, "must never reuse the old fixed targetPath.tmp name");
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

// PR 2 (item 10) review: appendEvent() now also serializes through the
// same target-side flock guard as updateJournalStatus()/
// acquireLockAndJournal() - see updateJournalStatus()'s own equivalent
// test for why.
test("appendEvent: serializes through the same target-side flock guard as updateJournalStatus/acquireLockAndJournal", async () => {
  const event = { apiVersion: "hof.dev/operation-event/v1", operationId: OPERATION_ID, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T10:00:00Z" };
  const { run, calls } = mockRun({ sshStdout: "HOF_MUTATE_APPENDED\n" });
  await appendEvent({ ...SSH_TARGET, run }, OPERATION_ID, event);
  const script = calls.find((c) => c.command === "ssh").input;
  assert.match(script, /flock -x 9/);
});

// PR 2 (item 10) review, critical finding 2: updateJournalStatus()/
// appendEvent() used to trust their own caller's cached isLost() check
// alone, with no fencing of their own at all on the target - a real
// TOCTOU gap a client-side check cannot close. Both now take an optional
// leaseToken and, when given, embed a real, target-side, atomic check
// (under the same flock guard) that the owner record still holds
// exactly that token before ever writing - see leaseFencingScript()'s
// own comment.
const LEASE_TOKEN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

test("updateJournalStatus: with a leaseToken, embeds a real target-side fencing check against the owner record before ever writing; without one, the script is unchanged", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  const fenced = mockRun({ sshStdout: "HOF_MUTATE_UPDATED\n" });
  await updateJournalStatus({ ...SSH_TARGET, run: fenced.run }, journalDoc, LEASE_TOKEN);
  const fencedScript = fenced.calls.find((c) => c.command === "ssh").input;
  assert.match(fencedScript, /exec\.lease\.owner/);
  assert.match(fencedScript, new RegExp(`!= '${LEASE_TOKEN}'`));
  assert.match(fencedScript, /HOF_MUTATE_LEASE_MISMATCH/);

  const unfenced = mockRun({ sshStdout: "HOF_MUTATE_UPDATED\n" });
  await updateJournalStatus({ ...SSH_TARGET, run: unfenced.run }, journalDoc);
  const unfencedScript = unfenced.calls.find((c) => c.command === "ssh").input;
  assert.doesNotMatch(unfencedScript, /exec\.lease\.owner/, "omitting leaseToken must leave the write completely unguarded, exactly like before this review");
});

test("updateJournalStatus: a real HOF_MUTATE_LEASE_MISMATCH response is refused with a clear, distinct error - never silently treated as success", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  const { run } = mockRun({ sshStdout: "HOF_MUTATE_LEASE_MISMATCH\n" });
  await assert.rejects(
    () => updateJournalStatus({ ...SSH_TARGET, run }, journalDoc, LEASE_TOKEN),
    /execution lease no longer matches this write's own token/,
  );
});

test("updateJournalStatus: rejects a malformed leaseToken before ever building a script", async () => {
  const journalDoc = { apiVersion: "hof.dev/operation-journal/v1", operationId: OPERATION_ID, status: "succeeded", committedGeneration: 1 };
  await assert.rejects(
    () => updateJournalStatus({ ...SSH_TARGET, run: async () => { throw new Error("must not be called"); } }, journalDoc, "not-a-token; rm -rf /"),
    /is not a valid execution-lease token/,
  );
});

test("appendEvent: with a leaseToken, embeds the same real target-side fencing check; a HOF_MUTATE_LEASE_MISMATCH response is refused with a clear, distinct error", async () => {
  const event = { apiVersion: "hof.dev/operation-event/v1", operationId: OPERATION_ID, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T10:00:00Z" };
  const fenced = mockRun({ sshStdout: "HOF_MUTATE_APPENDED\n" });
  await appendEvent({ ...SSH_TARGET, run: fenced.run }, OPERATION_ID, event, LEASE_TOKEN);
  const fencedScript = fenced.calls.find((c) => c.command === "ssh").input;
  assert.match(fencedScript, /exec\.lease\.owner/);
  assert.match(fencedScript, new RegExp(`!= '${LEASE_TOKEN}'`));

  await assert.rejects(
    () => appendEvent({ ...SSH_TARGET, run: mockRun({ sshStdout: "HOF_MUTATE_LEASE_MISMATCH\n" }).run }, OPERATION_ID, event, LEASE_TOKEN),
    /execution lease no longer matches this write's own token/,
  );
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

// acquireMutex/acquireExecutionLease: PR 2 (item 10) replaced the
// original SSH-heartbeat execution lease (a long-lived local child
// holding flock over a persistent streaming connection - see git
// history for its own three-review-round account of why a bare signal,
// then a bare stdin-EOF, both provably failed against a real target)
// with a target-side, TRANSIENT SYSTEMD UNIT holding the same flock, at
// the same EXECUTION_LEASE_PATH, acquired/checked/released through
// ordinary ONE-SHOT round trips over the shared runScript()/`run` seam -
// no more spawnFn, no more a fake streaming child. acquireExecutionLease
// is a thin compatibility alias apply.mjs keeps calling unchanged; a
// future backup/restore runner (PR 4/5) calls the general acquireMutex
// directly, against the exact same protocol (ADR 0006's own "one
// physical execution mutex across all three kinds").

test("acquireMutex: HOF_LEASE_HELD resolves, and the acquire script's own shape holds a real non-blocking flock via a transient systemd unit", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  assert.equal(lease.isLost(), false);
  const script = calls.find((c) => c.command === "ssh").input;
  assert.match(script, /systemd-run --unit='hof-exec-lease-[0-9a-f-]+' --quiet/);
  assert.match(script, /flock -n -x 9/);
  assert.match(script, new RegExp(EXECUTION_LEASE_PATH_ESCAPED));
  assert.equal(lease.token, script.match(/--unit='hof-exec-lease-([0-9a-f-]+)'/)[1], "the returned lease's own token must be exactly the one embedded in the real acquire script, not a second, independently-generated value");
});

// PR 2 (item 10) review, critical finding 1: `systemctl is-active`
// reporting a unit active does NOT by itself prove its own `flock -n -x`
// actually won - Type=simple/exec both report ActiveState=active the
// instant the process starts, well before the script inside it ever
// reaches its own flock line. Two genuinely concurrent acquisitions
// could both observe "active" during that window and both conclude
// HOF_LEASE_HELD. The fix reads the owner record's own token back
// before ever trusting "active" as proof - this test confirms the
// script the module actually sends does that (real, end-to-end
// contention against a genuine target is test/apply-acceptance.impl.mjs's
// own job, not reproducible against a mocked `run`).
test("acquireMutex: 'active' alone is never trusted as proof of ownership - the acquire script also confirms the owner record holds exactly this acquisition's own token before ever concluding HOF_LEASE_HELD", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n"]);
  await acquireMutex({ ...SSH_TARGET, run });
  const script = calls.find((c) => c.command === "ssh").input;
  // The poll loop's own "active" branch must read the owner record back
  // and compare it against this exact acquisition's own token before
  // ever printing HOF_LEASE_HELD - not merely check systemctl state.
  const activeBranch = script.slice(script.indexOf('"$state" = active'), script.indexOf("HOF_LEASE_HELD"));
  assert.match(activeBranch, /exec\.lease\.owner/, "the active branch must read the owner record, not just trust systemctl's own state");
  assert.match(activeBranch, /owner=\$\(cat/, "must capture the owner record's own current content");
  const token = script.match(/--unit='hof-exec-lease-([0-9a-f-]+)'/)[1];
  assert.match(activeBranch, new RegExp(`"\\$owner" = '${token}'`), "must compare the owner record against exactly this acquisition's own token before concluding HELD");
});

test("acquireMutex: two separate acquisitions embed two genuinely different, unique tokens - never a reused unit name", async () => {
  const first = mockSequencedRun(["HOF_LEASE_HELD\n"]);
  const second = mockSequencedRun(["HOF_LEASE_HELD\n"]);
  await acquireMutex({ ...SSH_TARGET, run: first.run });
  await acquireMutex({ ...SSH_TARGET, run: second.run });
  const unitOf = (calls) => calls.find((c) => c.command === "ssh").input.match(/--unit='(hof-exec-lease-[0-9a-f-]+)'/)[1];
  assert.notEqual(unitOf(first.calls), unitOf(second.calls));
});

test("acquireMutex: HOF_LEASE_BUSY rejects with a clear message naming the execution lease, matching what apply.mjs's own blocked(\"lease\", ...) surfaces", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_BUSY\n"]);
  await assert.rejects(acquireMutex({ ...SSH_TARGET, run }), /already holds the execution lease/);
});

test("acquireMutex: HOF_LEASE_TIMEOUT (the acquire poll never observed active or failed) rejects distinctly from HOF_LEASE_BUSY", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_TIMEOUT\n"]);
  await assert.rejects(acquireMutex({ ...SSH_TARGET, run }), /neither held nor busy/);
});

test("acquireMutex: an unrecognized acquire response is never silently treated as held or busy", async () => {
  const { run } = mockSequencedRun(["SOMETHING_ELSE\n"]);
  await assert.rejects(acquireMutex({ ...SSH_TARGET, run }), /unexpected target-mutate response/);
});

test("acquireMutex: local mode runs the acquire script via `sudo -n sh -s` directly, no SSH/known_hosts machinery", async () => {
  const calls = [];
  const run = async (command, args, opts) => { calls.push({ command, args, input: opts?.input }); return { stdout: "HOF_LEASE_HELD\n", stderr: "" }; };
  await acquireMutex({ mode: "local", run });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "sudo");
  assert.deepEqual(calls[0].args, ["-n", "sh", "-s"]);
});

test("acquireMutex: release() reports the raw HOF_LEASE_RELEASED round trip - stops the unit and clears the owner record, only ever by exact token match (the script itself, never trusted blindly - see its own guard)", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_RELEASED\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.release();
  const releaseScript = calls.filter((c) => c.command === "ssh")[1].input;
  assert.match(releaseScript, /rm -f/);
  assert.match(releaseScript, /systemctl stop/);
  assert.match(releaseScript, /\[ "\$\(cat '.*exec\.lease\.owner'\)" = '.*' \]/);
});

test("acquireMutex: HOF_LEASE_MISMATCH on release (the owner record no longer matches this acquisition's own token) never throws - degrades to best-effort, matching the target-side unit's own eventual self-expiry", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_MISMATCH\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.release(); // must not throw
});

test("acquireMutex: a transport failure while releasing is swallowed, never thrown back at the caller - an unreleased unit still self-expires on its own", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_HELD\n", new Error("ECONNRESET")]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.release(); // must not throw
});

// The heartbeat/assert-ownership operation IS the liveness check - each
// call also re-touches the owner record's own mtime (see acquireMutex()'s
// own comment: a passive read-only check would let the held unit expire
// out from under a caller that dutifully polled isLost() but never
// refreshed liveness on the target). assertOwnership() is called
// directly here rather than waiting out the real background interval.
test("acquireMutex: assertOwnership() touches the owner record and reports HOF_LEASE_OK without marking the lease lost", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_OK\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.assertOwnership();
  assert.equal(lease.isLost(), false);
  const assertScript = calls.filter((c) => c.command === "ssh")[1].input;
  assert.match(assertScript, /touch '.*exec\.lease\.owner'/);
});

test("acquireMutex: assertOwnership() reporting HOF_LEASE_LOST (the unit is gone, or the owner record no longer matches) is recorded and broadcast, fail-closed", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_LOST\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  const observed = [];
  lease.onLost((reason) => observed.push(reason));
  await lease.assertOwnership();
  assert.equal(lease.isLost(), true);
  assert.equal(observed.length, 1);
  assert.equal(observed[0], lease.lostReason());
});

test("acquireMutex: a transport failure DURING assertOwnership() is treated as a lost lease too - never silently ignored, fail-closed even when the target simply stopped answering", async () => {
  const { run } = mockSequencedRun(["HOF_LEASE_HELD\n", new Error("ECONNRESET")]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.assertOwnership();
  assert.equal(lease.isLost(), true);
  assert.match(lease.lostReason(), /ECONNRESET/);
});

test("acquireMutex: a voluntary release() is never mistaken for a loss - assertOwnership() called (e.g. a stray background tick) after release() is a genuine no-op, makes no further round trip, and never fires onLost", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_RELEASED\n"]);
  const lease = await acquireMutex({ ...SSH_TARGET, run });
  await lease.release();
  const observed = [];
  lease.onLost((reason) => observed.push(reason));
  const callsBefore = calls.length;
  await lease.assertOwnership();
  assert.equal(lease.isLost(), false);
  assert.equal(observed.length, 0);
  assert.equal(calls.length, callsBefore, "a released lease's own assertOwnership() must never make another round trip at all");
});

test("acquireExecutionLease: a thin compatibility alias for apply.mjs - identical protocol and shape to acquireMutex", async () => {
  const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n", "HOF_LEASE_RELEASED\n"]);
  const lease = await acquireExecutionLease({ ...SSH_TARGET, run });
  assert.equal(typeof lease.release, "function");
  assert.equal(typeof lease.isLost, "function");
  assert.equal(typeof lease.lostReason, "function");
  assert.equal(typeof lease.onLost, "function");
  assert.equal(typeof lease.assertOwnership, "function");
  await lease.release();
  assert.match(calls.find((c) => c.command === "ssh").input, /systemd-run/);
});

// ADR 0006: "one physical execution mutex across all three kinds" - a
// future backup/restore runner acquires this SAME mutex, at the SAME
// EXECUTION_LEASE_PATH, through this SAME acquireMutex() - there is no
// per-kind lease path or protocol variant to keep in sync. Simulated
// here by simply calling acquireMutex() from what would be three
// different callers (apply.mjs, and PR 4/5's own future backup/restore
// runner) and confirming every one of them produces the exact same
// script shape - the real, target-side contention itself (an apply and
// a concurrent backup both genuinely refusing to run at once) is
// exercised for real against a genuine systemd target by
// test/apply-acceptance.mjs's own acceptance scenario, not reproduced
// here (see this file's own top comment on why real OS/systemd/SSH
// interaction is never faked twice).
test("acquireMutex: apply, backup, and restore all serialize through the exact same shared flock path and unit-naming scheme - one physical mutex, not three", async () => {
  const scripts = [];
  for (let i = 0; i < 3; i += 1) {
    const { run, calls } = mockSequencedRun(["HOF_LEASE_HELD\n"]);
    await acquireMutex({ ...SSH_TARGET, run });
    scripts.push(calls.find((c) => c.command === "ssh").input);
  }
  for (const script of scripts) {
    assert.match(script, new RegExp(EXECUTION_LEASE_PATH_ESCAPED));
    assert.match(script, /hof-exec-lease-/);
  }
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
