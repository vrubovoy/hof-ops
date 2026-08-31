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

import { acquireLock, acquireLockAndJournal, appendEvent, readCurrentState, readEvents, readJournal, readLock, readTopology, releaseLock, updateJournalStatus, writeJournal } from "../scripts/target-mutate.mjs";

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
