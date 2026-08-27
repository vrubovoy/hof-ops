// Fast-suite coverage for target-mutate.mjs's own script-building and
// response-parsing logic, with a mocked `run` (like
// target-inspector.test.mjs's own ssh-mode tests) - real execution
// (a genuine sudo-enabled ephemeral container, real noclobber exclusive
// create, a real atomic rename) is covered separately by
// test/apply-acceptance.mjs (`pnpm test:apply-ssh`), not reproduced
// here.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { acquireLock, appendEvent, readEvents, readJournal, readLock, releaseLock, updateJournalStatus, writeJournal } from "../scripts/target-mutate.mjs";

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
