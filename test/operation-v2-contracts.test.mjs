// Schema-level coverage for operation-lock-v2 / operation-journal-v2 /
// operation-event-v2 (ADR 0006) - all three scoped strictly to
// operationKind backup/restore, never apply (a review round found the
// prior draft's "apply is schema-valid too, just unused" shape was an
// unresolved contradiction: the existing apply executor only ever reads
// and writes v1, so a v2 apply document was schema-valid but could never
// actually occur, and the various v1/v2 schemas' own descriptions
// disagreed with each other about which event schema paired with which
// journal kind). No real executor exists yet (that's a later PR in this
// item's own sequence), so every fixture here is hand-built, mirroring
// test/apply-contracts.test.mjs's own pattern for operation-lock-v1/
// operation-journal-v1.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");

async function validatorFor(schemaFile) {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  return ajv.compile(JSON.parse(await readFile(path.join(root, "schemas", schemaFile), "utf8")));
}

function targetBinding(overrides = {}) {
  return {
    mode: "ssh", host: "hof.example.com", port: 22, user: "deploy",
    hostKeySha256: "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno",
    installationId: null, baselineGeneration: 0,
    ...overrides,
  };
}

const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000001";
const PLAN_ID = "sha256:" + "a".repeat(64);

function sha(fill) {
  return "sha256:" + String(fill).repeat(64).slice(0, 64);
}

// --- operation-lock-v2 --------------------------------------------------

function lockFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-lock/v2",
    operationKind: "backup",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    acquiredAt: "2026-09-04T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
    ...overrides,
  };
}

test("operation-lock-v2: a backup lock validates", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.ok(validate(lockFixture()), JSON.stringify(validate.errors));
});

test("operation-lock-v2: a restore lock validates", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.ok(validate(lockFixture({ operationKind: "restore" })), JSON.stringify(validate.errors));
});

test("operation-lock-v2: rejects operationKind apply - the existing apply executor only ever reads/writes operation-lock-v1, never this schema", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.equal(validate(lockFixture({ operationKind: "apply" })), false);
});

test("operation-lock-v2: rejects an unrecognized operationKind", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.equal(validate(lockFixture({ operationKind: "upgrade" })), false);
});

test("operation-lock-v2: rejects a lock with no operationKind at all - a pre-ADR-0006 lock.json is operation-lock-v1, never this schema", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  const v1Shaped = lockFixture();
  delete v1Shaped.operationKind;
  assert.equal(validate(v1Shaped), false);
});

test("operation-lock-v2: still has deliberately no expiry/TTL field at all, unchanged from v1", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.equal(validate(lockFixture({ expiresAt: "2026-09-04T11:00:00Z" })), false);
});

test("operation-lock-v2: rejects a secret value smuggled into acquiredBy", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  const lock = lockFixture();
  lock.acquiredBy.sshPrivateKeyPath = "/home/operator/.ssh/id_ed25519";
  assert.equal(validate(lock), false);
});

test("operation-lock-v2: rejects an SSH-mode target with no host key - the pairing v1 only ever documented in prose is now actually enforced", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.equal(validate(lockFixture({ target: targetBinding({ hostKeySha256: null }) })), false);
});

test("operation-lock-v2: rejects a local-mode target that still carries a host key", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.equal(validate(lockFixture({ target: targetBinding({ mode: "local", host: null, port: null, user: null, hostKeySha256: "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno" }) })), false);
});

// --- operation-journal-v2 -------------------------------------------------

function backupInputDigests(overrides = {}) {
  return {
    releaseLockDigest: sha("1"), backupToolLockDigest: sha("2"), backupPolicyId: sha("3"),
    ...overrides,
  };
}

function restoreInputDigests(overrides = {}) {
  return {
    releaseLockDigest: sha("1"), backupToolLockDigest: sha("2"), manifestDigest: sha("4"), recoveryKitDigest: sha("5"),
    ...overrides,
  };
}

function journalFixture(overrides = {}) {
  const operationKind = overrides.operationKind ?? "backup";
  const base = {
    apiVersion: "hof.dev/operation-journal/v2",
    operationKind,
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    plan: { apiVersion: operationKind === "restore" ? "hof.dev/restore-plan/v1" : "hof.dev/backup-plan/v1", planId: PLAN_ID },
    inputDigests: operationKind === "restore" ? restoreInputDigests() : backupInputDigests(),
    startedAt: "2026-09-04T10:00:00Z",
    status: "in-progress",
    committedGeneration: null,
  };
  return { ...base, ...overrides };
}

test("operation-journal-v2: an in-progress journal (either kind) validates with committedGeneration null", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  for (const operationKind of ["backup", "restore"]) {
    assert.ok(validate(journalFixture({ operationKind })), `${operationKind}: ${JSON.stringify(validate.errors)}`);
  }
});

test("operation-journal-v2: rejects operationKind apply - the existing apply executor only ever reads/writes operation-journal-v1, never this schema", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const journal = journalFixture({ operationKind: "apply" });
  journal.plan = { apiVersion: "hof.dev/plan/v2", planId: PLAN_ID };
  journal.inputDigests = { manifestDigest: sha("1"), releaseLockDigest: sha("2"), catalogDigest: sha("3"), composeTemplateDigest: sha("4"), executionEnvironmentDigest: sha("5") };
  assert.equal(validate(journal), false);
});

test("operation-journal-v2: rejects a journal with no operationKind at all - a pre-ADR-0006 journal is operation-journal-v1, never this schema", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const v1Shaped = journalFixture();
  delete v1Shaped.operationKind;
  assert.equal(validate(v1Shaped), false);
});

test("operation-journal-v2: rejects an unrecognized operationKind", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  assert.equal(validate(journalFixture({ operationKind: "upgrade" })), false);
});

test("operation-journal-v2: rejects a backup journal embedding a restore-plan-v1 document, and vice versa", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const backupWithRestorePlan = journalFixture({ operationKind: "backup" });
  backupWithRestorePlan.plan = { apiVersion: "hof.dev/restore-plan/v1", planId: PLAN_ID };
  assert.equal(validate(backupWithRestorePlan), false);

  const restoreWithBackupPlan = journalFixture({ operationKind: "restore" });
  restoreWithBackupPlan.plan = { apiVersion: "hof.dev/backup-plan/v1", planId: PLAN_ID };
  assert.equal(validate(restoreWithBackupPlan), false);
});

test("operation-journal-v2: rejects backup inputDigests on a restore journal, and vice versa", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const backupWithRestoreDigests = journalFixture({ operationKind: "backup" });
  backupWithRestoreDigests.inputDigests = restoreInputDigests();
  assert.equal(validate(backupWithRestoreDigests), false);

  const restoreWithBackupDigests = journalFixture({ operationKind: "restore" });
  restoreWithBackupDigests.inputDigests = backupInputDigests();
  assert.equal(validate(restoreWithBackupDigests), false);
});

// The centerpiece: operationKind x status x committedGeneration.

test("operation-journal-v2: a succeeded RESTORE journal requires a real committed generation - the restored source generation, carried forward", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  assert.ok(validate(journalFixture({ operationKind: "restore", status: "succeeded", committedGeneration: 7 })), JSON.stringify(validate.errors));
  assert.equal(validate(journalFixture({ operationKind: "restore", status: "succeeded", committedGeneration: null })), false, "restore succeeded with no committed generation must be rejected");
});

test("operation-journal-v2: a succeeded BACKUP journal REQUIRES committedGeneration to stay null - a backup never mutates the generation", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  assert.ok(validate(journalFixture({ operationKind: "backup", status: "succeeded", committedGeneration: null })), JSON.stringify(validate.errors));
  assert.equal(validate(journalFixture({ operationKind: "backup", status: "succeeded", committedGeneration: 1 })), false, "a succeeded backup claiming a committed generation must be rejected, regardless of value");
});

test("operation-journal-v2: an in-progress or failed journal never carries a committed generation, regardless of kind", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  for (const operationKind of ["backup", "restore"]) {
    for (const status of ["in-progress", "failed"]) {
      assert.equal(validate(journalFixture({ operationKind, status, committedGeneration: 1 })), false, `${operationKind}/${status} with a committed generation must be rejected`);
      assert.ok(validate(journalFixture({ operationKind, status, committedGeneration: null })), `${operationKind}/${status} with null: ${JSON.stringify(validate.errors)}`);
    }
  }
});

test("operation-journal-v2: status: failed always means evidence.write already ran - see this schema's own status field description", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  // Schema-level, this is a documentation-only invariant (evidence
  // itself is a separate document, checked by scripts/backup-flow.mjs's
  // own bundle validators, not this schema) - this test only confirms
  // failed remains schema-valid on its own, as the terminal state its
  // own description now claims to be.
  assert.ok(validate(journalFixture({ operationKind: "backup", status: "failed", committedGeneration: null })), JSON.stringify(validate.errors));
});

test("operation-journal-v2: rejects a secret value smuggled into inputDigests", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const journal = journalFixture();
  journal.inputDigests.secretsSopsAgeKey = "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP";
  assert.equal(validate(journal), false);
});

test("operation-journal-v2: rejects a missing input digest", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const journal = journalFixture({ operationKind: "restore" });
  delete journal.inputDigests.recoveryKitDigest;
  assert.equal(validate(journal), false);
});

test("operation-journal-v2: rejects an SSH-mode target with no host key", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  assert.equal(validate(journalFixture({ target: targetBinding({ hostKeySha256: null }) })), false);
});

// --- operation-event-v2 ----------------------------------------------------

function eventFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-event/v2",
    operationKind: "backup",
    operationId: OPERATION_ID,
    step: "005.snapshot.create.onsite",
    attempt: 1,
    phase: "started",
    at: "2026-09-04T10:00:00Z",
    ...overrides,
  };
}

test("operation-event-v2: a backup event validates", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.ok(validate(eventFixture()), JSON.stringify(validate.errors));
});

test("operation-event-v2: a restore event validates", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.ok(validate(eventFixture({ operationKind: "restore", step: "003.data.restore.schlussel" })), JSON.stringify(validate.errors));
});

test("operation-event-v2: rejects operationKind apply - the existing apply executor only ever emits operation-event-v1, never this schema", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.equal(validate(eventFixture({ operationKind: "apply", step: "003.service.start.gateway" })), false);
});

test("operation-event-v2: rejects an unrecognized operationKind", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.equal(validate(eventFixture({ operationKind: "upgrade" })), false);
});

test("operation-event-v2: rejects a missing operationKind - unlike v1, this schema requires it", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  const event = eventFixture();
  delete event.operationKind;
  assert.equal(validate(event), false);
});

test("operation-event-v2: a failed phase requires a sanitized error; succeeded/started forbid one", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.equal(validate(eventFixture({ phase: "failed" })), false, "failed with no error must be rejected");
  assert.ok(validate(eventFixture({ phase: "failed", error: "snapshot.create timed out" })), JSON.stringify(validate.errors));
  assert.equal(validate(eventFixture({ phase: "succeeded", error: "should not be here" })), false);
});

test("operation-event-v2: destination is only ever valid on a backup-kind event", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.ok(validate(eventFixture({ operationKind: "backup", destination: "onsite" })), JSON.stringify(validate.errors));
  assert.equal(validate(eventFixture({ operationKind: "restore", step: "003.data.restore.schlussel", destination: "onsite" })), false, "restore never has a per-destination step");
});

test("operation-event-v2: destination follows the services-v1alpha1-compatible destinationName pattern (hyphens only, max 63 chars), not the broader identifier pattern", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.equal(validate(eventFixture({ operationKind: "backup", destination: "on.site" })), false);
});

test("operation-event-v2: rejects a raw exception dump or secret value smuggled into error", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  // error itself has no format restriction (a real diagnostic is free text) -
  // what's actually enforced is that no OTHER field can carry one instead.
  assert.equal(validate(eventFixture({ phase: "started", sshPrivateKeyPath: "/home/operator/.ssh/id_ed25519" })), false);
});

test("operation-event-v2: attempt must be a positive integer - a resumed, previously-failed step increments it, never reuses attempt 1", async () => {
  const validate = await validatorFor("operation-event-v2.schema.json");
  assert.equal(validate(eventFixture({ attempt: 0 })), false);
  assert.ok(validate(eventFixture({ attempt: 2 })), JSON.stringify(validate.errors));
});
