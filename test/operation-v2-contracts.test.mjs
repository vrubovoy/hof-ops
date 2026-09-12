// Schema-level coverage for the generic, kind-aware operation-lock-v2 /
// operation-journal-v2 contracts ADR 0006 introduces - no real executor
// exists yet (that's a later PR in this item's own sequence), so every
// fixture here is hand-built, mirroring test/apply-contracts.test.mjs's
// own pattern for operation-lock-v1/operation-journal-v1. The one piece
// of genuinely new cross-cutting logic these two schemas add over their
// v1 predecessors is the operationKind x status x committedGeneration
// conditional matrix - that's this file's own centerpiece.

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

// --- operation-lock-v2 --------------------------------------------------

function lockFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-lock/v2",
    operationKind: "apply",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    acquiredAt: "2026-09-04T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
    ...overrides,
  };
}

test("operation-lock-v2: an apply lock validates", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.ok(validate(lockFixture()), JSON.stringify(validate.errors));
});

test("operation-lock-v2: a backup lock validates", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.ok(validate(lockFixture({ operationKind: "backup" })), JSON.stringify(validate.errors));
});

test("operation-lock-v2: a restore lock validates", async () => {
  const validate = await validatorFor("operation-lock-v2.schema.json");
  assert.ok(validate(lockFixture({ operationKind: "restore" })), JSON.stringify(validate.errors));
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

// --- operation-journal-v2 -------------------------------------------------

function journalFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-journal/v2",
    operationKind: "apply",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    plan: { apiVersion: "hof.dev/plan/v2", planId: PLAN_ID },
    inputDigests: {
      manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
      catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
      executionEnvironmentDigest: "sha256:" + "5".repeat(64),
    },
    startedAt: "2026-09-04T10:00:00Z",
    status: "in-progress",
    committedGeneration: null,
    ...overrides,
  };
}

test("operation-journal-v2: an in-progress journal (any kind) validates with committedGeneration null", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  for (const operationKind of ["apply", "backup", "restore"]) {
    assert.ok(validate(journalFixture({ operationKind })), `${operationKind}: ${JSON.stringify(validate.errors)}`);
  }
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

// The centerpiece: operationKind x status x committedGeneration.

test("operation-journal-v2: a succeeded APPLY journal requires a real committed generation, exactly like v1", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  assert.ok(validate(journalFixture({ operationKind: "apply", status: "succeeded", committedGeneration: 3 })), JSON.stringify(validate.errors));
  assert.equal(validate(journalFixture({ operationKind: "apply", status: "succeeded", committedGeneration: null })), false, "apply succeeded with no committed generation must be rejected");
});

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
  for (const operationKind of ["apply", "backup", "restore"]) {
    for (const status of ["in-progress", "failed"]) {
      assert.equal(validate(journalFixture({ operationKind, status, committedGeneration: 1 })), false, `${operationKind}/${status} with a committed generation must be rejected`);
      assert.ok(validate(journalFixture({ operationKind, status, committedGeneration: null })), `${operationKind}/${status} with null: ${JSON.stringify(validate.errors)}`);
    }
  }
});

test("operation-journal-v2: rejects a secret value smuggled into inputDigests", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const journal = journalFixture();
  journal.inputDigests.secretsSopsAgeKey = "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP";
  assert.equal(validate(journal), false);
});

test("operation-journal-v2: rejects a missing input digest", async () => {
  const validate = await validatorFor("operation-journal-v2.schema.json");
  const journal = journalFixture();
  delete journal.inputDigests.executionEnvironmentDigest;
  assert.equal(validate(journal), false);
});
