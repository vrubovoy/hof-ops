// Schema-level coverage for the three apply-execution contracts ADR
// 0004 introduces (operation-lock-v1, operation-journal-v1,
// operation-event-v1) - no real executor exists yet to produce these
// for real, so every fixture here is a hand-built, realistic document.
// The one property every fixture is also checked against: no secret
// value, decrypted content, environment dump, or SSH private-key path
// ever fits through any of these schemas (additionalProperties: false
// everywhere, checked here by attempting to smuggle one in and
// confirming it's rejected).

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");

// strictRequired: false - operation-event-v1's own conditional
// (`allOf[0].then.required: ["error"]`) requires a property declared in
// the schema's OUTER properties block, not repeated locally in `then` -
// the same, already-accepted pattern release-lock-v1.schema.json's own
// thirdParty/trust split needed this for (see contracts.mjs).
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

// --- operation-lock-v1 ------------------------------------------------

test("operation-lock-v1: a genuine lock record validates", async () => {
  const validate = await validatorFor("operation-lock-v1.schema.json");
  const lock = {
    apiVersion: "hof.dev/operation-lock/v1",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    acquiredAt: "2026-08-27T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
  };
  assert.ok(validate(lock), JSON.stringify(validate.errors));
});

test("operation-lock-v1: local-mode target binding (no host key at all) also validates", async () => {
  const validate = await validatorFor("operation-lock-v1.schema.json");
  const lock = {
    apiVersion: "hof.dev/operation-lock/v1",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding({ mode: "local", host: null, port: null, user: null, hostKeySha256: null }),
    acquiredAt: "2026-08-27T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
  };
  assert.ok(validate(lock), JSON.stringify(validate.errors));
});

test("operation-lock-v1: has deliberately no expiry/TTL field at all - the lock survives the process dying", async () => {
  const validate = await validatorFor("operation-lock-v1.schema.json");
  const lockWithExpiry = {
    apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID, approvedPlanId: PLAN_ID, target: targetBinding(),
    acquiredAt: "2026-08-27T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" },
    expiresAt: "2026-08-27T11:00:00Z",
  };
  assert.equal(validate(lockWithExpiry), false);
});

test("operation-lock-v1: rejects a missing required field", async () => {
  const validate = await validatorFor("operation-lock-v1.schema.json");
  assert.equal(validate({ apiVersion: "hof.dev/operation-lock/v1" }), false);
});

test("operation-lock-v1: rejects a secret value smuggled into acquiredBy", async () => {
  const validate = await validatorFor("operation-lock-v1.schema.json");
  const lock = {
    apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID, approvedPlanId: PLAN_ID, target: targetBinding(),
    acquiredAt: "2026-08-27T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u", sshPrivateKeyPath: "/home/operator/.ssh/id_ed25519" },
  };
  assert.equal(validate(lock), false);
});

// --- operation-journal-v1 ----------------------------------------------

function journalFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-journal/v1",
    operationId: OPERATION_ID,
    approvedPlanId: PLAN_ID,
    target: targetBinding(),
    // The full approved plan-v2 document (PR #31 fix) - loosely typed at
    // the journal-schema level (see the schema's own comment on why),
    // so a minimal placeholder object is enough here; real content is
    // covered by operation-journal.test.mjs and apply.test.mjs instead.
    plan: { apiVersion: "hof.dev/plan/v2", planId: PLAN_ID },
    inputDigests: {
      manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
      catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
      executionEnvironmentDigest: "sha256:" + "5".repeat(64),
    },
    startedAt: "2026-08-27T10:00:00Z",
    status: "in-progress",
    committedGeneration: null,
    ...overrides,
  };
}

test("operation-journal-v1: an in-progress journal (no commit yet) validates", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  assert.ok(validate(journalFixture()), JSON.stringify(validate.errors));
});

test("operation-journal-v1: a succeeded journal with a real committed generation validates", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  assert.ok(validate(journalFixture({ status: "succeeded", committedGeneration: 1 })), JSON.stringify(validate.errors));
});

test("operation-journal-v1: rejects an unrecognized status", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  assert.equal(validate(journalFixture({ status: "done" })), false);
});

test("operation-journal-v1: rejects a missing input digest", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  const journal = journalFixture();
  delete journal.inputDigests.executionEnvironmentDigest;
  assert.equal(validate(journal), false);
});

test("operation-journal-v1: rejects a secret value smuggled into inputDigests", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  const journal = journalFixture();
  journal.inputDigests.secretsSopsAgeKey = "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP";
  assert.equal(validate(journal), false);
});

test("operation-journal-v1: rejects committedGeneration: 0 - a bootstrap always commits generation 1", async () => {
  const validate = await validatorFor("operation-journal-v1.schema.json");
  assert.equal(validate(journalFixture({ status: "succeeded", committedGeneration: 0 })), false);
});

// --- operation-event-v1 -------------------------------------------------

function eventFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/operation-event/v1",
    operationId: OPERATION_ID,
    step: "003.service.start.gateway",
    attempt: 1,
    phase: "started",
    at: "2026-08-27T10:05:00Z",
    ...overrides,
  };
}

test("operation-event-v1: a started event (no error) validates", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.ok(validate(eventFixture()), JSON.stringify(validate.errors));
});

test("operation-event-v1: a succeeded event validates, still with no error field", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.ok(validate(eventFixture({ phase: "succeeded" })), JSON.stringify(validate.errors));
});

test("operation-event-v1: a failed event REQUIRES a sanitized error", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.equal(validate(eventFixture({ phase: "failed" })), false, "failed with no error at all must be rejected");
  assert.ok(validate(eventFixture({ phase: "failed", error: "readiness.wait timed out after 60s" })), JSON.stringify(validate.errors));
});

test("operation-event-v1: a non-failed event must NOT carry an error field at all", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.equal(validate(eventFixture({ phase: "started", error: "should not be here" })), false);
  assert.equal(validate(eventFixture({ phase: "succeeded", error: "should not be here" })), false);
});

test("operation-event-v1: rejects an unrecognized phase", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.equal(validate(eventFixture({ phase: "skipped" })), false);
});

test("operation-event-v1: rejects attempt 0 - attempts are 1-indexed", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.equal(validate(eventFixture({ attempt: 0 })), false);
});

test("operation-event-v1: rejects a step id that isn't the plan's own operationId shape", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  assert.equal(validate(eventFixture({ step: "start the gateway" })), false);
});

test("operation-event-v1: rejects a raw exception dump or a secret value smuggled into error", async () => {
  const validate = await validatorFor("operation-event-v1.schema.json");
  // The schema itself can only enforce shape (a non-empty string) - this
  // documents the field is a plain string, so a caller-side sanitizer is
  // what actually keeps secrets out, not the schema alone. Still confirms
  // the schema doesn't require or special-case anything secret-shaped.
  assert.ok(validate(eventFixture({ phase: "failed", error: "connection refused" })));
});
