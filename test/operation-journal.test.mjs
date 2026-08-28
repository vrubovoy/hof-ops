import assert from "node:assert/strict";
import test from "node:test";

import {
  assertJournalResumable, buildEvent, buildJournalDocument, buildLockDocument,
  currentOperator, decideStepResumption, newOperationId, withJournalStatus,
} from "../scripts/operation-journal.mjs";

const TARGET = {
  mode: "ssh", host: "host.example", port: 22, user: "hof",
  hostKeySha256: "SHA256:" + "a".repeat(43), installationId: "00000000-0000-0000-0000-000000000000", baselineGeneration: 0,
};
const PLAN_ID = "sha256:" + "b".repeat(64);
const PLAN = { apiVersion: "hof.dev/plan/v2", planId: PLAN_ID };

test("newOperationId produces a real, distinct UUID every call", () => {
  const a = newOperationId();
  const b = newOperationId();
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.notEqual(a, b);
});

test("currentOperator reports real, non-empty identity fields", () => {
  const operator = currentOperator();
  assert.equal(typeof operator.workstation, "string");
  assert.ok(operator.workstation.length > 0);
  assert.equal(operator.pid, process.pid);
  assert.ok(operator.user.length > 0);
});

test("buildLockDocument produces a schema-valid document with a real timestamp", async () => {
  const operationId = newOperationId();
  const lock = await buildLockDocument({ operationId, approvedPlanId: PLAN_ID, target: TARGET, acquiredBy: currentOperator() });
  assert.equal(lock.apiVersion, "hof.dev/operation-lock/v1");
  assert.equal(lock.operationId, operationId);
  assert.equal(lock.approvedPlanId, PLAN_ID);
  assert.deepEqual(lock.target, TARGET);
  assert.ok(!Number.isNaN(Date.parse(lock.acquiredAt)));
});

test("buildJournalDocument starts in-progress with a null committedGeneration", async () => {
  const operationId = newOperationId();
  const inputDigests = {
    manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    executionEnvironmentDigest: "sha256:" + "5".repeat(64),
  };
  const journal = await buildJournalDocument({ operationId, approvedPlanId: PLAN_ID, target: TARGET, plan: PLAN, inputDigests });
  assert.equal(journal.apiVersion, "hof.dev/operation-journal/v1");
  assert.equal(journal.status, "in-progress");
  assert.equal(journal.committedGeneration, null);
  assert.deepEqual(journal.inputDigests, inputDigests);
  assert.deepEqual(journal.plan, PLAN);
});

test("buildJournalDocument refuses when approvedPlanId disagrees with plan.planId - the two must never be able to drift apart", async () => {
  const operationId = newOperationId();
  const inputDigests = {
    manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    executionEnvironmentDigest: "sha256:" + "5".repeat(64),
  };
  await assert.rejects(
    () => buildJournalDocument({ operationId, approvedPlanId: "sha256:" + "c".repeat(64), target: TARGET, plan: PLAN, inputDigests }),
    /these must always be the same value/,
  );
});

test("withJournalStatus produces a fresh document without mutating the original", async () => {
  const operationId = newOperationId();
  const inputDigests = {
    manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    executionEnvironmentDigest: "sha256:" + "5".repeat(64),
  };
  const journal = await buildJournalDocument({ operationId, approvedPlanId: PLAN_ID, target: TARGET, plan: PLAN, inputDigests });
  const committed = await withJournalStatus(journal, { status: "succeeded", committedGeneration: 1 });
  assert.equal(journal.status, "in-progress", "original document must be untouched");
  assert.equal(committed.status, "succeeded");
  assert.equal(committed.committedGeneration, 1);
});

test("buildEvent carries error only on phase: failed, per the schema's own allOf", async () => {
  const operationId = newOperationId();
  const started = await buildEvent({ operationId, step: "001.host.prepare", attempt: 1, phase: "started" });
  assert.ok(!("error" in started));
  const succeeded = await buildEvent({ operationId, step: "001.host.prepare", attempt: 1, phase: "succeeded" });
  assert.ok(!("error" in succeeded));
  const failed = await buildEvent({ operationId, step: "001.host.prepare", attempt: 1, phase: "failed", error: "connection refused" });
  assert.equal(failed.error, "connection refused");
});

test("buildEvent rejects phase: failed with no error message (the schema itself requires it)", async () => {
  await assert.rejects(
    () => buildEvent({ operationId: newOperationId(), step: "001.host.prepare", attempt: 1, phase: "failed" }),
    /does not satisfy schemas\/operation-event-v1/,
  );
});

test("decideStepResumption: no events at all -> run, attempt 1", () => {
  assert.equal(decideStepResumption([]), "run");
});

test("decideStepResumption: a succeeded event -> skip", () => {
  assert.equal(decideStepResumption([
    { phase: "started", attempt: 1 },
    { phase: "succeeded", attempt: 1 },
  ]), "skip");
});

test("decideStepResumption: a failed event -> failed (never actually reached via a live resume path, kept explicit)", () => {
  assert.equal(decideStepResumption([
    { phase: "started", attempt: 1 },
    { phase: "failed", attempt: 1, error: "boom" },
  ]), "failed");
});

test("decideStepResumption: a started event with no resolution -> blocked, never guessed", () => {
  assert.equal(decideStepResumption([{ phase: "started", attempt: 1 }]), "blocked");
});

test("decideStepResumption: succeeded wins over an earlier failed attempt (a real retry sequence)", () => {
  assert.equal(decideStepResumption([
    { phase: "started", attempt: 1 },
    { phase: "failed", attempt: 1, error: "boom" },
    { phase: "started", attempt: 2 },
    { phase: "succeeded", attempt: 2 },
  ]), "skip");
});

test("assertJournalResumable refuses an already-succeeded journal", () => {
  assert.throws(
    () => assertJournalResumable({ operationId: "x", status: "succeeded", committedGeneration: 1 }),
    /already succeeded \(committed generation 1\) - nothing to resume/,
  );
});

test("assertJournalResumable refuses an already-failed journal", () => {
  assert.throws(
    () => assertJournalResumable({ operationId: "x", status: "failed", committedGeneration: null }),
    /already failed - resume is refused/,
  );
});

test("assertJournalResumable allows an in-progress journal through", () => {
  assert.doesNotThrow(() => assertJournalResumable({ operationId: "x", status: "in-progress", committedGeneration: null }));
});
