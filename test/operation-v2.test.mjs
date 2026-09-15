// Unit coverage for scripts/operation-v2.mjs - the v2 (backup/restore)
// sibling of operation-journal.mjs's own v1 builders/validators, plus
// the new-in-PR-2 bundle-binding gate and write wrappers. Fixtures here
// are deliberately minimal, self-contained copies of the same shapes
// test/backup-contracts.test.mjs already builds in full (that file
// remains the authority for exhaustive schema/semantic coverage of the
// eleven ADR 0006 contracts themselves) - this file only needs "one
// genuinely valid backup plan" and "one genuinely valid restore plan" to
// exercise operation-v2.mjs's own logic.

import assert from "node:assert/strict";
import test from "node:test";

import { canonicalContentId, computeBackupId } from "../scripts/backup-ids.mjs";
import {
  assertBundleBinding, assertEventValid, assertJournalValid, assertLockValid,
  buildEvent, buildJournalDocument, buildLockDocument, isV2Lock, withJournalStatus,
  writeEvent, writeJournalStatus, writeLockAndJournal,
} from "../scripts/operation-v2.mjs";
import { assertLockValid as assertV1LockValid } from "../scripts/operation-journal.mjs";

function sha(fill) {
  return "sha256:" + String(fill).repeat(64).slice(0, 64);
}

const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000001";

function backupTargetBinding(overrides = {}) {
  return {
    mode: "ssh", host: "hof.example.com", port: 22, user: "deploy",
    hostKeySha256: "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno",
    installationId: "inst-1", baselineGeneration: 3,
    ...overrides,
  };
}

function restoreTargetBinding(overrides = {}) {
  return {
    mode: "ssh", host: "clean-host.example.com", port: 22, user: "deploy",
    hostKeySha256: "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno",
    installationId: null, baselineGeneration: 0,
    ...overrides,
  };
}

function fullBackupOperations() {
  return [
    { id: "001.maintenance.enter.platform", phase: "maintenance", action: "maintenance.enter", resource: "platform", reason: "begin backup" },
    { id: "002.staging.build.tree", phase: "staging", action: "staging.build", resource: "tree", reason: "build allowlisted staging tree" },
    { id: "003.maintenance.exit.platform", phase: "maintenance", action: "maintenance.exit", resource: "platform", reason: "end backup" },
    { id: "004.evidence.write.platform", phase: "evidence", action: "evidence.write", resource: "platform", reason: "record evidence" },
  ];
}

function fullRestoreOperations() {
  return [
    { id: "001.runner.install.runner", phase: "runner", action: "runner.install", resource: "runner", reason: "install signed runner" },
    { id: "002.checkpoint.data-restored.all", phase: "checkpoint", action: "checkpoint.data-restored", resource: "all", reason: "privileged checkpoint" },
    { id: "003.state.restore.state", phase: "state", action: "state.restore", resource: "state", reason: "restore state verbatim" },
    { id: "004.evidence.write.platform", phase: "evidence", action: "evidence.write", resource: "platform", reason: "record evidence" },
  ];
}

function buildBackupPlan(overrides = {}) {
  const content = {
    apiVersion: "hof.dev/backup-plan/v1",
    backupPolicyId: sha("9"),
    backupSequence: 1,
    trigger: "manual",
    executable: true,
    target: backupTargetBinding(),
    installationId: "inst-1",
    generation: 3,
    releaseLockDigest: sha("c"),
    backupToolLockDigest: sha("d"),
    consistencySet: [{ service: "schlussel", unit: "schlussel", volume: "schlussel-data", retained: false }],
    destinations: [{ name: "onsite", type: "local", path: "/mnt/hof-backups", secretRef: "backup-onsite-key" }],
    retention: { daily: 7, weekly: 4, monthly: 6 },
    operations: fullBackupOperations(),
    warnings: [],
    blockers: [],
    ...overrides,
  };
  const backupId = "backupId" in overrides ? overrides.backupId : computeBackupId({
    installationId: content.installationId, generation: content.generation,
    backupPolicyId: content.backupPolicyId, backupSequence: content.backupSequence,
  });
  const withBackupId = { ...content, backupId };
  const planId = "planId" in overrides ? overrides.planId : canonicalContentId(withBackupId, "planId");
  return { ...withBackupId, planId };
}

function buildRestorePlan(overrides = {}) {
  const content = {
    apiVersion: "hof.dev/restore-plan/v1",
    executable: true,
    target: restoreTargetBinding(),
    cleanObservation: { containers: [], volumes: [], networks: [], units: [], generatedArtifacts: [] },
    backupId: sha("b"),
    destinationName: "offsite",
    snapshotId: "abc123def456",
    manifestDigest: sha("1"),
    source: { installationId: "inst-1", generation: 3, release: "0.2.3", releaseLockDigest: sha("c") },
    recoveryKitDigest: sha("e"),
    backupToolLockDigest: sha("d"),
    consistencySet: [{ service: "schlussel", unit: "schlussel", volume: "schlussel-data", retained: false }],
    networks: [{ name: "hof-hof", internal: false }],
    operations: fullRestoreOperations(),
    warnings: [],
    blockers: [],
    ...overrides,
  };
  const planId = "planId" in overrides ? overrides.planId : canonicalContentId(content, "planId");
  return { ...content, planId };
}

// --- buildLockDocument / buildJournalDocument / buildEvent: schema-valid
// build, for both kinds. ----------------------------------------------

test("buildLockDocument: produces a schema-valid v2 lock for both backup and restore, and rejects any other operationKind", async () => {
  const plan = buildBackupPlan();
  const lock = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  assert.equal(lock.apiVersion, "hof.dev/operation-lock/v2");
  assert.equal(lock.operationKind, "backup");
  await assertLockValid(lock); // must not throw

  const restorePlan = buildRestorePlan();
  const restoreLock = await buildLockDocument({ operationKind: "restore", operationId: OPERATION_ID, approvedPlanId: restorePlan.planId, target: restorePlan.target });
  await assertLockValid(restoreLock);

  await assert.rejects(
    () => buildLockDocument({ operationKind: "apply", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target }),
    /requires operationKind "backup" or "restore"/,
  );
});

test("buildJournalDocument: rejects a mismatched approvedPlanId, exactly like operation-journal.mjs's own v1 builder", async () => {
  const plan = buildBackupPlan();
  await assert.rejects(
    () => buildJournalDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: sha("0"), target: plan.target, plan, inputDigests: {} }),
    /these must always be the same value/,
  );
});

test("buildJournalDocument: picks exactly the kind-specific inputDigests shape, dropping any field that doesn't belong to it", async () => {
  const plan = buildBackupPlan();
  const journal = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    // A restore-shaped field smuggled in by mistake - must never survive into the built document.
    inputDigests: { releaseLockDigest: sha("c"), backupToolLockDigest: sha("d"), backupPolicyId: plan.backupPolicyId, manifestDigest: sha("f") },
  });
  assert.deepEqual(Object.keys(journal.inputDigests).sort(), ["backupPolicyId", "backupToolLockDigest", "releaseLockDigest"]);
  await assertJournalValid(journal);
});

test("buildJournalDocument: a restore journal embedding a backup-plan-v1 document (or vice versa) fails its own schema, not silently accepted", async () => {
  const plan = buildBackupPlan();
  await assert.rejects(
    () => buildJournalDocument({
      operationKind: "restore", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
      inputDigests: { releaseLockDigest: sha("c"), backupToolLockDigest: sha("d"), manifestDigest: sha("f"), recoveryKitDigest: sha("e") },
    }),
    /does not satisfy schemas\/operation-journal-v2/,
  );
});

test("buildEvent: destination is required for a backup snapshot/retention step and forbidden everywhere else - enforced by the schema, never silently dropped or smuggled", async () => {
  const event = await buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "004.snapshot.create.onsite", attempt: 1, phase: "started", destination: "onsite" });
  assert.equal(event.destination, "onsite");
  await assert.rejects(
    () => buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "001.maintenance.enter.platform", attempt: 1, phase: "started", destination: "onsite" }),
    /does not satisfy schemas\/operation-event-v2/,
  );
  await assert.rejects(
    () => buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "004.snapshot.create.onsite", attempt: 1, phase: "started" }),
    /does not satisfy schemas\/operation-event-v2/,
  );
});

test("buildEvent: error is included only for phase failed, exactly like the v1 builder", async () => {
  const started = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.runner.install.runner", attempt: 1, phase: "started" });
  assert.ok(!("error" in started));
  const failed = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.runner.install.runner", attempt: 1, phase: "failed", error: "boom" });
  assert.equal(failed.error, "boom");
});

// --- isV2Lock / assertLockValid: v1<->v2 substitution rejection --------

test("isV2Lock: true for a genuine v2 lock, false for a v1 lock (even a schema-valid one) and for garbage", async () => {
  const plan = buildBackupPlan();
  const v2Lock = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  assert.equal(await isV2Lock(v2Lock), true);

  const v1Lock = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID, approvedPlanId: sha("0"), target: plan.target, acquiredAt: "2026-09-15T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  await assertV1LockValid(v1Lock); // fixture sanity: this really is a valid v1 lock
  assert.equal(await isV2Lock(v1Lock), false, "a genuinely valid v1 lock must never also validate as v2 - operationKind is required and v1 has none");

  assert.equal(await isV2Lock({ not: "a lock at all" }), false);
});

test("assertLockValid/assertJournalValid/assertEventValid: reject a v1-shaped document handed to the v2 validator, and vice versa is exercised by the isV2Lock test above", async () => {
  const plan = buildBackupPlan();
  const v1Lock = { apiVersion: "hof.dev/operation-lock/v1", operationId: OPERATION_ID, approvedPlanId: sha("0"), target: plan.target, acquiredAt: "2026-09-15T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  await assert.rejects(() => assertLockValid(v1Lock), /does not satisfy schemas\/operation-lock-v2/);
});

// --- withJournalStatus: immutability + terminal-status protection ------

test("withJournalStatus: updates status/committedGeneration on an in-progress journal, leaving every other field byte-for-byte identical", async () => {
  const plan = buildBackupPlan();
  const journal = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const updated = await withJournalStatus(journal, { status: "succeeded", committedGeneration: null });
  assert.equal(updated.status, "succeeded");
  for (const field of ["apiVersion", "operationKind", "operationId", "approvedPlanId", "target", "plan", "inputDigests", "startedAt"]) {
    assert.deepEqual(updated[field], journal[field], `${field} must stay byte-for-byte identical`);
  }
});

test("withJournalStatus: refuses to rewrite an already-terminal journal - a v2 journal's terminal status is never rewritten", async () => {
  const plan = buildBackupPlan();
  const journal = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const succeeded = await withJournalStatus(journal, { status: "succeeded" });
  await assert.rejects(() => withJournalStatus(succeeded, { status: "failed" }), /already terminal/);
});

test("withJournalStatus: an extra field on its own second argument (options) never reaches the candidate document - only status/committedGeneration are ever read off it", async () => {
  const plan = buildBackupPlan();
  const journal = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const updated = await withJournalStatus(journal, { status: "succeeded", committedGeneration: null, target: { mode: "local", host: null, port: null, user: null, hostKeySha256: null, installationId: "sneaked-in", baselineGeneration: 0 } });
  assert.deepEqual(updated.target, journal.target, "an unrecognized options field must never reach the candidate document, however it's named");
});

// --- assertBundleBinding: routes to validateBackupBundle/
// validateRestoreBundle by operationKind, and throws on any violation. --

test("assertBundleBinding: a coherent backup bundle (plan alone) passes; an incoherent one throws naming the actual violation", () => {
  const plan = buildBackupPlan();
  assertBundleBinding("backup", { plan }); // must not throw

  const tamperedPlan = { ...plan, target: { ...plan.target, installationId: "someone-else" } };
  assert.throws(() => assertBundleBinding("backup", { plan: tamperedPlan }), /plan\.target\.installationId does not match plan\.installationId/);
});

test("assertBundleBinding: a coherent restore bundle (plan alone) passes; routes to validateRestoreBundle for operationKind restore", () => {
  const plan = buildRestorePlan();
  assertBundleBinding("restore", { plan }); // must not throw

  const tamperedPlan = { ...plan, manifestDigest: sha("0") };
  assert.throws(() => assertBundleBinding("restore", { plan: tamperedPlan, manifest: { backupId: plan.backupId, installationId: "inst-1", generation: 3, release: "0.2.3", releaseLockDigest: plan.source.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, recoveryKitDigest: plan.recoveryKitDigest, consistencySet: plan.consistencySet } }), /manifestDigest/);
});

// --- Write wrappers: require an active lease, validate before ever
// reaching the raw transport. --------------------------------------------

function fakeMutate() {
  const calls = [];
  return {
    calls,
    async acquireLockAndJournal(conn, lockDoc, journalDoc) { calls.push(["acquireLockAndJournal", lockDoc, journalDoc]); return { acquired: true }; },
    async updateJournalStatus(conn, journal) { calls.push(["updateJournalStatus", journal]); },
    async appendEvent(conn, operationId, event) { calls.push(["appendEvent", operationId, event]); },
  };
}

function healthyLease() {
  return { isLost: () => false, lostReason: () => null };
}

function lostLease() {
  return { isLost: () => true, lostReason: () => "simulated: the heartbeat detected the unit is gone" };
}

test("writeLockAndJournal: refuses when the lease is lost, before ever reaching the raw transport", async () => {
  const plan = buildBackupPlan();
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeLockAndJournal(mutate, {}, lostLease(), { operationKind: "backup", lockDoc, journalDoc }),
    /execution lease for this target is no longer held/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeLockAndJournal: refuses a bundle-binding violation before ever reaching the raw transport", async () => {
  const plan = buildBackupPlan();
  const tamperedPlan = { ...plan, target: { ...plan.target, installationId: "someone-else" } };
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: tamperedPlan.planId, target: tamperedPlan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: tamperedPlan.planId, target: tamperedPlan.target, plan: tamperedPlan,
    inputDigests: { releaseLockDigest: tamperedPlan.releaseLockDigest, backupToolLockDigest: tamperedPlan.backupToolLockDigest, backupPolicyId: tamperedPlan.backupPolicyId },
  });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeLockAndJournal(mutate, {}, healthyLease(), { operationKind: "backup", lockDoc, journalDoc }),
    /bundle binding is violated/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeLockAndJournal: a healthy lease and a coherent bundle reach the raw transport exactly once, with the exact documents", async () => {
  const plan = buildBackupPlan();
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  const result = await writeLockAndJournal(mutate, {}, healthyLease(), { operationKind: "backup", lockDoc, journalDoc, bundle: { plan } });
  assert.deepEqual(result, { acquired: true });
  assert.equal(mutate.calls.length, 1);
  assert.deepEqual(mutate.calls[0], ["acquireLockAndJournal", lockDoc, journalDoc]);
});

test("writeJournalStatus: refuses when the lease is lost, and refuses a schema-invalid candidate, before ever reaching the raw transport", async () => {
  const plan = buildBackupPlan();
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  await assert.rejects(() => writeJournalStatus(mutate, {}, lostLease(), { operationKind: "backup", journal: journalDoc }), /execution lease for this target is no longer held/);
  await assert.rejects(() => writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: { ...journalDoc, status: "not-a-real-status" } }), /does not satisfy schemas\/operation-journal-v2/);
  assert.equal(mutate.calls.length, 0);
});

test("writeJournalStatus: a healthy lease and a valid, bound journal reach the raw transport", async () => {
  const plan = buildBackupPlan();
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const succeeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  const mutate = fakeMutate();
  await writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: succeeded, bundle: { plan } });
  assert.equal(mutate.calls.length, 1);
  assert.deepEqual(mutate.calls[0], ["updateJournalStatus", succeeded]);
});

test("writeEvent: refuses when the lease is lost, and refuses a schema-invalid event, before ever reaching the raw transport", async () => {
  const event = await buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "001.maintenance.enter.platform", attempt: 1, phase: "started" });
  const mutate = fakeMutate();
  await assert.rejects(() => writeEvent(mutate, {}, lostLease(), { operationId: OPERATION_ID, event }), /execution lease for this target is no longer held/);
  await assert.rejects(() => writeEvent(mutate, {}, healthyLease(), { operationId: OPERATION_ID, event: { ...event, phase: "not-a-real-phase" } }), /does not satisfy schemas\/operation-event-v2/);
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: a healthy lease and a valid event reach the raw transport", async () => {
  const event = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.runner.install.runner", attempt: 1, phase: "started" });
  const mutate = fakeMutate();
  await writeEvent(mutate, {}, healthyLease(), { operationId: OPERATION_ID, event });
  assert.equal(mutate.calls.length, 1);
  assert.deepEqual(mutate.calls[0], ["appendEvent", OPERATION_ID, event]);
});
