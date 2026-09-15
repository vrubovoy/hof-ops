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

const LEASE_TOKEN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

// journals: a Map<operationId, journal> standing in for the real,
// persisted target state writeJournalStatus() now reads fresh before
// ever trusting a candidate - a test populates it to control what
// "already on the target" looks like, independent of whatever candidate
// object it happens to pass to writeJournalStatus() itself.
function fakeMutate({ journals = new Map() } = {}) {
  const calls = [];
  return {
    calls, journals,
    async acquireLockAndJournal(conn, lockDoc, journalDoc) { calls.push(["acquireLockAndJournal", lockDoc, journalDoc]); return { acquired: true }; },
    async readJournal(conn, operationId) {
      const journal = journals.get(operationId);
      return journal ? { status: "present", journal } : { status: "absent", journal: null };
    },
    async updateJournalStatus(conn, journal, leaseToken) { calls.push(["updateJournalStatus", journal, leaseToken]); journals.set(journal.operationId, journal); },
    async appendEvent(conn, operationId, event, leaseToken) { calls.push(["appendEvent", operationId, event, leaseToken]); },
  };
}

// assertOwnershipCalls lets a test confirm the wrapper actually AWAITS a
// fresh assertOwnership() round trip before every write (PR 2 review,
// finding 5) - not merely reading a possibly-stale cached isLost().
function healthyLease({ token = LEASE_TOKEN, assertOwnershipCalls } = {}) {
  return {
    token,
    isLost: () => false,
    lostReason: () => null,
    assertOwnership: async () => { assertOwnershipCalls?.push(1); },
  };
}

function lostLease() {
  return { token: LEASE_TOKEN, isLost: () => true, lostReason: () => "simulated: the heartbeat detected the unit is gone", assertOwnership: async () => {} };
}

// A lease that reports healthy BEFORE assertOwnership() is called, but
// flips to lost once it actually runs - the only way to prove a wrapper
// is really awaiting a FRESH check, not just trusting isLost()'s value
// from before this write ever started.
function leaseThatGoesLostOnAssert() {
  let lost = false;
  return {
    token: LEASE_TOKEN,
    isLost: () => lost,
    lostReason: () => "simulated: discovered lost during a fresh assertOwnership() call",
    assertOwnership: async () => { lost = true; },
  };
}

test("writeLockAndJournal: refuses when no lease is given at all, or one missing isLost/assertOwnership - never silently treated as healthy (item 10 PR2 review, high finding 5)", async () => {
  const mutate = fakeMutate();
  await assert.rejects(() => writeLockAndJournal(mutate, {}, undefined, { operationKind: "backup", lockDoc: {}, journalDoc: {} }), /a real, active execution lease .* is required/);
  await assert.rejects(() => writeLockAndJournal(mutate, {}, { isLost: () => false }, { operationKind: "backup", lockDoc: {}, journalDoc: {} }), /a real, active execution lease .* is required/);
  assert.equal(mutate.calls.length, 0);
});

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

test("writeLockAndJournal: a lease that only goes lost DURING a fresh assertOwnership() call is still refused - never trusts a stale, already-healthy isLost() alone", async () => {
  const plan = buildBackupPlan();
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  const lease = leaseThatGoesLostOnAssert();
  assert.equal(lease.isLost(), false, "fixture sanity: healthy before assertOwnership() is ever called");
  await assert.rejects(
    () => writeLockAndJournal(mutate, {}, lease, { operationKind: "backup", lockDoc, journalDoc }),
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

test("writeLockAndJournal: a healthy lease and a coherent bundle reach the raw transport exactly once, after a real assertOwnership() call, with the exact documents", async () => {
  const plan = buildBackupPlan();
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  const assertOwnershipCalls = [];
  const result = await writeLockAndJournal(mutate, {}, healthyLease({ assertOwnershipCalls }), { operationKind: "backup", lockDoc, journalDoc, bundle: { plan } });
  assert.deepEqual(result, { acquired: true });
  assert.equal(assertOwnershipCalls.length, 1, "assertOwnership() must be awaited exactly once before the write");
  assert.equal(mutate.calls.length, 1);
  assert.deepEqual(mutate.calls[0], ["acquireLockAndJournal", lockDoc, journalDoc]);
});

function realBackupJournal(overrides = {}) {
  const plan = buildBackupPlan();
  return buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
    ...overrides,
  });
}

test("writeJournalStatus: refuses when the lease is lost, and refuses a schema-invalid candidate, before ever reading the persisted journal", async () => {
  const journalDoc = await realBackupJournal();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(() => writeJournalStatus(mutate, {}, lostLease(), { operationKind: "backup", journal: journalDoc }), /execution lease for this target is no longer held/);
  await assert.rejects(() => writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: { ...journalDoc, status: "not-a-real-status" } }), /does not satisfy schemas\/operation-journal-v2/);
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 3: the whole point of reading the persisted
// document fresh - a candidate that is internally self-consistent (and
// so would have passed the old, read-nothing version of this function)
// is still refused if nothing is actually on the target to update yet.
test("writeJournalStatus: refuses when no persisted journal exists on the target for this operationId", async () => {
  const journalDoc = await realBackupJournal();
  const mutate = fakeMutate(); // empty - nothing persisted
  await assert.rejects(
    () => writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: journalDoc }),
    /no persisted journal for operation .* was found on the target/,
  );
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 3's own core scenario: the persisted journal
// on the target is ALREADY terminal - a stale or malicious candidate
// object must never be allowed to rewrite it, however self-consistent
// the candidate itself looks.
test("writeJournalStatus: refuses to overwrite an already-terminal persisted journal, even with a schema-valid, internally-consistent candidate", async () => {
  const journalDoc = await realBackupJournal();
  const persistedSucceeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, persistedSucceeded]]) });
  // A caller's own in-memory candidate still claims in-progress -> failed,
  // built from the ORIGINAL (pre-succeeded) document it happened to be
  // holding onto - stale relative to what's actually on the target now.
  const staleCandidate = await withJournalStatus(journalDoc, { status: "failed" });
  await assert.rejects(
    () => writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: staleCandidate }),
    /already terminal/,
  );
  assert.equal(mutate.calls.length, 0);
  assert.equal(mutate.journals.get(OPERATION_ID).status, "succeeded", "the real, persisted terminal journal must be completely untouched");
});

// PR 2 review, High finding 3: a candidate whose own immutable field
// (here, plan) differs from what is actually persisted - never caught
// by the pure withJournalStatus() builder alone (which only ever
// compares an object against itself), only by reading the real
// persisted document and comparing against THAT.
test("writeJournalStatus: refuses a candidate whose own immutable field doesn't match the persisted document's, even though the candidate is itself schema-valid", async () => {
  const journalDoc = await realBackupJournal();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  const differentPlan = buildBackupPlan({ backupSequence: 2 });
  const tamperedCandidate = { ...journalDoc, plan: differentPlan, status: "succeeded" };
  await assert.rejects(
    () => writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: tamperedCandidate }),
    /does not match the persisted document's/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeJournalStatus: a healthy lease and a genuinely valid continuation of the persisted journal reach the raw transport, carrying the lease's own token", async () => {
  const journalDoc = await realBackupJournal();
  const plan = journalDoc.plan;
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  const succeeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  await writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: succeeded, bundle: { plan } });
  const writeCall = mutate.calls.find((c) => c[0] === "updateJournalStatus");
  assert.deepEqual(writeCall, ["updateJournalStatus", succeeded, LEASE_TOKEN]);
});

function realBackupEvent(overrides = {}) {
  return buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "001.maintenance.enter.platform", attempt: 1, phase: "started", ...overrides });
}

test("writeEvent: refuses when the lease is lost, and refuses a schema-invalid event, before ever reaching the raw transport", async () => {
  const plan = buildBackupPlan();
  const event = await realBackupEvent();
  const mutate = fakeMutate();
  await assert.rejects(() => writeEvent(mutate, {}, lostLease(), { operationKind: "backup", operationId: OPERATION_ID, event, plan }), /execution lease for this target is no longer held/);
  await assert.rejects(() => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event: { ...event, phase: "not-a-real-phase" }, plan }), /does not satisfy schemas\/operation-event-v2/);
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: requires the plan, to bind the event's step/destination against it", async () => {
  const event = await realBackupEvent();
  const mutate = fakeMutate();
  await assert.rejects(() => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }), /requires the operation's own plan/);
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 4: the real vulnerability - an event whose
// own operationId names a DIFFERENT operation than the one this write
// is actually for. target-mutate.mjs's own appendEvent() targets the
// events FILE purely from the `operationId` parameter, never from the
// event body, so without this check an event claiming to belong to
// operation A could be appended to operation B's own events file.
test("writeEvent: refuses an event whose own operationId doesn't match the operationId this write is for - refuses operation-id substitution", async () => {
  const plan = buildBackupPlan();
  const event = await realBackupEvent({ operationId: "99999999-9999-9999-9999-999999999999" });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event, plan }),
    /does not match the operationId this write is for/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses an event whose own operationKind doesn't match this write's own operationKind", async () => {
  const restorePlan = buildRestorePlan();
  const event = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.runner.install.runner", attempt: 1, phase: "started" });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event, plan: restorePlan }),
    /event\.operationKind .* does not match/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses an event naming a step that isn't part of the plan's own operations", async () => {
  const plan = buildBackupPlan();
  // Schema-valid step id shape, but not one of this plan's own operations.
  const event = await realBackupEvent({ step: "099.evidence.write.nowhere" });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event, plan }),
    /is not part of the plan's own operations/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses an event whose own destination doesn't match the plan's step for a per-destination action", async () => {
  const plan = buildBackupPlan({
    operations: [
      ...fullBackupOperations().slice(0, 3),
      { id: "004.snapshot.create.onsite", phase: "snapshot", action: "snapshot.create", resource: "onsite", destination: "onsite", reason: "snapshot to onsite" },
    ],
  });
  const event = await realBackupEvent({ step: "004.snapshot.create.onsite", destination: "offsite" });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event, plan }),
    /event\.destination .* does not match the plan's own step/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: a healthy lease and a genuinely plan-bound event reach the raw transport, carrying the lease's own token", async () => {
  const plan = buildRestorePlan();
  const event = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.runner.install.runner", attempt: 1, phase: "started" });
  const mutate = fakeMutate();
  await writeEvent(mutate, {}, healthyLease(), { operationKind: "restore", operationId: OPERATION_ID, event, plan });
  assert.equal(mutate.calls.length, 1);
  assert.deepEqual(mutate.calls[0], ["appendEvent", OPERATION_ID, event, LEASE_TOKEN]);
});
