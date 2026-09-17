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

// A pre-PR4 review found operation-v2.mjs never actually ran
// validateBackupPlanOperations()/validateRestorePlanOperations() (see
// operation-v2.mjs's own assertPlanValid() comment) - so these fixtures
// were never checked for real flow completeness/ordering, only for
// per-field schema shape. The short, 4/4-step lists this file used to
// have here were never actually coherent flows (missing service.stop/
// start, snapshot.create/retention.apply, readiness.wait entirely) - now
// that assertBundleBinding()/assertPlanValid() enforce this for real,
// they must be genuinely complete. Mirrors test/backup-contracts.test.mjs's
// own fullBackupOperations()/fullRestoreOperations() (that file remains
// the authority for exhaustive coverage of validateBackupPlanOperations/
// validateRestorePlanOperations themselves), trimmed to this file's own
// single destination ("onsite") and single consistencySet/network entry.
function fullBackupOperations() {
  return [
    { id: "001.maintenance.enter.platform", phase: "maintenance", action: "maintenance.enter", resource: "platform", reason: "begin backup" },
    { id: "002.service.stop.schlussel", phase: "service", action: "service.stop", resource: "schlussel", reason: "quiesce before staging" },
    { id: "003.staging.build.tree", phase: "staging", action: "staging.build", resource: "tree", reason: "build allowlisted staging tree" },
    { id: "004.snapshot.create.onsite", phase: "snapshot", action: "snapshot.create", resource: "onsite", destination: "onsite", reason: "snapshot to onsite" },
    { id: "005.retention.apply.onsite", phase: "retention", action: "retention.apply", resource: "onsite", destination: "onsite", reason: "apply retention onsite" },
    { id: "006.service.start.schlussel", phase: "service", action: "service.start", resource: "schlussel", reason: "restart after staging" },
    { id: "007.readiness.wait.platform", phase: "readiness", action: "readiness.wait", resource: "platform", condition: "healthy", reason: "confirm platform healthy" },
    { id: "008.maintenance.exit.platform", phase: "maintenance", action: "maintenance.exit", resource: "platform", reason: "end backup" },
    { id: "009.evidence.write.platform", phase: "evidence", action: "evidence.write", resource: "platform", reason: "record evidence" },
  ];
}

function fullRestoreOperations() {
  return [
    { id: "001.runner.install.runner", phase: "runner", action: "runner.install", resource: "runner", reason: "install signed runner" },
    { id: "002.target.verify-clean.target", phase: "target", action: "target.verify-clean", resource: "target", reason: "confirm genuinely clean" },
    { id: "003.snapshot.verify.offsite", phase: "snapshot", action: "snapshot.verify", resource: "offsite", reason: "verify pinned snapshot" },
    { id: "004.network.create.hof-hof", phase: "data", action: "network.create", resource: "hof-hof", reason: "create the hof network" },
    { id: "005.volume.create.schlussel-data", phase: "data", action: "volume.create", resource: "schlussel-data", reason: "create schlussel-data volume" },
    { id: "006.data.restore.schlussel-data", phase: "data", action: "data.restore", resource: "schlussel-data", reason: "restore schlussel-data" },
    { id: "007.manifest.verify.manifest", phase: "verification", action: "manifest.verify", resource: "manifest", reason: "verify restored manifest" },
    { id: "008.database.integrity-check.schlussel", phase: "verification", action: "database.integrity-check", resource: "schlussel", reason: "integrity-check schlussel" },
    { id: "009.checkpoint.data-restored.all", phase: "checkpoint", action: "checkpoint.data-restored", resource: "all", reason: "privileged checkpoint" },
    { id: "010.config.restore.config", phase: "config", action: "config.restore", resource: "config", reason: "restore generated config" },
    { id: "011.secret.materialize.secrets", phase: "secret", action: "secret.materialize", resource: "secrets", reason: "materialize runtime secrets" },
    { id: "012.state.restore.state", phase: "state", action: "state.restore", resource: "state", reason: "restore state verbatim" },
    { id: "013.service.start.schlussel", phase: "service", action: "service.start", resource: "schlussel", reason: "start restored services" },
    { id: "014.readiness.wait.platform", phase: "readiness", action: "readiness.wait", resource: "platform", condition: "healthy", reason: "confirm platform healthy" },
    { id: "015.evidence.write.platform", phase: "evidence", action: "evidence.write", resource: "platform", reason: "record evidence" },
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

test("assertBundleBinding: a coherent backup bundle (plan alone) passes; an incoherent one throws naming the actual violation", async () => {
  const plan = buildBackupPlan();
  await assertBundleBinding("backup", { plan }); // must not throw

  const tamperedPlan = { ...plan, target: { ...plan.target, installationId: "someone-else" } };
  await assert.rejects(() => assertBundleBinding("backup", { plan: tamperedPlan }), /plan\.target\.installationId does not match plan\.installationId/);
});

test("assertBundleBinding: a coherent restore bundle (plan alone) passes; routes to validateRestoreBundle for operationKind restore", async () => {
  const plan = buildRestorePlan();
  await assertBundleBinding("restore", { plan }); // must not throw

  const tamperedPlan = { ...plan, manifestDigest: sha("0") };
  await assert.rejects(() => assertBundleBinding("restore", { plan: tamperedPlan, manifest: { backupId: plan.backupId, installationId: "inst-1", generation: 3, release: "0.2.3", releaseLockDigest: plan.source.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, recoveryKitDigest: plan.recoveryKitDigest, consistencySet: plan.consistencySet } }), /manifestDigest/);
});

// PR 3 review, "pre-PR4 gap" finding: assertBundleBinding()/assertPlanValid()
// now also run validateBackupPlanOperations()/validateRestorePlanOperations()
// against bundle.plan - this is the regression test proving a SCHEMA-VALID
// plan with an incoherent operations sequence is refused before it ever
// reaches a write, not merely a plan with a bad id/digest binding (the two
// tests above). Uses a plan whose operations omit service.start entirely -
// schema-valid (backup-plan-v1 doesn't know about flow completeness at
// all - see backup-flow.mjs's own top comment on why), but a real gap
// validateBackupPlanOperations() alone can catch.
test("assertBundleBinding: a schema-valid plan whose own operations sequence is incoherent (missing service.start) is refused, never reaches a write", async () => {
  const incompleteOps = fullBackupOperations().filter((op) => op.action !== "service.start");
  const plan = buildBackupPlan({ operations: incompleteOps });
  await assert.rejects(
    () => assertBundleBinding("backup", { plan }),
    /expected at least one service\.start operation/,
  );
});

// --- Write wrappers: require an active lease, validate before ever
// reaching the raw transport. --------------------------------------------

const LEASE_TOKEN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

// journals: a Map<operationId, journal> standing in for the real,
// persisted target state writeJournalStatus()/writeEvent() now both
// read fresh before ever trusting a candidate - a test populates it to
// control what "already on the target" looks like, independent of
// whatever the caller happens to pass to those functions itself.
function fakeMutate({ journals = new Map() } = {}) {
  const calls = [];
  return {
    calls, journals,
    async acquireLockAndJournal(conn, lockDoc, journalDoc, leaseToken) { calls.push(["acquireLockAndJournal", lockDoc, journalDoc, leaseToken]); return { acquired: true }; },
    async readJournal(conn, operationId) {
      const journal = journals.get(operationId);
      return journal ? { status: "present", journal } : { status: "absent", journal: null };
    },
    async updateJournalStatus(conn, journal, leaseToken, expectedPreviousDocument) { calls.push(["updateJournalStatus", journal, leaseToken, expectedPreviousDocument]); journals.set(journal.operationId, journal); },
    async appendEvent(conn, operationId, event, leaseToken, expectedJournalSnapshot) { calls.push(["appendEvent", operationId, event, leaseToken, expectedJournalSnapshot]); },
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

// PR 2 review, High finding 3 (second round): a lease-SHAPED object with
// no token at all used to pass assertLeaseHealthy() and quietly hand
// `undefined` to the raw write, which target-mutate.mjs's own
// leaseFencingScript() treats as "no lease concept, write unguarded" -
// silently disabling every other fencing fix in this same review.
test("writeLockAndJournal: refuses a lease exposing isLost/assertOwnership but no genuine token - never silently disables fencing by passing undefined through", async () => {
  const mutate = fakeMutate();
  const tokenlessLease = { isLost: () => false, lostReason: () => null, assertOwnership: async () => {} };
  await assert.rejects(
    () => writeLockAndJournal(mutate, {}, tokenlessLease, { operationKind: "backup", lockDoc: {}, journalDoc: {} }),
    /exposes no token of its own/,
  );
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

// PR 3 review, "pre-PR4 gap" finding, integration-level regression test:
// a SCHEMA-VALID plan (buildJournalDocument's own schema check, and
// backup-plan-v1 itself, both pass it) whose own operations sequence is
// genuinely incoherent (here: a duplicate operation id) must never reach
// writeLockAndJournal()'s own raw transport call - proving
// validateBackupPlanOperations() is actually wired into the real write
// path a caller uses, not merely reachable by calling assertBundleBinding()
// directly (the unit-level test above already covers that).
test("writeLockAndJournal: a schema-valid plan with an incoherent operations sequence (duplicate operation id) never reaches the raw transport", async () => {
  const opsWithDuplicateId = fullBackupOperations();
  opsWithDuplicateId[1] = { ...opsWithDuplicateId[1], id: opsWithDuplicateId[0].id };
  const plan = buildBackupPlan({ operations: opsWithDuplicateId });
  const lockDoc = await buildLockDocument({ operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target });
  const journalDoc = await buildJournalDocument({
    operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
  });
  const mutate = fakeMutate();
  await assert.rejects(
    () => writeLockAndJournal(mutate, {}, healthyLease(), { operationKind: "backup", lockDoc, journalDoc }),
    /duplicate operation id/,
  );
  assert.equal(mutate.calls.length, 0, "the raw target-mutate transport must never be reached for an incoherent plan");
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
  assert.deepEqual(mutate.calls[0], ["acquireLockAndJournal", lockDoc, journalDoc, LEASE_TOKEN]);
});

// plan is its own, separate parameter (not folded into `overrides`) -
// approvedPlanId/target/inputDigests must all be derived from whichever
// plan is actually used, so a caller overriding `plan` (to build a
// journal bound to a plan with different operations, say) can never
// accidentally end up with a self-inconsistent journal (approvedPlanId
// pointing at the DEFAULT plan while `plan` itself is the override).
function realBackupJournal({ plan = buildBackupPlan(), ...overrides } = {}) {
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

test("writeJournalStatus: a healthy lease and a genuinely valid continuation of the persisted journal reach the raw transport, carrying the lease's own token AND the persisted document itself as the target-side CAS precondition", async () => {
  const journalDoc = await realBackupJournal();
  const plan = journalDoc.plan;
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  const succeeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  await writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: succeeded, bundle: { plan } });
  const writeCall = mutate.calls.find((c) => c[0] === "updateJournalStatus");
  // PR 2 review, High finding 4 (second round): the persisted document
  // exactly as read - not the candidate, not something re-derived -
  // must be passed through as target-mutate.mjs's own
  // expectedPreviousDocument, so the actual read-compare-write happens
  // atomically on the target, not as two independently racing JS round
  // trips.
  assert.deepEqual(writeCall, ["updateJournalStatus", succeeded, LEASE_TOKEN, journalDoc]);
});

// PR 2 review, High finding 4 (second round) - the real vulnerability:
// a SECOND writer reading the same in-progress journal after the FIRST
// one has already, genuinely landed its own transition. The first fix
// (reading `persisted` once, comparing in JS) could not catch this by
// itself, since the second call's own JS-side read/compare would run
// against the FIRST caller's in-memory state, not what the target
// itself already, actually holds a moment later - only passing the
// exact `persisted` snapshot through as a target-side CAS precondition
// (proven by the assertion above) closes it; this test just confirms
// the wrapper's own contract - the SAME persisted object it just read
// is what gets threaded through, not a re-fetched or reconstructed one.
test("writeJournalStatus: threads the exact persisted snapshot it read through as the CAS precondition - not a re-derived or default one", async () => {
  const journalDoc = await realBackupJournal();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  let readCallCount = 0;
  const realReadJournal = mutate.readJournal.bind(mutate);
  mutate.readJournal = async (...args) => { readCallCount += 1; return realReadJournal(...args); };
  const succeeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  await writeJournalStatus(mutate, {}, healthyLease(), { operationKind: "backup", journal: succeeded });
  assert.equal(readCallCount, 1, "reads the persisted journal exactly once");
  const writeCall = mutate.calls.find((c) => c[0] === "updateJournalStatus");
  assert.deepEqual(writeCall[3], journalDoc, "the CAS precondition is exactly the document that was read, unmodified");
});

function realBackupEvent(overrides = {}) {
  return buildEvent({ operationKind: "backup", operationId: OPERATION_ID, step: "001.maintenance.enter.platform", attempt: 1, phase: "started", ...overrides });
}

test("writeEvent: refuses when the lease is lost, and refuses a schema-invalid event, before ever reading the persisted journal", async () => {
  const journalDoc = await realBackupJournal();
  const event = await realBackupEvent();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(() => writeEvent(mutate, {}, lostLease(), { operationKind: "backup", operationId: OPERATION_ID, event }), /execution lease for this target is no longer held/);
  await assert.rejects(() => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event: { ...event, phase: "not-a-real-phase" } }), /does not satisfy schemas\/operation-event-v2/);
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 5 (second round): writeEvent() no longer
// accepts a `plan` parameter at all - the first fix's own `plan` was
// still whatever the CALLER happened to pass, so a caller (or a bug)
// could hand it a fabricated plan document containing exactly the
// step/destination a fabricated event needed, and it would validate. It
// now reads the persisted journal (the one this operationId's real
// events file is actually for) and uses ITS OWN embedded plan instead -
// this test confirms the "no persisted journal" case is refused, unlike
// the old version's "no plan given" case.
test("writeEvent: refuses when no persisted journal exists on the target to bind the event against", async () => {
  const event = await realBackupEvent();
  const mutate = fakeMutate(); // empty - nothing persisted
  await assert.rejects(() => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }), /no persisted journal for operation .* was found on the target/);
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses when the persisted journal's own operationKind doesn't match this write's own operationKind", async () => {
  const journalDoc = await realBackupJournal(); // operationKind: backup
  const event = await realBackupEvent();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "restore", operationId: OPERATION_ID, event }),
    /persisted journal's own operationKind .* does not match/,
  );
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 4 (first round) / High finding 5 (second
// round): the real vulnerability - an event whose own operationId names
// a DIFFERENT operation than the one this write is actually for.
// target-mutate.mjs's own appendEvent() targets the events FILE purely
// from the `operationId` parameter, never from the event body, so
// without this check an event claiming to belong to operation A could
// be appended to operation B's own events file.
test("writeEvent: refuses an event whose own operationId doesn't match the operationId this write is for - refuses operation-id substitution", async () => {
  const journalDoc = await realBackupJournal();
  const event = await realBackupEvent({ operationId: "99999999-9999-9999-9999-999999999999" });
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /does not match the operationId this write is for/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses an event whose own operationKind doesn't match this write's own operationKind, even when the persisted journal's own operationKind does match", async () => {
  const journalDoc = await realBackupJournal(); // operationKind: backup
  const event = await buildEvent({ operationKind: "restore", operationId: OPERATION_ID, step: "001.maintenance.enter.platform", attempt: 1, phase: "started" });
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /event\.operationKind .* does not match/,
  );
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 5 (second round)'s own core scenario: even
// with a genuine, persisted journal on the target, an event naming a
// step that isn't part of THAT journal's own real, approved plan is
// refused - never validated against a plan the caller merely asserts.
test("writeEvent: refuses an event naming a step that isn't part of the persisted journal's own plan operations", async () => {
  const journalDoc = await realBackupJournal();
  // Schema-valid step id shape, but not one of this journal's own plan's operations.
  const event = await realBackupEvent({ step: "099.evidence.write.nowhere" });
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /is not part of the persisted journal's own plan operations/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: refuses an event whose own destination doesn't match the persisted journal's own plan step for a per-destination action", async () => {
  // A genuinely complete, coherent plan (unlike before assertPlanValid()
  // ran validateBackupPlanOperations() at every write - see that
  // function's own comment - a truncated operations list would now be
  // refused for incompleteness before this test's own destination check
  // ever ran) - only the event's own destination is deliberately wrong.
  const journalDoc = await realBackupJournal({ plan: buildBackupPlan() });
  const event = await realBackupEvent({ step: "004.snapshot.create.onsite", destination: "offsite" });
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /event\.destination .* does not match the persisted journal's own plan step/,
  );
  assert.equal(mutate.calls.length, 0);
});

test("writeEvent: a healthy lease and a genuinely plan-bound event (bound against the PERSISTED journal's own plan) reach the raw transport, carrying the lease's own token AND the exact persisted journal snapshot", async () => {
  const journalDoc = await realBackupJournal();
  const event = await realBackupEvent();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event });
  assert.equal(mutate.calls.length, 1);
  // PR 2 review, High finding 4 (third round): the exact persisted
  // snapshot - not a re-derived or default one - must be threaded
  // through as target-mutate.mjs's own expectedJournalSnapshot, so the
  // real compare-and-swap (and the independent terminal-status re-
  // check) runs atomically on the target, not as two independently
  // racing JS round trips.
  assert.deepEqual(mutate.calls[0], ["appendEvent", OPERATION_ID, event, LEASE_TOKEN, journalDoc]);
});

// PR 2 review, High finding 3 (third round): an event has no business
// being appended once the persisted journal has already, genuinely
// finished - checked here, distinctly from the raw transport's own
// independent re-check (test/target-mutate.test.mjs's own equivalent
// test covers that layer).
test("writeEvent: refuses when the persisted journal is already terminal, before ever reaching the raw transport", async () => {
  const journalDoc = await realBackupJournal();
  const succeeded = await withJournalStatus(journalDoc, { status: "succeeded" });
  const event = await realBackupEvent();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, succeeded]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /already terminal \(status: succeeded\)/,
  );
  assert.equal(mutate.calls.length, 0);
});

// PR 2 review, High finding 3 (third round): a persisted journal whose
// own embedded plan is schema-valid but internally inconsistent (its
// own planId doesn't actually match its own content) must never be
// trusted for step/destination binding - assertJournalValid() alone
// (a schema check only, since operation-journal-v2.schema.json's own
// `plan` field is deliberately loosely typed) would not have caught
// this; assertBundleBinding() does, by recomputing planId from content.
test("writeEvent: refuses when the persisted journal's own embedded plan fails bundle binding (a tampered-but-schema-valid planId), before ever reaching the raw transport", async () => {
  const plan = buildBackupPlan();
  const tamperedPlan = { ...plan, planId: sha("0") }; // schema-valid shape, but no longer matches its own content
  const journalDoc = await realBackupJournal({ plan: tamperedPlan, approvedPlanId: tamperedPlan.planId });
  const event = await realBackupEvent();
  const mutate = fakeMutate({ journals: new Map([[OPERATION_ID, journalDoc]]) });
  await assert.rejects(
    () => writeEvent(mutate, {}, healthyLease(), { operationKind: "backup", operationId: OPERATION_ID, event }),
    /does not match its own recomputed content-id|planId/,
  );
  assert.equal(mutate.calls.length, 0);
});
