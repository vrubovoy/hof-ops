// Pure, no-I/O semantic validators for ADR 0006 (item 10, PR 1). JSON
// Schema alone cannot express "exactly one snapshot.create per
// configured destination" (the count depends on another array's own
// length) or "field X here equals field Y over there" (no $data
// references are used anywhere in this repo) - these functions fill
// that specific, narrow gap: given an already schema-valid document (or
// a bundle of them), do its own internal counts/ordering, and its
// bindings to the other documents in its bundle, actually hold. No
// target access, no clock, no randomness, nothing here ever mutates its
// input. This is a contracts-layer concern, not executor work: a
// candidate plan/bundle is either internally coherent or it isn't,
// independent of any real target ever existing.
//
// A third review round found the second round's own version of this
// file still had real gaps: ordering checks covered only a few of the
// ADR's actual predecessor relationships (accepting retention before
// its own snapshot, readiness before start, maintenance.exit before
// readiness, restore's volume.create after data.restore, checkpoint
// before its own verification, service.start before config/secret/
// state restoration); a blocked plan (executable: false, operations: [])
// was wrongly flagged as an incomplete flow instead of being recognized
// as never claiming to have one; bundle validators checked identity
// bindings (ids/digests) but never checked that a plan bound to an
// approved policy actually matches that policy's own destinations/
// retention, never bound restore's own claimed source to the manifest
// that is the actual proof of what is being restored, never bound a
// recovery kit's own installation/generation to the plan using it, and
// never accepted a lock/journal/event at all despite the ADR's own text
// claiming they were checked; and duplicate natural keys (two
// destinations named the same, two networks, two consistencySet
// volumes) inside a single document were never checked at all. This
// version closes all of that.

import { canonicalContentId, canonicalDocumentDigest, computeBackupId, consistencySetEntryKey, exactSetEquals, hasDuplicates } from "./backup-ids.mjs";
import { canonicalize, sha256 } from "./digest.mjs";

function indexOfAction(ops, action) {
  return ops.findIndex((op) => op.action === action);
}

function indicesOfAction(ops, action) {
  return ops.map((op, i) => (op.action === action ? i : -1)).filter((i) => i >= 0);
}

function sortedJSON(array) {
  return JSON.stringify([...array].sort());
}

// Structural equality, key-order-independent (canonicalize already
// recursively sorts object keys while preserving array element order -
// exactly the same notion of "the same document" every id in this repo
// is computed over).
function deepEqual(a, b) {
  return JSON.stringify(canonicalize(a)) === JSON.stringify(canonicalize(b));
}

// A targetBinding's own connection identity only - mode/host/port/user/
// hostKeySha256, never installationId/baselineGeneration, which for
// restore legitimately differ between plan.target (always genuinely
// clean, installationId: null, at planning time) and evidence.target
// (installationId now the source's own, assigned by state.restore
// during the operation itself).
function targetConnectionEqual(a, b) {
  const pick = ({ mode, host, port, user, hostKeySha256 }) => ({ mode, host, port, user, hostKeySha256 });
  return deepEqual(pick(a), pick(b));
}

// Every key for a given action, WITHOUT deduplicating - unlike
// mapByIndex below (a Map, which silently collapses two operations that
// happen to share a key down to one entry), this is what a caller must
// use to actually detect "the same resource/destination targeted twice"
// before ever building a Map from the same data.
function keysOf(ops, action, keyFn) {
  return ops.filter((op) => op.action === action).map(keyFn);
}

function mapByIndex(ops, action, keyFn) {
  const map = new Map();
  ops.forEach((op, i) => {
    if (op.action === action) map.set(keyFn(op), i);
  });
  return map;
}

// The Backup Flow's own fixed whitelist (ADR 0006), actually checked for
// completeness, per-destination cardinality, ordering, and internal
// consistency - not merely "every operation present is individually
// well-typed" (schemas/backup-plan-v1.schema.json's own per-operation
// phase/action pairing already covers that narrower claim). A blocked
// plan (executable: false) never claims to have a real flow at all - its
// own operations array is checked by the schema alone (blockers non-
// empty, executable: false); this function only ever analyzes an
// executable one. Returns an array of violation strings; empty means the
// flow is coherent.
export function validateBackupPlanOperations(plan) {
  if (plan.executable === false) return [];

  const violations = [];
  const ops = plan.operations;
  const byAction = (action) => ops.filter((op) => op.action === action);
  const destinationNames = plan.destinations.map((d) => d.name);

  if (hasDuplicates(plan.destinations, (d) => d.name)) violations.push("plan.destinations has a duplicate destination name");
  if (hasDuplicates(plan.consistencySet, consistencySetEntryKey)) violations.push("plan.consistencySet has a duplicate volume");

  for (const action of ["maintenance.enter", "maintenance.exit", "staging.build", "evidence.write"]) {
    const count = byAction(action).length;
    if (count !== 1) violations.push(`expected exactly one ${action} operation, found ${count}`);
  }
  for (const action of ["service.stop", "service.start", "readiness.wait"]) {
    if (byAction(action).length === 0) violations.push(`expected at least one ${action} operation`);
  }

  // A second, uniquely-IDed operation for a destination/resource already
  // covered is invisible to a Map-based cardinality check (the second
  // write just overwrites the first's own index) - a fourth review
  // round found exactly that gap. keysOf below returns every key WITHOUT
  // deduplicating, so hasDuplicates can actually see a repeat before
  // anything downstream ever collapses it into a Map.
  const snapshotKeys = keysOf(ops, "snapshot.create", (op) => op.destination);
  const retentionKeys = keysOf(ops, "retention.apply", (op) => op.destination);
  if (hasDuplicates(snapshotKeys, (k) => k)) violations.push("more than one snapshot.create operation targets the same destination");
  if (hasDuplicates(retentionKeys, (k) => k)) violations.push("more than one retention.apply operation targets the same destination");
  if (sortedJSON(snapshotKeys) !== sortedJSON(destinationNames)) {
    violations.push("snapshot.create operations must cover exactly the plan's own destinations, one each");
  }
  if (sortedJSON(retentionKeys) !== sortedJSON(destinationNames)) {
    violations.push("retention.apply operations must cover exactly the plan's own destinations, one each");
  }
  const snapshotByDestination = mapByIndex(ops, "snapshot.create", (op) => op.destination);
  const retentionByDestination = mapByIndex(ops, "retention.apply", (op) => op.destination);
  // Per-destination predecessor: THIS destination's own retention.apply
  // must come after THIS destination's own snapshot.create - checking
  // only "every retention after every snapshot in aggregate" would miss
  // a plan that interleaves per destination in the wrong order.
  for (const [destination, retentionIndex] of retentionByDestination) {
    const snapshotIndex = snapshotByDestination.get(destination);
    if (snapshotIndex !== undefined && retentionIndex < snapshotIndex) {
      violations.push(`retention.apply for destination "${destination}" must come after its own snapshot.create`);
    }
  }

  // service.stop and service.start must name the exact same set of
  // units - self-consistency (a unit stopped but never restarted, or
  // restarted without ever having been stopped, is never legitimate).
  // This does NOT prove the set matches the real, full topology (this
  // document carries no independent source-topology projection to check
  // that against - see ADR 0006's own Consequences on this point) - only
  // that the plan's own stop/start halves agree with each other.
  const stopUnits = byAction("service.stop").map((op) => op.resource);
  const startUnits = byAction("service.start").map((op) => op.resource);
  // A duplicate stop+matching duplicate start for the SAME unit passes
  // the set-equality check above (both arrays hold the identical
  // multiset) even though it's still two redundant, meaningless
  // operation pairs - a fifth review round found this. hasDuplicates
  // catches it independent of the set-equality check.
  if (hasDuplicates(stopUnits, (u) => u)) violations.push("more than one service.stop operation targets the same unit");
  if (hasDuplicates(startUnits, (u) => u)) violations.push("more than one service.start operation targets the same unit");
  if (sortedJSON(stopUnits) !== sortedJSON(startUnits)) {
    violations.push("service.stop and service.start must name the exact same set of units");
  }

  if (hasDuplicates(ops, (op) => op.id)) violations.push("duplicate operation id");

  if (ops.length > 0) {
    if (ops[0].action !== "maintenance.enter") violations.push("maintenance.enter must be the first operation");
    if (ops[ops.length - 1].action !== "evidence.write") violations.push("evidence.write must be the last operation");
  }

  const stagingIndex = indexOfAction(ops, "staging.build");
  const maintenanceEnterIndex = indexOfAction(ops, "maintenance.enter");
  const maintenanceExitIndex = indexOfAction(ops, "maintenance.exit");
  const stopIndices = indicesOfAction(ops, "service.stop");
  const snapshotIndices = indicesOfAction(ops, "snapshot.create");
  const retentionIndices = indicesOfAction(ops, "retention.apply");
  const startIndices = indicesOfAction(ops, "service.start");
  const readinessIndices = indicesOfAction(ops, "readiness.wait");
  const lastSnapshotOrRetention = Math.max(-1, ...snapshotIndices, ...retentionIndices);
  const lastStart = Math.max(-1, ...startIndices);
  const lastReadiness = Math.max(-1, ...readinessIndices);
  const firstReadiness = readinessIndices.length > 0 ? Math.min(...readinessIndices) : Infinity;

  if (stagingIndex >= 0 && maintenanceEnterIndex >= 0 && stagingIndex < maintenanceEnterIndex) {
    violations.push("staging.build must come after maintenance.enter");
  }
  if (stagingIndex >= 0 && stopIndices.some((i) => i > stagingIndex)) {
    violations.push("every service.stop must precede staging.build");
  }
  if (stagingIndex >= 0 && snapshotIndices.some((i) => i < stagingIndex)) {
    violations.push("every snapshot.create must come after staging.build");
  }
  if (startIndices.some((i) => i < lastSnapshotOrRetention)) {
    violations.push("service.start must come after every snapshot.create/retention.apply - it belongs to the finally block");
  }
  if (lastStart > firstReadiness) {
    violations.push("every service.start must come before every readiness.wait");
  }
  if (maintenanceExitIndex >= 0 && maintenanceExitIndex < lastReadiness) {
    violations.push("maintenance.exit must come after every readiness.wait");
  }
  if (maintenanceExitIndex >= 0 && maintenanceExitIndex < lastSnapshotOrRetention) {
    violations.push("maintenance.exit must come after every snapshot.create/retention.apply");
  }

  return violations;
}

// The Restore Flow's own fixed whitelist, same discipline as
// validateBackupPlanOperations above: completeness, per-network/per-
// volume cardinality, per-resource predecessor checks, and the full
// ordering chain ADR 0006 actually names - network before volume before
// data before verification before the sole privileged checkpoint before
// config/secret/state before service.start before readiness.wait.
export function validateRestorePlanOperations(plan) {
  if (plan.executable === false) return [];

  const violations = [];
  const ops = plan.operations;
  const byAction = (action) => ops.filter((op) => op.action === action);

  if (hasDuplicates(plan.consistencySet, consistencySetEntryKey)) violations.push("plan.consistencySet has a duplicate volume");
  if (hasDuplicates(plan.networks, (n) => n.name)) violations.push("plan.networks has a duplicate network name");

  for (const action of [
    "runner.install", "target.verify-clean", "snapshot.verify", "manifest.verify", "database.integrity-check",
    "checkpoint.data-restored", "config.restore", "secret.materialize", "state.restore", "evidence.write",
  ]) {
    const count = byAction(action).length;
    if (count !== 1) violations.push(`expected exactly one ${action} operation, found ${count}`);
  }
  for (const action of ["service.start", "readiness.wait"]) {
    if (byAction(action).length === 0) violations.push(`expected at least one ${action} operation`);
  }
  // A fifth review round found restore also allowed a repeated
  // service.start for the same unit, unnoticed.
  if (hasDuplicates(byAction("service.start").map((op) => op.resource), (u) => u)) {
    violations.push("more than one service.start operation targets the same unit");
  }

  const expectedNetworks = plan.networks.map((n) => n.name);
  const networkResources = byAction("network.create").map((op) => op.resource);
  if (hasDuplicates(networkResources, (k) => k)) violations.push("more than one network.create operation targets the same network");
  if (sortedJSON(networkResources) !== sortedJSON(expectedNetworks)) {
    violations.push("network.create operations must cover exactly the plan's own networks, one each");
  }

  const expectedVolumes = plan.consistencySet.map((entry) => entry.volume);
  const volumeKeys = keysOf(ops, "volume.create", (op) => op.resource);
  const dataRestoreKeys = keysOf(ops, "data.restore", (op) => op.resource);
  if (hasDuplicates(volumeKeys, (k) => k)) violations.push("more than one volume.create operation targets the same resource");
  if (hasDuplicates(dataRestoreKeys, (k) => k)) violations.push("more than one data.restore operation targets the same resource");
  if (sortedJSON(volumeKeys) !== sortedJSON(expectedVolumes)) {
    violations.push("volume.create operations must cover exactly the plan's own consistencySet volumes, one each");
  }
  if (sortedJSON(dataRestoreKeys) !== sortedJSON(expectedVolumes)) {
    violations.push("data.restore operations must cover exactly the plan's own consistencySet volumes, one each");
  }
  const volumeByResource = mapByIndex(ops, "volume.create", (op) => op.resource);
  const dataRestoreByResource = mapByIndex(ops, "data.restore", (op) => op.resource);
  // Per-resource predecessor: THIS volume's own volume.create must
  // precede THIS volume's own data.restore.
  for (const [resource, dataRestoreIndex] of dataRestoreByResource) {
    const volumeIndex = volumeByResource.get(resource);
    if (volumeIndex !== undefined && dataRestoreIndex < volumeIndex) {
      violations.push(`data.restore for "${resource}" must come after its own volume.create`);
    }
  }

  if (hasDuplicates(ops, (op) => op.id)) violations.push("duplicate operation id");

  if (ops.length > 0) {
    if (ops[0].action !== "runner.install") violations.push("runner.install must be the first operation");
    if (ops[ops.length - 1].action !== "evidence.write") violations.push("evidence.write must be the last operation");
  }

  const targetVerifyIndex = indexOfAction(ops, "target.verify-clean");
  const snapshotVerifyIndex = indexOfAction(ops, "snapshot.verify");
  const networkIndices = indicesOfAction(ops, "network.create");
  const volumeIndices = indicesOfAction(ops, "volume.create");
  const dataRestoreIndices = indicesOfAction(ops, "data.restore");
  const verificationIndices = [...indicesOfAction(ops, "manifest.verify"), ...indicesOfAction(ops, "database.integrity-check")];
  const checkpointIndex = indexOfAction(ops, "checkpoint.data-restored");
  const configIndex = indexOfAction(ops, "config.restore");
  const secretIndex = indexOfAction(ops, "secret.materialize");
  const stateIndex = indexOfAction(ops, "state.restore");
  const startIndices = indicesOfAction(ops, "service.start");
  const readinessIndices = indicesOfAction(ops, "readiness.wait");

  // A fourth review round found nothing checked that a restore actually
  // confirms the target is clean and the snapshot is genuinely the right
  // one BEFORE creating any network/volume or touching any data -
  // runner.install < target.verify-clean was already implied by
  // runner.install being required first, but target.verify-clean <
  // snapshot.verify < network.create never was.
  const firstNetwork = networkIndices.length > 0 ? Math.min(...networkIndices) : Infinity;
  if (targetVerifyIndex >= 0 && snapshotVerifyIndex >= 0 && targetVerifyIndex > snapshotVerifyIndex) {
    violations.push("target.verify-clean must come before snapshot.verify");
  }
  if (snapshotVerifyIndex >= 0 && snapshotVerifyIndex > firstNetwork) {
    violations.push("snapshot.verify must come before every network.create - nothing is provisioned before the snapshot is confirmed genuine");
  }

  const lastNetwork = Math.max(-1, ...networkIndices);
  if (volumeIndices.some((i) => i < lastNetwork)) {
    violations.push("every volume.create must come after every network.create");
  }

  const lastDataRestore = Math.max(-1, ...dataRestoreIndices);
  if (verificationIndices.some((i) => i < lastDataRestore)) {
    violations.push("manifest.verify/database.integrity-check must come after every data.restore");
  }

  const lastVerification = Math.max(-1, ...verificationIndices);
  if (checkpointIndex >= 0 && checkpointIndex < lastVerification) {
    violations.push("checkpoint.data-restored must come after manifest.verify/database.integrity-check");
  }
  if (checkpointIndex >= 0 && dataRestoreIndices.some((i) => i > checkpointIndex)) {
    violations.push("every data.restore must precede checkpoint.data-restored - it is the sole privileged boundary");
  }
  if (checkpointIndex >= 0 && configIndex >= 0 && configIndex < checkpointIndex) {
    violations.push("config.restore must come after checkpoint.data-restored");
  }
  if (checkpointIndex >= 0 && secretIndex >= 0 && secretIndex < checkpointIndex) {
    violations.push("secret.materialize must come after checkpoint.data-restored");
  }
  if (checkpointIndex >= 0 && stateIndex >= 0 && stateIndex < checkpointIndex) {
    violations.push("state.restore must come after checkpoint.data-restored");
  }

  const lastProvisioning = Math.max(-1, configIndex, secretIndex, stateIndex);
  if (startIndices.some((i) => i < lastProvisioning)) {
    violations.push("service.start must come after config.restore/secret.materialize/state.restore");
  }
  const lastStart = Math.max(-1, ...startIndices);
  if (readinessIndices.some((i) => i < lastStart)) {
    violations.push("readiness.wait must come after every service.start");
  }

  return violations;
}

// Cross-document bindings a single schema can never check on its own -
// policy -> plan -> manifest -> evidence, and now lock -> journal ->
// event too, all honestly content-addressed and actually referencing
// each other, not merely fields that happen to share a name. Every
// argument but plan is optional so a caller can check a partial bundle;
// only the checks whose documents are present run. Returns an array of
// violation strings; empty means the bundle is coherent.
export function validateBackupBundle({ policy, plan, manifest, evidence, kit, lock, journal, events } = {}) {
  const violations = [];
  if (!plan) {
    violations.push("a plan is required to validate a backup bundle");
    return violations;
  }

  if (plan.planId !== canonicalContentId(plan, "planId")) {
    violations.push("plan.planId does not match its own recomputed content-id");
  }
  const expectedBackupId = computeBackupId({
    installationId: plan.installationId,
    generation: plan.generation,
    backupPolicyId: plan.backupPolicyId,
    backupSequence: plan.backupSequence,
  });
  if (plan.backupId !== expectedBackupId) {
    violations.push("plan.backupId does not match its own recomputed domain-separated id");
  }
  // plan.target (the actual SSH connection binding - what installationId/
  // generation the target was OBSERVED to be at, right before this plan
  // was built) and plan's own top-level installationId/generation (what
  // this backup is declared to be FOR) must always agree, policy or no
  // policy - a fifth review round found nothing checked this at all, so
  // a plan could describe backing up installation X/generation 5 while
  // its own target binding was actually observed as installation Y/
  // generation 3.
  if (plan.target.installationId !== plan.installationId) {
    violations.push("plan.target.installationId does not match plan.installationId");
  }
  if (plan.target.baselineGeneration !== plan.generation) {
    violations.push("plan.target.baselineGeneration does not match plan.generation");
  }

  if (policy) {
    const expectedPolicyId = canonicalContentId(policy, ["policyId", "appliedGeneration", "appliedManifestDigest"]);
    if (policy.policyId !== expectedPolicyId) violations.push("policy.policyId does not match its own recomputed content-id");
    if (plan.backupPolicyId !== policy.policyId) violations.push("plan.backupPolicyId does not match the supplied policy's own policyId");
    if (plan.installationId !== policy.installationId) violations.push("plan.installationId does not match the supplied policy's own installationId");
    // A stale policy (last reconfirmed at an older generation than the
    // one this plan is actually built against) must never authorize a
    // newer generation's backup silently - policy.appliedGeneration
    // exists specifically so this can be checked (see backup-policy-v1
    // schema's own field description), but a fourth review round found
    // it never actually was.
    if (plan.generation !== policy.appliedGeneration) {
      violations.push("plan.generation does not match the supplied policy's own appliedGeneration - the policy is stale and must be reconfirmed via apply first");
    }
    // A plan referencing the right policyId while quietly using
    // different destinations/retention would otherwise bypass the whole
    // point of an approved policy - the id binding alone never checked
    // this.
    if (!deepEqual(plan.destinations, policy.destinations)) {
      violations.push("plan.destinations does not match the approved policy's own destinations exactly");
    }
    if (!deepEqual(plan.retention, policy.retention)) {
      violations.push("plan.retention does not match the approved policy's own retention exactly");
    }
  }

  if (manifest) {
    if (manifest.backupId !== plan.backupId) violations.push("manifest.backupId does not match plan.backupId");
    if (manifest.installationId !== plan.installationId) violations.push("manifest.installationId does not match plan.installationId");
    if (manifest.generation !== plan.generation) violations.push("manifest.generation does not match plan.generation");
    if (manifest.releaseLockDigest !== plan.releaseLockDigest) violations.push("manifest.releaseLockDigest does not match plan.releaseLockDigest");
    if (manifest.backupToolLockDigest !== plan.backupToolLockDigest) violations.push("manifest.backupToolLockDigest does not match plan.backupToolLockDigest");
    if (!exactSetEquals(manifest.consistencySet, plan.consistencySet, consistencySetEntryKey)) {
      violations.push("manifest.consistencySet does not exactly match plan.consistencySet");
    }
  }

  if (kit) {
    if (kit.installationId !== plan.installationId) violations.push("kit.installationId does not match plan.installationId");
    if (kit.createdForGeneration !== plan.generation) violations.push("kit.createdForGeneration does not match plan.generation");
    if (manifest && manifest.recoveryKitDigest !== canonicalDocumentDigest(kit)) {
      violations.push("manifest.recoveryKitDigest does not match the supplied kit's own recomputed digest");
    }
    // PR 3 (item 10): a kit that binds to the right plan/installation/
    // generation is still only a decoy shaped like one unless it's also
    // internally genuine - a schema-valid document with the right ids
    // but a garbage (or missing-magic-header) ciphertext would otherwise
    // sail through this bundle check untested. verifyRecoveryKit() is
    // the actual, pure verifier (see its own comment); every bundle that
    // carries a kit now runs it, not merely the id/digest bindings above.
    violations.push(...verifyRecoveryKit(kit));
  }

  if (evidence) {
    if (evidence.backupId !== plan.backupId) violations.push("evidence.backupId does not match plan.backupId");
    if (evidence.planId !== plan.planId) violations.push("evidence.planId does not match plan.planId");
    if (evidence.backupPolicyId !== plan.backupPolicyId) violations.push("evidence.backupPolicyId does not match plan.backupPolicyId");
    if (evidence.backupToolLockDigest !== plan.backupToolLockDigest) {
      violations.push("evidence.backupToolLockDigest does not match plan.backupToolLockDigest");
    }
    if (!deepEqual(evidence.target, plan.target)) violations.push("evidence.target does not match plan.target");
    if (manifest && evidence.manifestDigest !== canonicalDocumentDigest(manifest)) {
      violations.push("evidence.manifestDigest does not match the supplied manifest's own recomputed digest");
    }

    const expectedDestinations = plan.destinations.map((d) => d.name);
    const resultDestinations = evidence.perDestinationResults.map((r) => r.destination);
    if (hasDuplicates(evidence.perDestinationResults, (r) => r.destination)) {
      violations.push("evidence.perDestinationResults has a duplicate destination");
    }
    const unknown = resultDestinations.filter((d) => !expectedDestinations.includes(d));
    if (unknown.length > 0) {
      violations.push(`evidence.perDestinationResults names a destination not in the plan: ${unknown.join(", ")}`);
    }
    if (evidence.status === "succeeded" && sortedJSON(resultDestinations) !== sortedJSON(expectedDestinations)) {
      violations.push("a succeeded backup's evidence must report every configured destination, exactly - not a subset");
    }

    // Evidence was never actually bound to the operation (lock/journal)
    // that supposedly produced it - a fourth review round found this
    // gap: two entirely unrelated operationIds could share a plan
    // without ever being cross-checked.
    if (lock && evidence.operationId !== lock.operationId) violations.push("evidence.operationId does not match lock.operationId");
    if (journal) {
      if (evidence.operationId !== journal.operationId) violations.push("evidence.operationId does not match journal.operationId");
      // journal.status is binary (in-progress/succeeded/failed);
      // evidence.status is a three-way honest account
      // (succeeded/partial/failed) - see backup-evidence-v1's own
      // description for why. The two must still reconcile: journal
      // reaches a terminal status only once evidence.write ran, so
      // "in-progress" can never coexist with evidence existing at all,
      // "succeeded" must correspond to evidence.status: succeeded, and
      // "failed" must correspond to evidence.status: partial or failed
      // (never succeeded).
      if (journal.status === "in-progress") {
        violations.push("journal.status: in-progress can never coexist with evidence - evidence.write is what terminates the journal");
      }
      if (journal.status === "succeeded" && evidence.status !== "succeeded") {
        violations.push("journal.status: succeeded must correspond to evidence.status: succeeded");
      }
      if (journal.status === "failed" && evidence.status === "succeeded") {
        violations.push("journal.status: failed can never correspond to evidence.status: succeeded");
      }
      if (evidence.abandoned === true && journal.status !== "failed") {
        violations.push("evidence.abandoned: true must correspond to journal.status: failed - abandonment is itself a terminal failure");
      }
    }
    // abandoned: true asserts the flow never naturally completed - a
    // fifth review round found nothing checked this against the actual
    // event log; the first fix (requiring every plan operation to have
    // succeeded) was itself too narrow, since journal terminal semantics
    // only ever require evidence.write itself to have run - a sixth
    // review round gave the real minimal counterexample: journal failed,
    // abandoned: true, evidence.write's own event succeeded, but some
    // unrelated earlier step's event is missing. That still passed the
    // "every step" check while evidence.write having already, genuinely
    // succeeded is on its own the natural terminal completion abandoned
    // claims never happened - so only evidence.write's own event matters.
    if (events && evidence.abandoned === true) {
      const evidenceWriteOp = plan.operations.find((op) => op.action === "evidence.write");
      const evidenceWriteSucceeded = evidenceWriteOp
        ? events.some((event) => event.phase === "succeeded" && event.step === evidenceWriteOp.id)
        : false;
      if (evidenceWriteSucceeded) {
        violations.push("evidence.abandoned: true is incoherent with an event log showing evidence.write's own step already succeeded - a successful evidence.write is itself the flow's natural terminal completion, which abandonment means never happened");
      }
    }
  }

  if (lock) {
    if (lock.approvedPlanId !== plan.planId) violations.push("lock.approvedPlanId does not match plan.planId");
    if (!deepEqual(lock.target, plan.target)) violations.push("lock.target does not match plan.target");
    if (lock.operationKind !== "backup") violations.push("lock.operationKind is not backup");
  }

  if (journal) {
    if (journal.approvedPlanId !== plan.planId) violations.push("journal.approvedPlanId does not match plan.planId");
    if (journal.operationKind !== "backup") violations.push("journal.operationKind is not backup");
    if (!deepEqual(journal.target, plan.target)) violations.push("journal.target does not match plan.target");
    // journal.plan.planId matching plan.planId alone doesn't prove
    // journal.plan IS the real plan - operation-journal-v2.schema.json
    // only ever requires {apiVersion, planId} within its own embedded
    // plan (it never $ref's another schema file, this repo's own
    // convention), so a schema-valid journal could carry a correct
    // planId while its own embedded plan is otherwise truncated or
    // altered. A fifth review round found exactly that gap; the real
    // fix is structural equality against the actual plan passed in here,
    // not merely comparing one declared field.
    if (!deepEqual(journal.plan, plan)) violations.push("journal.plan does not structurally match the supplied plan - not merely a planId mismatch");
    if (journal.inputDigests?.releaseLockDigest !== plan.releaseLockDigest) {
      violations.push("journal.inputDigests.releaseLockDigest does not match plan.releaseLockDigest");
    }
    if (journal.inputDigests?.backupToolLockDigest !== plan.backupToolLockDigest) {
      violations.push("journal.inputDigests.backupToolLockDigest does not match plan.backupToolLockDigest");
    }
    if (journal.inputDigests?.backupPolicyId !== plan.backupPolicyId) {
      violations.push("journal.inputDigests.backupPolicyId does not match plan.backupPolicyId");
    }
    if (lock && lock.operationId !== journal.operationId) violations.push("lock.operationId does not match journal.operationId");
  }

  if (events) {
    const planStepIds = new Set(plan.operations.map((op) => op.id));
    for (const event of events) {
      if (journal && event.operationId !== journal.operationId) {
        violations.push(`event for step ${event.step} has an operationId not matching the journal`);
      }
      if (event.operationKind !== "backup") violations.push(`event for step ${event.step} has operationKind other than backup`);
      if (!planStepIds.has(event.step)) violations.push(`event names step "${event.step}", which is not in the plan's own operations`);
    }
  }

  return violations;
}

// The restore-side equivalent of validateBackupBundle above - plan ->
// manifest -> evidence, and lock -> journal -> event, honestly bound.
// Unlike the backup side, restore's own "source" claim (which
// installation/generation/release this backup came from) is a security-
// relevant statement about PROVENANCE - manifest is the actual, signed-
// snapshot-embedded proof of what is being restored, so plan.source not
// matching manifest's own installation/generation/release/releaseLock
// would let a restore plan claim one provenance while actually
// restoring a completely different one.
export function validateRestoreBundle({ plan, manifest, evidence, kit, lock, journal, events } = {}) {
  const violations = [];
  if (!plan) {
    violations.push("a plan is required to validate a restore bundle");
    return violations;
  }

  if (plan.planId !== canonicalContentId(plan, "planId")) {
    violations.push("plan.planId does not match its own recomputed content-id");
  }

  if (manifest) {
    if (plan.manifestDigest !== canonicalDocumentDigest(manifest)) {
      violations.push("plan.manifestDigest does not match the supplied manifest's own recomputed digest");
    }
    if (manifest.backupId !== plan.backupId) violations.push("manifest.backupId does not match plan.backupId");
    if (manifest.installationId !== plan.source.installationId) violations.push("manifest.installationId does not match plan.source.installationId");
    if (manifest.generation !== plan.source.generation) violations.push("manifest.generation does not match plan.source.generation");
    if (manifest.release !== plan.source.release) violations.push("manifest.release does not match plan.source.release");
    if (manifest.releaseLockDigest !== plan.source.releaseLockDigest) violations.push("manifest.releaseLockDigest does not match plan.source.releaseLockDigest");
    if (manifest.backupToolLockDigest !== plan.backupToolLockDigest) violations.push("manifest.backupToolLockDigest does not match plan.backupToolLockDigest");
    // ADR 0006's own Restore Flow text: "confirming the manifest's own
    // recoveryKitDigest matches the kit actually obtained, before
    // trusting anything else in the snapshot" - documented, never
    // actually implemented until a fourth review round caught it.
    if (manifest.recoveryKitDigest !== plan.recoveryKitDigest) violations.push("manifest.recoveryKitDigest does not match plan.recoveryKitDigest");
    if (!exactSetEquals(manifest.consistencySet, plan.consistencySet, consistencySetEntryKey)) {
      violations.push("manifest.consistencySet does not exactly match plan.consistencySet");
    }
  }

  if (kit) {
    if (kit.installationId !== plan.source.installationId) violations.push("kit.installationId does not match plan.source.installationId");
    if (kit.createdForGeneration !== plan.source.generation) violations.push("kit.createdForGeneration does not match plan.source.generation");
    if (plan.recoveryKitDigest !== canonicalDocumentDigest(kit)) violations.push("plan.recoveryKitDigest does not match the supplied kit's own recomputed digest");
    // PR 3 (item 10): see validateBackupBundle's own identical addition -
    // a restore is exactly the operation that will decrypt and TRUST this
    // kit's own contents, so binding checks alone (ids/digests) are even
    // less sufficient here than on the backup side.
    violations.push(...verifyRecoveryKit(kit));
  }

  if (evidence) {
    if (evidence.planId !== plan.planId) violations.push("evidence.planId does not match plan.planId");
    if (evidence.backupId !== plan.backupId) violations.push("evidence.backupId does not match plan.backupId");
    if (evidence.snapshotId !== plan.snapshotId) violations.push("evidence.snapshotId does not match plan.snapshotId");
    if (evidence.manifestDigest !== plan.manifestDigest) violations.push("evidence.manifestDigest does not match plan.manifestDigest");
    if (evidence.recoveryKitDigest !== plan.recoveryKitDigest) {
      violations.push("evidence.recoveryKitDigest does not match plan.recoveryKitDigest");
    }
    if (evidence.backupToolLockDigest !== plan.backupToolLockDigest) {
      violations.push("evidence.backupToolLockDigest does not match plan.backupToolLockDigest");
    }
    if (!deepEqual(evidence.source, plan.source)) violations.push("evidence.source does not match plan.source");
    // Only the connection identity is compared, never installationId/
    // baselineGeneration - those legitimately transition through the
    // operation itself (plan.target.installationId is always null,
    // genuinely clean, at planning time; evidence.target.installationId
    // is the source installationId state.restore actually assigned).
    if (!targetConnectionEqual(evidence.target, plan.target)) violations.push("evidence.target's own connection identity does not match plan.target's");

    if (lock && evidence.operationId !== lock.operationId) violations.push("evidence.operationId does not match lock.operationId");
    if (journal) {
      if (evidence.operationId !== journal.operationId) violations.push("evidence.operationId does not match journal.operationId");
      // restore-evidence-v1's own status is binary (succeeded/failed,
      // no "partial") - it maps directly onto journal.status.
      if (journal.status === "in-progress") {
        violations.push("journal.status: in-progress can never coexist with evidence - evidence.write is what terminates the journal");
      }
      if (journal.status !== evidence.status && journal.status !== "in-progress") {
        violations.push("journal.status does not match evidence.status");
      }
      if (evidence.abandoned === true && journal.status !== "failed") {
        violations.push("evidence.abandoned: true must correspond to journal.status: failed - abandonment is itself a terminal failure");
      }
    }
    // abandoned: true asserts the flow never naturally completed - a
    // fifth review round found nothing checked this against the actual
    // event log; the first fix (requiring every plan operation to have
    // succeeded) was itself too narrow, since journal terminal semantics
    // only ever require evidence.write itself to have run - a sixth
    // review round gave the real minimal counterexample: journal failed,
    // abandoned: true, evidence.write's own event succeeded, but some
    // unrelated earlier step's event is missing. That still passed the
    // "every step" check while evidence.write having already, genuinely
    // succeeded is on its own the natural terminal completion abandoned
    // claims never happened - so only evidence.write's own event matters.
    if (events && evidence.abandoned === true) {
      const evidenceWriteOp = plan.operations.find((op) => op.action === "evidence.write");
      const evidenceWriteSucceeded = evidenceWriteOp
        ? events.some((event) => event.phase === "succeeded" && event.step === evidenceWriteOp.id)
        : false;
      if (evidenceWriteSucceeded) {
        violations.push("evidence.abandoned: true is incoherent with an event log showing evidence.write's own step already succeeded - a successful evidence.write is itself the flow's natural terminal completion, which abandonment means never happened");
      }
    }
  }

  if (lock) {
    if (lock.approvedPlanId !== plan.planId) violations.push("lock.approvedPlanId does not match plan.planId");
    if (!deepEqual(lock.target, plan.target)) violations.push("lock.target does not match plan.target");
    if (lock.operationKind !== "restore") violations.push("lock.operationKind is not restore");
  }

  if (journal) {
    if (journal.approvedPlanId !== plan.planId) violations.push("journal.approvedPlanId does not match plan.planId");
    if (journal.operationKind !== "restore") violations.push("journal.operationKind is not restore");
    if (!deepEqual(journal.target, plan.target)) violations.push("journal.target does not match plan.target");
    // journal.plan.planId matching plan.planId alone doesn't prove
    // journal.plan IS the real plan - operation-journal-v2.schema.json
    // only ever requires {apiVersion, planId} within its own embedded
    // plan (it never $ref's another schema file, this repo's own
    // convention), so a schema-valid journal could carry a correct
    // planId while its own embedded plan is otherwise truncated or
    // altered. A fifth review round found exactly that gap; the real
    // fix is structural equality against the actual plan passed in here,
    // not merely comparing one declared field.
    if (!deepEqual(journal.plan, plan)) violations.push("journal.plan does not structurally match the supplied plan - not merely a planId mismatch");
    if (journal.inputDigests?.releaseLockDigest !== plan.source.releaseLockDigest) {
      violations.push("journal.inputDigests.releaseLockDigest does not match plan.source.releaseLockDigest");
    }
    if (journal.inputDigests?.backupToolLockDigest !== plan.backupToolLockDigest) {
      violations.push("journal.inputDigests.backupToolLockDigest does not match plan.backupToolLockDigest");
    }
    if (journal.inputDigests?.manifestDigest !== plan.manifestDigest) {
      violations.push("journal.inputDigests.manifestDigest does not match plan.manifestDigest");
    }
    if (journal.inputDigests?.recoveryKitDigest !== plan.recoveryKitDigest) {
      violations.push("journal.inputDigests.recoveryKitDigest does not match plan.recoveryKitDigest");
    }
    if (lock && lock.operationId !== journal.operationId) violations.push("lock.operationId does not match journal.operationId");
  }

  if (events) {
    const planStepIds = new Set(plan.operations.map((op) => op.id));
    for (const event of events) {
      if (journal && event.operationId !== journal.operationId) {
        violations.push(`event for step ${event.step} has an operationId not matching the journal`);
      }
      if (event.operationKind !== "restore") violations.push(`event for step ${event.step} has operationKind other than restore`);
      if (!planStepIds.has(event.step)) violations.push(`event names step "${event.step}", which is not in the plan's own operations`);
    }
    // A fourth review round found validateRestoreCommittedGeneration()
    // existed but was never actually wired into this bundle - only
    // exercised directly by its own unit tests, never as part of
    // validating a real bundle.
    if (journal) {
      violations.push(...validateRestoreCommittedGeneration(journal, events, plan));
    }
  }

  return violations;
}

// operation-journal-v2.schema.json's own committedGeneration is
// intentionally unconstrained by status for restore (see that schema's
// own field description) - its real correctness depends on whether
// state.restore actually succeeded, a fact only the event log carries.
// This checks exactly that: committedGeneration must be non-null if and
// only if a succeeded event for the state.restore step exists.
export function validateRestoreCommittedGeneration(journal, events, plan) {
  const violations = [];
  // A step's own id is free text an operation's author chooses - a
  // fourth review round already replaced a loose .includes() substring
  // match with an anchored regex over that same free text, but a fifth
  // round found even that remained spoofable: nothing ties an
  // operation's own id to its own action, so a schema-valid operation
  // could carry id: "010.state.restore.decoy" while its real action is
  // "config.restore" (or anything else) - fooling a regex keyed on id
  // text just as easily as .includes() did. The only trustworthy source
  // for "which step id is genuinely the state.restore operation" is the
  // plan's own operations array, keyed by action, never by id text.
  const stateRestoreOp = plan.operations.find((op) => op.action === "state.restore");
  const expectedGeneration = plan.source.generation;
  const stateRestoreSucceeded = stateRestoreOp
    ? events.some((event) => event.phase === "succeeded" && event.step === stateRestoreOp.id)
    : false;
  if (stateRestoreSucceeded) {
    if (journal.committedGeneration === null) {
      violations.push("committedGeneration must be set once state.restore has actually succeeded, regardless of the operation's own later outcome");
    } else if (journal.committedGeneration !== expectedGeneration) {
      violations.push("committedGeneration does not match the source generation state.restore actually committed");
    }
  } else if (journal.committedGeneration !== null) {
    violations.push("committedGeneration must stay null until state.restore actually succeeds");
  }
  return violations;
}

// A real age binary-format payload always begins with this exact
// literal line - the one structural property distinguishing a genuine
// age ciphertext from arbitrary base64-shaped plaintext (schemas/
// recovery-kit-v1.schema.json's own base64-alphabet pattern alone
// cannot tell "hunter2" apart from a real payload; this can).
const AGE_MAGIC = Buffer.from("age-encryption.org/v1\n", "utf8");

function stripBase64Padding(value) {
  return value.replace(/=+$/, "");
}

// Verifies a recovery-kit-v1 document is genuinely well-formed - not
// merely base64-alphabet-shaped (the schema's own weakest possible
// check on ciphertext) but actually decodable, actually beginning with
// a real age payload's own magic header, and actually matching its own
// declared ciphertextDigest; and that ageRecipientFingerprint is
// genuinely the recipient's own digest, not an unrelated value.
// Returns an array of violation strings. This checks the kit's own
// INTERNAL consistency only - whether it actually belongs to a given
// plan/installation/generation is validateBackupBundle's/
// validateRestoreBundle's own kit binding, above.
export function verifyRecoveryKit(kit) {
  const violations = [];
  const expectedFingerprint = sha256(Buffer.from(kit.ageRecipient, "utf8"));
  if (kit.ageRecipientFingerprint !== expectedFingerprint) {
    violations.push("ageRecipientFingerprint does not match the recomputed digest of ageRecipient");
  }

  let decoded;
  try {
    decoded = Buffer.from(kit.ciphertext, "base64");
  } catch {
    violations.push("ciphertext could not be base64-decoded at all");
    return violations;
  }
  if (stripBase64Padding(decoded.toString("base64")) !== stripBase64Padding(kit.ciphertext)) {
    violations.push("ciphertext is not valid, round-trippable base64");
    return violations;
  }
  if (!decoded.subarray(0, AGE_MAGIC.length).equals(AGE_MAGIC)) {
    violations.push("ciphertext does not begin with the age-encryption.org/v1 magic header - not a real age payload");
  }
  if (kit.ciphertextDigest !== sha256(decoded)) {
    violations.push("ciphertextDigest does not match the recomputed digest of the decoded ciphertext");
  }
  return violations;
}
