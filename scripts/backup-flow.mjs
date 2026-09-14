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

import { canonicalContentId, canonicalDocumentDigest, computeBackupId, consistencySetEntryKey, exactSetEquals, hasDuplicates } from "./backup-ids.mjs";
import { sha256 } from "./digest.mjs";

function indexOfAction(ops, action) {
  return ops.findIndex((op) => op.action === action);
}

function indicesOfAction(ops, action) {
  return ops.map((op, i) => (op.action === action ? i : -1)).filter((i) => i >= 0);
}

function sortedJSON(array) {
  return JSON.stringify([...array].sort());
}

// The Backup Flow's own fixed whitelist (ADR 0006), actually checked for
// completeness, per-destination cardinality, and ordering - not merely
// "every operation present is individually well-typed" (schemas/
// backup-plan-v1.schema.json's own per-operation phase/action pairing
// already covers that narrower claim). Returns an array of violation
// strings; empty means the flow is coherent. Never called on a plan
// that isn't already schema-valid - it assumes operations/destinations/
// consistencySet are already well-shaped arrays of well-shaped objects.
export function validateBackupPlanOperations(plan) {
  const violations = [];
  const ops = plan.operations;
  const byAction = (action) => ops.filter((op) => op.action === action);
  const destinationNames = plan.destinations.map((d) => d.name);

  for (const action of ["maintenance.enter", "maintenance.exit", "staging.build", "evidence.write"]) {
    const count = byAction(action).length;
    if (count !== 1) violations.push(`expected exactly one ${action} operation, found ${count}`);
  }
  for (const action of ["service.stop", "service.start", "readiness.wait"]) {
    if (byAction(action).length === 0) violations.push(`expected at least one ${action} operation`);
  }

  const snapshotDestinations = byAction("snapshot.create").map((op) => op.destination);
  if (sortedJSON(snapshotDestinations) !== sortedJSON(destinationNames)) {
    violations.push("snapshot.create operations must cover exactly the plan's own destinations, one each");
  }
  const retentionDestinations = byAction("retention.apply").map((op) => op.destination);
  if (sortedJSON(retentionDestinations) !== sortedJSON(destinationNames)) {
    violations.push("retention.apply operations must cover exactly the plan's own destinations, one each");
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
  if (readinessIndices.some((i) => i < lastSnapshotOrRetention)) {
    violations.push("readiness.wait must come after every snapshot.create/retention.apply");
  }
  if (maintenanceExitIndex >= 0 && maintenanceExitIndex < lastSnapshotOrRetention) {
    violations.push("maintenance.exit must come after every snapshot.create/retention.apply");
  }

  return violations;
}

// The Restore Flow's own fixed whitelist, same discipline as
// validateBackupPlanOperations above: completeness, per-network/per-
// volume cardinality, and the one hard ordering rule ADR 0006 names by
// name - checkpoint.data-restored is the sole privileged boundary, so
// every data.restore must precede it and config.restore/secret.
// materialize/state.restore must all follow it.
export function validateRestorePlanOperations(plan) {
  const violations = [];
  const ops = plan.operations;
  const byAction = (action) => ops.filter((op) => op.action === action);

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

  const networkResources = byAction("network.create").map((op) => op.resource);
  if (sortedJSON(networkResources) !== sortedJSON(plan.networks)) {
    violations.push("network.create operations must cover exactly the plan's own networks, one each");
  }
  const expectedVolumes = plan.consistencySet.map((entry) => entry.volume);
  const volumeResources = byAction("volume.create").map((op) => op.resource);
  if (sortedJSON(volumeResources) !== sortedJSON(expectedVolumes)) {
    violations.push("volume.create operations must cover exactly the plan's own consistencySet volumes, one each");
  }
  const dataRestoreResources = byAction("data.restore").map((op) => op.resource);
  if (sortedJSON(dataRestoreResources) !== sortedJSON(expectedVolumes)) {
    violations.push("data.restore operations must cover exactly the plan's own consistencySet volumes, one each");
  }

  if (hasDuplicates(ops, (op) => op.id)) violations.push("duplicate operation id");

  if (ops.length > 0) {
    if (ops[0].action !== "runner.install") violations.push("runner.install must be the first operation");
    if (ops[ops.length - 1].action !== "evidence.write") violations.push("evidence.write must be the last operation");
  }

  const checkpointIndex = indexOfAction(ops, "checkpoint.data-restored");
  const dataRestoreIndices = indicesOfAction(ops, "data.restore");
  const configIndex = indexOfAction(ops, "config.restore");
  const secretIndex = indexOfAction(ops, "secret.materialize");
  const stateIndex = indexOfAction(ops, "state.restore");

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

  return violations;
}

// Cross-document bindings a single schema can never check on its own -
// policy -> plan -> manifest -> evidence, all four honestly content-
// addressed and actually referencing each other, not merely fields that
// happen to share a name. Every argument but plan is optional so a
// caller can check a partial bundle (a plan alone, a plan+evidence
// without a manifest, ...); only the checks whose documents are present
// run. Returns an array of violation strings; empty means the bundle is
// coherent.
export function validateBackupBundle({ policy, plan, manifest, evidence } = {}) {
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

  if (policy) {
    const expectedPolicyId = canonicalContentId(policy, ["policyId", "appliedGeneration", "appliedManifestDigest"]);
    if (policy.policyId !== expectedPolicyId) violations.push("policy.policyId does not match its own recomputed content-id");
    if (plan.backupPolicyId !== policy.policyId) violations.push("plan.backupPolicyId does not match the supplied policy's own policyId");
    if (plan.installationId !== policy.installationId) violations.push("plan.installationId does not match the supplied policy's own installationId");
  }

  if (manifest) {
    if (manifest.backupId !== plan.backupId) violations.push("manifest.backupId does not match plan.backupId");
    if (manifest.installationId !== plan.installationId) violations.push("manifest.installationId does not match plan.installationId");
    if (manifest.generation !== plan.generation) violations.push("manifest.generation does not match plan.generation");
    if (!exactSetEquals(manifest.consistencySet, plan.consistencySet, consistencySetEntryKey)) {
      violations.push("manifest.consistencySet does not exactly match plan.consistencySet");
    }
  }

  if (evidence) {
    if (evidence.backupId !== plan.backupId) violations.push("evidence.backupId does not match plan.backupId");
    if (evidence.planId !== plan.planId) violations.push("evidence.planId does not match plan.planId");
    if (evidence.backupPolicyId !== plan.backupPolicyId) violations.push("evidence.backupPolicyId does not match plan.backupPolicyId");
    if (evidence.backupToolLockDigest !== plan.backupToolLockDigest) {
      violations.push("evidence.backupToolLockDigest does not match plan.backupToolLockDigest");
    }
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
  }

  return violations;
}

// The restore-side equivalent of validateBackupBundle above - plan ->
// manifest -> evidence, honestly bound.
export function validateRestoreBundle({ plan, manifest, evidence } = {}) {
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
    if (!exactSetEquals(manifest.consistencySet, plan.consistencySet, consistencySetEntryKey)) {
      violations.push("manifest.consistencySet does not exactly match plan.consistencySet");
    }
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
// Returns an array of violation strings.
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
