// Schema-level AND semantic-level coverage for the eleven backup/restore
// contracts ADR 0006 introduces, plus unit coverage for the pure
// scripts/backup-ids.mjs and scripts/backup-flow.mjs helpers those
// contracts depend on. No real executor exists yet (that's a later PR),
// so every fixture here is hand-built - but every id-bearing fixture
// computes its own id through the actual pure functions (never an
// arbitrary, unrelated sha), and the "happy path" bundle/operations
// fixtures are genuinely complete, honestly self-consistent documents -
// not a single allowlisted operation standing in for a whole flow. A
// review round found the previous version of this file accepted
// one-step "flows" and arbitrary unrelated ids as positive fixtures,
// which validated the schemas' own per-field shape but proved nothing
// about whether a real plan/bundle is actually coherent; this version
// exists specifically to close that gap. The one property every fixture
// is also checked against: no secret value, decrypted content, or
// credential ever fits through any of these schemas (additionalProperties:
// false everywhere, checked here by attempting to smuggle one in and
// confirming it's rejected).

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalContentId, canonicalDocumentDigest, computeBackupId, consistencySetEntryKey, exactSetEquals, hasDuplicates } from "../scripts/backup-ids.mjs";
import { validateBackupBundle, validateBackupPlanOperations, validateRestoreBundle, validateRestoreCommittedGeneration, validateRestorePlanOperations, verifyRecoveryKit } from "../scripts/backup-flow.mjs";
import { sha256 } from "../scripts/digest.mjs";

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
    installationId: "inst-1", baselineGeneration: 3,
    ...overrides,
  };
}

function sha(fill) {
  return "sha256:" + String(fill).repeat(64).slice(0, 64);
}

const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000001";

function consistencySetEntry(overrides = {}) {
  return { service: "schlussel", unit: "schlussel", volume: "schlussel-data", retained: false, ...overrides };
}

function localDestination(overrides = {}) {
  return { name: "onsite", type: "local", path: "/mnt/hof-backups", secretRef: "backup-onsite-key", ...overrides };
}

function s3Destination(overrides = {}) {
  return { name: "offsite", type: "s3", bucket: "hof-backups-example", region: "eu-central-1", secretRef: "backup-offsite-key", ...overrides };
}

// --- The Backup Flow's own complete, correctly-ordered operations list,
// for exactly the two destinations / one consistencySet entry every
// happy-path backup fixture below uses. ---------------------------------

function fullBackupOperations() {
  return [
    { id: "001.maintenance.enter.platform", phase: "maintenance", action: "maintenance.enter", resource: "platform", reason: "begin backup" },
    { id: "002.service.stop.schlussel", phase: "service", action: "service.stop", resource: "schlussel", reason: "quiesce before staging" },
    { id: "003.staging.build.tree", phase: "staging", action: "staging.build", resource: "tree", reason: "build allowlisted staging tree" },
    { id: "004.snapshot.create.onsite", phase: "snapshot", action: "snapshot.create", resource: "onsite", destination: "onsite", reason: "snapshot to onsite" },
    { id: "005.snapshot.create.offsite", phase: "snapshot", action: "snapshot.create", resource: "offsite", destination: "offsite", reason: "snapshot to offsite" },
    { id: "006.retention.apply.onsite", phase: "retention", action: "retention.apply", resource: "onsite", destination: "onsite", reason: "apply retention onsite" },
    { id: "007.retention.apply.offsite", phase: "retention", action: "retention.apply", resource: "offsite", destination: "offsite", reason: "apply retention offsite" },
    { id: "008.service.start.schlussel", phase: "service", action: "service.start", resource: "schlussel", reason: "restart after staging" },
    { id: "009.readiness.wait.platform", phase: "readiness", action: "readiness.wait", resource: "platform", condition: "healthy", reason: "confirm platform healthy" },
    { id: "010.maintenance.exit.platform", phase: "maintenance", action: "maintenance.exit", resource: "platform", reason: "end backup" },
    { id: "011.evidence.write.platform", phase: "evidence", action: "evidence.write", resource: "platform", reason: "record evidence" },
  ];
}

// --- The Restore Flow's own complete, correctly-ordered operations
// list, for exactly the one network / one consistencySet entry every
// happy-path restore fixture below uses. --------------------------------

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

// --- Builders: every id-bearing fixture recomputes its own id from its
// (possibly overridden) content through the real pure functions, unless
// the caller explicitly overrides the id property itself (a deliberate
// tampering test) - so a fixture built with no id override is always
// genuinely, honestly self-consistent. ------------------------------------

function buildBackupPolicy(overrides = {}) {
  const content = {
    apiVersion: "hof.dev/backup-policy/v1",
    installationId: "inst-1",
    appliedGeneration: 3,
    appliedManifestDigest: sha("1"),
    schedule: "03:30",
    destinations: [localDestination(), s3Destination()],
    retention: { daily: 7, weekly: 4, monthly: 6 },
    includeRetainedVolumes: true,
    ...overrides,
  };
  const policyId = "policyId" in overrides ? overrides.policyId : canonicalContentId(content, ["policyId", "appliedGeneration", "appliedManifestDigest"]);
  return { ...content, policyId };
}

function buildBackupPlan(overrides = {}, { policy = buildBackupPolicy() } = {}) {
  const content = {
    apiVersion: "hof.dev/backup-plan/v1",
    backupPolicyId: policy.policyId,
    backupSequence: 1,
    trigger: "manual",
    executable: true,
    target: targetBinding(),
    installationId: "inst-1",
    generation: 3,
    releaseLockDigest: sha("c"),
    backupToolLockDigest: sha("d"),
    consistencySet: [consistencySetEntry()],
    destinations: [localDestination(), s3Destination()],
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

function buildBackupManifest(overrides = {}, { plan = buildBackupPlan() } = {}) {
  return {
    apiVersion: "hof.dev/backup-manifest/v1",
    backupId: plan.backupId,
    createdAt: "2026-09-04T10:00:00Z",
    installationId: plan.installationId,
    generation: plan.generation,
    release: "0.2.3",
    manifestDigest: sha("1"),
    releaseLockDigest: plan.releaseLockDigest,
    catalogDigest: sha("2"),
    composeTemplateDigest: sha("3"),
    backupToolLockDigest: plan.backupToolLockDigest,
    consistencySet: plan.consistencySet,
    sanitizedManifestDigest: sha("f"),
    recoveryKitDigest: sha("e"),
    ...overrides,
  };
}

function buildDestinationResult(overrides = {}) {
  return { destination: "onsite", status: "succeeded", snapshotId: "abc123def456", verifiedAt: "2026-09-04T10:05:00Z", retentionApplied: true, ...overrides };
}

function buildBackupEvidence(overrides = {}, { plan = buildBackupPlan(), manifest = buildBackupManifest({}, { plan }) } = {}) {
  return {
    apiVersion: "hof.dev/backup-evidence/v1",
    operationId: OPERATION_ID,
    backupId: plan.backupId,
    planId: plan.planId,
    backupPolicyId: plan.backupPolicyId,
    manifestDigest: canonicalDocumentDigest(manifest),
    backupToolLockDigest: plan.backupToolLockDigest,
    target: plan.target,
    startedAt: "2026-09-04T10:00:00Z",
    completedAt: "2026-09-04T10:10:00Z",
    status: "succeeded",
    perDestinationResults: [buildDestinationResult({ destination: "onsite" }), buildDestinationResult({ destination: "offsite" })],
    readinessConfirmedAt: "2026-09-04T10:09:00Z",
    abandoned: false,
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

function emptyCleanObservation() {
  return { containers: [], volumes: [], networks: [], units: [], generatedArtifacts: [] };
}

// The historical backup-manifest-v1 this restore is reading, built
// FIRST (unlike the backup side, where plan comes before manifest) -
// restore-plan-v1 pins manifestDigest at approval time (Finding 5), so
// the plan's own content must be computed AFTER, and bound to, this
// manifest, never the other way around.
function buildRestoreManifest(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-manifest/v1",
    backupId: sha("b"),
    createdAt: "2026-09-04T10:00:00Z",
    installationId: "inst-1",
    generation: 3,
    release: "0.2.3",
    manifestDigest: sha("1"),
    releaseLockDigest: sha("c"),
    catalogDigest: sha("2"),
    composeTemplateDigest: sha("3"),
    backupToolLockDigest: sha("d"),
    consistencySet: [consistencySetEntry()],
    sanitizedManifestDigest: sha("f"),
    recoveryKitDigest: sha("e"),
    ...overrides,
  };
}

function buildRestorePlan(overrides = {}, { manifest = buildRestoreManifest() } = {}) {
  const content = {
    apiVersion: "hof.dev/restore-plan/v1",
    executable: true,
    target: restoreTargetBinding(),
    cleanObservation: emptyCleanObservation(),
    backupId: manifest.backupId,
    destinationName: "offsite",
    snapshotId: "abc123def456",
    manifestDigest: canonicalDocumentDigest(manifest),
    source: { installationId: manifest.installationId, generation: manifest.generation, release: manifest.release, releaseLockDigest: manifest.releaseLockDigest },
    recoveryKitDigest: manifest.recoveryKitDigest,
    backupToolLockDigest: manifest.backupToolLockDigest,
    consistencySet: manifest.consistencySet,
    networks: [{ name: "hof-hof", internal: false }],
    operations: fullRestoreOperations(),
    warnings: [],
    blockers: [],
    ...overrides,
  };
  const planId = "planId" in overrides ? overrides.planId : canonicalContentId(content, "planId");
  return { ...content, planId };
}

function buildRestoreEvidence(overrides = {}, { plan = buildRestorePlan() } = {}) {
  return {
    apiVersion: "hof.dev/restore-evidence/v1",
    operationId: OPERATION_ID,
    planId: plan.planId,
    backupId: plan.backupId,
    snapshotId: plan.snapshotId,
    manifestDigest: plan.manifestDigest,
    recoveryKitDigest: plan.recoveryKitDigest,
    backupToolLockDigest: plan.backupToolLockDigest,
    source: plan.source,
    target: restoreTargetBinding({ installationId: "inst-1", baselineGeneration: 0 }),
    startedAt: "2026-09-04T11:00:00Z",
    completedAt: "2026-09-04T11:20:00Z",
    status: "succeeded",
    dataRestoredCheckpointAt: "2026-09-04T11:15:00Z",
    readinessConfirmedAt: "2026-09-04T11:19:00Z",
    abandoned: false,
    ...overrides,
  };
}

// A real, valid age binary-format payload's own shape - magic header,
// one fake recipient stanza, a fake MAC line, then ciphertext bytes -
// long enough to clear recovery-kit-v1's own 200-char minLength and
// genuinely pass verifyRecoveryKit()'s own magic-header check.
function realisticAgePayload() {
  return Buffer.concat([
    Buffer.from("age-encryption.org/v1\n", "utf8"),
    Buffer.from("-> X25519 tvVUyO83i8AZfPd/z8QoBGXlNfxYP8LlsRRQ9d1Byi8\nZzjRTfeXHIexPRZ0/qEIVdCsPKKI+FfL0Fnpu4XLLfw\n", "utf8"),
    Buffer.from("--- Q7GBrAJzhXKZaJbHwvvV4a4FMHFANY9OI9SopN3vOnc\n", "utf8"),
    Buffer.from("fake-ciphertext-payload-bytes-padding-to-clear-minlength-0123456789", "utf8"),
  ]);
}

function buildRecoveryKit(overrides = {}) {
  const ageRecipient = "age1" + "q".repeat(58);
  const payload = realisticAgePayload();
  return {
    apiVersion: "hof.dev/recovery-kit/v1",
    installationId: "inst-1",
    createdAt: "2026-09-04T09:00:00Z",
    createdForGeneration: 3,
    ageRecipient,
    ageRecipientFingerprint: sha256(Buffer.from(ageRecipient, "utf8")),
    contentInventory: ["application-secrets", "tls-private-keys", "backup-destination-credentials"],
    ciphertextDigest: sha256(payload),
    ciphertext: payload.toString("base64"),
    ...overrides,
  };
}

// =============================================================================
// backup-plan-v1
// =============================================================================

test("backup-plan-v1: a genuine, complete manual backup plan, local + S3 destinations, validates", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const plan = buildBackupPlan();
  assert.ok(validate(plan), JSON.stringify(validate.errors));
});

test("backup-plan-v1: a scheduled trigger validates too", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.ok(validate(buildBackupPlan({ trigger: "scheduled" })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: rejects an empty destinations array - a backup with nothing to write to is never executable", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(buildBackupPlan({ destinations: [] })), false);
});

test("backup-plan-v1: rejects an empty consistencySet", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(buildBackupPlan({ consistencySet: [] })), false);
});

test("backup-plan-v1: rejects a local destination missing its required path", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = localDestination();
  delete destination.path;
  assert.equal(validate(buildBackupPlan({ destinations: [destination, s3Destination()] })), false);
});

test("backup-plan-v1: rejects a destination mixing local and s3 fields at once", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const mixed = { ...localDestination(), ...s3Destination(), name: "confused" };
  assert.equal(validate(buildBackupPlan({ destinations: [mixed] })), false);
});

test("backup-plan-v1: rejects a raw credential smuggled into a destination instead of secretRef", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = s3Destination({ accessKeySecret: "AKIAABCDEFGHIJKLMNOP" });
  assert.equal(validate(buildBackupPlan({ destinations: [destination] })), false);
});

test("backup-plan-v1: rejects a credential-bearing S3 endpoint (embedded userinfo, query, or fragment)", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  for (const endpoint of ["https://AKIAABCDEFGH:secret@s3.example.com", "https://s3.example.com/?token=secret", "https://s3.example.com#secret=1"]) {
    const destination = s3Destination({ endpoint });
    assert.equal(validate(buildBackupPlan({ destinations: [destination] })), false, endpoint);
  }
});

test("backup-plan-v1: accepts a real, credential-free S3 endpoint", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = s3Destination({ endpoint: "https://s3.eu-central-1.example.com" });
  assert.ok(validate(buildBackupPlan({ destinations: [destination] })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: rejects a destination name services-v1alpha1 itself would reject (dots, or over 63 chars)", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(buildBackupPlan({ destinations: [localDestination({ name: "on.site" })] })), false, "dots are never valid in a real services.yml destination name");
  assert.equal(validate(buildBackupPlan({ destinations: [localDestination({ name: "a".repeat(64) })] })), false, "over 63 chars is never valid in a real services.yml destination name");
});

test("backup-plan-v1: rejects an unrecognized operation action - no generic executor", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const ops = fullBackupOperations();
  ops[0] = { ...ops[0], action: "shell.run" };
  assert.equal(validate(buildBackupPlan({ operations: ops })), false);
});

test("backup-plan-v1: rejects a phase/action mismatch - snapshot phase with a service.stop action", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const ops = fullBackupOperations();
  ops[3] = { ...ops[3], action: "service.stop" };
  assert.equal(validate(buildBackupPlan({ operations: ops })), false);
});

test("backup-plan-v1: rejects a retention.apply operation missing its own destination - retention is per-destination, never one run-wide step", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const ops = fullBackupOperations();
  delete ops[5].destination;
  assert.equal(validate(buildBackupPlan({ operations: ops })), false);
});

test("backup-plan-v1: rejects a retained consistencySet entry missing its own retained flag", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const entry = consistencySetEntry();
  delete entry.retained;
  assert.equal(validate(buildBackupPlan({ consistencySet: [entry] })), false);
});

test("backup-plan-v1: a retained (disabled-but-kept) volume is a real, legitimate consistency-set member", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const entry = consistencySetEntry({ service: "herold", unit: "herold-backend", volume: "herold-data", retained: true });
  assert.ok(validate(buildBackupPlan({ consistencySet: [entry] })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: executable must faithfully reflect blockers", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(buildBackupPlan({ executable: true, blockers: ["drift detected"] })), false, "executable: true with a real blocker must be rejected");
  assert.equal(validate(buildBackupPlan({ executable: false, blockers: [] })), false, "executable: false with zero blockers must be rejected");
  assert.ok(validate(buildBackupPlan({ executable: false, blockers: ["drift detected"], operations: [] })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: an executable plan with an empty operations list is rejected - nothing to dispatch is never legitimate", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(buildBackupPlan({ executable: true, operations: [] })), false);
});

test("backup-plan-v1: rejects an unsafe (non-integer or over Number.MAX_SAFE_INTEGER) backupSequence", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  // backupSequence: 1.5/oversized is invalid input to computeBackupId
  // itself (it throws) - pin backupId explicitly so this test exercises
  // only the schema's own field-shape check, not id derivation.
  assert.equal(validate(buildBackupPlan({ backupSequence: 1.5, backupId: sha("b") })), false);
  assert.equal(validate(buildBackupPlan({ backupSequence: Number.MAX_SAFE_INTEGER + 2, backupId: sha("b") })), false);
});

// --- backup-plan-v1: the flow itself - completeness, cardinality, ordering ---

test("validateBackupPlanOperations: the full, correctly-ordered two-destination flow has zero violations", () => {
  const plan = buildBackupPlan();
  assert.deepEqual(validateBackupPlanOperations(plan), []);
});

test("validateBackupPlanOperations: flags a snapshot.create missing for one of the two configured destinations", () => {
  const ops = fullBackupOperations().filter((op) => op.id !== "005.snapshot.create.offsite");
  const plan = buildBackupPlan({ operations: ops });
  const violations = validateBackupPlanOperations(plan);
  assert.ok(violations.some((v) => v.includes("snapshot.create")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags a retention.apply missing for one of the two configured destinations", () => {
  const ops = fullBackupOperations().filter((op) => op.id !== "007.retention.apply.offsite");
  const plan = buildBackupPlan({ operations: ops });
  const violations = validateBackupPlanOperations(plan);
  assert.ok(violations.some((v) => v.includes("retention.apply")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags a missing maintenance.enter/exit, staging.build, or evidence.write", () => {
  for (const action of ["maintenance.enter", "maintenance.exit", "staging.build", "evidence.write"]) {
    const ops = fullBackupOperations().filter((op) => op.action !== action);
    const violations = validateBackupPlanOperations(buildBackupPlan({ operations: ops }));
    assert.ok(violations.some((v) => v.includes(action)), `${action}: ${JSON.stringify(violations)}`);
  }
});

test("validateBackupPlanOperations: flags service.start dispatched before every snapshot/retention has run", () => {
  const ops = fullBackupOperations();
  const serviceStart = ops.find((op) => op.action === "service.start");
  const reordered = [ops[0], ops[1], serviceStart, ...ops.filter((op) => op.action !== "service.start").slice(2)];
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: reordered }));
  assert.ok(violations.some((v) => v.includes("finally block")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags a duplicate operation id", () => {
  const ops = fullBackupOperations();
  ops[1] = { ...ops[1], id: ops[0].id };
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("duplicate operation id")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags maintenance.enter not being first, or evidence.write not being last", () => {
  const ops = fullBackupOperations();
  const swapped = [ops[1], ops[0], ...ops.slice(2)];
  assert.ok(validateBackupPlanOperations(buildBackupPlan({ operations: swapped })).some((v) => v.includes("first")));
  const opsEnd = fullBackupOperations();
  const swappedEnd = [...opsEnd.slice(0, -2), opsEnd[opsEnd.length - 1], opsEnd[opsEnd.length - 2]];
  assert.ok(validateBackupPlanOperations(buildBackupPlan({ operations: swappedEnd })).some((v) => v.includes("last")));
});

test("validateBackupPlanOperations: flags a destination's own retention.apply dispatched before that SAME destination's own snapshot.create - checking only aggregate order would miss this", () => {
  const ops = fullBackupOperations();
  const snapshotIndex = ops.findIndex((op) => op.id === "004.snapshot.create.onsite");
  const retentionIndex = ops.findIndex((op) => op.id === "006.retention.apply.onsite");
  [ops[snapshotIndex], ops[retentionIndex]] = [ops[retentionIndex], ops[snapshotIndex]];
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes('retention.apply for destination "onsite" must come after its own snapshot.create')), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags readiness.wait dispatched before service.start", () => {
  const ops = fullBackupOperations();
  const startIndex = ops.findIndex((op) => op.action === "service.start");
  const readinessIndex = ops.findIndex((op) => op.action === "readiness.wait");
  [ops[startIndex], ops[readinessIndex]] = [ops[readinessIndex], ops[startIndex]];
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("service.start must come before every readiness.wait")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags maintenance.exit dispatched before readiness.wait", () => {
  const ops = fullBackupOperations();
  const readinessIndex = ops.findIndex((op) => op.action === "readiness.wait");
  const exitIndex = ops.findIndex((op) => op.action === "maintenance.exit");
  [ops[readinessIndex], ops[exitIndex]] = [ops[exitIndex], ops[readinessIndex]];
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("maintenance.exit must come after every readiness.wait")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags a service.stop/service.start unit-set mismatch - a stopped unit never restarted, or vice versa", () => {
  const ops = fullBackupOperations();
  const stopIndex = ops.findIndex((op) => op.action === "service.stop");
  const mutated = ops.map((op, i) => (i === stopIndex ? { ...op, resource: "some-other-unit" } : op));
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: mutated }));
  assert.ok(violations.some((v) => v.includes("exact same set of units")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: flags a SYMMETRIC duplicate service.stop+service.start pair for the same unit - the set-equality check alone treats two matching duplicates as coherent", () => {
  const ops = fullBackupOperations();
  const stopIndex = ops.findIndex((op) => op.action === "service.stop");
  const startIndex = ops.findIndex((op) => op.action === "service.start");
  const withDupStop = [...ops];
  withDupStop.splice(stopIndex + 1, 0, { ...ops[stopIndex], id: "002b.service.stop.schlussel.dup" });
  const withDupBoth = withDupStop.map((op, i) => op);
  const startIndex2 = withDupBoth.findIndex((op) => op.action === "service.start");
  withDupBoth.splice(startIndex2 + 1, 0, { ...ops[startIndex], id: "008b.service.start.schlussel.dup" });
  const violations = validateBackupPlanOperations(buildBackupPlan({ operations: withDupBoth }));
  assert.ok(violations.some((v) => v.includes("more than one service.stop operation targets the same unit")), JSON.stringify(violations));
  assert.ok(violations.some((v) => v.includes("more than one service.start operation targets the same unit")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags a duplicate service.start for the same unit", () => {
  const ops = fullRestoreOperations();
  const startIndex = ops.findIndex((op) => op.action === "service.start");
  ops.splice(startIndex + 1, 0, { ...ops[startIndex], id: "013b.service.start.schlussel.dup" });
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("more than one service.start operation targets the same unit")), JSON.stringify(violations));
});

test("validateBackupPlanOperations: a blocked plan (executable: false) is never analyzed as an incomplete flow - it never claims to have one", () => {
  const blocked = buildBackupPlan({ executable: false, blockers: ["another operation already in progress"], operations: [] });
  assert.deepEqual(validateBackupPlanOperations(blocked), []);
});

test("validateBackupPlanOperations: flags a duplicate destination name or consistencySet volume at the PLAN level, not just within operations", () => {
  const dupDestinations = validateBackupPlanOperations(buildBackupPlan({ destinations: [localDestination(), localDestination()] }));
  assert.ok(dupDestinations.some((v) => v.includes("plan.destinations has a duplicate")), JSON.stringify(dupDestinations));

  const dupVolumes = validateBackupPlanOperations(buildBackupPlan({ consistencySet: [consistencySetEntry(), consistencySetEntry()] }));
  assert.ok(dupVolumes.some((v) => v.includes("plan.consistencySet has a duplicate")), JSON.stringify(dupVolumes));
});

test("validateBackupPlanOperations: flags a SECOND, uniquely-IDed snapshot.create or retention.apply for a destination already covered - a Map-based cardinality check alone would silently let the second overwrite the first", () => {
  const opsWithDupSnapshot = fullBackupOperations();
  const snapshotIndex = opsWithDupSnapshot.findIndex((op) => op.id === "004.snapshot.create.onsite");
  opsWithDupSnapshot.splice(snapshotIndex + 1, 0, { id: "004b.snapshot.create.onsite.dup", phase: "snapshot", action: "snapshot.create", resource: "onsite", destination: "onsite", reason: "duplicate" });
  const v1 = validateBackupPlanOperations(buildBackupPlan({ operations: opsWithDupSnapshot }));
  assert.ok(v1.some((v) => v.includes("more than one snapshot.create operation targets the same destination")), JSON.stringify(v1));

  const opsWithDupRetention = fullBackupOperations();
  const retentionIndex = opsWithDupRetention.findIndex((op) => op.id === "006.retention.apply.onsite");
  opsWithDupRetention.splice(retentionIndex + 1, 0, { id: "006b.retention.apply.onsite.dup", phase: "retention", action: "retention.apply", resource: "onsite", destination: "onsite", reason: "duplicate" });
  const v2 = validateBackupPlanOperations(buildBackupPlan({ operations: opsWithDupRetention }));
  assert.ok(v2.some((v) => v.includes("more than one retention.apply operation targets the same destination")), JSON.stringify(v2));
});

// =============================================================================
// restore-plan-v1
// =============================================================================

test("restore-plan-v1: a genuine, complete clean-host restore plan validates", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.ok(validate(buildRestorePlan()), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects a target that already has an installationId - restore is never in-place", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ target: restoreTargetBinding({ installationId: "some-existing-install" }) })), false);
});

test("restore-plan-v1: rejects a target with a non-zero baselineGeneration - restore requires a genuinely clean host", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ target: restoreTargetBinding({ baselineGeneration: 1 }) })), false);
});

test("restore-plan-v1: rejects an SSH-mode target with no host key", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ target: restoreTargetBinding({ hostKeySha256: null }) })), false);
});

test("restore-plan-v1: rejects a cleanObservation carrying any observed resource - clean means structurally empty, not merely claimed", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  for (const key of ["containers", "volumes", "networks", "units", "generatedArtifacts"]) {
    const observation = emptyCleanObservation();
    observation[key] = ["something-found"];
    assert.equal(validate(buildRestorePlan({ cleanObservation: observation })), false, key);
  }
});

test("restore-plan-v1: rejects a missing cleanObservation category", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const observation = emptyCleanObservation();
  delete observation.units;
  assert.equal(validate(buildRestorePlan({ cleanObservation: observation })), false);
});

test("restore-plan-v1: rejects a plan missing its own pinned snapshotId or manifestDigest - approval must pin what will actually be restored", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const withoutSnapshot = buildRestorePlan();
  delete withoutSnapshot.snapshotId;
  assert.equal(validate(withoutSnapshot), false);
  const withoutManifest = buildRestorePlan();
  delete withoutManifest.manifestDigest;
  assert.equal(validate(withoutManifest), false);
});

test("restore-plan-v1: source stays distinct from target - both present, never merged into one object", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const plan = buildRestorePlan();
  assert.equal(plan.target.installationId, null);
  assert.equal(plan.source.installationId, "inst-1");
  assert.ok(validate(plan), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects an unrecognized operation action - no generic executor", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const ops = fullRestoreOperations();
  ops[0] = { ...ops[0], action: "shell.run" };
  assert.equal(validate(buildRestorePlan({ operations: ops })), false);
});

test("restore-plan-v1: rejects a phase/action mismatch - checkpoint phase with a config.restore action", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const ops = fullRestoreOperations();
  ops[8] = { ...ops[8], action: "config.restore" };
  assert.equal(validate(buildRestorePlan({ operations: ops })), false);
});

test("restore-plan-v1: a network.create operation under the data phase validates - restore must create its own network on a clean host", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.ok(validate(buildRestorePlan()), JSON.stringify(validate.errors));
  assert.ok(fullRestoreOperations().some((op) => op.action === "network.create"));
});

test("restore-plan-v1: rejects an empty networks array - a clean target always needs at least one created", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ networks: [] })), false);
});

test("restore-plan-v1: rejects a network named by its bare logical key instead of its real physical name", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ networks: [{ name: "hof", internal: false }] })), false);
});

test("restore-plan-v1: rejects a plausible-looking but never-actually-producible physical name - only hof-hof and hof-wachter-internal exist, a hof- prefix pattern alone was too permissive", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ networks: [{ name: "hof-unrelated", internal: false }] })), false);
});

test("restore-plan-v1: rejects internal: false for hof-wachter-internal, and internal: true for any other network - only that one network is ever internal", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ networks: [{ name: "hof-wachter-internal", internal: false }] })), false);
  assert.equal(validate(buildRestorePlan({ networks: [{ name: "hof-hof", internal: true }] })), false);
  assert.ok(validate(buildRestorePlan({ networks: [{ name: "hof-wachter-internal", internal: true }] })), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects a missing source field", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const plan = buildRestorePlan();
  delete plan.source.releaseLockDigest;
  assert.equal(validate(plan), false);
});

test("restore-plan-v1: executable must faithfully reflect blockers", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(buildRestorePlan({ executable: true, blockers: ["target not clean"] })), false);
  assert.equal(validate(buildRestorePlan({ executable: false, blockers: [] })), false);
});

// --- restore-plan-v1: the flow itself ---------------------------------------

test("validateRestorePlanOperations: the full, correctly-ordered flow has zero violations", () => {
  assert.deepEqual(validateRestorePlanOperations(buildRestorePlan()), []);
});

test("validateRestorePlanOperations: flags a data.restore dispatched after checkpoint.data-restored", () => {
  const ops = fullRestoreOperations();
  const dataRestoreIndex = ops.findIndex((op) => op.action === "data.restore");
  const checkpointIndex = ops.findIndex((op) => op.action === "checkpoint.data-restored");
  [ops[dataRestoreIndex], ops[checkpointIndex]] = [ops[checkpointIndex], ops[dataRestoreIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("privileged boundary")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags config.restore/secret.materialize/state.restore dispatched before checkpoint.data-restored", () => {
  for (const action of ["config.restore", "secret.materialize", "state.restore"]) {
    const ops = fullRestoreOperations();
    const actionIndex = ops.findIndex((op) => op.action === action);
    const checkpointIndex = ops.findIndex((op) => op.action === "checkpoint.data-restored");
    [ops[actionIndex], ops[checkpointIndex]] = [ops[checkpointIndex], ops[actionIndex]];
    const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
    assert.ok(violations.some((v) => v.includes(action)), `${action}: ${JSON.stringify(violations)}`);
  }
});

test("validateRestorePlanOperations: flags a network.create missing for a configured network", () => {
  const ops = fullRestoreOperations().filter((op) => op.action !== "network.create");
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("network.create")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags a volume.create or data.restore missing for a consistencySet volume", () => {
  for (const action of ["volume.create", "data.restore"]) {
    const ops = fullRestoreOperations().filter((op) => op.action !== action);
    const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
    assert.ok(violations.some((v) => v.includes(action)), `${action}: ${JSON.stringify(violations)}`);
  }
});

test("validateRestorePlanOperations: flags a duplicate operation id", () => {
  const ops = fullRestoreOperations();
  ops[1] = { ...ops[1], id: ops[0].id };
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("duplicate operation id")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags a volume's own data.restore dispatched before that SAME volume's own volume.create", () => {
  const ops = fullRestoreOperations();
  const volumeIndex = ops.findIndex((op) => op.action === "volume.create");
  const dataRestoreIndex = ops.findIndex((op) => op.action === "data.restore");
  [ops[volumeIndex], ops[dataRestoreIndex]] = [ops[dataRestoreIndex], ops[volumeIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("must come after its own volume.create")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags volume.create dispatched before network.create", () => {
  const ops = fullRestoreOperations();
  const networkIndex = ops.findIndex((op) => op.action === "network.create");
  const volumeIndex = ops.findIndex((op) => op.action === "volume.create");
  [ops[networkIndex], ops[volumeIndex]] = [ops[volumeIndex], ops[networkIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("every volume.create must come after every network.create")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags manifest.verify/database.integrity-check dispatched after checkpoint.data-restored", () => {
  const ops = fullRestoreOperations();
  const verifyIndex = ops.findIndex((op) => op.action === "manifest.verify");
  const checkpointIndex = ops.findIndex((op) => op.action === "checkpoint.data-restored");
  [ops[verifyIndex], ops[checkpointIndex]] = [ops[checkpointIndex], ops[verifyIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("checkpoint.data-restored must come after manifest.verify")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags service.start dispatched before config.restore/secret.materialize/state.restore", () => {
  const ops = fullRestoreOperations();
  const startIndex = ops.findIndex((op) => op.action === "service.start");
  const configIndex = ops.findIndex((op) => op.action === "config.restore");
  [ops[startIndex], ops[configIndex]] = [ops[configIndex], ops[startIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("service.start must come after config.restore")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: flags readiness.wait dispatched before service.start", () => {
  const ops = fullRestoreOperations();
  const startIndex = ops.findIndex((op) => op.action === "service.start");
  const readinessIndex = ops.findIndex((op) => op.action === "readiness.wait");
  [ops[startIndex], ops[readinessIndex]] = [ops[readinessIndex], ops[startIndex]];
  const violations = validateRestorePlanOperations(buildRestorePlan({ operations: ops }));
  assert.ok(violations.some((v) => v.includes("readiness.wait must come after every service.start")), JSON.stringify(violations));
});

test("validateRestorePlanOperations: a blocked plan (executable: false) is never analyzed as an incomplete flow", () => {
  const blocked = buildRestorePlan({ executable: false, blockers: ["target not clean"], operations: [] });
  assert.deepEqual(validateRestorePlanOperations(blocked), []);
});

test("validateRestorePlanOperations: flags a duplicate consistencySet volume or network at the PLAN level", () => {
  const dupVolumes = validateRestorePlanOperations(buildRestorePlan({ consistencySet: [consistencySetEntry(), consistencySetEntry()] }));
  assert.ok(dupVolumes.some((v) => v.includes("plan.consistencySet has a duplicate")), JSON.stringify(dupVolumes));

  const dupNetworks = validateRestorePlanOperations(buildRestorePlan({ networks: [{ name: "hof-hof", internal: false }, { name: "hof-hof", internal: false }] }));
  assert.ok(dupNetworks.some((v) => v.includes("plan.networks has a duplicate")), JSON.stringify(dupNetworks));
});

test("validateRestorePlanOperations: flags a SECOND, uniquely-IDed volume.create, data.restore, or network.create for a resource already covered", () => {
  const opsWithDupVolume = fullRestoreOperations();
  const volumeIndex = opsWithDupVolume.findIndex((op) => op.id === "005.volume.create.schlussel-data");
  opsWithDupVolume.splice(volumeIndex + 1, 0, { id: "005b.volume.create.schlussel-data.dup", phase: "data", action: "volume.create", resource: "schlussel-data", reason: "duplicate" });
  const v1 = validateRestorePlanOperations(buildRestorePlan({ operations: opsWithDupVolume }));
  assert.ok(v1.some((v) => v.includes("more than one volume.create operation targets the same resource")), JSON.stringify(v1));

  const opsWithDupDataRestore = fullRestoreOperations();
  const dataRestoreIndex = opsWithDupDataRestore.findIndex((op) => op.id === "006.data.restore.schlussel-data");
  opsWithDupDataRestore.splice(dataRestoreIndex + 1, 0, { id: "006b.data.restore.schlussel-data.dup", phase: "data", action: "data.restore", resource: "schlussel-data", reason: "duplicate" });
  const v2 = validateRestorePlanOperations(buildRestorePlan({ operations: opsWithDupDataRestore }));
  assert.ok(v2.some((v) => v.includes("more than one data.restore operation targets the same resource")), JSON.stringify(v2));

  const opsWithDupNetwork = fullRestoreOperations();
  const networkIndex = opsWithDupNetwork.findIndex((op) => op.id === "004.network.create.hof-hof");
  opsWithDupNetwork.splice(networkIndex + 1, 0, { id: "004b.network.create.hof-hof.dup", phase: "data", action: "network.create", resource: "hof-hof", reason: "duplicate" });
  const v3 = validateRestorePlanOperations(buildRestorePlan({ operations: opsWithDupNetwork }));
  assert.ok(v3.some((v) => v.includes("more than one network.create operation targets the same network")), JSON.stringify(v3));
});

test("validateRestorePlanOperations: flags target.verify-clean after snapshot.verify, or snapshot.verify after network.create - nothing may be provisioned before the target and snapshot are both confirmed genuine", () => {
  const opsSwapVerify = fullRestoreOperations();
  const targetVerifyIndex = opsSwapVerify.findIndex((op) => op.action === "target.verify-clean");
  const snapshotVerifyIndex = opsSwapVerify.findIndex((op) => op.action === "snapshot.verify");
  [opsSwapVerify[targetVerifyIndex], opsSwapVerify[snapshotVerifyIndex]] = [opsSwapVerify[snapshotVerifyIndex], opsSwapVerify[targetVerifyIndex]];
  const v1 = validateRestorePlanOperations(buildRestorePlan({ operations: opsSwapVerify }));
  assert.ok(v1.some((v) => v.includes("target.verify-clean must come before snapshot.verify")), JSON.stringify(v1));

  const opsSnapshotAfterNetwork = fullRestoreOperations();
  const snapshotVerifyIndex2 = opsSnapshotAfterNetwork.findIndex((op) => op.action === "snapshot.verify");
  const networkIndex2 = opsSnapshotAfterNetwork.findIndex((op) => op.action === "network.create");
  [opsSnapshotAfterNetwork[snapshotVerifyIndex2], opsSnapshotAfterNetwork[networkIndex2]] = [opsSnapshotAfterNetwork[networkIndex2], opsSnapshotAfterNetwork[snapshotVerifyIndex2]];
  const v2 = validateRestorePlanOperations(buildRestorePlan({ operations: opsSnapshotAfterNetwork }));
  assert.ok(v2.some((v) => v.includes("snapshot.verify must come before every network.create")), JSON.stringify(v2));
});

// =============================================================================
// backup-manifest-v1
// =============================================================================

test("backup-manifest-v1: a genuine manifest written into a real snapshot validates", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  assert.ok(validate(buildBackupManifest()), JSON.stringify(validate.errors));
});

test("backup-manifest-v1: rejects a missing digest", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  const manifest = buildBackupManifest();
  delete manifest.composeTemplateDigest;
  assert.equal(validate(manifest), false);
});

test("backup-manifest-v1: rejects the old permissive-boolean shape for sanitizedManifest/recoveryKit inclusion - a digest is required now, not a boolean claim", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  const manifest = buildBackupManifest();
  delete manifest.sanitizedManifestDigest;
  delete manifest.recoveryKitDigest;
  manifest.sanitizedManifestIncluded = true;
  manifest.recoveryStoreIncluded = true;
  assert.equal(validate(manifest), false);
});

test("backup-manifest-v1: rejects a raw secret value smuggled in", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  assert.equal(validate(buildBackupManifest({ recoveryAgeIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

// =============================================================================
// backup-evidence-v1
// =============================================================================

test("backup-evidence-v1: a fully successful backup's evidence validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.ok(validate(buildBackupEvidence()), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects evidence missing its plan/policy/manifest/tool-lock bindings", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  for (const field of ["planId", "backupPolicyId", "manifestDigest", "backupToolLockDigest"]) {
    const evidence = buildBackupEvidence();
    delete evidence[field];
    assert.equal(validate(evidence), false, `missing ${field} must be rejected`);
  }
});

test("backup-evidence-v1: status succeeded is rejected if any destination actually failed", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = buildBackupEvidence({
    perDestinationResults: [buildDestinationResult({ destination: "onsite" }), buildDestinationResult({ destination: "offsite", status: "failed", error: "connection timed out", snapshotId: undefined, verifiedAt: undefined, retentionApplied: undefined })],
  });
  assert.equal(validate(evidence), false);
});

test("backup-evidence-v1: rejects status succeeded with an empty perDestinationResults - an empty result set is never a real success", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ perDestinationResults: [] })), false);
});

test("backup-evidence-v1: a real partial result (one destination succeeded, one failed) validates as status: partial", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = buildBackupEvidence({
    status: "partial",
    perDestinationResults: [buildDestinationResult({ destination: "onsite" }), { destination: "offsite", status: "failed", error: "connection timed out" }],
    readinessConfirmedAt: "2026-09-04T10:09:00Z",
  });
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects status: partial when every destination actually succeeded", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ status: "partial" })), false);
});

test("backup-evidence-v1: rejects status: failed when a destination actually succeeded - never a silent downgrade of a real success", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ status: "failed" })), false);
});

test("backup-evidence-v1: status: failed with zero destination attempts (crashed before any snapshot.create ran) validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.ok(validate(buildBackupEvidence({ status: "failed", perDestinationResults: [], readinessConfirmedAt: null })), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: a failed destination result requires a sanitized error and forbids snapshotId/verifiedAt/retentionApplied", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed" }], readinessConfirmedAt: null })), false, "failed with no error must be rejected");
  assert.equal(
    validate(buildBackupEvidence({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed", error: "timeout", snapshotId: "abc" }], readinessConfirmedAt: null })),
    false,
    "failed must never also carry a snapshotId",
  );
  assert.equal(
    validate(buildBackupEvidence({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed", error: "timeout", retentionApplied: true }], readinessConfirmedAt: null })),
    false,
    "failed must never also claim retentionApplied",
  );
});

test("backup-evidence-v1: a succeeded destination result requires snapshotId and verifiedAt, forbids error", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ perDestinationResults: [{ destination: "onsite", status: "succeeded" }, buildDestinationResult({ destination: "offsite" })] })), false);
  assert.equal(validate(buildBackupEvidence({ perDestinationResults: [{ ...buildDestinationResult({ destination: "onsite" }), error: "should not be here" }, buildDestinationResult({ destination: "offsite" })] })), false);
});

test("backup-evidence-v1: a succeeded destination whose own retention never completed is still a real success, with retentionApplied simply absent", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const result = buildDestinationResult({ destination: "onsite" });
  delete result.retentionApplied;
  assert.ok(validate(buildBackupEvidence({ perDestinationResults: [result, buildDestinationResult({ destination: "offsite" })] })), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects retentionApplied: false - presence itself is the true signal, false is never a legitimate value", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ perDestinationResults: [buildDestinationResult({ destination: "onsite", retentionApplied: false }), buildDestinationResult({ destination: "offsite" })] })), false);
});

test("backup-evidence-v1: rejects status: succeeded with readinessConfirmedAt null - snapshots all succeeding is not the same claim as the finally block completing", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(buildBackupEvidence({ readinessConfirmedAt: null })), false);
});

test("backup-evidence-v1: rejects a missing abandoned field, and rejects status: succeeded claiming abandoned: true", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const missing = buildBackupEvidence();
  delete missing.abandoned;
  assert.equal(validate(missing), false);
  assert.equal(validate(buildBackupEvidence({ abandoned: true })), false, "a real success can never also be an abandonment");
});

test("backup-evidence-v1: a genuinely abandoned, terminal failed evidence validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = buildBackupEvidence({
    status: "failed", perDestinationResults: [], readinessConfirmedAt: null, abandoned: true,
  });
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

// =============================================================================
// restore-evidence-v1
// =============================================================================

test("restore-evidence-v1: a fully successful restore's evidence validates", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.ok(validate(buildRestoreEvidence()), JSON.stringify(validate.errors));
});

test("restore-evidence-v1: rejects evidence missing its plan/snapshot/manifest/kit/tool-lock bindings", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  for (const field of ["planId", "snapshotId", "manifestDigest", "recoveryKitDigest", "backupToolLockDigest"]) {
    const evidence = buildRestoreEvidence();
    delete evidence[field];
    assert.equal(validate(evidence), false, `missing ${field} must be rejected`);
  }
});

test("restore-evidence-v1: a failed restore requires a sanitized error", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.equal(
    validate(buildRestoreEvidence({ status: "failed", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    false,
    "failed with no error must be rejected",
  );
  assert.ok(
    validate(buildRestoreEvidence({ status: "failed", error: "database integrity check failed", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    JSON.stringify(validate.errors),
  );
});

test("restore-evidence-v1: interrupted before checkpoint.data-restored validates with both checkpoints null", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.ok(
    validate(buildRestoreEvidence({ status: "failed", error: "connection lost mid-restore", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    JSON.stringify(validate.errors),
  );
});

test("restore-evidence-v1: a succeeded restore requires both checkpoints actually set", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.equal(validate(buildRestoreEvidence({ readinessConfirmedAt: null })), false);
  assert.equal(validate(buildRestoreEvidence({ dataRestoredCheckpointAt: null })), false);
});

test("restore-evidence-v1: keeps source and target as two distinct identities, never merged", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  const evidence = buildRestoreEvidence();
  assert.notEqual(evidence.source.generation, undefined);
  assert.equal(evidence.target.baselineGeneration, 0, "the target's own baseline was 0 (clean) before this restore ran");
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

test("restore-evidence-v1: rejects a failed restore claiming readinessConfirmedAt is non-null - readiness.wait is the step immediately before evidence.write", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  const evidence = buildRestoreEvidence({
    status: "failed", error: "integrity check failed", readinessConfirmedAt: "2026-09-04T11:19:00Z",
  });
  assert.equal(validate(evidence), false);
});

test("restore-evidence-v1: rejects a missing abandoned field, and rejects status: succeeded claiming abandoned: true", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  const missing = buildRestoreEvidence();
  delete missing.abandoned;
  assert.equal(validate(missing), false);
  assert.equal(validate(buildRestoreEvidence({ abandoned: true })), false, "a real success can never also be an abandonment");
});

test("restore-evidence-v1: a genuinely abandoned, terminal failed evidence validates - restore has no guaranteed finally block, so this is its only path to a terminal state when stuck", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  const evidence = buildRestoreEvidence({
    status: "failed", error: "operator abandoned a stuck operation", dataRestoredCheckpointAt: null, readinessConfirmedAt: null, abandoned: true,
  });
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

// =============================================================================
// backup-tool-lock-v1
// =============================================================================

function backupToolLockFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-tool-lock/v1",
    source: "https://github.com/vrubovoy/hof-ops",
    revision: "a".repeat(40),
    sourceTag: "backup-tool-v1.0.0",
    toolVersion: "1.0.0",
    image: "ghcr.io/vrubovoy/hof-ops-ee@sha256:" + "f".repeat(64),
    signatureIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/backup-tool.yml@refs/tags/backup-tool-v1.0.0",
    signatureOidcIssuer: "https://token.actions.githubusercontent.com",
    provenanceDigest: sha("6"),
    sbomDigest: sha("7"),
    pinnedTools: { restic: "0.16.4", sops: "3.9.0", age: "1.2.0" },
    compatibility: {
      backupPlanApiVersion: "hof.dev/backup-plan/v1",
      restorePlanApiVersion: "hof.dev/restore-plan/v1",
      backupPolicyApiVersion: "hof.dev/backup-policy/v1",
      recoveryKitApiVersion: "hof.dev/recovery-kit/v1",
      backupManifestApiVersion: "hof.dev/backup-manifest/v1",
      backupEvidenceApiVersion: "hof.dev/backup-evidence/v1",
      restoreEvidenceApiVersion: "hof.dev/restore-evidence/v1",
      operationLockApiVersion: "hof.dev/operation-lock/v2",
      operationJournalApiVersion: "hof.dev/operation-journal/v2",
      operationEventApiVersion: "hof.dev/operation-event/v2",
    },
    ...overrides,
  };
}

test("backup-tool-lock-v1: a genuine signed lock validates", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  assert.ok(validate(backupToolLockFixture()), JSON.stringify(validate.errors));
});

test("backup-tool-lock-v1: rejects a plain platform vX.Y.Z tag - must be backup-tool-vX.Y.Z, never collide with a platform release tag", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  assert.equal(validate(backupToolLockFixture({ sourceTag: "v1.0.0" })), false);
});

test("backup-tool-lock-v1: rejects an Execution Environment ee-vX.Y.Z tag - must not collide with that namespace either", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  assert.equal(validate(backupToolLockFixture({ sourceTag: "ee-v1.0.0" })), false);
});

test("backup-tool-lock-v1: rejects a tagged (not digest-pinned) image", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  assert.equal(validate(backupToolLockFixture({ image: "ghcr.io/vrubovoy/hof-ops-ee:v1.0.0" })), false);
});

test("backup-tool-lock-v1: rejects a missing pinned tool version", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  const lock = backupToolLockFixture();
  delete lock.pinnedTools.age;
  assert.equal(validate(lock), false);
});

test("backup-tool-lock-v1: rejects a missing toolVersion", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  const lock = backupToolLockFixture();
  delete lock.toolVersion;
  assert.equal(validate(lock), false);
});

test("backup-tool-lock-v1: rejects a missing or incomplete compatibility declaration", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  const missing = backupToolLockFixture();
  delete missing.compatibility;
  assert.equal(validate(missing), false, "missing compatibility entirely must be rejected");
  const incomplete = backupToolLockFixture();
  delete incomplete.compatibility.operationEventApiVersion;
  assert.equal(validate(incomplete), false, "an incomplete compatibility declaration must be rejected");
});

test("backup-tool-lock-v1: rejects a compatibility declaration naming a version it doesn't actually mean", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  const lock = backupToolLockFixture();
  lock.compatibility.operationEventApiVersion = "hof.dev/operation-event/v1";
  assert.equal(validate(lock), false);
});

test("backup-tool-lock-v1: compatibility must also declare the manifest and both evidence apiVersions - a runner that can produce plans but not verify what it wrote is only half-declared", async () => {
  const validate = await validatorFor("backup-tool-lock-v1.schema.json");
  for (const field of ["backupManifestApiVersion", "backupEvidenceApiVersion", "restoreEvidenceApiVersion"]) {
    const lock = backupToolLockFixture();
    delete lock.compatibility[field];
    assert.equal(validate(lock), false, field);
  }
});

// =============================================================================
// backup-policy-v1
// =============================================================================

test("backup-policy-v1: a genuine applied policy validates", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.ok(validate(buildBackupPolicy()), JSON.stringify(validate.errors));
});

test("backup-policy-v1: rejects includeRetainedVolumes: false - the fixed platform rule for this policy version", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(buildBackupPolicy({ includeRetainedVolumes: false })), false);
});

test("backup-policy-v1: rejects a schedule outside HH:MM (target-local time, never a cron expression)", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(buildBackupPolicy({ schedule: "0 3 * * *" })), false);
  assert.equal(validate(buildBackupPolicy({ schedule: "24:00" })), false);
});

test("backup-policy-v1: rejects an empty destinations array", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(buildBackupPolicy({ destinations: [] })), false);
});

test("backup-policy-v1: rejects a credential-bearing S3 endpoint", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  const destination = s3Destination({ endpoint: "https://key:secret@s3.example.com" });
  assert.equal(validate(buildBackupPolicy({ destinations: [destination] })), false);
});

test("backup-policy-v1: rejects a destination name services-v1alpha1 itself would reject", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(buildBackupPolicy({ destinations: [localDestination({ name: "on.site" })] })), false);
});

test("backup-policy-v1: rejects a raw credential smuggled in", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(buildBackupPolicy({ rootAgeIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

test("backup-policy-v1: policyId is unaffected by appliedGeneration/appliedManifestDigest - an unrelated apply reconfirming the same policy never mints a new one", () => {
  const a = buildBackupPolicy({ appliedGeneration: 3, appliedManifestDigest: sha("1") });
  const b = buildBackupPolicy({ appliedGeneration: 9, appliedManifestDigest: sha("9") });
  assert.equal(a.policyId, b.policyId, "same backup-relevant content, different reconfirmation metadata, must be the same policyId");
});

test("backup-policy-v1: policyId DOES change when the backup-relevant content itself changes", () => {
  const a = buildBackupPolicy({ schedule: "03:30" });
  const b = buildBackupPolicy({ schedule: "04:30" });
  assert.notEqual(a.policyId, b.policyId);
});

// =============================================================================
// recovery-kit-v1
// =============================================================================

test("recovery-kit-v1: a genuine recovery kit validates", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.ok(validate(buildRecoveryKit()), JSON.stringify(validate.errors));
});

test("recovery-kit-v1: rejects an empty contentInventory", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ contentInventory: [] })), false);
});

test("recovery-kit-v1: rejects a duplicate contentInventory category", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ contentInventory: ["application-secrets", "application-secrets"] })), false);
});

test("recovery-kit-v1: rejects a contentInventory category outside the fixed, closed set", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ contentInventory: ["ssh-host-keys"] })), false);
});

test("recovery-kit-v1: rejects a malformed age recipient", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ ageRecipient: "not-an-age-recipient" })), false);
});

test("recovery-kit-v1: rejects a private age identity smuggled in - the recipient is public, the identity never appears here", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ ageIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

test("recovery-kit-v1: rejects a plaintext value smuggled in under any other field name", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(buildRecoveryKit({ plaintextPreview: "hunter2" })), false);
});

test("recovery-kit-v1: schema alone accepts a base64'd plaintext string long enough to clear minLength - this is exactly why verifyRecoveryKit exists", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  const plaintext = Buffer.from("hunter2".repeat(40)).toString("base64");
  const kit = buildRecoveryKit({ ciphertext: plaintext, ciphertextDigest: sha256(Buffer.from(plaintext, "base64")) });
  assert.ok(validate(kit), "the schema on its own cannot tell this apart from a real payload");
  assert.ok(verifyRecoveryKit(kit).length > 0, "but the pure verifier must catch the missing age magic header");
});

// --- recovery-kit-v1: the pure verifier -------------------------------------

test("verifyRecoveryKit: a genuine kit has zero violations", () => {
  assert.deepEqual(verifyRecoveryKit(buildRecoveryKit()), []);
});

test("verifyRecoveryKit: flags a ciphertextDigest that doesn't match the decoded ciphertext", () => {
  const violations = verifyRecoveryKit(buildRecoveryKit({ ciphertextDigest: sha("0") }));
  assert.ok(violations.some((v) => v.includes("ciphertextDigest")), JSON.stringify(violations));
});

test("verifyRecoveryKit: flags an ageRecipientFingerprint that doesn't match the recomputed digest of ageRecipient", () => {
  const violations = verifyRecoveryKit(buildRecoveryKit({ ageRecipientFingerprint: sha("0") }));
  assert.ok(violations.some((v) => v.includes("ageRecipientFingerprint")), JSON.stringify(violations));
});

test("verifyRecoveryKit: flags ciphertext missing the real age magic header, even though it's valid base64", () => {
  const plaintext = Buffer.from("not-a-real-age-payload".repeat(10));
  const violations = verifyRecoveryKit(buildRecoveryKit({ ciphertext: plaintext.toString("base64"), ciphertextDigest: sha256(plaintext) }));
  assert.ok(violations.some((v) => v.includes("magic header")), JSON.stringify(violations));
});

// =============================================================================
// Cross-document bundle bindings (scripts/backup-flow.mjs)
// =============================================================================

test("validateBackupBundle: a genuinely coherent policy/plan/manifest/evidence bundle has zero violations", () => {
  const policy = buildBackupPolicy();
  const plan = buildBackupPlan({}, { policy });
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({}, { plan, manifest });
  assert.deepEqual(validateBackupBundle({ policy, plan, manifest, evidence }), []);
});

test("validateBackupBundle: flags a plan whose planId doesn't match its own recomputed content-id", () => {
  const plan = buildBackupPlan({ planId: sha("0") });
  const violations = validateBackupBundle({ plan });
  assert.ok(violations.some((v) => v.includes("planId")), JSON.stringify(violations));
});

test("validateBackupBundle: flags a plan whose backupId doesn't match its own recomputed domain-separated id", () => {
  const plan = buildBackupPlan({ backupId: sha("0") });
  const violations = validateBackupBundle({ plan });
  assert.ok(violations.some((v) => v.includes("backupId does not match")), JSON.stringify(violations));
});

test("validateBackupBundle: flags a plan whose target binding describes a different installation/generation than the plan itself declares - even with no policy supplied", () => {
  const wrongInstallation = buildBackupPlan({ target: targetBinding({ installationId: "some-other-installation" }) });
  const v1 = validateBackupBundle({ plan: wrongInstallation });
  assert.ok(v1.some((v) => v.includes("plan.target.installationId does not match plan.installationId")), JSON.stringify(v1));

  const wrongGeneration = buildBackupPlan({ target: targetBinding({ baselineGeneration: 99 }) });
  const v2 = validateBackupBundle({ plan: wrongGeneration });
  assert.ok(v2.some((v) => v.includes("plan.target.baselineGeneration does not match plan.generation")), JSON.stringify(v2));
});

test("validateBackupBundle: flags a plan bound to a policy it doesn't actually reference", () => {
  const policy = buildBackupPolicy();
  const otherPolicy = buildBackupPolicy({ schedule: "05:00" });
  const plan = buildBackupPlan({ backupPolicyId: otherPolicy.policyId }, { policy });
  const violations = validateBackupBundle({ policy, plan });
  assert.ok(violations.some((v) => v.includes("backupPolicyId")), JSON.stringify(violations));
});

test("validateBackupBundle: flags a manifest whose consistencySet doesn't exactly match the plan's own", () => {
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({ consistencySet: [consistencySetEntry({ volume: "different-volume" })] }, { plan });
  const violations = validateBackupBundle({ plan, manifest });
  assert.ok(violations.some((v) => v.includes("consistencySet")), JSON.stringify(violations));
});

test("validateBackupBundle: flags evidence naming an unrelated manifest (manifestDigest doesn't match the supplied manifest's own recomputed digest)", () => {
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({ manifestDigest: sha("0") }, { plan, manifest });
  const violations = validateBackupBundle({ plan, manifest, evidence });
  assert.ok(violations.some((v) => v.includes("manifestDigest")), JSON.stringify(violations));
});

test("validateBackupBundle: flags a succeeded evidence reporting only a subset of the plan's own configured destinations", () => {
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({ perDestinationResults: [buildDestinationResult({ destination: "onsite" })] }, { plan, manifest });
  const violations = validateBackupBundle({ plan, manifest, evidence });
  assert.ok(violations.some((v) => v.includes("every configured destination")), JSON.stringify(violations));
});

test("validateBackupBundle: flags evidence naming a destination the plan never configured", () => {
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({
    perDestinationResults: [buildDestinationResult({ destination: "onsite" }), buildDestinationResult({ destination: "offsite" }), buildDestinationResult({ destination: "unknown-dest" })],
  }, { plan, manifest });
  const violations = validateBackupBundle({ plan, manifest, evidence });
  assert.ok(violations.some((v) => v.includes("not in the plan")), JSON.stringify(violations));
});

test("validateBackupBundle: flags evidence with a duplicate destination result", () => {
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({
    perDestinationResults: [buildDestinationResult({ destination: "onsite" }), buildDestinationResult({ destination: "onsite" })],
  }, { plan, manifest });
  const violations = validateBackupBundle({ plan, manifest, evidence });
  assert.ok(violations.some((v) => v.includes("duplicate destination")), JSON.stringify(violations));
});

test("validateBackupBundle: a plan referencing the right policyId while actually using different destinations or retention bypasses the approved policy - must be flagged", () => {
  const policy = buildBackupPolicy();
  const planDifferentDestinations = buildBackupPlan({ destinations: [localDestination({ path: "/mnt/a-different-mount" }), s3Destination()] }, { policy });
  const v1 = validateBackupBundle({ policy, plan: planDifferentDestinations });
  assert.ok(v1.some((v) => v.includes("plan.destinations does not match the approved policy")), JSON.stringify(v1));

  const planDifferentRetention = buildBackupPlan({ retention: { daily: 1, weekly: 0, monthly: 0 } }, { policy });
  const v2 = validateBackupBundle({ policy, plan: planDifferentRetention });
  assert.ok(v2.some((v) => v.includes("plan.retention does not match the approved policy")), JSON.stringify(v2));
});

test("validateBackupBundle: flags a plan built against a stale policy - plan.generation must match policy.appliedGeneration", () => {
  const policy = buildBackupPolicy({ appliedGeneration: 3 });
  const staleGenerationPlan = buildBackupPlan({ generation: 9 }, { policy });
  const violations = validateBackupBundle({ policy, plan: staleGenerationPlan });
  assert.ok(violations.some((v) => v.includes("plan.generation does not match the supplied policy's own appliedGeneration")), JSON.stringify(violations));
});

test("validateBackupBundle: a kit is bound to the plan's own installation/generation and the manifest's own recoveryKitDigest", () => {
  const kit = buildRecoveryKit();
  const plan = buildBackupPlan();
  const manifest = buildBackupManifest({ recoveryKitDigest: canonicalDocumentDigest(kit) }, { plan });
  assert.deepEqual(validateBackupBundle({ plan, manifest, kit }), []);

  const wrongInstallation = { ...kit, installationId: "some-other-installation" };
  const v1 = validateBackupBundle({ plan, manifest, kit: wrongInstallation });
  assert.ok(v1.some((v) => v.includes("kit.installationId does not match plan.installationId")), JSON.stringify(v1));

  const wrongGeneration = { ...kit, createdForGeneration: 99 };
  const v2 = validateBackupBundle({ plan, manifest, kit: wrongGeneration });
  assert.ok(v2.some((v) => v.includes("kit.createdForGeneration does not match plan.generation")), JSON.stringify(v2));

  const staleManifest = buildBackupManifest({ recoveryKitDigest: sha("0") }, { plan });
  const v3 = validateBackupBundle({ plan, manifest: staleManifest, kit });
  assert.ok(v3.some((v) => v.includes("manifest.recoveryKitDigest does not match the supplied kit")), JSON.stringify(v3));
});

// PR 3 (item 10): a kit binding to the right plan/installation/generation
// (and to the manifest's own recoveryKitDigest) is still only a decoy
// shaped like a real kit unless its own ciphertext is genuinely age
// output - verifyRecoveryKit() is what actually proves that, and this
// bundle validator now runs it on every kit it's given (see
// scripts/backup-flow.mjs's own comment on this exact addition). Before
// that wiring, a schema-valid document with the right ids but a garbage
// ciphertext (any base64 string long enough to clear the schema's own
// minLength) would have sailed straight through this same call with zero
// violations.
test("validateBackupBundle: a schema-valid kit with the right bindings but a fake, non-age ciphertext is still refused - id/digest bindings alone are never sufficient", () => {
  const plan = buildBackupPlan();
  const fakeCiphertext = Buffer.from("not a real age payload, just long enough to clear the schema's own 200-char minLength requirement - 0123456789", "utf8");
  const kit = buildRecoveryKit({ ciphertext: fakeCiphertext.toString("base64"), ciphertextDigest: sha256(fakeCiphertext) });
  const manifest = buildBackupManifest({ recoveryKitDigest: canonicalDocumentDigest(kit) }, { plan });
  const violations = validateBackupBundle({ plan, manifest, kit });
  assert.ok(violations.some((v) => v.includes("age-encryption.org/v1 magic header")), JSON.stringify(violations));
});

test("validateBackupBundle: a genuinely coherent bundle including lock, journal, and events has zero violations", () => {
  const policy = buildBackupPolicy();
  const plan = buildBackupPlan({}, { policy });
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({}, { plan, manifest });
  const lock = {
    apiVersion: "hof.dev/operation-lock/v2", operationKind: "backup", operationId: OPERATION_ID,
    approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-09-04T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
  };
  const journal = {
    apiVersion: "hof.dev/operation-journal/v2", operationKind: "backup", operationId: OPERATION_ID,
    approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId },
    startedAt: "2026-09-04T10:00:00Z", status: "succeeded", committedGeneration: null,
  };
  const events = plan.operations.map((op) => ({
    apiVersion: "hof.dev/operation-event/v2", operationKind: "backup", operationId: OPERATION_ID,
    step: op.id, attempt: 1, phase: "succeeded", at: "2026-09-04T10:01:00Z",
    ...(op.destination ? { destination: op.destination } : {}),
  }));
  assert.deepEqual(validateBackupBundle({ policy, plan, manifest, evidence, lock, journal, events }), []);
});

test("validateBackupBundle: flags a lock/journal whose approvedPlanId, operationKind, or target don't actually match the plan, and a lock/journal operationId mismatch", () => {
  const plan = buildBackupPlan();
  const baseLock = { apiVersion: "hof.dev/operation-lock/v2", operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-09-04T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  const baseJournal = { apiVersion: "hof.dev/operation-journal/v2", operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId }, startedAt: "2026-09-04T10:00:00Z", status: "in-progress", committedGeneration: null };

  assert.ok(validateBackupBundle({ plan, lock: { ...baseLock, approvedPlanId: sha("0") } }).some((v) => v.includes("lock.approvedPlanId")));
  assert.ok(validateBackupBundle({ plan, journal: { ...baseJournal, approvedPlanId: sha("0") } }).some((v) => v.includes("journal.approvedPlanId")));
  assert.ok(validateBackupBundle({ plan, journal: { ...baseJournal, target: targetBinding({ host: "different-host" }) } }).some((v) => v.includes("journal.target")));
  assert.ok(validateBackupBundle({ plan, journal: { ...baseJournal, plan: { ...plan, planId: sha("0") } } }).some((v) => v.includes("journal.plan does not structurally match")));
  assert.ok(validateBackupBundle({ plan, lock: baseLock, journal: { ...baseJournal, operationId: "different-op-id" } }).some((v) => v.includes("lock.operationId does not match journal.operationId")));

  // A truncated embedded plan (correct planId, everything else missing)
  // is schema-valid against operation-journal-v2.schema.json's own
  // loosely-typed plan property, but is never the real "full, exact
  // plan document" that schema's own description promises - a fifth
  // review round found planId-only equality let this through silently.
  const truncatedPlan = { apiVersion: "hof.dev/backup-plan/v1", planId: plan.planId };
  assert.ok(validateBackupBundle({ plan, journal: { ...baseJournal, plan: truncatedPlan } }).some((v) => v.includes("journal.plan does not structurally match")));
});

test("validateBackupBundle: flags an event whose operationId/operationKind doesn't match the journal, or whose step isn't in the plan", () => {
  const plan = buildBackupPlan();
  const journal = { apiVersion: "hof.dev/operation-journal/v2", operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId }, startedAt: "2026-09-04T10:00:00Z", status: "in-progress", committedGeneration: null };
  const badEvent = { apiVersion: "hof.dev/operation-event/v2", operationKind: "backup", operationId: "some-other-op-id", step: plan.operations[0].id, attempt: 1, phase: "started", at: "2026-09-04T10:01:00Z" };
  const unknownStepEvent = { apiVersion: "hof.dev/operation-event/v2", operationKind: "backup", operationId: OPERATION_ID, step: "999.unknown.step.here", attempt: 1, phase: "started", at: "2026-09-04T10:01:00Z" };
  assert.ok(validateBackupBundle({ plan, journal, events: [badEvent] }).some((v) => v.includes("operationId not matching the journal")));
  assert.ok(validateBackupBundle({ plan, journal, events: [unknownStepEvent] }).some((v) => v.includes("not in the plan")));
});

test("validateBackupBundle: evidence is bound to lock/journal by operationId, and journal status must reconcile with evidence status/abandoned", () => {
  const policy = buildBackupPolicy();
  const plan = buildBackupPlan({}, { policy });
  const manifest = buildBackupManifest({}, { plan });
  const evidence = buildBackupEvidence({}, { plan, manifest });
  const lock = { apiVersion: "hof.dev/operation-lock/v2", operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-09-04T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  const succeededJournal = { apiVersion: "hof.dev/operation-journal/v2", operationKind: "backup", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests: { releaseLockDigest: plan.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, backupPolicyId: plan.backupPolicyId }, startedAt: "2026-09-04T10:00:00Z", status: "succeeded", committedGeneration: null };

  // evidence.operationId not matching lock/journal
  const otherEvidence = buildBackupEvidence({ operationId: "some-other-op-id" }, { plan, manifest });
  assert.ok(validateBackupBundle({ plan, evidence: otherEvidence, lock }).some((v) => v.includes("evidence.operationId does not match lock.operationId")));
  assert.ok(validateBackupBundle({ plan, evidence: otherEvidence, journal: succeededJournal }).some((v) => v.includes("evidence.operationId does not match journal.operationId")));

  // journal.status: in-progress can never coexist with evidence
  const inProgressJournal = { ...succeededJournal, status: "in-progress" };
  assert.ok(validateBackupBundle({ plan, evidence, journal: inProgressJournal }).some((v) => v.includes("in-progress can never coexist with evidence")));

  // journal.status: succeeded must correspond to evidence.status: succeeded
  const partialEvidence = buildBackupEvidence({ status: "partial", perDestinationResults: [buildDestinationResult({ destination: "onsite" }), { destination: "offsite", status: "failed", error: "timeout" }] }, { plan, manifest });
  assert.ok(validateBackupBundle({ plan, evidence: partialEvidence, journal: succeededJournal }).some((v) => v.includes("journal.status: succeeded must correspond to evidence.status: succeeded")));

  // journal.status: failed can never correspond to evidence.status: succeeded
  const failedJournal = { ...succeededJournal, status: "failed" };
  assert.ok(validateBackupBundle({ plan, evidence, journal: failedJournal }).some((v) => v.includes("journal.status: failed can never correspond to evidence.status: succeeded")));

  // evidence.abandoned: true must correspond to journal.status: failed
  const abandonedEvidence = buildBackupEvidence({ status: "failed", perDestinationResults: [], readinessConfirmedAt: null, abandoned: true }, { plan, manifest });
  assert.ok(validateBackupBundle({ plan, evidence: abandonedEvidence, journal: succeededJournal }).some((v) => v.includes("evidence.abandoned: true must correspond to journal.status: failed")));
  assert.deepEqual(validateBackupBundle({ plan, evidence: abandonedEvidence, journal: failedJournal }).filter((v) => v.includes("abandoned")), []);

  // evidence.abandoned: true is incoherent with an event log showing
  // evidence.write's own step already succeeded - a successful
  // evidence.write is itself the flow's natural terminal completion,
  // which abandonment means never happened.
  const allSucceededEvents = plan.operations.map((op) => ({
    apiVersion: "hof.dev/operation-event/v2", operationKind: "backup", operationId: OPERATION_ID,
    step: op.id, attempt: 1, phase: "succeeded", at: "2026-09-04T10:01:00Z",
    ...(op.destination ? { destination: op.destination } : {}),
  }));
  const violations = validateBackupBundle({ plan, evidence: abandonedEvidence, journal: failedJournal, events: allSucceededEvents });
  assert.ok(violations.some((v) => v.includes("evidence.write's own step already succeeded")), JSON.stringify(violations));

  // A genuinely incomplete event log (missing evidence.write's own
  // event) is coherent with abandonment.
  const incompleteEvents = allSucceededEvents.filter((event) => event.step !== plan.operations[plan.operations.length - 1].id);
  assert.deepEqual(validateBackupBundle({ plan, evidence: abandonedEvidence, journal: failedJournal, events: incompleteEvents }).filter((v) => v.includes("incoherent")), []);

  // A sixth review round's minimal counterexample: evidence.write's own
  // event succeeded, but some unrelated EARLIER step's event is missing
  // from the log entirely. The now-fixed check must still flag this -
  // it never depended on every other step also being present.
  const earlierStepId = plan.operations[0].id;
  const missingEarlierStepEvents = allSucceededEvents.filter((event) => event.step !== earlierStepId);
  const minimalViolations = validateBackupBundle({ plan, evidence: abandonedEvidence, journal: failedJournal, events: missingEarlierStepEvents });
  assert.ok(minimalViolations.some((v) => v.includes("evidence.write's own step already succeeded")), JSON.stringify(minimalViolations));
});

test("validateRestoreBundle: a genuinely coherent plan/manifest/evidence bundle has zero violations", () => {
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({}, { manifest });
  const evidence = buildRestoreEvidence({}, { plan });
  assert.deepEqual(validateRestoreBundle({ plan, manifest, evidence }), []);
});

test("validateRestoreBundle: flags a plan whose manifestDigest doesn't match the supplied manifest's own recomputed digest", () => {
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({ manifestDigest: sha("0") }, { manifest });
  const violations = validateRestoreBundle({ plan, manifest });
  assert.ok(violations.some((v) => v.includes("manifestDigest")), JSON.stringify(violations));
});

test("validateRestoreBundle: flags evidence whose snapshotId doesn't match the plan's own pinned snapshotId", () => {
  const plan = buildRestorePlan();
  const evidence = buildRestoreEvidence({ snapshotId: "some-other-snapshot" }, { plan });
  const violations = validateRestoreBundle({ plan, evidence });
  assert.ok(violations.some((v) => v.includes("snapshotId")), JSON.stringify(violations));
});

test("validateRestoreBundle: flags a manifest whose consistencySet doesn't exactly match the plan's own", () => {
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({}, { manifest });
  const tamperedManifest = { ...manifest, consistencySet: [consistencySetEntry({ volume: "different-volume" })] };
  const violations = validateRestoreBundle({ plan, manifest: tamperedManifest });
  assert.ok(violations.some((v) => v.includes("consistencySet")), JSON.stringify(violations));
});

test("validateRestoreBundle: flags a plan whose source claim (installationId/generation/release/releaseLockDigest) doesn't actually match the manifest that is the real proof of what's being restored", () => {
  const manifest = buildRestoreManifest();
  for (const [field, badValue] of [["installationId", "forged-installation"], ["generation", 999], ["release", "9.9.9"], ["releaseLockDigest", sha("0")]]) {
    const plan = buildRestorePlan({ source: { ...buildRestorePlan({}, { manifest }).source, [field]: badValue } }, { manifest });
    const violations = validateRestoreBundle({ plan, manifest });
    assert.ok(violations.some((v) => v.includes(`manifest.${field}`)), `${field}: ${JSON.stringify(violations)}`);
  }
});

test("validateRestoreBundle: flags a manifest whose backupToolLockDigest doesn't match the plan's own", () => {
  const manifest = buildRestoreManifest({ backupToolLockDigest: sha("0") });
  const plan = buildRestorePlan({}, { manifest: buildRestoreManifest() });
  const violations = validateRestoreBundle({ plan, manifest });
  assert.ok(violations.some((v) => v.includes("manifest.backupToolLockDigest")), JSON.stringify(violations));
});

test("validateRestoreBundle: flags a manifest whose own recoveryKitDigest doesn't match the plan's own - ADR 0006 promises this is confirmed before trusting anything else in the snapshot", () => {
  const manifest = buildRestoreManifest({ recoveryKitDigest: sha("0") });
  const plan = buildRestorePlan({}, { manifest: buildRestoreManifest() });
  const violations = validateRestoreBundle({ plan, manifest });
  assert.ok(violations.some((v) => v.includes("manifest.recoveryKitDigest")), JSON.stringify(violations));
});

test("validateRestoreBundle: a kit is bound to the plan's own source installation/generation and the plan's own recoveryKitDigest", () => {
  const kit = buildRecoveryKit();
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({ recoveryKitDigest: canonicalDocumentDigest(kit) }, { manifest });
  assert.deepEqual(validateRestoreBundle({ plan, kit }), []);

  const wrongInstallation = { ...kit, installationId: "some-other-installation" };
  assert.ok(validateRestoreBundle({ plan, kit: wrongInstallation }).some((v) => v.includes("kit.installationId does not match plan.source.installationId")));

  const wrongGeneration = { ...kit, createdForGeneration: 999 };
  assert.ok(validateRestoreBundle({ plan, kit: wrongGeneration }).some((v) => v.includes("kit.createdForGeneration does not match plan.source.generation")));

  const planWithStaleKitDigest = buildRestorePlan({ recoveryKitDigest: sha("0") }, { manifest });
  assert.ok(validateRestoreBundle({ plan: planWithStaleKitDigest, kit }).some((v) => v.includes("plan.recoveryKitDigest does not match the supplied kit")));
});

// PR 3 (item 10): the restore-side equivalent of validateBackupBundle's
// own identical addition above - a restore is exactly the operation that
// will decrypt and TRUST this kit's contents, so id/digest bindings
// alone (which a decoy can satisfy just as easily as a real kit) are
// even less sufficient here than on the backup side.
test("validateRestoreBundle: a schema-valid kit with the right bindings but a fake, non-age ciphertext is still refused - id/digest bindings alone are never sufficient", () => {
  const fakeCiphertext = Buffer.from("not a real age payload, just long enough to clear the schema's own 200-char minLength requirement - 0123456789", "utf8");
  const kit = buildRecoveryKit({ ciphertext: fakeCiphertext.toString("base64"), ciphertextDigest: sha256(fakeCiphertext) });
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({ recoveryKitDigest: canonicalDocumentDigest(kit) }, { manifest });
  const violations = validateRestoreBundle({ plan, kit });
  assert.ok(violations.some((v) => v.includes("age-encryption.org/v1 magic header")), JSON.stringify(violations));
});

test("validateRestoreBundle: evidence.source/target are bound to the plan - a forged source or a target on a different host must be flagged", () => {
  const plan = buildRestorePlan();
  const wrongSource = buildRestoreEvidence({ source: { ...plan.source, installationId: "forged" } }, { plan });
  assert.ok(validateRestoreBundle({ plan, evidence: wrongSource }).some((v) => v.includes("evidence.source does not match plan.source")));

  const wrongHost = buildRestoreEvidence({ target: restoreTargetBinding({ installationId: "inst-1", baselineGeneration: 0, host: "a-completely-different-host" }) }, { plan });
  assert.ok(validateRestoreBundle({ plan, evidence: wrongHost }).some((v) => v.includes("evidence.target's own connection identity")));
});

test("validateRestoreBundle: evidence.target legitimately differs from plan.target on installationId/baselineGeneration alone - state.restore assigns those DURING the operation, this must never be flagged", () => {
  const plan = buildRestorePlan();
  assert.equal(plan.target.installationId, null, "plan.target is genuinely clean at planning time");
  const evidence = buildRestoreEvidence({}, { plan });
  assert.equal(evidence.target.installationId, "inst-1", "evidence.target reflects what state.restore actually assigned");
  assert.deepEqual(validateRestoreBundle({ plan, evidence }), []);
});

test("validateRestoreBundle: a genuinely coherent bundle including lock, journal, and events has zero violations", () => {
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({}, { manifest });
  const evidence = buildRestoreEvidence({}, { plan });
  const lock = {
    apiVersion: "hof.dev/operation-lock/v2", operationKind: "restore", operationId: OPERATION_ID,
    approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-09-04T10:00:00Z",
    acquiredBy: { workstation: "operator-laptop", pid: 4242, user: "operator" },
  };
  const journal = {
    apiVersion: "hof.dev/operation-journal/v2", operationKind: "restore", operationId: OPERATION_ID,
    approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: { releaseLockDigest: plan.source.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, manifestDigest: plan.manifestDigest, recoveryKitDigest: plan.recoveryKitDigest },
    startedAt: "2026-09-04T10:00:00Z", status: "succeeded", committedGeneration: plan.source.generation,
  };
  const events = plan.operations.map((op) => ({
    apiVersion: "hof.dev/operation-event/v2", operationKind: "restore", operationId: OPERATION_ID,
    step: op.id, attempt: 1, phase: "succeeded", at: "2026-09-04T10:01:00Z",
  }));
  assert.deepEqual(validateRestoreBundle({ plan, manifest, evidence, lock, journal, events }), []);
});

test("validateRestoreBundle: evidence is bound to lock/journal by operationId, and journal status must reconcile with evidence status/abandoned", () => {
  const manifest = buildRestoreManifest();
  const plan = buildRestorePlan({}, { manifest });
  const evidence = buildRestoreEvidence({}, { plan });
  const lock = { apiVersion: "hof.dev/operation-lock/v2", operationKind: "restore", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-09-04T10:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  const succeededJournal = { apiVersion: "hof.dev/operation-journal/v2", operationKind: "restore", operationId: OPERATION_ID, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests: { releaseLockDigest: plan.source.releaseLockDigest, backupToolLockDigest: plan.backupToolLockDigest, manifestDigest: plan.manifestDigest, recoveryKitDigest: plan.recoveryKitDigest }, startedAt: "2026-09-04T10:00:00Z", status: "succeeded", committedGeneration: plan.source.generation };

  const otherEvidence = buildRestoreEvidence({ operationId: "some-other-op-id" }, { plan });
  assert.ok(validateRestoreBundle({ plan, evidence: otherEvidence, lock }).some((v) => v.includes("evidence.operationId does not match lock.operationId")));
  assert.ok(validateRestoreBundle({ plan, evidence: otherEvidence, journal: succeededJournal }).some((v) => v.includes("evidence.operationId does not match journal.operationId")));

  const inProgressJournal = { ...succeededJournal, status: "in-progress" };
  assert.ok(validateRestoreBundle({ plan, evidence, journal: inProgressJournal }).some((v) => v.includes("in-progress can never coexist with evidence")));

  const failedJournal = { ...succeededJournal, status: "failed", committedGeneration: null };
  assert.ok(validateRestoreBundle({ plan, evidence, journal: failedJournal }).some((v) => v.includes("journal.status does not match evidence.status")));

  const abandonedEvidence = buildRestoreEvidence({ status: "failed", error: "operator abandoned", dataRestoredCheckpointAt: null, readinessConfirmedAt: null, abandoned: true }, { plan });
  assert.ok(validateRestoreBundle({ plan, evidence: abandonedEvidence, journal: succeededJournal }).some((v) => v.includes("evidence.abandoned: true must correspond to journal.status: failed")));
  const journalMatchingAbandoned = { ...succeededJournal, status: "failed", committedGeneration: null };
  assert.deepEqual(validateRestoreBundle({ plan, evidence: abandonedEvidence, journal: journalMatchingAbandoned }).filter((v) => v.includes("abandoned")), []);

  const allSucceededEvents = plan.operations.map((op) => ({
    apiVersion: "hof.dev/operation-event/v2", operationKind: "restore", operationId: OPERATION_ID,
    step: op.id, attempt: 1, phase: "succeeded", at: "2026-09-04T10:01:00Z",
  }));
  const violations = validateRestoreBundle({ plan, evidence: abandonedEvidence, journal: journalMatchingAbandoned, events: allSucceededEvents });
  assert.ok(violations.some((v) => v.includes("evidence.write's own step already succeeded")), JSON.stringify(violations));

  // A sixth review round's minimal counterexample: evidence.write's own
  // event succeeded, but some unrelated EARLIER step's event is missing
  // from the log entirely - must still be flagged.
  const earlierStepId = plan.operations[0].id;
  const missingEarlierStepEvents = allSucceededEvents.filter((event) => event.step !== earlierStepId);
  const minimalViolations = validateRestoreBundle({ plan, evidence: abandonedEvidence, journal: journalMatchingAbandoned, events: missingEarlierStepEvents });
  assert.ok(minimalViolations.some((v) => v.includes("evidence.write's own step already succeeded")), JSON.stringify(minimalViolations));

  // A genuinely incomplete event log missing evidence.write's own event
  // is still coherent with abandonment.
  const missingEvidenceWriteEvents = allSucceededEvents.filter((event) => event.step !== plan.operations[plan.operations.length - 1].id);
  assert.deepEqual(validateRestoreBundle({ plan, evidence: abandonedEvidence, journal: journalMatchingAbandoned, events: missingEvidenceWriteEvents }).filter((v) => v.includes("incoherent")), []);
});

test("validateRestoreCommittedGeneration: correctness against the real event log, independent of overall journal status", () => {
  const plan = buildRestorePlan();
  const stateRestoreStepId = plan.operations.find((op) => op.action === "state.restore").id;
  const expectedGeneration = plan.source.generation;
  const committed = { committedGeneration: expectedGeneration };
  const wrongValue = { committedGeneration: expectedGeneration + 1 };
  const notCommitted = { committedGeneration: null };
  const withStateRestore = [{ step: stateRestoreStepId, phase: "succeeded" }];
  const withoutStateRestore = [{ step: "011.secret.materialize.secrets", phase: "succeeded" }];

  assert.deepEqual(validateRestoreCommittedGeneration(committed, withStateRestore, plan), []);
  assert.deepEqual(validateRestoreCommittedGeneration(notCommitted, withoutStateRestore, plan), []);
  assert.ok(validateRestoreCommittedGeneration(notCommitted, withStateRestore, plan).some((v) => v.includes("must be set once state.restore")));
  assert.ok(validateRestoreCommittedGeneration(committed, withoutStateRestore, plan).some((v) => v.includes("must stay null")));
  assert.ok(validateRestoreCommittedGeneration(wrongValue, withStateRestore, plan).some((v) => v.includes("does not match the source generation")));
});

test("validateRestoreCommittedGeneration: identifies state.restore by the plan's own action field, never by pattern-matching a free-text step id", () => {
  // A schema-valid plan operation could name its own id anything at all
  // ("010.state.restore.decoy") while its real action is something else
  // entirely - a fifth review round found a regex over step text alone
  // could be fooled by exactly this. The plan's own operations array,
  // keyed by action, is the only trustworthy source.
  const plan = buildRestorePlan();
  const decoyOps = plan.operations.map((op) => (op.action === "config.restore" ? { ...op, id: "010.state.restore.decoy" } : op));
  const decoyPlan = { ...plan, operations: decoyOps };
  const realStateRestoreId = plan.operations.find((op) => op.action === "state.restore").id;

  // An event for the DECOY id (config.restore's own operation, renamed)
  // must never be mistaken for the real state.restore succeeding.
  const decoyEvent = [{ step: "010.state.restore.decoy", phase: "succeeded" }];
  assert.deepEqual(validateRestoreCommittedGeneration({ committedGeneration: null }, decoyEvent, decoyPlan), []);
  assert.ok(validateRestoreCommittedGeneration({ committedGeneration: plan.source.generation }, decoyEvent, decoyPlan).some((v) => v.includes("must stay null")));

  // The REAL state.restore operation's own id still works correctly.
  const realEvent = [{ step: realStateRestoreId, phase: "succeeded" }];
  assert.deepEqual(validateRestoreCommittedGeneration({ committedGeneration: plan.source.generation }, realEvent, plan), []);
});

// =============================================================================
// scripts/backup-ids.mjs (pure helpers)
// =============================================================================

test("canonicalContentId: reordering a document's own keys never changes the id - only content does", () => {
  const doc = { planId: "sha256:ignored", a: 1, b: { z: 1, y: 2 } };
  const reordered = { b: { y: 2, z: 1 }, a: 1, planId: "sha256:ignored" };
  assert.equal(canonicalContentId(doc, "planId"), canonicalContentId(reordered, "planId"));
});

test("canonicalContentId: an actual content change changes the id", () => {
  const doc = { planId: "sha256:ignored", a: 1 };
  const changed = { planId: "sha256:ignored", a: 2 };
  assert.notEqual(canonicalContentId(doc, "planId"), canonicalContentId(changed, "planId"));
});

test("canonicalContentId: accepts an array of excluded fields, not just one", () => {
  const doc = { id: "x", meta1: "a", meta2: "b", content: 1 };
  const a = canonicalContentId(doc, ["id", "meta1", "meta2"]);
  const b = canonicalContentId({ ...doc, meta1: "different", meta2: "also-different" }, ["id", "meta1", "meta2"]);
  assert.equal(a, b, "excluded fields must never affect the id");
  const c = canonicalContentId({ ...doc, content: 2 }, ["id", "meta1", "meta2"]);
  assert.notEqual(a, c, "a non-excluded field must still affect the id");
});

test("canonicalDocumentDigest: excludes nothing - even a field named like an id is included", () => {
  const doc = { a: 1, id: "this-is-content-here-not-excluded" };
  const changed = { a: 1, id: "different" };
  assert.notEqual(canonicalDocumentDigest(doc), canonicalDocumentDigest(changed));
});

test("computeBackupId: deterministic - the same four inputs always produce the same id", () => {
  const input = { installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 4 };
  assert.equal(computeBackupId(input), computeBackupId({ ...input }));
});

test("computeBackupId: two attempts (identical installation/generation/policy) get different ids purely from backupSequence", () => {
  const first = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 4 });
  const second = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 5 });
  assert.notEqual(first, second, "a genuinely new operationId's own next sequence must still mint a fresh id");
});

test("computeBackupId: a --resume of the same operationId reuses its own already-allocated sequence, hence the same backupId - not a new one per attempt", () => {
  // Modeled here as: two calls with the SAME backupSequence (the sequence
  // this operationId's journal already recorded at creation, never
  // reallocated on --resume) always produce the identical backupId,
  // regardless of how many times the operator retries within that one
  // operationId.
  const input = { installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 4 };
  const firstAttempt = computeBackupId(input);
  const resumedAttempt = computeBackupId(input);
  assert.equal(firstAttempt, resumedAttempt);
});

test("computeBackupId: a different installation, generation, or policy each independently changes the id", () => {
  const base = { installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 4 };
  const baseId = computeBackupId(base);
  assert.notEqual(computeBackupId({ ...base, installationId: "inst-2" }), baseId);
  assert.notEqual(computeBackupId({ ...base, generation: 4 }), baseId);
  assert.notEqual(computeBackupId({ ...base, backupPolicyId: sha("z") }), baseId);
});

test("computeBackupId: rejects a non-positive-integer backupSequence or generation", () => {
  const base = { installationId: "inst-1", generation: 3, backupPolicyId: sha("4"), backupSequence: 4 };
  assert.throws(() => computeBackupId({ ...base, backupSequence: 0 }));
  assert.throws(() => computeBackupId({ ...base, backupSequence: 1.5 }));
  assert.throws(() => computeBackupId({ ...base, generation: 0 }));
  assert.throws(() => computeBackupId({ ...base, installationId: "" }));
});

test("exactSetEquals: order-independent, but sensitive to a genuinely added, removed, or duplicated member", () => {
  const a = [consistencySetEntry({ volume: "x" }), consistencySetEntry({ volume: "y" })];
  const reordered = [consistencySetEntry({ volume: "y" }), consistencySetEntry({ volume: "x" })];
  assert.ok(exactSetEquals(a, reordered, consistencySetEntryKey), "reordering the same members must still be equal");

  const missing = [consistencySetEntry({ volume: "x" })];
  assert.equal(exactSetEquals(a, missing, consistencySetEntryKey), false, "a removed member must not be equal");

  const duplicated = [consistencySetEntry({ volume: "x" }), consistencySetEntry({ volume: "x" }), consistencySetEntry({ volume: "y" })];
  assert.equal(exactSetEquals(a, duplicated, consistencySetEntryKey), false, "an extra duplicate member must not be equal");
});

test("hasDuplicates: catches a duplicate destination name, consistencySet volume, or operation id", () => {
  assert.equal(hasDuplicates([localDestination(), s3Destination()], (d) => d.name), false);
  assert.equal(hasDuplicates([localDestination(), localDestination()], (d) => d.name), true);

  const set = [consistencySetEntry({ volume: "a" }), consistencySetEntry({ volume: "a" })];
  assert.equal(hasDuplicates(set, consistencySetEntryKey), true);

  const ops = fullBackupOperations();
  ops[1] = { ...ops[1], id: ops[0].id };
  assert.equal(hasDuplicates(ops, (op) => op.id), true);
});
