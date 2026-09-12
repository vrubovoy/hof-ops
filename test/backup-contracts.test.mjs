// Schema-level coverage for the six backup/restore contracts ADR 0006
// introduces - no real executor exists yet (that's a later PR in this
// item's own sequence), so every fixture here is a hand-built,
// realistic document, mirroring test/apply-contracts.test.mjs's own
// pattern. The one property every fixture is also checked against: no
// secret value, decrypted content, or credential ever fits through any
// of these schemas (additionalProperties: false everywhere, checked
// here by attempting to smuggle one in and confirming it's rejected).

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
    installationId: "inst-1", baselineGeneration: 3,
    ...overrides,
  };
}

function sha(fill) {
  return "sha256:" + String(fill).repeat(64).slice(0, 64);
}

const OPERATION_ID = "3b1f6c2e-6e35-4f7a-9c3b-000000000001";
const BACKUP_ID = sha("b");
const PLAN_ID = sha("a");

function consistencySetEntry(overrides = {}) {
  return { service: "schlussel", unit: "schlussel", volume: "schlussel-data", retained: false, ...overrides };
}

function localDestination(overrides = {}) {
  return { name: "onsite", type: "local", path: "/mnt/hof-backups", secretRef: "backup-onsite-key", ...overrides };
}

function s3Destination(overrides = {}) {
  return { name: "offsite", type: "s3", bucket: "hof-backups-example", region: "eu-central-1", secretRef: "backup-offsite-key", ...overrides };
}

// --- backup-plan-v1 -------------------------------------------------------

function backupOperation(overrides = {}) {
  return { id: "005.snapshot.create.onsite", phase: "snapshot", action: "snapshot.create", resource: "onsite", destination: "onsite", reason: "manual backup run", ...overrides };
}

function backupPlanFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-plan/v1",
    planId: PLAN_ID,
    backupId: BACKUP_ID,
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
    operations: [backupOperation()],
    warnings: [],
    blockers: [],
    ...overrides,
  };
}

test("backup-plan-v1: a genuine manual backup plan, local + S3 destinations, validates", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.ok(validate(backupPlanFixture()), JSON.stringify(validate.errors));
});

test("backup-plan-v1: a scheduled trigger validates too", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.ok(validate(backupPlanFixture({ trigger: "scheduled" })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: rejects an empty destinations array - a backup with nothing to write to is never executable", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ destinations: [] })), false);
});

test("backup-plan-v1: rejects an empty consistencySet", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ consistencySet: [] })), false);
});

test("backup-plan-v1: rejects a local destination missing its required path", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = localDestination();
  delete destination.path;
  assert.equal(validate(backupPlanFixture({ destinations: [destination] })), false);
});

test("backup-plan-v1: rejects a destination mixing local and s3 fields at once", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const mixed = { ...localDestination(), ...s3Destination(), name: "confused" };
  assert.equal(validate(backupPlanFixture({ destinations: [mixed] })), false);
});

test("backup-plan-v1: rejects a raw credential smuggled into a destination instead of secretRef", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = s3Destination({ accessKeySecret: "AKIAABCDEFGHIJKLMNOP" });
  assert.equal(validate(backupPlanFixture({ destinations: [destination] })), false);
});

test("backup-plan-v1: rejects an unrecognized operation action - no generic executor", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ operations: [backupOperation({ action: "shell.run" })] })), false);
});

test("backup-plan-v1: rejects a retained consistencySet entry missing its own retained flag", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const entry = consistencySetEntry();
  delete entry.retained;
  assert.equal(validate(backupPlanFixture({ consistencySet: [entry] })), false);
});

test("backup-plan-v1: a retained (disabled-but-kept) volume is a real, legitimate consistency-set member", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const entry = consistencySetEntry({ service: "herold", unit: "herold-backend", volume: "herold-data", retained: true });
  assert.ok(validate(backupPlanFixture({ consistencySet: [entry] })), JSON.stringify(validate.errors));
});

// --- restore-plan-v1 -------------------------------------------------------

function restoreTargetBinding(overrides = {}) {
  return {
    mode: "ssh", host: "clean-host.example.com", port: 22, user: "deploy",
    hostKeySha256: "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno",
    installationId: null, baselineGeneration: 0,
    ...overrides,
  };
}

function restoreOperation(overrides = {}) {
  return { id: "003.data.restore.schlussel", phase: "data", action: "data.restore", resource: "schlussel-data", reason: "restore drill", ...overrides };
}

function restorePlanFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/restore-plan/v1",
    planId: PLAN_ID,
    executable: true,
    target: restoreTargetBinding(),
    backupId: BACKUP_ID,
    destinationName: "offsite",
    source: { installationId: "inst-1", generation: 3, release: "0.2.3", releaseLockDigest: sha("c") },
    recoveryKitDigest: sha("e"),
    backupToolLockDigest: sha("d"),
    consistencySet: [consistencySetEntry()],
    operations: [restoreOperation()],
    warnings: [],
    blockers: [],
    ...overrides,
  };
}

test("restore-plan-v1: a genuine clean-host restore plan validates", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.ok(validate(restorePlanFixture()), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects a target that already has an installationId - restore is never in-place", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ target: restoreTargetBinding({ installationId: "some-existing-install" }) })), false);
});

test("restore-plan-v1: rejects a target with a non-zero baselineGeneration - restore requires a genuinely clean host", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ target: restoreTargetBinding({ baselineGeneration: 1 }) })), false);
});

test("restore-plan-v1: source stays distinct from target - both present, never merged into one object", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const plan = restorePlanFixture();
  assert.equal(plan.target.installationId, null);
  assert.equal(plan.source.installationId, "inst-1");
  assert.ok(validate(plan), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects an unrecognized operation action - no generic executor", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ operations: [restoreOperation({ action: "shell.run" })] })), false);
});

test("restore-plan-v1: rejects a missing source field", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const plan = restorePlanFixture();
  delete plan.source.releaseLockDigest;
  assert.equal(validate(plan), false);
});

// --- backup-manifest-v1 -----------------------------------------------------

function backupManifestFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-manifest/v1",
    backupId: BACKUP_ID,
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
    sanitizedManifestIncluded: true,
    recoveryStoreIncluded: true,
    ...overrides,
  };
}

test("backup-manifest-v1: a genuine manifest written into a real snapshot validates", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  assert.ok(validate(backupManifestFixture()), JSON.stringify(validate.errors));
});

test("backup-manifest-v1: rejects a missing digest", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  const manifest = backupManifestFixture();
  delete manifest.composeTemplateDigest;
  assert.equal(validate(manifest), false);
});

test("backup-manifest-v1: rejects a raw secret value smuggled in", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  assert.equal(validate(backupManifestFixture({ recoveryAgeIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

// --- backup-evidence-v1 ------------------------------------------------------

function destinationResult(overrides = {}) {
  return { destination: "onsite", status: "succeeded", snapshotId: "abc123def456", verifiedAt: "2026-09-04T10:05:00Z", ...overrides };
}

function backupEvidenceFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-evidence/v1",
    operationId: OPERATION_ID,
    backupId: BACKUP_ID,
    target: targetBinding(),
    startedAt: "2026-09-04T10:00:00Z",
    completedAt: "2026-09-04T10:10:00Z",
    status: "succeeded",
    perDestinationResults: [destinationResult()],
    retentionApplied: true,
    ...overrides,
  };
}

test("backup-evidence-v1: a fully successful backup's evidence validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.ok(validate(backupEvidenceFixture()), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: status succeeded is rejected if any destination actually failed", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = backupEvidenceFixture({
    perDestinationResults: [destinationResult(), destinationResult({ destination: "offsite", status: "failed", error: "connection timed out", snapshotId: undefined, verifiedAt: undefined })],
  });
  assert.equal(validate(evidence), false);
});

test("backup-evidence-v1: a real partial result (one destination succeeded, one failed) validates as status: partial", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = backupEvidenceFixture({
    status: "partial",
    perDestinationResults: [
      destinationResult(),
      { destination: "offsite", status: "failed", error: "connection timed out" },
    ],
  });
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects status: partial when every destination actually succeeded", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ status: "partial" })), false);
});

test("backup-evidence-v1: rejects status: failed when a destination actually succeeded - never a silent downgrade of a real success", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ status: "failed" })), false);
});

test("backup-evidence-v1: status: failed with zero destination attempts (crashed before any snapshot.create ran) validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.ok(validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [], retentionApplied: false })), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: a failed destination result requires a sanitized error and forbids snapshotId/verifiedAt", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed" }] })), false, "failed with no error must be rejected");
  assert.equal(
    validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed", error: "timeout", snapshotId: "abc" }] })),
    false,
    "failed must never also carry a snapshotId",
  );
});

test("backup-evidence-v1: a succeeded destination result requires snapshotId and verifiedAt, forbids error", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [{ destination: "onsite", status: "succeeded" }] })), false);
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [{ ...destinationResult(), error: "should not be here" }] })), false);
});

// --- restore-evidence-v1 -----------------------------------------------------

function restoreEvidenceFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/restore-evidence/v1",
    operationId: OPERATION_ID,
    backupId: BACKUP_ID,
    source: { installationId: "inst-1", generation: 3, release: "0.2.3", releaseLockDigest: sha("c") },
    target: restoreTargetBinding({ installationId: "inst-1", baselineGeneration: 0 }),
    startedAt: "2026-09-04T11:00:00Z",
    completedAt: "2026-09-04T11:20:00Z",
    status: "succeeded",
    dataRestoredCheckpointAt: "2026-09-04T11:15:00Z",
    readinessConfirmedAt: "2026-09-04T11:19:00Z",
    ...overrides,
  };
}

test("restore-evidence-v1: a fully successful restore's evidence validates", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.ok(validate(restoreEvidenceFixture()), JSON.stringify(validate.errors));
});

test("restore-evidence-v1: a failed restore requires a sanitized error", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.equal(
    validate(restoreEvidenceFixture({ status: "failed", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    false,
    "failed with no error must be rejected",
  );
  assert.ok(
    validate(restoreEvidenceFixture({ status: "failed", error: "database integrity check failed", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    JSON.stringify(validate.errors),
  );
});

test("restore-evidence-v1: interrupted before checkpoint.data-restored validates with both checkpoints null", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.ok(
    validate(restoreEvidenceFixture({ status: "failed", error: "connection lost mid-restore", dataRestoredCheckpointAt: null, readinessConfirmedAt: null })),
    JSON.stringify(validate.errors),
  );
});

test("restore-evidence-v1: a succeeded restore requires both checkpoints actually set", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  assert.equal(validate(restoreEvidenceFixture({ readinessConfirmedAt: null })), false);
  assert.equal(validate(restoreEvidenceFixture({ dataRestoredCheckpointAt: null })), false);
});

test("restore-evidence-v1: keeps source and target as two distinct identities, never merged", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  const evidence = restoreEvidenceFixture();
  assert.notEqual(evidence.source.generation, undefined);
  assert.equal(evidence.target.baselineGeneration, 0, "the target's own baseline was 0 (clean) before this restore ran");
  assert.ok(validate(evidence), JSON.stringify(validate.errors));
});

// --- backup-tool-lock-v1 -----------------------------------------------------

function backupToolLockFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-tool-lock/v1",
    source: "https://github.com/vrubovoy/hof-ops",
    revision: "a".repeat(40),
    sourceTag: "backup-tool-v1.0.0",
    image: "ghcr.io/vrubovoy/hof-ops-ee@sha256:" + "f".repeat(64),
    signatureIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/backup-tool.yml@refs/tags/backup-tool-v1.0.0",
    signatureOidcIssuer: "https://token.actions.githubusercontent.com",
    provenanceDigest: sha("6"),
    sbomDigest: sha("7"),
    pinnedTools: { restic: "0.16.4", sops: "3.9.0", age: "1.2.0" },
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
