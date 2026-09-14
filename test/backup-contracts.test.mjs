// Schema-level coverage for the ten backup/restore contracts ADR 0006
// introduces (backup-plan-v1, restore-plan-v1, backup-manifest-v1,
// backup-evidence-v1, restore-evidence-v1, backup-tool-lock-v1,
// backup-policy-v1, recovery-kit-v1) plus unit coverage for the pure
// scripts/backup-ids.mjs helpers those schemas' own field descriptions
// depend on. No real executor exists yet (that's a later PR in this
// item's own sequence), so every fixture here is a hand-built, realistic
// document, mirroring test/apply-contracts.test.mjs's own pattern. The
// one property every fixture is also checked against: no secret value,
// decrypted content, or credential ever fits through any of these
// schemas (additionalProperties: false everywhere, checked here by
// attempting to smuggle one in and confirming it's rejected).

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalContentId, computeBackupId, consistencySetEntryKey, exactSetEquals, hasDuplicates } from "../scripts/backup-ids.mjs";

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
const POLICY_ID = sha("4");
const SEQUENCE = 4;

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
    backupPolicyId: POLICY_ID,
    backupSequence: SEQUENCE,
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

test("backup-plan-v1: rejects a credential-bearing S3 endpoint (embedded userinfo)", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = s3Destination({ endpoint: "https://AKIAABCDEFGH:secret@s3.example.com" });
  assert.equal(validate(backupPlanFixture({ destinations: [destination] })), false);
});

test("backup-plan-v1: accepts a real, credential-free S3 endpoint", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const destination = s3Destination({ endpoint: "https://s3.eu-central-1.example.com" });
  assert.ok(validate(backupPlanFixture({ destinations: [destination] })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: rejects an unrecognized operation action - no generic executor", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ operations: [backupOperation({ action: "shell.run" })] })), false);
});

test("backup-plan-v1: rejects a phase/action mismatch - snapshot phase with a service.stop action", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ operations: [backupOperation({ action: "service.stop" })] })), false);
});

test("backup-plan-v1: rejects a retention.apply operation missing its own destination - retention is per-destination, never one run-wide step", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const op = { id: "006.retention.apply.onsite", phase: "retention", action: "retention.apply", resource: "onsite", reason: "apply retention" };
  assert.equal(validate(backupPlanFixture({ operations: [op] })), false);
});

test("backup-plan-v1: a retention.apply operation with its own destination validates", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  const op = { id: "006.retention.apply.onsite", phase: "retention", action: "retention.apply", resource: "onsite", destination: "onsite", reason: "apply retention" };
  assert.ok(validate(backupPlanFixture({ operations: [op] })), JSON.stringify(validate.errors));
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

test("backup-plan-v1: executable must faithfully reflect blockers", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ executable: true, blockers: ["drift detected"] })), false, "executable: true with a real blocker must be rejected");
  assert.equal(validate(backupPlanFixture({ executable: false, blockers: [] })), false, "executable: false with zero blockers must be rejected");
  assert.ok(validate(backupPlanFixture({ executable: false, blockers: ["drift detected"], operations: [] })), JSON.stringify(validate.errors));
});

test("backup-plan-v1: an executable plan with an empty operations list is rejected - nothing to dispatch is never legitimate", async () => {
  const validate = await validatorFor("backup-plan-v1.schema.json");
  assert.equal(validate(backupPlanFixture({ executable: true, operations: [] })), false);
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
    networks: ["hof"],
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

test("restore-plan-v1: rejects an SSH-mode target with no host key", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ target: restoreTargetBinding({ hostKeySha256: null }) })), false);
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

test("restore-plan-v1: rejects a phase/action mismatch - checkpoint phase with a config.restore action", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const op = { id: "007.checkpoint.data-restored.all", phase: "checkpoint", action: "config.restore", resource: "checkpoint", reason: "mismatched" };
  assert.equal(validate(restorePlanFixture({ operations: [op] })), false);
});

test("restore-plan-v1: a network.create operation under the data phase validates - restore must create its own network on a clean host", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const op = { id: "001.network.create.hof", phase: "data", action: "network.create", resource: "hof", reason: "clean host has no network yet" };
  assert.ok(validate(restorePlanFixture({ operations: [op] })), JSON.stringify(validate.errors));
});

test("restore-plan-v1: rejects an empty networks array - a clean target always needs at least one created", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ networks: [] })), false);
});

test("restore-plan-v1: rejects a missing source field", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  const plan = restorePlanFixture();
  delete plan.source.releaseLockDigest;
  assert.equal(validate(plan), false);
});

test("restore-plan-v1: executable must faithfully reflect blockers", async () => {
  const validate = await validatorFor("restore-plan-v1.schema.json");
  assert.equal(validate(restorePlanFixture({ executable: true, blockers: ["target not clean"] })), false);
  assert.equal(validate(restorePlanFixture({ executable: false, blockers: [] })), false);
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
    sanitizedManifestDigest: sha("f"),
    recoveryKitDigest: sha("e"),
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

test("backup-manifest-v1: rejects the old permissive-boolean shape for sanitizedManifest/recoveryKit inclusion - a digest is required now, not a boolean claim", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  const manifest = backupManifestFixture();
  delete manifest.sanitizedManifestDigest;
  delete manifest.recoveryKitDigest;
  manifest.sanitizedManifestIncluded = true;
  manifest.recoveryStoreIncluded = true;
  assert.equal(validate(manifest), false);
});

test("backup-manifest-v1: rejects a raw secret value smuggled in", async () => {
  const validate = await validatorFor("backup-manifest-v1.schema.json");
  assert.equal(validate(backupManifestFixture({ recoveryAgeIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

// --- backup-evidence-v1 ------------------------------------------------------

function destinationResult(overrides = {}) {
  return { destination: "onsite", status: "succeeded", snapshotId: "abc123def456", verifiedAt: "2026-09-04T10:05:00Z", retentionApplied: true, ...overrides };
}

function backupEvidenceFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-evidence/v1",
    operationId: OPERATION_ID,
    backupId: BACKUP_ID,
    planId: PLAN_ID,
    backupPolicyId: POLICY_ID,
    manifestDigest: sha("1"),
    backupToolLockDigest: sha("d"),
    target: targetBinding(),
    startedAt: "2026-09-04T10:00:00Z",
    completedAt: "2026-09-04T10:10:00Z",
    status: "succeeded",
    perDestinationResults: [destinationResult()],
    ...overrides,
  };
}

test("backup-evidence-v1: a fully successful backup's evidence validates", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.ok(validate(backupEvidenceFixture()), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects evidence missing its plan/policy/manifest/tool-lock bindings", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  for (const field of ["planId", "backupPolicyId", "manifestDigest", "backupToolLockDigest"]) {
    const evidence = backupEvidenceFixture();
    delete evidence[field];
    assert.equal(validate(evidence), false, `missing ${field} must be rejected`);
  }
});

test("backup-evidence-v1: status succeeded is rejected if any destination actually failed", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const evidence = backupEvidenceFixture({
    perDestinationResults: [destinationResult(), destinationResult({ destination: "offsite", status: "failed", error: "connection timed out", snapshotId: undefined, verifiedAt: undefined, retentionApplied: undefined })],
  });
  assert.equal(validate(evidence), false);
});

test("backup-evidence-v1: rejects status succeeded with an empty perDestinationResults - an empty result set is never a real success", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [] })), false);
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
  assert.ok(validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [] })), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: a failed destination result requires a sanitized error and forbids snapshotId/verifiedAt/retentionApplied", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed" }] })), false, "failed with no error must be rejected");
  assert.equal(
    validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed", error: "timeout", snapshotId: "abc" }] })),
    false,
    "failed must never also carry a snapshotId",
  );
  assert.equal(
    validate(backupEvidenceFixture({ status: "failed", perDestinationResults: [{ destination: "onsite", status: "failed", error: "timeout", retentionApplied: true }] })),
    false,
    "failed must never also claim retentionApplied",
  );
});

test("backup-evidence-v1: a succeeded destination result requires snapshotId and verifiedAt, forbids error", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [{ destination: "onsite", status: "succeeded" }] })), false);
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [{ ...destinationResult(), error: "should not be here" }] })), false);
});

test("backup-evidence-v1: a succeeded destination whose own retention never completed is still a real success, with retentionApplied simply absent", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  const result = destinationResult();
  delete result.retentionApplied;
  assert.ok(validate(backupEvidenceFixture({ perDestinationResults: [result] })), JSON.stringify(validate.errors));
});

test("backup-evidence-v1: rejects retentionApplied: false - presence itself is the true signal, false is never a legitimate value", async () => {
  const validate = await validatorFor("backup-evidence-v1.schema.json");
  assert.equal(validate(backupEvidenceFixture({ perDestinationResults: [destinationResult({ retentionApplied: false })] })), false);
});

// --- restore-evidence-v1 -----------------------------------------------------

function restoreEvidenceFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/restore-evidence/v1",
    operationId: OPERATION_ID,
    planId: PLAN_ID,
    backupId: BACKUP_ID,
    snapshotId: "abc123def456",
    manifestDigest: sha("1"),
    recoveryKitDigest: sha("e"),
    backupToolLockDigest: sha("d"),
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

test("restore-evidence-v1: rejects evidence missing its plan/snapshot/manifest/kit/tool-lock bindings", async () => {
  const validate = await validatorFor("restore-evidence-v1.schema.json");
  for (const field of ["planId", "snapshotId", "manifestDigest", "recoveryKitDigest", "backupToolLockDigest"]) {
    const evidence = restoreEvidenceFixture();
    delete evidence[field];
    assert.equal(validate(evidence), false, `missing ${field} must be rejected`);
  }
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

// --- backup-policy-v1 ---------------------------------------------------------

function backupPolicyFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-policy/v1",
    policyId: POLICY_ID,
    installationId: "inst-1",
    appliedGeneration: 3,
    appliedManifestDigest: sha("1"),
    schedule: "03:30",
    destinations: [localDestination(), s3Destination()],
    retention: { daily: 7, weekly: 4, monthly: 6 },
    includeRetainedVolumes: true,
    ...overrides,
  };
}

test("backup-policy-v1: a genuine applied policy validates", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.ok(validate(backupPolicyFixture()), JSON.stringify(validate.errors));
});

test("backup-policy-v1: rejects includeRetainedVolumes: false - the fixed platform rule for this policy version", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(backupPolicyFixture({ includeRetainedVolumes: false })), false);
});

test("backup-policy-v1: rejects a schedule outside HH:MM (target-local time, never a cron expression)", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(backupPolicyFixture({ schedule: "0 3 * * *" })), false);
  assert.equal(validate(backupPolicyFixture({ schedule: "24:00" })), false);
});

test("backup-policy-v1: rejects an empty destinations array", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(backupPolicyFixture({ destinations: [] })), false);
});

test("backup-policy-v1: rejects a credential-bearing S3 endpoint", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  const destination = s3Destination({ endpoint: "https://key:secret@s3.example.com" });
  assert.equal(validate(backupPolicyFixture({ destinations: [destination] })), false);
});

test("backup-policy-v1: rejects a raw credential smuggled in", async () => {
  const validate = await validatorFor("backup-policy-v1.schema.json");
  assert.equal(validate(backupPolicyFixture({ rootAgeIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

// --- recovery-kit-v1 -----------------------------------------------------------

function recoveryKitFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/recovery-kit/v1",
    installationId: "inst-1",
    createdAt: "2026-09-04T09:00:00Z",
    createdForGeneration: 3,
    ageRecipient: "age1" + "q".repeat(58),
    ageRecipientFingerprint: sha("9"),
    contentInventory: ["application-secrets", "tls-private-keys", "backup-destination-credentials"],
    ciphertextDigest: sha("8"),
    ciphertext: Buffer.from("not-a-real-age-ciphertext-payload").toString("base64"),
    ...overrides,
  };
}

test("recovery-kit-v1: a genuine recovery kit validates", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.ok(validate(recoveryKitFixture()), JSON.stringify(validate.errors));
});

test("recovery-kit-v1: rejects an empty contentInventory", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ contentInventory: [] })), false);
});

test("recovery-kit-v1: rejects a duplicate contentInventory category", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ contentInventory: ["application-secrets", "application-secrets"] })), false);
});

test("recovery-kit-v1: rejects a contentInventory category outside the fixed, closed set", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ contentInventory: ["ssh-host-keys"] })), false);
});

test("recovery-kit-v1: rejects a malformed age recipient", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ ageRecipient: "not-an-age-recipient" })), false);
});

test("recovery-kit-v1: rejects a private age identity smuggled in - the recipient is public, the identity never appears here", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ ageIdentity: "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP" })), false);
});

test("recovery-kit-v1: rejects a plaintext value smuggled in under any other field name", async () => {
  const validate = await validatorFor("recovery-kit-v1.schema.json");
  assert.equal(validate(recoveryKitFixture({ plaintextPreview: "hunter2" })), false);
});

// --- scripts/backup-ids.mjs (pure helpers) --------------------------------------

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

test("computeBackupId: deterministic - the same four inputs always produce the same id", () => {
  const input = { installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 };
  assert.equal(computeBackupId(input), computeBackupId({ ...input }));
});

test("computeBackupId: two repeat backups (identical installation/generation/policy) get different ids purely from backupSequence", () => {
  const first = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 });
  const second = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 5 });
  assert.notEqual(first, second, "a repeat backup with everything else unchanged must still mint a fresh id");
});

test("computeBackupId: a different installation, generation, or policy each independently changes the id", () => {
  const base = { installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 };
  const baseId = computeBackupId(base);
  assert.notEqual(computeBackupId({ ...base, installationId: "inst-2" }), baseId);
  assert.notEqual(computeBackupId({ ...base, generation: 4 }), baseId);
  assert.notEqual(computeBackupId({ ...base, backupPolicyId: sha("z") }), baseId);
});

test("computeBackupId: is not a content-id of a whole plan - it never sees consistencySet/destinations at all", () => {
  const a = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 });
  // Two plans differing only in consistencySet/destinations, but with the SAME four backupId inputs, get the SAME backupId - by design (see ADR 0006), since what actually distinguishes a repeat attempt is the sequence, not incidental plan content.
  const b = computeBackupId({ installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 });
  assert.equal(a, b);
});

test("computeBackupId: rejects a non-positive-integer backupSequence or generation", () => {
  const base = { installationId: "inst-1", generation: 3, backupPolicyId: POLICY_ID, backupSequence: 4 };
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

  const ops = [backupOperation({ id: "005.snapshot.create.onsite" }), backupOperation({ id: "005.snapshot.create.onsite" })];
  assert.equal(hasDuplicates(ops, (op) => op.id), true);
});
