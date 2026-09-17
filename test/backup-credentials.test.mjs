// scripts/backup-credentials.mjs coverage - the typed, decrypted backup-
// destination credentials store (ADR 0006, item 10 PR 3). The SOPS-
// shelling orchestration (readBackupCredentialsStore/
// writeBackupCredentialsStore) runs against the SAME fake "sops" binary
// fixture test/secrets.test.mjs already established
// (test/fixtures/secrets-fake-sops) - same "verify for real once by
// hand, fake for the fast suite" pattern, no second fixture needed since
// this module's own SOPS transport is byte-for-byte the same shelling
// convention secrets.mjs already uses.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { readBackupCredentialsStore, validateBackupCredentials, writeBackupCredentialsStore } from "../scripts/backup-credentials.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeSopsDir = path.join(root, "test/fixtures/secrets-fake-sops");

let workDir;
test.before(async () => { workDir = await mkdtemp(path.join(tmpdir(), "hof-backup-credentials-")); });
test.after(async () => { if (workDir) await rm(workDir, { recursive: true, force: true }); });

function withFakeSops(fn) {
  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeSopsDir}${path.delimiter}${originalPath}`;
  return fn().finally(() => { process.env.PATH = originalPath; });
}

function localDestination(overrides = {}) {
  return { name: "onsite", type: "local", path: "/mnt/hof-backups", secretRef: "backup-onsite-key", ...overrides };
}

function s3Destination(overrides = {}) {
  return { name: "offsite", type: "s3", bucket: "hof-backups-example", region: "eu-central-1", secretRef: "backup-offsite-key", ...overrides };
}

function localCredential(overrides = {}) {
  return { type: "local", resticPassword: "resticpw-onsite", ...overrides };
}

function s3Credential(overrides = {}) {
  return { type: "s3", resticPassword: "resticpw-offsite", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "s3cr3tkey", ...overrides };
}

// --- validateBackupCredentials: happy paths -----------------------------

test("validateBackupCredentials: a local destination with a matching, well-typed credential has zero violations", () => {
  const destinations = [localDestination()];
  const credentials = { "backup-onsite-key": localCredential() };
  assert.deepEqual(validateBackupCredentials(destinations, credentials), []);
});

test("validateBackupCredentials: an s3 destination with a matching credential, including an optional sessionToken, has zero violations", () => {
  const destinations = [s3Destination()];
  const credentials = { "backup-offsite-key": s3Credential({ sessionToken: "session-abc" }) };
  assert.deepEqual(validateBackupCredentials(destinations, credentials), []);
});

test("validateBackupCredentials: an s3 destination's credential without sessionToken (the common case - a long-lived key pair) has zero violations", () => {
  const destinations = [s3Destination()];
  const credentials = { "backup-offsite-key": s3Credential() };
  assert.deepEqual(validateBackupCredentials(destinations, credentials), []);
});

test("validateBackupCredentials: a mix of local and s3 destinations, each with its own correctly-typed credential, has zero violations", () => {
  const destinations = [localDestination(), s3Destination()];
  const credentials = { "backup-onsite-key": localCredential(), "backup-offsite-key": s3Credential() };
  assert.deepEqual(validateBackupCredentials(destinations, credentials), []);
});

// --- missing / foreign / duplicate refs ---------------------------------

test("validateBackupCredentials: flags a destination with no matching credential entry at all", () => {
  const violations = validateBackupCredentials([localDestination()], {});
  assert.ok(violations.some((v) => v.includes("missing credentials") && v.includes("backup-onsite-key")));
});

test("validateBackupCredentials: flags a credentials entry whose secretRef no destination actually uses", () => {
  const violations = validateBackupCredentials([localDestination()], {
    "backup-onsite-key": localCredential(),
    "backup-unused-key": localCredential(),
  });
  assert.ok(violations.some((v) => v.includes("no destination actually uses") && v.includes("backup-unused-key")));
});

test("validateBackupCredentials: flags two destinations sharing one secretRef", () => {
  const violations = validateBackupCredentials(
    [localDestination({ name: "onsite" }), localDestination({ name: "onsite-2" })],
    { "backup-onsite-key": localCredential() },
  );
  assert.ok(violations.some((v) => v.includes("duplicate secretRef")));
});

test("validateBackupCredentials: missing AND foreign are both reported at once, never just the first one found", () => {
  const violations = validateBackupCredentials(
    [localDestination()],
    { "backup-unrelated-key": localCredential() },
  );
  assert.ok(violations.some((v) => v.includes("missing credentials")));
  assert.ok(violations.some((v) => v.includes("no destination actually uses")));
});

// --- type mismatch --------------------------------------------------------

test("validateBackupCredentials: flags a credential typed \"s3\" for a destination that is actually \"local\"", () => {
  const violations = validateBackupCredentials([localDestination()], { "backup-onsite-key": s3Credential() });
  assert.ok(violations.some((v) => v.includes(".type") && v.includes("does not match destination")));
});

test("validateBackupCredentials: flags a credential typed \"local\" for a destination that is actually \"s3\"", () => {
  const violations = validateBackupCredentials([s3Destination()], { "backup-offsite-key": localCredential() });
  assert.ok(violations.some((v) => v.includes(".type") && v.includes("does not match destination")));
});

// --- empty / missing / unexpected fields ----------------------------------

test("validateBackupCredentials: flags an empty resticPassword on a local credential", () => {
  const violations = validateBackupCredentials([localDestination()], { "backup-onsite-key": localCredential({ resticPassword: "" }) });
  assert.ok(violations.some((v) => v.includes("resticPassword")));
});

test("validateBackupCredentials: flags a missing accessKeyId/secretAccessKey on an s3 credential", () => {
  const violations = validateBackupCredentials([s3Destination()], {
    "backup-offsite-key": { type: "s3", resticPassword: "p" },
  });
  assert.ok(violations.some((v) => v.includes("accessKeyId")));
  assert.ok(violations.some((v) => v.includes("secretAccessKey")));
});

test("validateBackupCredentials: an empty-string sessionToken, when present, is flagged (must be non-empty or simply absent)", () => {
  const violations = validateBackupCredentials([s3Destination()], { "backup-offsite-key": s3Credential({ sessionToken: "" }) });
  assert.ok(violations.some((v) => v.includes("sessionToken")));
});

test("validateBackupCredentials: flags an unexpected field on a local credential (e.g. a stray accessKeyId) - closedness, not merely required-fields-present", () => {
  const violations = validateBackupCredentials([localDestination()], {
    "backup-onsite-key": { type: "local", resticPassword: "p", accessKeyId: "should-not-be-here" },
  });
  assert.ok(violations.some((v) => v.includes("unexpected field") && v.includes("accessKeyId")));
});

test("validateBackupCredentials: flags a credential entry that isn't even an object", () => {
  const violations = validateBackupCredentials([localDestination()], { "backup-onsite-key": "just-a-string" });
  assert.ok(violations.some((v) => v.includes("is not an object")));
});

// --- S3 endpoint with embedded credential/query/fragment -----------------

test("validateBackupCredentials: refuses an s3 destination whose endpoint carries embedded userinfo (https://user:pass@host)", () => {
  const violations = validateBackupCredentials(
    [s3Destination({ endpoint: "https://AKIAEXAMPLE:secret@s3.example.com" })],
    { "backup-offsite-key": s3Credential() },
  );
  assert.ok(violations.some((v) => v.includes("embedded credential")));
});

test("validateBackupCredentials: refuses an s3 destination whose endpoint carries a query string", () => {
  const violations = validateBackupCredentials(
    [s3Destination({ endpoint: "https://s3.example.com/?token=leaked" })],
    { "backup-offsite-key": s3Credential() },
  );
  assert.ok(violations.some((v) => v.includes("embedded credential")));
});

test("validateBackupCredentials: refuses an s3 destination whose endpoint carries a fragment", () => {
  const violations = validateBackupCredentials(
    [s3Destination({ endpoint: "https://s3.example.com/#leaked" })],
    { "backup-offsite-key": s3Credential() },
  );
  assert.ok(violations.some((v) => v.includes("embedded credential")));
});

test("validateBackupCredentials: a genuinely clean s3 endpoint (no userinfo/query/fragment) is never flagged", () => {
  const violations = validateBackupCredentials(
    [s3Destination({ endpoint: "https://s3.example.com/bucket-path" })],
    { "backup-offsite-key": s3Credential() },
  );
  assert.deepEqual(violations, []);
});

// --- readBackupCredentialsStore / writeBackupCredentialsStore ------------

test("readBackupCredentialsStore: a genuinely absent store returns {} - not an error", async () => {
  const values = await readBackupCredentialsStore({ storePath: path.join(workDir, "does-not-exist.sops.json") });
  assert.deepEqual(values, {});
});

test("writeBackupCredentialsStore/readBackupCredentialsStore: a real round trip through the fake sops binary", () => withFakeSops(async () => {
  const storePath = path.join(workDir, "roundtrip.sops.json");
  const credentials = { "backup-onsite-key": localCredential() };
  await writeBackupCredentialsStore({ storePath, credentials, recipients: ["age1recoveryxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"] });
  const read = await readBackupCredentialsStore({ storePath, identityFile: await writeIdentity("age1recoveryxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") });
  assert.deepEqual(read, credentials);
}));

test("writeBackupCredentialsStore: refuses to write with zero recipients - never an unrecoverable or unencrypted store", async () => {
  await assert.rejects(
    () => writeBackupCredentialsStore({ storePath: path.join(workDir, "no-recipients.sops.json"), credentials: {}, recipients: [] }),
    /at least one age recipient/,
  );
});

test("readBackupCredentialsStore: a genuine decrypt failure (wrong identity) fails closed - never silently treated as an empty store", () => withFakeSops(async () => {
  const storePath = path.join(workDir, "wrong-identity.sops.json");
  await writeBackupCredentialsStore({ storePath, credentials: { "backup-onsite-key": localCredential() }, recipients: ["age1correctxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"] });
  const wrongIdentityFile = await writeIdentity("age1wrongxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
  await assert.rejects(() => readBackupCredentialsStore({ storePath, identityFile: wrongIdentityFile }));
}));

test("readBackupCredentialsStore: a store that exists but isn't real sops-encrypted JSON at all fails closed", async () => {
  const { writeFile } = await import("node:fs/promises");
  const storePath = path.join(workDir, "corrupt.sops.json");
  await writeFile(storePath, "not json at all");
  await assert.rejects(() => readBackupCredentialsStore({ storePath }));
});

let identityCounter = 0;
async function writeIdentity(recipient) {
  const { writeFile } = await import("node:fs/promises");
  identityCounter += 1;
  const identityFile = path.join(workDir, `identity-${identityCounter}.txt`);
  await writeFile(identityFile, `${recipient}\n`);
  return identityFile;
}
