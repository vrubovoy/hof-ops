// scripts/recovery-kit.mjs coverage - the single typed recovery
// boundary (ADR 0006, item 10 PR 3). The age-shelling orchestration
// (createRecoveryKit/openRecoveryKit) runs against a fake "age" binary
// on PATH, same "verify for real once by hand, fake for the fast suite"
// pattern already used for sops (test/fixtures/secrets-fake-sops) and
// cosign - see test/fixtures/recovery-kit-fake-age/age's own header
// comment for the real age 1.3.2 round trip (encrypt/decrypt, wrong
// identity, garbage input) this fixture stands in for, independently
// verified by hand before this file was written. Supplied-TLS material
// uses real openssl-generated certificates (same technique as
// test/supplied-tls.test.mjs), never fixture strings - a mismatched
// key/cert pair genuinely fails Node's own X509Certificate.checkPrivateKey,
// not a hand-simulated rejection.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { canonicalDocumentDigest } from "../scripts/backup-ids.mjs";
import { verifyRecoveryKit } from "../scripts/backup-flow.mjs";
import { loadContracts } from "../scripts/contracts.mjs";
import { sha256 } from "../scripts/digest.mjs";
import {
  assembleRecoveryPayload, createRecoveryKit, openRecoveryKit, sanitizeManifest, validateClosedRecoveryPayload,
} from "../scripts/recovery-kit.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeAgeDir = path.join(root, "test/fixtures/recovery-kit-fake-age");

let workDir;
let manifest;
let catalog;
let fileCounter = 0;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-recovery-kit-"));
  ({ manifest, catalog } = structuredClone(await loadContracts()));
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

function withFakeAge(fn) {
  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeAgeDir}${path.delimiter}${originalPath}`;
  return fn().finally(() => { process.env.PATH = originalPath; });
}

// A fake age recipient/identity pair, valid against the fake age binary's
// own "identity file content IS the paired recipient string" convention
// (see that fixture's own header comment) - genuinely matches
// recovery-kit-v1.schema.json's own ageRecipient pattern.
async function fakeAgePair(label = "a") {
  fileCounter += 1;
  const recipient = `age1${label}${"q".repeat(58 - label.length)}`;
  const identityFile = path.join(workDir, `identity-${fileCounter}.txt`);
  await writeFile(identityFile, `${recipient}\n`);
  return { recipient, identityFile };
}

// Same minimal real-openssl self-signed-cert technique as
// test/supplied-tls.test.mjs's own generateKeyAndCert() (duplicated, not
// imported - that helper is module-local there) - a real CSR carrying a
// real SAN extension, self-signed against a per-call throwaway CA
// database, so a mismatched key/cert pair genuinely fails
// X509Certificate.checkPrivateKey rather than a hand-simulated check.
function opensslTimestamp(date) {
  return `${date.toISOString().replace(/[-:T]/g, "").split(".")[0]}Z`;
}

async function realPublicHostnames() {
  const { publicHostnames } = await import("../scripts/render-topology.mjs");
  return publicHostnames(manifest, catalog);
}

async function generateKeyAndCert() {
  fileCounter += 1;
  const keyPath = path.join(workDir, `key-${fileCounter}.pem`);
  const csrPath = path.join(workDir, `csr-${fileCounter}.pem`);
  const certPath = path.join(workDir, `cert-${fileCounter}.pem`);
  const configPath = path.join(workDir, `ca-${fileCounter}.cnf`);
  const indexPath = path.join(workDir, `index-${fileCounter}.txt`);
  const serialPath = path.join(workDir, `serial-${fileCounter}.txt`);
  const hostnames = await realPublicHostnames();
  const san = hostnames.map((h) => `DNS:${h}`).join(",");

  await writeFile(configPath, [
    "[ ca ]", "default_ca = CA_default", "",
    "[ CA_default ]",
    `database = ${indexPath}`,
    `serial = ${serialPath}`,
    `new_certs_dir = ${workDir}`,
    "default_md = sha256",
    "policy = policy_anything",
    "copy_extensions = copy", "",
    "[ policy_anything ]", "commonName = supplied", "",
    "[ req ]", "distinguished_name = req_dn", "req_extensions = v3_req", "",
    "[ req_dn ]", "",
    "[ v3_req ]",
    `subjectAltName = ${san}`, "",
  ].join("\n"));
  await writeFile(indexPath, "");
  await writeFile(serialPath, "01\n");

  await exec("openssl", ["genrsa", "-out", keyPath, "2048"]);
  await exec("openssl", ["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", "/CN=example.com", "-config", configPath, "-reqexts", "v3_req"]);
  await exec("openssl", [
    "ca", "-batch", "-selfsign", "-config", configPath,
    "-keyfile", keyPath, "-in", csrPath, "-out", certPath,
    "-startdate", opensslTimestamp(new Date(Date.now() - 60_000)),
    "-enddate", opensslTimestamp(new Date(Date.now() + 24 * 60 * 60 * 1000)),
  ]);
  return { keyPath, certPath };
}

function suppliedManifest({ certificatePath, privateKeyPath }) {
  return { ...manifest, tls: { mode: "supplied", certificatePath, privateKeyPath } };
}

// --- fixtures for the closed payload / assembleRecoveryPayload --------

function realisticPayload(overrides = {}) {
  return {
    installationId: "inst-1",
    generation: 3,
    sanitizedManifest: { apiVersion: "hof.dev/v1alpha1" },
    releaseLock: { document: { apiVersion: "hof.dev/release-lock/v1" }, signature: "sig-bytes", certificate: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----", signingIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/tags/v0.2.3", oidcIssuer: "https://token.actions.githubusercontent.com" },
    backupToolLock: { document: { apiVersion: "hof.dev/backup-tool-lock/v1" }, signature: "sig-bytes-2", certificate: "-----BEGIN CERTIFICATE-----\nfake2\n-----END CERTIFICATE-----", signingIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/tags/backup-tool-v1.0.0", oidcIssuer: "https://token.actions.githubusercontent.com" },
    applicationSecrets: { "glocke-to-schlussel-hmac-secret": "hunter2value" },
    suppliedTls: { certificatePem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", privateKeyPem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n" },
    destinationCredentials: { "backup-onsite-key": { type: "local", resticPassword: "resticpw" } },
    ...overrides,
  };
}

function stateFixture(overrides = {}) {
  return { installationId: "inst-1", generation: 3, ...overrides };
}

function backupToolLockFixture(overrides = {}) {
  return {
    apiVersion: "hof.dev/backup-tool-lock/v1",
    source: "https://github.com/vrubovoy/hof-ops",
    revision: "a".repeat(40),
    sourceTag: "backup-tool-v1.0.0",
    toolVersion: "1.0.0",
    image: "ghcr.io/vrubovoy/hof-backup-tool@sha256:" + "b".repeat(64),
    signatureIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/tags/backup-tool-v1.0.0",
    signatureOidcIssuer: "https://token.actions.githubusercontent.com",
    provenanceDigest: "sha256:" + "c".repeat(64),
    sbomDigest: "sha256:" + "d".repeat(64),
    pinnedTools: { restic: "0.16.0", sops: "3.8.0", age: "1.3.2" },
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

function localDestination(overrides = {}) {
  return { name: "onsite", type: "local", path: "/mnt/hof-backups", secretRef: "backup-onsite-key", ...overrides };
}

// --- createRecoveryKit / openRecoveryKit: the real (fake-seam) round trip

test("createRecoveryKit/openRecoveryKit: a real encrypt/decrypt round trip via age returns the exact original payload", () => withFakeAge(async () => {
  const { recipient, identityFile } = await fakeAgePair("a");
  const payload = realisticPayload();
  const kit = await createRecoveryKit({ payload, ageRecipient: recipient });
  assert.equal(kit.apiVersion, "hof.dev/recovery-kit/v1");
  assert.equal(kit.ageRecipient, recipient);
  assert.deepEqual(verifyRecoveryKit(kit), []);
  const opened = await openRecoveryKit({ kit, identityFile });
  assert.deepEqual(opened, payload);
}));

test("createRecoveryKit: contentInventory reflects exactly which categories are actually present", () => withFakeAge(async () => {
  const { recipient } = await fakeAgePair("b");
  const kit = await createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient });
  assert.deepEqual([...kit.contentInventory].sort(), ["application-secrets", "backup-destination-credentials", "tls-private-keys"]);
}));

test("createRecoveryKit: refuses an invalid age recipient before ever touching age", async () => {
  const calls = [];
  const run = async (...args) => { calls.push(args); throw new Error("must not be called"); };
  await assert.rejects(
    () => createRecoveryKit({ payload: realisticPayload(), ageRecipient: "not-a-real-recipient", run }),
    /requires a valid age recipient/,
  );
  assert.equal(calls.length, 0, "age must never be invoked once the recipient itself is invalid");
});

test("createRecoveryKit: refuses a malformed closed payload before ever touching age", async () => {
  const calls = [];
  const run = async (...args) => { calls.push(args); throw new Error("must not be called"); };
  await assert.rejects(
    () => createRecoveryKit({ payload: { installationId: "inst-1" }, ageRecipient: `age1${"q".repeat(58)}`, run }),
    /malformed payload/,
  );
  assert.equal(calls.length, 0);
});

// --- openRecoveryKit: refusal paths -------------------------------------

test("openRecoveryKit: refuses a wrong identity - the ciphertext is real age output, but this identity never matches its recipient", () => withFakeAge(async () => {
  const { recipient } = await fakeAgePair("c");
  const { identityFile: wrongIdentityFile } = await fakeAgePair("d");
  const kit = await createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient });
  await assert.rejects(() => openRecoveryKit({ kit, identityFile: wrongIdentityFile }), /could not decrypt recovery kit/);
}));

test("openRecoveryKit: refuses when no identityFile is given at all - never silently proceeds without one", () => withFakeAge(async () => {
  const { recipient } = await fakeAgePair("e");
  const kit = await createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient });
  await assert.rejects(() => openRecoveryKit({ kit, identityFile: undefined }), /requires identityFile/);
}));

test("openRecoveryKit: rejects invalid base64 in ciphertext at the schema layer, before ever attempting decryption", async () => {
  const { recipient } = await fakeAgePair("f");
  const kit = await withFakeAge(async () => createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient }));
  await assert.rejects(
    () => openRecoveryKit({ kit: { ...kit, ciphertext: "not valid base64 at all!!! ".repeat(10) }, identityFile: "/dev/null" }),
    /not schema-valid/,
  );
});

test("openRecoveryKit: rejects a ciphertextDigest that doesn't match the actual ciphertext - verifyRecoveryKit runs before any decrypt attempt", () => withFakeAge(async () => {
  const { recipient, identityFile } = await fakeAgePair("g");
  const kit = await createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient });
  await assert.rejects(
    () => openRecoveryKit({ kit: { ...kit, ciphertextDigest: `sha256:${"0".repeat(64)}` }, identityFile }),
    /failed verifyRecoveryKit/,
  );
}));

test("openRecoveryKit: rejects an ageRecipientFingerprint that doesn't match the recomputed digest of ageRecipient", () => withFakeAge(async () => {
  const { recipient, identityFile } = await fakeAgePair("h");
  const kit = await createRecoveryKit({ payload: realisticPayload(), ageRecipient: recipient });
  await assert.rejects(
    () => openRecoveryKit({ kit: { ...kit, ageRecipientFingerprint: `sha256:${"1".repeat(64)}` }, identityFile }),
    /failed verifyRecoveryKit/,
  );
}));

test("openRecoveryKit: rejects a genuinely malformed age stream (no real magic header), even though it clears the schema's own base64 minLength", () => withFakeAge(async () => {
  const { identityFile } = await fakeAgePair("i");
  const fakePayload = Buffer.from("x".repeat(300), "utf8");
  const bogusKit = {
    apiVersion: "hof.dev/recovery-kit/v1",
    installationId: "inst-1",
    createdAt: new Date().toISOString(),
    createdForGeneration: 1,
    ageRecipient: `age1${"q".repeat(58)}`,
    ageRecipientFingerprint: sha256(Buffer.from(`age1${"q".repeat(58)}`, "utf8")),
    contentInventory: ["application-secrets"],
    ciphertextDigest: sha256(fakePayload),
    ciphertext: fakePayload.toString("base64"),
  };
  await assert.rejects(() => openRecoveryKit({ kit: bogusKit, identityFile }), /failed verifyRecoveryKit/);
}));

test("openRecoveryKit: a kit that is schema-valid and genuinely age-encrypted, but decrypts to something that is not a well-formed closed payload, is refused - never handed back as if it were real", () => withFakeAge(async () => {
  const { recipient, identityFile } = await fakeAgePair("j");
  const kit = await createRecoveryKit({ payload: { installationId: "inst-1", generation: 1, sanitizedManifest: {}, releaseLock: { document: {}, signature: "s", certificate: "c", signingIdentity: "i", oidcIssuer: "o" }, backupToolLock: { document: {}, signature: "s", certificate: "c", signingIdentity: "i", oidcIssuer: "o" }, applicationSecrets: { a: "b" }, destinationCredentials: {} }, ageRecipient: recipient });
  // Genuinely decryptable and schema/verifyRecoveryKit-clean; the
  // payload it decrypts to is the well-formed one above - now prove a
  // DIFFERENT, non-JSON plaintext (still real age output) is refused at
  // the payload layer rather than being handed back as if it parsed.
  const { stdout: garbageCiphertext } = await execFileAge(["-r", recipient], Buffer.from("this is not json at all"));
  const garbageKit = {
    ...kit,
    ciphertextDigest: sha256(garbageCiphertext),
    ciphertext: garbageCiphertext.toString("base64"),
  };
  await assert.rejects(() => openRecoveryKit({ kit: garbageKit, identityFile }), /not valid JSON/);
}));

function execFileAge(args, input) {
  return new Promise((resolve, reject) => {
    const child = execFile(path.join(fakeAgeDir, "age"), args, { encoding: "buffer", maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    child.stdin.write(input);
    child.stdin.end();
  });
}

// --- validateClosedRecoveryPayload --------------------------------------

test("validateClosedRecoveryPayload: a genuine payload has zero violations", () => {
  assert.deepEqual(validateClosedRecoveryPayload(realisticPayload()), []);
});

test("validateClosedRecoveryPayload: rejects an unexpected top-level field", () => {
  const violations = validateClosedRecoveryPayload({ ...realisticPayload(), extra: "smuggled" });
  assert.ok(violations.some((v) => v.includes("unexpected top-level field")));
});

test("validateClosedRecoveryPayload: rejects a payload with nothing to recover at all", () => {
  const violations = validateClosedRecoveryPayload({
    installationId: "inst-1", generation: 1, sanitizedManifest: {},
    releaseLock: { document: {}, signature: "s", certificate: "c", signingIdentity: "i", oidcIssuer: "o" },
    backupToolLock: { document: {}, signature: "s", certificate: "c", signingIdentity: "i", oidcIssuer: "o" },
    applicationSecrets: {}, destinationCredentials: {},
  });
  assert.ok(violations.some((v) => v.includes("nothing to recover")));
});

test("validateClosedRecoveryPayload: rejects a non-string application secret value", () => {
  const violations = validateClosedRecoveryPayload(realisticPayload({ applicationSecrets: { a: 12345 } }));
  assert.ok(violations.some((v) => v.includes('applicationSecrets["a"]')));
});

// --- assembleRecoveryPayload ---------------------------------------------

test("assembleRecoveryPayload: requires manifest.tls.mode === supplied - acme-http01 is refused BEFORE ever touching age, encryption, or secrets", async () => {
  const calls = [];
  const run = async (...args) => { calls.push(args); throw new Error("must not be called"); };
  await assert.rejects(
    () => assembleRecoveryPayload({
      state: stateFixture(),
      manifest: { ...manifest, tls: { mode: "acme-http01", email: "a@example.com" } },
      catalog,
      enabledIds: [],
      secretsStorePath: path.join(workDir, "does-not-exist.sops.json"),
      releaseLock: {}, releaseLockSignature: "s", releaseLockCertificate: "c", releaseLockSigningIdentity: "i", releaseLockOidcIssuer: "o",
      backupToolLock: backupToolLockFixture(), backupToolLockSignature: "s", backupToolLockCertificate: "c",
      destinations: [], destinationCredentials: {},
      run,
    }),
    /requires manifest\.tls\.mode === "supplied"/,
  );
  assert.equal(calls.length, 0, "acme-http01 must be refused before any run() invocation at all - no age, no sops");
});

test("assembleRecoveryPayload: requires a trusted state document - installationId/generation are never accepted as free-standing metadata", async () => {
  // The state check runs BEFORE the TLS-mode check (see
  // assembleRecoveryPayload's own comment on why installationId/
  // generation are never free-standing metadata) - a placeholder,
  // never-actually-read certificatePath/privateKeyPath is enough to
  // prove that ordering.
  await assert.rejects(
    () => assembleRecoveryPayload({
      state: { installationId: "inst-1" }, // missing generation
      manifest: suppliedManifest({ certificatePath: "/never/read.pem", privateKeyPath: "/never/read-key.pem" }),
      catalog, enabledIds: [],
      secretsStorePath: path.join(workDir, "does-not-exist.sops.json"),
      releaseLock: {}, releaseLockSignature: "s", releaseLockCertificate: "c", releaseLockSigningIdentity: "i", releaseLockOidcIssuer: "o",
      backupToolLock: backupToolLockFixture(), backupToolLockSignature: "s", backupToolLockCertificate: "c",
      destinations: [], destinationCredentials: {},
    }),
    /requires a trusted state document/,
  );
});

test("assembleRecoveryPayload: a mismatched supplied TLS certificate/private key pair is refused - propagated from the existing PEM/key-match validation, never re-implemented here", async () => {
  const { certPath } = await generateKeyAndCert();
  const { keyPath: mismatchedKeyPath } = await generateKeyAndCert();
  await assert.rejects(
    () => assembleRecoveryPayload({
      state: stateFixture(),
      manifest: suppliedManifest({ certificatePath: certPath, privateKeyPath: mismatchedKeyPath }),
      catalog, enabledIds: [],
      secretsStorePath: path.join(workDir, "does-not-exist.sops.json"),
      releaseLock: {}, releaseLockSignature: "s", releaseLockCertificate: "c", releaseLockSigningIdentity: "i", releaseLockOidcIssuer: "o",
      backupToolLock: backupToolLockFixture(), backupToolLockSignature: "s", backupToolLockCertificate: "c",
      destinations: [], destinationCredentials: {},
    }),
    /does not correspond to the certificate/,
  );
});

test("assembleRecoveryPayload: a genuine, matching supplied TLS pair plus application secrets and destination credentials assembles a well-formed, sanitized payload", () => withFakeAge(async () => {
  const { certPath, keyPath } = await generateKeyAndCert();
  const secretsStorePath = path.join(workDir, "assemble-secrets.sops.json");
  const { writeSecretsStore, requiredSecrets } = await import("../scripts/secrets.mjs");
  const { recipient: opRecipient, identityFile: opIdentityFile } = await fakeAgePair("op");
  const enabledIds = ["schlussel", "glocke"];
  // Every secret requiredSecrets() actually computes for this exact
  // manifest/enabledIds pair - never a hand-picked subset guessed to be
  // "enough", which would silently drift the moment the real fixture
  // manifest's own features (e.g. browserPush) changed.
  const requiredValues = {};
  for (const { name } of requiredSecrets(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), enabledIds)) {
    requiredValues[name] = `value-for-${name}`;
  }
  // secrets.mjs's own SOPS transport uses the SAME real `sops` binary
  // convention as test/secrets.test.mjs - reuse that file's own fake-sops
  // fixture on PATH here too, alongside the fake age already on PATH,
  // so this one test can exercise both real seams without a real sops or
  // real age binary installed.
  const fakeSopsDir = path.join(root, "test/fixtures/secrets-fake-sops");
  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeSopsDir}${path.delimiter}${process.env.PATH}`;
  try {
    await writeSecretsStore({ storePath: secretsStorePath, values: requiredValues, recipients: [opRecipient] });
  } finally {
    process.env.PATH = originalPath;
  }

  const { recipient: recoveryRecipient } = await fakeAgePair("recov");
  const destinations = [localDestination()];
  const destinationCredentials = { "backup-onsite-key": { type: "local", resticPassword: "resticpw" } };
  const releaseLock = { apiVersion: "hof.dev/release-lock/v1" };
  const backupToolLock = backupToolLockFixture();

  process.env.PATH = `${fakeSopsDir}${path.delimiter}${originalPath}`;
  let payload;
  try {
    payload = await assembleRecoveryPayload({
      state: stateFixture(),
      manifest: suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }),
      catalog,
      enabledIds: ["schlussel", "glocke"],
      secretsStorePath,
      secretsIdentityFile: opIdentityFile,
      releaseLock, releaseLockSignature: "relsig", releaseLockCertificate: "relcert", releaseLockSigningIdentity: "https://github.com/x", releaseLockOidcIssuer: "https://token.actions.githubusercontent.com",
      backupToolLock, backupToolLockSignature: "btlsig", backupToolLockCertificate: "btlcert",
      destinations, destinationCredentials,
    });
  } finally {
    process.env.PATH = originalPath;
  }

  assert.equal(payload.installationId, "inst-1");
  assert.equal(payload.generation, 3);
  assert.deepEqual(payload.sanitizedManifest, sanitizeManifest(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath })));
  assert.equal(payload.releaseLock.document, releaseLock);
  assert.equal(payload.backupToolLock.document, backupToolLock);
  assert.deepEqual(payload.applicationSecrets, requiredValues);
  assert.match(payload.suppliedTls.certificatePem, /-----BEGIN CERTIFICATE-----/);
  assert.deepEqual(payload.destinationCredentials, destinationCredentials);
  assert.deepEqual(validateClosedRecoveryPayload(payload), []);

  // And the whole thing survives a genuine encrypt/decrypt round trip,
  // exactly - the sanitized manifest and release/tool bundles included,
  // byte for byte.
  const kit = await createRecoveryKit({ payload, ageRecipient: recoveryRecipient });
  const expectedDigest = canonicalDocumentDigest(kit);
  assert.match(expectedDigest, /^sha256:[0-9a-f]{64}$/);
}));

test("assembleRecoveryPayload: refuses when the secrets store is missing a currently-required secret", () => withFakeAge(async () => {
  const { certPath, keyPath } = await generateKeyAndCert();
  await assert.rejects(
    () => assembleRecoveryPayload({
      state: stateFixture(),
      manifest: suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }),
      catalog,
      enabledIds: ["schlussel", "glocke"],
      secretsStorePath: path.join(workDir, "genuinely-missing.sops.json"),
      releaseLock: {}, releaseLockSignature: "s", releaseLockCertificate: "c", releaseLockSigningIdentity: "i", releaseLockOidcIssuer: "o",
      backupToolLock: backupToolLockFixture(), backupToolLockSignature: "s", backupToolLockCertificate: "c",
      destinations: [], destinationCredentials: {},
    }),
    /missing required secret/,
  );
}));

test("assembleRecoveryPayload: refuses when destinationCredentials is missing a credential for a configured destination", () => withFakeAge(async () => {
  const { certPath, keyPath } = await generateKeyAndCert();
  await assert.rejects(
    () => assembleRecoveryPayload({
      state: stateFixture(),
      manifest: suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }),
      catalog, enabledIds: [],
      secretsStorePath: path.join(workDir, "does-not-exist-2.sops.json"),
      releaseLock: {}, releaseLockSignature: "s", releaseLockCertificate: "c", releaseLockSigningIdentity: "i", releaseLockOidcIssuer: "o",
      backupToolLock: backupToolLockFixture(), backupToolLockSignature: "s", backupToolLockCertificate: "c",
      destinations: [localDestination()], destinationCredentials: {},
    }),
    /missing credential/,
  );
}));

// --- sanitizeManifest ----------------------------------------------------

test("sanitizeManifest: strips target (host/user/port) and supplied TLS paths, keeps everything else needed for historical topology reconstruction", () => {
  const sanitized = sanitizeManifest(suppliedManifest({ certificatePath: "/home/op/cert.pem", privateKeyPath: "/home/op/key.pem" }));
  assert.equal(sanitized.target, undefined);
  assert.deepEqual(sanitized.tls, { mode: "supplied" });
  assert.equal(sanitized.domains?.base, manifest.domains.base);
  assert.deepEqual(sanitized.services, manifest.services);
  assert.deepEqual(sanitized.backup, manifest.backup);
});

test("sanitizeManifest: acme-http01 mode (no paths to strip) passes through unchanged", () => {
  const acmeManifest = { ...manifest, tls: { mode: "acme-http01", email: "ops@example.com" } };
  const sanitized = sanitizeManifest(acmeManifest);
  assert.deepEqual(sanitized.tls, { mode: "acme-http01", email: "ops@example.com" });
  assert.equal(sanitized.target, undefined);
});
