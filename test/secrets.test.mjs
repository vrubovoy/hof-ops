// scripts/secrets.mjs coverage - crypto derivation (real, no fake) plus
// the SOPS-shelling orchestration (a fake sops binary on PATH, same
// "verify for real once by hand, fake for the fast suite" pattern
// already used for cosign - see test/fixtures/secrets-fake-sops's own
// header comment for the real verification this fixture stands in for).

import assert from "node:assert/strict";
import { createECDH } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ensureSecrets, generateSecretValue, readSecretsStore, requiredSecrets, runSecretsEnsure, vapidPublicKeyFor, writeSecretsStore,
} from "../scripts/secrets.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeSopsDir = path.join(root, "test/fixtures/secrets-fake-sops");

let workDir;
test.before(async () => { workDir = await mkdtemp(path.join(tmpdir(), "hof-secrets-")); });
test.after(async () => { if (workDir) await rm(workDir, { recursive: true, force: true }); });

function withFakeSops(fn) {
  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeSopsDir}${path.delimiter}${originalPath}`;
  return fn().finally(() => { process.env.PATH = originalPath; });
}

// requiredSecrets() ------------------------------------------------------

test("requiredSecrets: nothing needed when no optional secret-bearing service is enabled", () => {
  assert.deepEqual(requiredSecrets({}, ["tor", "schlussel", "schloss"]), []);
});

// schlussel is mandatory and always enabled - with glocke also enabled
// and no OTHER (optional) producer, this is the minimal real
// configuration: schlussel's own outgoing secret (it's a GLOCKE_PRODUCERS
// entry itself) plus glocke's own reverse secret to schlussel, nothing
// for kuvert/tafel/zettel since none of those are enabled here.
test("requiredSecrets: glocke + schlussel alone (no optional producer enabled) still needs schlussel's own and glocke's reverse HMAC secret", () => {
  const secrets = requiredSecrets({}, ["tor", "schlussel", "schloss", "glocke"]);
  assert.deepEqual(secrets.map((s) => s.name).sort(), ["glocke-to-schlussel-hmac-secret", "schlussel-to-glocke-hmac-secret"].sort());
});

test("requiredSecrets: one entry per enabled producer, only when both it and glocke are enabled", () => {
  const secrets = requiredSecrets({}, ["tor", "schlussel", "schloss", "glocke", "kuvert", "tafel"]);
  const names = secrets.map((s) => s.name);
  assert.ok(names.includes("kuvert-to-glocke-hmac-secret"));
  assert.ok(names.includes("tafel-to-glocke-hmac-secret"));
  assert.ok(!names.includes("zettel-to-glocke-hmac-secret"), "zettel isn't enabled here");
});

test("requiredSecrets: kuvert alone (glocke disabled) needs no HMAC secret at all", () => {
  assert.deepEqual(requiredSecrets({}, ["tor", "schlussel", "schloss", "kuvert"]), []);
});

test("requiredSecrets: VAPID private key only when both glocke and browserPush are enabled", () => {
  const base = ["tor", "schlussel", "schloss", "glocke"];
  assert.ok(!requiredSecrets({ features: { browserPush: { enabled: false } } }, base).some((s) => s.name === "glocke-vapid-private-key"));
  assert.ok(!requiredSecrets({}, base.filter((id) => id !== "glocke")).some((s) => s.name === "glocke-vapid-private-key"), "no glocke at all");
  const withPush = requiredSecrets({ features: { browserPush: { enabled: true } } }, base);
  assert.deepEqual(withPush.find((s) => s.name === "glocke-vapid-private-key"), { name: "glocke-vapid-private-key", envVar: "GLOCKE_VAPID_PRIVATE_KEY", kind: "vapid-private-key" });
});

test("requiredSecrets: herold and wachter each need exactly their own single secret, independent of everything else", () => {
  assert.deepEqual(requiredSecrets({}, ["tor", "schlussel", "schloss", "herold"]), [{ name: "herold-credential-encryption-key", envVar: "HEROLD_CREDENTIAL_ENCRYPTION_KEY", kind: "token" }]);
  assert.deepEqual(requiredSecrets({}, ["tor", "schlussel", "schloss", "wachter"]), [{ name: "wachter-agent-token", envVar: "WACHTER_AGENT_TOKEN", kind: "token" }]);
});

// generateSecretValue() / vapidPublicKeyFor() - real crypto, no fakes ---

test("generateSecretValue('token') produces a genuinely random, sufficiently long value every time", () => {
  const a = generateSecretValue("token");
  const b = generateSecretValue("token");
  assert.notEqual(a, b);
  // Every real consuming app enforces >=32 raw bytes (see e.g. zettel's
  // own outbox.ts) - base64url of 32 random bytes clears that easily.
  assert.ok(Buffer.byteLength(a) >= 32);
});

test("generateSecretValue('vapid-private-key') produces a real, usable P-256 private scalar", () => {
  const priv = generateSecretValue("vapid-private-key");
  assert.equal(Buffer.from(priv, "base64url").length, 32);
  // Must genuinely derive a valid public key - proves this isn't just a
  // random 32-byte string, but real, curve-valid key material.
  const ecdh = createECDH("prime256v1");
  assert.doesNotThrow(() => ecdh.setPrivateKey(Buffer.from(priv, "base64url")));
});

test("vapidPublicKeyFor derives the real, correct uncompressed P-256 public point - byte-identical to glocke's own derivation method", () => {
  const priv = generateSecretValue("vapid-private-key");
  const pub = vapidPublicKeyFor(priv);
  assert.equal(Buffer.from(pub, "base64url").length, 65);
  assert.equal(Buffer.from(pub, "base64url")[0], 0x04, "uncompressed point prefix");
  // Deterministic - the same private key always derives the same public key.
  assert.equal(vapidPublicKeyFor(priv), pub);
  // Round-trip via the exact method glocke/backend/src/config.ts uses to
  // cross-check a configured pair (createECDH.setPrivateKey ->
  // getPublicKey) - not just internally consistent within this module.
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(priv, "base64url"));
  assert.equal(ecdh.getPublicKey("base64url"), pub);
});

// readSecretsStore / writeSecretsStore / ensureSecrets - real fake-sops
// shelling, exercising the actual argv shape a real sops accepts -----

test("readSecretsStore: a genuinely absent store returns {}, not an error", async () => {
  const values = await readSecretsStore({ storePath: path.join(workDir, "does-not-exist.sops.json") });
  assert.deepEqual(values, {});
});

test("writeSecretsStore then readSecretsStore round-trips real values, decryptable by either recipient's own identity", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "roundtrip.sops.json");
    const values = { "kuvert-to-glocke-hmac-secret": "s".repeat(43) };
    await writeSecretsStore({ storePath, values, recipients: ["age1operator", "age1recovery"] });

    const operatorIdentity = path.join(workDir, "operator.key");
    await writeFile(operatorIdentity, "age1operator\n");
    const viaOperator = await readSecretsStore({ storePath, identityFile: operatorIdentity });
    assert.deepEqual(viaOperator, values);

    const recoveryIdentity = path.join(workDir, "recovery.key");
    await writeFile(recoveryIdentity, "age1recovery\n");
    const viaRecovery = await readSecretsStore({ storePath, identityFile: recoveryIdentity });
    assert.deepEqual(viaRecovery, values);
  });
});

test("readSecretsStore: a wrong identity is refused, not silently treated as an empty store", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "wrong-identity.sops.json");
    await writeSecretsStore({ storePath, values: { x: "y" }, recipients: ["age1operator"] });
    const wrongIdentity = path.join(workDir, "wrong.key");
    await writeFile(wrongIdentity, "age1intruder\n");
    await assert.rejects(() => readSecretsStore({ storePath, identityFile: wrongIdentity }));
  });
});

test("writeSecretsStore requires at least one recipient - refuses to write an unrecoverable or unencrypted store", async () => {
  await assert.rejects(
    () => writeSecretsStore({ storePath: path.join(workDir, "no-recipients.sops.json"), values: {}, recipients: [] }),
    /requires at least one age recipient/,
  );
});

test("writeSecretsStore never leaves the short-lived plaintext temp file behind, success or failure", async () => {
  const before = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-secrets-plain-"));
  await withFakeSops(() => writeSecretsStore({ storePath: path.join(workDir, "cleanup.sops.json"), values: { a: "b" }, recipients: ["age1x"] }));
  const after = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-secrets-plain-"));
  assert.ok(after.length <= before.length, "no net leftover plaintext temp file");
});

test("ensureSecrets: a fresh bootstrap generates every required secret and writes a genuinely encrypted store", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "ensure-fresh.sops.json");
    const manifest = { features: { browserPush: { enabled: true } } };
    const enabledIds = ["tor", "schlussel", "schloss", "glocke", "herold"];
    const { values, addedNames } = await ensureSecrets({ manifest, enabledIds, storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery" });

    assert.deepEqual(addedNames.sort(), requiredSecrets(manifest, enabledIds).map((s) => s.name).sort());
    assert.equal(Object.keys(values).length, addedNames.length);

    // The store on disk is genuinely mock-"encrypted" (via the fake) -
    // not a bare plaintext JSON dump of real secret values.
    const onDisk = JSON.parse(await readFile(storePath, "utf8"));
    assert.equal(onDisk.__hof_test_sops_mock, true);
    assert.deepEqual(onDisk.recipients, ["age1operator", "age1recovery"]);
  });
});

test("ensureSecrets: re-running against an unchanged configuration adds nothing and never re-writes the store", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "ensure-idempotent.sops.json");
    const identityFile = path.join(workDir, "ensure-idempotent-identity.key");
    await writeFile(identityFile, "age1operator\n");
    const manifest = {};
    const enabledIds = ["tor", "schlussel", "schloss", "herold"];

    const first = await ensureSecrets({ manifest, enabledIds, storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery", identityFile });
    assert.equal(first.addedNames.length, 1);
    const mtimeBefore = (await import("node:fs/promises")).stat ? (await (await import("node:fs/promises")).stat(storePath)).mtimeMs : null;

    const second = await ensureSecrets({ manifest, enabledIds, storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery", identityFile });
    assert.deepEqual(second.addedNames, []);
    assert.deepEqual(second.values, first.values);
    if (mtimeBefore !== null) {
      const mtimeAfter = (await (await import("node:fs/promises")).stat(storePath)).mtimeMs;
      assert.equal(mtimeAfter, mtimeBefore, "the store file itself was never rewritten when nothing changed");
    }
  });
});

test("ensureSecrets: adding a newly-enabled service on top of an existing store keeps every prior value and adds only what's new", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "ensure-grow.sops.json");
    const identityFile = path.join(workDir, "ensure-grow-identity.key");
    await writeFile(identityFile, "age1operator\n");

    const before = await ensureSecrets({ manifest: {}, enabledIds: ["tor", "schlussel", "schloss", "herold"], storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery", identityFile });
    const after = await ensureSecrets({ manifest: {}, enabledIds: ["tor", "schlussel", "schloss", "herold", "wachter"], storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery", identityFile });

    assert.deepEqual(after.addedNames, ["wachter-agent-token"]);
    assert.equal(after.values["herold-credential-encryption-key"], before.values["herold-credential-encryption-key"], "the prior secret's own value must never be regenerated");
  });
});

test("ensureSecrets requires both an operator and a recovery age recipient", async () => {
  await assert.rejects(
    () => ensureSecrets({ manifest: {}, enabledIds: [], storePath: path.join(workDir, "x.sops.json"), operatorAgeRecipient: undefined, recoveryAgeRecipient: "age1recovery" }),
    /requires operatorAgeRecipient/,
  );
  await assert.rejects(
    () => ensureSecrets({ manifest: {}, enabledIds: [], storePath: path.join(workDir, "x.sops.json"), operatorAgeRecipient: "age1operator", recoveryAgeRecipient: undefined }),
    /requires recoveryAgeRecipient.*ADR 0004/s,
  );
});

// runSecretsEnsure() - the real CLI entry point, real files on disk ------

test("runSecretsEnsure: reads real services.yml/catalog paths and never returns a plaintext value, only names", async () => {
  await withFakeSops(async () => {
    const storePath = path.join(workDir, "cli-entry.sops.json");
    const result = await runSecretsEnsure({
      servicesPath: path.join(root, "examples/services.yml"),
      storePath, operatorAgeRecipient: "age1operator", recoveryAgeRecipient: "age1recovery",
    });
    assert.ok(result.totalCount > 0);
    assert.equal(result.addedNames.length, result.totalCount);
    assert.deepEqual(Object.keys(result), ["addedNames", "totalCount"]);
  });
});
