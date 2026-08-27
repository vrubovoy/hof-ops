// hofctl secrets - the workstation-side secret store for a bootstrap
// apply (see ADR 0004; item 8 is bootstrap-only, so this module is too -
// an applied installation's secrets rotation is a later delivery item).
// secrets.sops.yaml lives on the OPERATOR'S OWN workstation (matching
// ADR 0001: the control plane runs there, matching manifest.tls's own
// certificatePath/privateKeyPath convention for "supplied" TLS), SOPS-
// encrypted to age. Real values never touch a plan, a journal, an
// event, or render-topology.mjs's own output - only two things ever
// leave this module: the fixed set of REQUIRED secret NAMES (used to
// wire up Compose's own file-based secrets mechanism, deterministic,
// no live value needed) and, for the one case that genuinely needs it
// (the VAPID public key, which glocke's own app reads as a plain env
// var, not `_FILE`-aware - see render-topology.mjs), a value this
// module derived, never generated or stored raw itself beyond what
// SOPS already protects.

import { execFile } from "node:child_process";
import { createECDH, randomBytes, randomUUID } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const exec = promisify(execFile);

// The exact fixed secret vocabulary this platform ever needs, derived
// once here from the same manifest/enabledIds render-topology.mjs
// already computes from - so its own `_FILE` env wiring and this
// module's bootstrap generation can never drift apart. `name` doubles
// as both the SOPS store's own key and the target-side file name under
// /etc/hof/secrets/<name> (Compose's `secrets: {file: ...}` mechanism
// mounts it inside the container at /run/secrets/<name> - the exact
// `_FILE` convention every consuming app already implements, see
// glocke/herold/kuvert/tafel/zettel's own resolveSecret()).
//
// kind:
//   "token" - a fresh 32-byte random value (base64url) the first time a
//     bootstrap needs it, never regenerated after - an inter-service
//     HMAC secret or bearer token. Every consuming app already
//     validates >=32 raw bytes (see e.g. zettel/tafel/kuvert's own
//     notification outbox code), which base64url of 32 random bytes
//     (43 characters) always satisfies.
//   "vapid-private-key" - a fresh P-256 private scalar (base64url) -
//     see vapidPublicKeyFor() below for the one place its (non-secret)
//     public counterpart is derived from it.
export function requiredSecrets(manifest, enabledIds) {
  const enabled = new Set(enabledIds);
  const secrets = [];
  for (const producer of ["schlussel", "kuvert", "tafel", "zettel"]) {
    if (enabled.has("glocke") && enabled.has(producer)) {
      secrets.push({ name: `${producer}-to-glocke-hmac-secret`, envVar: `${producer.toUpperCase()}_TO_GLOCKE_HMAC_SECRET`, kind: "token" });
    }
  }
  if (enabled.has("glocke")) secrets.push({ name: "glocke-to-schlussel-hmac-secret", envVar: "GLOCKE_TO_SCHLUSSEL_HMAC_SECRET", kind: "token" });
  if (enabled.has("glocke") && manifest.features?.browserPush?.enabled) {
    secrets.push({ name: "glocke-vapid-private-key", envVar: "GLOCKE_VAPID_PRIVATE_KEY", kind: "vapid-private-key" });
  }
  if (enabled.has("herold")) secrets.push({ name: "herold-credential-encryption-key", envVar: "HEROLD_CREDENTIAL_ENCRYPTION_KEY", kind: "token" });
  if (enabled.has("wachter")) secrets.push({ name: "wachter-agent-token", envVar: "WACHTER_AGENT_TOKEN", kind: "token" });
  return secrets;
}

export function generateSecretValue(kind) {
  if (kind === "token") return randomBytes(32).toString("base64url");
  if (kind === "vapid-private-key") {
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    return ecdh.getPrivateKey("base64url");
  }
  throw new Error(`unknown secret kind: ${JSON.stringify(kind)}`);
}

// The VAPID public key is mathematically derived from the private one,
// never separately stored - glocke's own config.ts derives it exactly
// this way (createECDH('prime256v1').setPrivateKey(...).getPublicKey())
// to cross-check a configured pair actually matches, so this must stay
// byte-identical to that.
export function vapidPublicKeyFor(privateKeyBase64url) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(privateKeyBase64url, "base64url"));
  return ecdh.getPublicKey("base64url");
}

function defaultRun(command, args, { input, env } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 8 * 1024 * 1024, env: { ...process.env, ...env } }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

// Reads and decrypts the store at storePath - {} (not an error) when
// the file genuinely doesn't exist yet (a fresh installation's first
// bootstrap has no secrets.sops.yaml at all). Any other failure
// (corrupt file, wrong/missing age identity) is never silently treated
// as "no secrets yet".
export async function readSecretsStore({ storePath, identityFile, run = defaultRun }) {
  let exists = true;
  try {
    await readFile(storePath);
  } catch (error) {
    if (error.code === "ENOENT") exists = false;
    else throw error;
  }
  if (!exists) return {};

  const { stdout } = await run("sops", ["--decrypt", "--input-type", "json", "--output-type", "json", storePath], {
    env: identityFile ? { SOPS_AGE_KEY_FILE: identityFile } : {},
  });
  return JSON.parse(stdout);
}

// Encrypts `values` to every recipient (the operator's own age public
// key, and the external recovery recipient - see ADR 0004/plan-v2's own
// `recovery.ageRecipient`) and writes the result to storePath. Values
// are written to a short-lived plaintext temp file (0600, cleaned up in
// a finally, same pattern as validate-deployment.mjs's own pinned-blob
// temp file) - never held on disk unencrypted any longer than the one
// `sops --encrypt` call needs.
export async function writeSecretsStore({ storePath, values, recipients, run = defaultRun }) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("writeSecretsStore requires at least one age recipient - refusing to write an unrecoverable or unencrypted store");
  }
  const plainPath = path.join(tmpdir(), `hof-secrets-plain-${randomUUID()}.json`);
  await writeFile(plainPath, JSON.stringify(values), { mode: 0o600 });
  try {
    const { stdout } = await run("sops", ["--encrypt", "--age", recipients.join(","), "--input-type", "json", "--output-type", "json", plainPath], {});
    await writeFile(storePath, stdout, { mode: 0o600 });
  } finally {
    await rm(plainPath, { force: true });
  }
}

// The bootstrap orchestration: read whatever's already in the store,
// generate a fresh value for every currently-required secret that's
// missing, and - only if anything was actually added - re-encrypt and
// write the store back out to both recipients. Returns
// {values, addedNames} - values is the full plaintext map (used only
// in-memory, by a future apply's own secret-delivery step and by
// render-topology.mjs's own vapidPublicKey derivation - never written
// anywhere unencrypted by this function itself beyond the short-lived
// temp file writeSecretsStore already cleans up).
export async function ensureSecrets({ manifest, enabledIds, storePath, operatorAgeRecipient, recoveryAgeRecipient, identityFile, run = defaultRun }) {
  if (!operatorAgeRecipient) throw new Error("ensureSecrets requires operatorAgeRecipient - the primary age public key secrets.sops.yaml is encrypted to");
  if (!recoveryAgeRecipient) throw new Error("ensureSecrets requires recoveryAgeRecipient - see ADR 0004, a bootstrap always needs an external recovery recipient");

  const required = requiredSecrets(manifest, enabledIds);
  const values = await readSecretsStore({ storePath, identityFile, run });
  const addedNames = [];
  for (const { name, kind } of required) {
    if (name in values) continue;
    values[name] = generateSecretValue(kind);
    addedNames.push(name);
  }
  if (addedNames.length > 0) {
    await writeSecretsStore({ storePath, values, recipients: [operatorAgeRecipient, recoveryAgeRecipient], run });
  }
  return { values, addedNames };
}

// The `hofctl secrets ensure` CLI's own entry point - reads
// services.yml/the catalog from disk (paths, not already-parsed
// objects, matching runPreflight/runPlan's own CLI-facing shape) and
// delegates to ensureSecrets(). Returns only {addedNames, totalCount} -
// never the plaintext values themselves, so the CLI layer can never
// accidentally print one.
export async function runSecretsEnsure({ servicesPath, catalogPath, storePath, operatorAgeRecipient, recoveryAgeRecipient, identityFile, run }) {
  const [manifest, catalog] = await Promise.all([
    readFile(servicesPath, "utf8").then(YAML.parse),
    readFile(catalogPath ?? path.join(root, "catalog/services-v1.yaml"), "utf8").then(YAML.parse),
  ]);
  const enabledIds = catalog.services.filter((service) => service.mandatory || manifest.services?.[service.id]?.enabled === true).map((service) => service.id);

  const { addedNames } = await ensureSecrets({ manifest, enabledIds, storePath, operatorAgeRecipient, recoveryAgeRecipient, identityFile, run });
  return { addedNames, totalCount: requiredSecrets(manifest, enabledIds).length };
}
