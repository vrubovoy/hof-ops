// PR 3 (item 10, ADR 0006): the typed, decrypted backup-destination
// credentials store - restic/S3 secrets a backup/restore run actually
// needs to reach its own configured destinations, keyed by the exact
// same secretRef name backup-policy-v1/backup-plan-v1's own destinations
// array already carries. Deliberately separate from scripts/secrets.mjs
// (application secrets, a completely different vocabulary/lifecycle -
// see that module's own top comment) rather than folding this into it:
// conflating "what an app needs at runtime" with "what a backup run
// needs to reach a destination" would let an unrelated app secret and a
// destination credential collide on one shared name, or let a change to
// one module's own required-secrets shape silently perturb the other's.
// Same SOPS transport discipline as secrets.mjs throughout: values only
// ever exist in memory or in a short-lived, 0600, finally-cleaned-up
// plaintext temp file for the one `sops` call that genuinely needs a
// real file on disk - never written anywhere else, never logged, never
// part of any argv.

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { hasDuplicates } from "./backup-ids.mjs";

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

// A destination's own required credential FIELDS, by type - the exact
// vocabulary a backup/restore runner needs to actually drive restic
// against that destination kind. "local" needs only the restic
// repository password (still secret - even a local repository is
// encrypted at rest by restic itself); "s3" additionally needs the
// access key pair, plus an optional session token for a temporary/
// assumed-role credential (never required - most S3-compatible
// destinations use a long-lived key pair with no session token at all).
const REQUIRED_FIELDS_BY_TYPE = {
  local: ["resticPassword"],
  s3: ["resticPassword", "accessKeyId", "secretAccessKey"],
};
const OPTIONAL_FIELDS_BY_TYPE = {
  local: [],
  s3: ["sessionToken"],
};

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

// A destination's own endpoint must never carry an embedded credential -
// exactly the same rule backup-policy-v1.schema.json's own destination
// $def already enforces at the schema level (a pattern excluding "@",
// "?", "#"). Checked again here, independently: this module's own
// validator is meant to stand on its own for a caller that built a
// destinations array by hand (a test fixture, a future CLI flag) rather
// than through a schema-validated policy document - defense in depth,
// never a substitute for the schema check, never assuming it already
// ran.
function endpointCarriesEmbeddedCredential(endpoint) {
  if (typeof endpoint !== "string") return false;
  try {
    const parsed = new URL(endpoint);
    return parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "";
  } catch {
    // An unparseable endpoint is a distinct problem (not a credential
    // leak) - the caller's own schema validation is responsible for
    // rejecting it as malformed; this function only ever flags a
    // genuinely embedded credential/query/fragment on an otherwise
    // parseable URL.
    return false;
  }
}

// destinations: backup-policy-v1 (or backup-plan-v1)'s own destinations
// array - never trusted as already-validated; this function re-checks
// the one property (no embedded endpoint credential) that matters most
// for a credentials-handling module to never assume away. credentials:
// the decrypted store, keyed by secretRef - { [secretRef]: { type,
// resticPassword, accessKeyId?, secretAccessKey?, sessionToken? } }.
// Returns an array of violation strings; empty means the credentials
// store is exactly, genuinely sufficient for these destinations - no
// more, no less.
// A single credential entry's own internal shape - real object, a known
// type, every field that type requires present and a non-empty string,
// every optional field (when present) also non-empty, and closed
// (additionalProperties: false style - a field the entry's own type
// never uses must never silently pass through, since a typo'd field
// name would otherwise leave the REAL required field missing while
// looking superficially populated). Deliberately independent of any
// `destinations` array - this is the one piece of this module's own
// validation that recovery-kit.mjs's own validateClosedRecoveryPayload()
// also needs (a decrypted kit's own destinationCredentials carries no
// destinations array of its own to cross-reference at all), so it is
// exported and reused there rather than re-implemented a second time.
// Returns an array of violation strings, each already prefixed with the
// given label (typically `credentials["ref"]` or an equivalent payload
// path) so a caller's own message reads naturally either way.
export function validateCredentialEntry(label, entry) {
  const violations = [];
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    return [`${label} is not an object`];
  }
  if (entry.type !== "local" && entry.type !== "s3") {
    return [`${label}.type ("${entry.type}") is not a known destination type`];
  }
  const required = REQUIRED_FIELDS_BY_TYPE[entry.type] ?? [];
  const optional = OPTIONAL_FIELDS_BY_TYPE[entry.type] ?? [];
  for (const field of required) {
    if (!isNonEmptyString(entry[field])) {
      violations.push(`${label}.${field} is required and must be a non-empty string for a "${entry.type}" destination`);
    }
  }
  const allowed = new Set(["type", ...required, ...optional]);
  for (const field of Object.keys(entry)) {
    if (!allowed.has(field)) {
      violations.push(`${label} carries an unexpected field "${field}" for a "${entry.type}" destination`);
    }
  }
  for (const field of optional) {
    if (field in entry && !isNonEmptyString(entry[field])) {
      violations.push(`${label}.${field}, when present, must be a non-empty string`);
    }
  }
  return violations;
}

export function validateBackupCredentials(destinations, credentials) {
  const violations = [];

  if (hasDuplicates(destinations, (d) => d.secretRef)) {
    violations.push("destinations has a duplicate secretRef - two destinations must never share one credential entry");
  }

  for (const destination of destinations) {
    if (destination.type === "s3" && endpointCarriesEmbeddedCredential(destination.endpoint)) {
      violations.push(`destination "${destination.name}" has an endpoint carrying an embedded credential, query, or fragment - the secretRef is the only way a credential may reach this destination`);
    }
  }

  const destinationRefs = destinations.map((d) => d.secretRef);
  const credentialRefs = Object.keys(credentials);

  const missing = destinationRefs.filter((ref) => !(ref in credentials));
  if (missing.length > 0) {
    violations.push(`missing credentials for secretRef(s): ${[...new Set(missing)].join(", ")}`);
  }
  const foreign = credentialRefs.filter((ref) => !destinationRefs.includes(ref));
  if (foreign.length > 0) {
    violations.push(`credentials store carries secretRef(s) no destination actually uses: ${foreign.join(", ")}`);
  }

  const destinationByRef = new Map(destinations.map((d) => [d.secretRef, d]));
  for (const ref of credentialRefs) {
    const destination = destinationByRef.get(ref);
    if (!destination) continue; // already reported above as foreign
    const entry = credentials[ref];
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.type !== undefined && entry.type !== destination.type) {
      violations.push(`credentials["${ref}"].type ("${entry.type}") does not match destination "${destination.name}"'s own type ("${destination.type}")`);
      continue;
    }
    violations.push(...validateCredentialEntry(`credentials["${ref}"]`, entry));
  }

  return violations;
}

// Reads and decrypts the store at storePath - {} (not an error) only
// when the file genuinely doesn't exist yet, exactly like
// secrets.mjs's own readSecretsStore(). Any other failure (corrupt
// file, wrong/missing age identity, sops itself failing) fails closed -
// never silently treated as "no credentials configured".
export async function readBackupCredentialsStore({ storePath, identityFile, run = defaultRun }) {
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

// Encrypts `credentials` to every given recipient and writes the result
// to storePath - same short-lived-plaintext-temp-file discipline as
// secrets.mjs's own writeSecretsStore(): a unique, 0600 temp path,
// removed in a finally regardless of how the sops call itself resolves.
export async function writeBackupCredentialsStore({ storePath, credentials, recipients, run = defaultRun }) {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("writeBackupCredentialsStore requires at least one age recipient - refusing to write an unrecoverable or unencrypted store");
  }
  const plainPath = path.join(tmpdir(), `hof-backup-credentials-plain-${randomUUID()}.json`);
  await writeFile(plainPath, JSON.stringify(credentials), { mode: 0o600 });
  try {
    const { stdout } = await run("sops", ["--encrypt", "--age", recipients.join(","), "--input-type", "json", "--output-type", "json", plainPath], {});
    await writeFile(storePath, stdout, { mode: 0o600 });
  } finally {
    await rm(plainPath, { force: true });
  }
}
