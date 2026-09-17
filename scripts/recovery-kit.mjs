// PR 3 (item 10, ADR 0006): the single typed recovery boundary. Every
// application secret, TLS private key, and backup-destination credential
// this platform ever puts into a recovery kit passes through exactly the
// two functions this module exports - createRecoveryKit()/
// openRecoveryKit() - and nowhere else. The private age identity that
// can ever decrypt a kit is never generated, stored, or transmitted by
// any Hof artifact (ADR 0006's own Decision) - it lives with the
// operator alone, supplied here only as a file path (openRecoveryKit's
// own identityFile), exactly like secrets.mjs's own identityFile
// convention; this module never reads or holds its contents beyond the
// one `age -d` child process invocation that genuinely needs it.
//
// The plaintext recovery payload - the "closed" shape
// validateClosedRecoveryPayload() below enforces - exists only ever in
// memory, for the lifetime of one createRecoveryKit()/openRecoveryKit()
// call: it is never written to a schema file of its own (this repo's
// schemas/ directory is reserved for documents that cross a process or
// file boundary independently; the recovery payload never does - it is
// born, encrypted, and discarded inside one function call, or decrypted
// and handed to its one caller inside another), never written to disk
// (age's own stdin/stdout streaming means this module never needs a
// plaintext temp file at all, unlike secrets.mjs's own SOPS-based
// writeSecretsStore(), which genuinely cannot avoid one), and never
// logged, thrown into an error message, or otherwise allowed to escape
// through any diagnostic.
//
// PR 3 delivers primitives, not an executor: nothing here decides WHEN
// to rotate a kit, WHICH generation's secrets to include, or how a
// backup/restore plan's own operations invoke this module - that is
// PR 4/5's own runner work (ADR 0006's own Decision). assembleRecoveryPayload()
// below is the one exception worth calling out: it exists here (not in a
// later PR's own runner module) because it is itself pure assembly of
// already-existing, already-validated inputs (readSecretsStore(),
// readSuppliedTlsMaterial(), a caller-supplied trusted state/lock/
// credentials bundle) into the closed payload shape - no target access,
// no policy/plan interpretation, nothing a runner would need to decide.

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

import { validateBackupCredentials, validateCredentialEntry } from "./backup-credentials.mjs";
import { verifyRecoveryKit } from "./backup-flow.mjs";
import { sha256 } from "./digest.mjs";
import { readSecretsStore, requiredSecrets } from "./secrets.mjs";
import { readSuppliedTlsMaterial } from "./supplied-tls.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const RECOVERY_KIT_SCHEMA = JSON.parse(await readFile(path.join(root, "schemas/recovery-kit-v1.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validateRecoveryKitSchema = ajv.compile(RECOVERY_KIT_SCHEMA);

function schemaErrors(validate) {
  return (validate.errors ?? []).map((error) => `${error.instancePath || "/"}: ${error.message}`);
}

// Buffer-in, Buffer-out - unlike secrets.mjs's own defaultRun (text
// stdin/stdout, matching sops's own JSON-in-JSON-out CLI contract), age
// ciphertext is genuinely binary (it begins with a literal magic header
// but is never valid UTF-8 as a whole) - decoding it through a text
// encoding at any point would corrupt it. `encoding: "buffer"` is what
// makes execFile's own callback hand back real Buffers for stdout/stderr
// instead of decoding them.
function defaultRun(command, args, { input } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 64 * 1024 * 1024, encoding: "buffer" }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

// A real Buffer/Uint8Array with at least one byte - what
// assembleRecoveryPayload() requires for manifestBytes/releaseLockBytes/
// backupToolLockBytes, specifically to rule out a caller passing a
// pre-parsed object (or a plain string, which sha256() would silently
// digest differently than the real file bytes would) where only the
// EXACT raw bytes a trusted digest was computed from can ever bind
// correctly.
function isByteSource(value) {
  return (Buffer.isBuffer(value) || value instanceof Uint8Array) && value.length > 0;
}

const SIGNED_BUNDLE_STRING_FIELDS = ["signature", "certificate", "signingIdentity", "oidcIssuer"];

function validateSignedBundleShape(label, bundle, violations) {
  if (!isPlainObject(bundle)) {
    violations.push(`recovery payload ${label} bundle must be an object`);
    return;
  }
  if (!isPlainObject(bundle.document)) violations.push(`recovery payload ${label}.document must be an object`);
  for (const field of SIGNED_BUNDLE_STRING_FIELDS) {
    if (!isNonEmptyString(bundle[field])) violations.push(`recovery payload ${label}.${field} must be a non-empty string`);
  }
}

const CLOSED_PAYLOAD_TOP_LEVEL_FIELDS = new Set([
  "installationId", "generation", "sanitizedManifest",
  "releaseLock", "backupToolLock", "applicationSecrets", "suppliedTls", "destinationCredentials",
]);

// The closed recovery payload's own strict shape - every field this
// module will ever put into, or accept out of, a recovery kit's own
// ciphertext, and nothing else. Hand-written (not AJV-driven - see this
// module's own top comment on why there is no schema file for this
// shape) but held to the exact same "closed, typed, nothing silently
// extra" discipline every real schema in this repo already enforces:
// additionalProperties is effectively false at every level, and every
// leaf is checked for its own real type, never merely "truthy". Used
// both before ever encrypting (createRecoveryKit, catching a caller
// that built a malformed payload) and after ever decrypting
// (openRecoveryKit, never trusting that ciphertext - once genuinely
// decrypted - is automatically well-shaped plaintext; verifyRecoveryKit()
// only ever proves the ciphertext is REAL age output, never that its own
// interior is this module's own expected shape). Returns an array of
// violation strings; empty means the payload is genuinely well-formed.
export function validateClosedRecoveryPayload(payload) {
  const violations = [];
  if (!isPlainObject(payload)) return ["recovery payload must be a plain object"];

  for (const key of Object.keys(payload)) {
    if (!CLOSED_PAYLOAD_TOP_LEVEL_FIELDS.has(key)) violations.push(`recovery payload carries an unexpected top-level field "${key}"`);
  }

  if (!isNonEmptyString(payload.installationId)) violations.push("recovery payload installationId must be a non-empty string");
  if (!Number.isInteger(payload.generation) || payload.generation < 1) {
    violations.push("recovery payload generation must be a positive integer");
  }
  if (!isPlainObject(payload.sanitizedManifest)) violations.push("recovery payload sanitizedManifest must be an object");

  validateSignedBundleShape("releaseLock", payload.releaseLock, violations);
  validateSignedBundleShape("backupToolLock", payload.backupToolLock, violations);

  if (!isPlainObject(payload.applicationSecrets)) {
    violations.push("recovery payload applicationSecrets must be an object");
  } else {
    for (const [name, value] of Object.entries(payload.applicationSecrets)) {
      if (!isNonEmptyString(value)) violations.push(`recovery payload applicationSecrets["${name}"] must be a non-empty string`);
    }
  }

  if (payload.suppliedTls !== undefined) {
    if (!isPlainObject(payload.suppliedTls)) {
      violations.push("recovery payload suppliedTls, when present, must be an object");
    } else {
      for (const key of Object.keys(payload.suppliedTls)) {
        if (key !== "certificatePem" && key !== "privateKeyPem") violations.push(`recovery payload suppliedTls carries an unexpected field "${key}"`);
      }
      for (const field of ["certificatePem", "privateKeyPem"]) {
        if (!isNonEmptyString(payload.suppliedTls[field])) violations.push(`recovery payload suppliedTls.${field} must be a non-empty string`);
      }
    }
  }

  // PR 3 review, high finding: this used to check only entry.type's own
  // enum, never the per-type required fields (resticPassword; s3 also
  // needs accessKeyId/secretAccessKey), never closed-field semantics (an
  // unexpected stray field silently passing through) - a decrypted kit
  // could pass this check while being genuinely useless for restore
  // (e.g. an s3 credential missing its own accessKeyId). Reuses
  // backup-credentials.mjs's own validateCredentialEntry() - the exact
  // same per-entry shape check validateBackupCredentials() itself runs -
  // rather than a second, weaker, parallel implementation.
  if (!isPlainObject(payload.destinationCredentials)) {
    violations.push("recovery payload destinationCredentials must be an object");
  } else {
    for (const [ref, entry] of Object.entries(payload.destinationCredentials)) {
      violations.push(...validateCredentialEntry(`recovery payload destinationCredentials["${ref}"]`, entry));
    }
  }

  // A recovery kit exists to recover secrets - one that genuinely
  // carries none at all (every category below empty) is never
  // legitimate, and recovery-kit-v1.schema.json's own contentInventory
  // (minItems: 1) would refuse it anyway; catching it here, before ever
  // touching age, gives a far clearer diagnostic than a downstream
  // schema error naming a field the caller never directly set.
  const hasApplicationSecrets = isPlainObject(payload.applicationSecrets) && Object.keys(payload.applicationSecrets).length > 0;
  const hasTlsPrivateKeys = payload.suppliedTls !== undefined;
  const hasDestinationCredentials = isPlainObject(payload.destinationCredentials) && Object.keys(payload.destinationCredentials).length > 0;
  if (!hasApplicationSecrets && !hasTlsPrivateKeys && !hasDestinationCredentials) {
    violations.push("recovery payload carries no application secrets, TLS private keys, or destination credentials at all - a recovery kit with nothing to recover is never legitimate");
  }

  return violations;
}

function computeContentInventory(payload) {
  const inventory = [];
  if (Object.keys(payload.applicationSecrets).length > 0) inventory.push("application-secrets");
  if (payload.suppliedTls !== undefined) inventory.push("tls-private-keys");
  if (Object.keys(payload.destinationCredentials).length > 0) inventory.push("backup-destination-credentials");
  return inventory;
}

async function ageEncrypt(plaintext, ageRecipient, run) {
  const { stdout } = await run("age", ["-r", ageRecipient], { input: plaintext });
  return stdout;
}

async function ageDecrypt(ciphertext, identityFile, run) {
  if (!isNonEmptyString(identityFile)) {
    throw new Error("openRecoveryKit requires identityFile - the external private age identity, never generated or stored by Hof, must be supplied by the operator at open time");
  }
  try {
    const { stdout } = await run("age", ["-d", "-i", identityFile], { input: ciphertext });
    return stdout;
  } catch (error) {
    const stderrText = error?.stderr ? Buffer.from(error.stderr).toString("utf8").trim() : (error instanceof Error ? error.message : String(error));
    throw new Error(`could not decrypt recovery kit: ${stderrText} - wrong identity, or a genuinely corrupt/foreign ciphertext`);
  }
}

// Encrypts `payload` (already validated - see validateClosedRecoveryPayload
// above, run here unconditionally regardless of what a caller may already
// have checked) to `ageRecipient` alone - never any second recipient, and
// never the operator's own age key the way secrets.mjs's own
// writeSecretsStore() encrypts application secrets to both the operator
// and the recovery recipient (ADR 0006's own external-only identity
// decision: a recovery kit is recoverable ONLY by whoever holds the
// matching external private identity, deliberately not also by the
// operator's own day-to-day key). installationId/createdForGeneration are
// taken directly from payload.installationId/payload.generation - never
// separate parameters a caller could pass inconsistently with the
// payload's own claims (assembleRecoveryPayload() below is what actually
// cross-checks those against trusted state, before a payload ever reaches
// this function). Returns a schema-valid, verifyRecoveryKit()-clean
// recovery-kit-v1 document.
export async function createRecoveryKit({ payload, ageRecipient, createdAt, run = defaultRun }) {
  const payloadViolations = validateClosedRecoveryPayload(payload);
  if (payloadViolations.length > 0) {
    throw new Error(`refusing to create a recovery kit from a malformed payload: ${payloadViolations.join("; ")}`);
  }
  if (!/^age1[a-z0-9]{58}$/.test(ageRecipient ?? "")) {
    throw new Error(`createRecoveryKit requires a valid age recipient (ageRecipient), got: ${JSON.stringify(ageRecipient)}`);
  }

  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = await ageEncrypt(plaintext, ageRecipient, run);

  const kit = {
    apiVersion: "hof.dev/recovery-kit/v1",
    installationId: payload.installationId,
    createdAt: createdAt ?? new Date().toISOString(),
    createdForGeneration: payload.generation,
    ageRecipient,
    ageRecipientFingerprint: sha256(Buffer.from(ageRecipient, "utf8")),
    contentInventory: computeContentInventory(payload),
    ciphertextDigest: sha256(ciphertext),
    ciphertext: ciphertext.toString("base64"),
  };

  if (!validateRecoveryKitSchema(kit)) {
    throw new Error(`internal error: the recovery kit this function just built is not schema-valid: ${schemaErrors(validateRecoveryKitSchema).join("; ")}`);
  }
  const kitViolations = verifyRecoveryKit(kit);
  if (kitViolations.length > 0) {
    throw new Error(`internal error: the recovery kit this function just built failed its own verifyRecoveryKit(): ${kitViolations.join("; ")}`);
  }

  return kit;
}

// The inverse of createRecoveryKit() above - validates the kit document
// itself FIRST (schema, then verifyRecoveryKit()'s own real-ciphertext
// check), only ever attempting to decrypt once both pass, then validates
// the decrypted plaintext against the exact same closed-payload shape
// createRecoveryKit() itself enforces before ever returning it to a
// caller. A kit that is schema-valid and genuinely age-encrypted but
// decrypts to something that isn't this module's own expected shape
// (a foreign, unrelated age payload happening to use the same recipient,
// say) is refused here, not handed back as if it were a real recovery
// payload.
export async function openRecoveryKit({ kit, identityFile, run = defaultRun }) {
  if (!validateRecoveryKitSchema(kit)) {
    throw new Error(`refusing to open a recovery kit that is not schema-valid: ${schemaErrors(validateRecoveryKitSchema).join("; ")}`);
  }
  const kitViolations = verifyRecoveryKit(kit);
  if (kitViolations.length > 0) {
    throw new Error(`refusing to open a recovery kit that failed verifyRecoveryKit(): ${kitViolations.join("; ")}`);
  }

  const ciphertext = Buffer.from(kit.ciphertext, "base64");
  const plaintext = await ageDecrypt(ciphertext, identityFile, run);

  let payload;
  try {
    payload = JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("the decrypted recovery kit payload is not valid JSON - a genuinely foreign or corrupted payload, even though it decrypted under the supplied identity");
  }
  const payloadViolations = validateClosedRecoveryPayload(payload);
  if (payloadViolations.length > 0) {
    throw new Error(`the decrypted recovery kit payload is not a well-formed closed recovery payload: ${payloadViolations.join("; ")}`);
  }

  return payload;
}

// A copy of services.yml stripped of everything that is either
// meaningless off the workstation it came from (tls.certificatePath/
// privateKeyPath - filesystem paths, not portable, and the real
// certificate/key material already travels separately in
// payload.suppliedTls) or a statement about THIS SPECIFIC transport
// (target.host/user/port - a restore target is not guaranteed to be, and
// in the disaster-recovery case that matters most is actively NOT, the
// same host/user/port the original backup ran against). Every other
// field - domains, enabled services, features, the backup: policy shape
// itself - genuinely describes the historical topology a restore needs
// to reconstruct, and secretRef names (never values) are exactly the
// kind of reference-only metadata this module's own recovery payload is
// safe to carry unencrypted-adjacent (it IS still inside the encrypted
// ciphertext, alongside everything else - "sanitized" here means safe to
// have existed in the staging tree/snapshot at all, per ADR 0006's own
// backup-manifest-v1 sanitizedManifestDigest, not safe as plaintext on
// its own).
export function sanitizeManifest(manifest) {
  const { target, tls, ...rest } = manifest;
  const sanitizedTls = tls?.mode === "supplied" ? { mode: "supplied" } : tls;
  return { ...rest, tls: sanitizedTls };
}

// Assembles the closed recovery payload from already-existing, already-
// validated inputs - the one place in this module that actually reads
// application secrets and supplied TLS material, so the two closed-
// payload-building code paths (a fresh kit's own assembly, and this
// function's own tests) never risk drifting apart on what "the payload"
// actually contains.
//
// state: the trusted state-v1 document (current.json) - installationId/
// generation are taken from HERE, never from manifest/catalog/caller-
// supplied loose values, and manifest/releaseLock/backupToolLock are all
// cross-checked to genuinely describe this SAME installation/generation
// before ever being trusted as "the" recovery payload for it. A caller
// that wants a kit for some other installation/generation must supply a
// different state, never override installationId/generation directly -
// there is deliberately no way to pass those as free-standing, unbound
// metadata.
//
// manifestBytes/catalog: the EXACT raw bytes services.yml was actually
// read as (never a pre-parsed object - see this function's own review-
// finding comment below on why) and the release-owned catalog needed to
// resolve public hostnames for TLS. manifest.tls.mode must be "supplied"
// (the only mode with any real TLS source material on the workstation at
// all; see this module's own top comment and ADR 0006's own fixed
// decision) or this throws before ever touching age, encryption, or any
// other input. enabledIds: exactly what apply.mjs's own
// ensureSecretsAvailable() already computes this the same way for - the
// services actually enabled by this manifest, used to filter
// applicationSecrets down to only what THIS deployment currently needs
// (never a whole, possibly-stale secrets store carrying leftovers from a
// service disabled generations ago).
//
// releaseLockBytes/releaseLockSignature/releaseLockCertificate/
// releaseLockSigningIdentity/releaseLockOidcIssuer,
// backupToolLockBytes/backupToolLockSignature/backupToolLockCertificate/
// expectedBackupToolLockDigest: the exact historical, already-signature-
// verified artifacts this generation was actually deployed/backed up
// with. This function still does not itself re-verify their Cosign
// signatures (that stays validate-deployment.mjs's own established job,
// already run once by whichever caller obtained these bytes in the first
// place - re-running it here would just be a second, redundant trust
// decision over the same bytes, not a stronger one) - but it DOES now
// cryptographically bind them to the declared state/generation before
// ever trusting them as "the" provenance for this kit:
//
// PR 3 review, high finding: this function used to accept manifest/
// releaseLock/backupToolLock as independent, already-parsed objects with
// NO binding at all to state's own installationId/generation beyond the
// caller's own say-so - a kit could carry a sanitizedManifest, release
// lock, and tool lock that were internally well-shaped but had nothing
// to do with the generation actually being recovered (swapped, stale, or
// simply mismatched inputs from a confused caller), and nothing here
// would ever notice. Fixed: manifestBytes/releaseLockBytes are now
// required as raw bytes, never a pre-parsed object, specifically so this
// function can independently recompute sha256(bytes) and cross-check it
// against state.manifestDigest/state.releaseLockDigest - state-v1's own
// established digest fields, the same formula apply.mjs's own real
// commit path already uses (sha256 of the raw file bytes, never a
// canonicalized/re-serialized form). A mismatch means these bytes were
// NOT what this installation's own trusted state record says was
// actually applied at this generation, and the whole assembly refuses
// before ever reaching age. backup-tool-lock has no such state-v1 field
// of its own (ADR 0006's own decision: it is deliberately independent of
// any platform generation) - expectedBackupToolLockDigest is instead a
// required parameter the CALLER supplies from whatever their own trusted
// source for "the currently-pinned backup tool" is, bound the same way.
//
// destinations/destinationCredentials: backup-policy-v1's own
// destinations array and the already-decrypted typed credentials store -
// validated via backup-credentials.mjs's own validateBackupCredentials()
// (exact secretRef sufficiency, per-type required fields, no foreign/
// stale entries) and filtered down to exactly those refs before ever
// being embedded - see this function's own review-finding comment further
// below.
export async function assembleRecoveryPayload({
  state,
  manifestBytes,
  catalog,
  enabledIds,
  secretsStorePath,
  secretsIdentityFile,
  releaseLockBytes, releaseLockSignature, releaseLockCertificate, releaseLockSigningIdentity, releaseLockOidcIssuer,
  backupToolLockBytes, backupToolLockSignature, backupToolLockCertificate, expectedBackupToolLockDigest,
  destinations,
  destinationCredentials,
  // Injectable ONLY for readSecretsStore()'s own sake (secrets.mjs's own
  // sops-shelling run, env-aware for SOPS_AGE_KEY_FILE) - deliberately
  // NOT this module's own age-flavored defaultRun above (Buffer I/O, no
  // env support at all): the two run() conventions serve genuinely
  // different child processes with different I/O contracts, and forcing
  // one shared default here would silently break readSecretsStore()'s
  // own SOPS_AGE_KEY_FILE wiring the moment a caller relied on this
  // function's own default. Left undefined unless a caller/test
  // explicitly wants to observe or fake the sops invocation - readSecretsStore()'s
  // own default parameter (secrets.mjs's own defaultRun) already applies
  // correctly when this stays undefined, exactly as if it were never
  // passed at all.
  secretsRun,
}) {
  if (!isPlainObject(state) || !isNonEmptyString(state.installationId) || !Number.isInteger(state.generation) || state.generation < 1) {
    throw new Error("assembleRecoveryPayload requires a trusted state document with a real installationId and generation - installationId/generation are never accepted as free-standing metadata");
  }
  if (!isByteSource(manifestBytes) || !isByteSource(releaseLockBytes) || !isByteSource(backupToolLockBytes)) {
    throw new Error("assembleRecoveryPayload requires manifestBytes/releaseLockBytes/backupToolLockBytes as the exact raw bytes each was actually read as - never a pre-parsed object, which could never be bound to state's own trusted digests");
  }
  if (!isNonEmptyString(state.manifestDigest)) {
    throw new Error("assembleRecoveryPayload requires state.manifestDigest - a trusted state record with no manifestDigest can never bind this kit's own sanitizedManifest to a real, applied generation");
  }
  const actualManifestDigest = sha256(manifestBytes);
  if (actualManifestDigest !== state.manifestDigest) {
    throw new Error(`assembleRecoveryPayload: manifestBytes does not match state.manifestDigest (state says ${state.manifestDigest}, manifestBytes actually hashes to ${actualManifestDigest}) - refusing to bind a recovery kit's own sanitizedManifest to artifacts that do not actually match the declared generation`);
  }
  if (!isNonEmptyString(state.releaseLockDigest)) {
    throw new Error("assembleRecoveryPayload requires state.releaseLockDigest - a trusted state record with no releaseLockDigest can never bind this kit's own release lock to a real, applied generation");
  }
  const actualReleaseLockDigest = sha256(releaseLockBytes);
  if (actualReleaseLockDigest !== state.releaseLockDigest) {
    throw new Error(`assembleRecoveryPayload: releaseLockBytes does not match state.releaseLockDigest (state says ${state.releaseLockDigest}, releaseLockBytes actually hashes to ${actualReleaseLockDigest}) - refusing to bind a recovery kit's own release lock to artifacts that do not actually match the declared generation`);
  }
  if (!isNonEmptyString(expectedBackupToolLockDigest)) {
    throw new Error("assembleRecoveryPayload requires expectedBackupToolLockDigest - backup-tool-lock has no state-v1 field of its own to bind against (ADR 0006's own decision: it is independent of any platform generation), so the caller's own trusted digest is this binding's only source");
  }
  const actualBackupToolLockDigest = sha256(backupToolLockBytes);
  if (actualBackupToolLockDigest !== expectedBackupToolLockDigest) {
    throw new Error(`assembleRecoveryPayload: backupToolLockBytes does not match expectedBackupToolLockDigest (expected ${expectedBackupToolLockDigest}, backupToolLockBytes actually hashes to ${actualBackupToolLockDigest}) - refusing to bind a recovery kit to a tool lock that does not actually match the caller's own trusted digest`);
  }

  const manifest = YAML.parse(manifestBytes.toString("utf8"));
  const releaseLock = JSON.parse(releaseLockBytes.toString("utf8"));
  const backupToolLock = JSON.parse(backupToolLockBytes.toString("utf8"));

  if (manifest?.tls?.mode !== "supplied") {
    throw new Error(`assembleRecoveryPayload requires manifest.tls.mode === "supplied" (found ${JSON.stringify(manifest?.tls?.mode)}) - TLS without fully-defined source material on this workstation blocks recovery kit creation before any encryption ever happens; only supplied TLS has real private key material here to recover at all`);
  }

  const suppliedTlsMaterial = await readSuppliedTlsMaterial(manifest, catalog);
  // readSuppliedTlsMaterial() itself returns undefined for every mode
  // except "supplied" (already refused above) - a defensive, should-
  // never-happen check, not a reachable branch.
  if (!suppliedTlsMaterial) {
    throw new Error("assembleRecoveryPayload: readSuppliedTlsMaterial returned no material despite manifest.tls.mode being \"supplied\" - internal inconsistency, refusing to proceed");
  }

  const requiredSecretsList = requiredSecrets(manifest, enabledIds);
  const decryptedStore = await readSecretsStore({ storePath: secretsStorePath, identityFile: secretsIdentityFile, run: secretsRun });
  const missingSecrets = requiredSecretsList.filter((s) => !(s.name in decryptedStore)).map((s) => s.name);
  if (missingSecrets.length > 0) {
    throw new Error(`assembleRecoveryPayload: the secrets store is missing required secret(s): ${missingSecrets.join(", ")} - run "hofctl secrets ensure" first`);
  }
  // Filtered to exactly this deployment's own current requirements - see
  // this function's own top comment on why a whole, possibly-stale store
  // is never embedded wholesale.
  const applicationSecrets = {};
  for (const { name } of requiredSecretsList) applicationSecrets[name] = decryptedStore[name];

  // PR 3 review, high finding: this used to run its own weaker, partial
  // inline check (duplicates + missing only) and then embed the WHOLE
  // destinationCredentials object verbatim - never checking for foreign/
  // stale entries (a credential left over from a destination no longer
  // in the policy, or simply an unrelated one sitting in a broader
  // credentials store the caller happens to hold), never checking
  // per-type required fields or type match against the destination
  // actually using each ref. Fixed by SCOPING first (copying only the
  // refs `destinations` itself actually names, ignoring anything else in
  // the caller's own store - a real caller's own destinationCredentials
  // may legitimately be broader than what THIS kit needs, e.g. a store
  // still carrying a since-removed destination's own credential; that
  // must never block assembly, it must simply never be embedded), THEN
  // validating that scoped subset via backup-credentials.mjs's own
  // validateBackupCredentials() (the same strict, policy-derived check
  // this module was built alongside) - missing/malformed/wrongly-typed
  // entries for a destination THIS kit actually uses still refuse
  // assembly outright; anything else in the caller's own broader store
  // is simply never looked at, and so can never leak into the kit
  // either way.
  const scopedDestinationCredentials = {};
  for (const { secretRef } of destinations ?? []) {
    if (secretRef in (destinationCredentials ?? {})) scopedDestinationCredentials[secretRef] = destinationCredentials[secretRef];
  }
  const credentialViolations = validateBackupCredentials(destinations ?? [], scopedDestinationCredentials);
  if (credentialViolations.length > 0) {
    throw new Error(`assembleRecoveryPayload: destinationCredentials is not valid for the given destinations: ${credentialViolations.join("; ")}`);
  }

  for (const [label, bundle] of [["releaseLock", releaseLock], ["backupToolLock", backupToolLock]]) {
    if (!isPlainObject(bundle)) throw new Error(`assembleRecoveryPayload requires a real ${label} document`);
  }
  if (!isNonEmptyString(releaseLockSignature) || !isNonEmptyString(releaseLockCertificate) || !isNonEmptyString(releaseLockSigningIdentity) || !isNonEmptyString(releaseLockOidcIssuer)) {
    throw new Error("assembleRecoveryPayload requires releaseLockSignature/releaseLockCertificate/releaseLockSigningIdentity/releaseLockOidcIssuer, all non-empty - the exact signed provenance this generation was actually deployed with, never omitted");
  }
  if (!isNonEmptyString(backupToolLockSignature) || !isNonEmptyString(backupToolLockCertificate)) {
    throw new Error("assembleRecoveryPayload requires backupToolLockSignature/backupToolLockCertificate, both non-empty");
  }
  // Unlike release-lock-v1 (no top-level signatureIdentity/OidcIssuer of
  // its own - see this function's own comment above), backup-tool-lock-v1
  // DOES self-declare who signed the whole document - required by its own
  // schema, but this function accepts an already-parsed object without
  // re-validating it against that schema (see this function's own top
  // comment on why), so a caller-supplied object missing them is still
  // possible and must still be refused explicitly rather than silently
  // embedding undefined/empty values.
  if (!isNonEmptyString(backupToolLock.signatureIdentity) || !isNonEmptyString(backupToolLock.signatureOidcIssuer)) {
    throw new Error("assembleRecoveryPayload requires backupToolLock.signatureIdentity/signatureOidcIssuer, both non-empty");
  }

  const payload = {
    installationId: state.installationId,
    generation: state.generation,
    sanitizedManifest: sanitizeManifest(manifest),
    releaseLock: {
      document: releaseLock,
      signature: releaseLockSignature,
      certificate: releaseLockCertificate,
      signingIdentity: releaseLockSigningIdentity,
      oidcIssuer: releaseLockOidcIssuer,
    },
    backupToolLock: {
      document: backupToolLock,
      signature: backupToolLockSignature,
      certificate: backupToolLockCertificate,
      signingIdentity: backupToolLock.signatureIdentity,
      oidcIssuer: backupToolLock.signatureOidcIssuer,
    },
    applicationSecrets,
    suppliedTls: {
      certificatePem: suppliedTlsMaterial.certificatePem,
      privateKeyPem: suppliedTlsMaterial.privateKeyPem,
    },
    destinationCredentials: scopedDestinationCredentials,
  };

  const violations = validateClosedRecoveryPayload(payload);
  if (violations.length > 0) {
    throw new Error(`assembleRecoveryPayload built a payload that is not well-formed: ${violations.join("; ")}`);
  }
  return payload;
}
