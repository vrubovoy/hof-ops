#!/usr/bin/env node
// hofctl validate - the read-only gate before anything else touches a
// host. Two layers: the schema/cross-contract checks contracts.mjs
// already does (against WHATEVER services.yml/catalog/release-lock this
// deployment actually has, not the repo's own illustrative examples),
// plus the deployment-integrity checks a real host needs that a fixture
// never exercises - does this release lock actually match the catalog
// and renderer this hofctl ships with, is it new enough for this
// hofctl, and is it genuinely signed.

import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { validateContracts } from "./contracts.mjs";
import { sha256 } from "./digest.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HOFCTL_VERSION = JSON.parse(await readFile(path.join(root, "package.json"), "utf8")).version;

// Same ordering rule as semver itself, restricted to the plain MAJOR.MINOR.PATCH
// the release-lock/services.yml schemas already require - no prerelease/build
// metadata to compare here.
function compareSemver(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

async function readYaml(filePath) {
  return YAML.parse(await readFile(filePath, "utf8"));
}

async function fileExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function verifyReleaseLockSignature(releaseLockPath, options) {
  const signaturePath = options.releaseLockSignature ?? `${releaseLockPath}.sig`;
  const certificatePath = options.releaseLockCertificate ?? `${releaseLockPath}.pem`;
  if (!(await fileExists(signaturePath)) || !(await fileExists(certificatePath))) {
    return [`release lock: no signature found at ${signaturePath} (or --release-lock-signature/--release-lock-certificate) - a deployment must not apply an unsigned lock`];
  }
  if (!options.releaseLockIdentity) {
    return ["release lock: --release-lock-identity is required to verify a signature against (the expected signing workflow's identity)"];
  }
  try {
    await exec("cosign", [
      "verify-blob",
      "--certificate", certificatePath,
      "--signature", signaturePath,
      "--certificate-identity", options.releaseLockIdentity,
      "--certificate-oidc-issuer", options.releaseLockOidcIssuer ?? "https://token.actions.githubusercontent.com",
      releaseLockPath,
    ]);
    return [];
  } catch (error) {
    return [`release lock: signature verification failed: ${error instanceof Error ? error.message : error}`];
  }
}

// Same options as validateDeployment() below - returns the parsed
// manifest/catalog/releaseLock and the three schemas alongside the
// errors array, so a caller that needs to keep going past validation
// (hofctl plan, in particular) never has to re-read or re-parse the
// same deployment files a second time just to get at them.
//
// options: { servicesPath, catalogPath, releaseLockPath, releaseSelectionPath?,
//   stableChannelPath?, releaseLockSignature?, releaseLockCertificate?,
//   releaseLockIdentity?, releaseLockOidcIssuer?, skipSignature? }
export async function loadAndValidateDeployment(options) {
  // The catalog is release-owned and ships inside hof-ops itself - a
  // deployment only ever overrides it deliberately (e.g. testing an
  // unpublished catalog change), so default to the one this hofctl
  // actually carries rather than requiring --catalog on every call. Uses
  // ??= (not a spread-merge default) so an explicitly-passed key set to
  // undefined doesn't shadow the default the way spread would.
  options.catalogPath ??= path.join(root, "catalog/services-v1.yaml");
  const errors = [];

  const [servicesSchema, catalogSchema, releaseLockSchema, releaseSelectionSchema, stableChannelSchema] = await Promise.all([
    readJson(path.join(root, "schemas/services-v1alpha1.schema.json")),
    readJson(path.join(root, "schemas/service-catalog-v1.schema.json")),
    readJson(path.join(root, "schemas/release-lock-v1.schema.json")),
    readJson(path.join(root, "schemas/release-selection-v1.schema.json")),
    readJson(path.join(root, "schemas/stable-channel-v1.schema.json")),
  ]);

  let manifest, catalog, catalogBytes, releaseLock, releaseLockBytes;
  try {
    [manifest, [catalog, catalogBytes], [releaseLock, releaseLockBytes]] = await Promise.all([
      readYaml(options.servicesPath),
      readFile(options.catalogPath).then((bytes) => [YAML.parse(bytes.toString("utf8")), bytes]),
      readFile(options.releaseLockPath).then((bytes) => [JSON.parse(bytes.toString("utf8")), bytes]),
    ]);
  } catch (error) {
    return { errors: [`could not read services.yml/catalog/release-lock: ${error instanceof Error ? error.message : error}`], manifest: null, catalog: null, releaseLock: null, servicesSchema, catalogSchema, releaseLockSchema };
  }

  const contracts = { servicesSchema, catalogSchema, releaseLockSchema, releaseSelectionSchema, stableChannelSchema, manifest, catalog, releaseLock };
  if (options.releaseSelectionPath) contracts.releaseSelection = await readYaml(options.releaseSelectionPath);
  if (options.stableChannelPath) contracts.stableChannel = await readJson(options.stableChannelPath);
  errors.push(...validateContracts(contracts));

  const composeTemplateBytes = await readFile(path.join(root, "scripts/render-topology.mjs"));
  const actualCatalogDigest = sha256(catalogBytes);
  if (releaseLock.catalogDigest && releaseLock.catalogDigest !== actualCatalogDigest) {
    errors.push(`release lock: catalogDigest ${releaseLock.catalogDigest} does not match the actual catalog (${actualCatalogDigest}) - this lock was not built against the catalog this hofctl has`);
  }
  const actualComposeTemplateDigest = sha256(composeTemplateBytes);
  if (releaseLock.composeTemplateDigest && releaseLock.composeTemplateDigest !== actualComposeTemplateDigest) {
    errors.push(`release lock: composeTemplateDigest ${releaseLock.composeTemplateDigest} does not match this hofctl's own renderer (${actualComposeTemplateDigest}) - apply would generate a topology this release was never tested against`);
  }

  if (releaseLock.minimumHofctlVersion && compareSemver(HOFCTL_VERSION, releaseLock.minimumHofctlVersion) < 0) {
    errors.push(`release lock requires hofctl >= ${releaseLock.minimumHofctlVersion}, this is ${HOFCTL_VERSION}`);
  }

  if (options.skipSignature) {
    // Never the silent default - only reachable via an explicit flag, and
    // always noted in the result so a caller can't mistake "skipped" for
    // "passed".
    errors.push("release lock signature check was explicitly skipped (--skip-signature) - do not apply with this flag set");
  } else {
    errors.push(...await verifyReleaseLockSignature(options.releaseLockPath, options));
  }

  return { errors, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema };
}

// The original, narrower shape (`validate`'s own CLI still only ever
// wants the errors array) - kept as a thin wrapper so nothing about
// hofctl validate's own contract changes.
export async function validateDeployment(options) {
  return (await loadAndValidateDeployment(options)).errors;
}
