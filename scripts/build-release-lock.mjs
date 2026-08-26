#!/usr/bin/env node
// Resolves the current, real state of every catalog artifact (source
// commit, signed image digest, SBOM/provenance attestations) into a
// release-lock.json. Read-only against GitHub/GHCR - never mutates
// anything. Signing the resulting file is a separate step (this script's
// own GitHub Actions caller does it with `cosign sign-blob`, using the
// workflow's ambient OIDC identity - there's no interactive keyless
// signing path to reuse from a plain CLI run).
//
// Usage: node scripts/build-release-lock.mjs --release 0.1.0 [--out FILE]

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OWNER = "vrubovoy";
const REGISTRY = "ghcr.io/vrubovoy";
const MINIMUM_HOFCTL_VERSION = "0.1.0";

// Every artifact this script resolves against the upstream image itself
// rather than a Hof-signed GHCR build - kept in one place since it's the
// one genuinely different code path (see resolveThirdPartyComponent).
const THIRD_PARTY_ARTIFACTS = {
  gateway: "docker.io/library/caddy:2-alpine",
};

function parseArgs(argv) {
  const args = { out: null, release: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--release") args.release = argv[++i];
    else if (argv[i] === "--out") args.out = argv[++i];
  }
  if (!args.release) throw new Error("--release <semver> is required");
  return args;
}

async function gh(ghArgs) {
  const { stdout } = await exec("gh", ghArgs, { maxBuffer: 64 * 1024 * 1024 });
  return stdout;
}

async function verifyAttestation(imageRef, predicateType) {
  const args = ["attestation", "verify", `oci://${imageRef}`, "--owner", OWNER, "--format", "json"];
  if (predicateType) args.push("--predicate-type", predicateType);
  const out = await gh(args);
  const results = JSON.parse(out);
  if (results.length === 0) {
    throw new Error(`no ${predicateType ?? "build provenance"} attestation found for ${imageRef}`);
  }
  return results[0];
}

// Not a canonical-JSON digest (RFC 8785) - just a stable fingerprint of
// the exact statement gh's own JSON output returned for this run, so a
// later drift (a re-signed or re-attested statement) produces a
// different value. Reproducible by anyone re-running `gh attestation
// verify --format json` against the same subject.
function digestOfStatement(statement) {
  return "sha256:" + createHash("sha256").update(JSON.stringify(statement)).digest("hex");
}

async function resolveSelfBuiltComponent(artifact) {
  const imageRef = `${REGISTRY}/${artifact}:latest`;
  const [provenance, sbom] = await Promise.all([
    verifyAttestation(imageRef, undefined),
    verifyAttestation(imageRef, "https://spdx.dev/Document"),
  ]);

  const provenanceStatement = provenance.verificationResult.statement;
  const sbomStatement = sbom.verificationResult.statement;
  const digest = provenanceStatement.subject[0].digest.sha256;
  if (sbomStatement.subject[0].digest.sha256 !== digest) {
    throw new Error(`${artifact}: provenance and SBOM attestations disagree on the image digest`);
  }

  const cert = provenance.verificationResult.signature.certificate;
  return {
    source: cert.sourceRepositoryURI,
    revision: cert.sourceRepositoryDigest,
    image: `${REGISTRY}/${artifact}@sha256:${digest}`,
    signatureIdentity: cert.subjectAlternativeName,
    provenanceDigest: digestOfStatement(provenanceStatement),
    sbomDigest: digestOfStatement(sbomStatement),
    configSchema: 1,
    // No prior release to diff a database schema against yet - wire this
    // up when delivery item 8 (upgrade/rollback) needs a real from/to.
  };
}

async function resolveThirdPartyComponent(upstreamRef) {
  const { stdout } = await exec("docker", ["buildx", "imagetools", "inspect", upstreamRef, "--format", "{{json .Manifest}}"]);
  const manifest = JSON.parse(stdout);
  const [repository] = upstreamRef.split(":");
  return { image: `${repository}@${manifest.digest}`, thirdParty: true };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const [catalogText, releaseLockSchema] = await Promise.all([
    readFile(path.join(root, "catalog/services-v1.yaml"), "utf8"),
    readFile(path.join(root, "schemas/release-lock-v1.schema.json"), "utf8").then(JSON.parse),
  ]);
  const catalog = YAML.parse(catalogText);
  const catalogDigest = "sha256:" + createHash("sha256").update(JSON.stringify(catalog)).digest("hex");

  const artifacts = catalog.services.flatMap((service) => service.artifacts);
  console.error(`Resolving ${artifacts.length} artifacts for release ${args.release}...`);

  const components = {};
  for (const artifact of artifacts) {
    process.stderr.write(`  ${artifact}... `);
    components[artifact] = THIRD_PARTY_ARTIFACTS[artifact]
      ? await resolveThirdPartyComponent(THIRD_PARTY_ARTIFACTS[artifact])
      : await resolveSelfBuiltComponent(artifact);
    console.error("ok");
  }

  const releaseLock = {
    apiVersion: "hof.dev/release-lock/v1",
    release: args.release,
    minimumHofctlVersion: MINIMUM_HOFCTL_VERSION,
    catalogDigest,
    components,
  };

  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  const validate = ajv.compile(releaseLockSchema);
  if (!validate(releaseLock)) {
    for (const error of validate.errors ?? []) {
      console.error(`${error.instancePath || "/"}: ${error.message}`);
    }
    throw new Error("generated release lock failed its own schema");
  }

  const json = JSON.stringify(releaseLock, null, 2) + "\n";
  if (args.out) {
    await writeFile(args.out, json);
    console.error(`Wrote ${args.out}`);
  } else {
    process.stdout.write(json);
  }
}

main().catch((error) => {
  console.error(error.stack ?? String(error));
  process.exitCode = 1;
});
