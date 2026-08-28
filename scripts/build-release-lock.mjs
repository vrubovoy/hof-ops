#!/usr/bin/env node

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
const PROVENANCE_TYPE = "https://slsa.dev/provenance/v1";
const SBOM_TYPE = "https://spdx.dev/Document";

function parseArgs(argv) {
  const args = { out: null, release: null, selection: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--release") args.release = argv[++i];
    else if (argv[i] === "--selection") args.selection = argv[++i];
    else if (argv[i] === "--out") args.out = argv[++i];
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!args.release) throw new Error("--release <semver> is required");
  if (!args.selection) throw new Error("--selection <file> is required");
  return args;
}

function repositoryFile(relativePath) {
  const resolved = path.resolve(root, relativePath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(`path escapes repository: ${relativePath}`);
  }
  return resolved;
}

async function command(program, args) {
  const { stdout } = await exec(program, args, { maxBuffer: 64 * 1024 * 1024 });
  return stdout;
}

async function gh(args) {
  return command("gh", args);
}

function sha256(value) {
  return "sha256:" + createHash("sha256").update(value).digest("hex");
}

function validateWithSchema(schema, value, label) {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (validate(value)) return;
  const details = (validate.errors ?? [])
    .map((error) => `${label}${error.instancePath || "/"}: ${error.message}`)
    .join("\n");
  throw new Error(details);
}

export function assertReleaseVersion(version) {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
    throw new Error(`release must be a canonical stable semver: ${version}`);
  }
}

function flattenPages(json) {
  const value = JSON.parse(json);
  return Array.isArray(value[0]) ? value.flat() : value;
}

// tagPrefix defaults to the platform's own "v" (every ordinary component
// tag, e.g. v1.0.0) - the Ansible Execution Environment is the one
// exception: it versions independently of the platform release inside
// this SAME repository (see ansible/README.md's own "Versioning"
// section), so its own git tag is ee-vX.Y.Z, never plain vX.Y.Z - two
// different things sharing one repository must never be able to collide
// on the same git tag. Only the git tag differs; the GHCR image tag it
// produces is still the ordinary v${version} (see resolveBuiltArtifact's
// own caller, which never changes selection.image's own expected suffix).
async function resolveRevision(repository, version, tagPrefix = "v") {
  const sourceTag = `${tagPrefix}${version}`;
  const revision = JSON.parse(await gh(["api", `repos/${repository}/commits/${sourceTag}`])).sha;
  if (!/^[a-f0-9]{40}$/.test(revision)) {
    throw new Error(`${repository}@${sourceTag}: GitHub did not resolve a full commit SHA`);
  }
  return { revision, sourceTag };
}

async function verifyChecks(repository, revision, requiredChecks) {
  const [checkOutput, statusOutput] = await Promise.all([
    gh(["api", "--paginate", "--slurp", `repos/${repository}/commits/${revision}/check-runs`]),
    gh(["api", `repos/${repository}/commits/${revision}/status`]),
  ]);
  const checkRuns = flattenPages(checkOutput).flatMap((page) => page.check_runs ?? []);
  const statuses = JSON.parse(statusOutput).statuses ?? [];

  for (const required of requiredChecks) {
    const matchingChecks = checkRuns.filter((check) => check.name === required);
    const matchingStatuses = statuses.filter((status) => status.context === required);
    const passed = matchingChecks.some(
      (check) => check.head_sha === revision && check.status === "completed" && check.conclusion === "success"
    ) || matchingStatuses.some((status) => status.sha === revision && status.state === "success");
    if (!passed) throw new Error(`${repository}@${revision}: required GitHub check did not pass: ${required}`);
  }
}

async function resolveDigest(taggedImage) {
  const output = await command("docker", [
    "buildx", "imagetools", "inspect", taggedImage, "--format", "{{json .Manifest}}",
  ]);
  const digest = JSON.parse(output).digest;
  if (!/^sha256:[a-f0-9]{64}$/.test(digest ?? "")) {
    throw new Error(`${taggedImage}: registry did not return a sha256 manifest digest`);
  }
  return digest;
}

function statementFromVerification(result, label) {
  const statement = result?.verificationResult?.statement;
  if (!statement) throw new Error(`${label}: GitHub returned no verified attestation statement`);
  return statement;
}

function assertAttestationSubject(statement, digest, label) {
  const matches = (statement.subject ?? []).some((subject) => subject.digest?.sha256 === digest.slice(7));
  if (!matches) throw new Error(`${label}: attestation subject does not match ${digest}`);
}

async function githubAttestation(image, repository, predicateType) {
  const output = await gh([
    "attestation", "verify", `oci://${image}`, "--repo", repository,
    "--predicate-type", predicateType, "--format", "json",
  ]);
  const results = JSON.parse(output);
  if (results.length === 0) throw new Error(`${image}: no ${predicateType} attestation found`);
  return results[0];
}

async function verifySupplyChain(selection, revision, image) {
  const identityArgs = [
    "--certificate-identity", selection.workflowIdentity,
    "--certificate-oidc-issuer", selection.oidcIssuer,
  ];
  // Verifies the plain Cosign image signature - a separate artifact from
  // the two attestations below, and the one gap a pure `gh attestation
  // verify` pass doesn't close (that only ever checks attestations, never
  // this bare signature). `cosign verify-attestation` was tried here too
  // but doesn't find what `actions/attest-sbom`/`attest-build-provenance`
  // publish (confirmed against a real release run: "no matching
  // attestations" even though `gh attestation verify` finds and fully
  // verifies the same ones cryptographically) - the two tools' registry
  // discovery for GitHub-published attestations isn't compatible yet, so
  // `gh attestation verify` below is this function's real attestation
  // check, not a redundant second one.
  await command("cosign", ["verify", ...identityArgs, image]);

  const [provenance, sbom] = await Promise.all([
    githubAttestation(image, selection.repository, PROVENANCE_TYPE),
    githubAttestation(image, selection.repository, SBOM_TYPE),
  ]);
  const provenanceStatement = statementFromVerification(provenance, `${image} provenance`);
  const sbomStatement = statementFromVerification(sbom, `${image} SBOM`);
  const digest = image.slice(image.indexOf("@") + 1);
  assertAttestationSubject(provenanceStatement, digest, `${image} provenance`);
  assertAttestationSubject(sbomStatement, digest, `${image} SBOM`);

  for (const [kind, verification] of [["provenance", provenance], ["SBOM", sbom]]) {
    const certificate = verification.verificationResult.signature?.certificate;
    if (certificate?.sourceRepositoryURI !== `https://github.com/${selection.repository}`) {
      throw new Error(`${image} ${kind}: source repository does not match the selection`);
    }
    if (certificate?.sourceRepositoryDigest !== revision) {
      throw new Error(`${image} ${kind}: source revision does not match ${revision}`);
    }
  }

  return {
    provenanceDigest: sha256(JSON.stringify(provenanceStatement)),
    sbomDigest: sha256(JSON.stringify(sbomStatement)),
  };
}

async function resolveBuiltArtifact(selection, includeComponentMetadata, tagPrefix = "v") {
  const { revision, sourceTag } = await resolveRevision(selection.repository, selection.version, tagPrefix);
  await verifyChecks(selection.repository, revision, selection.requiredChecks);
  const digest = await resolveDigest(selection.image);
  const image = `${selection.image.replace(/:[^/:]+$/, "")}@${digest}`;
  const attestations = await verifySupplyChain(selection, revision, image);
  const result = {
    source: `https://github.com/${selection.repository}`,
    revision,
    sourceTag,
    image,
    signatureIdentity: selection.workflowIdentity,
    signatureOidcIssuer: selection.oidcIssuer,
    ...attestations,
  };
  if (includeComponentMetadata) {
    result.configSchema = selection.configSchema;
    if (selection.databaseArtifact) result.database = selection.database;
  }
  return result;
}

async function resolveThirdPartyComponent(selection) {
  const digest = await resolveDigest(selection.image);
  return {
    image: `${selection.image.replace(/:[^/:]+$/, "")}@${digest}`,
    thirdParty: true,
    trust: {
      policy: "digest-only",
      upstream: selection.image,
      limitation: selection.trust.limitation,
    },
  };
}

export async function buildReleaseLock(args) {
  assertReleaseVersion(args.release);
  const [selectionText, selectionSchema, lockSchema] = await Promise.all([
    readFile(repositoryFile(args.selection), "utf8"),
    readFile(path.join(root, "schemas/release-selection-v1.schema.json"), "utf8").then(JSON.parse),
    readFile(path.join(root, "schemas/release-lock-v1.schema.json"), "utf8").then(JSON.parse),
  ]);
  const selection = YAML.parse(selectionText);
  validateWithSchema(selectionSchema, selection, "release selection");
  if (selection.release !== args.release) {
    throw new Error(`selection release ${selection.release} does not match requested release ${args.release}`);
  }
  if (selection.ansibleEnvironment && !selection.ansibleEnvironment.image.endsWith(`:v${selection.ansibleEnvironment.version}`)) {
    throw new Error("Ansible environment image tag must equal v plus its selected version");
  }

  const [catalogBytes, composeTemplateBytes] = await Promise.all([
    readFile(repositoryFile(selection.catalog)),
    readFile(repositoryFile(selection.composeTemplate)),
  ]);
  const catalog = YAML.parse(catalogBytes.toString("utf8"));
  const expectedArtifacts = new Set(catalog.services.flatMap((service) => service.artifacts));
  const selectedArtifacts = new Set(Object.keys(selection.components));
  const databaseArtifacts = new Set(
    catalog.services
      .filter((service) => service.id !== "tor" && service.volumes.length > 0)
      .map((service) => service.health.component)
  );
  for (const artifact of expectedArtifacts) {
    if (!selectedArtifacts.has(artifact)) throw new Error(`release selection is missing catalog artifact ${artifact}`);
  }
  for (const artifact of selectedArtifacts) {
    if (!expectedArtifacts.has(artifact)) throw new Error(`release selection has unknown catalog artifact ${artifact}`);
    const component = selection.components[artifact];
    if (!component.thirdParty && !component.image.endsWith(`:v${component.version}`)) {
      throw new Error(`${artifact}: image tag must equal v${component.version}`);
    }
    if (!component.thirdParty && component.databaseArtifact !== databaseArtifacts.has(artifact)) {
      throw new Error(`${artifact}: databaseArtifact does not match the catalog persistence contract`);
    }
  }

  const components = {};
  for (const [name, component] of Object.entries(selection.components)) {
    process.stderr.write(`Resolving ${name}... `);
    components[name] = component.thirdParty
      ? await resolveThirdPartyComponent(component)
      : await resolveBuiltArtifact(component, true);
    console.error("ok");
  }

  const releaseLock = {
    apiVersion: "hof.dev/release-lock/v1",
    release: args.release,
    minimumHofctlVersion: selection.minimumHofctlVersion,
    catalogDigest: sha256(catalogBytes),
    composeTemplateDigest: sha256(composeTemplateBytes),
    components,
  };
  if (selection.ansibleEnvironment) {
    // "ee-v" - the Execution Environment's own git tag convention (see
    // ansible/README.md's "Versioning" section and resolveRevision's own
    // comment above) - never plain "v", which is the platform's own
    // release tag in this SAME repository.
    releaseLock.ansibleEnvironment = await resolveBuiltArtifact(selection.ansibleEnvironment, false, "ee-v");
  }
  validateWithSchema(lockSchema, releaseLock, "release lock");
  return releaseLock;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const releaseLock = await buildReleaseLock(args);
  const json = JSON.stringify(releaseLock, null, 2) + "\n";
  if (args.out) {
    await writeFile(args.out, json);
    console.error(`Wrote ${args.out}`);
  } else {
    process.stdout.write(json);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.stack ?? String(error));
    process.exitCode = 1;
  });
}
