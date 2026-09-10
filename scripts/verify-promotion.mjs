#!/usr/bin/env node

// The stable-promotion gate. Given an immutable candidate tag, the exact
// release-lock.json downloaded from that candidate's GitHub Release, the
// acceptance-evidence-v1 document from the acceptance run, the acceptance
// run's own live GitHub metadata, and the catalog/renderer digests
// computed from THIS checkout (promote.yml runs from protected main),
// this decides whether the candidate may be promoted to `stable`.
//
// It rebuilds nothing and re-resolves nothing - promotion moves the exact
// bytes acceptance already exercised - so every check here is an equality
// check, never a fresh computation that could drift.
//
// Cosign identity verification of BOTH blobs (the candidate lock against
// release.yml@<some ref>, and this evidence against
// acceptance.yml@refs/heads/main), the candidate certificate's
// github-workflow-sha, the "candidate commit is an ancestor of main"
// check, and the candidate release's `immutable` flag all live in
// promote.yml itself (they need cosign / git / the GitHub API). This
// module is the pure, unit-testable core of everything else.
//
// Refuses unless ALL hold:
//   - evidence is schema-valid and result === "succeeded"
//   - the candidate lock is schema-valid (checked with main's own schema)
//   - evidence.candidate / .release match the tag being promoted
//   - evidence.releaseLockDigest === sha256(downloaded release-lock.json)
//   - evidence.executionEnvironmentDigest === the EE digest inside that lock
//   - the lock's own `release` === the tag's release
//   - the lock's catalogDigest / composeTemplateDigest === the digests of
//     catalog/renderer in THIS (main) checkout
//   - evidence.commit === evidence.acceptanceCommit === the candidate
//     release's own target commit
//   - the acceptance run's live .path / head_branch / head_sha / status /
//     conclusion / run_attempt / id / html_url all match what evidence
//     recorded, and the workflow is acceptance.yml on main, completed
//     successfully
//   - the two required restore legs are both present, not duplicated, and
//     every destination in each leg succeeded

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

import { validateCatalog, validateReleaseLock } from "./contracts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const CANDIDATE_TAG = /^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-rc\.[1-9][0-9]*$/;
const SHA40 = /^[0-9a-f]{40}$/;
const ACCEPTANCE_WORKFLOW_PATH = ".github/workflows/acceptance.yml";
const ACCEPTANCE_WORKFLOW_REF = "refs/heads/main";
const REQUIRED_SCENARIO_IDS = ["debian12-to-ubuntu2404", "ubuntu2404-to-debian12"];

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];
    if (!key || value === undefined) throw new Error(`dangling flag: ${argv[i]}`);
    if (key in args) throw new Error(`duplicate flag: --${key}`);
    args[key] = value;
  }
  return args;
}

function sha256(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

// `run` is the acceptance run's live GitHub metadata, exactly as
// promote.yml pulls it from `gh api repos/{repo}/actions/runs/{id}`:
// { id, path, headBranch, headSha, status, conclusion, runAttempt, htmlUrl }.
// `expectedCatalogDigest` / `expectedComposeTemplateDigest` are computed
// from THIS checkout (main) by the caller.
export function verifyPromotion({
  candidate, releaseLockBytes, releaseLock, releaseLockSchema,
  evidence, evidenceSchema, commit, run, expectedRunId,
  catalog, expectedCatalogDigest, expectedComposeTemplateDigest,
}) {
  const errors = [];
  const fail = (message) => errors.push(message);

  const tagMatch = CANDIDATE_TAG.exec(candidate ?? "");
  if (!tagMatch) return { ok: false, errors: [`candidate is not an immutable candidate tag vX.Y.Z-rc.N: ${candidate}`] };
  const release = tagMatch[1];

  if (!SHA40.test(commit ?? "")) return { ok: false, errors: [`--commit must be a full 40-character candidate commit SHA: ${commit}`] };

  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);

  const validateEvidence = ajv.compile(evidenceSchema);
  if (!validateEvidence(evidence)) {
    return { ok: false, errors: [`acceptance evidence is not schema-valid: ${ajv.errorsText(validateEvidence.errors)}`] };
  }
  const validateLock = ajv.compile(releaseLockSchema);
  if (!validateLock(releaseLock)) {
    fail(`downloaded release-lock.json is not schema-valid against main's release-lock-v1 schema: ${ajv.errorsText(validateLock.errors)}`);
  }

  // Full cross-contract check with main's own trusted catalog, not just
  // JSON Schema: every catalog artifact must be present in the lock and
  // no unknown component may appear (contracts.mjs's own rules, the ones
  // `pnpm validate` runs). A schema-valid lock that quietly dropped an
  // optional component would otherwise sail through, especially when
  // acceptance only exercised core topology.
  if (catalog !== undefined) {
    for (const message of validateCatalog(catalog)) fail(`main catalog: ${message}`);
    for (const message of validateReleaseLock(releaseLock, catalog)) fail(message);
  }

  if (evidence.result !== "succeeded") fail(`acceptance evidence result is ${evidence.result}, not succeeded`);
  if (evidence.candidate !== candidate) fail(`acceptance evidence is for ${evidence.candidate}, not the candidate being promoted (${candidate})`);
  if (evidence.release !== release) fail(`acceptance evidence release ${evidence.release} does not match the candidate tag's release ${release}`);

  const lockDigest = sha256(releaseLockBytes);
  if (evidence.releaseLockDigest !== lockDigest) {
    fail(`acceptance evidence release-lock digest ${evidence.releaseLockDigest} does not match the downloaded release-lock.json (${lockDigest}) - acceptance did not run these exact bytes`);
  }

  const eeImage = releaseLock?.ansibleEnvironment?.image;
  const at = typeof eeImage === "string" ? eeImage.indexOf("@") : -1;
  const eeDigest = at === -1 ? null : eeImage.slice(at + 1);
  if (!eeDigest) fail("downloaded release-lock.json has no ansibleEnvironment.image digest");
  else if (evidence.executionEnvironmentDigest !== eeDigest) {
    fail(`acceptance evidence EE digest ${evidence.executionEnvironmentDigest} does not match the release lock's ${eeDigest}`);
  }

  if (releaseLock?.release !== release) {
    fail(`downloaded release-lock.json release ${releaseLock?.release} does not match the candidate tag's release ${release}`);
  }

  // catalog / renderer must be exactly what main ships - a feature-branch
  // candidate cannot smuggle a modified catalog or render-topology.mjs
  // past promotion.
  if (expectedCatalogDigest !== undefined && releaseLock?.catalogDigest !== expectedCatalogDigest) {
    fail(`release lock catalogDigest ${releaseLock?.catalogDigest} does not match main's catalog (${expectedCatalogDigest})`);
  }
  if (expectedComposeTemplateDigest !== undefined && releaseLock?.composeTemplateDigest !== expectedComposeTemplateDigest) {
    fail(`release lock composeTemplateDigest ${releaseLock?.composeTemplateDigest} does not match main's renderer (${expectedComposeTemplateDigest})`);
  }

  if (evidence.commit !== commit) fail(`acceptance evidence commit ${evidence.commit} does not match the candidate release commit ${commit}`);
  if (evidence.acceptanceCommit !== commit) fail(`acceptance ran commit ${evidence.acceptanceCommit}, not the candidate commit ${commit}`);

  // Run provenance - evidence's recorded values AND the live run must
  // both agree, and both must describe acceptance.yml on main, completed
  // successfully.
  if (evidence.acceptanceWorkflowPath !== ACCEPTANCE_WORKFLOW_PATH) fail(`acceptance evidence workflow path is ${evidence.acceptanceWorkflowPath}, not ${ACCEPTANCE_WORKFLOW_PATH}`);
  if (evidence.acceptanceWorkflowRef !== ACCEPTANCE_WORKFLOW_REF) fail(`acceptance evidence workflow ref is ${evidence.acceptanceWorkflowRef}, not ${ACCEPTANCE_WORKFLOW_REF}`);

  if (!run || typeof run !== "object") {
    fail("no live acceptance run metadata supplied");
  } else {
    if (run.path !== ACCEPTANCE_WORKFLOW_PATH) fail(`live acceptance run workflow path is ${run.path}, not ${ACCEPTANCE_WORKFLOW_PATH}`);
    if (run.headBranch !== "main") fail(`live acceptance run head_branch is ${run.headBranch}, not main`);
    if (run.headSha !== evidence.acceptanceCommit) fail(`live acceptance run head_sha ${run.headSha} does not match evidence acceptanceCommit ${evidence.acceptanceCommit}`);
    if (run.status !== "completed") fail(`live acceptance run status is ${run.status}, not completed`);
    if (run.conclusion !== "success") fail(`live acceptance run conclusion is ${run.conclusion}, not success`);
    if (Number(run.runAttempt) !== evidence.acceptanceRunAttempt) fail(`live acceptance run attempt ${run.runAttempt} does not match evidence acceptanceRunAttempt ${evidence.acceptanceRunAttempt}`);
    if (String(run.id) !== evidence.acceptanceRunId) fail(`live acceptance run id ${run.id} does not match evidence acceptanceRunId ${evidence.acceptanceRunId}`);
    if (expectedRunId !== undefined && evidence.acceptanceRunId !== String(expectedRunId)) {
      fail(`evidence acceptanceRunId ${evidence.acceptanceRunId} does not match the run id promotion was asked to use (${expectedRunId})`);
    }
    if (run.htmlUrl !== evidence.acceptanceRunUrl) fail(`live acceptance run html_url ${run.htmlUrl} does not match evidence acceptanceRunUrl ${evidence.acceptanceRunUrl}`);
  }

  // Restore matrix - both required legs, no duplicates, every
  // destination green.
  const ids = (evidence.scenarios ?? []).map((scenario) => scenario.scenarioId);
  if (new Set(ids).size !== ids.length) fail(`duplicate scenarioId in acceptance evidence: ${ids.join(", ")}`);
  for (const requiredId of REQUIRED_SCENARIO_IDS) {
    if (!ids.includes(requiredId)) fail(`acceptance evidence is missing required restore leg ${requiredId}`);
  }
  for (const id of ids) {
    if (!REQUIRED_SCENARIO_IDS.includes(id)) fail(`acceptance evidence has an unexpected restore leg ${id}`);
  }
  for (const scenario of evidence.scenarios ?? []) {
    for (const destination of ["local", "s3"]) {
      if (scenario.destinations?.[destination]?.result !== "succeeded") {
        fail(`restore leg ${scenario.scenarioId} destination ${destination} is ${scenario.destinations?.[destination]?.result}, not succeeded`);
      }
    }
    if (scenario.result !== "succeeded") fail(`restore leg ${scenario.scenarioId} result is ${scenario.result}, not succeeded`);
  }

  return { ok: errors.length === 0, errors, release };
}

// Resolve the catalog / renderer paths a release selection names, digest
// them from disk exactly the way build-release-lock.mjs does when it
// writes catalogDigest / composeTemplateDigest, and parse the catalog
// itself for the full cross-contract check.
export async function loadTrustedInputsFromSelection(repoRoot, selectionRelPath = "examples/release-selection.yml") {
  const selection = YAML.parse(await readFile(path.join(repoRoot, selectionRelPath), "utf8"));
  for (const key of ["catalog", "composeTemplate"]) {
    if (typeof selection?.[key] !== "string" || selection[key].includes("..") || selection[key].startsWith("/")) {
      throw new Error(`release selection ${key} is not a safe repo-relative path: ${selection?.[key]}`);
    }
  }
  const catalogBytes = await readFile(path.join(repoRoot, selection.catalog));
  return {
    catalog: YAML.parse(catalogBytes.toString("utf8")),
    catalogDigest: sha256(catalogBytes),
    composeTemplateDigest: sha256(await readFile(path.join(repoRoot, selection.composeTemplate))),
  };
}

// Maps the raw `gh api repos/{repo}/actions/runs/{id}` JSON to the shape
// verifyPromotion() expects - no shell interpolation of any API field.
export function runMetadataFromApi(raw) {
  return {
    id: raw?.id,
    path: raw?.path,
    headBranch: raw?.head_branch,
    headSha: raw?.head_sha,
    status: raw?.status,
    conclusion: raw?.conclusion,
    runAttempt: raw?.run_attempt,
    htmlUrl: raw?.html_url,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["candidate", "release-lock", "evidence", "commit", "run-json", "run-id"]) {
    if (!args[required]) throw new Error(`--${required} is required`);
  }

  const repoRoot = args["repo-root"] ? path.resolve(args["repo-root"]) : root;
  const releaseLockBytes = await readFile(args["release-lock"]);
  const evidenceSchema = JSON.parse(await readFile(path.join(root, "schemas/acceptance-evidence-v1.schema.json"), "utf8"));
  const releaseLockSchema = JSON.parse(await readFile(path.join(repoRoot, "schemas/release-lock-v1.schema.json"), "utf8"));
  const { catalog, catalogDigest, composeTemplateDigest } = await loadTrustedInputsFromSelection(repoRoot, args.selection ?? "examples/release-selection.yml");

  const { ok, errors, release } = verifyPromotion({
    candidate: args.candidate,
    releaseLockBytes,
    releaseLock: JSON.parse(releaseLockBytes),
    releaseLockSchema,
    evidence: JSON.parse(await readFile(args.evidence, "utf8")),
    evidenceSchema,
    commit: args.commit,
    run: runMetadataFromApi(JSON.parse(await readFile(args["run-json"], "utf8"))),
    expectedRunId: args["run-id"],
    catalog,
    expectedCatalogDigest: catalogDigest,
    expectedComposeTemplateDigest: composeTemplateDigest,
  });

  if (!ok) {
    console.error("promotion refused:");
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
  }
  process.stdout.write(`${release}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
