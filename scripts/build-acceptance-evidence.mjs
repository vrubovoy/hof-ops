#!/usr/bin/env node

// Emits one schema-valid acceptance-evidence-v1 document from a real
// published-artifact acceptance run. It is deliberately dumb: the caller
// (the future .github/workflows/acceptance.yml, running only on
// protected main) passes in the per-leg / per-destination results it
// observed plus its own GitHub run context; this script assembles,
// derives every `result` from the leaves up, digests the exact
// release-lock.json the run downloaded, and schema-checks the whole
// thing before writing it. acceptance.yml then Cosign-signs the output
// with its own OIDC identity; promote.yml verifies that identity, the
// run provenance recorded here, and the digest binding before it will
// promote anything (see scripts/verify-promotion.mjs).

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const ACCEPTANCE_WORKFLOW_PATH = ".github/workflows/acceptance.yml";
export const ACCEPTANCE_WORKFLOW_REF = "refs/heads/main";
export const REQUIRED_SCENARIO_IDS = ["debian12-to-ubuntu2404", "ubuntu2404-to-debian12"];

// --flag value pairs, plus --scenario repeated any number of times.
function parseArgs(argv) {
  const args = { scenario: [] };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];
    if (!key || value === undefined) throw new Error(`dangling flag: ${argv[i]}`);
    if (key === "scenario") args.scenario.push(value);
    else if (key in args) throw new Error(`duplicate flag: --${key}`);
    else args[key] = value;
  }
  return args;
}

// scenarioId=debian12-to-ubuntu2404,local=succeeded,s3=succeeded
function parseScenario(spec) {
  const fields = {};
  for (const part of spec.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) throw new Error(`malformed --scenario field (expected key=value): ${part}`);
    fields[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  for (const required of ["scenarioId", "local", "s3"]) {
    if (!fields[required]) throw new Error(`--scenario is missing ${required}: ${spec}`);
  }
  const destinations = { local: { result: fields.local }, s3: { result: fields.s3 } };
  const result = destinations.local.result === "succeeded" && destinations.s3.result === "succeeded" ? "succeeded" : "failed";
  return { scenarioId: fields.scenarioId, destinations, result };
}

export function buildAcceptanceEvidence({
  candidate, commit, releaseLockBytes, executionEnvironmentDigest, scenarios,
  acceptanceRunId, acceptanceRunAttempt, acceptanceCommit, acceptanceRunUrl, recordedAt,
}) {
  const releaseMatch = /^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-rc\.[1-9][0-9]*$/.exec(candidate ?? "");
  if (!releaseMatch) throw new Error(`--candidate must be an immutable candidate tag vX.Y.Z-rc.N: ${candidate}`);

  const ids = (scenarios ?? []).map((scenario) => scenario.scenarioId);
  const missing = REQUIRED_SCENARIO_IDS.filter((id) => !ids.includes(id));
  if (missing.length > 0) throw new Error(`acceptance evidence is missing required restore leg(s): ${missing.join(", ")}`);
  if (new Set(ids).size !== ids.length) throw new Error(`duplicate scenarioId in acceptance evidence: ${ids.join(", ")}`);
  const extra = ids.filter((id) => !REQUIRED_SCENARIO_IDS.includes(id));
  if (extra.length > 0) throw new Error(`unknown scenarioId in acceptance evidence: ${extra.join(", ")}`);

  const result = scenarios.every((scenario) => scenario.result === "succeeded") ? "succeeded" : "failed";

  return {
    apiVersion: "hof.dev/acceptance-evidence/v1",
    candidate,
    release: releaseMatch[1],
    commit,
    releaseLockDigest: "sha256:" + createHash("sha256").update(releaseLockBytes).digest("hex"),
    executionEnvironmentDigest,
    acceptanceWorkflowPath: ACCEPTANCE_WORKFLOW_PATH,
    acceptanceWorkflowRef: ACCEPTANCE_WORKFLOW_REF,
    acceptanceRunId,
    acceptanceRunAttempt,
    acceptanceCommit,
    acceptanceRunUrl,
    result,
    scenarios,
    recordedAt: recordedAt ?? new Date().toISOString(),
  };
}

// Reads the pinned EE image digest straight out of the release lock the
// run actually downloaded, so evidence can never disagree with the lock
// it is evidence for.
export function executionEnvironmentDigestOf(releaseLock) {
  const image = releaseLock?.ansibleEnvironment?.image;
  const at = typeof image === "string" ? image.indexOf("@") : -1;
  if (at === -1) throw new Error("release lock has no ansibleEnvironment.image digest");
  return image.slice(at + 1);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["candidate", "commit", "release-lock", "acceptance-run-id", "acceptance-run-attempt", "acceptance-commit", "acceptance-run-url", "out"]) {
    if (!args[required]) throw new Error(`--${required} is required`);
  }

  const releaseLockBytes = await readFile(args["release-lock"]);
  const releaseLock = JSON.parse(releaseLockBytes);

  const evidence = buildAcceptanceEvidence({
    candidate: args.candidate,
    commit: args.commit,
    releaseLockBytes,
    executionEnvironmentDigest: executionEnvironmentDigestOf(releaseLock),
    scenarios: args.scenario.map(parseScenario),
    acceptanceRunId: args["acceptance-run-id"],
    acceptanceRunAttempt: Number(args["acceptance-run-attempt"]),
    acceptanceCommit: args["acceptance-commit"],
    acceptanceRunUrl: args["acceptance-run-url"],
  });

  const schema = JSON.parse(await readFile(path.join(root, "schemas/acceptance-evidence-v1.schema.json"), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(evidence)) throw new Error("assembled evidence is not schema-valid: " + ajv.errorsText(validate.errors));

  await writeFile(args.out, JSON.stringify(evidence, null, 2) + "\n");
  process.stdout.write(`${evidence.result}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
