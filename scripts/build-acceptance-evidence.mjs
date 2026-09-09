#!/usr/bin/env node

// Emits one schema-valid acceptance-evidence-v1 document from a real
// published-artifact acceptance run. It is deliberately dumb: it does
// not itself decide whether acceptance passed - the caller (the
// acceptance workflow) passes in the per-scenario results it observed,
// and this script only assembles, derives `result` from them, digests
// the exact release-lock.json the run downloaded, and schema-checks the
// whole thing before writing it. The stable-promotion workflow is what
// later consumes the output as its gate (see scripts/verify-promotion.mjs).

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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

// name=debian12->ubuntu2404 restore,source=debian12,target=ubuntu2404,result=succeeded
function parseScenario(spec) {
  const fields = {};
  for (const part of spec.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) throw new Error(`malformed --scenario field (expected key=value): ${part}`);
    fields[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  for (const required of ["name", "source", "target", "result"]) {
    if (!fields[required]) throw new Error(`--scenario is missing ${required}: ${spec}`);
  }
  return { name: fields.name, source: fields.source, target: fields.target, result: fields.result };
}

export function buildAcceptanceEvidence({ candidate, commit, releaseLockBytes, executionEnvironmentDigest, scenarios, acceptanceRunUrl, recordedAt }) {
  const releaseMatch = /^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-rc\.[1-9][0-9]*$/.exec(candidate ?? "");
  if (!releaseMatch) throw new Error(`--candidate must be an immutable candidate tag vX.Y.Z-rc.N: ${candidate}`);
  if (!Array.isArray(scenarios) || scenarios.length === 0) throw new Error("at least one --scenario is required");

  const result = scenarios.every((scenario) => scenario.result === "succeeded") ? "succeeded" : "failed";

  return {
    apiVersion: "hof.dev/acceptance-evidence/v1",
    candidate,
    release: releaseMatch[1],
    commit,
    releaseLockDigest: "sha256:" + createHash("sha256").update(releaseLockBytes).digest("hex"),
    executionEnvironmentDigest,
    result,
    scenarios,
    acceptanceRunUrl,
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
  for (const required of ["candidate", "commit", "release-lock", "run-url", "out"]) {
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
    acceptanceRunUrl: args["run-url"],
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
