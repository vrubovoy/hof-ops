#!/usr/bin/env node

// The stable-promotion gate. Given an immutable candidate tag, the
// exact release-lock.json downloaded from that candidate's GitHub
// Release, and the acceptance-evidence-v1 document from the acceptance
// run, this decides whether the candidate may be promoted to the stable
// channel. It rebuilds nothing and re-resolves nothing - promotion
// moves the exact bytes acceptance already exercised, so every check
// here is an equality check against those bytes, never a fresh
// computation that could drift.
//
// Refuses unless ALL hold:
//   - evidence is schema-valid
//   - evidence.result === "succeeded"
//   - evidence.candidate === the candidate tag being promoted
//   - evidence.release === the release the tag would promote to
//   - evidence.releaseLockDigest === sha256(downloaded release-lock.json)
//   - evidence.executionEnvironmentDigest === the EE digest inside that lock
//   - the lock's own `release` field === evidence.release
//   - (when --commit is given) evidence.commit === that commit

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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

const CANDIDATE_TAG = /^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-rc\.[1-9][0-9]*$/;

export function verifyPromotion({ candidate, releaseLockBytes, releaseLock, evidence, evidenceSchema, commit }) {
  const errors = [];

  const tagMatch = CANDIDATE_TAG.exec(candidate ?? "");
  if (!tagMatch) {
    errors.push(`candidate is not an immutable candidate tag vX.Y.Z-rc.N: ${candidate}`);
    return { ok: false, errors };
  }
  const release = tagMatch[1];

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(evidenceSchema);
  if (!validate(evidence)) {
    errors.push(`acceptance evidence is not schema-valid: ${ajv.errorsText(validate.errors)}`);
    return { ok: false, errors };
  }

  if (evidence.result !== "succeeded") errors.push(`acceptance evidence result is ${evidence.result}, not succeeded`);
  if (evidence.candidate !== candidate) errors.push(`acceptance evidence is for ${evidence.candidate}, not the candidate being promoted (${candidate})`);
  if (evidence.release !== release) errors.push(`acceptance evidence release ${evidence.release} does not match the candidate tag's release ${release}`);

  const lockDigest = "sha256:" + createHash("sha256").update(releaseLockBytes).digest("hex");
  if (evidence.releaseLockDigest !== lockDigest) {
    errors.push(`acceptance evidence release-lock digest ${evidence.releaseLockDigest} does not match the downloaded release-lock.json (${lockDigest}) - acceptance did not run these exact bytes`);
  }

  const eeImage = releaseLock?.ansibleEnvironment?.image;
  const at = typeof eeImage === "string" ? eeImage.indexOf("@") : -1;
  const eeDigest = at === -1 ? null : eeImage.slice(at + 1);
  if (!eeDigest) errors.push("downloaded release-lock.json has no ansibleEnvironment.image digest");
  else if (evidence.executionEnvironmentDigest !== eeDigest) {
    errors.push(`acceptance evidence EE digest ${evidence.executionEnvironmentDigest} does not match the release lock's ${eeDigest}`);
  }

  if (releaseLock?.release !== release) {
    errors.push(`downloaded release-lock.json release ${releaseLock?.release} does not match the candidate tag's release ${release}`);
  }

  if (commit !== undefined && evidence.commit !== commit) {
    errors.push(`acceptance evidence commit ${evidence.commit} does not match the candidate release commit ${commit}`);
  }

  return { ok: errors.length === 0, errors, release };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["candidate", "release-lock", "evidence"]) {
    if (!args[required]) throw new Error(`--${required} is required`);
  }

  const releaseLockBytes = await readFile(args["release-lock"]);
  const evidenceSchema = JSON.parse(await readFile(path.join(root, "schemas/acceptance-evidence-v1.schema.json"), "utf8"));

  const { ok, errors, release } = verifyPromotion({
    candidate: args.candidate,
    releaseLockBytes,
    releaseLock: JSON.parse(releaseLockBytes),
    evidence: JSON.parse(await readFile(args.evidence, "utf8")),
    evidenceSchema,
    commit: args.commit,
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
