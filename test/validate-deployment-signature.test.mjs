// Real-cosign (fake binary) coverage for validate-deployment.mjs's
// verifyReleaseLockSignature() - specifically the gate-7-errata fix:
// cosign must verify the exact bytes already read into memory (and
// used to build the manifest/catalog/releaseLock objects everything
// else, including hofctl plan's own render, is built from), never a
// fresh re-read of releaseLockPath - a mutable pathname handed straight
// to `cosign verify-blob` could otherwise verify different content than
// what this process actually validated/planned if the file changed
// between the two reads.

import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateDeployment } from "../scripts/validate-deployment.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");
const examplesServices = path.join(root, "examples/services.yml");
const examplesCatalog = path.join(root, "catalog/services-v1.yaml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");

let workDir;
let releaseLockPath;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-validate-signature-"));
  releaseLockPath = path.join(workDir, "release-lock.json");
  await writeFile(releaseLockPath, await readFile(examplesReleaseLock));
  await writeFile(`${releaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${releaseLockPath}.pem`, "fake-certificate\n");
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

async function withFakeCosign(env, fn) {
  const originalPath = process.env.PATH;
  const saved = {};
  for (const key of Object.keys(env)) saved[key] = process.env[key];
  process.env.PATH = `${fakeCosignDir}${path.delimiter}${originalPath}`;
  Object.assign(process.env, env);
  try {
    return await fn();
  } finally {
    process.env.PATH = originalPath;
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function baseOptions(overrides = {}) {
  return {
    servicesPath: examplesServices, catalogPath: examplesCatalog, releaseLockPath,
    releaseLockIdentity: "test@example.com",
    ...overrides,
  };
}

test("cosign verifies the exact bytes read at call time, even when the original releaseLockPath is replaced during the verification window itself", async () => {
  const recordedBlobPath = path.join(workDir, "recorded-blob.json");
  const originalBytes = await readFile(releaseLockPath);

  // The fake cosign process itself mutates releaseLockPath the instant
  // it starts (well after loadAndValidateDeployment's own initial read
  // has already completed and parsed releaseLock into memory), then
  // records whatever blob path it was actually told to verify -
  // deterministic, no real race required: if cosign were (wrongly)
  // re-reading releaseLockPath live instead of a pinned copy, the
  // recorded blob would come back tampered.
  const errors = await withFakeCosign(
    { HOF_TEST_COSIGN_OUTCOME: "success", HOF_TEST_COSIGN_RECORD_BLOB: recordedBlobPath, HOF_TEST_COSIGN_MUTATE_PATH: releaseLockPath },
    () => validateDeployment(baseOptions()),
  );

  assert.deepEqual(errors, []);
  // The mutation genuinely happened - otherwise this test would prove
  // nothing at all.
  const mutatedBytes = await readFile(releaseLockPath);
  assert.notDeepEqual(mutatedBytes, originalBytes);
  const recordedBytes = await readFile(recordedBlobPath);
  assert.deepEqual(recordedBytes, originalBytes, "cosign must have verified the originally-read (pinned) bytes, not the file's later-mutated content");

  // Restore the fixture for any later test in this file.
  await writeFile(releaseLockPath, originalBytes);
});

test("the pinned temp blob file is always cleaned up, on both a passing and a failing verification", async () => {
  const before = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-release-lock-"));

  await withFakeCosign({ HOF_TEST_COSIGN_OUTCOME: "success" }, () => validateDeployment(baseOptions()));
  await withFakeCosign({ HOF_TEST_COSIGN_OUTCOME: "failure" }, () => validateDeployment(baseOptions()));

  const after = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-release-lock-"));
  assert.deepEqual(after, before, "no leftover pinned release-lock temp file after either outcome");
});

test("a real cosign signature failure is reported as a genuine deployment error, not silently ignored", async () => {
  const errors = await withFakeCosign({ HOF_TEST_COSIGN_OUTCOME: "failure" }, () => validateDeployment(baseOptions()));
  assert.ok(errors.some((message) => message.includes("signature verification failed")));
});
