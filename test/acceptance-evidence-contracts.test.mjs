// Contract coverage for Item 10 PR 0's stable-promotion gate: the
// acceptance-evidence-v1 schema, scripts/build-acceptance-evidence.mjs's
// own assembly/derivation, and scripts/verify-promotion.mjs's own
// accept/refuse decision. No workflow runs here - these are the parts of
// the candidate -> acceptance -> stable pipeline that are testable
// without a real GitHub API round trip (same reasoning as
// test/release-lock-contracts.test.mjs).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { buildAcceptanceEvidence, executionEnvironmentDigestOf } from "../scripts/build-acceptance-evidence.mjs";
import { verifyPromotion } from "../scripts/verify-promotion.mjs";

const root = path.resolve(import.meta.dirname, "..");
const EE_DIGEST = "sha256:" + "b".repeat(64);

async function evidenceSchema() {
  return JSON.parse(await readFile(path.join(root, "schemas/acceptance-evidence-v1.schema.json"), "utf8"));
}

async function evidenceValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(await evidenceSchema());
}

function releaseLockFixture(overrides = {}) {
  return {
    release: "0.3.0",
    ansibleEnvironment: { image: `ghcr.io/vrubovoy/hof-ops-ee@${EE_DIGEST}` },
    ...overrides,
  };
}

function scenariosFixture() {
  return [
    { name: "debian12 source -> ubuntu2404 restore", source: "debian12", target: "ubuntu2404", result: "succeeded" },
    { name: "ubuntu2404 source -> debian12 restore", source: "ubuntu2404", target: "debian12", result: "succeeded" },
  ];
}

function evidenceFixture(releaseLockBytes, overrides = {}) {
  return {
    ...buildAcceptanceEvidence({
      candidate: "v0.3.0-rc.7",
      commit: "a".repeat(40),
      releaseLockBytes,
      executionEnvironmentDigest: EE_DIGEST,
      scenarios: scenariosFixture(),
      acceptanceRunUrl: "https://github.com/vrubovoy/hof-ops/actions/runs/123",
      recordedAt: "2026-09-09T00:00:00Z",
    }),
    ...overrides,
  };
}

test("acceptance-evidence-v1: accepts a well-formed, succeeded document", async () => {
  const validate = await evidenceValidator();
  const doc = evidenceFixture(Buffer.from("release-lock-bytes"));
  assert.ok(validate(doc), JSON.stringify(validate.errors));
});

test("acceptance-evidence-v1: rejects a non-candidate tag, a bad digest, empty scenarios, and unknown properties", async () => {
  const validate = await evidenceValidator();
  const base = evidenceFixture(Buffer.from("x"));
  assert.equal(validate({ ...base, candidate: "v0.3.0" }), false, "plain vX.Y.Z is not a candidate tag");
  assert.equal(validate({ ...base, candidate: "v0.3.0-rc.0" }), false, "-rc.0 is not allowed");
  assert.equal(validate({ ...base, releaseLockDigest: "sha256:short" }), false);
  assert.equal(validate({ ...base, scenarios: [] }), false);
  assert.equal(validate({ ...base, extra: true }), false);
});

test("build-acceptance-evidence: derives result=failed when any scenario failed, succeeded only when all did", () => {
  const bytes = Buffer.from("lock");
  const allGreen = buildAcceptanceEvidence({
    candidate: "v1.2.3-rc.1", commit: "b".repeat(40), releaseLockBytes: bytes,
    executionEnvironmentDigest: EE_DIGEST, scenarios: scenariosFixture(),
    acceptanceRunUrl: "https://github.com/x/y/actions/runs/1", recordedAt: "2026-09-09T00:00:00Z",
  });
  assert.equal(allGreen.result, "succeeded");
  assert.equal(allGreen.release, "1.2.3");
  assert.equal(allGreen.releaseLockDigest, "sha256:" + createHash("sha256").update(bytes).digest("hex"));

  const oneRed = buildAcceptanceEvidence({
    candidate: "v1.2.3-rc.1", commit: "b".repeat(40), releaseLockBytes: bytes,
    executionEnvironmentDigest: EE_DIGEST,
    scenarios: [{ name: "n", source: "debian12", target: "ubuntu2404", result: "failed" }],
    acceptanceRunUrl: "https://github.com/x/y/actions/runs/1", recordedAt: "2026-09-09T00:00:00Z",
  });
  assert.equal(oneRed.result, "failed");
});

test("build-acceptance-evidence: rejects a non-candidate --candidate outright", () => {
  assert.throws(() => buildAcceptanceEvidence({
    candidate: "v1.2.3", commit: "b".repeat(40), releaseLockBytes: Buffer.from("l"),
    executionEnvironmentDigest: EE_DIGEST, scenarios: scenariosFixture(),
    acceptanceRunUrl: "https://github.com/x/y/actions/runs/1",
  }), /immutable candidate tag/);
});

test("executionEnvironmentDigestOf: pulls the digest out of the lock, throws without one", () => {
  assert.equal(executionEnvironmentDigestOf(releaseLockFixture()), EE_DIGEST);
  assert.throws(() => executionEnvironmentDigestOf({ ansibleEnvironment: { image: "ghcr.io/x/y:tag" } }), /no ansibleEnvironment\.image digest/);
});

test("verify-promotion: promotes a candidate whose evidence binds to the exact downloaded lock", async () => {
  const releaseLockBytes = Buffer.from(JSON.stringify(releaseLockFixture()));
  const result = verifyPromotion({
    candidate: "v0.3.0-rc.7",
    releaseLockBytes,
    releaseLock: JSON.parse(releaseLockBytes),
    evidence: evidenceFixture(releaseLockBytes),
    evidenceSchema: await evidenceSchema(),
    commit: "a".repeat(40),
  });
  assert.deepEqual(result, { ok: true, errors: [], release: "0.3.0" });
});

test("verify-promotion: refuses a tampered release-lock (digest no longer matches acceptance)", async () => {
  const acceptedBytes = Buffer.from(JSON.stringify(releaseLockFixture()));
  const tamperedBytes = Buffer.from(JSON.stringify(releaseLockFixture({ release: "0.3.0", extra: "smuggled" })));
  const { ok, errors } = verifyPromotion({
    candidate: "v0.3.0-rc.7",
    releaseLockBytes: tamperedBytes,
    releaseLock: JSON.parse(tamperedBytes),
    evidence: evidenceFixture(acceptedBytes),
    evidenceSchema: await evidenceSchema(),
  });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => /release-lock digest .* does not match/.test(e)), errors.join("; "));
});

test("verify-promotion: refuses failed evidence, a mismatched candidate, a mismatched commit, and an EE digest that disagrees with the lock", async () => {
  const releaseLockBytes = Buffer.from(JSON.stringify(releaseLockFixture()));
  const schema = await evidenceSchema();
  const common = { candidate: "v0.3.0-rc.7", releaseLockBytes, releaseLock: JSON.parse(releaseLockBytes), evidenceSchema: schema };

  assert.equal(verifyPromotion({ ...common, evidence: evidenceFixture(releaseLockBytes, { result: "failed" }) }).ok, false);
  assert.equal(verifyPromotion({ ...common, evidence: evidenceFixture(releaseLockBytes, { candidate: "v0.3.0-rc.6" }) }).ok, false);
  assert.equal(verifyPromotion({ ...common, commit: "c".repeat(40), evidence: evidenceFixture(releaseLockBytes) }).ok, false);

  const wrongEe = verifyPromotion({ ...common, evidence: evidenceFixture(releaseLockBytes, { executionEnvironmentDigest: "sha256:" + "e".repeat(64) }) });
  assert.equal(wrongEe.ok, false);
  assert.ok(wrongEe.errors.some((e) => /EE digest/.test(e)), wrongEe.errors.join("; "));
});

test("verify-promotion: refuses when the lock's own release disagrees with the candidate tag", async () => {
  const releaseLockBytes = Buffer.from(JSON.stringify(releaseLockFixture({ release: "9.9.9" })));
  const { ok, errors } = verifyPromotion({
    candidate: "v0.3.0-rc.7",
    releaseLockBytes,
    releaseLock: JSON.parse(releaseLockBytes),
    evidence: evidenceFixture(releaseLockBytes),
    evidenceSchema: await evidenceSchema(),
  });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => /release 9\.9\.9 does not match/.test(e)), errors.join("; "));
});
