// Contract coverage for Item 10 PR 0's stable-promotion gate: the
// acceptance-evidence-v1 schema, scripts/build-acceptance-evidence.mjs's
// assembly/derivation, and scripts/verify-promotion.mjs's accept/refuse
// decision - including the provenance, digest-binding, and full-matrix
// checks the first findings-first review required. No workflow runs
// here; the parts that need cosign / git / the GitHub API live in
// promote.yml (same reasoning as test/release-lock-contracts.test.mjs).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { buildAcceptanceEvidence, executionEnvironmentDigestOf, REQUIRED_SCENARIO_IDS } from "../scripts/build-acceptance-evidence.mjs";
import { verifyPromotion } from "../scripts/verify-promotion.mjs";

const root = path.resolve(import.meta.dirname, "..");
const EE_DIGEST = "sha256:" + "b".repeat(64);
const COMMIT = "a".repeat(40);
const CANDIDATE = "v0.3.0-rc.7";
const RUN_ID = "48273910";
const RUN_URL = "https://github.com/vrubovoy/hof-ops/actions/runs/48273910";

async function readJson(rel) {
  return JSON.parse(await readFile(path.join(root, rel), "utf8"));
}

async function evidenceSchema() {
  return readJson("schemas/acceptance-evidence-v1.schema.json");
}

async function releaseLockSchema() {
  return readJson("schemas/release-lock-v1.schema.json");
}

async function trustedCatalog() {
  const { default: YAML } = await import("yaml");
  return YAML.parse(await readFile(path.join(root, "catalog/services-v1.yaml"), "utf8"));
}

async function evidenceValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(await evidenceSchema());
}

// A real, schema-valid release lock (examples/release-lock.json) with
// just the fields promotion inspects moved onto the fixture's values.
async function releaseLockFixture(overrides = {}) {
  const lock = await readJson("examples/release-lock.json");
  lock.release = "0.3.0";
  lock.ansibleEnvironment.image = `ghcr.io/vrubovoy/hof-ops-ee@${EE_DIGEST}`;
  return { ...lock, ...overrides };
}

function greenScenarios() {
  return REQUIRED_SCENARIO_IDS.map((scenarioId) => ({
    scenarioId,
    destinations: { local: { result: "succeeded" }, s3: { result: "succeeded" } },
    result: "succeeded",
  }));
}

function evidenceFor(releaseLockBytes, overrides = {}) {
  const base = buildAcceptanceEvidence({
    candidate: CANDIDATE,
    commit: COMMIT,
    releaseLockBytes,
    executionEnvironmentDigest: EE_DIGEST,
    scenarios: greenScenarios(),
    acceptanceRunId: RUN_ID,
    acceptanceRunAttempt: 1,
    acceptanceCommit: COMMIT,
    acceptanceRunUrl: RUN_URL,
    recordedAt: "2026-09-09T00:00:00Z",
  });
  return { ...base, ...overrides };
}

function runFixture(overrides = {}) {
  return {
    id: RUN_ID,
    path: ".github/workflows/acceptance.yml",
    headBranch: "main",
    headSha: COMMIT,
    status: "completed",
    conclusion: "success",
    runAttempt: 1,
    htmlUrl: RUN_URL,
    ...overrides,
  };
}

async function promotionArgs(overrides = {}) {
  const lock = await releaseLockFixture();
  const releaseLockBytes = Buffer.from(JSON.stringify(lock));
  return {
    candidate: CANDIDATE,
    releaseLockBytes,
    releaseLock: lock,
    releaseLockSchema: await releaseLockSchema(),
    evidence: evidenceFor(releaseLockBytes),
    evidenceSchema: await evidenceSchema(),
    commit: COMMIT,
    run: runFixture(),
    expectedRunId: RUN_ID,
    catalog: await trustedCatalog(),
    expectedCatalogDigest: lock.catalogDigest,
    expectedComposeTemplateDigest: lock.composeTemplateDigest,
    ...overrides,
  };
}

// --- schema -----------------------------------------------------------

test("acceptance-evidence-v1: accepts a well-formed, succeeded document", async () => {
  const validate = await evidenceValidator();
  const doc = evidenceFor(Buffer.from("release-lock-bytes"));
  assert.ok(validate(doc), JSON.stringify(validate.errors));
});

test("acceptance-evidence-v1: rejects malformed candidate, digest, run id, workflow path/ref, and unknown properties", async () => {
  const validate = await evidenceValidator();
  const base = evidenceFor(Buffer.from("x"));
  assert.equal(validate({ ...base, candidate: "v0.3.0" }), false);
  assert.equal(validate({ ...base, candidate: "v0.3.0-rc.0" }), false);
  assert.equal(validate({ ...base, releaseLockDigest: "sha256:short" }), false);
  assert.equal(validate({ ...base, acceptanceRunId: "0" }), false);
  assert.equal(validate({ ...base, acceptanceWorkflowPath: ".github/workflows/other.yml" }), false);
  assert.equal(validate({ ...base, acceptanceWorkflowRef: "refs/heads/feature" }), false);
  assert.equal(validate({ ...base, extra: true }), false);
});

test("acceptance-evidence-v1: requires exactly the two restore legs, each with both destinations", async () => {
  const validate = await evidenceValidator();
  const base = evidenceFor(Buffer.from("x"));
  assert.equal(validate({ ...base, scenarios: [base.scenarios[0]] }), false, "one leg is not enough");
  assert.equal(validate({ ...base, scenarios: [...base.scenarios, base.scenarios[0]] }), false, "three legs is too many");
  const noS3 = structuredClone(base);
  delete noS3.scenarios[0].destinations.s3;
  assert.equal(validate(noS3), false, "a leg must record both local and s3");
});

// --- build-acceptance-evidence --------------------------------------

test("build-acceptance-evidence: derives leg result from destinations and overall from legs", () => {
  const bytes = Buffer.from("lock");
  const oneS3Red = buildAcceptanceEvidence({
    candidate: CANDIDATE, commit: COMMIT, releaseLockBytes: bytes, executionEnvironmentDigest: EE_DIGEST,
    scenarios: [
      { scenarioId: "debian12-to-ubuntu2404", destinations: { local: { result: "succeeded" }, s3: { result: "failed" } }, result: "failed" },
      { scenarioId: "ubuntu2404-to-debian12", destinations: { local: { result: "succeeded" }, s3: { result: "succeeded" } }, result: "succeeded" },
    ],
    acceptanceRunId: RUN_ID, acceptanceRunAttempt: 1, acceptanceCommit: COMMIT, acceptanceRunUrl: RUN_URL,
    recordedAt: "2026-09-09T00:00:00Z",
  });
  assert.equal(oneS3Red.result, "failed");
  assert.equal(oneS3Red.release, "0.3.0");
  assert.equal(oneS3Red.releaseLockDigest, "sha256:" + createHash("sha256").update(bytes).digest("hex"));
});

test("build-acceptance-evidence: rejects a missing leg, a duplicate leg, and a non-candidate tag", () => {
  const bytes = Buffer.from("l");
  const common = {
    commit: COMMIT, releaseLockBytes: bytes, executionEnvironmentDigest: EE_DIGEST,
    acceptanceRunId: RUN_ID, acceptanceRunAttempt: 1, acceptanceCommit: COMMIT, acceptanceRunUrl: RUN_URL,
  };
  assert.throws(() => buildAcceptanceEvidence({ ...common, candidate: CANDIDATE, scenarios: [greenScenarios()[0]] }), /missing required restore leg/);
  const [leg0, leg1] = greenScenarios();
  assert.throws(() => buildAcceptanceEvidence({ ...common, candidate: CANDIDATE, scenarios: [leg0, leg1, leg0] }), /duplicate scenarioId/);
  assert.throws(() => buildAcceptanceEvidence({ ...common, candidate: "v1.2.3", scenarios: greenScenarios() }), /immutable candidate tag/);
});

test("executionEnvironmentDigestOf: pulls the digest out of the lock, throws without one", () => {
  assert.equal(executionEnvironmentDigestOf({ ansibleEnvironment: { image: `ghcr.io/x/y@${EE_DIGEST}` } }), EE_DIGEST);
  assert.throws(() => executionEnvironmentDigestOf({ ansibleEnvironment: { image: "ghcr.io/x/y:tag" } }), /no ansibleEnvironment\.image digest/);
});

// --- verify-promotion: happy path ---------------------------------

test("verify-promotion: promotes when evidence, signature-provenance inputs, digests, and the full matrix all bind", async () => {
  const result = verifyPromotion(await promotionArgs());
  assert.deepEqual(result, { ok: true, errors: [], release: "0.3.0" });
});

// --- verify-promotion: refusals ---------------------------------

test("verify-promotion: refuses a tampered release-lock (digest no longer matches acceptance)", async () => {
  const args = await promotionArgs();
  const tampered = { ...args.releaseLock, smuggled: "x" };
  const { ok, errors } = verifyPromotion({
    ...args,
    releaseLock: tampered,
    releaseLockBytes: Buffer.from(JSON.stringify(tampered)),
  });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => /release-lock digest .* does not match/.test(e)), errors.join("; "));
});

test("verify-promotion: refuses catalog / renderer digests that disagree with main", async () => {
  for (const field of ["expectedCatalogDigest", "expectedComposeTemplateDigest"]) {
    const { ok, errors } = verifyPromotion(await promotionArgs({ [field]: "sha256:" + "f".repeat(64) }));
    assert.equal(ok, false, field);
    assert.ok(errors.some((e) => /does not match main's (catalog|renderer)/.test(e)), errors.join("; "));
  }
});

test("verify-promotion: refuses a schema-invalid release lock (checked with main's own schema)", async () => {
  const args = await promotionArgs();
  const broken = { ...args.releaseLock };
  delete broken.catalogDigest;
  const { ok, errors } = verifyPromotion({ ...args, releaseLock: broken, releaseLockBytes: Buffer.from(JSON.stringify(broken)), evidence: evidenceFor(Buffer.from(JSON.stringify(broken))) });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => /not schema-valid against main's/.test(e)), errors.join("; "));
});

test("verify-promotion: refuses a schema-valid lock that dropped an optional catalog component (full cross-contract check with main's catalog)", async () => {
  const args = await promotionArgs();
  // A real optional artifact - present in the catalog, quietly removed
  // from the lock. catalogDigest is untouched, so the digest check above
  // passes; only the cross-contract check catches this.
  const dropped = "herold-backend";
  assert.ok(args.releaseLock.components[dropped], "fixture assumption: the example lock carries this optional component");
  const lock = structuredClone(args.releaseLock);
  delete lock.components[dropped];
  const bytes = Buffer.from(JSON.stringify(lock));
  const { ok, errors } = verifyPromotion({ ...args, releaseLock: lock, releaseLockBytes: bytes, evidence: evidenceFor(bytes) });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => new RegExp(`missing catalog artifact ${dropped}`).test(e)), errors.join("; "));
});

test("verify-promotion: refuses a lock carrying a component the catalog does not define", async () => {
  const args = await promotionArgs();
  const lock = structuredClone(args.releaseLock);
  lock.components["ghost-backend"] = structuredClone(lock.components["herold-backend"]);
  const bytes = Buffer.from(JSON.stringify(lock));
  const { ok, errors } = verifyPromotion({ ...args, releaseLock: lock, releaseLockBytes: bytes, evidence: evidenceFor(bytes) });
  assert.equal(ok, false);
  assert.ok(errors.some((e) => /unknown catalog artifact ghost-backend/.test(e)), errors.join("; "));
});

test("verify-promotion: refuses failed evidence, wrong candidate, wrong release, EE-digest / lock-release mismatch", async () => {
  const cases = [
    ["result", { result: "failed" }],
    ["candidate", { candidate: "v0.3.0-rc.6" }],
    ["release", { release: "0.9.9" }],
    ["executionEnvironmentDigest", { executionEnvironmentDigest: "sha256:" + "e".repeat(64) }],
  ];
  for (const [label, overrides] of cases) {
    const args = await promotionArgs();
    const { ok } = verifyPromotion({ ...args, evidence: { ...args.evidence, ...overrides } });
    assert.equal(ok, false, label);
  }
  // lock's own release disagreeing with the candidate tag
  const args = await promotionArgs();
  const lock = { ...args.releaseLock, release: "9.9.9" };
  assert.equal(verifyPromotion({ ...args, releaseLock: lock, releaseLockBytes: Buffer.from(JSON.stringify(lock)), evidence: evidenceFor(Buffer.from(JSON.stringify(lock))) }).ok, false);
});

test("verify-promotion: refuses a commit that is not the candidate commit, both for `commit` and acceptanceCommit", async () => {
  const other = "c".repeat(40);
  assert.equal(verifyPromotion(await promotionArgs({ commit: other })).ok, false, "commit arg mismatch");
  const args = await promotionArgs();
  assert.equal(verifyPromotion({ ...args, evidence: { ...args.evidence, acceptanceCommit: other } }).ok, false, "acceptanceCommit mismatch");
});

test("verify-promotion: refuses every kind of run-provenance disagreement", async () => {
  const runMutations = [
    ["path", { path: ".github/workflows/test.yml" }],
    ["headBranch", { headBranch: "feature" }],
    ["headSha", { headSha: "d".repeat(40) }],
    ["status", { status: "in_progress" }],
    ["conclusion", { conclusion: "failure" }],
    ["runAttempt", { runAttempt: 2 }],
    ["id", { id: "99999999" }],
    ["htmlUrl", { htmlUrl: "https://github.com/vrubovoy/hof-ops/actions/runs/1" }],
  ];
  for (const [label, overrides] of runMutations) {
    const { ok } = verifyPromotion(await promotionArgs({ run: runFixture(overrides) }));
    assert.equal(ok, false, label);
  }
  // no live run metadata at all
  assert.equal(verifyPromotion(await promotionArgs({ run: undefined })).ok, false, "missing run");
  // evidence run id disagreeing with the id promotion was asked to use
  const args = await promotionArgs();
  assert.equal(verifyPromotion({ ...args, expectedRunId: "11112222" }).ok, false, "expectedRunId mismatch");
});

test("verify-promotion: refuses an incomplete or padded restore matrix", async () => {
  // one leg only - the schema's minItems:2 already refuses this
  {
    const args = await promotionArgs();
    const evidence = { ...args.evidence, scenarios: [args.evidence.scenarios[0]] };
    const { ok, errors } = verifyPromotion({ ...args, evidence });
    assert.equal(ok, false);
    assert.ok(errors.some((e) => /schema-valid|missing required restore leg/.test(e)), errors.join("; "));
  }
  // two legs, but the same scenarioId twice - schema-valid (exactly two
  // items, both in the enum), caught by verify-promotion's own logic
  {
    const args = await promotionArgs();
    const evidence = { ...args.evidence, scenarios: [args.evidence.scenarios[0], structuredClone(args.evidence.scenarios[0])] };
    const { ok, errors } = verifyPromotion({ ...args, evidence });
    assert.equal(ok, false);
    assert.ok(errors.some((e) => /duplicate scenarioId/.test(e)), errors.join("; "));
  }
  // a destination failed inside a leg
  {
    const args = await promotionArgs();
    const evidence = structuredClone(args.evidence);
    evidence.scenarios[1].destinations.s3.result = "failed";
    const { ok, errors } = verifyPromotion({ ...args, evidence });
    assert.equal(ok, false);
    assert.ok(errors.some((e) => /destination s3 is failed/.test(e)), errors.join("; "));
  }
});
