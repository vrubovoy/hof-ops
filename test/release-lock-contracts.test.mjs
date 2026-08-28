// Schema-level coverage for release-lock-v1.schema.json's own
// ansibleEnvironment field - a 2026-08-28 review found
// build-release-lock.mjs always resolved every component's own git tag
// as plain vX.Y.Z, including the Ansible Execution Environment, whose
// real tag is ee-vX.Y.Z (see ansible/README.md's own "Versioning"
// section) - two different things sharing this SAME repository must
// never be able to collide on the same git tag. No real unit-test seam
// exists for resolveRevision()/resolveBuiltArtifact() themselves (they
// shell out to a real `gh api` with no injected runner - see
// PLATFORM-OPS-PLAN.md's own history: this module is exercised for
// real by .github/workflows/release.yml, not mocked), so this file
// covers the one thing that IS testable without a real GitHub API call:
// the schema itself now actually enforces the distinction the code
// fix depends on.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(import.meta.dirname, "..");

async function validatorFor(defName) {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  const schema = JSON.parse(await readFile(path.join(root, "schemas/release-lock-v1.schema.json"), "utf8"));
  ajv.addSchema(schema, schema.$id);
  return ajv.getSchema(`${schema.$id}#/$defs/${defName}`);
}

function artifactFixture(overrides = {}) {
  return {
    source: "https://github.com/vrubovoy/hof-ops",
    revision: "1".repeat(40),
    sourceTag: "v1.0.0",
    image: "ghcr.io/vrubovoy/hof-ops-ee@sha256:" + "b".repeat(64),
    signatureIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/test.yml@refs/tags/v1.0.0",
    signatureOidcIssuer: "https://token.actions.githubusercontent.com",
    provenanceDigest: "sha256:" + "c".repeat(64),
    sbomDigest: "sha256:" + "d".repeat(64),
    ...overrides,
  };
}

test("ansibleEnvironmentArtifact: accepts the real ee-vX.Y.Z sourceTag the Execution Environment actually uses", async () => {
  const validate = await validatorFor("ansibleEnvironmentArtifact");
  assert.ok(validate(artifactFixture({ sourceTag: "ee-v1.0.0" })), JSON.stringify(validate.errors));
});

test("ansibleEnvironmentArtifact: rejects a plain vX.Y.Z sourceTag - the exact bug this schema change fixes (build-release-lock.mjs used to always resolve this one as plain v too)", async () => {
  const validate = await validatorFor("ansibleEnvironmentArtifact");
  assert.equal(validate(artifactFixture({ sourceTag: "v1.0.0" })), false);
});

test("ansibleEnvironmentArtifact: rejects an ee- prefix on the wrong side, or any other malformed variant", async () => {
  const validate = await validatorFor("ansibleEnvironmentArtifact");
  for (const sourceTag of ["1.0.0", "vee-1.0.0", "ee-1.0.0", "ee-vv1.0.0", "ee-v1.0"]) {
    assert.equal(validate(artifactFixture({ sourceTag })), false, `${sourceTag} must be rejected`);
  }
});

test("artifact (every ordinary component): still only ever accepts a plain vX.Y.Z sourceTag - never the Execution Environment's own ee- prefix", async () => {
  const validate = await validatorFor("artifact");
  assert.ok(validate(artifactFixture({ sourceTag: "v1.0.0" })), JSON.stringify(validate.errors));
  assert.equal(validate(artifactFixture({ sourceTag: "ee-v1.0.0" })), false);
});

test("examples/release-lock.json's own ansibleEnvironment block is itself schema-valid against ansibleEnvironmentArtifact", async () => {
  const validate = await validatorFor("ansibleEnvironmentArtifact");
  const releaseLock = JSON.parse(await readFile(path.join(root, "examples/release-lock.json"), "utf8"));
  assert.ok(validate(releaseLock.ansibleEnvironment), JSON.stringify(validate.errors));
  assert.equal(releaseLock.ansibleEnvironment.sourceTag, "ee-v1.0.0");
});
