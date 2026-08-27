import assert from "node:assert/strict";
import test from "node:test";

import { verifyExecutionEnvironmentSignature } from "../scripts/execution-environment.mjs";

const ANSIBLE_ENVIRONMENT = {
  source: "https://github.com/vrubovoy/hof-ops",
  revision: "a".repeat(40),
  sourceTag: "ee-v0.1.0",
  image: "ghcr.io/vrubovoy/hof-ops-ee@sha256:" + "b".repeat(64),
  signatureIdentity: "https://github.com/vrubovoy/hof-ops/.github/workflows/execution-environment.yml@refs/tags/ee-v0.1.0",
  signatureOidcIssuer: "https://token.actions.githubusercontent.com",
  provenanceDigest: "sha256:" + "c".repeat(64),
  sbomDigest: "sha256:" + "d".repeat(64),
};

test("verifies with exactly the real cosign verify argv shape, in order", async () => {
  const calls = [];
  await verifyExecutionEnvironmentSignature(ANSIBLE_ENVIRONMENT, { run: async (args) => { calls.push(args); } });
  assert.deepEqual(calls, [[
    "verify",
    "--certificate-identity", ANSIBLE_ENVIRONMENT.signatureIdentity,
    "--certificate-oidc-issuer", ANSIBLE_ENVIRONMENT.signatureOidcIssuer,
    ANSIBLE_ENVIRONMENT.image,
  ]]);
});

test("a real cosign failure is surfaced as a genuine verification error, never silently ignored", async () => {
  await assert.rejects(
    () => verifyExecutionEnvironmentSignature(ANSIBLE_ENVIRONMENT, { run: async () => { throw new Error("no matching signatures"); } }),
    /Execution Environment image .* failed Cosign signature verification: no matching signatures/,
  );
});

test("refuses to verify a release lock with no ansibleEnvironment at all", async () => {
  await assert.rejects(
    () => verifyExecutionEnvironmentSignature(undefined, { run: async () => {} }),
    /release lock has no ansibleEnvironment/,
  );
});
