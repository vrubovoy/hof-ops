// Verifies the pinned Ansible Execution Environment image's own real
// Cosign signature before hofctl apply ever runs it - "apply verifies
// the EE image's signature the same way hofctl validate verifies the
// release lock's, before ever running it" (ADR 0004). Deliberately its
// own tiny module, not folded into validate-deployment.mjs - that one
// verifies a *blob* (`cosign verify-blob` against the release-lock.json
// file itself); this verifies an OCI *image* (`cosign verify` against
// the digest-pinned image reference release-lock.json's own
// ansibleEnvironment.image already carries - see
// release-lock-v1.schema.json's `image` pattern, always `repo@sha256:...`).
//
// Deliberately does NOT also re-verify SBOM/provenance attestations
// here (unlike build-release-lock.mjs's own verifySupplyChain, which
// does, at release-build time) - that evidence was already gathered and
// baked into the release lock once, at build time; apply's own job is
// only to confirm the exact image bytes it's about to run are still the
// ones that signature covers, every single time it runs them.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

async function defaultRun(args) {
  await exec("cosign", args, { maxBuffer: 8 * 1024 * 1024 });
}

// ansibleEnvironment: release-lock-v1.schema.json's own `artifact` shape
// ({image, signatureIdentity, signatureOidcIssuer, ...}) - the exact
// object loadAndValidateDeployment() already parsed and schema-checked,
// never re-read from disk here. run is a testing seam (see
// execution-environment.test.mjs) - hofctl apply itself never passes it.
export async function verifyExecutionEnvironmentSignature(ansibleEnvironment, { run = defaultRun } = {}) {
  if (!ansibleEnvironment) {
    throw new Error("release lock has no ansibleEnvironment - cannot verify or run a pinned Execution Environment that was never declared");
  }
  const { image, signatureIdentity, signatureOidcIssuer } = ansibleEnvironment;
  try {
    await run(["verify", "--certificate-identity", signatureIdentity, "--certificate-oidc-issuer", signatureOidcIssuer, image]);
  } catch (error) {
    throw new Error(`Execution Environment image ${image} failed Cosign signature verification: ${error instanceof Error ? error.message : error}`);
  }
}
