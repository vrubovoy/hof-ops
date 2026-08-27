import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { validateDeployment } from "../scripts/validate-deployment.mjs";

const root = path.resolve(import.meta.dirname, "..");
const examplesServices = path.join(root, "examples/services.yml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");
const examplesCatalog = path.join(root, "catalog/services-v1.yaml");

// Every case here uses --skip-signature: cosign isn't installed in every
// environment these tests run in, and the signature check itself is
// exercised separately below purely through its file-presence/argument
// guard rails, which need no real cosign invocation at all.
function baseOptions(overrides = {}) {
  return {
    servicesPath: examplesServices,
    catalogPath: examplesCatalog,
    releaseLockPath: examplesReleaseLock,
    skipSignature: true,
    ...overrides,
  };
}

test("a genuinely valid deployment reports only the explicit signature skip", async () => {
  const errors = await validateDeployment(baseOptions());
  assert.deepEqual(errors, ["release lock signature check was explicitly skipped (--skip-signature) - do not apply with this flag set"]);
});

test("defaults catalogPath to hof-ops's own bundled catalog when not given", async () => {
  const errors = await validateDeployment(baseOptions({ catalogPath: undefined }));
  assert.deepEqual(errors, ["release lock signature check was explicitly skipped (--skip-signature) - do not apply with this flag set"]);
});

test("rejects a services.yml that fails schema/cross-contract validation", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-validate-"));
  try {
    const badServicesPath = path.join(directory, "services.yml");
    await writeFile(badServicesPath, "apiVersion: hof.dev/v1alpha1\nkind: Services\nrelease: \"1.0.0\"\nsecrets:\n  password: unsafe\n");
    const errors = await validateDeployment(baseOptions({ servicesPath: badServicesPath }));
    assert.ok(errors.some((error) => /services\.yml/.test(error)), errors.join("\n"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects a release lock whose catalogDigest no longer matches the actual catalog", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-validate-"));
  try {
    const { readFile } = await import("node:fs/promises");
    const lock = JSON.parse(await readFile(examplesReleaseLock, "utf8"));
    lock.catalogDigest = "sha256:" + "0".repeat(64);
    const lockPath = path.join(directory, "release-lock.json");
    await writeFile(lockPath, JSON.stringify(lock));
    const errors = await validateDeployment(baseOptions({ releaseLockPath: lockPath }));
    assert.ok(errors.some((error) => /catalogDigest .* does not match the actual catalog/.test(error)), errors.join("\n"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects a release lock whose composeTemplateDigest no longer matches render-topology.mjs", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-validate-"));
  try {
    const { readFile } = await import("node:fs/promises");
    const lock = JSON.parse(await readFile(examplesReleaseLock, "utf8"));
    lock.composeTemplateDigest = "sha256:" + "0".repeat(64);
    const lockPath = path.join(directory, "release-lock.json");
    await writeFile(lockPath, JSON.stringify(lock));
    const errors = await validateDeployment(baseOptions({ releaseLockPath: lockPath }));
    assert.ok(errors.some((error) => /composeTemplateDigest .* does not match this hofctl's own renderer/.test(error)), errors.join("\n"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects a release lock that requires a newer hofctl than this one", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-validate-"));
  try {
    const { readFile } = await import("node:fs/promises");
    const lock = JSON.parse(await readFile(examplesReleaseLock, "utf8"));
    lock.minimumHofctlVersion = "99.0.0";
    const lockPath = path.join(directory, "release-lock.json");
    await writeFile(lockPath, JSON.stringify(lock));
    const errors = await validateDeployment(baseOptions({ releaseLockPath: lockPath }));
    assert.ok(errors.some((error) => /requires hofctl >= 99\.0\.0/.test(error)), errors.join("\n"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fails closed when no signature sidecar files exist and --skip-signature is not passed", async () => {
  const errors = await validateDeployment(baseOptions({ skipSignature: false }));
  assert.ok(errors.some((error) => /no signature found/.test(error)), errors.join("\n"));
});

test("requires --release-lock-identity even when signature files are present", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-validate-"));
  try {
    const sigPath = path.join(directory, "release-lock.json.sig");
    const pemPath = path.join(directory, "release-lock.json.pem");
    await writeFile(sigPath, "not-a-real-signature");
    await writeFile(pemPath, "not-a-real-certificate");
    const errors = await validateDeployment(baseOptions({
      skipSignature: false,
      releaseLockSignature: sigPath,
      releaseLockCertificate: pemPath,
    }));
    assert.ok(errors.some((error) => /--release-lock-identity is required/.test(error)), errors.join("\n"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("surfaces a readable error when a required file is simply missing", async () => {
  const errors = await validateDeployment(baseOptions({ servicesPath: path.join(root, "does-not-exist.yml") }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /could not read services\.yml\/catalog\/release-lock/);
});
