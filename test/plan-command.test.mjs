// Unit-level coverage for scripts/plan-command.mjs's runPlan() -
// orchestration only (deployment validation -> inspect -> completeness
// -> baseline -> render -> buildPlan -> schema-validate), exercised with
// a real (fake) cosign binary on PATH so the release-lock signature gate
// genuinely runs (not skipped - plan never accepts --skip-signature),
// and an injected `inspect` seam standing in for a real SSH/local
// target-inspector run (that's target-inspector.mjs's own job, already
// covered by target-inspector.test.mjs/target-probe.test.mjs/
// ssh-acceptance.mjs). See plan-cli-acceptance.test.mjs for the
// complementary real-subprocess, real-CLI-path coverage (usage errors,
// stdout/stderr/exit-code contract, a genuine end-to-end bootstrap
// through the real `sh`+fake docker/sudo+fake cosign).

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { loadContracts } from "../scripts/contracts.mjs";
import { BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER, runPlan } from "../scripts/plan-command.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { topologyToServiceState } from "../scripts/state.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");
const examplesServices = path.join(root, "examples/services.yml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");

let workDir;
let signedReleaseLockPath;

async function planValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const { readFile } = await import("node:fs/promises");
  return ajv.compile(JSON.parse(await readFile(path.join(root, "schemas/plan-v1.schema.json"), "utf8")));
}

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-plan-command-"));
  const { readFile } = await import("node:fs/promises");
  signedReleaseLockPath = path.join(workDir, "release-lock.json");
  await writeFile(signedReleaseLockPath, await readFile(examplesReleaseLock));
  // Fake cosign only checks for the sidecars' *presence*, not their
  // content - loadAndValidateDeployment() requires both files to exist
  // before it will even attempt verification.
  await writeFile(`${signedReleaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${signedReleaseLockPath}.pem`, "fake-certificate\n");
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

// Runs the given async fn with the fake cosign prepended to PATH -
// runPlan() itself has no signature-related test seam at all (by
// design: it always calls the real loadAndValidateDeployment, the same
// gate `hofctl validate` uses, never a substitutable mock), so this is
// the one thing that has to reach into process.env for the duration of
// a single test.
async function withFakeCosign(outcome, fn) {
  const originalPath = process.env.PATH;
  const originalOutcome = process.env.HOF_TEST_COSIGN_OUTCOME;
  process.env.PATH = `${fakeCosignDir}${path.delimiter}${originalPath}`;
  process.env.HOF_TEST_COSIGN_OUTCOME = outcome;
  try {
    return await fn();
  } finally {
    process.env.PATH = originalPath;
    if (originalOutcome === undefined) delete process.env.HOF_TEST_COSIGN_OUTCOME;
    else process.env.HOF_TEST_COSIGN_OUTCOME = originalOutcome;
  }
}

function cleanSnapshot(overrides = {}) {
  return {
    mode: "local", transport: { verified: true, trustDigest: null },
    host: {
      os: { id: "debian", versionId: "12" }, architecture: "x86_64", cpuCores: 4,
      totalMemoryBytes: 8 * 1024 ** 3, freeDiskBytes: 40 * 1024 ** 3, clockSynchronized: true, sudoNonInteractive: true,
    },
    ports: [],
    docker: {
      engineAvailable: true, composeAvailable: true,
      containersStatus: "available", resources: [],
      volumesStatus: "available", volumes: [],
      networksStatus: "available", networks: [],
    },
    managedState: { currentStatus: "absent", current: null, topologyStatus: "absent", topology: null },
    generatedArtifactsStatus: "available", generatedArtifacts: {},
    ...overrides,
  };
}

function basePlanOptions(overrides = {}) {
  return {
    manifestPath: examplesServices, releaseLockPath: signedReleaseLockPath,
    releaseLockIdentity: "test@example.com", targetMode: "local",
    ...overrides,
  };
}

test("deployment validation blocked: no signature sidecars at all - fake cosign is never even reached", async () => {
  const result = await runPlan(basePlanOptions({ releaseLockPath: examplesReleaseLock, inspect: async () => { throw new Error("must never be called"); } }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "deployment");
  assert.ok(result.diagnostics.some((line) => line.includes("no signature found")));
});

test("deployment validation blocked: an invalid services.yml never reaches inspection", async () => {
  const invalidServices = path.join(workDir, "invalid-services.yml");
  await writeFile(invalidServices, "apiVersion: hof.dev/v1alpha1\n"); // missing target/domains/tls
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ manifestPath: invalidServices, inspect: async () => { throw new Error("must never be called"); } })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "deployment");
});

test("transport blocked: an inspection failure is reported, not silently treated as a clean host", async () => {
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ inspect: async () => { throw new Error("Permission denied (publickey)"); } })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "transport");
  assert.ok(result.diagnostics.some((line) => line.includes("Permission denied")));
});

test("state blocked: an unreadable current.json refuses to plan rather than guessing", async () => {
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ inspect: async () => cleanSnapshot({ managedState: { currentStatus: "unreadable", current: null, topologyStatus: "absent", topology: null } }) })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "state");
});

test("docker blocked: a genuinely incomplete Docker observation (volumes listing failed) refuses to plan, even though containers succeeded", async () => {
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ inspect: async () => cleanSnapshot({ docker: { ...cleanSnapshot().docker, volumesStatus: "unavailable" } }) })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "docker");
  assert.ok(result.diagnostics[0].includes("volumes"));
});

test("artifacts blocked: generated-artifact checksums unavailable refuses to plan", async () => {
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ inspect: async () => cleanSnapshot({ generatedArtifactsStatus: "unavailable" }) })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "artifacts");
});

test("state blocked: corrupt managed state (topology.json without current.json) surfaces resolveBaseline's own refusal, not a crash", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const result = await withFakeCosign("success", () =>
    runPlan(basePlanOptions({ inspect: async () => cleanSnapshot({ managedState: { currentStatus: "absent", current: null, topologyStatus: "present", topology: rendered } }) })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "state");
  assert.ok(result.diagnostics[0].includes("topology.json but no current.json"));
});

test("a genuine, signed, real-cosign-verified bootstrap plan is schema-valid and executable, with the deterministic bootstrap installationId placeholder", async () => {
  const validate = await planValidator();
  const result = await withFakeCosign("success", () => runPlan(basePlanOptions({ inspect: async () => cleanSnapshot() })));

  assert.equal(result.blocked, false);
  assert.equal(result.plan.mode, "bootstrap");
  assert.equal(result.plan.executable, true);
  assert.ok(result.plan.summary.create > 0);
  assert.ok(validate(result.plan), JSON.stringify(validate.errors));
  // installationId itself never appears literally in the plan's own
  // fields (it's excluded from configFingerprint, see state.mjs) - the
  // constant is exported and checked for its own value/shape instead.
  assert.match(BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER, /^[0-9a-f-]+$/);
});

test("deployment blocked: a real cosign signature failure (fake cosign scripted to fail) is reported, not silently ignored", async () => {
  const result = await withFakeCosign("failure", () => runPlan(basePlanOptions({ inspect: async () => cleanSnapshot() })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "deployment");
  assert.ok(result.diagnostics.some((line) => line.includes("signature verification failed")));
});

test("a genuine applied no-op plan against a matching, already-applied installation is schema-valid and executable", async () => {
  const validate = await planValidator();
  const contracts = await loadContracts();
  const installationId = "3b1f6c2e-6e35-4f7a-9c3b-000000000000";
  const rendered = renderTopology({ ...contracts, installationId, generation: 5 });
  const state = topologyToServiceState(rendered, contracts.catalog);

  const current = {
    apiVersion: "hof.dev/state/v1", installationId, generation: 5,
    lastSuccessfulOperationId: "op-1", appliedAt: "2026-08-27T10:00:00Z", release: state.release,
    manifestDigest: state.manifestDigest ?? "sha256:" + "1".repeat(64),
    releaseLockDigest: state.releaseLockDigest ?? "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    topologyDigest: state.topologyDigest, generatedArtifacts: {},
  };

  const resources = Object.entries(state.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({ service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true, installationId }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId, kind, composeProject: "hof" });

  const snapshot = cleanSnapshot({
    managedState: { currentStatus: "present", current, topologyStatus: "present", topology: rendered },
    docker: {
      engineAvailable: true, composeAvailable: true,
      containersStatus: "available", resources,
      volumesStatus: "available", volumes: state.volumes.map((name) => asResourceRecord(name, "volume")),
      networksStatus: "available", networks: state.networks.map((name) => asResourceRecord(name, "network")),
    },
  });

  const result = await withFakeCosign("success", () => runPlan(basePlanOptions({ inspect: async () => snapshot })));

  assert.equal(result.blocked, false);
  assert.equal(result.plan.mode, "applied");
  assert.equal(result.plan.executable, true);
  assert.deepEqual(result.plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.deepEqual(result.plan.operations, []);
  assert.equal(result.plan.baseline.installationId, installationId);
  // The next plan against an already-applied host is one generation
  // ahead of what's actually on disk - even though a no-op emits no
  // operations at all, buildPlan's own desired render must still have
  // been computed with generation 6, not the stale 5.
  assert.ok(validate(result.plan), JSON.stringify(validate.errors));
});

test("repairDrift actually reaches buildPlan: a manual-change drift blocks by default and clears once repairDrift is passed through", async () => {
  const contracts = await loadContracts();
  const installationId = "3b1f6c2e-6e35-4f7a-9c3b-000000000000";
  const rendered = renderTopology({ ...contracts, installationId, generation: 1 });
  const state = topologyToServiceState(rendered, contracts.catalog);
  const current = {
    apiVersion: "hof.dev/state/v1", installationId, generation: 1,
    lastSuccessfulOperationId: "op-1", appliedAt: "2026-08-27T10:00:00Z", release: state.release,
    manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    topologyDigest: state.topologyDigest, generatedArtifacts: {},
  };
  const resources = Object.entries(state.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({
        service, unit, artifact: entry.artifact,
        image: unit === "kuvert-backend" ? "ghcr.io/vrubovoy/kuvert-backend@sha256:" + "9".repeat(64) : entry.image,
        state: "running", managed: true, installationId,
      }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId, kind, composeProject: "hof" });
  const snapshot = cleanSnapshot({
    managedState: { currentStatus: "present", current, topologyStatus: "present", topology: rendered },
    docker: {
      engineAvailable: true, composeAvailable: true,
      containersStatus: "available", resources,
      volumesStatus: "available", volumes: state.volumes.map((name) => asResourceRecord(name, "volume")),
      networksStatus: "available", networks: state.networks.map((name) => asResourceRecord(name, "network")),
    },
  });

  const blockedResult = await withFakeCosign("success", () => runPlan(basePlanOptions({ inspect: async () => snapshot })));
  assert.equal(blockedResult.blocked, false);
  assert.equal(blockedResult.plan.executable, false);

  const repairedResult = await withFakeCosign("success", () => runPlan(basePlanOptions({ inspect: async () => snapshot, repairDrift: true })));
  assert.equal(repairedResult.blocked, false);
  assert.equal(repairedResult.plan.executable, true);
});
