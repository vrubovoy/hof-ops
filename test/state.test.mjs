import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { loadContracts } from "../scripts/contracts.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { emptyBaseline, loadState, resolveBaseline, topologyToServiceState } from "../scripts/state.mjs";

const root = path.resolve(import.meta.dirname, "..");

test("a real current.json record satisfies schemas/state-v1.schema.json", async () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const { readFile } = await import("node:fs/promises");
  const validate = ajv.compile(JSON.parse(await readFile(path.join(root, "schemas/state-v1.schema.json"), "utf8")));

  const record = {
    apiVersion: "hof.dev/state/v1",
    installationId: "3b1f6c2e-6e35-4f7a-9c3b-000000000000",
    generation: 1,
    lastSuccessfulOperationId: "operation-1",
    appliedAt: "2026-08-27T10:00:00Z",
    release: "0.1.1",
    manifestDigest: "sha256:" + "1".repeat(64),
    releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64),
    composeTemplateDigest: "sha256:" + "4".repeat(64),
    topologyDigest: "sha256:" + "5".repeat(64),
    generatedArtifacts: { "compose.yml": "sha256:" + "6".repeat(64), "Caddyfile": "sha256:" + "7".repeat(64) },
  };
  assert.ok(validate(record), JSON.stringify(validate.errors));
});

test("emptyBaseline is the synthetic bootstrap baseline", () => {
  assert.deepEqual(emptyBaseline(), { mode: "bootstrap", generation: 0, release: null, services: {}, volumes: [] });
});

test("topologyToServiceState reads Hof's own ownership labels, not artifact-name guessing", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const state = topologyToServiceState(rendered, contracts.catalog);

  assert.equal(state.release, rendered.topology.release);
  assert.equal(state.services.kuvert.enabled, true);
  assert.equal(state.services.kuvert.artifacts["kuvert-backend"].image, rendered.compose.services["kuvert-backend"].image);
  // Wächter's two containers (wachter, wachter-agent) share one catalog
  // artifact (wachter-backend) - both must resolve to the same service.
  assert.equal(state.services.wachter.enabled, true);
  assert.deepEqual(Object.keys(state.services.wachter.artifacts), ["wachter-backend"]);
  // Persistent services carry a schemaVersion, others don't have the key at all.
  assert.equal(typeof state.services.kuvert.schemaVersion, "number");
  assert.equal("schemaVersion" in state.services.schloss, false);
});

test("topologyToServiceState marks a disabled service as present but empty", async () => {
  const contracts = await loadContracts();
  contracts.manifest.services.schrank.enabled = false;
  const rendered = renderTopology(contracts);
  const state = topologyToServiceState(rendered, contracts.catalog);
  assert.deepEqual(state.services.schrank, { enabled: false, artifacts: {}, schemaVersion: null });
});

test("loadState returns null when there is no state directory at all", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-state-"));
  assert.equal(await loadState(directory), null);
});

test("loadState throws when current.json exists but topology.json is missing (corrupt state)", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-state-"));
  await writeFile(path.join(directory, "current.json"), JSON.stringify({ generation: 1 }));
  await assert.rejects(() => loadState(directory), /topology\.json is missing/);
});

test("resolveBaseline: clean host with no state and no Docker resources bootstraps", async () => {
  const contracts = await loadContracts();
  const directory = await mkdtemp(path.join(tmpdir(), "hof-state-"));
  const baseline = await resolveBaseline({ statePath: directory, catalog: contracts.catalog, hasManagedResources: false });
  assert.deepEqual(baseline, emptyBaseline());
});

test("resolveBaseline: fails closed when state is missing but Docker already has managed resources", async () => {
  const contracts = await loadContracts();
  const directory = await mkdtemp(path.join(tmpdir(), "hof-state-"));
  await assert.rejects(
    () => resolveBaseline({ statePath: directory, catalog: contracts.catalog, hasManagedResources: true }),
    /managed resources exist but the authoritative state is missing/,
  );
});

test("resolveBaseline: loads a real saved generation and shapes it through topologyToServiceState", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const directory = await mkdtemp(path.join(tmpdir(), "hof-state-"));
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, "current.json"), JSON.stringify({ generation: 3, release: rendered.topology.release }));
  await writeFile(path.join(directory, "topology.json"), JSON.stringify(rendered));

  const baseline = await resolveBaseline({ statePath: directory, catalog: contracts.catalog, hasManagedResources: false });
  assert.equal(baseline.mode, "applied");
  assert.equal(baseline.generation, 3);
  assert.deepEqual(baseline.services, topologyToServiceState(rendered, contracts.catalog).services);
});
