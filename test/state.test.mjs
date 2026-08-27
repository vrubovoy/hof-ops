import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { loadContracts } from "../scripts/contracts.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { emptyBaseline, resolveBaseline, topologyToServiceState } from "../scripts/state.mjs";

const root = path.resolve(import.meta.dirname, "..");
const available = { status: "available", resources: [] };

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
  assert.deepEqual(emptyBaseline(), {
    mode: "bootstrap", generation: 0, release: null,
    manifestDigest: null, releaseLockDigest: null, topologyDigest: null,
    services: {}, volumes: [],
  });
});

test("topologyToServiceState reads Hof's own ownership labels, keyed by unit, not by artifact", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const state = topologyToServiceState(rendered, contracts.catalog, { manifest: contracts.manifest, releaseLock: contracts.releaseLock });

  assert.equal(state.release, rendered.topology.release);
  assert.match(state.manifestDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(state.releaseLockDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(state.topologyDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(state.services.kuvert.enabled, true);
  assert.equal(state.services.kuvert.units["kuvert-backend"].image, rendered.compose.services["kuvert-backend"].image);
  assert.equal(state.services.kuvert.units["kuvert-backend"].artifact, "kuvert-backend");
  // Wächter's two containers (wachter, wachter-agent) share one catalog
  // artifact (wachter-backend) but must be two distinct units, or the
  // agent silently disappears from state entirely.
  assert.equal(state.services.wachter.enabled, true);
  assert.deepEqual(Object.keys(state.services.wachter.units).sort(), ["wachter", "wachter-agent"]);
  assert.equal(state.services.wachter.units.wachter.artifact, "wachter-backend");
  assert.equal(state.services.wachter.units["wachter-agent"].artifact, "wachter-backend");
  // Persistent services carry a schemaVersion, others don't have the key at all.
  assert.equal(typeof state.services.kuvert.schemaVersion, "number");
  assert.equal("schemaVersion" in state.services.schloss, false);
});

test("topologyToServiceState's manifest/releaseLock digests are optional - null when not supplied", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const state = topologyToServiceState(rendered, contracts.catalog);
  assert.equal(state.manifestDigest, null);
  assert.equal(state.releaseLockDigest, null);
  assert.match(state.topologyDigest, /^sha256:[0-9a-f]{64}$/);
});

test("a unit's configFingerprint changes when its rendered environment changes, even with the same image", async () => {
  const contracts = await loadContracts();
  const before = topologyToServiceState(renderTopology(contracts), contracts.catalog);

  const changed = structuredClone(contracts);
  changed.manifest.domains.base = "changed.example.com";
  const after = topologyToServiceState(renderTopology(changed), changed.catalog);

  assert.equal(before.services.kuvert.units["kuvert-backend"].image, after.services.kuvert.units["kuvert-backend"].image);
  assert.notEqual(before.services.kuvert.units["kuvert-backend"].configFingerprint, after.services.kuvert.units["kuvert-backend"].configFingerprint);
  assert.notEqual(before.topologyDigest, after.topologyDigest);
});

test("the gateway unit's configFingerprint changes when only the Caddyfile content changes", async () => {
  const contracts = await loadContracts();
  const before = topologyToServiceState(renderTopology(contracts), contracts.catalog);

  const changed = structuredClone(contracts);
  changed.manifest.tls.email = "changed@example.com";
  const after = topologyToServiceState(renderTopology(changed), changed.catalog);

  assert.equal(before.services.tor.units.gateway.image, after.services.tor.units.gateway.image);
  assert.notEqual(before.services.tor.units.gateway.configFingerprint, after.services.tor.units.gateway.configFingerprint);
});

test("topologyToServiceState marks a disabled service as present but empty", async () => {
  const contracts = await loadContracts();
  contracts.manifest.services.schrank.enabled = false;
  const rendered = renderTopology(contracts);
  const state = topologyToServiceState(rendered, contracts.catalog);
  assert.deepEqual(state.services.schrank, { enabled: false, units: {}, schemaVersion: null });
});

test("resolveBaseline throws when current.json is present but topology.json is missing (corrupt state)", async () => {
  const contracts = await loadContracts();
  const managedState = { current: { generation: 1 }, topology: null };
  assert.throws(
    () => resolveBaseline({ managedState, catalog: contracts.catalog, observation: available }),
    /current\.json but no topology\.json/,
  );
});

test("resolveBaseline requires an explicit observation - never defaults to 'nothing is running'", async () => {
  const contracts = await loadContracts();
  assert.throws(() => resolveBaseline({ managedState: null, catalog: contracts.catalog }), /requires an explicit observation/);
});

test("resolveBaseline: clean host with no state and available, empty observation bootstraps", async () => {
  const contracts = await loadContracts();
  const baseline = resolveBaseline({ managedState: null, catalog: contracts.catalog, observation: available });
  assert.deepEqual(baseline, emptyBaseline());
});

test("resolveBaseline: fails closed when state is missing but the inspector couldn't reach the host at all", async () => {
  const contracts = await loadContracts();
  assert.throws(
    () => resolveBaseline({ managedState: null, catalog: contracts.catalog, observation: { status: "unavailable", resources: [] } }),
    /observation is unavailable, refusing to assume a clean bootstrap/,
  );
});

test("resolveBaseline: fails closed when state is missing but Docker already has managed resources", async () => {
  const contracts = await loadContracts();
  const observation = { status: "available", resources: [{ service: "kuvert", unit: "kuvert-backend", managed: true, image: "x", state: "running" }] };
  assert.throws(
    () => resolveBaseline({ managedState: null, catalog: contracts.catalog, observation }),
    /managed resources exist but the authoritative state is missing/,
  );
});

test("resolveBaseline: loads a real saved generation and carries through its recorded digests", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const expected = topologyToServiceState(rendered, contracts.catalog);
  const managedState = {
    current: {
      generation: 3, release: rendered.topology.release,
      manifestDigest: "sha256:" + "a".repeat(64), releaseLockDigest: "sha256:" + "b".repeat(64),
      topologyDigest: expected.topologyDigest,
    },
    topology: rendered,
  };

  const baseline = resolveBaseline({ managedState, catalog: contracts.catalog, observation: available });
  assert.equal(baseline.mode, "applied");
  assert.equal(baseline.generation, 3);
  assert.equal(baseline.manifestDigest, "sha256:" + "a".repeat(64));
  assert.equal(baseline.releaseLockDigest, "sha256:" + "b".repeat(64));
  assert.equal(baseline.topologyDigest, expected.topologyDigest);
  assert.deepEqual(baseline.services, expected.services);
});

test("resolveBaseline: refuses managed state whose recorded topologyDigest doesn't match its own saved topology.json", async () => {
  const contracts = await loadContracts();
  const rendered = renderTopology(contracts);
  const managedState = { current: { generation: 1, topologyDigest: "sha256:" + "0".repeat(64) }, topology: rendered };

  assert.throws(
    () => resolveBaseline({ managedState, catalog: contracts.catalog, observation: available }),
    /does not match a fresh digest of its own saved topology\.json/,
  );
});
