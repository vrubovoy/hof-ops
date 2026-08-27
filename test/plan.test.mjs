import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { loadContracts } from "../scripts/contracts.mjs";
import { buildPlan } from "../scripts/plan.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { emptyBaseline, topologyToServiceState } from "../scripts/state.mjs";

const root = path.resolve(import.meta.dirname, "..");

async function planValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(JSON.parse(await readFile(path.join(root, "schemas/plan-v1.schema.json"), "utf8")));
}

async function fixture(overrides = (contracts) => contracts) {
  const contracts = structuredClone(await loadContracts());
  overrides(contracts);
  return { contracts, rendered: renderTopology(contracts) };
}

// Every artifact baseline expects, marked running with the exact image
// baseline recorded - the "nothing has drifted" observation a real
// Docker inspector would report on an untouched host.
function observedMatching(baseline) {
  return Object.entries(baseline.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.artifacts).map(([artifact, entry]) => ({ service, artifact, image: entry.image, state: "running" }))
      : [],
  );
}

test("bootstrap: a clean host plans to create every enabled artifact and migrate every enabled database", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlan({ baseline: emptyBaseline(), desiredRendered: rendered, catalog: contracts.catalog });

  assert.equal(plan.mode, "bootstrap");
  assert.equal(plan.executable, true);
  assert.equal(plan.summary.remove, 0);
  assert.equal(plan.summary.update, 0);
  assert.equal(plan.summary.create, plan.operations.filter((o) => o.action === "image.pull").length);
  assert.ok(plan.summary.create > 0);
  assert.ok(plan.summary.migrate > 0);
  assert.equal(plan.operations.at(0).action, "host.prepare");
  assert.equal(plan.operations.at(-1).action, "state.commit");
  // Every migration happens after every image is pulled and before any
  // service starts - a fresh volume must never be handed to a running
  // app before it's actually migrated.
  const lastPull = plan.operations.findLastIndex((o) => o.action === "image.pull");
  const firstMigrate = plan.operations.findIndex((o) => o.action === "database.migrate");
  const firstStart = plan.operations.findIndex((o) => o.action === "service.start");
  assert.ok(lastPull < firstMigrate, "pulls happen before migrations");
  assert.ok(firstMigrate < firstStart, "migrations happen before any service starts");
});

test("no-op: re-planning an untouched, fully-observed host changes nothing", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = { mode: "applied", generation: 5, ...topologyToServiceState(rendered, contracts.catalog) };
  const plan = buildPlan({ baseline, desiredRendered: rendered, catalog: contracts.catalog, observedResources: observedMatching(baseline) });

  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.deepEqual(plan.operations, []);
  assert.deepEqual(plan.drift, []);
  assert.equal(plan.mode, "applied");
});

test("topology change: enabling a previously-disabled service only touches that service", async () => {
  const before = await fixture((contracts) => { contracts.manifest.services.schrank.enabled = false; });
  const baseline = { mode: "applied", generation: 2, ...topologyToServiceState(before.rendered, before.contracts.catalog) };

  const after = await fixture((contracts) => { contracts.manifest.services.schrank.enabled = true; });
  const plan = buildPlan({
    baseline, desiredRendered: after.rendered, catalog: after.contracts.catalog,
    observedResources: observedMatching(baseline),
  });

  assert.equal(plan.summary.create, 2); // schrank-backend + schrank-frontend
  assert.equal(plan.summary.update, 0);
  assert.equal(plan.summary.remove, 0);
  assert.equal(plan.summary.migrate, 1); // schrank's own database, bootstrapped for the first time
  const touchedResources = plan.operations.filter((o) => o.resource?.startsWith("schrank")).map((o) => o.action);
  assert.ok(touchedResources.includes("service.start"));
  assert.ok(!plan.operations.some((o) => o.resource === "kuvert-backend"));
});

test("topology change: disabling a service backs it up and stops it, never removes its volume", async () => {
  const before = await fixture();
  const baseline = { mode: "applied", generation: 4, ...topologyToServiceState(before.rendered, before.contracts.catalog) };

  const after = await fixture((contracts) => { contracts.manifest.services.kuvert.enabled = false; });
  const plan = buildPlan({
    baseline, desiredRendered: after.rendered, catalog: after.contracts.catalog,
    observedResources: observedMatching(baseline),
  });

  assert.equal(plan.summary.remove, 2);
  assert.ok(plan.operations.some((o) => o.action === "backup.create" && o.resource === "kuvert-data"));
  assert.ok(plan.operations.some((o) => o.action === "service.stop" && o.resource === "kuvert-backend"));
  assert.ok(!plan.operations.some((o) => o.action === "volume.ensure" && o.resource === "kuvert-data"));
});

test("drift: a manually swapped image is reported as manual-change and warned about, not silently repaired", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = { mode: "applied", generation: 1, ...topologyToServiceState(rendered, contracts.catalog) };
  const observedResources = observedMatching(baseline).map((resource) =>
    resource.artifact === "kuvert-backend" ? { ...resource, image: "ghcr.io/vrubovoy/kuvert-backend@sha256:" + "9".repeat(64) } : resource,
  );

  const plan = buildPlan({ baseline, desiredRendered: rendered, catalog: contracts.catalog, observedResources });

  assert.deepEqual(plan.drift, [{
    resource: "kuvert/kuvert-backend", kind: "manual-change",
    detail: `observed image ghcr.io/vrubovoy/kuvert-backend@sha256:${"9".repeat(64)} does not match last-applied ${baseline.services.kuvert.artifacts["kuvert-backend"].image}`,
  }]);
  assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-backend")));
  // Desired still wants the release-locked image, not the manually
  // swapped one - drift is reported, not treated as the new baseline.
  assert.equal(plan.summary.update, 0);
});

test("drift: a missing container is folded into a repair operation even though desired matches baseline", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = { mode: "applied", generation: 1, ...topologyToServiceState(rendered, contracts.catalog) };
  const observedResources = observedMatching(baseline).filter((resource) => resource.artifact !== "kuvert-backend");

  const plan = buildPlan({ baseline, desiredRendered: rendered, catalog: contracts.catalog, observedResources });

  assert.equal(plan.drift.length, 1);
  assert.equal(plan.drift[0].kind, "missing");
  assert.equal(plan.summary.update, 1);
  assert.ok(plan.operations.some((o) => o.action === "service.start" && o.resource === "kuvert-backend"));
  assert.ok(plan.operations.some((o) => o.action === "database.migrate" && o.resource === "kuvert-backend"), "a re-created container gets re-migrated");
});

test("drift: an unmanaged resource is reported and warned about, never silently adopted", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = { mode: "applied", generation: 1, ...topologyToServiceState(rendered, contracts.catalog) };
  const observedResources = [...observedMatching(baseline), { service: "kuvert", artifact: "kuvert-worker", image: "ghcr.io/example/other:latest", state: "running" }];

  const plan = buildPlan({ baseline, desiredRendered: rendered, catalog: contracts.catalog, observedResources });

  assert.ok(plan.drift.some((entry) => entry.kind === "unmanaged" && entry.resource === "kuvert/kuvert-worker"));
  assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-worker")));
});

test("upgrade: a schema version bump on an otherwise-unchanged service triggers exactly its own migration", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = { mode: "applied", generation: 1, ...topologyToServiceState(rendered, contracts.catalog) };
  const bumped = structuredClone(rendered);
  bumped.topology.databaseSchemas.kuvert = { from: 1, to: 2, rollbackCompatible: true };

  const plan = buildPlan({ baseline, desiredRendered: bumped, catalog: contracts.catalog, observedResources: observedMatching(baseline) });

  assert.equal(plan.summary.migrate, 1);
  assert.equal(plan.summary.create, 0);
  assert.equal(plan.summary.update, 0);
  const migration = plan.operations.find((o) => o.action === "database.migrate");
  assert.equal(migration.resource, "kuvert-backend");
  assert.deepEqual(migration.schema, { from: 1, to: 2, rollbackCompatible: true });
  assert.equal(migration.reason, "schema version changed");
});

test("a real bootstrap plan and a real no-op plan both satisfy schemas/plan-v1.schema.json", async () => {
  const validate = await planValidator();
  const { contracts, rendered } = await fixture();

  const bootstrapPlan = buildPlan({ baseline: emptyBaseline(), desiredRendered: rendered, catalog: contracts.catalog });
  assert.ok(validate(bootstrapPlan), JSON.stringify(validate.errors));

  const baseline = { mode: "applied", generation: 9, ...topologyToServiceState(rendered, contracts.catalog) };
  const noopPlan = buildPlan({ baseline, desiredRendered: rendered, catalog: contracts.catalog, observedResources: observedMatching(baseline) });
  assert.ok(validate(noopPlan), JSON.stringify(validate.errors));
});

test("planId is deterministic for identical inputs and changes when the plan actually differs", async () => {
  const { contracts, rendered } = await fixture();
  const planA = buildPlan({ baseline: emptyBaseline(), desiredRendered: rendered, catalog: contracts.catalog });
  const planB = buildPlan({ baseline: emptyBaseline(), desiredRendered: rendered, catalog: contracts.catalog });
  assert.equal(planA.planId, planB.planId);

  // schrank is disabled by default in the example fixture - enable it to
  // actually produce a different desired state, not a no-op override.
  const other = await fixture((c) => { c.manifest.services.schrank.enabled = true; });
  const planC = buildPlan({ baseline: emptyBaseline(), desiredRendered: other.rendered, catalog: other.contracts.catalog });
  assert.notEqual(planA.planId, planC.planId);
});
