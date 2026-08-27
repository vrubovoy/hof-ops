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
const available = { status: "available", resources: [] };

async function planValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(JSON.parse(await readFile(path.join(root, "schemas/plan-v1.schema.json"), "utf8")));
}

async function fixture(overrides = (contracts) => contracts) {
  const contracts = structuredClone(await loadContracts());
  overrides(contracts);
  const rendered = renderTopology(contracts);
  return { contracts, rendered };
}

function baselineFrom(rendered, catalog, generation = 1) {
  return { mode: "applied", generation, ...topologyToServiceState(rendered, catalog) };
}

// Every unit baseline expects, marked running with the exact image
// baseline recorded - the "nothing has drifted" observation a real
// TargetInspector would report on an untouched host.
function observedMatching(baseline) {
  const resources = Object.entries(baseline.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({ service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true }))
      : [],
  );
  return { status: "available", resources };
}

function buildDesired({ baseline, rendered, contracts, observation = available, repairDrift }) {
  return buildPlan({
    baseline, desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock,
    catalog: contracts.catalog, observation, repairDrift,
  });
}

test("bootstrap: a clean host plans to create every enabled unit and migrate every enabled database", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildDesired({ baseline: emptyBaseline(), rendered, contracts });

  assert.equal(plan.mode, "bootstrap");
  assert.equal(plan.executable, true);
  assert.deepEqual(plan.blockers, []);
  assert.equal(plan.summary.remove, 0);
  assert.equal(plan.summary.update, 0);
  assert.equal(plan.summary.create, plan.operations.filter((o) => o.action === "image.pull").length);
  assert.ok(plan.summary.create > 0);
  assert.ok(plan.summary.migrate > 0);
  // Wachter's API and its agent must both get their own image.pull -
  // one shared artifact, but two units, two pulls.
  assert.equal(plan.operations.filter((o) => o.action === "image.pull" && o.resource.startsWith("wachter")).length, 2);
  assert.equal(plan.operations.at(0).action, "host.prepare");
  assert.equal(plan.operations.at(-1).action, "state.commit");
  const lastPull = plan.operations.findLastIndex((o) => o.action === "image.pull");
  const firstMigrate = plan.operations.findIndex((o) => o.action === "database.migrate");
  const firstStart = plan.operations.findIndex((o) => o.action === "service.start");
  assert.ok(lastPull < firstMigrate, "pulls happen before migrations");
  assert.ok(firstMigrate < firstStart, "migrations happen before any service starts");
  // No backup on a fresh install - there's nothing yet to protect.
  assert.ok(!plan.operations.some((o) => o.action === "backup.create"));
});

test("bootstrap migration operations carry their own argv/volume - a plan is self-sufficient, apply never re-reads the catalog", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildDesired({ baseline: emptyBaseline(), rendered, contracts });
  const migration = plan.operations.find((o) => o.action === "database.migrate" && o.resource === "kuvert-backend");
  assert.deepEqual(migration.argv, ["node", "backend/dist/migrate.js"]);
  assert.equal(migration.volume, "kuvert-data");
});

test("no-op: re-planning an untouched, fully-observed host changes nothing", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 5);
  const plan = buildDesired({ baseline, rendered, contracts, observation: observedMatching(baseline) });

  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.deepEqual(plan.operations, []);
  assert.deepEqual(plan.drift, []);
  assert.deepEqual(plan.blockers, []);
  assert.equal(plan.executable, true);
  assert.equal(plan.mode, "applied");
});

test("config-only change: a domain edit with no image change still plans a config.write and unit restarts", async () => {
  const before = await fixture();
  const baseline = baselineFrom(before.rendered, before.contracts.catalog, 2);

  const after = await fixture((contracts) => { contracts.manifest.domains.base = "changed.example.com"; });
  const plan = buildDesired({ baseline, rendered: after.rendered, contracts: after.contracts, observation: observedMatching(baseline) });

  assert.ok(plan.summary.update > 0, "a domain change touches units even though no image changed");
  assert.ok(plan.operations.some((o) => o.action === "config.write"));
  assert.ok(plan.operations.some((o) => o.action === "state.commit"));
  // No image actually changed, so nothing needs re-verifying/re-pulling.
  assert.ok(!plan.operations.some((o) => o.action === "image.pull"));
  assert.notEqual(baseline.topologyDigest, plan.desired.topologyDigest);
});

test("config-only change: a backup-schedule edit with no per-unit footprint still forces config.write via topologyDigest", async () => {
  const before = await fixture();
  const baseline = baselineFrom(before.rendered, before.contracts.catalog, 2);

  const after = await fixture((contracts) => { contracts.manifest.backup.schedule = "04:30"; });
  const plan = buildDesired({ baseline, rendered: after.rendered, contracts: after.contracts, observation: observedMatching(baseline) });

  assert.notEqual(baseline.topologyDigest, plan.desired.topologyDigest);
  // No unit's own rendered Compose definition changed - only the plan's
  // top-level topologyDigest catches this.
  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.ok(plan.operations.some((o) => o.action === "config.write"));
  assert.ok(plan.operations.some((o) => o.action === "state.commit"));
});

test("topology change: enabling a previously-disabled service creates its own units and cascades to every unit whose config actually references it", async () => {
  const before = await fixture((contracts) => { contracts.manifest.services.schrank.enabled = false; });
  const baseline = baselineFrom(before.rendered, before.contracts.catalog, 2);

  const after = await fixture((contracts) => { contracts.manifest.services.schrank.enabled = true; });
  const plan = buildDesired({ baseline, rendered: after.rendered, contracts: after.contracts, observation: observedMatching(baseline) });

  assert.equal(plan.summary.create, 2); // schrank-backend + schrank-frontend
  assert.equal(plan.summary.remove, 0);
  assert.equal(plan.summary.migrate, 1); // schrank's own database, bootstrapped for the first time
  assert.ok(plan.operations.some((o) => o.resource === "schrank-backend" && o.action === "service.start"));
  assert.ok(!plan.operations.some((o) => o.action === "backup.create"), "a first-time migration for a newly enabled service needs no backup");
  // A brand new public origin (schrank.example.com) genuinely changes
  // the gateway's Caddyfile, Schlüssel's/Glocke's ALLOWED_ORIGINS, and
  // Schloss's launcher-card URL list - real cascading updates the old
  // image-only diff would have missed entirely (see finding #1).
  assert.equal(plan.summary.update, 5);
  for (const resource of ["gateway", "schlussel", "schlussel-frontend", "schloss", "glocke-backend"]) {
    assert.ok(plan.operations.some((o) => o.resource === resource && o.action === "service.stop"), resource);
  }
  assert.ok(!plan.operations.some((o) => o.resource === "kuvert-backend"));
  // schlussel and glocke-backend are both database-backed and both got
  // updated above - purely because their CORS origins shifted, not
  // because their own image/schema changed. Only schrank (the service
  // that was actually enabled) may migrate.
  assert.equal(plan.summary.migrate, 1);
  assert.ok(!plan.operations.some((o) => o.action === "database.migrate" && o.resource !== "schrank-backend"));
});

test("topology change: disabling a service backs it up and stops it, never removes its volume", async () => {
  const before = await fixture();
  const baseline = baselineFrom(before.rendered, before.contracts.catalog, 4);

  const after = await fixture((contracts) => { contracts.manifest.services.kuvert.enabled = false; });
  const plan = buildDesired({ baseline, rendered: after.rendered, contracts: after.contracts, observation: observedMatching(baseline) });

  assert.equal(plan.summary.remove, 2);
  assert.ok(plan.operations.some((o) => o.action === "backup.create" && o.resource === "kuvert-data"));
  assert.ok(plan.operations.some((o) => o.action === "service.stop" && o.resource === "kuvert-backend"));
  assert.ok(!plan.operations.some((o) => o.action === "volume.ensure" && o.resource === "kuvert-data"));
});

test("drift: a manually swapped image is a blocker by default, not silently repaired", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.resources = observation.resources.map((resource) =>
    resource.artifact === "kuvert-backend" ? { ...resource, image: "ghcr.io/vrubovoy/kuvert-backend@sha256:" + "9".repeat(64) } : resource,
  );

  const plan = buildDesired({ baseline, rendered, contracts, observation });

  assert.deepEqual(plan.drift, [{
    resource: "kuvert/kuvert-backend", kind: "manual-change",
    detail: `observed image ghcr.io/vrubovoy/kuvert-backend@sha256:${"9".repeat(64)} does not match last-applied ${baseline.services.kuvert.units["kuvert-backend"].image}`,
  }]);
  assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-backend")));
  assert.equal(plan.executable, false);
  assert.ok(plan.blockers.some((blocker) => blocker.includes("kuvert/kuvert-backend")));
  // Desired still wants the release-locked image, not the manually
  // swapped one - drift is reported and blocks, not treated as new baseline.
  assert.equal(plan.summary.update, 0);
});

test("drift: repairDrift folds a manual-change into a repair and clears its blocker", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.resources = observation.resources.map((resource) =>
    resource.artifact === "kuvert-backend" ? { ...resource, image: "ghcr.io/vrubovoy/kuvert-backend@sha256:" + "9".repeat(64) } : resource,
  );

  const plan = buildDesired({ baseline, rendered, contracts, observation, repairDrift: true });

  assert.equal(plan.executable, true);
  assert.deepEqual(plan.blockers, []);
  assert.ok(plan.operations.some((o) => o.action === "service.start" && o.resource === "kuvert-backend"));
  // Still surfaced as a warning even though it's being repaired.
  assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-backend")));
});

test("drift: a missing container is folded into a repair operation even though desired matches baseline", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.resources = observation.resources.filter((resource) => resource.artifact !== "kuvert-backend");

  const plan = buildDesired({ baseline, rendered, contracts, observation });

  assert.equal(plan.drift.length, 1);
  assert.equal(plan.drift[0].kind, "missing");
  assert.equal(plan.executable, true);
  assert.equal(plan.summary.update, 1);
  assert.ok(plan.operations.some((o) => o.action === "service.start" && o.resource === "kuvert-backend"));
  assert.ok(plan.operations.some((o) => o.action === "database.migrate" && o.resource === "kuvert-backend"), "a re-created container gets re-migrated");
});

test("drift: an unmanaged resource always blocks, even with repairDrift", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.resources.push({ service: "kuvert", unit: "kuvert-worker", artifact: "kuvert-worker", image: "ghcr.io/example/other:latest", state: "running", managed: false });

  for (const repairDrift of [false, true]) {
    const plan = buildDesired({ baseline, rendered, contracts, observation, repairDrift });
    assert.ok(plan.drift.some((entry) => entry.kind === "unmanaged" && entry.resource === "kuvert/kuvert-worker"));
    assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-worker")));
    assert.equal(plan.executable, false, `repairDrift=${repairDrift}`);
    assert.ok(plan.blockers.some((blocker) => blocker.includes("kuvert/kuvert-worker")), `repairDrift=${repairDrift}`);
  }
});

test("drift: Wachter's API and agent are two separate observed resources, not one collapsed unit", async () => {
  const { contracts, rendered } = await fixture((c) => { c.manifest.services.wachter.enabled = true; });
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.resources = observation.resources.filter((resource) => resource.unit !== "wachter-agent");

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.deepEqual(plan.drift, [{ resource: "wachter/wachter-agent", kind: "missing", detail: "baseline expects this container but it isn't running" }]);
  // The API itself is untouched - only the agent is missing.
  assert.ok(!plan.operations.some((o) => o.resource === "wachter" && o.action === "service.stop"));
  assert.ok(plan.operations.some((o) => o.resource === "wachter-agent" && o.action === "service.start"));
});

test("observation unavailable: an applied host refuses to plan changes blind", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const plan = buildDesired({ baseline, rendered, contracts, observation: { status: "unavailable", resources: [] } });

  assert.equal(plan.executable, false);
  assert.ok(plan.blockers.some((blocker) => blocker.includes("observation unavailable")));
  assert.deepEqual(plan.drift, []);
  // The desired diff itself is still computed and shown, just not safe to run.
  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
});

test("buildPlan requires an explicit observation - never defaults to 'nothing is running'", async () => {
  const { contracts, rendered } = await fixture();
  assert.throws(
    () => buildPlan({ baseline: emptyBaseline(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog }),
    /requires an explicit observation/,
  );
});

test("upgrade: a schema version bump on an otherwise-unchanged service triggers exactly its own migration, with a backup first", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const bumped = structuredClone(rendered);
  bumped.topology.databaseSchemas.kuvert = { from: 1, to: 2, rollbackCompatible: true };

  const plan = buildPlan({
    baseline, desiredRendered: bumped, manifest: contracts.manifest, releaseLock: contracts.releaseLock,
    catalog: contracts.catalog, observation: observedMatching(baseline),
  });

  assert.equal(plan.summary.migrate, 1);
  assert.equal(plan.summary.create, 0);
  assert.equal(plan.summary.update, 1, "the migrated unit still needs a stop/start cycle even with no image change");
  const migration = plan.operations.find((o) => o.action === "database.migrate");
  assert.equal(migration.resource, "kuvert-backend");
  assert.deepEqual(migration.schema, { from: 1, to: 2, rollbackCompatible: true });
  assert.equal(migration.reason, "schema version changed");
  assert.ok(plan.operations.some((o) => o.action === "backup.create" && o.resource === "kuvert-data"), "an in-place upgrade migration backs up first");
  const stopIndex = plan.operations.findIndex((o) => o.action === "service.stop" && o.resource === "kuvert-backend");
  const backupIndex = plan.operations.findIndex((o) => o.action === "backup.create" && o.resource === "kuvert-data");
  const migrateIndex = plan.operations.findIndex((o) => o.action === "database.migrate");
  assert.ok(stopIndex < backupIndex && backupIndex < migrateIndex, "stop, then backup, then migrate");
});

test("upgrade: a rollback-incompatible migration is a warning, not a blocker", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const bumped = structuredClone(rendered);
  bumped.topology.databaseSchemas.kuvert = { from: 1, to: 2, rollbackCompatible: false };

  const plan = buildPlan({
    baseline, desiredRendered: bumped, manifest: contracts.manifest, releaseLock: contracts.releaseLock,
    catalog: contracts.catalog, observation: observedMatching(baseline),
  });

  assert.equal(plan.executable, true);
  assert.ok(plan.warnings.some((warning) => warning.includes("not rollback-compatible")));
});

test("upgrade: a baseline schema that doesn't match this release's expected starting point is a blocker", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  baseline.services.kuvert.schemaVersion = 4; // baseline claims schema 4; release lock still expects to start from 1
  const bumped = structuredClone(rendered);
  bumped.topology.databaseSchemas.kuvert = { from: 1, to: 2, rollbackCompatible: true };

  const plan = buildPlan({
    baseline, desiredRendered: bumped, manifest: contracts.manifest, releaseLock: contracts.releaseLock,
    catalog: contracts.catalog, observation: observedMatching(baseline),
  });

  assert.equal(plan.executable, false);
  assert.ok(plan.blockers.some((blocker) => blocker.includes("does not match this release's expected starting schema")));
});

test("a real bootstrap plan and a real no-op plan both satisfy schemas/plan-v1.schema.json", async () => {
  const validate = await planValidator();
  const { contracts, rendered } = await fixture();

  const bootstrapPlan = buildDesired({ baseline: emptyBaseline(), rendered, contracts });
  assert.ok(validate(bootstrapPlan), JSON.stringify(validate.errors));

  const baseline = baselineFrom(rendered, contracts.catalog, 9);
  const noopPlan = buildDesired({ baseline, rendered, contracts, observation: observedMatching(baseline) });
  assert.ok(validate(noopPlan), JSON.stringify(validate.errors));
});

test("planId is deterministic for identical inputs and changes when the plan actually differs", async () => {
  const { contracts, rendered } = await fixture();
  const planA = buildDesired({ baseline: emptyBaseline(), rendered, contracts });
  const planB = buildDesired({ baseline: emptyBaseline(), rendered, contracts });
  assert.equal(planA.planId, planB.planId);

  // schrank is disabled by default in the example fixture - enable it to
  // actually produce a different desired state, not a no-op override.
  const other = await fixture((c) => { c.manifest.services.schrank.enabled = true; });
  const planC = buildDesired({ baseline: emptyBaseline(), rendered: other.rendered, contracts: other.contracts });
  assert.notEqual(planA.planId, planC.planId);
});
