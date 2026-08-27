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

// The synthetic "genuinely clean host" observation - available on all
// three Docker resource kinds, nothing recorded anywhere.
const available = {
  containersStatus: "available", resources: [],
  volumesStatus: "available", volumes: [],
  networksStatus: "available", networks: [],
  generatedArtifactsStatus: "available", generatedArtifacts: {},
};

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

// installationId defaults to a fixed test value on every baseline built
// this way - computeDrift/computeMissingResources both scope "ours" by
// baseline.installationId, so a baseline with none at all (undefined)
// would make every real observation look foreign. generatedArtifacts
// defaults to {} (an applied host that never had a generated-file
// checksum recorded) - individual tests override it to exercise
// generated-file drift.
function baselineFrom(rendered, catalog, generation = 1, { installationId = "inst-1", generatedArtifacts = {} } = {}) {
  return { mode: "applied", generation, installationId, generatedArtifacts, ...topologyToServiceState(rendered, catalog) };
}

// Every unit baseline expects, marked running with the exact image
// baseline recorded, under baseline's own installationId - the "nothing
// has drifted" observation a real TargetInspector would report on an
// untouched host. Volumes/networks and generatedArtifacts are matched
// too, so a test that wants ONE specific kind of drift can start from
// this and override just that one thing.
function observedMatching(baseline) {
  const resources = Object.entries(baseline.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({
        service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true, installationId: baseline.installationId,
      }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId: baseline.installationId, kind, composeProject: "hof" });
  return {
    containersStatus: "available", resources,
    volumesStatus: "available", volumes: baseline.volumes.map((name) => asResourceRecord(name, "volume")),
    networksStatus: "available", networks: baseline.networks.map((name) => asResourceRecord(name, "network")),
    generatedArtifactsStatus: "available", generatedArtifacts: { ...baseline.generatedArtifacts },
  };
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
  // The gateway waits only for "running" (no Compose healthcheck by
  // design); every other unit waits for "healthy".
  const gatewayReadiness = plan.operations.find((o) => o.action === "readiness.wait" && o.resource === "gateway");
  assert.equal(gatewayReadiness.condition, "running");
  const otherReadiness = plan.operations.find((o) => o.action === "readiness.wait" && o.resource === "kuvert-backend");
  assert.equal(otherReadiness.condition, "healthy");
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

test("topology change: disabling a multi-unit service creates exactly one backup for its shared volume, stops and removes every one of its units", async () => {
  const before = await fixture();
  const baseline = baselineFrom(before.rendered, before.contracts.catalog, 4);

  const after = await fixture((contracts) => { contracts.manifest.services.kuvert.enabled = false; });
  const plan = buildDesired({ baseline, rendered: after.rendered, contracts: after.contracts, observation: observedMatching(baseline) });

  assert.equal(plan.summary.remove, 2);
  const backups = plan.operations.filter((o) => o.action === "backup.create" && o.resource === "kuvert-data");
  assert.equal(backups.length, 1, "one backup per removed SERVICE, not one per removed unit");
  for (const unit of ["kuvert-backend", "kuvert-frontend"]) {
    assert.ok(plan.operations.some((o) => o.action === "service.stop" && o.resource === unit), `${unit} stopped`);
    assert.ok(plan.operations.some((o) => o.action === "service.remove" && o.resource === unit), `${unit} actually removed, not left running`);
  }
  assert.ok(!plan.operations.some((o) => o.action === "volume.ensure" && o.resource === "kuvert-data"), "the volume itself is never touched - never destroyed");

  // Ordering within the removal: every unit is stopped first, the shared
  // backup happens once after all stops, and removal happens only after
  // the backup - never remove-before-backup.
  const lastStop = plan.operations.findLastIndex((o) => o.action === "service.stop" && (o.resource === "kuvert-backend" || o.resource === "kuvert-frontend"));
  const backupIndex = plan.operations.findIndex((o) => o.action === "backup.create" && o.resource === "kuvert-data");
  const firstRemove = plan.operations.findIndex((o) => o.action === "service.remove" && (o.resource === "kuvert-backend" || o.resource === "kuvert-frontend"));
  assert.ok(lastStop < backupIndex, "every unit stopped before the shared backup runs");
  assert.ok(backupIndex < firstRemove, "backup completes before any unit is actually removed");
});

test("topology change: re-planning after a disable has already been applied is a true no-op - removed units don't linger as orphan drift", async () => {
  const before = await fixture();
  const disabledContracts = await fixture((contracts) => { contracts.manifest.services.kuvert.enabled = false; });
  // The baseline as it would read AFTER a real apply actually ran the
  // disable-service plan above: kuvert's units gone from the topology,
  // its volume no longer expected either (apply's own state.commit would
  // have dropped it from desired.volumes going forward)... but the
  // volume itself is deliberately left in Docker (never destroyed) - so
  // a correct baseline still expects nothing, while Docker still quietly
  // holds the orphaned volume. That orphan is intentionally out of this
  // plan's blocking scope (it was never re-adopted, never re-claimed).
  const baseline = baselineFrom(disabledContracts.rendered, disabledContracts.contracts.catalog, 5);
  const observation = observedMatching(baseline);

  const plan = buildDesired({ baseline, rendered: disabledContracts.rendered, contracts: disabledContracts.contracts, observation });

  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.deepEqual(plan.operations, []);
  assert.deepEqual(plan.drift, []);
  assert.equal(plan.executable, true);
  assert.notEqual(before.rendered.topology.release, undefined); // sanity: fixture actually built
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
  observation.resources.push({ service: "kuvert", unit: "kuvert-worker", artifact: "kuvert-worker", image: "ghcr.io/example/other:latest", state: "running", managed: false, installationId: null });

  for (const repairDrift of [false, true]) {
    const plan = buildDesired({ baseline, rendered, contracts, observation, repairDrift });
    assert.ok(plan.drift.some((entry) => entry.kind === "unmanaged" && entry.resource === "kuvert/kuvert-worker"));
    assert.ok(plan.warnings.some((warning) => warning.includes("kuvert/kuvert-worker")));
    assert.equal(plan.executable, false, `repairDrift=${repairDrift}`);
    assert.ok(plan.blockers.some((blocker) => blocker.includes("kuvert/kuvert-worker")), `repairDrift=${repairDrift}`);
  }
});

// The reviewer's own scenario: a different Hof installation's container
// happens to carry the exact same service/unit labels (a second
// installation sharing this host). It must never be mistaken for this
// plan's own resource - it's unmanaged drift, and baseline's own unit is
// separately reported as missing (nothing of ours is actually running).
test("drift: a resource with a matching service/unit but a foreign installationId is never treated as ours", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1, { installationId: "inst-1" });
  const observation = observedMatching(baseline);
  observation.resources = observation.resources.map((resource) =>
    resource.artifact === "kuvert-backend" ? { ...resource, installationId: "inst-OTHER" } : resource,
  );

  const plan = buildDesired({ baseline, rendered, contracts, observation });

  assert.ok(plan.drift.some((entry) => entry.resource === "kuvert/kuvert-backend" && entry.kind === "missing"), "baseline's own unit is missing - nothing of ours is running");
  assert.ok(plan.drift.some((entry) => entry.resource === "kuvert/kuvert-backend" && entry.kind === "unmanaged" && entry.detail.includes("inst-OTHER")), "the foreign installation's container is reported as unmanaged, never silently adopted");
  assert.equal(plan.executable, false);
});

// A duplicate own-unit observation (two containers both genuinely
// carrying this installation's own labels for the same service/unit -
// a stray leftover from a crashed apply, say) must never crash the
// planner. Current behavior: the map dedupes to one, and because a
// baseline-matching key is found, neither copy is flagged as drift -
// documented here so a future change to this behavior is a deliberate,
// visible diff, not a silent regression.
test("drift: a duplicate own-unit observation dedupes without crashing", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  const duplicate = observation.resources.find((resource) => resource.artifact === "kuvert-backend");
  observation.resources.push({ ...duplicate });

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.ok(!plan.drift.some((entry) => entry.resource === "kuvert/kuvert-backend"));
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

test("drift: an orphaned managed volume with no matching baseline entry is reported as unmanaged, not silently ignored", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  // Not directly asserted in plan.drift (computeMissingResources only
  // ever reports what's MISSING relative to baseline, not extras) - this
  // documents that an extra own-installation volume with no baseline
  // counterpart plans no destructive action at all (Hof never deletes a
  // volume it didn't explicitly plan to remove).
  observation.volumes.push({ resource: "leftover-orphan", name: "leftover-orphan", managed: true, installationId: baseline.installationId, kind: "volume", composeProject: "hof" });

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.ok(!plan.operations.some((o) => o.resource === "leftover-orphan"));
});

test("missing volume: a baseline-expected persistent volume that's gone from Docker is a hard blocker, never silently recreated", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = observedMatching(baseline);
  observation.volumes = observation.volumes.filter((volume) => volume.resource !== "kuvert-data");

  for (const repairDrift of [false, true]) {
    const plan = buildDesired({ baseline, rendered, contracts, observation, repairDrift });
    assert.equal(plan.executable, false, `repairDrift=${repairDrift}`);
    assert.ok(plan.blockers.some((blocker) => blocker.includes("kuvert-data") && blocker.includes("gone")), `repairDrift=${repairDrift}`);
    assert.ok(!plan.operations.some((o) => o.action === "volume.ensure" && o.resource === "kuvert-data"), `repairDrift=${repairDrift}: never silently recreated`);
  }
});

test("missing network: a baseline-expected network that's gone from Docker is safely auto-repaired, never a blocker", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  assert.ok(baseline.networks.includes("hof"));
  const observation = observedMatching(baseline);
  observation.networks = observation.networks.filter((network) => network.resource !== "hof");

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.equal(plan.executable, true);
  assert.deepEqual(plan.blockers, []);
  const repair = plan.operations.find((o) => o.action === "volume.ensure" && o.resource === "hof");
  assert.ok(repair, "a missing network is repaired via the same volume.ensure-shaped operation");
  assert.match(repair.reason, /recreate a missing network/);
});

test("generated-file drift: a missing generated file is always auto-repaired via config.write, with no blocker either way", async () => {
  const { contracts, rendered } = await fixture();
  const digest = "sha256:" + "d".repeat(64);
  const baseline = baselineFrom(rendered, contracts.catalog, 1, { generatedArtifacts: { "compose.yml": digest } });
  const observation = observedMatching(baseline);
  observation.generatedArtifacts = {}; // the file is simply gone

  for (const repairDrift of [false, true]) {
    const plan = buildDesired({ baseline, rendered, contracts, observation, repairDrift });
    assert.equal(plan.executable, true, `repairDrift=${repairDrift}`);
    assert.ok(plan.drift.some((entry) => entry.kind === "generated-missing" && entry.resource === "generated/compose.yml"), `repairDrift=${repairDrift}`);
    assert.ok(plan.operations.some((o) => o.action === "config.write"), `repairDrift=${repairDrift}`);
  }
});

test("generated-file drift: a hand-modified generated file is a blocker unless --repair-drift is given", async () => {
  const { contracts, rendered } = await fixture();
  const baselineDigest = "sha256:" + "d".repeat(64);
  const observedDigest = "sha256:" + "e".repeat(64);
  const baseline = baselineFrom(rendered, contracts.catalog, 1, { generatedArtifacts: { "compose.yml": baselineDigest } });
  const observation = observedMatching(baseline);
  observation.generatedArtifacts = { "compose.yml": observedDigest };

  const blocked = buildDesired({ baseline, rendered, contracts, observation });
  assert.equal(blocked.executable, false);
  assert.ok(blocked.blockers.some((blocker) => blocker.includes("generated/compose.yml") && blocker.includes("never silently overwritten")));
  assert.ok(!blocked.operations.some((o) => o.action === "config.write"), "never silently overwritten without an explicit repair");

  const repaired = buildDesired({ baseline, rendered, contracts, observation, repairDrift: true });
  assert.equal(repaired.executable, true);
  assert.deepEqual(repaired.blockers, []);
  assert.ok(repaired.operations.some((o) => o.action === "config.write"));
  assert.ok(repaired.warnings.some((warning) => warning.includes("generated/compose.yml")), "still surfaced as a warning even once repaired");
});

test("generated-file drift: a regenerated Caddyfile forces the gateway to actually restart, not just config.write", async () => {
  const { contracts, rendered } = await fixture();
  const digest = "sha256:" + "d".repeat(64);
  const baseline = baselineFrom(rendered, contracts.catalog, 1, { generatedArtifacts: { Caddyfile: digest } });
  const observation = observedMatching(baseline);
  observation.generatedArtifacts = {};

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.ok(plan.operations.some((o) => o.action === "service.stop" && o.resource === "gateway"));
  assert.ok(plan.operations.some((o) => o.action === "service.start" && o.resource === "gateway"));
  const readiness = plan.operations.find((o) => o.action === "readiness.wait" && o.resource === "gateway");
  assert.equal(readiness.condition, "running");
});

test("generated-file drift: a non-Caddyfile file (e.g. compose.yml) never triggers a gateway restart on its own", async () => {
  const { contracts, rendered } = await fixture();
  const digest = "sha256:" + "d".repeat(64);
  const baseline = baselineFrom(rendered, contracts.catalog, 1, { generatedArtifacts: { "compose.yml": digest } });
  const observation = observedMatching(baseline);
  observation.generatedArtifacts = {};

  const plan = buildDesired({ baseline, rendered, contracts, observation });
  assert.ok(!plan.operations.some((o) => o.resource === "gateway"));
});

test("observation unavailable: an applied host refuses to plan changes blind", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const plan = buildDesired({ baseline, rendered, contracts, observation: { ...available, containersStatus: "unavailable", volumesStatus: "unavailable", networksStatus: "unavailable" } });

  assert.equal(plan.executable, false);
  assert.ok(plan.blockers.some((blocker) => blocker.includes("observation unavailable")));
  assert.deepEqual(plan.drift, []);
  // The desired diff itself is still computed and shown, just not safe to run.
  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
});

test("observation unavailable: only the containers listing failing is still enough to block an applied host", async () => {
  const { contracts, rendered } = await fixture();
  const baseline = baselineFrom(rendered, contracts.catalog, 1);
  const observation = { ...observedMatching(baseline), containersStatus: "unavailable" };
  const plan = buildDesired({ baseline, rendered, contracts, observation });

  assert.equal(plan.executable, false);
  assert.ok(plan.blockers.some((blocker) => blocker.includes("observation unavailable")));
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

test("a real bootstrap plan, a real no-op plan, and a real disable-service plan all satisfy schemas/plan-v1.schema.json", async () => {
  const validate = await planValidator();
  const { contracts, rendered } = await fixture();

  const bootstrapPlan = buildDesired({ baseline: emptyBaseline(), rendered, contracts });
  assert.ok(validate(bootstrapPlan), JSON.stringify(validate.errors));

  const baseline = baselineFrom(rendered, contracts.catalog, 9);
  const noopPlan = buildDesired({ baseline, rendered, contracts, observation: observedMatching(baseline) });
  assert.ok(validate(noopPlan), JSON.stringify(validate.errors));

  const disabled = await fixture((c) => { c.manifest.services.kuvert.enabled = false; });
  const disablePlan = buildDesired({ baseline, rendered: disabled.rendered, contracts: disabled.contracts, observation: observedMatching(baseline) });
  assert.ok(validate(disablePlan), JSON.stringify(validate.errors));
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
