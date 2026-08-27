// hofctl plan's pure core: given a baseline (last-applied state, or the
// synthetic bootstrap baseline), a freshly rendered desired topology,
// and what's actually observed running, produce the typed, ordered
// operation list described in PLATFORM-OPS-PLAN.md. No I/O here - state
// loading lives in state.mjs, host/Docker inspection is TargetInspector's
// job; this only ever computes from what it's handed, so it's the part
// every fixture (bootstrap/no-op/topology-change/drift/upgrade) can
// exercise directly.

import { sha256 } from "./digest.mjs";
import { topologyToServiceState } from "./state.mjs";

// Compares two {services: {units}} snapshots unit by unit - keyed by
// hof.unit (the real Compose service key), not by catalog artifact, so
// Wächter's API and its agent (one shared artifact, two units) never
// collapse into a single diff entry. Absent-or-disabled is treated
// identically ("nothing here") on both sides, so enabling a service that
// was merely disabled diffs the same way as one that's brand new.
// configFingerprint (not just image) decides update, so a domain/CORS/
// browserPush/TLS-driven environment change registers even when the
// pinned image tag didn't move; imageChanged is tracked separately so
// buildOperations can skip a pointless image.verify/pull for a
// config-only change.
function diffUnits(baseline, desired) {
  const create = [];
  const update = [];
  const remove = [];
  const serviceIds = new Set([...Object.keys(baseline.services), ...Object.keys(desired.services)]);

  for (const service of serviceIds) {
    const b = baseline.services[service]?.enabled ? baseline.services[service] : { units: {} };
    const d = desired.services[service]?.enabled ? desired.services[service] : { units: {} };
    const units = new Set([...Object.keys(b.units), ...Object.keys(d.units)]);
    for (const unit of units) {
      const from = b.units[unit];
      const to = d.units[unit];
      if (to && !from) create.push({ service, unit, artifact: to.artifact, image: to.image, imageChanged: true, reason: "new unit" });
      else if (to && from && to.configFingerprint !== from.configFingerprint) {
        const imageChanged = to.image !== from.image;
        update.push({
          service, unit, artifact: to.artifact, fromImage: from.image, toImage: to.image, imageChanged,
          reason: imageChanged ? "image changed" : "configuration changed",
        });
      } else if (!to && from) remove.push({ service, unit, artifact: from.artifact, image: from.image });
    }
  }
  return { create, update, remove };
}

function alreadyTouchedKeys(create, update) {
  return new Set([...create, ...update].map((entry) => `${entry.service}/${entry.unit}`));
}

// A no-op re-apply must still notice a container that vanished out from
// under it (the reconciler's "interrupted operation can be safely
// resumed" and "no-op only when nothing actually needs doing" properties
// both depend on this) - folds any "missing" drift for a still-desired
// unit into the update set as a repair, even though desired and baseline
// agree on the image/config.
function foldMissingIntoRepairs(desired, drift, create, update) {
  const touched = alreadyTouchedKeys(create, update);
  for (const entry of drift) {
    if (entry.kind !== "missing" || touched.has(entry.resource)) continue;
    const [service, unit] = entry.resource.split("/");
    const desiredUnit = desired.services[service]?.units?.[unit];
    if (!desiredUnit) continue;
    update.push({
      service, unit, artifact: desiredUnit.artifact, fromImage: desiredUnit.image, toImage: desiredUnit.image,
      imageChanged: true, reason: "repair: container missing",
    });
    touched.add(entry.resource);
  }
}

// A manually swapped image/config is, by default, a blocker (see
// computeBlockers) rather than something apply silently overwrites -
// this fold is only ever called when the caller explicitly opted into
// repairDrift, forcing the unit back to what desired actually wants.
// Never touches "unmanaged" drift - Hof never claims a resource it
// didn't already own, drift repair or not.
function foldManualChangeIntoRepairs(desired, drift, create, update) {
  const touched = alreadyTouchedKeys(create, update);
  for (const entry of drift) {
    if (entry.kind !== "manual-change" || touched.has(entry.resource)) continue;
    const [service, unit] = entry.resource.split("/");
    const desiredUnit = desired.services[service]?.units?.[unit];
    if (!desiredUnit) continue;
    update.push({
      service, unit, artifact: desiredUnit.artifact, fromImage: desiredUnit.image, toImage: desiredUnit.image,
      imageChanged: true, reason: "repair: reverting manually changed drift",
    });
    touched.add(entry.resource);
  }
}

// baseline vs what's actually observed running - independent of what's
// now desired, so "services.yml changed" and "someone touched Docker by
// hand" stay distinguishable (see PLATFORM-OPS-PLAN.md). observation
// must be {status, resources}; when the inspector couldn't actually
// reach the host, there is nothing honest to compare against, so drift
// is simply not computed at all (the caller is expected to have already
// turned "unavailable" into a blocker - see computeBlockers).
function computeDrift(baseline, observation) {
  if (observation.status !== "available") return [];
  const drift = [];
  const observedByKey = new Map(observation.resources.map((resource) => [`${resource.service}/${resource.unit}`, resource]));
  const baselineKeys = new Set();

  for (const [service, definition] of Object.entries(baseline.services)) {
    if (!definition.enabled) continue;
    for (const [unit, expected] of Object.entries(definition.units)) {
      const key = `${service}/${unit}`;
      baselineKeys.add(key);
      const observed = observedByKey.get(key);
      if (!observed) {
        drift.push({ resource: key, kind: "missing", detail: "baseline expects this container but it isn't running" });
      } else if (observed.image !== expected.image || observed.state !== "running") {
        drift.push({
          resource: key, kind: "manual-change",
          detail: observed.image !== expected.image
            ? `observed image ${observed.image} does not match last-applied ${expected.image}`
            : `observed state is ${observed.state}, expected running`,
        });
      }
    }
  }

  for (const resource of observation.resources) {
    const key = `${resource.service}/${resource.unit}`;
    if (!baselineKeys.has(key)) drift.push({ resource: key, kind: "unmanaged", detail: "running, but not recorded in the last-applied state" });
  }

  return drift;
}

// Which persistent, enabled services need a database.migrate at all -
// decided once, up front, so foldMigrationOnlyIntoUpdates (which needs
// to know the answer before the operation list exists) and
// migrationOperations (which builds the operations themselves) always
// agree on exactly the same set. imageChangedUnits deliberately checks
// only the database component's OWN image, not "was this service
// touched for any reason" - a sibling unit's config-only change (say,
// Schlüssel's ALLOWED_ORIGINS shifting because an unrelated service was
// enabled) must never trigger a migration on its own.
function servicesNeedingMigration(baseline, desired, imageChangedUnits, catalog) {
  return catalog.services.filter((service) => {
    if (!service.database || !desired.services[service.id]?.enabled) return false;
    const wasEnabled = baseline.services[service.id]?.enabled === true;
    const schemaChanged = baseline.services[service.id]?.schemaVersion !== desired.services[service.id]?.schemaVersion;
    const unitEntry = Object.entries(desired.services[service.id].units).find(([, unit]) => unit.artifact === service.database.component);
    const componentImageChanged = unitEntry && imageChangedUnits.has(`${service.id}/${unitEntry[0]}`);
    return !wasEnabled || schemaChanged || componentImageChanged;
  });
}

// A schema-only bump (image/config otherwise untouched) still needs its
// unit stopped and restarted around the migration - without this fold
// that unit would never appear in update at all, and buildOperations
// would try to migrate a database whose container was never stopped.
function foldMigrationOnlyIntoUpdates(desired, needing, create, update) {
  const touched = alreadyTouchedKeys(create, update);
  for (const service of needing) {
    if (touched.has(`${service.id}/${service.database.component}`)) continue;
    const entry = Object.entries(desired.services[service.id].units).find(([, unit]) => unit.artifact === service.database.component);
    if (!entry) continue;
    const [unit, info] = entry;
    if (touched.has(`${service.id}/${unit}`)) continue;
    update.push({ service: service.id, unit, artifact: info.artifact, fromImage: info.image, toImage: info.image, imageChanged: false, reason: "schema version changed" });
    touched.add(`${service.id}/${unit}`);
  }
}

function migrationOperations(baseline, desired, desiredRendered, needing) {
  const operations = [];
  const blockers = [];
  const warnings = [];
  const needsBackup = [];

  for (const service of needing) {
    const wasEnabled = baseline.services[service.id]?.enabled === true;
    const baselineSchema = baseline.services[service.id]?.schemaVersion ?? null;
    // The release lock's own declared from/to/rollbackCompatible for
    // this component (see catalog/services-v1.yaml's database.command
    // comment and the release-lock schema) - real per-component data,
    // not inferred from baseline's own possibly-stale record.
    const schema = desiredRendered.topology.databaseSchemas[service.id];
    const schemaChanged = baselineSchema !== desired.services[service.id]?.schemaVersion;

    if (wasEnabled && baselineSchema !== null && baselineSchema !== schema.from) {
      blockers.push(
        `${service.id}: baseline schema version ${baselineSchema} does not match this release's expected starting schema ${schema.from} - refusing to plan a migration that skips versions`,
      );
    }
    if (!schema.rollbackCompatible) {
      warnings.push(`${service.id}: migrating to schema ${schema.to} is not rollback-compatible - a future rollback cannot simply reapply the previous release`);
    }

    const unitEntry = Object.entries(desired.services[service.id].units).find(([, unit]) => unit.artifact === service.database.component);
    operations.push({
      id: `database.migrate.${service.id}`,
      phase: "database",
      action: "database.migrate",
      resource: service.database.component,
      ...(unitEntry?.[1]?.image ? { image: unitEntry[1].image } : {}),
      argv: service.database.command,
      volume: service.database.volume,
      schema: { from: schema.from, to: schema.to, rollbackCompatible: schema.rollbackCompatible },
      reason: !wasEnabled ? "initialize database" : schemaChanged ? "schema version changed" : "component image changed",
    });
    // Bootstrap migrates into a database nothing has ever written to -
    // there's nothing to protect yet. An in-place upgrade is exactly
    // the case that needs a safety net before an irreversible schema
    // change.
    if (wasEnabled) needsBackup.push({ service: service.id, volume: service.database.volume });
  }
  return { operations, blockers, warnings, needsBackup };
}

function buildOperations({ baseline, desired, create, update, remove, migrations, needsBackup, catalog }) {
  const operations = [];
  let sequence = 0;
  const next = (id, phase, action, resource, rest) => {
    sequence += 1;
    operations.push({ id: `${String(sequence).padStart(3, "0")}.${id}`, phase, action, resource, ...rest });
  };

  // topologyDigest covers backup schedule/retention/destinations and
  // anything else renderTopology() produces with no per-unit Compose
  // footprint at all (see topologyToServiceState) - without this, a
  // backup-only edit would leave anyChange false and never regenerate
  // anything, even though the desired state genuinely changed.
  const topologyChanged = baseline.topologyDigest !== desired.topologyDigest;
  const anyChange = create.length + update.length + remove.length + migrations.length > 0 || topologyChanged;
  if (baseline.mode === "bootstrap" && anyChange) {
    next("host.prepare", "host", "host.prepare", "host", { reason: "first successful apply for this installation" });
    next("secret.ensure", "secret", "secret.ensure", "secrets.sops.yaml", { reason: "first successful apply for this installation" });
  }

  const newVolumes = desired.volumes.filter((volume) => !baseline.volumes.includes(volume));
  for (const volume of newVolumes) next(`volume.ensure.${volume}`, "volume", "volume.ensure", volume, { reason: "new persistent volume" });

  for (const entry of [...create, ...update].filter((entry) => entry.imageChanged)) {
    next(`image.verify.${entry.service}.${entry.unit}`, "image", "image.verify", entry.unit, { image: entry.image ?? entry.toImage, reason: "confirm the release-locked, hofctl validate-approved image" });
    next(`image.pull.${entry.service}.${entry.unit}`, "image", "image.pull", entry.unit, { image: entry.image ?? entry.toImage, reason: "pull the digest-pinned image" });
  }

  if (anyChange) next("config.write", "config", "config.write", "compose.yml", { reason: "regenerate Compose/Caddyfile/env from the current desired state" });

  for (const entry of update) next(`service.stop.${entry.service}.${entry.unit}`, "service", "service.stop", entry.unit, { reason: entry.reason });

  for (const entry of remove) {
    const service = catalog.services.find((candidate) => candidate.id === entry.service);
    if (service?.database) next(`backup.create.${entry.service}`, "backup", "backup.create", service.database.volume, { reason: "back up before removing a persistent service" });
    next(`service.stop.${entry.service}.${entry.unit}`, "service", "service.stop", entry.unit, { reason: "service disabled" });
  }

  // After the units that need it are stopped, before the (irreversible)
  // schema change actually runs.
  for (const backup of needsBackup) next(`backup.create.migrate.${backup.service}`, "backup", "backup.create", backup.volume, { reason: "back up before an in-place database migration" });

  for (const operation of migrations) {
    sequence += 1;
    operations.push({ ...operation, id: `${String(sequence).padStart(3, "0")}.${operation.id}` });
  }

  for (const entry of [...create, ...update]) {
    next(`service.start.${entry.service}.${entry.unit}`, "service", "service.start", entry.unit, { image: entry.image ?? entry.toImage, reason: entry.reason ?? "new unit" });
    next(`readiness.wait.${entry.service}.${entry.unit}`, "readiness", "readiness.wait", entry.unit, { reason: "wait for the container to report healthy" });
  }

  if (anyChange) next("state.commit", "state", "state.commit", "state/current.json", { reason: "record this generation as last-applied, only after every prior operation succeeded" });

  return operations;
}

// A plan can't honestly claim "safe to apply" (executable: true) when:
// - the inspector never actually reached the host, so drift is unknown
//   for an existing installation (bootstrap without observation never
//   reaches here at all - resolveBaseline refuses it earlier);
// - a migration would skip schema versions;
// - Docker has drifted from the last-applied state in a way this plan
//   was not explicitly told to repair.
function computeBlockers({ baseline, observation, migrationBlockers, drift, repairDrift }) {
  const blockers = [...migrationBlockers];
  if (baseline.mode === "applied" && observation.status !== "available") {
    blockers.push("observation unavailable - cannot verify current host state before planning changes to an existing installation");
  }
  if (!repairDrift) {
    for (const entry of drift) {
      if (entry.kind === "manual-change" || entry.kind === "unmanaged") {
        blockers.push(`${entry.resource}: ${entry.detail} (drift must be resolved, or an explicit repair authorized, before this plan can run)`);
      }
    }
  } else {
    // Even with repairDrift, an unmanaged resource is never silently
    // claimed - only a manual-change on a resource Hof already owns
    // gets folded into a repair.
    for (const entry of drift) {
      if (entry.kind === "unmanaged") blockers.push(`${entry.resource}: ${entry.detail} (unmanaged resources are never auto-adopted, even with repairDrift)`);
    }
  }
  return blockers;
}

// options: { baseline, desiredRendered, manifest, releaseLock, catalog,
//   observation: { status: "available" | "unavailable", resources: [] },
//   repairDrift = false }
export function buildPlan({ baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift = false }) {
  if (!observation || typeof observation.status !== "string" || !Array.isArray(observation.resources)) {
    throw new Error("buildPlan requires an explicit observation ({status, resources}) - it must never default to 'nothing is running'");
  }

  const desired = topologyToServiceState(desiredRendered, catalog, { manifest, releaseLock });
  const drift = computeDrift(baseline, observation);
  const { create, update, remove } = diffUnits(baseline, desired);

  if (observation.status === "available") {
    foldMissingIntoRepairs(desired, drift, create, update);
    if (repairDrift) foldManualChangeIntoRepairs(desired, drift, create, update);
  }

  const imageChangedUnits = new Set([...create, ...update].filter((entry) => entry.imageChanged).map((entry) => `${entry.service}/${entry.unit}`));
  const needingMigration = servicesNeedingMigration(baseline, desired, imageChangedUnits, catalog);
  foldMigrationOnlyIntoUpdates(desired, needingMigration, create, update);

  const { operations: migrations, blockers: migrationBlockers, warnings: migrationWarnings, needsBackup } =
    migrationOperations(baseline, desired, desiredRendered, needingMigration);

  const operations = buildOperations({ baseline, desired, create, update, remove, migrations, needsBackup, catalog });
  const migrateCount = operations.filter((operation) => operation.action === "database.migrate").length;

  const mode = baseline.mode === "bootstrap" ? "bootstrap" : "applied";
  const blockers = computeBlockers({ baseline, observation, migrationBlockers, drift, repairDrift });
  const driftWarnings = drift
    .filter((entry) => entry.kind === "manual-change" || entry.kind === "unmanaged")
    .map((entry) => `${entry.resource}: ${entry.detail}`);
  const warnings = [...driftWarnings, ...migrationWarnings];

  const plan = {
    apiVersion: "hof.dev/plan/v1",
    mode,
    executable: blockers.length === 0,
    baseline,
    desired,
    drift,
    summary: { create: create.length, update: update.length, remove: remove.length, migrate: migrateCount },
    operations,
    warnings,
    blockers,
  };

  return { ...plan, planId: sha256(Buffer.from(JSON.stringify(plan))) };
}
