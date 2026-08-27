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

// Compares two {services, volumes} snapshots artifact by artifact.
// Absent-or-disabled is treated identically ("nothing here") on both
// sides, so enabling a service that was merely disabled (not entirely
// unknown to the catalog) diffs the same way as one that's brand new.
function diffArtifacts(baseline, desired) {
  const create = [];
  const update = [];
  const remove = [];
  const serviceIds = new Set([...Object.keys(baseline.services), ...Object.keys(desired.services)]);

  for (const service of serviceIds) {
    const b = baseline.services[service]?.enabled ? baseline.services[service] : { artifacts: {} };
    const d = desired.services[service]?.enabled ? desired.services[service] : { artifacts: {} };
    const artifacts = new Set([...Object.keys(b.artifacts), ...Object.keys(d.artifacts)]);
    for (const artifact of artifacts) {
      const from = b.artifacts[artifact];
      const to = d.artifacts[artifact];
      if (to && !from) create.push({ service, artifact, image: to.image });
      else if (to && from && to.image !== from.image) update.push({ service, artifact, fromImage: from.image, toImage: to.image, reason: "image changed" });
      else if (!to && from) remove.push({ service, artifact, image: from.image });
    }
  }
  return { create, update, remove };
}

// A no-op re-apply must still notice a container that vanished out from
// under it (the reconciler's "interrupted operation can be safely
// resumed" and "no-op only when nothing actually needs doing" properties
// both depend on this) - folds any "missing" drift for a still-desired
// artifact into the update set as a repair, even though desired and
// baseline agree on the image.
function foldMissingIntoRepairs(desired, drift, create, update) {
  const alreadyTouched = new Set([...create, ...update].map((entry) => `${entry.service}/${entry.artifact}`));
  for (const entry of drift) {
    if (entry.kind !== "missing") continue;
    const [service, artifact] = entry.resource.split("/");
    if (alreadyTouched.has(entry.resource)) continue;
    const image = desired.services[service]?.artifacts?.[artifact]?.image;
    if (!image) continue;
    update.push({ service, artifact, fromImage: image, toImage: image, reason: "repair: container missing" });
    alreadyTouched.add(entry.resource);
  }
}

// baseline vs what's actually observed running - independent of what's
// now desired, so "services.yml changed" and "someone touched Docker by
// hand" stay distinguishable (see PLATFORM-OPS-PLAN.md).
function computeDrift(baseline, observedResources) {
  const drift = [];
  const observedByKey = new Map(observedResources.map((resource) => [`${resource.service}/${resource.artifact}`, resource]));
  const baselineKeys = new Set();

  for (const [service, definition] of Object.entries(baseline.services)) {
    if (!definition.enabled) continue;
    for (const [artifact, expected] of Object.entries(definition.artifacts)) {
      const key = `${service}/${artifact}`;
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

  for (const resource of observedResources) {
    const key = `${resource.service}/${resource.artifact}`;
    if (!baselineKeys.has(key)) drift.push({ resource: key, kind: "unmanaged", detail: "running, but not recorded in the last-applied state" });
  }

  return drift;
}

function migrationOperations(baseline, desired, desiredRendered, catalog, create, update) {
  const touchedServices = new Set([...create, ...update].map((entry) => entry.service));
  const operations = [];
  for (const service of catalog.services) {
    if (!service.database || !desired.services[service.id]?.enabled) continue;
    const wasEnabled = baseline.services[service.id]?.enabled === true;
    const schemaChanged = baseline.services[service.id]?.schemaVersion !== desired.services[service.id]?.schemaVersion;
    if (!wasEnabled || schemaChanged || touchedServices.has(service.id)) {
      const image = desired.services[service.id].artifacts[service.database.component]?.image;
      // The release lock's own declared from/to/rollbackCompatible for
      // this component (see catalog/services-v1.yaml's database.command
      // comment and the release-lock schema) - real per-component data,
      // not inferred from baseline's own possibly-stale record.
      const schema = desiredRendered.topology.databaseSchemas[service.id];
      operations.push({
        id: `database.migrate.${service.id}`,
        phase: "database",
        action: "database.migrate",
        resource: service.database.component,
        ...(image ? { image } : {}),
        schema: { from: schema.from, to: schema.to, rollbackCompatible: schema.rollbackCompatible },
        reason: !wasEnabled ? "initialize database" : schemaChanged ? "schema version changed" : "component image changed",
      });
    }
  }
  return operations;
}

function buildOperations({ baseline, desired, desiredRendered, catalog, create, update, remove }) {
  const operations = [];
  let sequence = 0;
  const next = (id, phase, action, resource, rest) => {
    sequence += 1;
    operations.push({ id: `${String(sequence).padStart(3, "0")}.${id}`, phase, action, resource, ...rest });
  };

  // Computed up front, not just from create/update/remove - a schema
  // version can change with no image change (a hypothetical, but a real
  // possibility given they're independent fields on the release lock),
  // and that alone must still trigger config.write/state.commit/etc.
  const migrations = migrationOperations(baseline, desired, desiredRendered, catalog, create, update);
  const anyChange = create.length + update.length + remove.length + migrations.length > 0;
  if (baseline.mode === "bootstrap" && anyChange) {
    next("host.prepare", "host", "host.prepare", "host", { reason: "first successful apply for this installation" });
    next("secret.ensure", "secret", "secret.ensure", "secrets.sops.yaml", { reason: "first successful apply for this installation" });
  }

  const newVolumes = desired.volumes.filter((volume) => !baseline.volumes.includes(volume));
  for (const volume of newVolumes) next(`volume.ensure.${volume}`, "volume", "volume.ensure", volume, { reason: "new persistent volume" });

  for (const entry of [...create, ...update]) {
    next(`image.verify.${entry.service}.${entry.artifact}`, "image", "image.verify", entry.artifact, { image: entry.image ?? entry.toImage, reason: "confirm the release-locked, hofctl validate-approved image" });
    next(`image.pull.${entry.service}.${entry.artifact}`, "image", "image.pull", entry.artifact, { image: entry.image ?? entry.toImage, reason: "pull the digest-pinned image" });
  }

  if (anyChange) next("config.write", "config", "config.write", "compose.yml", { reason: "regenerate Compose/Caddyfile/env from the current desired state" });

  for (const entry of update) next(`service.stop.${entry.service}.${entry.artifact}`, "service", "service.stop", entry.artifact, { reason: entry.reason });

  for (const entry of remove) {
    const service = catalog.services.find((candidate) => candidate.id === entry.service);
    if (service?.database) next(`backup.create.${entry.service}`, "backup", "backup.create", service.database.volume, { reason: "back up before removing a persistent service" });
    next(`service.stop.${entry.service}.${entry.artifact}`, "service", "service.stop", entry.artifact, { reason: "service disabled" });
  }

  for (const operation of migrations) {
    sequence += 1;
    operations.push({ ...operation, id: `${String(sequence).padStart(3, "0")}.${operation.id}` });
  }

  for (const entry of [...create, ...update]) {
    next(`service.start.${entry.service}.${entry.artifact}`, "service", "service.start", entry.artifact, { image: entry.image ?? entry.toImage, reason: entry.reason ?? "new artifact" });
    next(`readiness.wait.${entry.service}.${entry.artifact}`, "readiness", "readiness.wait", entry.artifact, { reason: "wait for the container to report healthy" });
  }

  if (anyChange) next("state.commit", "state", "state.commit", "state/current.json", { reason: "record this generation as last-applied, only after every prior operation succeeded" });

  return operations;
}

// options: { baseline, desiredRendered, catalog, observedResources = [] }
export function buildPlan({ baseline, desiredRendered, catalog, observedResources = [] }) {
  const desired = topologyToServiceState(desiredRendered, catalog);

  const drift = computeDrift(baseline, observedResources);
  const { create, update, remove } = diffArtifacts(baseline, desired);
  foldMissingIntoRepairs(desired, drift, create, update);

  const operations = buildOperations({ baseline, desired, desiredRendered, catalog, create, update, remove });
  const migrateCount = operations.filter((operation) => operation.action === "database.migrate").length;

  const mode = baseline.mode === "bootstrap" ? "bootstrap" : "applied";
  const blockers = [];
  const warnings = drift
    .filter((entry) => entry.kind === "manual-change" || entry.kind === "unmanaged")
    .map((entry) => `${entry.resource}: ${entry.detail}`);

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
