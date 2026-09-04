// hofctl plan's pure core: given a baseline (last-applied state, or the
// synthetic bootstrap baseline), a freshly rendered desired topology,
// and what's actually observed running, produce the typed, ordered
// operation list described in PLATFORM-OPS-PLAN.md. No I/O here - state
// loading lives in state.mjs, host/Docker inspection is TargetInspector's
// job; this only ever computes from what it's handed, so it's the part
// every fixture (bootstrap/no-op/topology-change/drift/upgrade) can
// exercise directly.

import { sha256 } from "./digest.mjs";
import { WACHTER_INTERNAL_NETWORK_NAME } from "./render-topology.mjs";
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
// hand" stay distinguishable (see PLATFORM-OPS-PLAN.md). Only a
// resource whose own installationId matches baseline's own recorded one
// is ever treated as "ours" - a bare service/unit label match is not
// enough (a different Hof installation sharing this host, or one that
// simply forgot the hof.managed label, must never be mistaken for a
// resource this plan already owns). When containers couldn't even be
// listed, drift is simply not computed at all (the caller is expected
// to have already turned that into a blocker - see computeBlockers).
function computeDrift(baseline, observation) {
  if (observation.containersStatus !== "available") return [];
  const drift = [];
  const isOwn = (resource) => resource.managed && baseline.installationId !== null && resource.installationId === baseline.installationId;
  const ownByKey = new Map(observation.resources.filter(isOwn).map((resource) => [`${resource.service}/${resource.unit}`, resource]));
  const baselineKeys = new Set();

  for (const [service, definition] of Object.entries(baseline.services)) {
    if (!definition.enabled) continue;
    for (const [unit, expected] of Object.entries(definition.units)) {
      const key = `${service}/${unit}`;
      baselineKeys.add(key);
      const observed = ownByKey.get(key);
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
    if (isOwn(resource) && baselineKeys.has(key)) continue; // already accounted for above
    const detail = !resource.managed
      ? "running, but carries no hof.managed label"
      : !isOwn(resource)
        ? `running, but belongs to a different installation (${resource.installationId ?? "unlabeled"})`
        : "running, but not recorded in the last-applied state";
    drift.push({ resource: key, kind: "unmanaged", detail });
  }

  return drift;
}

// Same "ours" scoping as computeDrift, applied to the fixed-name
// compose volumes/networks. A missing volume is never auto-recreated
// (that would silently hand back an empty volume in place of one that
// may hold real data - see computeMissingVolumes below); a missing
// network is stateless infrastructure and safe to just recreate.
function computeMissingResources(baseline, kind, status, list) {
  if (status !== "available") return [];
  const ownNames = new Set(
    list.filter((entry) => entry.managed && baseline.installationId !== null && entry.installationId === baseline.installationId).map((entry) => entry.resource),
  );
  const expected = kind === "volume" ? baseline.volumes : baseline.networks;
  return expected.filter((name) => !ownNames.has(name));
}

// Compares baseline's own recorded checksums (from the last successful
// apply) against what's actually on disk right now, using each file's
// own present|absent|unreadable status (see target-inspector.mjs's
// parseGeneratedArtifacts) rather than just "is there a digest" - a
// positively-confirmed-absent file is auto-repairable (config.write
// regenerates it); a modified one is never silently overwritten; an
// unreadable one (exists, but couldn't be hashed even with sudo) is
// genuinely unknown territory - it might be exactly what baseline
// expects, might be hand-modified, might be about to be deleted - and
// must never be folded into "missing" just because there's no digest to
// compare (that would let a merely permission-walled file be silently
// regenerated as if it were confirmed gone). See computeBlockers/
// buildOperations for how each kind is actually handled.
function computeGeneratedDrift(baseline, observation) {
  if (observation.generatedArtifactsStatus !== "available") return [];
  const drift = [];
  for (const [filename, expectedDigest] of Object.entries(baseline.generatedArtifacts ?? {})) {
    if (!expectedDigest) continue;
    const observed = observation.generatedArtifacts?.[filename];
    if (!observed || observed.status === "unreadable") {
      drift.push({
        resource: `generated/${filename}`, kind: "generated-unreadable",
        detail: `expected sha256 ${expectedDigest}, could not be read (even with sudo) - refusing to guess whether it's missing or merely permission-walled`,
      });
    } else if (observed.status === "absent") {
      drift.push({ resource: `generated/${filename}`, kind: "generated-missing", detail: `expected sha256 ${expectedDigest}, file is missing` });
    } else if (observed.digest !== expectedDigest) {
      drift.push({ resource: `generated/${filename}`, kind: "generated-modified", detail: `expected sha256 ${expectedDigest}, observed ${observed.digest}` });
    }
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
//
// Item 9 (ADR 0005): a service being re-enabled from a RETAINED disable
// (baseline.retainedServices carries its own last-migrated schema
// version) needs no migration at all when that recorded version already
// matches what's now desired - re-running the initial migration against
// data that's already at the current schema would be wrong, not just
// redundant. A retained schema version that DISAGREES with desired can
// only happen via a release change, already refused elsewhere as
// upgrade scope (see computeUpgradeBlockers) - this is defensive, not a
// path a real plan can actually reach.
function servicesNeedingMigration(baseline, desired, imageChangedUnits, catalog) {
  return catalog.services.filter((service) => {
    if (!service.database || !desired.services[service.id]?.enabled) return false;
    const wasEnabled = baseline.services[service.id]?.enabled === true;
    const retained = baseline.retainedServices?.[service.id];
    const isRetainedReenable = !wasEnabled && retained && retained.schemaVersion === desired.services[service.id]?.schemaVersion;
    if (isRetainedReenable) return false;
    const schemaChanged = baseline.services[service.id]?.schemaVersion !== desired.services[service.id]?.schemaVersion;
    const unitEntry = Object.entries(desired.services[service.id].units).find(([, unit]) => unit.artifact === service.database.component);
    const componentImageChanged = unitEntry && imageChangedUnits.has(`${service.id}/${unitEntry[0]}`);
    return !wasEnabled || schemaChanged || componentImageChanged;
  });
}

// Item 9 (ADR 0005): release/schema/image changes to an ALREADY-enabled
// unit are out of this item's own scope - items 10/11's job. The
// primary check is release-level (this platform's own image/schema
// versions are always tied to a release as a whole, never bumped
// independently) - the per-unit check right after is defense in depth
// for the same invariant, never reachable on its own given the
// release-level check already ran, but cheap and exact. Deliberately
// compares fromImage !== toImage, NOT the entry's own imageChanged flag
// - a drift-repair fold (foldMissingIntoRepairs/foldManualChangeIntoRepairs)
// also sets imageChanged: true for a legitimate repair back to the
// SAME already-expected image (fromImage === toImage there), which must
// never be mistaken for an upgrade attempt. create entries are never
// checked here - a brand-new unit always uses the CURRENT release's own
// image by construction; that's a first enable, never an upgrade.
//
// A THIRD, independent check follows for schema version specifically -
// ADR 0005's own decision text calls out "release, schema version, or
// image" as three separate upgrade-scope dimensions, and while a real
// release always ties its schema versions to itself as a whole (so the
// release-level check above is the path that actually fires in
// practice), a bare schema bump with no accompanying release/image
// change must still be caught directly, not assumed unreachable - this
// is what keeps migrationOperations()'s own wasEnabled/needsBackup path
// genuinely dead code under item 9, as its own comment claims. A
// service that isn't enabled in BOTH baseline and desired is skipped
// here entirely - a first enable and a retained re-enable are never
// upgrades, whatever their schema version.
function computeUpgradeBlockers(baseline, desired, update, catalog) {
  const blockers = [];
  if (baseline.release !== null && desired.release !== baseline.release) {
    blockers.push(`release change (${baseline.release} -> ${desired.release}) is out of item 9's own scope - see ADR 0005, items 10-11`);
  }
  for (const entry of update) {
    if (entry.imageChanged && entry.fromImage !== entry.toImage) {
      blockers.push(`${entry.service}/${entry.unit}: image change on an already-enabled unit (${entry.fromImage} -> ${entry.toImage}) is out of item 9's own scope - see ADR 0005, items 10-11`);
    }
  }
  for (const service of catalog.services) {
    if (!service.database) continue;
    const wasEnabled = baseline.services[service.id]?.enabled === true;
    const stillEnabled = desired.services[service.id]?.enabled === true;
    const desiredSchema = desired.services[service.id]?.schemaVersion ?? null;
    if (wasEnabled && stillEnabled) {
      const baselineSchema = baseline.services[service.id]?.schemaVersion ?? null;
      if (baselineSchema !== null && desiredSchema !== null && baselineSchema !== desiredSchema) {
        blockers.push(`${service.id}: schema version change (${baselineSchema} -> ${desiredSchema}) on an already-enabled service is out of item 9's own scope - see ADR 0005, items 10-11`);
      }
      continue;
    }
    // Item 9 review fix (finding 5): re-enabling a service from a RETAINED
    // disable when its recorded retained schema version does NOT match
    // what's now desired. servicesNeedingMigration() only skips migration
    // for a retained re-enable when the two versions already agree; a
    // mismatch falls straight through and migrationOperations() emits an
    // EXECUTABLE database.migrate with reason "initialize database"
    // (wasEnabled is false, so its own from/to schema-skip guard never
    // fires) - which would run a fresh-install migration against real,
    // still-existing retained data that sits at a different schema. That
    // is a genuine data migration and belongs to items 10-11, exactly like
    // the enabled->enabled case just above. Block it here, before
    // migrationOperations() ever runs.
    if (!wasEnabled && stillEnabled) {
      const retained = baseline.retainedServices?.[service.id];
      if (retained && desiredSchema !== null && retained.schemaVersion !== desiredSchema) {
        blockers.push(`${service.id}: re-enabling a retained service whose recorded schema version (${retained.schemaVersion}) does not match the desired schema version (${desiredSchema}) would migrate real retained data - out of item 9's own scope, see ADR 0005, items 10-11`);
      }
    }
  }
  return blockers;
}

// Item 9 (ADR 0005): retain-only removal for a persistent (database-
// owning) service - never a silent default. Returns { blockers,
// retainedServices } - retainedServices is what desired.retainedServices
// will carry forward if this plan runs: baseline's own map, minus any
// service this plan is about to re-enable, plus a fresh entry for any
// service this plan is about to disable-with-retain. A stateless
// service's own removal is unaffected (never needs authorization, never
// enters retainedServices at all - there's no database to retain).
function computeRetainedServices(baseline, manifest, remove, create, catalog) {
  const blockers = [];
  const retainedServices = { ...(baseline.retainedServices ?? {}) };
  for (const entry of remove) {
    const service = catalog.services.find((candidate) => candidate.id === entry.service);
    if (!service?.database) continue; // stateless - nothing to retain, no authorization needed
    if (manifest.services?.[entry.service]?.dataRetention !== "retain") {
      blockers.push(`${entry.service}: disabling a persistent service requires services.${entry.service}.dataRetention: retain (see ADR 0005) - refusing to plan a silent, irreversible removal`);
      continue;
    }
    retainedServices[entry.service] = { volume: service.database.volume, schemaVersion: baseline.services[entry.service]?.schemaVersion ?? 0 };
  }
  // A service this plan is re-enabling (present in `create` - it was
  // disabled a moment ago) is no longer retained-and-disabled; it's
  // live again.
  for (const entry of create) {
    if (retainedServices[entry.service]) delete retainedServices[entry.service];
  }
  return { blockers, retainedServices };
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

// A generated-file repair (missing, or modified with repairDrift) folds
// the gateway unit into update too, whenever the Caddyfile itself is
// the file in question - a regenerated Caddyfile does nothing until the
// gateway actually restarts and reads it. No image change, just a
// config-reason restart.
function foldGatewayRestartForCaddyfile(desired, generatedDriftToRepair, create, update) {
  if (!generatedDriftToRepair.some((entry) => entry.resource === "generated/Caddyfile")) return;
  const touched = alreadyTouchedKeys(create, update);
  if (touched.has("tor/gateway")) return;
  const gatewayUnit = desired.services.tor?.units?.gateway;
  if (!gatewayUnit) return;
  update.push({
    service: "tor", unit: "gateway", artifact: gatewayUnit.artifact, fromImage: gatewayUnit.image, toImage: gatewayUnit.image,
    imageChanged: false, reason: "repair: Caddyfile was regenerated, gateway must restart to read it",
  });
}

function migrationOperations(baseline, desired, desiredRendered, needing) {
  const operations = [];
  const blockers = [];
  const warnings = [];

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
    // Item 9 (ADR 0005): a wasEnabled service reaching here at all means
    // computeUpgradeBlockers has already blocked this plan (any real
    // schema or image change on an already-enabled service is upgrade
    // scope, items 10-11) - so this migration is purely informational on
    // a non-executable plan, never something a real apply would run.
    // backup.create is gone entirely - it isn't in item 9's own applied
    // whitelist (scripts/applied-actions.mjs) and no item-9 path ever
    // runs a backup, blocked-and-informational or not.
  }
  return { operations, blockers, warnings };
}

// Item 9 review (operation ordering finding): orders `entries` (each a
// diffUnits()-shaped {service, unit, ...}) so that if entry A's own
// catalog service dependsOn entry B's own service, and BOTH are present
// in this exact list, B's own entry (or entries - a multi-unit service
// like schlussel+schlussel-frontend must have EVERY one of its own units
// sequenced first) comes before A's. A dependency NOT present in this
// list at all (already stable, untouched by this apply) imposes no
// constraint - only a dependency this SAME apply is itself
// creating/restarting can possibly still be down when a dependent
// unit's own readiness check runs. Stable: two entries with no
// dependency relationship between them keep their original relative
// order (Kahn's algorithm, always advancing the EARLIEST-appearing
// ready entry, never an arbitrary one) - every existing scenario with
// no cross-service dependency at play is byte-for-byte unaffected.
function topologicallySortByDependency(entries, catalog) {
  const dependsOnByService = new Map(catalog.services.map((service) => [service.id, service.dependsOn ?? []]));
  const servicesPresent = new Set(entries.map((entry) => entry.service));
  const inPlanDependencies = (entry) => (dependsOnByService.get(entry.service) ?? []).filter((serviceId) => servicesPresent.has(serviceId));

  const remaining = [...entries];
  const doneServices = new Set();
  const sorted = [];
  while (remaining.length > 0) {
    const readyIndex = remaining.findIndex((entry) => inPlanDependencies(entry).every((serviceId) => doneServices.has(serviceId)));
    // Every real dependsOn edge in this catalog is a genuine DAG (no
    // cycles, confirmed directly against catalog/services-v1.yaml) - an
    // apparent deadlock here is a real bug in the catalog itself
    // (a cycle), never something safe to silently paper over with an
    // arbitrary fallback order.
    if (readyIndex === -1) {
      throw new Error(`internal error: dependsOn cycle (or unresolvable ordering) prevents sequencing service.start for: ${remaining.map((entry) => `${entry.service}/${entry.unit}`).join(", ")}`);
    }
    const [entry] = remaining.splice(readyIndex, 1);
    sorted.push(entry);
    // Only "done" once EVERY one of this service's own units in this
    // exact list has been sequenced - a multi-unit service must have
    // ALL of its units resolved before anything depending on the
    // SERVICE (not just one specific unit) is unblocked.
    if (!remaining.some((other) => other.service === entry.service)) doneServices.add(entry.service);
  }
  return sorted;
}

// Item 9 (ADR 0005) reordered this: volume/network ensure, image
// verify/pull, THEN stop affected/removed units, THEN write the new
// desired config, THEN remove disabled units, THEN migrations, THEN
// start/readiness, THEN commit - config.write used to run BEFORE any
// stop at all, so the freshly-written compose.yml could momentarily
// describe a topology units still running under the OLD one hadn't
// caught up to yet. backup.create is gone entirely, from both the
// removal path AND the migration path (never in item 9's own action
// whitelist - see scripts/applied-actions.mjs and ADR 0005) - real
// again once items 10-11 relax it.
function buildOperations({ baseline, desired, create, update, remove, migrations, catalog, missingVolumes, missingNetworks, generatedDriftToRepair, secretsByUnit, allSecretNames }) {
  const operations = [];
  let sequence = 0;
  const next = (id, phase, action, resource, rest) => {
    sequence += 1;
    operations.push({ id: `${String(sequence).padStart(3, "0")}.${id}`, phase, action, resource, ...rest });
  };

  // Item 9 review fix (finding 6): the exact set of secret names this
  // plan's own secret.ensure is approved to (re)deliver. A bootstrap
  // delivers every required secret (first install). An applied plan
  // delivers ONLY the secrets consumed by units it actually starts,
  // restarts, or migrates ([...create, ...update] already covers every
  // such unit, including a migration's own component - see
  // foldMigrationOnlyIntoUpdates) - so an unrelated applied change (a
  // backup-schedule edit, a config-only tweak elsewhere) can never
  // silently overwrite a live secret whose consumers this plan never
  // touches, leaving them split across old and new values with no
  // coordinated restart.
  const scopedSecretNames = baseline.mode === "bootstrap"
    ? [...allSecretNames].sort()
    : [...new Set([...create, ...update].flatMap((entry) => secretsByUnit.get(entry.unit) ?? []))].sort();

  // topologyDigest covers backup schedule/retention/destinations and
  // anything else renderTopology() produces with no per-unit Compose
  // footprint at all (see topologyToServiceState) - without this, a
  // backup-only edit would leave anyChange false and never regenerate
  // anything, even though the desired state genuinely changed.
  const topologyChanged = baseline.topologyDigest !== desired.topologyDigest;
  const anyChange = create.length + update.length + remove.length + migrations.length + generatedDriftToRepair.length > 0
    || topologyChanged || missingNetworks.length > 0;
  if (anyChange) {
    if (baseline.mode === "bootstrap") {
      next("host.prepare", "host", "host.prepare", "host", { reason: "first successful apply for this installation" });
    }
    // Idempotent either way (the secret role's own copy loop over an
    // unchanged map is simply a no-op) - unconditional on anyChange for
    // BOTH modes now, not just bootstrap, so a newly-enabled service
    // that needs its own secret actually gets it. `secrets` scopes
    // exactly which values apply is approved to deliver (finding 6) - an
    // empty list on an applied change that restarts no secret-consuming
    // unit is legitimate and makes this a genuine no-op.
    next("secret.ensure", "secret", "secret.ensure", "secrets.sops.yaml", {
      secrets: scopedSecretNames,
      reason: baseline.mode === "bootstrap"
        ? "first successful apply for this installation"
        : scopedSecretNames.length > 0
          ? "deliver the secrets consumed by the units this change starts or restarts"
          : "no secret-consuming unit is started or restarted by this change - nothing to deliver",
    });
  }

  const newVolumes = desired.volumes.filter((volume) => !baseline.volumes.includes(volume));
  for (const volume of newVolumes) next(`volume.ensure.${volume}`, "volume", "volume.ensure", volume, { reason: "new persistent volume" });
  // A network is stateless - unlike a volume, a baseline-expected one
  // that's simply gone is safe to just recreate rather than block on.
  // Its own typed action (network.ensure), not volume.ensure reused - a
  // consumer that only knows how to act on the operation's own `action`
  // field (an apply executor, an audit log) must be able to tell "make
  // sure this named volume exists" and "make sure this named network
  // exists" apart without also reading `resource`/`reason` text.
  //
  // Item 9 review (network lifecycle finding): missingNetworks alone
  // (baseline-expected, but observed absent) used to be the WHOLE story
  // - a network newly required by the DESIRED topology that baseline
  // never expected at all (wachter-internal, the very first time
  // Wachter is enabled) got no network.ensure of its own, ever. Compose
  // itself then silently auto-created it as a NON-external network on
  // whatever unit's own `docker compose run` happened to need it first -
  // exactly the same "Compose thinks it owns this network" class of bug
  // the rest of this fix closes for the "hof" network. newNetworks below
  // closes the other half: desired's own network list, minus whatever
  // baseline already expected.
  const newNetworks = desired.networks.filter((network) => !baseline.networks.includes(network));
  const networksToEnsure = [...new Set([...missingNetworks, ...newNetworks])];
  for (const network of networksToEnsure) {
    next(`network.ensure.${network}`, "volume", "network.ensure", network, {
      reason: missingNetworks.includes(network) ? "recreate a missing network" : "new network",
      // Only wachter-internal is ever internal (no default route to the
      // outside world) - see render-topology.mjs's own
      // WACHTER_INTERNAL_NETWORK_NAME/physicalNetworkName() comments.
      // Omitted (never `false`) for every other network, matching this
      // schema's own "absent means false" convention for every other
      // optional operation field.
      ...(network === WACHTER_INTERNAL_NETWORK_NAME ? { internal: true } : {}),
    });
  }

  for (const entry of [...create, ...update].filter((entry) => entry.imageChanged)) {
    next(`image.verify.${entry.service}.${entry.unit}`, "image", "image.verify", entry.unit, { image: entry.image ?? entry.toImage, reason: "confirm the release-locked, hofctl validate-approved image" });
    next(`image.pull.${entry.service}.${entry.unit}`, "image", "image.pull", entry.unit, { image: entry.image ?? entry.toImage, reason: "pull the digest-pinned image" });
  }

  for (const entry of update) next(`service.stop.${entry.service}.${entry.unit}`, "service", "service.stop", entry.unit, { reason: entry.reason });
  for (const entry of remove) next(`service.stop.${entry.service}.${entry.unit}`, "service", "service.stop", entry.unit, { reason: "service disabled" });

  if (anyChange) next("config.write", "config", "config.write", "compose.yml", { reason: "regenerate Compose/Caddyfile/env from the current desired state" });

  for (const entry of remove) next(`service.remove.${entry.service}.${entry.unit}`, "service", "service.remove", entry.unit, { reason: "service disabled" });

  for (const operation of migrations) {
    sequence += 1;
    operations.push({ ...operation, id: `${String(sequence).padStart(3, "0")}.${operation.id}` });
  }

  // Item 9 review (operation ordering finding): a real, reproducible
  // deadlock a further review found - [...create, ...update] used to be
  // dispatched in that fixed, unconditional order. A brand new unit
  // (create) can have a real catalog dependsOn dependency that is
  // SIMULTANEOUSLY being restarted (update) by this very same apply -
  // e.g. herold (dependsOn: [tor, schlussel]) newly enabled, cascading a
  // CORS/ALLOWED_ORIGINS change into schlussel's own already-running
  // config, so schlussel gets its own update entry too. That dependency
  // was already stopped earlier (the update-only service.stop pass
  // above) and its own restart is itself an `update` entry, dispatched
  // AFTER every `create` entry in the old fixed order - so herold's own
  // readiness.wait (its real /ready check depends on reaching schlussel)
  // used to run, and exhaust its own full retry budget failing, WHILE
  // schlussel was still down, since schlussel's own restart had not even
  // been dispatched yet. Sorted here via a stable topological sort keyed
  // on the catalog's own dependsOn graph, restricted to dependencies
  // this SAME apply is actually touching (an already-stable, untouched
  // dependency imposes no ordering constraint at all) - every existing,
  // already-verified scenario with no such cross-service dependency
  // relationship keeps its own exact original relative order (see
  // topologicallySortByDependency()'s own comment).
  for (const entry of topologicallySortByDependency([...create, ...update], catalog)) {
    next(`service.start.${entry.service}.${entry.unit}`, "service", "service.start", entry.unit, { image: entry.image ?? entry.toImage, reason: entry.reason ?? "new unit" });
    // The gateway deliberately has no Compose healthcheck (see
    // render-topology.mjs's own comment on why) - it can only ever wait
    // for "running", never "healthy".
    const condition = entry.unit === "gateway" ? "running" : "healthy";
    next(`readiness.wait.${entry.service}.${entry.unit}`, "readiness", "readiness.wait", entry.unit, { condition, reason: `wait for the container to report ${condition}` });
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
//   was not explicitly told to repair;
// - a generated file was hand-modified (never silently overwritten,
//   even with repairDrift's own manual-change allowance - modified
//   generated files need their own explicit repair path);
// - a baseline-expected persistent volume is simply gone (never
//   silently replaced with an empty one).
function computeBlockers({ baseline, observation, migrationBlockers, drift, generatedDrift, repairDrift, missingVolumes, upgradeBlockers, retainBlockers }) {
  const blockers = [...migrationBlockers, ...upgradeBlockers, ...retainBlockers];
  if (baseline.mode === "applied" && observation.containersStatus !== "available") {
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
  for (const entry of generatedDrift) {
    if (entry.kind === "generated-modified" && !repairDrift) {
      blockers.push(`${entry.resource}: ${entry.detail} (a hand-modified generated file is never silently overwritten - pass --repair-drift to restore it)`);
    }
    // Unlike a positively-confirmed-missing file, an unreadable one is
    // never auto-repaired even with --repair-drift - it might not
    // actually be gone at all, and config.write would silently clobber
    // whatever's really there.
    if (entry.kind === "generated-unreadable") {
      blockers.push(`${entry.resource}: ${entry.detail}`);
    }
  }
  for (const volume of missingVolumes) {
    blockers.push(`${volume}: baseline expects this persistent volume but it's gone - refusing to silently create an empty replacement (this needs an explicit restore, not an apply)`);
  }
  return blockers;
}

// options: { baseline, desiredRendered, manifest, releaseLock, catalog,
//   observation: { containersStatus, resources, volumesStatus, volumes,
//     networksStatus, networks, generatedArtifactsStatus, generatedArtifacts },
//   repairDrift = false,
//   suppliedTlsCertificateFingerprint/suppliedTlsPrivateKeyFingerprint:
//     item 9 (ADR 0005) - only ever given for a real "supplied" tls
//     mode, threaded straight into desired's own topologyToServiceState()
//     call (see that function's own comment) and folded into the
//     gateway unit's own configFingerprint, so a workstation-side
//     certificate rotation registers as a real diff. }
export function buildPlan({ baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift = false, suppliedTlsCertificateFingerprint, suppliedTlsPrivateKeyFingerprint }) {
  const observationOk = observation
    && ["containersStatus", "volumesStatus", "networksStatus", "generatedArtifactsStatus"].every((key) => typeof observation[key] === "string")
    && ["resources", "volumes", "networks"].every((key) => Array.isArray(observation[key]))
    && observation.generatedArtifacts && typeof observation.generatedArtifacts === "object";
  if (!observationOk) {
    throw new Error(
      "buildPlan requires an explicit observation ({containersStatus, resources, volumesStatus, volumes, " +
      "networksStatus, networks, generatedArtifactsStatus, generatedArtifacts}) - it must never default to 'nothing is running'",
    );
  }

  const desired = topologyToServiceState(desiredRendered, catalog, { manifest, releaseLock, suppliedTlsCertificateFingerprint, suppliedTlsPrivateKeyFingerprint });
  const drift = computeDrift(baseline, observation);
  const generatedDrift = computeGeneratedDrift(baseline, observation);
  const missingVolumes = computeMissingResources(baseline, "volume", observation.volumesStatus, observation.volumes);
  const missingNetworks = computeMissingResources(baseline, "network", observation.networksStatus, observation.networks);
  const { create, update, remove } = diffUnits(baseline, desired);

  if (observation.containersStatus === "available") {
    foldMissingIntoRepairs(desired, drift, create, update);
    if (repairDrift) foldManualChangeIntoRepairs(desired, drift, create, update);
  }
  // Missing generated files are always auto-repaired (config.write is
  // idempotent and safe); a modified one only joins the repair once
  // repairDrift is explicitly given (otherwise it stays a blocker - see
  // computeBlockers).
  const generatedDriftToRepair = generatedDrift.filter((entry) => entry.kind === "generated-missing" || (entry.kind === "generated-modified" && repairDrift));
  foldGatewayRestartForCaddyfile(desired, generatedDriftToRepair, create, update);

  // Item 9 (ADR 0005): release/schema/image changes to an existing unit,
  // and retain-only removal for a persistent service - computed from
  // create/update/remove exactly as diffUnits (plus the folds above)
  // left them, before migration folding below adds anything further
  // (migration-only folds never set imageChanged: true, so they can
  // never trip the upgrade blocker; they're irrelevant to retention).
  const upgradeBlockers = computeUpgradeBlockers(baseline, desired, update, catalog);
  const { blockers: retainBlockers, retainedServices } = computeRetainedServices(baseline, manifest, remove, create, catalog);

  const imageChangedUnits = new Set([...create, ...update].filter((entry) => entry.imageChanged).map((entry) => `${entry.service}/${entry.unit}`));
  const needingMigration = servicesNeedingMigration(baseline, desired, imageChangedUnits, catalog);
  foldMigrationOnlyIntoUpdates(desired, needingMigration, create, update);

  const { operations: migrations, blockers: migrationBlockers, warnings: migrationWarnings } =
    migrationOperations(baseline, desired, desiredRendered, needingMigration);

  // Item 9 review fix (finding 6): unit -> secret names it consumes,
  // straight from the rendered Compose (wireSecret() adds each name to
  // the service's own `secrets:` list - see render-topology.mjs), so
  // buildOperations can scope secret.ensure to exactly the units this
  // plan restarts. allSecretNames is every file-based secret this
  // rendered topology declares.
  const secretsByUnit = new Map(
    Object.entries(desiredRendered.compose?.services ?? {}).map(([unit, definition]) => [unit, definition.secrets ?? []]),
  );
  const allSecretNames = Object.keys(desiredRendered.compose?.secrets ?? {});

  const operations = buildOperations({
    baseline, desired, create, update, remove, migrations, catalog,
    missingVolumes, missingNetworks, generatedDriftToRepair, secretsByUnit, allSecretNames,
  });
  const migrateCount = operations.filter((operation) => operation.action === "database.migrate").length;

  const mode = baseline.mode === "bootstrap" ? "bootstrap" : "applied";
  const blockers = computeBlockers({ baseline, observation, migrationBlockers, drift, generatedDrift, repairDrift, missingVolumes, upgradeBlockers, retainBlockers });
  const driftWarnings = drift
    .filter((entry) => entry.kind === "manual-change" || entry.kind === "unmanaged")
    .map((entry) => `${entry.resource}: ${entry.detail}`);
  const generatedDriftWarnings = generatedDrift.map((entry) => `${entry.resource}: ${entry.detail}`);
  const warnings = [...driftWarnings, ...generatedDriftWarnings, ...migrationWarnings];

  const plan = {
    apiVersion: "hof.dev/plan/v1",
    mode,
    executable: blockers.length === 0,
    baseline,
    desired: { ...desired, retainedServices },
    drift: [...drift, ...generatedDrift],
    summary: { create: create.length, update: update.length, remove: remove.length, migrate: migrateCount },
    operations,
    warnings,
    blockers,
  };

  return { ...plan, planId: sha256(Buffer.from(JSON.stringify(plan))) };
}
