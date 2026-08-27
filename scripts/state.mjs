// hofctl plan's baseline: the last-applied deployment state, and the
// bootstrap/fail-closed rules for when it's missing (see
// PLATFORM-OPS-PLAN.md's hofctl plan design). Pure - takes managedState
// as already-parsed JSON (read target-side by target-probe.sh, as part
// of the same atomic snapshot TargetInspector collects everything else
// from) rather than touching a filesystem itself. There is no local
// file-reading helper here at all, even for --target-mode local -
// target-probe.sh reads /var/lib/hof/state/{current,topology}.json the
// same way over both transports, so this module never needs to know
// where the JSON came from.

import { sha256 } from "./digest.mjs";

export function emptyBaseline() {
  return {
    mode: "bootstrap", generation: 0, release: null,
    manifestDigest: null, releaseLockDigest: null, topologyDigest: null,
    services: {}, volumes: [],
  };
}

function stableStringify(value) {
  return JSON.stringify(value);
}

// Bookkeeping labels a real apply changes on every single run by design
// (the generation counter bumps every time, whether or not anything
// else did) - fingerprinting them would make every unit look "changed"
// on every apply, defeating the whole no-op guarantee. hof.installation-
// id is excluded too (fixed for the life of an installation in
// practice, but never something a *configuration* change legitimately
// touches). hof.service/hof.unit/hof.artifact/hof.managed stay in scope
// - they're stable identity, not per-apply bookkeeping.
const FINGERPRINT_EXCLUDED_LABELS = new Set(["hof.installation-id", "hof.generation"]);

// A unit's full rendered Compose definition, not just its image - a
// domain/CORS/browserPush/TLS-driven environment change must register as
// a real diff even when the pinned image tag didn't move. The gateway
// unit additionally folds in the rendered Caddyfile, since that's the
// one generated artifact a Compose service definition alone doesn't
// capture at all (it's a bind-mounted file, not an env var).
function unitConfigFingerprint(definition, unit, rendered) {
  const stableLabels = definition.labels
    ? Object.fromEntries(Object.entries(definition.labels).filter(([key]) => !FINGERPRINT_EXCLUDED_LABELS.has(key)))
    : definition.labels;
  const stableDefinition = { ...definition, labels: stableLabels };
  return sha256(Buffer.from(stableStringify({ definition: stableDefinition, caddyfile: unit === "gateway" ? rendered.caddyfile : undefined })));
}

// topologyToServiceState() is handed either a freshly rendered
// renderTopology() output (always well-formed) or a loaded, previously
// untrusted JSON blob (managedState.topology, over the wire from
// target-probe.sh). This is the state directory's own topology.json -
// deliberately NOT the same shape as `hofctl render`'s own topology.json
// output file (which is just the inner `.topology` object, for a
// different purpose - a human/installer-facing summary). A future
// hofctl apply must write the FULL wrapper ({compose, caddyfile,
// topology, backup, ...}) to /var/lib/hof/state/topology.json, or this
// throws a clear error instead of a confusing "cannot read properties
// of undefined" deep inside the loop below.
function assertRenderedShape(rendered) {
  if (
    !rendered || typeof rendered !== "object"
    || !rendered.compose || typeof rendered.compose.services !== "object"
    || typeof rendered.caddyfile !== "string"
    || !rendered.topology || !Array.isArray(rendered.topology.enabledServices)
    || !rendered.backup
  ) {
    throw new Error(
      "managed state's topology.json is not a full rendered-topology wrapper " +
      "({compose, caddyfile, topology, backup}) - it must never be just the inner " +
      "`topology` object (that shape is hofctl render's own output file, a different thing)",
    );
  }
}

// Turns a renderTopology() output into the same {services, volumes, ...}
// shape emptyBaseline() and loadState() both produce, so buildPlan can
// diff "desired" against either without caring which one it is. Reads
// Hof's own ownership labels (hof.service/hof.unit/hof.artifact) rather
// than re-deriving compose service names from the catalog's artifact
// list - Wächter's two containers share one catalog artifact but render
// as two separate units, and schlussel's naming has no service-id
// prefix at all; the labels are already the one place both are resolved.
// manifest/releaseLock are optional - only the "desired" side (built
// from the live files) can supply them; a baseline loaded from a past
// topology.json doesn't have the original files to hash, and trusts
// current.json's own recorded digests instead (see resolveBaseline).
export function topologyToServiceState(rendered, catalog, { manifest, releaseLock } = {}) {
  assertRenderedShape(rendered);
  const enabledIds = new Set(rendered.topology.enabledServices);
  const services = {};
  for (const service of catalog.services) {
    services[service.id] = { enabled: enabledIds.has(service.id), units: {} };
    // Only persistent services carry a schema version at all - plan.mjs's
    // migration decision needs last-applied vs desired to compare, and
    // this is the one place both baseline and desired go through, so
    // it's computed once here instead of twice.
    if (service.database) services[service.id].schemaVersion = rendered.topology.databaseSchemas?.[service.id]?.to ?? null;
  }

  for (const [unit, definition] of Object.entries(rendered.compose.services)) {
    const serviceId = definition.labels?.["hof.service"];
    const artifactId = definition.labels?.["hof.artifact"];
    if (!serviceId || !artifactId || !services[serviceId]) continue;
    services[serviceId].units[unit] = { artifact: artifactId, image: definition.image, configFingerprint: unitConfigFingerprint(definition, unit, rendered) };
  }

  return {
    release: rendered.topology.release,
    manifestDigest: manifest ? sha256(Buffer.from(stableStringify(manifest))) : null,
    releaseLockDigest: releaseLock ? sha256(Buffer.from(stableStringify(releaseLock))) : null,
    // Everything renderTopology() produces that ISN'T already covered by
    // a per-unit configFingerprint above - backup schedule/retention/
    // destinations have no Compose footprint of their own at all, so
    // without this a backup-only change would be invisible to the whole
    // diff, not just to one unit.
    topologyDigest: sha256(Buffer.from(stableStringify({ topology: rendered.topology, backup: rendered.backup, caddyfile: rendered.caddyfile }))),
    services,
    volumes: Object.keys(rendered.compose.volumes).sort(),
  };
}

// The single decision point PLATFORM-OPS-PLAN.md describes: state
// present -> use it; state absent and observation confirms Docker
// already holds resources labeled for this installation -> refuse
// (hofctl adopt is the only sanctioned recovery, not implemented here);
// state absent and observation confirms Docker is clean -> the
// synthetic bootstrap baseline.
//
// managedState is TargetInspector's own snapshot.managedState
// ({current, topology}, either already-parsed JSON or null) - current
// present with topology null is corrupt state, not "never applied".
// observation must be explicit ({status, resources}) - there is no
// default, because "the inspector didn't run" and "the inspector
// confirmed nothing is there" are two different facts and must never be
// conflated into the same silent assumption. catalog is needed only to
// shape topology.json back into the {services, volumes} baseline via
// topologyToServiceState.
export function resolveBaseline({ managedState, catalog, observation }) {
  if (!observation || typeof observation.status !== "string" || !Array.isArray(observation.resources)) {
    throw new Error("resolveBaseline requires an explicit observation ({status, resources}) - it must never default to 'nothing is running'");
  }

  const current = managedState?.current ?? null;
  const topology = managedState?.topology ?? null;
  if (current) {
    if (!topology) {
      throw new Error("managed state has current.json but no topology.json - state directory is corrupt, cannot compute a baseline");
    }
    const serviceState = topologyToServiceState(topology, catalog);
    // current.json's own recorded topologyDigest should always match a
    // fresh recompute from the topology.json saved alongside it - if it
    // doesn't, the state directory was corrupted or hand-edited after
    // the fact, and this baseline can't be trusted.
    if (current.topologyDigest && current.topologyDigest !== serviceState.topologyDigest) {
      throw new Error(
        "managed state's recorded topologyDigest does not match a fresh digest of its own saved topology.json - " +
        "state directory is corrupt or was hand-edited, cannot compute a baseline",
      );
    }
    return {
      mode: "applied",
      generation: current.generation,
      // manifestDigest/releaseLockDigest can't be recomputed from a saved
      // topology.json alone (the original files aren't kept) - trusted
      // from current.json's own record, exactly as apply wrote them.
      manifestDigest: current.manifestDigest ?? null,
      releaseLockDigest: current.releaseLockDigest ?? null,
      topologyDigest: serviceState.topologyDigest,
      release: serviceState.release,
      services: serviceState.services,
      volumes: serviceState.volumes,
    };
  }

  if (observation.status !== "available") {
    throw new Error("cannot confirm this host has no existing managed resources - observation is unavailable, refusing to assume a clean bootstrap");
  }
  if (observation.resources.some((resource) => resource.managed)) {
    throw new Error(
      "managed resources exist but the authoritative state is missing - " +
      "refusing to guess at a baseline. This needs a typed recovery operation " +
      "(hofctl adopt, not implemented yet), not an automatic adoption.",
    );
  }
  return emptyBaseline();
}
