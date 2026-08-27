// hofctl plan's baseline: the last-applied deployment state, read from
// /var/lib/hof/state - and the bootstrap/fail-closed rules for when it's
// missing (see PLATFORM-OPS-PLAN.md's hofctl plan design). hofctl apply
// (out of scope for delivery item 7) is the only thing that ever writes
// these files; this module only reads them.

import { readFile } from "node:fs/promises";
import path from "node:path";

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

// A unit's full rendered Compose definition, not just its image - a
// domain/CORS/browserPush/TLS-driven environment change must register as
// a real diff even when the pinned image tag didn't move. The gateway
// unit additionally folds in the rendered Caddyfile, since that's the
// one generated artifact a Compose service definition alone doesn't
// capture at all (it's a bind-mounted file, not an env var).
function unitConfigFingerprint(definition, unit, rendered) {
  return sha256(Buffer.from(stableStringify({ definition, caddyfile: unit === "gateway" ? rendered.caddyfile : undefined })));
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

async function readJsonIfExists(filePath) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw new Error(`could not read ${filePath}: ${error.message}`);
  }
}

// Loads the real on-disk baseline, or null if this host has never had a
// successful apply. Distinct from resolveBaseline() below: this function
// alone can't decide whether a missing state directory is fine
// (genuinely never applied) or a fail-closed adoption refusal (Docker
// already has managed resources) - it only knows what's on disk.
export async function loadState(statePath) {
  const current = await readJsonIfExists(path.join(statePath, "current.json"));
  if (!current) return null;
  const topology = await readJsonIfExists(path.join(statePath, "topology.json"));
  if (!topology) {
    throw new Error(`${statePath}/current.json exists but topology.json is missing - state directory is corrupt, cannot compute a baseline`);
  }
  return { current, topology };
}

// The single decision point PLATFORM-OPS-PLAN.md describes: state
// present -> use it; state absent and observation confirms Docker
// already holds resources labeled for this installation -> refuse
// (hofctl adopt is the only sanctioned recovery, not implemented here);
// state absent and observation confirms Docker is clean -> the
// synthetic bootstrap baseline. observation must be explicit
// ({status, resources}) - there is no default, because "the inspector
// didn't run" and "the inspector confirmed nothing is there" are two
// different facts and must never be conflated into the same silent
// assumption. catalog is needed only to shape topology.json back into
// the {services, volumes} baseline via topologyToServiceState.
export async function resolveBaseline({ statePath, catalog, observation }) {
  if (!observation || typeof observation.status !== "string" || !Array.isArray(observation.resources)) {
    throw new Error("resolveBaseline requires an explicit observation ({status, resources}) - it must never default to 'nothing is running'");
  }

  const state = await loadState(statePath);
  if (state) {
    const serviceState = topologyToServiceState(state.topology, catalog);
    // current.json's own recorded topologyDigest should always match a
    // fresh recompute from the topology.json saved alongside it - if it
    // doesn't, the state directory was corrupted or hand-edited after
    // the fact, and this baseline can't be trusted.
    if (state.current.topologyDigest && state.current.topologyDigest !== serviceState.topologyDigest) {
      throw new Error(
        `${statePath}/current.json's topologyDigest does not match a fresh digest of the saved topology.json - ` +
        "state directory is corrupt or was hand-edited, cannot compute a baseline",
      );
    }
    return {
      mode: "applied",
      generation: state.current.generation,
      // manifestDigest/releaseLockDigest can't be recomputed from a saved
      // topology.json alone (the original files aren't kept) - trusted
      // from current.json's own record, exactly as apply wrote them.
      manifestDigest: state.current.manifestDigest ?? null,
      releaseLockDigest: state.current.releaseLockDigest ?? null,
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
