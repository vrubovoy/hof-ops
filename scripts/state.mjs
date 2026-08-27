// hofctl plan's baseline: the last-applied deployment state, read from
// /var/lib/hof/state - and the bootstrap/fail-closed rules for when it's
// missing (see PLATFORM-OPS-PLAN.md's hofctl plan design). hofctl apply
// (out of scope for delivery item 7) is the only thing that ever writes
// these files; this module only reads them.

import { readFile } from "node:fs/promises";
import path from "node:path";

export function emptyBaseline() {
  return { mode: "bootstrap", generation: 0, release: null, services: {}, volumes: [] };
}

// Turns a renderTopology() output into the same {services, volumes}
// shape emptyBaseline() and loadState() both produce, so buildPlan can
// diff "desired" against either without caring which one it is. Reads
// Hof's own ownership labels (hof.service/hof.artifact) rather than
// re-deriving compose service names from the catalog's artifact list -
// Wächter's two containers share one catalog artifact but render as two
// differently-named Compose services (one of them renamed from its own
// artifact id), and schlussel's naming has no service-id prefix at all;
// the labels are already the one place that ambiguity is resolved.
export function topologyToServiceState(rendered, catalog) {
  const enabledIds = new Set(rendered.topology.enabledServices);
  const services = {};
  for (const service of catalog.services) {
    services[service.id] = { enabled: enabledIds.has(service.id), artifacts: {} };
    // Only persistent services carry a schema version at all - plan.mjs's
    // migration decision needs last-applied vs desired to compare, and
    // this is the one place both baseline (loaded from a saved
    // topology.json) and desired (freshly rendered) go through, so it's
    // computed once here instead of twice.
    if (service.database) services[service.id].schemaVersion = rendered.topology.databaseSchemas?.[service.id]?.to ?? null;
  }

  for (const definition of Object.values(rendered.compose.services)) {
    const serviceId = definition.labels?.["hof.service"];
    const artifactId = definition.labels?.["hof.artifact"];
    if (!serviceId || !artifactId || !services[serviceId]) continue;
    services[serviceId].artifacts[artifactId] = { image: definition.image };
  }

  return { release: rendered.topology.release, services, volumes: Object.keys(rendered.compose.volumes).sort() };
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
// present -> use it; state absent and Docker already holds resources
// labeled for this installation -> refuse (hofctl adopt is the only
// sanctioned recovery, not implemented here); state absent and Docker
// is clean -> the synthetic bootstrap baseline. catalog is needed only
// to shape topology.json back into the {services, volumes} baseline via
// topologyToServiceState.
export async function resolveBaseline({ statePath, catalog, hasManagedResources }) {
  const state = await loadState(statePath);
  if (state) {
    const serviceState = topologyToServiceState(state.topology, catalog);
    return { mode: "applied", generation: state.current.generation, ...serviceState };
  }
  if (hasManagedResources) {
    throw new Error(
      "managed resources exist but the authoritative state is missing - " +
      "refusing to guess at a baseline. This needs a typed recovery operation " +
      "(hofctl adopt, not implemented yet), not an automatic adoption.",
    );
  }
  return emptyBaseline();
}
