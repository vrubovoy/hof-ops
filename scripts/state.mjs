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
    mode: "bootstrap", generation: 0, release: null, installationId: null,
    manifestDigest: null, releaseLockDigest: null, topologyDigest: null,
    services: {}, volumes: [], networks: [], generatedArtifacts: {},
    retainedServices: {}, suppliedTlsCertificateFingerprint: null, suppliedTlsPrivateKeyFingerprint: null,
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
// capture at all (it's a bind-mounted file, not an env var) - and, item
// 9 (ADR 0005), the supplied TLS certificate/private-key fingerprint:
// Caddy only ever references a FIXED target-side path for a supplied
// certificate, never its content, so the Caddyfile's own text stays
// byte-identical across a real certificate rotation - without folding
// the fingerprint in here too, a workstation-side cert/key swap with no
// other config change would be invisible to this whole diff, exactly
// the "rotation looks like a no-op" gap a further review found.
function unitConfigFingerprint(definition, unit, rendered, suppliedTlsFingerprint) {
  const stableLabels = definition.labels
    ? Object.fromEntries(Object.entries(definition.labels).filter(([key]) => !FINGERPRINT_EXCLUDED_LABELS.has(key)))
    : definition.labels;
  const stableDefinition = { ...definition, labels: stableLabels };
  return sha256(Buffer.from(stableStringify({
    definition: stableDefinition,
    caddyfile: unit === "gateway" ? rendered.caddyfile : undefined,
    suppliedTls: unit === "gateway" ? suppliedTlsFingerprint : undefined,
  })));
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
// suppliedTlsCertificateFingerprint/suppliedTlsPrivateKeyFingerprint
// (item 9, ADR 0005): only ever given for the DESIRED side (a fresh
// read+hash of the operator's own certificate/private-key files right
// now, exactly like buildPlanV2's own top-level suppliedTls already
// does) - a baseline loaded from a past current.json trusts its own
// recorded value instead (see resolveBaseline), the same manifestDigest/
// releaseLockDigest pattern this function already established.
export function topologyToServiceState(rendered, catalog, { manifest, releaseLock, suppliedTlsCertificateFingerprint, suppliedTlsPrivateKeyFingerprint } = {}) {
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

  const suppliedTlsFingerprint = suppliedTlsCertificateFingerprint !== undefined || suppliedTlsPrivateKeyFingerprint !== undefined
    ? { certificateFingerprint: suppliedTlsCertificateFingerprint ?? null, privateKeyFingerprint: suppliedTlsPrivateKeyFingerprint ?? null }
    : undefined;
  for (const [unit, definition] of Object.entries(rendered.compose.services)) {
    const serviceId = definition.labels?.["hof.service"];
    const artifactId = definition.labels?.["hof.artifact"];
    if (!serviceId || !artifactId || !services[serviceId]) continue;
    services[serviceId].units[unit] = { artifact: artifactId, image: definition.image, configFingerprint: unitConfigFingerprint(definition, unit, rendered, suppliedTlsFingerprint) };
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
    // Unlike volumes, a missing network is safe to just recreate
    // (stateless infrastructure) - plan.mjs still needs to know what's
    // expected to tell "recreate this" apart from "this was never ours".
    networks: Object.keys(rendered.compose.networks).sort(),
    suppliedTlsCertificateFingerprint: suppliedTlsCertificateFingerprint ?? null,
    suppliedTlsPrivateKeyFingerprint: suppliedTlsPrivateKeyFingerprint ?? null,
  };
}

function validateObservation(observation) {
  const required = [
    "containersStatus", "resources", "volumesStatus", "volumes", "networksStatus", "networks",
    "generatedArtifactsStatus", "generatedArtifacts",
  ];
  const ok = observation
    && required.every((key) => key in observation)
    && ["containersStatus", "volumesStatus", "networksStatus", "generatedArtifactsStatus"].every((key) => typeof observation[key] === "string")
    && ["resources", "volumes", "networks"].every((key) => Array.isArray(observation[key]))
    && typeof observation.generatedArtifacts === "object" && observation.generatedArtifacts !== null;
  if (!ok) {
    throw new Error(
      "resolveBaseline requires an explicit observation ({containersStatus, resources, volumesStatus, volumes, " +
      "networksStatus, networks, generatedArtifactsStatus, generatedArtifacts}) - it must never default to 'nothing is running'",
    );
  }
}

// The single decision point PLATFORM-OPS-PLAN.md describes: state
// present -> use it; state absent and observation confirms every
// resource kind (containers/volumes/networks) is both inspectable and
// clean -> the synthetic bootstrap baseline; state absent but any kind
// couldn't be inspected, or any of them already holds a resource
// labeled for Hof, -> refuse (hofctl adopt is the only sanctioned
// recovery, not implemented here) rather than guess.
//
// managedState is TargetInspector's own snapshot.managedState
// ({current, topology}, either already-parsed JSON or null) - current
// present with topology absent, or topology present with current
// absent, are BOTH corrupt state, not "never applied" (a topology.json
// left behind by a wiped current.json is exactly as untrustworthy as
// the reverse). observation must be explicit - there is no default,
// because "the inspector didn't run" and "the inspector confirmed
// nothing is there" are two different facts and must never be
// conflated into the same silent assumption. catalog is needed only to
// shape topology.json back into the {services, volumes} baseline via
// topologyToServiceState.
export function resolveBaseline({ managedState, catalog, observation }) {
  validateObservation(observation);

  const current = managedState?.current ?? null;
  const topology = managedState?.topology ?? null;
  if (current && !topology) {
    throw new Error("managed state has current.json but no topology.json - state directory is corrupt, cannot compute a baseline");
  }
  if (topology && !current) {
    throw new Error("managed state has topology.json but no current.json - state directory is corrupt (a prior installation's leftover?), cannot compute a baseline");
  }

  if (current) {
    // Item 9 (ADR 0005): the baseline's own gateway configFingerprint
    // must be recomputed with the SAME supplied-TLS fingerprint that was
    // actually current when this generation was committed - otherwise
    // every single plan against a supplied-TLS installation would show a
    // spurious gateway diff (baseline computed as if suppliedTls were
    // absent, desired computed with the real, current fingerprint),
    // breaking the no-op invariant for any installation using supplied
    // TLS at all. A real certificate/key rotation still registers as a
    // genuine diff: buildPlan's own desired-side topologyToServiceState
    // call is given the FRESH fingerprint read off disk at planning
    // time, not this recorded one.
    const serviceState = topologyToServiceState(topology, catalog, {
      suppliedTlsCertificateFingerprint: current.suppliedTlsCertificateFingerprint ?? undefined,
      suppliedTlsPrivateKeyFingerprint: current.suppliedTlsPrivateKeyFingerprint ?? undefined,
    });
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
    // Item 9 (ADR 0005): a retained service's own volume is deliberately
    // folded in here, not just left to serviceState.volumes above -
    // topologyToServiceState() only ever derives volumes from the
    // rendered Compose (a disabled service renders no volume at all), so
    // without this a retained-but-currently-disabled service's own real,
    // still-existing volume would look "missing" to computeMissingResources
    // the moment it's no longer mounted by a running container, even
    // though it was never actually removed.
    const retainedServices = current.retainedServices ?? {};
    const volumes = [...new Set([...serviceState.volumes, ...Object.values(retainedServices).map((entry) => entry.volume)])].sort();
    return {
      mode: "applied",
      generation: current.generation,
      installationId: current.installationId,
      // manifestDigest/releaseLockDigest can't be recomputed from a saved
      // topology.json alone (the original files aren't kept) - trusted
      // from current.json's own record, exactly as apply wrote them.
      manifestDigest: current.manifestDigest ?? null,
      releaseLockDigest: current.releaseLockDigest ?? null,
      topologyDigest: serviceState.topologyDigest,
      release: serviceState.release,
      services: serviceState.services,
      volumes,
      networks: serviceState.networks,
      generatedArtifacts: current.generatedArtifacts ?? {},
      retainedServices,
      suppliedTlsCertificateFingerprint: current.suppliedTlsCertificateFingerprint ?? null,
      suppliedTlsPrivateKeyFingerprint: current.suppliedTlsPrivateKeyFingerprint ?? null,
    };
  }

  // "absent" (Docker genuinely isn't installed on this host at all) is
  // just as good as "available and empty" for bootstrap eligibility -
  // there is trivially nothing that could be a leftover managed
  // resource. Only "unavailable" (installed but couldn't be safely
  // inspected) still fails closed. See ADR 0004's "Docker Absent" rules.
  const ACCEPTABLE_FOR_BOOTSTRAP = new Set(["available", "absent"]);
  const availability = [observation.containersStatus, observation.volumesStatus, observation.networksStatus];
  if (availability.some((status) => !ACCEPTABLE_FOR_BOOTSTRAP.has(status))) {
    throw new Error(
      "cannot confirm this host has no existing managed resources - containers/volumes/networks observation " +
      "is not all available or positively confirmed absent, refusing to assume a clean bootstrap",
    );
  }
  const anyManaged = [...observation.resources, ...observation.volumes, ...observation.networks].some((entry) => entry.managed);
  if (anyManaged) {
    throw new Error(
      "managed resources (containers, volumes, or networks) exist but the authoritative state is missing - " +
      "refusing to guess at a baseline. This needs a typed recovery operation " +
      "(hofctl adopt, not implemented yet), not an automatic adoption.",
    );
  }
  return emptyBaseline();
}
