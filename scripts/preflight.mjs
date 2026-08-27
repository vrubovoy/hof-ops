// hofctl preflight - pure evaluation over one TargetInspector snapshot
// (see PLATFORM-OPS-PLAN.md's hofctl plan design / TargetInspector
// review). Every host-level fact (OS/arch/CPU/RAM/disk/clock/sudo/
// ports/Docker/managed state) comes from that single atomic snapshot -
// this module itself never touches the target's filesystem, network
// sockets, or Docker socket directly. Only DNS resolution stays
// controller-local (it's asking whether the *internet* can find the
// target's declared hostname, which has nothing to do with the target
// host itself).

import dns from "node:dns/promises";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

import { publicHostnames } from "./render-topology.mjs";
import { resolveBaseline } from "./state.mjs";
import { inspectTarget } from "./target-inspector.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Conservative floors, not yet backed by a published sizing guide -
// override with --min-free-disk-gb/--min-memory-gb/--min-cpu-cores if a
// real deployment needs different numbers.
export const DEFAULT_THRESHOLDS = {
  minFreeDiskBytes: 20 * 1024 ** 3,
  minTotalMemoryBytes: 4 * 1024 ** 3,
  minCpuCores: 2,
};

// Matches the Ansible role's own stated platform support (item 5 of
// PLATFORM-OPS-PLAN.md's reconciliation ordering) - arm64 is explicitly
// out of scope for v1.
const SUPPORTED_OS = [
  { id: "debian", versionId: "12" },
  { id: "ubuntu", versionId: "24.04" },
];

function gib(bytes) {
  return (bytes / 1024 ** 3).toFixed(1);
}

function check(id, status, message) {
  return { id, status, message };
}

function failedResult(id, message) {
  return { checks: [check(id, "fail", message)], ok: false };
}

// A threshold that isn't a finite, non-negative number can't be
// compared against anything meaningfully - NaN in particular makes
// every `<` comparison false, which would silently turn "invalid input"
// into "check passes". Guarded here so every caller (CLI or library) is
// protected, not just hofctl.mjs's own argument parsing.
function validThreshold(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

export function checkTransport(snapshot) {
  const detail = snapshot.transport.trustDigest ? ` (${snapshot.transport.trustDigest})` : "";
  return check("transport", "pass", `verified ${snapshot.mode} connection${detail}`);
}

export function checkOs(snapshot) {
  const { id, versionId } = snapshot.host.os;
  const supported = SUPPORTED_OS.some((entry) => entry.id === id && entry.versionId === versionId);
  return supported
    ? check("os", "pass", `${id} ${versionId} is a supported platform`)
    : check("os", "fail", `${id} ${versionId} is not a supported platform (need Debian 12 or Ubuntu 24.04)`);
}

export function checkArchitecture(snapshot) {
  return snapshot.host.architecture === "x86_64"
    ? check("architecture", "pass", "x86_64")
    : check("architecture", "fail", `${snapshot.host.architecture ?? "unknown"} is not supported (need x86_64)`);
}

export function checkDisk(snapshot, minFreeDiskBytes) {
  if (!validThreshold(minFreeDiskBytes)) return check("disk", "unknown", `invalid disk threshold: ${minFreeDiskBytes}`);
  const freeBytes = snapshot.host.freeDiskBytes;
  if (freeBytes == null) return check("disk", "unknown", "could not determine free disk space on the target");
  if (freeBytes < minFreeDiskBytes) return check("disk", "fail", `/var/lib has ${gib(freeBytes)} GiB free, need at least ${gib(minFreeDiskBytes)} GiB`);
  return check("disk", "pass", `/var/lib has ${gib(freeBytes)} GiB free`);
}

export function checkMemory(snapshot, minTotalMemoryBytes) {
  if (!validThreshold(minTotalMemoryBytes)) return check("memory", "unknown", `invalid memory threshold: ${minTotalMemoryBytes}`);
  const totalBytes = snapshot.host.totalMemoryBytes;
  if (totalBytes == null) return check("memory", "unknown", "could not determine total memory on the target");
  if (totalBytes < minTotalMemoryBytes) return check("memory", "fail", `target has ${gib(totalBytes)} GiB RAM, need at least ${gib(minTotalMemoryBytes)} GiB`);
  return check("memory", "pass", `target has ${gib(totalBytes)} GiB RAM`);
}

export function checkCpu(snapshot, minCpuCores) {
  if (!validThreshold(minCpuCores)) return check("cpu", "unknown", `invalid CPU threshold: ${minCpuCores}`);
  const cpuCores = snapshot.host.cpuCores;
  if (cpuCores == null) return check("cpu", "unknown", "could not determine CPU core count on the target");
  if (cpuCores < minCpuCores) return check("cpu", "fail", `target has ${cpuCores} CPU core(s), need at least ${minCpuCores}`);
  return check("cpu", "pass", `target has ${cpuCores} CPU core(s)`);
}

export function checkClock(snapshot) {
  if (snapshot.host.clockSynchronized === null) return check("clock", "unknown", "could not determine NTP sync status on the target");
  return snapshot.host.clockSynchronized
    ? check("clock", "pass", "system clock is NTP-synchronized")
    : check("clock", "fail", "system clock is not NTP-synchronized");
}

export function checkSudo(snapshot) {
  return snapshot.host.sudoNonInteractive
    ? check("sudo", "pass", "passwordless sudo is available")
    : check("sudo", "fail", "passwordless sudo is not available - apply needs it for privileged host operations");
}

// free -> pass. occupied by a resource this installation's own
// current.json already claims (matching installationId, actually
// running) -> pass (a repeat apply must not treat its own gateway as a
// conflict). occupied by anything else - including another Hof
// installation's own gateway sharing this host - or unknown (can't
// determine either way) -> fail closed.
export function checkPort(snapshot, portNumber) {
  const entry = snapshot.ports.find((candidate) => candidate.port === portNumber);
  if (!entry || entry.state === "unknown") return check(`port-${portNumber}`, "unknown", `could not determine whether port ${portNumber} is in use`);
  if (entry.state === "free") return check(`port-${portNumber}`, "pass", `port ${portNumber} is free`);
  if (entry.owner && entry.owner !== "foreign") return check(`port-${portNumber}`, "pass", `port ${portNumber} is occupied by this installation's own ${entry.owner}`);
  return check(`port-${portNumber}`, "fail", `port ${portNumber} is already in use by something else - hofctl apply needs it free for the gateway`);
}

export function checkDocker(snapshot) {
  if (!snapshot.docker.engineAvailable) return check("docker", "fail", "Docker Engine is not reachable");
  if (!snapshot.docker.composeAvailable) return check("docker", "fail", "Docker Compose plugin is not available");
  // Engine/Compose can report available while a *listing* itself still
  // failed (a narrower, rarer permission gap, and one bad `docker
  // inspect` call taints the whole batch - see target-probe.sh) -
  // without this, that failure would look exactly like "Docker is fine
  // and nothing is running" everywhere downstream (managed-state, port
  // ownership, orphan volume/network detection, a future hofctl plan).
  const unavailable = ["containers", "volumes", "networks"].filter((kind) => snapshot.docker[`${kind}Status`] !== "available");
  if (unavailable.length > 0) return check("docker", "fail", `Docker is reachable but its ${unavailable.join("/")} listing could not be read`);
  return check("docker", "pass", "Docker Engine and the Compose plugin are both available");
}

// The full observation contract resolveBaseline()/buildPlan() require -
// built once here from the snapshot so preflight's own managed-state
// check and hofctl plan (see scripts/plan-command.mjs) always construct
// it identically, rather than each keeping its own copy that could
// silently drift apart.
export function observationFromSnapshot(snapshot) {
  return {
    containersStatus: snapshot.docker.containersStatus,
    resources: snapshot.docker.resources,
    volumesStatus: snapshot.docker.volumesStatus,
    volumes: snapshot.docker.volumes,
    networksStatus: snapshot.docker.networksStatus,
    networks: snapshot.docker.networks,
    generatedArtifactsStatus: snapshot.generatedArtifactsStatus,
    generatedArtifacts: snapshot.generatedArtifacts,
  };
}

// current.json/topology.json being unreadable (exists, but this
// connection couldn't read it even with sudo) is a distinct, more
// dangerous condition than genuinely absent - resolveBaseline() must
// never be handed a state file we merely *hope* is absent.
export function checkManagedStateReadable(snapshot) {
  const unreadable = [];
  if (snapshot.managedState.currentStatus === "unreadable") unreadable.push("current.json");
  if (snapshot.managedState.topologyStatus === "unreadable") unreadable.push("topology.json");
  if (unreadable.length > 0) {
    return check("managed-state-readable", "fail", `${unreadable.join(" and ")} exist but could not be read (even with sudo) - cannot tell whether this host has already been applied`);
  }
  return check("managed-state-readable", "pass", "managed state files are readable (or genuinely absent)");
}

// resolveBaseline() already encodes every remaining managed-state
// invariant that matters (corrupt state, fail-closed adoption refusal)
// - preflight just needs to surface whichever one fires as a normal
// check instead of a thrown exception. Only reached once
// checkManagedStateReadable() above has already confirmed neither file
// is in the ambiguous "unreadable" state.
export function checkManagedState(snapshot, catalog) {
  if (snapshot.managedState.currentStatus === "unreadable" || snapshot.managedState.topologyStatus === "unreadable") {
    return check("managed-state", "unknown", "skipped - managed state is unreadable (see managed-state-readable)");
  }
  try {
    resolveBaseline({ managedState: snapshot.managedState, catalog, observation: observationFromSnapshot(snapshot) });
    return check("managed-state", "pass", "managed state is consistent");
  } catch (error) {
    return check("managed-state", "fail", error instanceof Error ? error.message : String(error));
  }
}

export async function checkDns(hostnames, resolver = dns) {
  if (hostnames.length === 0) return check("dns", "pass", "no public hostnames to resolve");
  const failures = [];
  const notes = [];
  for (const hostname of hostnames) {
    try {
      await resolver.resolve4(hostname);
    } catch (error) {
      failures.push(`${hostname}: no A record (${error instanceof Error ? error.code ?? error.message : error})`);
    }
    try {
      await resolver.resolve6(hostname);
    } catch {
      // AAAA is informational only - IPv6 reachability isn't a platform
      // requirement (see PLATFORM-OPS-PLAN.md: DNS-01/IPv6-only support
      // is explicitly deferred), so a missing AAAA never fails preflight.
      notes.push(`${hostname}: no AAAA record (IPv6 disabled or unconfigured - not required)`);
    }
  }
  if (failures.length > 0) return check("dns", "fail", failures.join("; "));
  return check("dns", "pass", ["every public hostname resolves an A record", ...notes].join("; "));
}

// Compiled once and cached, not just the Ajv instance - Ajv refuses to
// compile the same schema $id twice on one instance, which a naive
// "cache the instance, recompile every call" version hits on the very
// second runPreflight() call in one process.
let manifestValidator;
async function validateManifestSchema(manifest) {
  manifestValidator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/services-v1alpha1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  if (!manifestValidator(manifest)) return manifestValidator.errors.map((error) => `services.yml${error.instancePath || "/"}: ${error.message}`);
  return [];
}

// publicHostnames() (used to build the DNS check below) walks the
// catalog's own service/hostname structure - an invalid catalog (a
// custom --catalog override, or simple corruption) must fail loudly
// here, not resolve to a confusing crash or a silently wrong hostname
// list.
let catalogValidator;
async function validateCatalogSchema(catalog) {
  catalogValidator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/service-catalog-v1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  if (!catalogValidator(catalog)) return catalogValidator.errors.map((error) => `catalog${error.instancePath || "/"}: ${error.message}`);
  return [];
}

// options: { manifestPath, catalogPath?, targetMode?, knownHostsFile?,
//   hostKeySha256?, identityFile?, connectTimeoutSeconds?, minFreeDiskBytes?,
//   minTotalMemoryBytes?, minCpuCores?, resolver?, inspect? }
export async function runPreflight(options) {
  const catalogPath = options.catalogPath ?? path.join(root, "catalog/services-v1.yaml");
  const [manifest, catalog] = await Promise.all([
    readFile(options.manifestPath, "utf8").then(YAML.parse),
    readFile(catalogPath, "utf8").then(YAML.parse),
  ]);

  // Schema validation happens before target.host/target.user/target.port
  // are ever used to build a real SSH command - target-inspector.mjs
  // validates its own inputs too (defense in depth), but an invalid
  // manifest must never even get that far.
  const manifestErrors = await validateManifestSchema(manifest);
  if (manifestErrors.length > 0) return failedResult("manifest", manifestErrors.join("; "));
  const catalogErrors = await validateCatalogSchema(catalog);
  if (catalogErrors.length > 0) return failedResult("catalog", catalogErrors.join("; "));

  const targetMode = options.targetMode ?? "ssh";
  const host = manifest.target?.host;
  const port = manifest.target?.port ?? 22;
  const user = manifest.target?.user;
  const inspect = options.inspect ?? inspectTarget;

  let snapshot;
  try {
    snapshot = await inspect({
      targetMode, host, port, user,
      knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
      identityFile: options.identityFile, connectTimeoutSeconds: options.connectTimeoutSeconds,
    });
  } catch (error) {
    const where = targetMode === "local" ? "the local host" : `${user}@${host}:${port}`;
    return failedResult("transport", `could not inspect ${where}: ${error instanceof Error ? error.message : error}`);
  }

  const thresholds = {
    minFreeDiskBytes: validThreshold(options.minFreeDiskBytes) ? options.minFreeDiskBytes : DEFAULT_THRESHOLDS.minFreeDiskBytes,
    minTotalMemoryBytes: validThreshold(options.minTotalMemoryBytes) ? options.minTotalMemoryBytes : DEFAULT_THRESHOLDS.minTotalMemoryBytes,
    minCpuCores: validThreshold(options.minCpuCores) ? options.minCpuCores : DEFAULT_THRESHOLDS.minCpuCores,
  };
  const hostnames = publicHostnames(manifest, catalog);

  const checks = [
    checkTransport(snapshot),
    checkOs(snapshot),
    checkArchitecture(snapshot),
    checkDisk(snapshot, thresholds.minFreeDiskBytes),
    checkMemory(snapshot, thresholds.minTotalMemoryBytes),
    checkCpu(snapshot, thresholds.minCpuCores),
    checkClock(snapshot),
    checkSudo(snapshot),
    checkPort(snapshot, 80),
    checkPort(snapshot, 443),
    checkDocker(snapshot),
    checkManagedStateReadable(snapshot),
    checkManagedState(snapshot, catalog),
    await checkDns(hostnames, options.resolver),
  ];

  // "unknown" fails closed - a host preflight can't tell an operator
  // "safe to proceed" about something it was unable to actually check.
  const ok = checks.every((entry) => entry.status === "pass");
  return { checks, ok, snapshot };
}
