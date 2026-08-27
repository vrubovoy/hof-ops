// Runs target-probe.sh (a single fixed, read-only, versioned script -
// never a caller-built command) against a target host, either over a
// strictly-verified SSH transport (production default) or locally
// (--target-mode local, dev/test only - never chosen automatically, even
// for a target.host of "localhost"). Returns one atomic snapshot: host
// facts, port state, whitelisted Docker resources, and this
// installation's managed state, all read in the same probe run so
// nothing can change between what preflight/plan separately look at.
//
// Deliberately exports nothing beyond inspectTarget() - no generic "run
// this command on the target" escape hatch. The probe script itself is
// the only thing that ever executes target-side.

import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROBE_PATH = path.join(root, "scripts/target-probe.sh");
const PROBE_VERSION = "HOF-PROBE-V3";

// Every singleton is now mandatory - the probe always emits exactly one
// of each, with an explicit "unknown"/status sentinel rather than
// omitting the record when a value can't be determined (see
// target-probe.sh). A record silently missing is a protocol violation,
// not "the host doesn't have that".
const SINGLETON_RECORDS = new Set([
  "os", "arch", "cpu", "memory", "disk", "clock", "sudo", "docker",
  "docker-containers-status", "docker-volumes-status", "docker-networks-status",
  "state-current-status", "state-current", "state-topology-status", "state-topology",
  "generated-artifacts-status", "generated-artifacts",
]);
const REPEATED_RECORDS = new Set(["port", "container", "volume", "network"]);
const KNOWN_RECORDS = new Set([...SINGLETON_RECORDS, ...REPEATED_RECORDS]);

// The exact order target-probe.sh's Go templates join fields in - both
// sides must agree on this, since \x1f-split output carries no field
// names of its own.
const CONTAINER_FIELDS = [
  "name", "image", "state", "health",
  "labelManaged", "labelInstallationId", "labelService", "labelUnit", "labelArtifact", "labelGeneration",
  "labelComposeProject", "labelComposeService",
  "networks", "volumes", "ports",
];
// Volumes/networks have no state/health/mounts of their own - just
// identity and ownership labels, enough to detect an orphaned Hof
// resource with no container currently referencing it.
const RESOURCE_FIELDS = ["name", "labelManaged", "labelInstallationId", "labelGeneration", "labelKind", "labelResource", "labelComposeProject"];

const AVAILABILITY_STATUSES = new Set(["available", "unavailable"]);
const STATE_FILE_STATUSES = new Set(["present", "absent", "unreadable"]);

function parseAvailabilityStatus(value, name) {
  if (!AVAILABILITY_STATUSES.has(value)) throw new Error(`probe record ${name} has an unrecognized status: ${JSON.stringify(value)}`);
  return value;
}

// A typo like "presnt" must never silently fall through to "absent" -
// only the exact three known values are accepted. status and payload
// are also cross-checked for consistency: "present" always carries a
// non-empty payload, "absent"/"unreadable" always carry an empty one -
// a mismatch is itself a protocol violation, not something to paper over.
function parseStateFileStatus(statusValue, payloadValue, statusName, payloadName) {
  if (!STATE_FILE_STATUSES.has(statusValue)) throw new Error(`probe record ${statusName} has an unrecognized status: ${JSON.stringify(statusValue)}`);
  if (statusValue === "present" && payloadValue.length === 0) throw new Error(`probe record ${statusName} is "present" but ${payloadName} is empty`);
  if (statusValue !== "present" && payloadValue.length > 0) throw new Error(`probe record ${statusName} is "${statusValue}" but ${payloadName} is unexpectedly non-empty`);
  return statusValue;
}

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
const STRICT_BASE64_LENGTH = (value) => value.length % 4 === 0;

// Matches services-v1alpha1.schema.json's own target.host (hostname
// format)/target.user (identifier pattern) exactly - validated again
// here, independent of whatever the caller already checked, because
// this module is the actual security boundary that turns these values
// into real argv tokens (see inspectSsh below). A value starting with
// "-" here becomes an OpenSSH *option*, not a destination, once handed
// to `ssh` as a bare positional argument - this is what actually closes
// that off, not just the schema.
const HOSTNAME_PATTERN = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;
const USERNAME_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;

function validateSshDestination(host, user, port) {
  if (typeof host !== "string" || !HOSTNAME_PATTERN.test(host)) {
    throw new Error(`refusing to connect: "${host}" is not a valid hostname`);
  }
  if (typeof user !== "string" || !USERNAME_PATTERN.test(user)) {
    throw new Error(`refusing to connect: "${user}" is not a valid SSH username`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`refusing to connect: ${port} is not a valid port number`);
  }
}

// The one real process-execution primitive, injectable as options.run so
// unit tests can assert on exact argv/stdin without a real SSH transport
// - see target-inspector.test.mjs. input is optional (ssh-keyscan takes
// none; ssh/sh both take the probe script over stdin).
function defaultRun(command, args, { input, timeout } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 8 * 1024 * 1024, timeout }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

// A real installation never has more than a few dozen containers - a
// bound here is a second, protocol-level backstop independent of
// execFile's own maxBuffer, against a compromised or simply broken probe
// flooding the parser with records.
const MAX_PROBE_LINES = 2000;

function decodeStrict(encoded, name) {
  if (!BASE64_PATTERN.test(encoded) || !STRICT_BASE64_LENGTH(encoded)) {
    throw new Error(`probe record ${name} is not valid base64`);
  }
  return Buffer.from(encoded, "base64").toString("utf8");
}

// Fails closed on anything that isn't exactly the fixed protocol -
// a truncated transcript, an unrecognized or missing record, a
// singleton that appeared twice, or a payload that isn't valid base64
// must never be silently interpreted as "the host is fine".
function parseProbeOutput(stdout) {
  const lines = stdout.split("\n").filter((line) => line.length > 0);
  if (lines.length > MAX_PROBE_LINES) {
    throw new Error(`probe output has ${lines.length} lines, more than the ${MAX_PROBE_LINES}-line bound - refusing to parse`);
  }
  if (lines[0] !== PROBE_VERSION) {
    throw new Error(`probe output does not start with the expected ${PROBE_VERSION} marker - refusing to trust a mismatched or corrupted transcript`);
  }
  if (lines.at(-1) !== "END") {
    throw new Error("probe output is truncated - missing the END terminator, refusing to trust a partial transcript");
  }

  const singles = {};
  const repeated = { port: [], container: [], volume: [], network: [] };
  for (const line of lines.slice(1, -1)) {
    const match = /^R (\S+) (.*)$/.exec(line);
    if (!match) throw new Error(`malformed probe protocol line: ${JSON.stringify(line)}`);
    const [, name, encoded] = match;
    if (!KNOWN_RECORDS.has(name)) throw new Error(`unknown probe record: ${name}`);
    const value = decodeStrict(encoded, name);
    if (SINGLETON_RECORDS.has(name)) {
      if (name in singles) throw new Error(`duplicate probe record: ${name}`);
      singles[name] = value;
    } else {
      repeated[name].push(value);
    }
  }

  for (const name of SINGLETON_RECORDS) {
    if (!(name in singles)) throw new Error(`missing mandatory probe record: ${name}`);
  }

  return { singles, ...repeated };
}

function parseNonNegativeIntegerOrUnknown(value, name) {
  if (value === "unknown") return null;
  if (!/^\d+$/.test(value)) throw new Error(`probe record ${name} is not a non-negative integer or "unknown": ${JSON.stringify(value)}`);
  return Number(value);
}

function parseContainerRecord(raw) {
  const fields = raw.split("\x1f");
  if (fields.length !== CONTAINER_FIELDS.length) {
    throw new Error(`probe container record has ${fields.length} fields, expected exactly ${CONTAINER_FIELDS.length}`);
  }
  const record = Object.fromEntries(CONTAINER_FIELDS.map((field, index) => [field, fields[index]]));
  const toList = (value) => value.split(",").map((entry) => entry.trim()).filter(Boolean);

  let generation = null;
  if (record.labelGeneration) {
    if (!/^\d+$/.test(record.labelGeneration)) throw new Error(`container ${record.name}: hof.generation label is not a non-negative integer: ${JSON.stringify(record.labelGeneration)}`);
    generation = Number(record.labelGeneration);
  }
  const ports = [...new Set(toList(record.ports).map((value) => {
    if (!/^\d+$/.test(value)) throw new Error(`container ${record.name}: published port ${JSON.stringify(value)} is not a number`);
    const port = Number(value);
    if (port < 1 || port > 65535) throw new Error(`container ${record.name}: published port ${port} is out of range`);
    return port;
  }))];

  return {
    unit: record.labelUnit || null,
    service: record.labelService || null,
    artifact: record.labelArtifact || null,
    installationId: record.labelInstallationId || null,
    generation,
    managed: record.labelManaged === "true",
    composeProject: record.labelComposeProject || null,
    composeService: record.labelComposeService || null,
    name: record.name.replace(/^\//, ""),
    image: record.image,
    state: record.state,
    health: record.health === "none" ? null : record.health,
    networks: toList(record.networks),
    volumes: toList(record.volumes),
    ports,
  };
}

function parseResourceRecord(raw, kindLabel) {
  const fields = raw.split("\x1f");
  if (fields.length !== RESOURCE_FIELDS.length) {
    throw new Error(`probe ${kindLabel} record has ${fields.length} fields, expected exactly ${RESOURCE_FIELDS.length}`);
  }
  const record = Object.fromEntries(RESOURCE_FIELDS.map((field, index) => [field, fields[index]]));

  let generation = null;
  if (record.labelGeneration) {
    if (!/^\d+$/.test(record.labelGeneration)) throw new Error(`${kindLabel} ${record.name}: hof.generation label is not a non-negative integer: ${JSON.stringify(record.labelGeneration)}`);
    generation = Number(record.labelGeneration);
  }

  return {
    name: record.name,
    managed: record.labelManaged === "true",
    installationId: record.labelInstallationId || null,
    generation,
    kind: record.labelKind || null,
    resource: record.labelResource || null,
    composeProject: record.labelComposeProject || null,
  };
}

const PORT_STATES = new Set(["free", "occupied", "unknown"]);

let stateSchemaValidator;
async function validateManagedCurrent(value) {
  if (value === null) return;
  // Compiled once and cached, not just the Ajv instance - Ajv refuses to
  // compile the same schema $id twice on one instance, which a naive
  // "cache the instance, recompile every call" version hits on the very
  // second snapshot in one process.
  stateSchemaValidator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/state-v1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  if (!stateSchemaValidator(value)) {
    throw new Error(`managed state's current.json does not satisfy schemas/state-v1.schema.json: ${JSON.stringify(stateSchemaValidator.errors)}`);
  }
}

async function buildSnapshot(mode, transport, stdout) {
  const { singles, port, container, volume, network } = parseProbeOutput(stdout);
  const resources = container.map(parseContainerRecord);
  const volumes = volume.map((raw) => parseResourceRecord(raw, "volume"));
  const networks = network.map((raw) => parseResourceRecord(raw, "network"));

  const [osId, osVersionId] = singles.os.split("|");
  const [dockerEngine, dockerCompose] = singles.docker.split("|");

  const currentStatus = parseStateFileStatus(singles["state-current-status"], singles["state-current"], "state-current-status", "state-current");
  const managedCurrent = currentStatus === "present" ? JSON.parse(singles["state-current"]) : null;
  await validateManagedCurrent(managedCurrent);
  const topologyStatus = parseStateFileStatus(singles["state-topology-status"], singles["state-topology"], "state-topology-status", "state-topology");
  const managedTopology = topologyStatus === "present" ? JSON.parse(singles["state-topology"]) : null;

  // Only a resource belonging to THIS installation (per the managed
  // state we just read) counts as "ours" for port-ownership purposes -
  // a different Hof installation's gateway sharing the same host must
  // never be mistaken for our own, and a fresh install with no recorded
  // installationId yet has no "ours" to match against at all.
  const selfInstallationId = managedCurrent?.installationId ?? null;

  const seenPorts = new Set();
  const ports = port.map((entry) => {
    const [portNumberRaw, state] = entry.split("|");
    if (!/^\d+$/.test(portNumberRaw)) throw new Error(`port record has a non-numeric port: ${JSON.stringify(portNumberRaw)}`);
    const portNumber = Number(portNumberRaw);
    if (portNumber < 1 || portNumber > 65535) throw new Error(`port record has an out-of-range port: ${portNumber}`);
    if (!PORT_STATES.has(state)) throw new Error(`port record has an unrecognized state: ${JSON.stringify(state)}`);
    if (seenPorts.has(portNumber)) throw new Error(`duplicate port record: ${portNumber}`);
    seenPorts.add(portNumber);

    let owner = null;
    if (state === "occupied") {
      const managedOwner = resources.find((resource) =>
        resource.managed
        && resource.state === "running"
        && selfInstallationId !== null
        && resource.installationId === selfInstallationId
        && resource.ports.includes(portNumber));
      owner = managedOwner ? managedOwner.unit : "foreign";
    }
    return { port: portNumber, state, owner };
  });

  return {
    mode,
    transport,
    host: {
      os: { id: osId, versionId: osVersionId },
      architecture: singles.arch,
      cpuCores: parseNonNegativeIntegerOrUnknown(singles.cpu, "cpu"),
      totalMemoryBytes: parseNonNegativeIntegerOrUnknown(singles.memory, "memory"),
      freeDiskBytes: parseNonNegativeIntegerOrUnknown(singles.disk, "disk"),
      clockSynchronized: singles.clock === "yes" ? true : singles.clock === "no" ? false : null,
      sudoNonInteractive: singles.sudo === "yes",
    },
    ports,
    docker: {
      engineAvailable: Boolean(dockerEngine),
      composeAvailable: Boolean(dockerCompose),
      containersStatus: parseAvailabilityStatus(singles["docker-containers-status"], "docker-containers-status"),
      resources,
      volumesStatus: parseAvailabilityStatus(singles["docker-volumes-status"], "docker-volumes-status"),
      volumes,
      networksStatus: parseAvailabilityStatus(singles["docker-networks-status"], "docker-networks-status"),
      networks,
    },
    managedState: {
      currentStatus,
      current: managedCurrent,
      topologyStatus,
      topology: managedTopology,
    },
    generatedArtifactsStatus: parseAvailabilityStatus(singles["generated-artifacts-status"], "generated-artifacts-status"),
    generatedArtifacts: JSON.parse(singles["generated-artifacts"]),
  };
}

const SSH_HARDENING = [
  "-o", "BatchMode=yes",
  "-o", "PasswordAuthentication=no",
  "-o", "KbdInteractiveAuthentication=no",
  "-o", "ClearAllForwardings=yes",
  "-o", "PermitLocalCommand=no",
  "-o", "RequestTTY=no",
  "-o", "ConnectionAttempts=1",
];

function sha256Fingerprint(base64Key) {
  const digest = createHash("sha256").update(Buffer.from(base64Key, "base64")).digest("base64");
  return "SHA256:" + digest.replace(/=+$/, "");
}

// Resolves exactly one trusted known_hosts line for this host/port -
// either the caller's own file (used as-is, untouched) or a freshly
// keyscanned key whose SHA256 fingerprint matches --host-key-sha256
// exactly. Never both, never neither (enforced by the caller).
async function resolveKnownHosts({ host, port, knownHostsFile, hostKeySha256, connectTimeoutSeconds, run }) {
  if (knownHostsFile) return { file: knownHostsFile, cleanup: async () => {} };

  const { stdout } = await run("ssh-keyscan", ["-p", String(port), "-T", String(connectTimeoutSeconds), "-t", "rsa,ed25519,ecdsa", host], {});
  const candidates = stdout.split("\n").filter((line) => line && !line.startsWith("#"));
  const match = candidates.find((line) => {
    const parts = line.trim().split(/\s+/);
    return parts.length >= 3 && sha256Fingerprint(parts[2]) === hostKeySha256;
  });
  if (!match) {
    throw new Error(`no host key offered by ${host}:${port} matches the expected fingerprint ${hostKeySha256} - refusing to connect`);
  }

  const file = path.join(tmpdir(), `hof-known-hosts-${randomUUID()}`);
  await writeFile(file, match + "\n", { mode: 0o600 });
  return { file, cleanup: () => unlink(file).catch(() => {}) };
}

function positiveIntegerOrDefault(value, fallback, name) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer, got ${JSON.stringify(value)}`);
  return value;
}

async function inspectSsh(options) {
  const {
    host, port = 22, user, knownHostsFile, hostKeySha256, identityFile,
    connectTimeoutSeconds, run = defaultRun,
  } = options;
  const timeout = positiveIntegerOrDefault(connectTimeoutSeconds, 10, "connectTimeoutSeconds");
  validateSshDestination(host, user, port);
  if (Boolean(knownHostsFile) === Boolean(hostKeySha256)) {
    throw new Error("exactly one of knownHostsFile or hostKeySha256 is required for SSH target inspection");
  }

  const { file: userKnownHostsFile, cleanup } = await resolveKnownHosts({ host, port, knownHostsFile, hostKeySha256, connectTimeoutSeconds: timeout, run });
  try {
    const probeScript = await readFile(PROBE_PATH, "utf8");
    const args = [
      ...SSH_HARDENING,
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${userKnownHostsFile}`,
      "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", `ConnectTimeout=${timeout}`,
      "-p", String(port),
      ...(identityFile ? ["-i", identityFile, "-o", "IdentitiesOnly=yes"] : []),
      // Ends option processing before the destination - a defense-in-
      // depth backstop alongside validateSshDestination() above, so a
      // value that somehow still started with "-" could never be
      // reinterpreted as another SSH option.
      "--",
      `${user}@${host}`,
      "sh", "-s",
    ];
    const { stdout } = await run("ssh", args, { input: probeScript, timeout: (timeout + 20) * 1000 });
    const trustDigest = knownHostsFile ? null : hostKeySha256;
    return await buildSnapshot("ssh", { verified: true, trustDigest }, stdout);
  } finally {
    await cleanup();
  }
}

async function inspectLocal(options) {
  const { run = defaultRun } = options;
  if (options.knownHostsFile || options.hostKeySha256 || options.identityFile) {
    throw new Error("--target-mode local does not accept SSH trust/identity options");
  }
  const probeScript = await readFile(PROBE_PATH, "utf8");
  const { stdout } = await run("sh", ["-s"], { input: probeScript, timeout: 30_000 });
  return await buildSnapshot("local", { verified: true, trustDigest: null }, stdout);
}

// options: { targetMode: "ssh" | "local", host, port, user, knownHostsFile,
//   hostKeySha256, identityFile, connectTimeoutSeconds, run? }
// run is an internal testing seam (see target-inspector.test.mjs) -
// hofctl itself never passes it, always getting the real process runner.
export async function inspectTarget(options) {
  return options.targetMode === "local" ? inspectLocal(options) : inspectSsh(options);
}
