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

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROBE_PATH = path.join(root, "scripts/target-probe.sh");

const SINGLETON_RECORDS = new Set(["os", "arch", "cpu", "memory", "disk", "clock", "sudo", "docker", "state-current", "state-topology", "generated-artifacts"]);
const REPEATED_RECORDS = new Set(["port", "container"]);
const KNOWN_RECORDS = new Set([...SINGLETON_RECORDS, ...REPEATED_RECORDS]);

// The exact order target-probe.sh's Go template joins container fields
// in - both sides must agree on this, since \x1f-split output carries
// no field names of its own.
const CONTAINER_FIELDS = [
  "name", "image", "state", "health",
  "labelManaged", "labelInstallationId", "labelService", "labelUnit", "labelArtifact", "labelGeneration",
  "labelComposeProject", "labelComposeService",
  "networks", "volumes", "ports",
];

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

// Fails closed on anything that isn't exactly the fixed protocol -
// a truncated transcript, an unrecognized record, or a singleton that
// somehow appeared twice must never be silently interpreted as "the
// host is fine".
function parseProbeOutput(stdout) {
  const lines = stdout.split("\n").filter((line) => line.length > 0);
  if (lines.length > MAX_PROBE_LINES) {
    throw new Error(`probe output has ${lines.length} lines, more than the ${MAX_PROBE_LINES}-line bound - refusing to parse`);
  }
  if (lines[0] !== "HOF-PROBE-V1") {
    throw new Error("probe output does not start with the expected HOF-PROBE-V1 marker - refusing to trust a mismatched or corrupted transcript");
  }
  if (lines.at(-1) !== "END") {
    throw new Error("probe output is truncated - missing the END terminator, refusing to trust a partial transcript");
  }

  const singles = {};
  const port = [];
  const container = [];
  for (const line of lines.slice(1, -1)) {
    const match = /^R (\S+) (.*)$/.exec(line);
    if (!match) throw new Error(`malformed probe protocol line: ${JSON.stringify(line)}`);
    const [, name, encoded] = match;
    if (!KNOWN_RECORDS.has(name)) throw new Error(`unknown probe record: ${name}`);
    const value = Buffer.from(encoded, "base64").toString("utf8");
    if (SINGLETON_RECORDS.has(name)) {
      if (name in singles) throw new Error(`duplicate probe record: ${name}`);
      singles[name] = value;
    } else if (name === "port") port.push(value);
    else container.push(value);
  }
  return { singles, port, container };
}

function parseContainerRecord(raw) {
  const fields = raw.split("\x1f");
  const record = Object.fromEntries(CONTAINER_FIELDS.map((field, index) => [field, fields[index] ?? ""]));
  const toList = (value) => value.split(",").map((entry) => entry.trim()).filter(Boolean);
  return {
    unit: record.labelUnit || null,
    service: record.labelService || null,
    artifact: record.labelArtifact || null,
    installationId: record.labelInstallationId || null,
    generation: record.labelGeneration ? Number(record.labelGeneration) : null,
    managed: record.labelManaged === "true",
    composeProject: record.labelComposeProject || null,
    composeService: record.labelComposeService || null,
    name: record.name.replace(/^\//, ""),
    image: record.image,
    state: record.state,
    health: record.health === "none" ? null : record.health,
    networks: toList(record.networks),
    volumes: toList(record.volumes),
    // A HostPort can appear twice (IPv4 and IPv6 both bound) - dedupe.
    ports: [...new Set(toList(record.ports).map(Number))],
  };
}

function buildSnapshot(mode, transport, stdout) {
  const { singles, port, container } = parseProbeOutput(stdout);
  const resources = container.map(parseContainerRecord);

  const [osId, osVersionId] = (singles.os ?? "unknown|unknown").split("|");
  const [dockerEngine, dockerCompose] = (singles.docker ?? "|").split("|");

  const ports = port.map((entry) => {
    const [portNumber, state] = entry.split("|");
    let owner = null;
    if (state === "occupied") {
      const managedOwner = resources.find((resource) => resource.managed && resource.ports.includes(Number(portNumber)));
      owner = managedOwner ? managedOwner.unit : "foreign";
    }
    return { port: Number(portNumber), state, owner };
  });

  return {
    mode,
    transport,
    host: {
      os: { id: osId, versionId: osVersionId },
      architecture: singles.arch ?? null,
      cpuCores: singles.cpu ? Number(singles.cpu) : null,
      totalMemoryBytes: singles.memory ? Number(singles.memory) : null,
      freeDiskBytes: singles.disk ? Number(singles.disk) : null,
      clockSynchronized: singles.clock === "yes" ? true : singles.clock === "no" ? false : null,
      sudoNonInteractive: singles.sudo === "yes",
    },
    ports,
    docker: {
      engineAvailable: Boolean(dockerEngine),
      composeAvailable: Boolean(dockerCompose),
      resources,
    },
    managedState: {
      current: singles["state-current"] ? JSON.parse(singles["state-current"]) : null,
      topology: singles["state-topology"] ? JSON.parse(singles["state-topology"]) : null,
    },
    generatedArtifacts: JSON.parse(singles["generated-artifacts"] ?? "{}"),
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

async function inspectSsh(options) {
  const {
    host, port = 22, user, knownHostsFile, hostKeySha256, identityFile,
    connectTimeoutSeconds = 10, run = defaultRun,
  } = options;
  if (!host || !user) throw new Error("SSH target inspection requires both host and user");
  if (Boolean(knownHostsFile) === Boolean(hostKeySha256)) {
    throw new Error("exactly one of knownHostsFile or hostKeySha256 is required for SSH target inspection");
  }

  const { file: userKnownHostsFile, cleanup } = await resolveKnownHosts({ host, port, knownHostsFile, hostKeySha256, connectTimeoutSeconds, run });
  try {
    const probeScript = await readFile(PROBE_PATH, "utf8");
    const args = [
      ...SSH_HARDENING,
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${userKnownHostsFile}`,
      "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", `ConnectTimeout=${connectTimeoutSeconds}`,
      "-p", String(port),
      ...(identityFile ? ["-i", identityFile, "-o", "IdentitiesOnly=yes"] : []),
      `${user}@${host}`,
      "sh", "-s",
    ];
    const { stdout } = await run("ssh", args, { input: probeScript, timeout: (connectTimeoutSeconds + 20) * 1000 });
    const trustDigest = knownHostsFile ? null : hostKeySha256;
    return buildSnapshot("ssh", { verified: true, trustDigest }, stdout);
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
  return buildSnapshot("local", { verified: true, trustDigest: null }, stdout);
}

// options: { targetMode: "ssh" | "local", host, port, user, knownHostsFile,
//   hostKeySha256, identityFile, connectTimeoutSeconds, run? }
// run is an internal testing seam (see target-inspector.test.mjs) -
// hofctl itself never passes it, always getting the real process runner.
export async function inspectTarget(options) {
  return options.targetMode === "local" ? inspectLocal(options) : inspectSsh(options);
}
