import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import test from "node:test";

import { inspectTarget } from "../scripts/target-inspector.mjs";

function b64(value) {
  return Buffer.from(value).toString("base64");
}

function validCurrentJson(overrides = {}) {
  return {
    apiVersion: "hof.dev/state/v1",
    installationId: "3b1f6c2e-6e35-4f7a-9c3b-000000000000",
    generation: 1,
    lastSuccessfulOperationId: "operation-1",
    appliedAt: "2026-08-27T10:00:00Z",
    release: "0.1.1",
    manifestDigest: "sha256:" + "1".repeat(64),
    releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64),
    composeTemplateDigest: "sha256:" + "4".repeat(64),
    topologyDigest: "sha256:" + "5".repeat(64),
    generatedArtifacts: {},
    ...overrides,
  };
}

// Builds a valid HOF-PROBE-V2 transcript from a plain object of
// singleton values plus port/container arrays - the same shape
// target-probe.sh's own output decodes to, without needing a real shell.
// Every mandatory singleton has a default so a test only has to
// override the one thing it's exercising.
function probeOutput({
  os = "debian|12", arch = "x86_64", cpu = "4", memory = "8589934592", disk = "53687091200",
  clock = "yes", sudo = "yes", docker = "27.0.0|2.28.0", dockerResourcesStatus = "available",
  stateCurrentStatus = "absent", stateCurrent = "", stateTopologyStatus = "absent", stateTopology = "",
  generatedArtifactsStatus = "available", generatedArtifacts = "{}", ports = [], containers = [], version = "HOF-PROBE-V2",
} = {}) {
  const lines = [version];
  const record = (name, value) => lines.push(`R ${name} ${b64(value)}`);
  record("os", os);
  record("arch", arch);
  record("cpu", cpu);
  record("memory", memory);
  record("disk", disk);
  record("clock", clock);
  record("sudo", sudo);
  record("docker", docker);
  record("docker-resources-status", dockerResourcesStatus);
  for (const port of ports) record("port", port);
  for (const container of containers) record("container", container);
  record("state-current-status", stateCurrentStatus);
  record("state-current", stateCurrent);
  record("state-topology-status", stateTopologyStatus);
  record("state-topology", stateTopology);
  record("generated-artifacts-status", generatedArtifactsStatus);
  record("generated-artifacts", generatedArtifacts);
  lines.push("END");
  return lines.join("\n") + "\n";
}

// The exact field order/count target-probe.sh's Go template joins - see
// CONTAINER_FIELDS in target-inspector.mjs.
function containerRecord({
  name = "unit", image = "ghcr.io/vrubovoy/example@sha256:" + "a".repeat(64), state = "running", health = "none",
  managed = "true", installationId = "inst-1", service = "kuvert", unit = "kuvert-backend", artifact = "kuvert-backend",
  generation = "1", composeProject = "hof", composeService = "kuvert-backend", networks = "hof,", volumes = "",
  ports = "",
} = {}) {
  return [name, image, state, health, managed, installationId, service, unit, artifact, generation, composeProject, composeService, networks, volumes, ports].join("\x1f");
}

function fakeRun(responses) {
  const calls = [];
  const run = async (command, args, options) => {
    calls.push({ command, args, options });
    const key = command;
    if (!(key in responses)) throw new Error(`fakeRun: no response registered for command ${command}`);
    const response = responses[key];
    if (response instanceof Error) throw response;
    return response;
  };
  run.calls = calls;
  return run;
}

test("ssh mode builds exactly the hardened argument list, in known-hosts mode", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await inspectTarget({
    targetMode: "ssh", host: "target.example.com", port: 2222, user: "deploy",
    knownHostsFile: "/etc/hof/known_hosts", identityFile: "/etc/hof/id_ed25519",
    connectTimeoutSeconds: 7, run,
  });

  assert.equal(run.calls.length, 1);
  const call = run.calls[0];
  assert.equal(call.command, "ssh");
  assert.deepEqual(call.args, [
    "-o", "BatchMode=yes",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "PermitLocalCommand=no",
    "-o", "RequestTTY=no",
    "-o", "ConnectionAttempts=1",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=/etc/hof/known_hosts",
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=7",
    "-p", "2222",
    "-i", "/etc/hof/id_ed25519", "-o", "IdentitiesOnly=yes",
    "--",
    "deploy@target.example.com",
    "sh", "-s",
  ]);
  // The fixed probe script, verbatim, over stdin - never a caller-built command.
  assert.match(call.options.input, /^#!\/bin\/sh/);
  assert.match(call.options.input, /HOF-PROBE-V2/);
});

test("ssh mode never uses ssh-keyscan when a known-hosts file is supplied", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", knownHostsFile: "/kh", run });
  assert.deepEqual(run.calls.map((call) => call.command), ["ssh"]);
});

test("host-key-sha256 mode keyscans, matches the fingerprint, and always writes the temp known_hosts to a fresh path", async () => {
  // A real ed25519 test key and its real SHA256 fingerprint (computed
  // independently with `ssh-keygen -l -E sha256`), so this test exercises
  // the actual fingerprint algorithm, not a self-referential mock.
  const keyBase64 = "AAAAC3NzaC1lZDI1NTE5AAAAIF3+kiD6IUxc4xrFjKJI/9v42GCfTbG6v9/16Am1GiL6";
  const expectedFingerprint = "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno";

  const run = fakeRun({
    "ssh-keyscan": { stdout: `target.example.com ssh-ed25519 ${keyBase64}\n`, stderr: "" },
    ssh: { stdout: probeOutput(), stderr: "" },
  });
  const snapshot = await inspectTarget({
    targetMode: "ssh", host: "target.example.com", user: "deploy",
    hostKeySha256: expectedFingerprint, connectTimeoutSeconds: 5, run,
  });

  assert.equal(snapshot.transport.trustDigest, expectedFingerprint);
  const sshCall = run.calls.find((call) => call.command === "ssh");
  const knownHostsOption = sshCall.args.find((arg) => arg.startsWith("UserKnownHostsFile="));
  assert.match(knownHostsOption, /^UserKnownHostsFile=.*hof-known-hosts-/);
});

test("host-key-sha256 mode refuses to connect at all when no offered key matches", async () => {
  const run = fakeRun({
    "ssh-keyscan": { stdout: "target.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3+kiD6IUxc4xrFjKJI/9v42GCfTbG6v9/16Am1GiL6\n", stderr: "" },
  });
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", hostKeySha256: "SHA256:doesnotmatch", run }),
    /no host key offered by h\.example\.com:22 matches the expected fingerprint/,
  );
  // Never even attempted the actual connection.
  assert.deepEqual(run.calls.map((call) => call.command), ["ssh-keyscan"]);
});

test("exactly one of knownHostsFile/hostKeySha256 is required - neither and both are both rejected before any process runs", async () => {
  const run = fakeRun({});
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", run }), /exactly one of knownHostsFile or hostKeySha256/);
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", knownHostsFile: "/a", hostKeySha256: "SHA256:x", run }),
    /exactly one of knownHostsFile or hostKeySha256/,
  );
  assert.equal(run.calls.length, 0);
});

test("a temporary known_hosts file from host-key-sha256 mode is always cleaned up, including on a later failure", async () => {
  const keyLine = "target.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3+kiD6IUxc4xrFjKJI/9v42GCfTbG6v9/16Am1GiL6";
  const fingerprint = "SHA256:gcuHMcC8doDMjedrPcW196YKgc/MpHxl+BU6kA8Shno";
  const before = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-known-hosts-"));

  const run = fakeRun({
    "ssh-keyscan": { stdout: keyLine + "\n", stderr: "" },
    ssh: Object.assign(new Error("Permission denied (publickey)"), { stdout: "", stderr: "Permission denied (publickey).\n" }),
  });
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "deploy", hostKeySha256: fingerprint, run }));

  const after = (await readdir(tmpdir())).filter((name) => name.startsWith("hof-known-hosts-"));
  assert.deepEqual(after, before, "no leftover temporary known_hosts file after a failed connection");
});

test("--target-mode local rejects any SSH trust/identity option", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput(), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", knownHostsFile: "/kh", run }), /does not accept SSH trust\/identity options/);
  await assert.rejects(() => inspectTarget({ targetMode: "local", hostKeySha256: "SHA256:x", run }), /does not accept SSH trust\/identity options/);
  await assert.rejects(() => inspectTarget({ targetMode: "local", identityFile: "/id", run }), /does not accept SSH trust\/identity options/);
});

test("local mode never invokes ssh or ssh-keyscan at all", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput(), stderr: "" } });
  await inspectTarget({ targetMode: "local", run });
  assert.deepEqual(run.calls.map((call) => call.command), ["sh"]);
  assert.deepEqual(run.calls[0].args, ["-s"]);
});

test("a run() failure (auth rejected, connection refused, timeout) propagates - never silently treated as a clean, empty host", async () => {
  const timeoutError = Object.assign(new Error("Connection timed out"), { killed: true, signal: "SIGTERM" });
  const run = fakeRun({ ssh: timeoutError });
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", knownHostsFile: "/kh", run }), /Connection timed out/);
});

test("refuses a host value that would be interpreted as an SSH option, even with a valid known_hosts file", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "-oProxyCommand=touch /tmp/pwned", user: "deploy", knownHostsFile: "/kh", run }),
    /not a valid hostname/,
  );
  assert.equal(run.calls.length, 0, "never attempts a connection with an invalid destination");
});

test("refuses a user value that would be interpreted as an SSH option", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "-oProxyCommand=touch /tmp/pwned", knownHostsFile: "/kh", run }),
    /not a valid SSH username/,
  );
  assert.equal(run.calls.length, 0);
});

test("refuses an out-of-range or non-integer port before connecting", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "deploy", port: 0, knownHostsFile: "/kh", run }), /not a valid port number/);
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "deploy", port: 70000, knownHostsFile: "/kh", run }), /not a valid port number/);
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "deploy", port: Number.NaN, knownHostsFile: "/kh", run }), /not a valid port number/);
});

test("the SSH argv always contains a -- terminator right before the destination, as defense in depth", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await inspectTarget({ targetMode: "ssh", host: "target.example.com", user: "deploy", knownHostsFile: "/kh", run });
  const args = run.calls[0].args;
  const destinationIndex = args.indexOf("deploy@target.example.com");
  assert.equal(args[destinationIndex - 1], "--");
});

test("rejects a non-finite or non-positive connectTimeoutSeconds instead of silently using it", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", knownHostsFile: "/kh", connectTimeoutSeconds: Number.NaN, run }), /connectTimeoutSeconds must be a positive integer/);
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "h.example.com", user: "u", knownHostsFile: "/kh", connectTimeoutSeconds: -5, run }), /connectTimeoutSeconds must be a positive integer/);
});

test("an oversized transcript is rejected by the protocol-level line bound, independent of execFile's own maxBuffer", async () => {
  const huge = "HOF-PROBE-V2\n" + Array.from({ length: 3000 }, (_, i) => `R port ${b64(`${8000 + i}|free`)}`).join("\n") + "\nEND\n";
  const run = fakeRun({ sh: { stdout: huge, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /more than the 2000-line bound/);
});

test("a truncated transcript (no END) is rejected, not silently accepted as partial data", async () => {
  const truncated = probeOutput().replace(/\nEND\n$/, "\n");
  const run = fakeRun({ sh: { stdout: truncated, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /missing the END terminator/);
});

test("a wrong version marker is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ version: "HOF-PROBE-V1" }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /does not start with the expected HOF-PROBE-V2 marker/);
});

test("an unrecognized record name is rejected, not ignored", async () => {
  const withExtra = probeOutput().replace("\nEND\n", `\nR shell-history ${b64("rm -rf /")}\nEND\n`);
  const run = fakeRun({ sh: { stdout: withExtra, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /unknown probe record: shell-history/);
});

test("a duplicate singleton record is rejected", async () => {
  const duplicated = probeOutput().replace("\nEND\n", `\nR cpu ${b64("999")}\nEND\n`);
  const run = fakeRun({ sh: { stdout: duplicated, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /duplicate probe record: cpu/);
});

test("a missing mandatory singleton record is rejected, not treated as absent", async () => {
  const missingCpu = probeOutput().split("\n").filter((line) => !line.startsWith("R cpu ")).join("\n");
  const run = fakeRun({ sh: { stdout: missingCpu, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /missing mandatory probe record: cpu/);
});

test("a malformed protocol line is rejected", async () => {
  const malformed = probeOutput().replace("\nEND\n", "\nnot a valid record line at all\nEND\n");
  const run = fakeRun({ sh: { stdout: malformed, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /malformed probe protocol line/);
});

test("a payload that isn't valid base64 is rejected", async () => {
  const bad = probeOutput().replace(/R cpu \S+/, "R cpu not-valid-base64!!");
  const run = fakeRun({ sh: { stdout: bad, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /not valid base64/);
});

test("cpu/memory/disk must be a non-negative integer or the literal \"unknown\"", async () => {
  const negative = probeOutput({ cpu: "-1" });
  const run = fakeRun({ sh: { stdout: negative, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /probe record cpu is not a non-negative integer/);
});

test("cpu/memory/disk of \"unknown\" parses as null, not zero", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ cpu: "unknown", memory: "unknown", disk: "unknown" }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.equal(snapshot.host.cpuCores, null);
  assert.equal(snapshot.host.totalMemoryBytes, null);
  assert.equal(snapshot.host.freeDiskBytes, null);
});

test("an unrecognized port state is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ ports: ["80|maybe"] }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /unrecognized state/);
});

test("a duplicate port record for the same port number is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ ports: ["80|free", "80|occupied"] }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /duplicate port record: 80/);
});

test("a container record with the wrong field count is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ containers: ["too\x1ffew\x1ffields"] }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /has 3 fields, expected exactly 15/);
});

test("a non-numeric hof.generation label is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ containers: [containerRecord({ generation: "not-a-number" })] }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /hof\.generation label is not a non-negative integer/);
});

test("an out-of-range published port on a container is rejected", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ containers: [containerRecord({ ports: "99999," })] }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /published port 99999 is out of range/);
});

test("a state-current that fails schemas/state-v1.schema.json is rejected, not silently trusted", async () => {
  const invalid = JSON.stringify({ apiVersion: "hof.dev/state/v1" }); // missing every other required field
  const run = fakeRun({ sh: { stdout: probeOutput({ stateCurrentStatus: "present", stateCurrent: invalid }), stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /does not satisfy schemas\/state-v1\.schema\.json/);
});

test("a schema-valid state-current parses through untouched", async () => {
  const current = validCurrentJson();
  const run = fakeRun({ sh: { stdout: probeOutput({ stateCurrentStatus: "present", stateCurrent: JSON.stringify(current) }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.deepEqual(snapshot.managedState.current, current);
  assert.equal(snapshot.managedState.currentStatus, "present");
});

test("the parsed snapshot exposes only the whitelisted container fields - no Config.Env, command, or bind-mount paths anywhere in it", async () => {
  const container = containerRecord({ name: "sneaky-container" });
  const run = fakeRun({ sh: { stdout: probeOutput({ containers: [container] }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });

  assert.equal(snapshot.docker.resources.length, 1);
  const resource = snapshot.docker.resources[0];
  assert.deepEqual(Object.keys(resource).sort(), [
    "artifact", "composeProject", "composeService", "generation", "health", "image",
    "installationId", "managed", "name", "networks", "ports", "service", "state", "unit", "volumes",
  ].sort());
  const serialized = JSON.stringify(snapshot);
  assert.doesNotMatch(serialized, /DATABASE_PATH|SECRET|PASSWORD|\/var\/lib\/docker|bind/i);
});

test("port ownership is resolved only from a container matching this installation's own recorded installationId, actually running", async () => {
  const current = validCurrentJson({ installationId: "inst-1" });
  const ownGateway = containerRecord({ name: "gateway", service: "tor", unit: "gateway", artifact: "gateway", installationId: "inst-1", state: "running", ports: "80,443," });
  const foreignGateway = containerRecord({ name: "other-gateway", service: "tor", unit: "gateway", artifact: "gateway", installationId: "inst-OTHER", state: "running", ports: "8080," });
  const stoppedOwn = containerRecord({ name: "stopped", service: "tor", unit: "gateway", artifact: "gateway", installationId: "inst-1", state: "exited", ports: "9090," });

  const run = fakeRun({
    sh: {
      stdout: probeOutput({
        stateCurrentStatus: "present", stateCurrent: JSON.stringify(current),
        ports: ["80|occupied", "443|occupied", "8080|occupied", "9090|occupied"],
        containers: [ownGateway, foreignGateway, stoppedOwn],
      }),
      stderr: "",
    },
  });
  const snapshot = await inspectTarget({ targetMode: "local", run });

  assert.deepEqual(snapshot.ports.find((p) => p.port === 80), { port: 80, state: "occupied", owner: "gateway" });
  assert.deepEqual(snapshot.ports.find((p) => p.port === 443), { port: 443, state: "occupied", owner: "gateway" });
  assert.equal(snapshot.ports.find((p) => p.port === 8080).owner, "foreign", "a different installation's own gateway is never 'ours'");
  assert.equal(snapshot.ports.find((p) => p.port === 9090).owner, "foreign", "an exited container never counts as currently occupying anything");
});

test("port ownership never claims anything as 'ours' when there is no recorded installation yet (fresh bootstrap)", async () => {
  const managed = containerRecord({ name: "gateway", service: "tor", unit: "gateway", artifact: "gateway", installationId: "inst-1", state: "running", ports: "80," });
  const run = fakeRun({ sh: { stdout: probeOutput({ ports: ["80|occupied"], containers: [managed] }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.equal(snapshot.ports.find((p) => p.port === 80).owner, "foreign");
});

test("docker-resources-status distinguishes 'Docker is fine, nothing running' from 'the container listing itself failed'", async () => {
  const runAvailable = fakeRun({ sh: { stdout: probeOutput({ dockerResourcesStatus: "available" }), stderr: "" } });
  const available = await inspectTarget({ targetMode: "local", run: runAvailable });
  assert.equal(available.docker.resourcesStatus, "available");
  assert.deepEqual(available.docker.resources, []);

  const runUnavailable = fakeRun({ sh: { stdout: probeOutput({ dockerResourcesStatus: "unavailable" }), stderr: "" } });
  const unavailable = await inspectTarget({ targetMode: "local", run: runUnavailable });
  assert.equal(unavailable.docker.resourcesStatus, "unavailable");
});

test("state file present/absent/unreadable statuses all parse distinctly", async () => {
  const runAbsent = fakeRun({ sh: { stdout: probeOutput({ stateCurrentStatus: "absent" }), stderr: "" } });
  const absent = await inspectTarget({ targetMode: "local", run: runAbsent });
  assert.equal(absent.managedState.currentStatus, "absent");
  assert.equal(absent.managedState.current, null);

  const runUnreadable = fakeRun({ sh: { stdout: probeOutput({ stateCurrentStatus: "unreadable" }), stderr: "" } });
  const unreadable = await inspectTarget({ targetMode: "local", run: runUnreadable });
  assert.equal(unreadable.managedState.currentStatus, "unreadable");
  assert.equal(unreadable.managedState.current, null);
});

test("generatedArtifacts parses through as the real JSON object", async () => {
  const artifacts = { "compose.yml": "sha256:" + "6".repeat(64), "topology.json": "sha256:" + "7".repeat(64) };
  const run = fakeRun({ sh: { stdout: probeOutput({ generatedArtifacts: JSON.stringify(artifacts) }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.deepEqual(snapshot.generatedArtifacts, artifacts);
});

test("generatedArtifactsStatus distinguishes 'sha256sum isn't on this target at all' from 'it ran, files are just missing'", async () => {
  const runAvailable = fakeRun({ sh: { stdout: probeOutput({ generatedArtifactsStatus: "available" }), stderr: "" } });
  const available = await inspectTarget({ targetMode: "local", run: runAvailable });
  assert.equal(available.generatedArtifactsStatus, "available");

  const runUnavailable = fakeRun({ sh: { stdout: probeOutput({ generatedArtifactsStatus: "unavailable" }), stderr: "" } });
  const unavailable = await inspectTarget({ targetMode: "local", run: runUnavailable });
  assert.equal(unavailable.generatedArtifactsStatus, "unavailable");
});
