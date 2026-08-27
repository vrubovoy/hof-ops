import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import test from "node:test";

import { inspectTarget } from "../scripts/target-inspector.mjs";

function b64(value) {
  return Buffer.from(value).toString("base64");
}

// Builds a valid HOF-PROBE-V1 transcript from a plain object of
// singleton values plus port/container arrays - the same shape
// target-probe.sh's own output decodes to, without needing a real shell.
function probeOutput({ os = "debian|12", arch = "x86_64", cpu = "4", memory = "8589934592", disk = "53687091200", clock = "yes", sudo = "yes", docker = "27.0.0|2.28.0", stateCurrent = "", stateTopology = "", generatedArtifacts = "{}", ports = [], containers = [] } = {}) {
  const lines = ["HOF-PROBE-V1"];
  const record = (name, value) => lines.push(`R ${name} ${b64(value)}`);
  record("os", os);
  record("arch", arch);
  record("cpu", cpu);
  record("memory", memory);
  record("disk", disk);
  record("clock", clock);
  record("sudo", sudo);
  record("docker", docker);
  for (const port of ports) record("port", port);
  for (const container of containers) record("container", container);
  record("state-current", stateCurrent);
  record("state-topology", stateTopology);
  record("generated-artifacts", generatedArtifacts);
  lines.push("END");
  return lines.join("\n") + "\n";
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
    "deploy@target.example.com",
    "sh", "-s",
  ]);
  // The fixed probe script, verbatim, over stdin - never a caller-built command.
  assert.match(call.options.input, /^#!\/bin\/sh/);
  assert.match(call.options.input, /HOF-PROBE-V1/);
});

test("ssh mode never uses ssh-keyscan when a known-hosts file is supplied", async () => {
  const run = fakeRun({ ssh: { stdout: probeOutput(), stderr: "" } });
  await inspectTarget({ targetMode: "ssh", host: "h", user: "u", knownHostsFile: "/kh", run });
  assert.deepEqual(run.calls.map((call) => call.command), ["ssh"]);
});

test("host-key-sha256 mode keyscans, matches the fingerprint, and never leaks the temp known_hosts path into the ssh args in a discoverable way beyond the option itself", async () => {
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
    () => inspectTarget({ targetMode: "ssh", host: "h", user: "u", hostKeySha256: "SHA256:doesnotmatch", run }),
    /no host key offered by h:22 matches the expected fingerprint/,
  );
  // Never even attempted the actual connection.
  assert.deepEqual(run.calls.map((call) => call.command), ["ssh-keyscan"]);
});

test("exactly one of knownHostsFile/hostKeySha256 is required - neither and both are both rejected before any process runs", async () => {
  const run = fakeRun({});
  await assert.rejects(() => inspectTarget({ targetMode: "ssh", host: "h", user: "u", run }), /exactly one of knownHostsFile or hostKeySha256/);
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "h", user: "u", knownHostsFile: "/a", hostKeySha256: "SHA256:x", run }),
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
  await assert.rejects(
    () => inspectTarget({ targetMode: "local", knownHostsFile: "/kh", run }),
    /does not accept SSH trust\/identity options/,
  );
  await assert.rejects(
    () => inspectTarget({ targetMode: "local", hostKeySha256: "SHA256:x", run }),
    /does not accept SSH trust\/identity options/,
  );
  await assert.rejects(
    () => inspectTarget({ targetMode: "local", identityFile: "/id", run }),
    /does not accept SSH trust\/identity options/,
  );
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
  await assert.rejects(
    () => inspectTarget({ targetMode: "ssh", host: "h", user: "u", knownHostsFile: "/kh", run }),
    /Connection timed out/,
  );
});

test("an oversized transcript is rejected by the protocol-level line bound, independent of execFile's own maxBuffer", async () => {
  const huge = "HOF-PROBE-V1\n" + Array.from({ length: 3000 }, (_, i) => `R port ${b64(`${8000 + i}|free`)}`).join("\n") + "\nEND\n";
  const run = fakeRun({ sh: { stdout: huge, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /more than the 2000-line bound/);
});

test("a truncated transcript (no END) is rejected, not silently accepted as partial data", async () => {
  const truncated = probeOutput().replace(/\nEND\n$/, "\n");
  const run = fakeRun({ sh: { stdout: truncated, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /missing the END terminator/);
});

test("a wrong version marker is rejected", async () => {
  const wrongVersion = probeOutput().replace("HOF-PROBE-V1", "HOF-PROBE-V2");
  const run = fakeRun({ sh: { stdout: wrongVersion, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /does not start with the expected HOF-PROBE-V1 marker/);
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

test("a malformed protocol line is rejected", async () => {
  const malformed = probeOutput().replace("\nEND\n", "\nnot a valid record line at all\nEND\n");
  const run = fakeRun({ sh: { stdout: malformed, stderr: "" } });
  await assert.rejects(() => inspectTarget({ targetMode: "local", run }), /malformed probe protocol line/);
});

test("the parsed snapshot exposes only the whitelisted container fields - no Config.Env, command, or bind-mount paths anywhere in it", async () => {
  const fields = [
    "sneaky-container", "ghcr.io/vrubovoy/kuvert-backend@sha256:" + "a".repeat(64), "running", "healthy",
    "true", "inst-1", "kuvert", "kuvert-backend", "kuvert-backend", "2",
    "hof", "kuvert-backend", "hof,", "kuvert-data,", "3001,",
  ];
  const container = fields.join("\x1f");
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

test("port ownership is resolved from the same snapshot's managed container records, not a privileged process lookup", async () => {
  const managed = ["gateway", "ghcr.io/vrubovoy/gateway@sha256:" + "b".repeat(64), "running", "none", "true", "inst-1", "tor", "gateway", "gateway", "1", "hof", "gateway", "hof,", "", "80,443,"].join("\x1f");
  const run = fakeRun({ sh: { stdout: probeOutput({ ports: ["80|occupied", "443|occupied", "8080|occupied"], containers: [managed] }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });

  assert.deepEqual(snapshot.ports.find((p) => p.port === 80), { port: 80, state: "occupied", owner: "gateway" });
  assert.deepEqual(snapshot.ports.find((p) => p.port === 443), { port: 443, state: "occupied", owner: "gateway" });
  assert.deepEqual(snapshot.ports.find((p) => p.port === 8080), { port: 8080, state: "occupied", owner: "foreign" });
});

test("managedState parses absent state files as null, not an error", async () => {
  const run = fakeRun({ sh: { stdout: probeOutput({ stateCurrent: "", stateTopology: "" }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.deepEqual(snapshot.managedState, { current: null, topology: null });
});

test("managedState parses present state files as their real JSON content", async () => {
  const current = JSON.stringify({ apiVersion: "hof.dev/state/v1", generation: 4 });
  const run = fakeRun({ sh: { stdout: probeOutput({ stateCurrent: current }), stderr: "" } });
  const snapshot = await inspectTarget({ targetMode: "local", run });
  assert.deepEqual(snapshot.managedState.current, { apiVersion: "hof.dev/state/v1", generation: 4 });
});
