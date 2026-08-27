// Real transport acceptance test for target-inspector.mjs - run via
// `pnpm test:ssh`, deliberately NOT matched by `test/*.test.mjs` (the
// fast default `pnpm test` glob), since this needs Docker and takes
// noticeably longer. Builds and starts a genuinely ephemeral, pinned
// Debian 12 sshd container (ports and keys fresh per run, nothing
// baked in, nothing left behind), and exercises inspectTarget()'s real
// OpenSSH handshake end to end - both trust modes, a rejected stale
// fingerprint, a rejected wrong identity, and the real target-probe.sh
// parsing real host facts over the wire. No production host, ever.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { inspectTarget } from "../scripts/target-inspector.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = path.join(root, "test/fixtures/ssh-acceptance");
const imageTag = "hof-ops-ssh-acceptance:test";
const containerName = `hof-ssh-acceptance-${randomUUID()}`;

let workDir;
let hostPort;
let userKeyPath;
let knownHostsPath;
let hostKeyFingerprint;

async function waitForPort(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await exec("ssh-keyscan", ["-p", String(port), "-T", "2", "127.0.0.1"]);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw new Error(`sshd on port ${port} never became reachable within ${timeoutMs}ms`);
}

before(async () => {
  await exec("docker", ["build", "--quiet", "--tag", imageTag, fixtureDir], { timeout: 180_000 });

  workDir = await mkdtemp(path.join(tmpdir(), "hof-ssh-acceptance-"));
  const hostKeyPath = path.join(workDir, "host_key");
  userKeyPath = path.join(workDir, "user_key");
  await exec("ssh-keygen", ["-t", "ed25519", "-f", hostKeyPath, "-N", "", "-q"]);
  await exec("ssh-keygen", ["-t", "ed25519", "-f", userKeyPath, "-N", "", "-q"]);
  const { stdout: publicKey } = await exec("cat", [`${userKeyPath}.pub`]);
  await writeFile(path.join(workDir, "authorized_keys"), publicKey, { mode: 0o644 });

  await exec("docker", [
    "run", "--detach", "--rm", "--name", containerName,
    "--publish", "127.0.0.1::22",
    "--volume", `${workDir}/host_key:/hof-keys/host_key:ro`,
    "--volume", `${workDir}/authorized_keys:/hof-keys/authorized_keys:ro`,
    imageTag,
  ]);
  const { stdout: containerPort } = await exec("docker", ["port", containerName, "22/tcp"]);
  hostPort = Number(containerPort.trim().split(":").pop());

  await waitForPort(hostPort, 30_000);

  knownHostsPath = path.join(workDir, "known_hosts");
  const { stdout: scanned } = await exec("ssh-keyscan", ["-p", String(hostPort), "-t", "ed25519", "127.0.0.1"]);
  await writeFile(knownHostsPath, scanned);

  const { stdout: fingerprintLine } = await exec("ssh-keygen", ["-l", "-E", "sha256", "-f", `${hostKeyPath}.pub`]);
  hostKeyFingerprint = fingerprintLine.trim().split(/\s+/)[1];
});

after(async () => {
  await exec("docker", ["rm", "--force", containerName]).catch(() => {});
  // Doesn't leave a stale, unpinned local image sitting around after
  // the run - the fixture is meant to be genuinely ephemeral end to end.
  await exec("docker", ["rmi", "--force", imageTag]).catch(() => {});
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

test("real SSH handshake in known-hosts mode returns a genuine host snapshot", async () => {
  const snapshot = await inspectTarget({
    targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
    identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
  });
  assert.equal(snapshot.mode, "ssh");
  assert.equal(snapshot.transport.verified, true);
  assert.equal(snapshot.host.os.id, "debian");
  assert.equal(snapshot.host.os.versionId, "12");
  assert.equal(snapshot.host.architecture, "x86_64");
  assert.ok(snapshot.host.cpuCores > 0);
  assert.ok(snapshot.host.totalMemoryBytes > 0);
  // ADR 0004's exact target binding: known-hosts mode must return the
  // real accepted key's own fingerprint (parsed from a real ssh -v
  // transcript), not null - and it must match the same real host key
  // this whole fixture was built from, independently confirmed here via
  // the exact same `ssh-keygen -l -E sha256` ground truth the
  // host-key-sha256 test below already trusts.
  assert.equal(snapshot.transport.trustDigest, hostKeyFingerprint);
});

test("real SSH handshake in host-key-sha256 mode matches the real fingerprint and never leaves a temp known_hosts behind", async () => {
  const before = await import("node:fs/promises").then((m) => m.readdir(tmpdir()));
  const snapshot = await inspectTarget({
    targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
    identityFile: userKeyPath, hostKeySha256: hostKeyFingerprint, connectTimeoutSeconds: 10,
  });
  assert.equal(snapshot.transport.trustDigest, hostKeyFingerprint);
  const after = await import("node:fs/promises").then((m) => m.readdir(tmpdir()));
  assert.deepEqual(after.filter((n) => n.startsWith("hof-known-hosts-")), before.filter((n) => n.startsWith("hof-known-hosts-")));
});

test("a wrong host-key fingerprint is refused before any connection is attempted", async () => {
  await assert.rejects(
    () => inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, hostKeySha256: "SHA256:wrongwrongwrongwrongwrongwrongwrongwrongwro", connectTimeoutSeconds: 10,
    }),
    /no host key offered by 127\.0\.0\.1:\d+ matches the expected fingerprint/,
  );
});

test("a stale known_hosts entry (real key rotation) is rejected by StrictHostKeyChecking, not silently accepted", async () => {
  const staleDir = await mkdtemp(path.join(tmpdir(), "hof-ssh-stale-"));
  try {
    await exec("ssh-keygen", ["-t", "ed25519", "-f", path.join(staleDir, "other_key"), "-N", "", "-q"]);
    const { stdout: otherPublic } = await exec("cat", [path.join(staleDir, "other_key.pub")]);
    const staleKnownHosts = path.join(staleDir, "known_hosts");
    await writeFile(staleKnownHosts, `[127.0.0.1]:${hostPort} ${otherPublic.trim().split(" ").slice(0, 2).join(" ")}\n`);

    await assert.rejects(() => inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, knownHostsFile: staleKnownHosts, connectTimeoutSeconds: 10,
    }));
  } finally {
    await rm(staleDir, { recursive: true, force: true });
  }
});

test("a wrong identity key is refused by real publickey auth, not silently treated as an empty host", async () => {
  const wrongKeyDir = await mkdtemp(path.join(tmpdir(), "hof-ssh-wrongkey-"));
  try {
    const wrongKeyPath = path.join(wrongKeyDir, "wrong_key");
    await exec("ssh-keygen", ["-t", "ed25519", "-f", wrongKeyPath, "-N", "", "-q"]);
    await assert.rejects(() => inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: wrongKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
    }), /Permission denied/);
  } finally {
    await rm(wrongKeyDir, { recursive: true, force: true });
  }
});

// This fixture container never installs Docker at all (see its own
// Dockerfile - openssh-server/sudo/ca-certificates only) - a real
// stand-in for a genuinely fresh, un-provisioned host. Per ADR 0004's
// "Docker Absent" rules, that must report "absent", a legitimate
// bootstrap candidate, never "unavailable" (which means installed but
// unreachable - a real, different failure).
test("Docker genuinely absent (never installed) from the target is reported absent on the engine and all three resource kinds, not unavailable", async () => {
  const snapshot = await inspectTarget({
    targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
    identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
  });
  assert.equal(snapshot.docker.engineStatus, "absent");
  assert.equal(snapshot.docker.composeAvailable, false);
  assert.equal(snapshot.docker.containersStatus, "absent");
  assert.equal(snapshot.docker.volumesStatus, "absent");
  assert.equal(snapshot.docker.networksStatus, "absent");
  assert.deepEqual(snapshot.docker.resources, []);
  assert.deepEqual(snapshot.docker.volumes, []);
  assert.deepEqual(snapshot.docker.networks, []);
});

// This fixture's hofprobe user deliberately has no sudoers entry at all
// (see the "no sudo, mode 600" test below) - under the
// positive-confirmation-only absence policy, that means a missing state
// file can never be reported as "absent" (only root can positively
// confirm non-existence); it's "unreadable", exactly like a permission
// wall would be. A real production target must have passwordless sudo
// anyway (hofctl preflight's own checkSudo already requires it) - the
// genuine "absent, positively confirmed via sudo" path is covered by
// target-probe.test.mjs's own real-shell (fake-sudo) execution instead.
test("managed state on a fresh container with no sudo access reads as unreadable, never guessed as absent", async () => {
  const snapshot = await inspectTarget({
    targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
    identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
  });
  assert.equal(snapshot.host.sudoNonInteractive, false);
  assert.equal(snapshot.managedState.currentStatus, "unreadable");
  assert.equal(snapshot.managedState.current, null);
  assert.equal(snapshot.managedState.topologyStatus, "unreadable");
});

test("a real, readable current.json on the target parses through as genuine JSON content over the real transport", async () => {
  const current = {
    apiVersion: "hof.dev/state/v1", installationId: "real-transport-test", generation: 2,
    lastSuccessfulOperationId: "op-1", appliedAt: "2026-08-27T10:00:00Z", release: "0.1.1",
    manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64),
    catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64),
    topologyDigest: "sha256:" + "5".repeat(64), generatedArtifacts: {},
  };
  await exec("docker", [
    "exec", containerName, "sh", "-c",
    `mkdir -p /var/lib/hof/state && cat > /var/lib/hof/state/current.json <<'JSON'\n${JSON.stringify(current)}\nJSON\nchmod 644 /var/lib/hof/state/current.json`,
  ]);
  try {
    const snapshot = await inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
    });
    assert.equal(snapshot.managedState.currentStatus, "present");
    assert.deepEqual(snapshot.managedState.current, current);
  } finally {
    await exec("docker", ["exec", containerName, "rm", "-f", "/var/lib/hof/state/current.json"]);
  }
});

test("a state file that exists but this user genuinely cannot read (no sudo, mode 600, root-owned) reports unreadable - never silently treated as absent", async () => {
  await exec("docker", [
    "exec", containerName, "sh", "-c",
    "mkdir -p /var/lib/hof/state && echo '{}' > /var/lib/hof/state/current.json && chown root:root /var/lib/hof/state/current.json && chmod 600 /var/lib/hof/state/current.json",
  ]);
  try {
    const snapshot = await inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
    });
    assert.equal(snapshot.host.sudoNonInteractive, false, "hofprobe has no sudoers entry in this fixture, by design");
    assert.equal(snapshot.managedState.currentStatus, "unreadable");
    assert.equal(snapshot.managedState.current, null);
  } finally {
    await exec("docker", ["exec", containerName, "rm", "-f", "/var/lib/hof/state/current.json"]);
  }
});

test("a readable generated file reports present with a real sha256 digest, over the real transport", async () => {
  await exec("docker", [
    "exec", containerName, "sh", "-c",
    "mkdir -p /etc/hof/generated && printf 'services: {}\\n' > /etc/hof/generated/compose.yml && chmod 644 /etc/hof/generated/compose.yml",
  ]);
  const { stdout: sumLine } = await exec("docker", ["exec", containerName, "sha256sum", "/etc/hof/generated/compose.yml"]);
  const expectedDigest = `sha256:${sumLine.trim().split(/\s+/)[0]}`;
  try {
    const snapshot = await inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
    });
    assert.equal(snapshot.generatedArtifactsStatus, "available");
    assert.deepEqual(snapshot.generatedArtifacts["compose.yml"], { status: "present", digest: expectedDigest });
  } finally {
    await exec("docker", ["exec", containerName, "rm", "-f", "/etc/hof/generated/compose.yml"]);
  }
});

test("a generated file that exists but this user genuinely cannot read (no sudo, mode 600, root-owned) reports unreadable - never silently indistinguishable from a genuinely missing one", async () => {
  await exec("docker", [
    "exec", containerName, "sh", "-c",
    "mkdir -p /etc/hof/generated && echo 'services: {}' > /etc/hof/generated/Caddyfile && chown root:root /etc/hof/generated/Caddyfile && chmod 600 /etc/hof/generated/Caddyfile",
  ]);
  try {
    const snapshot = await inspectTarget({
      targetMode: "ssh", host: "127.0.0.1", port: hostPort, user: "hofprobe",
      identityFile: userKeyPath, knownHostsFile: knownHostsPath, connectTimeoutSeconds: 10,
    });
    assert.equal(snapshot.host.sudoNonInteractive, false, "hofprobe has no sudoers entry in this fixture, by design");
    assert.deepEqual(snapshot.generatedArtifacts.Caddyfile, { status: "unreadable", digest: null });
    // A genuinely different, still-absent file in the same batch stays
    // "absent" - "unreadable" must be scoped to the one file that's
    // actually permission-walled, not smeared across the whole batch.
    assert.deepEqual(snapshot.generatedArtifacts["service.env"], { status: "unreadable", digest: null }, "also unreadable here - this fixture has no sudo at all, so nothing can be positively confirmed absent either");
  } finally {
    await exec("docker", ["exec", containerName, "rm", "-f", "/etc/hof/generated/Caddyfile"]);
  }
});
