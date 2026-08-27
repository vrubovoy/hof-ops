import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  checkArchitecture, checkClock, checkCpu, checkDisk, checkDns, checkDocker, checkManagedState,
  checkManagedStateReadable, checkMemory, checkOs, checkPort, checkSudo, checkTransport, runPreflight,
} from "../scripts/preflight.mjs";

const root = path.resolve(import.meta.dirname, "..");

function fakeSnapshot(overrides = {}) {
  return {
    mode: "ssh",
    transport: { verified: true, trustDigest: "SHA256:abc" },
    host: {
      os: { id: "debian", versionId: "12" },
      architecture: "x86_64",
      cpuCores: 4,
      totalMemoryBytes: 8 * 1024 ** 3,
      freeDiskBytes: 40 * 1024 ** 3,
      clockSynchronized: true,
      sudoNonInteractive: true,
    },
    ports: [{ port: 80, state: "free", owner: null }, { port: 443, state: "free", owner: null }],
    docker: { engineAvailable: true, composeAvailable: true, resourcesStatus: "available", resources: [] },
    managedState: { currentStatus: "absent", current: null, topologyStatus: "absent", topology: null },
    generatedArtifacts: {},
    ...overrides,
  };
}

test("checkTransport reports the verified mode and trust digest", () => {
  const result = checkTransport(fakeSnapshot());
  assert.equal(result.status, "pass");
  assert.match(result.message, /verified ssh connection \(SHA256:abc\)/);
});

test("checkOs passes for Debian 12 and Ubuntu 24.04, fails for anything else", () => {
  assert.equal(checkOs(fakeSnapshot({ host: { ...fakeSnapshot().host, os: { id: "debian", versionId: "12" } } })).status, "pass");
  assert.equal(checkOs(fakeSnapshot({ host: { ...fakeSnapshot().host, os: { id: "ubuntu", versionId: "24.04" } } })).status, "pass");
  assert.equal(checkOs(fakeSnapshot({ host: { ...fakeSnapshot().host, os: { id: "ubuntu", versionId: "22.04" } } })).status, "fail");
  assert.equal(checkOs(fakeSnapshot({ host: { ...fakeSnapshot().host, os: { id: "fedora", versionId: "40" } } })).status, "fail");
});

test("checkArchitecture passes only for x86_64", () => {
  assert.equal(checkArchitecture(fakeSnapshot({ host: { ...fakeSnapshot().host, architecture: "x86_64" } })).status, "pass");
  assert.equal(checkArchitecture(fakeSnapshot({ host: { ...fakeSnapshot().host, architecture: "aarch64" } })).status, "fail");
});

test("checkDisk passes/fails/unknown based on the snapshot's freeDiskBytes", () => {
  assert.equal(checkDisk(fakeSnapshot({ host: { ...fakeSnapshot().host, freeDiskBytes: 40 * 1024 ** 3 } }), 1024 ** 3).status, "pass");
  assert.equal(checkDisk(fakeSnapshot({ host: { ...fakeSnapshot().host, freeDiskBytes: 1 } }), 1024 ** 3).status, "fail");
  assert.equal(checkDisk(fakeSnapshot({ host: { ...fakeSnapshot().host, freeDiskBytes: null } }), 1024 ** 3).status, "unknown");
});

test("checkDisk/Memory/Cpu report unknown, not a silent pass, for a non-finite or negative threshold", () => {
  assert.equal(checkDisk(fakeSnapshot(), Number.NaN).status, "unknown");
  assert.equal(checkDisk(fakeSnapshot(), -1).status, "unknown");
  assert.equal(checkMemory(fakeSnapshot(), Number.NaN).status, "unknown");
  assert.equal(checkCpu(fakeSnapshot(), Number.POSITIVE_INFINITY).status, "unknown");
});

test("checkMemory passes/fails/unknown based on the snapshot's totalMemoryBytes", () => {
  assert.equal(checkMemory(fakeSnapshot(), 1).status, "pass");
  assert.equal(checkMemory(fakeSnapshot(), 999 * 1024 ** 3).status, "fail");
  assert.equal(checkMemory(fakeSnapshot({ host: { ...fakeSnapshot().host, totalMemoryBytes: null } }), 1).status, "unknown");
});

test("checkCpu passes/fails/unknown based on the snapshot's cpuCores", () => {
  assert.equal(checkCpu(fakeSnapshot(), 2).status, "pass");
  assert.equal(checkCpu(fakeSnapshot(), 999).status, "fail");
  assert.equal(checkCpu(fakeSnapshot({ host: { ...fakeSnapshot().host, cpuCores: null } }), 2).status, "unknown");
});

test("checkClock reflects the snapshot's tri-state clockSynchronized", () => {
  assert.equal(checkClock(fakeSnapshot({ host: { ...fakeSnapshot().host, clockSynchronized: true } })).status, "pass");
  assert.equal(checkClock(fakeSnapshot({ host: { ...fakeSnapshot().host, clockSynchronized: false } })).status, "fail");
  assert.equal(checkClock(fakeSnapshot({ host: { ...fakeSnapshot().host, clockSynchronized: null } })).status, "unknown");
});

test("checkSudo reflects sudoNonInteractive", () => {
  assert.equal(checkSudo(fakeSnapshot({ host: { ...fakeSnapshot().host, sudoNonInteractive: true } })).status, "pass");
  assert.equal(checkSudo(fakeSnapshot({ host: { ...fakeSnapshot().host, sudoNonInteractive: false } })).status, "fail");
});

test("checkPort: free passes", () => {
  const snapshot = fakeSnapshot({ ports: [{ port: 80, state: "free", owner: null }] });
  assert.equal(checkPort(snapshot, 80).status, "pass");
});

test("checkPort: occupied by this installation's own managed unit passes", () => {
  const snapshot = fakeSnapshot({ ports: [{ port: 80, state: "occupied", owner: "gateway" }] });
  const result = checkPort(snapshot, 80);
  assert.equal(result.status, "pass");
  assert.match(result.message, /this installation's own gateway/);
});

test("checkPort: occupied by a foreign process (including another installation's own gateway) fails", () => {
  const snapshot = fakeSnapshot({ ports: [{ port: 80, state: "occupied", owner: "foreign" }] });
  assert.equal(checkPort(snapshot, 80).status, "fail");
});

test("checkPort: unknown state, or a missing record entirely, fails closed as unknown", () => {
  assert.equal(checkPort(fakeSnapshot({ ports: [{ port: 80, state: "unknown", owner: null }] }), 80).status, "unknown");
  assert.equal(checkPort(fakeSnapshot({ ports: [] }), 80).status, "unknown");
});

test("checkDocker requires engine, compose, and a successful container listing", () => {
  assert.equal(checkDocker(fakeSnapshot({ docker: { engineAvailable: true, composeAvailable: true, resourcesStatus: "available", resources: [] } })).status, "pass");
  assert.equal(checkDocker(fakeSnapshot({ docker: { engineAvailable: false, composeAvailable: true, resourcesStatus: "available", resources: [] } })).status, "fail");
  assert.equal(checkDocker(fakeSnapshot({ docker: { engineAvailable: true, composeAvailable: false, resourcesStatus: "available", resources: [] } })).status, "fail");
  const result = checkDocker(fakeSnapshot({ docker: { engineAvailable: true, composeAvailable: true, resourcesStatus: "unavailable", resources: [] } }));
  assert.equal(result.status, "fail");
  assert.match(result.message, /container listing could not be read/);
});

test("checkManagedStateReadable fails when either state file exists but couldn't be read, even with sudo", () => {
  assert.equal(checkManagedStateReadable(fakeSnapshot()).status, "pass");
  assert.equal(checkManagedStateReadable(fakeSnapshot({ managedState: { ...fakeSnapshot().managedState, currentStatus: "unreadable" } })).status, "fail");
  assert.equal(checkManagedStateReadable(fakeSnapshot({ managedState: { ...fakeSnapshot().managedState, topologyStatus: "unreadable" } })).status, "fail");
});

test("checkDns passes when every hostname resolves an A record, AAAA optional", async () => {
  const resolver = {
    resolve4: async () => ["203.0.113.10"],
    resolve6: async () => { throw Object.assign(new Error("no AAAA"), { code: "ENODATA" }); },
  };
  const result = await checkDns(["schloss.example.com"], resolver);
  assert.equal(result.status, "pass");
  assert.match(result.message, /no AAAA record/);
});

test("checkDns fails when a hostname has no A record", async () => {
  const resolver = {
    resolve4: async () => { throw Object.assign(new Error("not found"), { code: "ENOTFOUND" }); },
    resolve6: async () => ["2001:db8::1"],
  };
  const result = await checkDns(["schloss.example.com"], resolver);
  assert.equal(result.status, "fail");
  assert.match(result.message, /no A record/);
});

test("checkDns passes trivially with no public hostnames", async () => {
  assert.equal((await checkDns([], {})).status, "pass");
});

const catalogFixture = { services: [{ id: "tor", mandatory: true, artifacts: ["gateway"], dependsOn: [], volumes: [], health: { component: "gateway", path: "/" } }] };

test("checkManagedState passes on a genuinely clean bootstrap host", () => {
  assert.equal(checkManagedState(fakeSnapshot(), catalogFixture).status, "pass");
});

test("checkManagedState fails when state is missing but Docker already holds managed resources", () => {
  const snapshot = fakeSnapshot({ docker: { engineAvailable: true, composeAvailable: true, resourcesStatus: "available", resources: [{ service: "tor", unit: "gateway", managed: true }] } });
  const result = checkManagedState(snapshot, catalogFixture);
  assert.equal(result.status, "fail");
  assert.match(result.message, /managed resources exist but the authoritative state is missing/);
});

test("checkManagedState is skipped (unknown), not silently passed, when state is unreadable", () => {
  const snapshot = fakeSnapshot({ managedState: { ...fakeSnapshot().managedState, currentStatus: "unreadable" } });
  const result = checkManagedState(snapshot, catalogFixture);
  assert.equal(result.status, "unknown");
});

test("checkManagedState derives observation.status from the snapshot's own docker.resourcesStatus, not a hardcoded 'available'", () => {
  const snapshot = fakeSnapshot({ docker: { engineAvailable: true, composeAvailable: true, resourcesStatus: "unavailable", resources: [] } });
  const result = checkManagedState(snapshot, catalogFixture);
  assert.equal(result.status, "fail");
  assert.match(result.message, /observation is unavailable/);
});

test("runPreflight: an invalid manifest is rejected before ever attempting a connection", async () => {
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const directory = await mkdtemp(path.join(tmpdir(), "hof-preflight-invalid-"));
  const invalidManifestPath = path.join(directory, "services.yml");
  await writeFile(invalidManifestPath, "apiVersion: hof.dev/v1alpha1\ntarget:\n  host: -oProxyCommand=touch /tmp/pwn\n  user: deploy\n");
  try {
    let inspectCalled = false;
    const inspect = async () => { inspectCalled = true; return fakeSnapshot(); };
    const { checks, ok } = await runPreflight({ manifestPath: invalidManifestPath, inspect });
    assert.equal(ok, false);
    assert.deepEqual(checks.map((c) => c.id), ["manifest"]);
    assert.equal(inspectCalled, false, "never attempts to inspect a target from an invalid manifest");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runPreflight: a failed inspection produces a single failing transport check, nothing else", async () => {
  const inspect = async () => { throw new Error("Permission denied (publickey)"); };
  const { checks, ok } = await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect, targetMode: "ssh",
  });
  assert.equal(ok, false);
  assert.deepEqual(checks.map((c) => c.id), ["transport"]);
  assert.match(checks[0].message, /Permission denied/);
});

test("runPreflight: ok is true when every check genuinely passes against a faked snapshot", async () => {
  const inspect = async () => fakeSnapshot();
  const { checks, ok } = await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect,
    minFreeDiskBytes: 1, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
  });
  assert.equal(ok, true);
  assert.ok(checks.every((c) => c.status === "pass"));
  assert.ok(checks.some((c) => c.id === "managed-state"));
  assert.ok(checks.some((c) => c.id === "managed-state-readable"));
});

test("runPreflight: ok is false whenever any single check fails or is unknown", async () => {
  const inspect = async () => fakeSnapshot({ host: { ...fakeSnapshot().host, clockSynchronized: null }, docker: { engineAvailable: false, composeAvailable: true, resourcesStatus: "available", resources: [] } });
  const { checks, ok } = await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect,
    minFreeDiskBytes: 1, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => { throw new Error("no network"); }, resolve6: async () => { throw new Error("no network"); } },
  });
  assert.equal(ok, false);
  assert.ok(checks.some((c) => c.id === "clock" && c.status === "unknown"));
  assert.ok(checks.some((c) => c.id === "docker" && c.status === "fail"));
});

test("runPreflight: an invalid --min-free-disk-gb-style threshold falls back to the safe default, never to NaN", async () => {
  // 10 GiB clears the CLI's own default (20 GiB) neither way - the real
  // point is that passing NaN must fall back to a real, sane threshold
  // (still correctly failing here) rather than NaN making every
  // comparison silently true.
  const inspect = async () => fakeSnapshot({ host: { ...fakeSnapshot().host, freeDiskBytes: 10 * 1024 ** 3 } });
  const { checks, ok } = await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect,
    minFreeDiskBytes: Number.NaN, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
  });
  assert.equal(ok, false);
  const disk = checks.find((c) => c.id === "disk");
  assert.equal(disk.status, "fail");
  assert.match(disk.message, /need at least 20\.0 GiB/, "fell back to DEFAULT_THRESHOLDS, not NaN (which would compare as always-false-then-'pass')");
});

test("runPreflight defaults catalogPath to hof-ops's own bundled catalog", async () => {
  const inspect = async () => fakeSnapshot();
  const { ok } = await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect,
    minFreeDiskBytes: 1, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
  });
  assert.equal(ok, true);
});

test("runPreflight passes targetMode/host/user/port through to inspect() from manifest.target", async () => {
  const seen = [];
  const inspect = async (options) => { seen.push(options); return fakeSnapshot(); };
  await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect,
    minFreeDiskBytes: 1, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].targetMode, "ssh");
  assert.equal(seen[0].host, "hof.example.com");
  assert.equal(seen[0].user, "deploy");
  assert.equal(seen[0].port, 22);
});

test("runPreflight honors an explicit --target-mode local, never inferring it from the hostname", async () => {
  const seen = [];
  const inspect = async (options) => { seen.push(options); return fakeSnapshot({ mode: "local", transport: { verified: true, trustDigest: null } }); };
  await runPreflight({
    manifestPath: path.join(root, "examples/services.yml"), inspect, targetMode: "local",
    minFreeDiskBytes: 1, minTotalMemoryBytes: 1, minCpuCores: 1,
    resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
  });
  assert.equal(seen[0].targetMode, "local");
});
