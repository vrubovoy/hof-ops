import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  checkClock, checkCpu, checkDisk, checkDns, checkDocker, checkMemory, checkPort, runPreflight,
} from "../scripts/preflight.mjs";

const root = path.resolve(import.meta.dirname, "..");

test("checkDisk passes when free space clears the threshold", () => {
  const result = checkDisk("/", 1);
  assert.equal(result.status, "pass");
});

test("checkDisk fails when free space is below the threshold", () => {
  const result = checkDisk("/", Number.MAX_SAFE_INTEGER);
  assert.equal(result.status, "fail");
});

test("checkDisk reports unknown for a path that doesn't exist", () => {
  const result = checkDisk("/does/not/exist/at/all", 1);
  assert.equal(result.status, "unknown");
});

test("checkMemory passes/fails based on the injected total", () => {
  assert.equal(checkMemory(1, 8 * 1024 ** 3).status, "pass");
  assert.equal(checkMemory(16 * 1024 ** 3, 8 * 1024 ** 3).status, "fail");
});

test("checkCpu passes/fails based on the injected core count", () => {
  assert.equal(checkCpu(2, 4).status, "pass");
  assert.equal(checkCpu(8, 4).status, "fail");
});

test("checkClock passes when timedatectl reports NTPSynchronized=yes", async () => {
  const result = await checkClock(async () => ({ stdout: "yes\n" }));
  assert.equal(result.status, "pass");
});

test("checkClock fails when timedatectl reports NTPSynchronized=no", async () => {
  const result = await checkClock(async () => ({ stdout: "no\n" }));
  assert.equal(result.status, "fail");
});

test("checkClock reports unknown when timedatectl isn't available", async () => {
  const result = await checkClock(async () => { throw new Error("command not found"); });
  assert.equal(result.status, "unknown");
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
  const result = await checkDns([], {});
  assert.equal(result.status, "pass");
});

test("checkPort: a port expected to already be listening passes when it is", async () => {
  const result = await checkPort(22, true, async () => "in-use");
  assert.equal(result.status, "pass");
});

test("checkPort: a port expected to already be listening fails when it isn't", async () => {
  const result = await checkPort(22, true, async () => "free");
  assert.equal(result.status, "fail");
});

test("checkPort: a port expected to be free passes when it is", async () => {
  const result = await checkPort(80, false, async () => "free");
  assert.equal(result.status, "pass");
});

test("checkPort: a port expected to be free fails when something already holds it", async () => {
  const result = await checkPort(80, false, async () => "in-use");
  assert.equal(result.status, "fail");
});

test("checkPort: reports unknown rather than guessing when the probe can't tell", async () => {
  const result = await checkPort(80, false, async () => "unknown");
  assert.equal(result.status, "unknown");
});

test("checkPort actually binds and releases a real free port", async () => {
  const result = await checkPort(0, false); // port 0 -> OS picks a free ephemeral port, always free
  assert.equal(result.status, "pass");
});

test("checkDocker passes when both docker and docker compose respond", async () => {
  const result = await checkDocker(async () => ({ stdout: "ok" }));
  assert.equal(result.status, "pass");
});

test("checkDocker fails when Docker Engine isn't reachable", async () => {
  const result = await checkDocker(async () => { throw new Error("connection refused"); });
  assert.equal(result.status, "fail");
});

test("runPreflight: ok is false whenever any single check fails or is unknown", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-preflight-"));
  try {
    const servicesPath = path.join(directory, "services.yml");
    await writeFile(servicesPath, await import("node:fs/promises").then((m) => m.readFile(path.join(root, "examples/services.yml"), "utf8")));
    const { checks, ok } = await runPreflight({
      manifestPath: servicesPath,
      minFreeDiskBytes: 1,
      minTotalMemoryBytes: 1,
      minCpuCores: 1,
      execImpl: async () => { throw new Error("not available in this sandbox"); },
      resolver: { resolve4: async () => { throw new Error("no network"); }, resolve6: async () => { throw new Error("no network"); } },
      portProbe: async () => "unknown",
    });
    assert.equal(ok, false);
    assert.ok(checks.some((entry) => entry.id === "clock" && entry.status === "unknown"));
    assert.ok(checks.some((entry) => entry.id === "docker" && entry.status === "fail"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runPreflight: ok is true when every check is faked to pass", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-preflight-"));
  try {
    const servicesPath = path.join(directory, "services.yml");
    await writeFile(servicesPath, await import("node:fs/promises").then((m) => m.readFile(path.join(root, "examples/services.yml"), "utf8")));
    const { checks, ok } = await runPreflight({
      manifestPath: servicesPath,
      minFreeDiskBytes: 1,
      minTotalMemoryBytes: 1,
      minCpuCores: 1,
      execImpl: async () => ({ stdout: "yes\n" }),
      resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
      portProbe: async (port) => (port === 22 ? "in-use" : "free"),
    });
    assert.equal(ok, true);
    assert.equal(checks.length, 9);
    assert.ok(checks.every((entry) => entry.status === "pass"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runPreflight defaults catalogPath to hof-ops's own bundled catalog", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-preflight-"));
  try {
    const servicesPath = path.join(directory, "services.yml");
    await writeFile(servicesPath, await import("node:fs/promises").then((m) => m.readFile(path.join(root, "examples/services.yml"), "utf8")));
    const { ok } = await runPreflight({
      manifestPath: servicesPath,
      minFreeDiskBytes: 1,
      minTotalMemoryBytes: 1,
      minCpuCores: 1,
      execImpl: async () => ({ stdout: "yes\n" }),
      resolver: { resolve4: async () => ["203.0.113.10"], resolve6: async () => ["2001:db8::1"] },
      portProbe: async (port) => (port === 22 ? "in-use" : "free"),
    });
    assert.equal(ok, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
