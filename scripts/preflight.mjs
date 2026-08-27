#!/usr/bin/env node
// hofctl preflight - host-level checks that must be true before an
// Ansible run (or any apply) ever touches the host, matching the
// reconciliation plan's own role ordering (disk/RAM/CPU/clock -> DNS ->
// ports -> Docker). Read-only: it only inspects the host, it never
// changes anything.

import { execFile } from "node:child_process";
import dns from "node:dns/promises";
import { statfsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { publicHostnames } from "./render-topology.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Conservative floors, not yet backed by a published sizing guide -
// override with --min-free-disk-gb/--min-memory-gb/--min-cpu-cores if a
// real deployment needs different numbers. Chosen to comfortably run
// every mandatory service plus every optional one, restic backups, and
// normal container image churn on a small single-host deployment.
export const DEFAULT_THRESHOLDS = {
  minFreeDiskBytes: 20 * 1024 ** 3,
  minTotalMemoryBytes: 4 * 1024 ** 3,
  minCpuCores: 2,
};

function gib(bytes) {
  return (bytes / 1024 ** 3).toFixed(1);
}

function check(id, status, message) {
  return { id, status, message };
}

export function checkDisk(diskPath, minFreeDiskBytes) {
  try {
    const stats = statfsSync(diskPath);
    const freeBytes = stats.bavail * stats.bsize;
    if (freeBytes < minFreeDiskBytes) {
      return check("disk", "fail", `${diskPath} has ${gib(freeBytes)} GiB free, need at least ${gib(minFreeDiskBytes)} GiB`);
    }
    return check("disk", "pass", `${diskPath} has ${gib(freeBytes)} GiB free`);
  } catch (error) {
    return check("disk", "unknown", `could not stat ${diskPath}: ${error instanceof Error ? error.message : error}`);
  }
}

export function checkMemory(minTotalMemoryBytes, totalMemoryBytes = os.totalmem()) {
  if (totalMemoryBytes < minTotalMemoryBytes) {
    return check("memory", "fail", `host has ${gib(totalMemoryBytes)} GiB RAM, need at least ${gib(minTotalMemoryBytes)} GiB`);
  }
  return check("memory", "pass", `host has ${gib(totalMemoryBytes)} GiB RAM`);
}

export function checkCpu(minCpuCores, cpuCount = os.cpus().length) {
  if (cpuCount < minCpuCores) {
    return check("cpu", "fail", `host has ${cpuCount} CPU core(s), need at least ${minCpuCores}`);
  }
  return check("cpu", "pass", `host has ${cpuCount} CPU core(s)`);
}

export async function checkClock(execImpl = exec) {
  try {
    const { stdout } = await execImpl("timedatectl", ["show", "--property=NTPSynchronized", "--value"]);
    const synchronized = stdout.trim() === "yes";
    return synchronized
      ? check("clock", "pass", "system clock is NTP-synchronized")
      : check("clock", "fail", "system clock is not NTP-synchronized (timedatectl reports NTPSynchronized=no)");
  } catch (error) {
    return check("clock", "unknown", `could not determine NTP sync via timedatectl: ${error instanceof Error ? error.message : error}`);
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

// expectListening: true for a port that should already be bound (SSH -
// preflight is refusing to lock itself out, not asking SSH to be free),
// false for a port apply itself needs to claim (80/443 - must be free
// of any conflicting reverse proxy already sitting on it).
export function checkPort(port, expectListening, portProbe = defaultPortProbe) {
  return portProbe(port).then((state) => {
    if (state === "unknown") {
      return check(`port-${port}`, "unknown", `could not determine whether port ${port} is in use (needs root/CAP_NET_BIND_SERVICE to check ports below 1024)`);
    }
    const listening = state === "in-use";
    if (listening === expectListening) {
      return check(`port-${port}`, "pass", expectListening ? `port ${port} is listening as expected` : `port ${port} is free`);
    }
    return check(
      `port-${port}`,
      "fail",
      expectListening
        ? `port ${port} is not listening (expected sshd or an equivalent already bound)`
        : `port ${port} is already in use by something else - hofctl apply needs it free for the gateway`,
    );
  });
}

function defaultPortProbe(port) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", (error) => {
      if (error.code === "EADDRINUSE") resolve("in-use");
      else resolve("unknown"); // most commonly EACCES for <1024 without privilege
    });
    server.once("listening", () => {
      server.close(() => resolve("free"));
    });
    server.listen(port, "0.0.0.0");
  });
}

export async function checkDocker(execImpl = exec) {
  try {
    await execImpl("docker", ["version", "--format", "{{.Server.Version}}"]);
  } catch (error) {
    return check("docker", "fail", `Docker Engine is not reachable: ${error instanceof Error ? error.message : error}`);
  }
  try {
    await execImpl("docker", ["compose", "version"]);
  } catch (error) {
    return check("docker", "fail", `Docker Compose plugin is not available: ${error instanceof Error ? error.message : error}`);
  }
  return check("docker", "pass", "Docker Engine and the Compose plugin are both available");
}

// options: { manifestPath, catalogPath?, diskPath?, minFreeDiskBytes?,
//   minTotalMemoryBytes?, minCpuCores?, resolver?, execImpl?, portProbe? }
export async function runPreflight(options) {
  const catalogPath = options.catalogPath ?? path.join(root, "catalog/services-v1.yaml");
  const [manifest, catalog] = await Promise.all([
    readFile(options.manifestPath, "utf8").then(YAML.parse),
    readFile(catalogPath, "utf8").then(YAML.parse),
  ]);

  const thresholds = { ...DEFAULT_THRESHOLDS, ...options };
  const sshPort = manifest.target?.port ?? 22;
  const hostnames = publicHostnames(manifest, catalog);

  const checks = await Promise.all([
    checkDisk(options.diskPath ?? "/", thresholds.minFreeDiskBytes),
    checkMemory(thresholds.minTotalMemoryBytes),
    checkCpu(thresholds.minCpuCores),
    checkClock(options.execImpl),
    checkDns(hostnames, options.resolver),
    checkPort(sshPort, true, options.portProbe),
    checkPort(80, false, options.portProbe),
    checkPort(443, false, options.portProbe),
    checkDocker(options.execImpl),
  ]);

  // "unknown" fails closed - a host preflight can't tell an operator
  // "safe to proceed" about something it was unable to actually check.
  const ok = checks.every((entry) => entry.status === "pass");
  return { checks, ok };
}
