// Real-execution coverage for scripts/target-probe.sh itself - not
// mocked at the JS layer (see target-inspector.test.mjs for that), and
// not requiring a real Docker daemon or a real sudoers grant either
// (see test/ssh-acceptance.mjs, `pnpm test:ssh`, for the full real-SSH,
// real-container acceptance suite). Runs the genuine shell script under
// a real `sh`, with a fake docker/sudo pair on PATH (see
// test/fixtures/target-probe-fake-docker) that scripts exactly two
// scenarios the reviewer called out as needing real execution:
// Docker reachable only via sudo, and one of several `docker inspect`
// calls failing tainting the whole batch.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { inspectTarget } from "../scripts/target-inspector.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeBinDir = path.join(root, "test/fixtures/target-probe-fake-docker");

// A drop-in replacement for target-inspector.mjs's own internal
// defaultRun() (not exported - this is deliberately reimplemented, not
// imported, since the whole point is to inject a real env/PATH into a
// real child process) - the only difference from the real one is the
// extra env vars, so inspectTarget's own local-mode plumbing (reading
// the real target-probe.sh off disk, piping it over stdin to `sh -s`)
// is exercised completely unmodified.
function runWithEnv(env) {
  return (command, args, { input, timeout } = {}) => new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 8 * 1024 * 1024, timeout, env: { ...process.env, ...env } }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

function fakeDockerEnv(scenario) {
  return { PATH: `${fakeBinDir}${path.delimiter}${process.env.PATH}`, HOF_TEST_SCENARIO: scenario };
}

// A real, from-scratch PATH containing every tool target-probe.sh
// itself needs (resolved off the real system PATH, via `which`) plus
// the existing fake sudo (its generic true/cat/test/sha256sum handlers
// keep sudo_reads working) - but genuinely NO docker binary anywhere on
// it, real or fake. `command -v docker` fails for real here, exactly
// like it would on a fresh host Ansible hasn't provisioned yet - there
// is no way to fake "absent" by exiting 1 from a stub, since the whole
// point is that no file named "docker" exists on PATH at all.
let noDockerBinDir;
const REQUIRED_TOOLS = ["awk", "sed", "sort", "cat", "base64", "df", "uname", "nproc", "tr", "sh", "node"];
const OPTIONAL_TOOLS = ["ss", "netstat", "timedatectl"];

before(async () => {
  noDockerBinDir = await mkdtemp(path.join(tmpdir(), "hof-no-docker-path-"));
  for (const tool of REQUIRED_TOOLS) {
    const { stdout } = await exec("which", [tool]);
    await symlink(stdout.trim(), path.join(noDockerBinDir, tool));
  }
  for (const tool of OPTIONAL_TOOLS) {
    try {
      const { stdout } = await exec("which", [tool]);
      await symlink(stdout.trim(), path.join(noDockerBinDir, tool));
    } catch {
      // Genuinely optional - target-probe.sh itself already falls back
      // to "unknown"/tries the next tool when one of these is missing.
    }
  }
  await symlink(path.join(fakeBinDir, "sudo"), path.join(noDockerBinDir, "sudo"));
});

after(async () => {
  if (noDockerBinDir) await rm(noDockerBinDir, { recursive: true, force: true });
});

test("Docker reachable only via sudo: docker_run()'s plain-then-sudo fallback actually reaches a real container listing", async () => {
  const snapshot = await inspectTarget({ targetMode: "local", run: runWithEnv(fakeDockerEnv("sudo-only-success")) });

  assert.equal(snapshot.host.sudoNonInteractive, true);
  assert.equal(snapshot.docker.engineStatus, "available");
  assert.equal(snapshot.docker.composeAvailable, true);
  assert.equal(snapshot.docker.containersStatus, "available");
  assert.equal(snapshot.docker.resources.length, 1);
  assert.equal(snapshot.docker.resources[0].name, "c1");
  assert.equal(snapshot.docker.resources[0].managed, true);
  assert.equal(snapshot.docker.resources[0].installationId, "inst-1");
  assert.equal(snapshot.docker.resources[0].service, "kuvert");
  assert.equal(snapshot.docker.resources[0].unit, "kuvert-backend");
  // Volumes/networks are listed separately and independently succeed
  // (empty, in this fixture) - a container-listing success must not be
  // mistaken for the other two kinds also having been checked.
  assert.equal(snapshot.docker.volumesStatus, "available");
  assert.deepEqual(snapshot.docker.volumes, []);
  assert.equal(snapshot.docker.networksStatus, "available");
  assert.deepEqual(snapshot.docker.networks, []);
});

test("one of several docker inspect calls failing taints the whole containers batch as unavailable, with zero partial records", async () => {
  const snapshot = await inspectTarget({ targetMode: "local", run: runWithEnv(fakeDockerEnv("partial-failure")) });

  // Two containers are listed (c1, c2); c1's own inspect would succeed,
  // but c2's fails - the buffer-then-commit pattern must discard c1's
  // already-buffered record too, not silently emit a "complete-looking"
  // one-container result.
  assert.equal(snapshot.docker.containersStatus, "unavailable");
  assert.deepEqual(snapshot.docker.resources, []);
  // Docker itself is still genuinely reachable (engine/compose both
  // answered) - this is specifically a listing/inspect failure, not
  // "Docker is down".
  assert.equal(snapshot.docker.engineStatus, "available");
  assert.equal(snapshot.docker.composeAvailable, true);
});

test("Docker genuinely absent from PATH (no docker binary at all, real or fake) is reported absent on the engine and all three resource kinds, not unavailable", async () => {
  const snapshot = await inspectTarget({ targetMode: "local", run: runWithEnv({ PATH: noDockerBinDir }) });

  assert.equal(snapshot.docker.engineStatus, "absent");
  assert.equal(snapshot.docker.composeAvailable, false);
  assert.equal(snapshot.docker.containersStatus, "absent");
  assert.equal(snapshot.docker.volumesStatus, "absent");
  assert.equal(snapshot.docker.networksStatus, "absent");
  assert.deepEqual(snapshot.docker.resources, []);
  assert.deepEqual(snapshot.docker.volumes, []);
  assert.deepEqual(snapshot.docker.networks, []);
});

test("Docker installed but genuinely unreachable (every call fails, even via sudo) is reported unavailable, never confused with absent", async () => {
  const snapshot = await inspectTarget({ targetMode: "local", run: runWithEnv(fakeDockerEnv("docker-down")) });

  assert.equal(snapshot.docker.engineStatus, "unavailable");
  assert.equal(snapshot.docker.composeAvailable, false);
  assert.equal(snapshot.docker.containersStatus, "unavailable");
  assert.equal(snapshot.docker.volumesStatus, "unavailable");
  assert.equal(snapshot.docker.networksStatus, "unavailable");
});

// The positive-confirmation-only absence policy's "yes, genuinely
// absent" branch, exercised for real: this machine has no
// /var/lib/hof/state directory at all, sudo_reads is verified via a
// real `sudo -n cat /etc/hostname` (through the fake sudo, but against
// the real file), and `sudo -n test -e` on the real, nonexistent state
// path genuinely fails - "absent" here is root's own positive
// confirmation, not an unprivileged guess. See ssh-acceptance.mjs's own
// "no sudo access" test for the fail-closed "unreadable" counterpart.
test("a state file confirmed absent via a real (fake-sudo) root-level test -e is reported absent, not unreadable", async () => {
  const snapshot = await inspectTarget({ targetMode: "local", run: runWithEnv(fakeDockerEnv("sudo-only-success")) });

  assert.equal(snapshot.host.sudoNonInteractive, true);
  assert.equal(snapshot.managedState.currentStatus, "absent");
  assert.equal(snapshot.managedState.current, null);
  assert.equal(snapshot.managedState.topologyStatus, "absent");
  assert.equal(snapshot.managedState.topology, null);
});
