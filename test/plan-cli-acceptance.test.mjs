// Real-subprocess acceptance coverage for `hofctl plan` - spawns the
// actual scripts/hofctl.mjs binary (never imports its internals), with
// a fake docker/sudo pair (test/fixtures/target-probe-fake-docker) and a
// fake cosign (test/fixtures/plan-cli) on PATH so a genuine bootstrap
// plan can be computed end to end - real target-probe.sh under a real
// `sh`, real schema/cross-contract/signature validation, real buildPlan -
// without a real Docker daemon, sudoers grant, or Sigstore round trip.
// Complements plan-command.test.mjs's own unit-level orchestration
// coverage: this file's job is the CLI's own contract - flag parsing,
// stdout/stderr separation, and exit codes.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hofctlPath = path.join(root, "scripts/hofctl.mjs");
const examplesServices = path.join(root, "examples/services.yml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");
const fakeDockerDir = path.join(root, "test/fixtures/target-probe-fake-docker");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");

let workDir;
let signedReleaseLockPath;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-plan-cli-"));
  signedReleaseLockPath = path.join(workDir, "release-lock.json");
  await writeFile(signedReleaseLockPath, await readFile(examplesReleaseLock));
  await writeFile(`${signedReleaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${signedReleaseLockPath}.pem`, "fake-certificate\n");
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

function run(args, { env = {} } = {}) {
  return exec("node", [hofctlPath, ...args], {
    env: { ...process.env, PATH: `${fakeDockerDir}${path.delimiter}${fakeCosignDir}${path.delimiter}${process.env.PATH}`, ...env },
  });
}

async function expectFailure(args, env = {}) {
  try {
    const { stdout, stderr } = await run(args, { env });
    assert.fail(`expected a non-zero exit, got success with stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`);
  } catch (error) {
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

test("usage error: missing required flags exits 2 with empty stdout", async () => {
  const { code, stdout } = await expectFailure(["plan", "--services", examplesServices]);
  assert.equal(code, 2);
  assert.equal(stdout, "");
});

test("usage error: --skip-signature is rejected outright, never silently accepted", async () => {
  const { code, stdout, stderr } = await expectFailure([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local", "--skip-signature",
  ]);
  assert.equal(code, 2);
  assert.equal(stdout, "");
  assert.match(stderr, /does not accept --skip-signature/);
});

test("usage error: a duplicate flag is rejected, not silently overwritten", async () => {
  const { code, stdout, stderr } = await expectFailure([
    "plan", "--services", examplesServices, "--services", examplesServices,
    "--release-lock", signedReleaseLockPath, "--release-lock-identity", "test@example.com", "--target-mode", "local",
  ]);
  assert.equal(code, 2);
  assert.equal(stdout, "");
  assert.match(stderr, /duplicate flag/);
});

test("usage error: an unknown flag is rejected, not silently ignored", async () => {
  const { code, stdout, stderr } = await expectFailure([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local", "--min-cpu-cores", "2",
  ]);
  assert.equal(code, 2);
  assert.equal(stdout, "");
  assert.match(stderr, /unknown flag for plan/);
});

test("usage error: --target-mode local rejects SSH trust options", async () => {
  const { code } = await expectFailure([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local", "--known-hosts", "/tmp/kh",
  ]);
  assert.equal(code, 2);
});

test("blocked: missing signature sidecars exits 1, nothing on stdout, a real diagnostic on stderr", async () => {
  const { code, stdout, stderr } = await expectFailure([
    "plan", "--services", examplesServices, "--release-lock", examplesReleaseLock,
    "--release-lock-identity", "test@example.com", "--target-mode", "local",
  ]);
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.match(stderr, /no signature found/);
});

const RECOVERY_AGE_RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

test("a genuine end-to-end bootstrap plan through the real CLI: exactly one plan-v2 JSON document on stdout, exit 0", async () => {
  const { stdout, stderr } = await run([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local",
    "--recovery-age-recipient", RECOVERY_AGE_RECIPIENT,
  ], { env: { HOF_TEST_COSIGN_OUTCOME: "success" } });

  const lines = stdout.split("\n").filter((line) => line.length > 0);
  assert.equal(lines.length, 1, `stdout must contain exactly one line, got:\n${stdout}`);
  const plan = JSON.parse(lines[0]);
  // A bootstrap target now prints the same plan-v2 document hofctl
  // apply itself requires --approve-plan-id/--plan to match (PR #31
  // fix) - see PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry.
  assert.equal(plan.apiVersion, "hof.dev/plan/v2");
  assert.equal(plan.mode, "bootstrap");
  assert.equal(plan.executable, true);
  assert.ok(plan.summary.create > 0);
  assert.match(plan.planId, /^sha256:[0-9a-f]{64}$/);
  // Diagnostics (if any) stay on stderr, never mixed into stdout - this
  // run may still print nothing at all to stderr, which is fine too.
  assert.doesNotMatch(stderr, /hof\.dev\/plan\/v2/);
});

test("--repair-drift is accepted as a bare boolean flag (no value consumed after it)", async () => {
  const { stdout } = await run([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local", "--repair-drift",
    "--recovery-age-recipient", RECOVERY_AGE_RECIPIENT,
  ], { env: { HOF_TEST_COSIGN_OUTCOME: "success" } });
  const plan = JSON.parse(stdout.trim());
  assert.equal(plan.apiVersion, "hof.dev/plan/v2");
});

test("a bootstrap plan through the real CLI without --recovery-age-recipient is blocked (exit 1), not silently planned with none", async () => {
  const { code, stdout, stderr } = await expectFailure([
    "plan", "--services", examplesServices, "--release-lock", signedReleaseLockPath,
    "--release-lock-identity", "test@example.com", "--target-mode", "local",
  ], { HOF_TEST_COSIGN_OUTCOME: "success" });
  assert.equal(code, 1);
  assert.equal(stdout, "");
  assert.match(stderr, /--recovery-age-recipient is required/);
});
