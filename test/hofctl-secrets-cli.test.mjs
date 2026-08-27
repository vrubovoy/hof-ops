// Real-subprocess coverage for `hofctl secrets ensure` - a fake sops
// binary on PATH (see test/fixtures/secrets-fake-sops), real files on
// disk, exercising the real CLI's own flag parsing, stdout/stderr
// separation, and exit codes exactly like plan-cli-acceptance.test.mjs
// already does for `hofctl plan`.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hofctlPath = path.join(root, "scripts/hofctl.mjs");
const fakeSopsDir = path.join(root, "test/fixtures/secrets-fake-sops");
const examplesServices = path.join(root, "examples/services.yml");

let workDir;
test.before(async () => { workDir = await mkdtemp(path.join(tmpdir(), "hof-secrets-cli-")); });
test.after(async () => { if (workDir) await rm(workDir, { recursive: true, force: true }); });

function run(args, env = {}) {
  return exec("node", [hofctlPath, ...args], { env: { ...process.env, PATH: `${fakeSopsDir}${path.delimiter}${process.env.PATH}`, ...env } });
}

async function expectFailure(args, env = {}) {
  try {
    const { stdout, stderr } = await run(args, env);
    assert.fail(`expected non-zero exit, got stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`);
  } catch (error) {
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

test("usage error: missing required flags exits 2", async () => {
  const { code, stdout } = await expectFailure(["secrets", "ensure", "--services", examplesServices]);
  assert.equal(code, 2);
  assert.equal(stdout, "");
});

test("usage error: an unknown secrets subcommand exits 2", async () => {
  const { code, stderr } = await expectFailure(["secrets", "rotate"]);
  assert.equal(code, 2);
  assert.match(stderr, /unknown secrets subcommand: rotate/);
});

test("a real end-to-end run generates every required secret name (never a value) as NDJSON, exit 0", async () => {
  const storePath = path.join(workDir, "fresh.sops.json");
  const { stdout } = await run(["secrets", "ensure", "--services", examplesServices, "--store", storePath, "--operator-age-recipient", "age1operator", "--recovery-age-recipient", "age1recovery"]);

  const lines = stdout.trim().split("\n").map((line) => JSON.parse(line));
  const added = lines.filter((line) => line.type === "secrets.added");
  const result = lines.find((line) => line.type === "secrets.result");
  assert.ok(added.length > 0);
  assert.equal(result.added, added.length);
  assert.equal(result.total, added.length);
  // Never a real value anywhere on stdout - only the fixed secret names.
  for (const entry of added) assert.match(entry.name, /^[a-z][a-z0-9-]+$/);
});

test("re-running against the same store, with the right identity, reports zero newly added", async () => {
  const storePath = path.join(workDir, "idempotent.sops.json");
  const identityFile = path.join(workDir, "operator.key");
  await (await import("node:fs/promises")).writeFile(identityFile, "age1operator\n");

  await run(["secrets", "ensure", "--services", examplesServices, "--store", storePath, "--operator-age-recipient", "age1operator", "--recovery-age-recipient", "age1recovery", "--identity-file", identityFile]);
  const { stdout } = await run(["secrets", "ensure", "--services", examplesServices, "--store", storePath, "--operator-age-recipient", "age1operator", "--recovery-age-recipient", "age1recovery", "--identity-file", identityFile]);

  const result = JSON.parse(stdout.trim().split("\n").at(-1));
  assert.equal(result.type, "secrets.result");
  assert.equal(result.added, 0);
});
