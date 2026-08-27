// Real-subprocess regression coverage for hofctl.mjs's own "validate"
// flag-to-option mapping - a gate-7 errata fix: --release-selection and
// --stable-channel were parsed into options.releaseSelection/
// options.stableChannel (parseFlags() derives the key directly from the
// flag name), but the code building validateDeployment()'s own options
// object only ever looked for releaseSelectionPath/stableChannelPath -
// two DIFFERENT keys - so a supplied --release-selection/--stable-channel
// file was silently never read or validated at all, no matter what it
// contained. Proven here the only way that's actually convincing: an
// invalid file passed via each flag must produce a real validation error
// that mentions it - if the flag were still being dropped, this would
// report a clean pass instead.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
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

let workDir;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-validate-cli-"));
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

async function runValidate(extraArgs) {
  try {
    const { stdout } = await exec("node", [
      hofctlPath, "validate", "--services", examplesServices, "--release-lock", examplesReleaseLock,
      "--skip-signature", ...extraArgs,
    ]);
    return stdout;
  } catch (error) {
    // hofctl validate exits 1 (not a thrown/fatal error) whenever
    // errors.length > 0 - the CLI's own JSON lines are still on stdout.
    return error.stdout;
  }
}

function parseValidateLines(stdout) {
  return stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

test("--release-selection is actually read and validated, not silently dropped", async () => {
  const invalidPath = path.join(workDir, "invalid-release-selection.yml");
  await writeFile(invalidPath, "apiVersion: hof.dev/release-selection/v1\n"); // missing every required component

  const stdout = await runValidate(["--release-selection", invalidPath]);
  const lines = parseValidateLines(stdout);
  const messages = lines.filter((line) => line.type === "validate.error").map((line) => line.message);
  assert.ok(
    messages.some((message) => message.startsWith("release selection: missing catalog artifact")),
    `expected a "release selection: missing catalog artifact ..." error, got:\n${JSON.stringify(messages, null, 2)}`,
  );
});

test("--stable-channel is actually read and validated, not silently dropped", async () => {
  const invalidPath = path.join(workDir, "invalid-stable-channel.json");
  await writeFile(invalidPath, JSON.stringify({ apiVersion: "hof.dev/channel/v1" })); // missing channel/release/tag/etc

  const stdout = await runValidate(["--stable-channel", invalidPath]);
  const lines = parseValidateLines(stdout);
  const messages = lines.filter((line) => line.type === "validate.error").map((line) => line.message);
  assert.ok(
    messages.some((message) => message.startsWith("stable channel")),
    `expected a "stable channel..." schema error, got:\n${JSON.stringify(messages, null, 2)}`,
  );
});

test("a genuinely valid --release-selection produces no release-selection-specific errors", async () => {
  const validPath = path.join(root, "examples/release-selection.yml");
  const stdout = await runValidate(["--release-selection", validPath]);
  const lines = parseValidateLines(stdout);
  const messages = lines.filter((line) => line.type === "validate.error").map((line) => line.message);
  assert.ok(!messages.some((message) => message.startsWith("release selection")), `unexpected release-selection error(s): ${JSON.stringify(messages, null, 2)}`);
});
