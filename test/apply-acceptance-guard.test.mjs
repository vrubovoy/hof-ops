// Regression test for Item 10 PR 0's privileged opt-in guard (review,
// Low finding): `node test/apply-acceptance.mjs` with
// HOF_ALLOW_PRIVILEGED_ACCEPTANCE unset must exit 0 having loaded
// nothing from apply-acceptance.impl.mjs - the guarantee "before any
// side effect" is now architectural (a thin entrypoint that
// dynamic-imports the impl only after the check), not just "the modules
// it imports happen not to touch Docker today".

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const entrypoint = path.join(root, "test/apply-acceptance.mjs");

test("test:apply-ssh without the opt-in exits 0 and never loads the impl module", async () => {
  const env = { ...process.env };
  delete env.HOF_ALLOW_PRIVILEGED_ACCEPTANCE;

  const { stdout, stderr } = await exec(process.execPath, [entrypoint], { env, timeout: 20_000 });

  assert.match(stdout, /skipped - privileged Docker acceptance is opt-in/);
  // The impl registers node:test cases whose names would appear in
  // stdout if it had loaded; the first one is unmistakable.
  assert.doesNotMatch(stdout + stderr, /bootstrap apply against the real, published, signed/);
  assert.doesNotMatch(stdout + stderr, /# tests \d/); // no test runner summary => impl never registered anything
});

test("the impl module is not matched by the default `pnpm test` glob", () => {
  // test/*.test.mjs must not pick up apply-acceptance.impl.mjs - the
  // suffix is the guard. A plain `pnpm test` must never load it.
  assert.doesNotMatch("apply-acceptance.impl.mjs", /\.test\.mjs$/);
});
