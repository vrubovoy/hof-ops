import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { runIntegrationMatrix } from "../scripts/integration-matrix.mjs";

test("topology matrix renders Compose from the pinned example lock", async () => {
  await runIntegrationMatrix({ lock: "examples/release-lock.json", runtime: false });
});

test("topology fixtures are release-agnostic - a lock pinned to a different release still passes", async () => {
  const lock = JSON.parse(await readFile("examples/release-lock.json", "utf8"));
  assert.notEqual(lock.release, "9.9.9", "fixture assumption: the example lock isn't already 9.9.9");
  lock.release = "9.9.9";
  const directory = await mkdtemp(path.join(tmpdir(), "hof-release-agnostic-"));
  const lockPath = path.join(directory, "release-lock.json");
  await writeFile(lockPath, JSON.stringify(lock));

  await runIntegrationMatrix({ lock: lockPath, runtime: false });
});
