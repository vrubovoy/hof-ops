import test from "node:test";

import { runIntegrationMatrix } from "../scripts/integration-matrix.mjs";

test("topology matrix renders Compose from the pinned example lock", async () => {
  await runIntegrationMatrix({ lock: "examples/release-lock.json", runtime: false });
});
