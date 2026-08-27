import assert from "node:assert/strict";
import test from "node:test";

import { loadContracts } from "../scripts/contracts.mjs";
import { buildPlanV2 } from "../scripts/plan-v2.mjs";
import { BOOTSTRAP_ALLOWED_ACTIONS, validateBootstrapActions } from "../scripts/bootstrap-actions.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { emptyBaseline } from "../scripts/state.mjs";

const RECOVERY_RECIPIENT = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqgpqyqszq";
const CLEAN_ABSENT_OBSERVATION = {
  containersStatus: "absent", resources: [],
  volumesStatus: "absent", volumes: [],
  networksStatus: "absent", networks: [],
  generatedArtifactsStatus: "available", generatedArtifacts: {},
};

async function realBootstrapPlan() {
  const contracts = await loadContracts();
  const rendered = renderTopology({ ...contracts, installationId: "00000000-0000-0000-0000-000000000000", generation: 1 });
  return buildPlanV2({
    baseline: emptyBaseline(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog,
    observation: CLEAN_ABSENT_OBSERVATION, repairDrift: false,
    target: { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: "SHA256:abcdefgh" },
    recoveryAgeRecipient: RECOVERY_RECIPIENT,
  });
}

test("a real, freshly-built bootstrap plan passes the whitelist cleanly - every operation buildPlan actually emits for a bootstrap is allowed", async () => {
  const plan = await realBootstrapPlan();
  assert.ok(plan.operations.length > 10, "sanity: this is a real, substantial operations list, not an empty one trivially passing");
  assert.deepEqual(validateBootstrapActions(plan), []);
});

test("rejects a plan whose mode is not \"bootstrap\"", () => {
  const errors = validateBootstrapActions({ mode: "applied", operations: [] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /plan mode is "applied", not "bootstrap"/);
});

test("rejects every applied-mode-only action explicitly, by name, even though it's a real action plan-v1/v2 can otherwise emit", () => {
  for (const action of ["backup.create", "service.stop", "service.remove"]) {
    const errors = validateBootstrapActions({ mode: "bootstrap", operations: [{ id: "001.x", action, resource: "kuvert-data" }] });
    assert.equal(errors.length, 1, action);
    assert.match(errors[0], /only ever makes sense against an already-applied host/, action);
  }
});

test("rejects an unrecognized action outright", () => {
  const errors = validateBootstrapActions({ mode: "bootstrap", operations: [{ id: "001.x", action: "shell.exec", resource: "anything" }] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /not in the bootstrap action whitelist/);
});

test("collects every violation across multiple bad operations, not just the first", () => {
  const errors = validateBootstrapActions({
    mode: "bootstrap",
    operations: [
      { id: "001.x", action: "service.stop", resource: "a" },
      { id: "002.x", action: "host.prepare", resource: "host" },
      { id: "003.x", action: "shell.exec", resource: "b" },
    ],
  });
  assert.equal(errors.length, 2);
});

test("BOOTSTRAP_ALLOWED_ACTIONS matches exactly the whitelist the PR spec named, no more and no less", () => {
  assert.deepEqual(
    [...BOOTSTRAP_ALLOWED_ACTIONS].sort(),
    [
      "config.write", "database.migrate", "host.prepare", "image.pull", "image.verify", "network.ensure",
      "readiness.wait", "secret.ensure", "service.start", "state.commit", "volume.ensure",
    ].sort(),
  );
});

test("undefined/missing operations list is treated as empty, never throws", () => {
  assert.deepEqual(validateBootstrapActions({ mode: "bootstrap" }), []);
});

test("a completely empty/undefined plan is still handled gracefully - reports the mode violation, doesn't crash", () => {
  assert.deepEqual(validateBootstrapActions({}), ['plan mode is undefined, not "bootstrap" - a bootstrap apply only ever runs a bootstrap plan']);
  assert.deepEqual(validateBootstrapActions(undefined), ['plan mode is undefined, not "bootstrap" - a bootstrap apply only ever runs a bootstrap plan']);
});
