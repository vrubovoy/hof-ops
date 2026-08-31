import assert from "node:assert/strict";
import test from "node:test";

import { APPLIED_ALLOWED_ACTIONS, validateAppliedActions } from "../scripts/applied-actions.mjs";

test("rejects a plan whose mode is not \"applied\"", () => {
  const errors = validateAppliedActions({ mode: "bootstrap", operations: [] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /plan mode is "bootstrap", not "applied"/);
});

test("rejects host.prepare explicitly, by name, even though it's a real action plan-v1/v2 can otherwise emit", () => {
  const errors = validateAppliedActions({ mode: "applied", operations: [{ id: "001.x", action: "host.prepare", resource: "host" }] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /only ever makes sense on a genuinely clean bootstrap host/);
});

test("rejects backup.create explicitly, out of item 9's own scope entirely - not merely \"not whitelisted\"", () => {
  const errors = validateAppliedActions({ mode: "applied", operations: [{ id: "001.x", action: "backup.create", resource: "kuvert-data" }] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /outside item 9's own scope entirely/);
});

test("allows service.stop and service.remove - the two actions bootstrap's own whitelist explicitly refuses, applied's own reason to exist", () => {
  for (const action of ["service.stop", "service.remove"]) {
    const errors = validateAppliedActions({ mode: "applied", operations: [{ id: "001.x", action, resource: "kuvert-backend" }] });
    assert.deepEqual(errors, [], action);
  }
});

test("rejects an unrecognized action outright", () => {
  const errors = validateAppliedActions({ mode: "applied", operations: [{ id: "001.x", action: "shell.exec", resource: "anything" }] });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /not in the applied action whitelist/);
});

test("collects every violation across multiple bad operations, not just the first", () => {
  const errors = validateAppliedActions({
    mode: "applied",
    operations: [
      { id: "001.x", action: "host.prepare", resource: "host" },
      { id: "002.x", action: "backup.create", resource: "kuvert-data" },
      { id: "003.x", action: "shell.exec", resource: "b" },
      { id: "004.x", action: "service.stop", resource: "a" },
    ],
  });
  assert.equal(errors.length, 3);
});

test("APPLIED_ALLOWED_ACTIONS matches exactly the whitelist the PR spec named, no more and no less - bootstrap's own set minus host.prepare, plus service.stop/service.remove", () => {
  assert.deepEqual(
    [...APPLIED_ALLOWED_ACTIONS].sort(),
    [
      "config.write", "database.migrate", "image.pull", "image.verify", "network.ensure",
      "readiness.wait", "secret.ensure", "service.remove", "service.start", "service.stop",
      "state.commit", "volume.ensure",
    ].sort(),
  );
});

test("undefined/missing operations list is treated as empty, never throws", () => {
  assert.deepEqual(validateAppliedActions({ mode: "applied" }), []);
});
