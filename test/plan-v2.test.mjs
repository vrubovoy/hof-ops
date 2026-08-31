import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { loadContracts } from "../scripts/contracts.mjs";
import { buildPlanV2, computePlanId } from "../scripts/plan-v2.mjs";
import { renderTopology } from "../scripts/render-topology.mjs";
import { emptyBaseline, topologyToServiceState } from "../scripts/state.mjs";

const root = path.resolve(import.meta.dirname, "..");
const RECOVERY_RECIPIENT = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqgpqyqszq";

// Ajv's own strict mode otherwise rejects the schema's `allOf[0].then.
// required: ["recovery"]` branch (recovery is declared in the OUTER
// properties block, shared with the else branch, not repeated locally
// in `then`) - the exact same, already-accepted pattern release-lock-
// v1.schema.json's own thirdParty/trust split needed strictRequired:
// false for (see contracts.mjs).
async function planV2Validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  return ajv.compile(JSON.parse(await readFile(path.join(root, "schemas/plan-v2.schema.json"), "utf8")));
}

async function fixture(overrides = (contracts) => contracts) {
  const contracts = structuredClone(await loadContracts());
  overrides(contracts);
  const rendered = renderTopology({ ...contracts, installationId: "00000000-0000-0000-0000-000000000000", generation: 1 });
  return { contracts, rendered };
}

const CLEAN_ABSENT_OBSERVATION = {
  containersStatus: "absent", resources: [],
  volumesStatus: "absent", volumes: [],
  networksStatus: "absent", networks: [],
  generatedArtifactsStatus: "available", generatedArtifacts: {},
};

function bootstrapOptions(overrides = {}) {
  return {
    baseline: emptyBaseline(), observation: CLEAN_ABSENT_OBSERVATION, repairDrift: false,
    target: { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: "SHA256:abcdefgh" },
    recoveryAgeRecipient: RECOVERY_RECIPIENT,
    ...overrides,
  };
}

test("a genuine bootstrap plan-v2 document is schema-valid, with target binding and the bootstrap installation placeholder's own generation", async () => {
  const validate = await planV2Validator();
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });

  assert.ok(validate(plan), JSON.stringify(validate.errors));
  assert.equal(plan.apiVersion, "hof.dev/plan/v2");
  assert.equal(plan.mode, "bootstrap");
  assert.deepEqual(plan.target, {
    mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: "SHA256:abcdefgh",
    installationId: null, baselineGeneration: 0,
  });
  assert.deepEqual(plan.policy, { repairDrift: false });
  assert.deepEqual(plan.recovery, { ageRecipient: RECOVERY_RECIPIENT });
  assert.ok(!("suppliedTls" in plan), "acme-http01 (the fixture's default tls mode) never carries suppliedTls");
});

test("target binding always derives installationId/baselineGeneration from the resolved baseline, never from the caller's own target object", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({
    ...bootstrapOptions({ target: { mode: "ssh", host: "h", port: 22, user: "u", hostKeySha256: "SHA256:x", installationId: "should-be-ignored", baselineGeneration: 999 } }),
    desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog,
  });
  assert.equal(plan.target.installationId, null);
  assert.equal(plan.target.baselineGeneration, 0);
});

test("local mode always reports hostKeySha256: null in the target binding, even if the caller mistakenly passed one", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({
    ...bootstrapOptions({ target: { mode: "local", host: null, port: null, user: null, hostKeySha256: "SHA256:should-be-ignored" } }),
    desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog,
  });
  assert.equal(plan.target.mode, "local");
  assert.equal(plan.target.hostKeySha256, null);
});

test("a host-key change alone produces a different planId - the exact ADR 0004 property a target-bound plan needs", async () => {
  const { contracts, rendered } = await fixture();
  const base = { desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog };
  const planA = buildPlanV2({ ...bootstrapOptions({ target: { mode: "ssh", host: "h", port: 22, user: "u", hostKeySha256: "SHA256:aaaa" } }), ...base });
  const planB = buildPlanV2({ ...bootstrapOptions({ target: { mode: "ssh", host: "h", port: 22, user: "u", hostKeySha256: "SHA256:bbbb" } }), ...base });
  assert.notEqual(planA.planId, planB.planId);
});

// Item 9 (ADR 0005): schema-level forward-compat only - a real bootstrap
// plan (this test's own fixture) never carries these fields at all
// (buildPlan/buildPlanV2 don't emit them until the planner itself gains
// applied-mode support, plan.test.mjs's own job), but the schema must
// already accept a document that does, since a real applied plan will.
test("plan-v2 schema accepts baseline.retainedServices and baseline/desired suppliedTls*Fingerprint when present", async () => {
  const validate = await planV2Validator();
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });
  const withNewFields = {
    ...plan,
    baseline: {
      ...plan.baseline,
      retainedServices: { kuvert: { volume: "kuvert-backend-data", schemaVersion: 1, retainedAt: "2026-08-30T00:00:00Z" } },
      suppliedTlsCertificateFingerprint: "sha256:" + "8".repeat(64),
      suppliedTlsPrivateKeyFingerprint: "sha256:" + "9".repeat(64),
    },
    desired: { ...plan.desired, suppliedTlsCertificateFingerprint: "sha256:" + "8".repeat(64), suppliedTlsPrivateKeyFingerprint: "sha256:" + "9".repeat(64) },
  };
  assert.ok(validate(withNewFields), JSON.stringify(validate.errors));
});

test("planId is deterministic for identical inputs, including the target binding", async () => {
  const { contracts, rendered } = await fixture();
  const base = { desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog };
  const planA = buildPlanV2({ ...bootstrapOptions(), ...base });
  const planB = buildPlanV2({ ...bootstrapOptions(), ...base });
  assert.equal(planA.planId, planB.planId);
});

// A further, 2026-08-31 review found computePlanId() used plain
// JSON.stringify() directly - insertion-order-dependent, not actually
// canonical despite the name and every caller comment claiming
// otherwise. A document with the exact same content but differently
// ordered object keys (a different JS engine, a formatter, a
// content-preserving hand-edit) must recompute to the SAME planId;
// actual content changes must still recompute to a different one.

test("computePlanId: reordering an object's own keys never changes the id - only content does", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });

  const reorderKeysDeep = (value) => {
    if (Array.isArray(value)) return value.map(reorderKeysDeep);
    if (value !== null && typeof value === "object") {
      const reversed = {};
      for (const key of Object.keys(value).reverse()) reversed[key] = reorderKeysDeep(value[key]);
      return reversed;
    }
    return value;
  };
  const reordered = reorderKeysDeep(plan);
  assert.notDeepEqual(Object.keys(reordered), Object.keys(plan), "fixture assumption: reversing top-level keys must actually change their order");
  assert.equal(computePlanId(reordered), plan.planId, "same content, different key order, must recompute to the same planId");
});

test("computePlanId: an actual content change still changes the id, even after canonicalization", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });
  const tampered = { ...plan, policy: { repairDrift: !plan.policy.repairDrift } };
  assert.notEqual(computePlanId(tampered), plan.planId);
});

// Item 9 (ADR 0005): buildPlanV2 covers both baseline modes now - the
// bootstrap-only guard this used to test is gone. Mirrors plan.test.mjs's
// own "no-op: re-planning an untouched, fully-observed host changes
// nothing" convention: baseline and desiredRendered come from the exact
// SAME rendered topology (buildPlanV2 never re-renders desiredRendered
// itself with a bumped generation - that's plan-command.mjs's/apply.mjs's
// own job, done before calling in), so a genuine no-op needs no separate
// re-render just to prove the applied path produces a real, schema-valid
// plan-v2 document.
test("a genuine applied plan-v2 no-op document is schema-valid, mode: applied, with no recovery field and the baseline's own installationId/generation", async () => {
  const validate = await planV2Validator();
  const { contracts, rendered } = await fixture();
  const installationId = "00000000-0000-0000-0000-000000000000"; // this file's own fixture() renders with this fixed id
  const baseline = { mode: "applied", installationId, generation: 5, ...topologyToServiceState(rendered, contracts.catalog), generatedArtifacts: {} };

  const resources = Object.entries(baseline.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({ service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true, installationId }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId, kind, composeProject: "hof" });
  const observation = {
    containersStatus: "available", resources,
    volumesStatus: "available", volumes: baseline.volumes.map((name) => asResourceRecord(name, "volume")),
    networksStatus: "available", networks: baseline.networks.map((name) => asResourceRecord(name, "network")),
    generatedArtifactsStatus: "available", generatedArtifacts: {},
  };

  const plan = buildPlanV2({
    baseline, desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog,
    observation, repairDrift: false,
    target: { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: "SHA256:abcdefgh" },
  });

  assert.ok(validate(plan), JSON.stringify(validate.errors));
  assert.equal(plan.mode, "applied");
  assert.equal(plan.executable, true, plan.blockers.join("\n"));
  assert.deepEqual(plan.summary, { create: 0, update: 0, remove: 0, migrate: 0 });
  assert.deepEqual(plan.target, {
    mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: "SHA256:abcdefgh",
    installationId, baselineGeneration: 5,
  });
  assert.ok(!("recovery" in plan), "an applied plan never carries a recovery field - the schema forbids it");
});

test("refuses a bootstrap plan with no recovery age recipient at all", async () => {
  const { contracts, rendered } = await fixture();
  assert.throws(
    () => buildPlanV2({ ...bootstrapOptions({ recoveryAgeRecipient: undefined }), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog }),
    /requires an external age recovery recipient/,
  );
});

test("suppliedTls: both fingerprints required and embedded correctly when manifest.tls.mode is \"supplied\", omitted for acme-http01", async () => {
  const validate = await planV2Validator();
  const supplied = await fixture((c) => {
    c.manifest.tls = { mode: "supplied", certificatePath: "/etc/hof/tls/fullchain.pem", privateKeyPath: "/etc/hof/tls/privkey.pem" };
  });
  const certificateFingerprint = "sha256:" + "a".repeat(64);
  const privateKeyFingerprint = "sha256:" + "b".repeat(64);
  const plan = buildPlanV2({
    ...bootstrapOptions({ suppliedTlsCertificateFingerprint: certificateFingerprint, suppliedTlsPrivateKeyFingerprint: privateKeyFingerprint }),
    desiredRendered: supplied.rendered, manifest: supplied.contracts.manifest, releaseLock: supplied.contracts.releaseLock, catalog: supplied.contracts.catalog,
  });
  assert.deepEqual(plan.suppliedTls, { mode: "supplied", certificateFingerprint, privateKeyFingerprint });
  assert.ok(validate(plan), JSON.stringify(validate.errors));
});

test("suppliedTls: refuses to plan a \"supplied\" tls mode with no certificate/private-key fingerprint given", async () => {
  const supplied = await fixture((c) => {
    c.manifest.tls = { mode: "supplied", certificatePath: "/etc/hof/tls/fullchain.pem", privateKeyPath: "/etc/hof/tls/privkey.pem" };
  });
  assert.throws(
    () => buildPlanV2({ ...bootstrapOptions(), desiredRendered: supplied.rendered, manifest: supplied.contracts.manifest, releaseLock: supplied.contracts.releaseLock, catalog: supplied.contracts.catalog }),
    /manifest\.tls\.mode is "supplied" but no suppliedTlsCertificateFingerprint\/suppliedTlsPrivateKeyFingerprint was given/,
  );
  // Half-given (a real bug this test exists to catch: only one of the
  // two fingerprints supplied) must refuse too, not silently plan with
  // an incomplete pair.
  assert.throws(
    () => buildPlanV2({ ...bootstrapOptions({ suppliedTlsCertificateFingerprint: "sha256:" + "a".repeat(64) }), desiredRendered: supplied.rendered, manifest: supplied.contracts.manifest, releaseLock: supplied.contracts.releaseLock, catalog: supplied.contracts.catalog }),
    /manifest\.tls\.mode is "supplied" but no suppliedTlsCertificateFingerprint\/suppliedTlsPrivateKeyFingerprint was given/,
  );
});

test("suppliedTls: refuses a fingerprint given for a non-\"supplied\" tls mode", async () => {
  const { contracts, rendered } = await fixture();
  assert.throws(
    () => buildPlanV2({ ...bootstrapOptions({ suppliedTlsCertificateFingerprint: "sha256:" + "a".repeat(64), suppliedTlsPrivateKeyFingerprint: "sha256:" + "b".repeat(64) }), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog }),
    /suppliedTlsCertificateFingerprint\/suppliedTlsPrivateKeyFingerprint was given but manifest\.tls\.mode is not "supplied"/,
  );
});

test("imageTrust: a third-party component (the gateway) is digest-only; a first-party one carries its real signature identity", async () => {
  const { contracts, rendered } = await fixture();
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });

  const gateway = plan.operations.find((o) => o.action === "image.verify" && o.resource === "gateway");
  assert.deepEqual(gateway.imageTrust, { policy: "digest-only" });

  const schlussel = plan.operations.find((o) => o.action === "image.verify" && o.resource === "schlussel");
  assert.equal(schlussel.imageTrust.policy, "signed");
  assert.equal(schlussel.imageTrust.signatureIdentity, contracts.releaseLock.components.schlussel.signatureIdentity);
  assert.equal(schlussel.imageTrust.signatureOidcIssuer, contracts.releaseLock.components.schlussel.signatureOidcIssuer);

  // Non-image.verify operations never carry imageTrust at all.
  assert.ok(!plan.operations.some((o) => o.action !== "image.verify" && "imageTrust" in o));
});

test("imageTrust: Wächter's two units (sharing one catalog artifact) both resolve to that one shared component's own trust info", async () => {
  const wachter = await fixture((c) => { c.manifest.services.wachter.enabled = true; });
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: wachter.rendered, manifest: wachter.contracts.manifest, releaseLock: wachter.contracts.releaseLock, catalog: wachter.contracts.catalog });

  const api = plan.operations.find((o) => o.action === "image.verify" && o.resource === "wachter");
  const agent = plan.operations.find((o) => o.action === "image.verify" && o.resource === "wachter-agent");
  assert.equal(api.imageTrust.policy, "signed");
  assert.deepEqual(api.imageTrust, agent.imageTrust);
  assert.equal(api.imageTrust.signatureIdentity, wachter.contracts.releaseLock.components["wachter-backend"].signatureIdentity);
});

test("a real bootstrap plan-v2 is schema-valid end to end, including a full operations list", async () => {
  const validate = await planV2Validator();
  const { contracts, rendered } = await fixture((c) => { c.manifest.services.wachter.enabled = true; });
  const plan = buildPlanV2({ ...bootstrapOptions(), desiredRendered: rendered, manifest: contracts.manifest, releaseLock: contracts.releaseLock, catalog: contracts.catalog });
  assert.ok(plan.operations.length > 10);
  assert.ok(validate(plan), JSON.stringify(validate.errors));
});
