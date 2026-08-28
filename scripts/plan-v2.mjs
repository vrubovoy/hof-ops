// hofctl plan's v2 output - target-bound, bootstrap-only for delivery
// item 8 (see ADR 0004). Deliberately NOT wired into the real hofctl
// plan CLI in this PR - that happens once hofctl apply actually exists
// to consume --approve-plan-id (a later item-8 PR). This module is a
// pure wrapper around plan.mjs's own buildPlan() (the v1 diff engine,
// unchanged): it adds exact target binding, planning policy, per-
// image.verify trust policy (from the release lock), and the bootstrap-
// only recovery/suppliedTls fields, then recomputes planId over the
// whole v2 document. plan-v1 itself is untouched and stays the
// historical contract.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { sha256 } from "./digest.mjs";
import { buildPlan } from "./plan.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// One shared compiled validator for the whole plan-v2 document - both
// hofctl plan (which now produces this shape for a bootstrap target,
// see plan-command.mjs) and hofctl apply (which both validates a loaded
// --plan file against it and re-validates its own live recompute
// against it) must judge the exact same schema the exact same way; two
// independently-instantiated Ajv compilations of the same file is a
// real, if unlikely, way for the two to quietly drift.
let compiledValidator;
export async function planV2Validator() {
  compiledValidator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/plan-v2.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  return compiledValidator;
}

// The release lock's own per-artifact trust info, translated into the
// operation-carried shape apply will need (see plan-v2.schema.json's
// operation.imageTrust) - a first-party component is verified by real
// Cosign identity; a third-party one is trusted by digest pin alone
// (see release-lock-v1.schema.json's own thirdParty/trust split).
function imageTrustFor(component) {
  if (!component) return undefined;
  return component.thirdParty
    ? { policy: "digest-only" }
    : { policy: "signed", signatureIdentity: component.signatureIdentity, signatureOidcIssuer: component.signatureOidcIssuer };
}

// options: everything buildPlan() itself takes ({baseline,
//   desiredRendered, manifest, releaseLock, catalog, observation,
//   repairDrift}), plus:
//   target: {mode, host, port, user, hostKeySha256} - the raw
//     connection facts inspectTarget() actually observed (hostKeySha256
//     is inspectTarget()'s own snapshot.transport.trustDigest - the
//     real accepted fingerprint, see target-inspector.mjs). installationId
//     and baselineGeneration are never taken from the caller - they're
//     always derived from the resolved baseline itself, so a v2 plan's
//     own target binding can never disagree with what it was actually
//     diffed against.
//   recoveryAgeRecipient: string - required (this builder only ever
//     produces a bootstrap plan, and a bootstrap always needs one).
//   suppliedTlsCertificateFingerprint/suppliedTlsPrivateKeyFingerprint:
//     sha256 digests of the operator's own certificate/private-key
//     files, read, VALIDATED (key match, validity, SAN coverage - see
//     scripts/supplied-tls.mjs's own readSuppliedTlsMaterial), and
//     hashed at planning time - required together when manifest.tls.mode
//     is "supplied", must both be omitted otherwise.
export function buildPlanV2(options) {
  const { baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift, target, recoveryAgeRecipient, suppliedTlsCertificateFingerprint, suppliedTlsPrivateKeyFingerprint } = options;

  if (baseline.mode !== "bootstrap") {
    throw new Error("buildPlanV2 only ever produces a bootstrap plan in this delivery item - applied-mode reconciliation is a later delivery item, see ADR 0004");
  }
  if (!recoveryAgeRecipient) {
    throw new Error("a bootstrap plan requires an external age recovery recipient (recoveryAgeRecipient) - see ADR 0004");
  }
  if (manifest.tls.mode === "supplied" && (suppliedTlsCertificateFingerprint === undefined || suppliedTlsPrivateKeyFingerprint === undefined)) {
    throw new Error("manifest.tls.mode is \"supplied\" but no suppliedTlsCertificateFingerprint/suppliedTlsPrivateKeyFingerprint was given - the operator's certificate and private key files must be read, validated, and hashed before planning");
  }
  if (manifest.tls.mode !== "supplied" && (suppliedTlsCertificateFingerprint !== undefined || suppliedTlsPrivateKeyFingerprint !== undefined)) {
    throw new Error("suppliedTlsCertificateFingerprint/suppliedTlsPrivateKeyFingerprint was given but manifest.tls.mode is not \"supplied\"");
  }

  const v1 = buildPlan({ baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift });

  // Compose unit -> catalog artifact, so an image.verify operation's own
  // `resource` (the unit) can be mapped back to the release lock's own
  // component key - they diverge for Wächter (two units, one shared
  // artifact).
  const artifactByUnit = new Map();
  for (const service of Object.values(v1.desired.services)) {
    for (const [unit, entry] of Object.entries(service.units)) artifactByUnit.set(unit, entry.artifact);
  }
  const operations = v1.operations.map((operation) => {
    if (operation.action !== "image.verify") return operation;
    const imageTrust = imageTrustFor(releaseLock.components?.[artifactByUnit.get(operation.resource)]);
    return imageTrust ? { ...operation, imageTrust } : operation;
  });

  const plan = {
    apiVersion: "hof.dev/plan/v2",
    mode: v1.mode,
    executable: v1.executable,
    target: {
      mode: target.mode,
      host: target.host ?? null,
      port: target.port ?? null,
      user: target.user ?? null,
      // Always null in local mode, regardless of what the caller passed
      // - there is no SSH transport to fingerprint, matching
      // inspectTarget()'s own local-mode contract (transport.trustDigest
      // is always null there too).
      hostKeySha256: target.mode === "local" ? null : (target.hostKeySha256 ?? null),
      installationId: baseline.installationId,
      baselineGeneration: baseline.generation,
    },
    policy: { repairDrift: Boolean(repairDrift) },
    recovery: { ageRecipient: recoveryAgeRecipient },
    ...(suppliedTlsCertificateFingerprint !== undefined
      ? { suppliedTls: { mode: "supplied", certificateFingerprint: suppliedTlsCertificateFingerprint, privateKeyFingerprint: suppliedTlsPrivateKeyFingerprint } }
      : {}),
    baseline: v1.baseline,
    desired: v1.desired,
    drift: v1.drift,
    summary: v1.summary,
    operations,
    warnings: v1.warnings,
    blockers: v1.blockers,
  };

  return { ...plan, planId: computePlanId(plan) };
}

// The exact, canonical planId computation - a plan-v2 document (or
// plan-v1's own object, this formula is action-shape-agnostic) minus its
// own `planId` field, hashed. Exported so a caller reading a plan back
// off disk (a --plan file, or a journal's own embedded plan) can
// recompute this independently and confirm the document's own `planId`
// field genuinely matches its content - a schema-valid plan document
// with a stale or hand-edited `planId` field would otherwise be
// silently trusted (a real gap a 2026-08-28 review found: apply.mjs
// schema-validated a loaded --plan file and compared the caller's
// --approve-plan-id against the file's own `planId` property, but never
// confirmed that property was itself honest).
export function computePlanId(planWithoutId) {
  const { planId: _ignored, ...rest } = planWithoutId;
  return sha256(Buffer.from(JSON.stringify(rest)));
}
