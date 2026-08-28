#!/usr/bin/env node
// hofctl plan - the last piece of delivery item 7's read-only path
// (validate -> preflight -> plan). Wires the already-landed pure pieces
// (buildPlan/resolveBaseline/inspectTarget) into one real CLI flow:
// validate the deployment contracts exactly like `hofctl validate` does
// (including the release lock's real Cosign signature - never
// skippable here, unlike validate), inspect the target exactly once,
// refuse to plan against an incomplete observation, resolve the
// baseline, render the desired topology in-memory with the correct
// installation/generation semantics, and print exactly one plan
// document to stdout. Never writes anything, anywhere.
//
// A BOOTSTRAP target prints a real plan-v2 document (item 8, PR #31
// fix) - the exact same buildPlanV2() `hofctl apply` itself recomputes
// and requires --approve-plan-id/--plan to match byte-for-byte; before
// this fix, plan printed plan-v1 while apply independently required
// approval of a structurally different plan-v2 document, so a real
// `hofctl plan` run's own planId could never be the ID apply actually
// needed (see PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry). An
// APPLIED target (item 9, applied-mode reconciliation, doesn't exist
// yet - hofctl apply only ever supports a bootstrap plan, see ADR 0004)
// still prints the historical plan-v1 shape, informational only - there
// is nothing for a v2 plan to be approved for yet on an already-applied
// host.
//
// Deliberately its own module, not folded into hofctl.mjs, matching
// every other subcommand's own file (render-topology.mjs, preflight.mjs,
// validate-deployment.mjs) - hofctl.mjs stays a thin dispatcher.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { buildPlan } from "./plan.mjs";
import { buildPlanV2, planV2Validator } from "./plan-v2.mjs";
import { checkManagedStateReadable, observationFromSnapshot } from "./preflight.mjs";
import { renderTopology } from "./render-topology.mjs";
import { resolveBaseline } from "./state.mjs";
import { suppliedTlsCertificateFingerprint } from "./supplied-tls.mjs";
import { inspectTarget } from "./target-inspector.mjs";
import { loadAndValidateDeployment } from "./validate-deployment.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// A plan is computed entirely in memory and never actually applied, so
// there is no real installation yet to name on a bootstrap host - a
// fixed, deterministic placeholder (never a fresh randomUUID(), which
// would make planId change between two back-to-back `hofctl plan` runs
// against the same untouched host) stands in for it. The real
// installationId is assigned once, for real, by a future `hofctl apply`
// - this value is never written anywhere.
export const BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER = "00000000-0000-0000-0000-000000000000";

let compiledPlanValidator;
async function planValidator() {
  compiledPlanValidator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/plan-v1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  return compiledPlanValidator;
}

// Every way runPlan() can end without a plan at all - always a single
// human-readable diagnostic line plus a short machine-stable `reason`
// tag, never a thrown exception (the CLI wrapper below turns this
// straight into exit code 1, one line on stderr, nothing on stdout).
function blocked(reason, message) {
  return { blocked: true, reason, diagnostics: [message] };
}

// options: { manifestPath, catalogPath?, releaseLockPath, releaseLockIdentity,
//   releaseLockOidcIssuer?, targetMode?, knownHostsFile?, hostKeySha256?,
//   identityFile?, connectTimeoutSeconds?, repairDrift?, inspect?,
//   recoveryAgeRecipient? }
// recoveryAgeRecipient is required only when the target turns out to be
// a genuine bootstrap candidate (see buildPlanV2's own contract) - it's
// impossible to know that before inspecting the target, so this can't
// be validated any earlier than apply.mjs's own identical check is.
// inspect is a testing seam only (see plan-command.test.mjs) - the real
// CLI always gets the genuine inspectTarget.
export async function runPlan(options) {
  // Step 1 (schemas/cross-contracts/digests/signature) - identical gate
  // to `hofctl validate`, run before anything ever touches the network.
  // Never skippable here: plan has no --skip-signature at all.
  const { errors, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema } = await loadAndValidateDeployment({
    servicesPath: options.manifestPath,
    catalogPath: options.catalogPath,
    releaseLockPath: options.releaseLockPath,
    releaseLockIdentity: options.releaseLockIdentity,
    releaseLockOidcIssuer: options.releaseLockOidcIssuer,
    skipSignature: false,
  });
  if (errors.length > 0) return { blocked: true, reason: "deployment", diagnostics: errors };

  // Step 2: inspectTarget() exactly once - the one atomic snapshot every
  // later step reads from, so nothing can change underneath this plan
  // between what different steps separately look at.
  const targetMode = options.targetMode ?? "ssh";
  const host = manifest.target?.host;
  const port = manifest.target?.port ?? 22;
  const user = manifest.target?.user;
  const inspect = options.inspect ?? inspectTarget;

  let snapshot;
  try {
    snapshot = await inspect({
      targetMode, host, port, user,
      knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
      identityFile: options.identityFile, connectTimeoutSeconds: options.connectTimeoutSeconds,
    });
  } catch (error) {
    const where = targetMode === "local" ? "the local host" : `${user}@${host}:${port}`;
    return blocked("transport", `could not inspect ${where}: ${error instanceof Error ? error.message : error}`);
  }

  // Step 3: state/artifact/Docker completeness, checked once, up front,
  // for BOTH a bootstrap and an already-applied host - resolveBaseline()
  // only ever re-derives this itself for the bootstrap branch (see
  // state.mjs), and buildPlan()'s own blocker only re-checks
  // containersStatus, not volumes/networks/generated-artifacts. This is
  // the one place that refuses to plan at all - not just report a
  // degraded plan - when any single one of those listings couldn't be
  // read, on an installation that's already applied too.
  const readable = checkManagedStateReadable(snapshot);
  if (readable.status !== "pass") return blocked("state", readable.message);

  const observation = observationFromSnapshot(snapshot);
  // "absent" (Docker genuinely not installed) is not incomplete - it's
  // a real, positively-confirmed answer a genuinely clean bootstrap
  // host is expected to give. Only "unavailable" (installed but
  // couldn't be safely inspected) blocks here; resolveBaseline() below
  // still separately refuses "absent" on an already-applied baseline
  // (Docker vanishing from an existing installation is real corruption,
  // never silently treated as a fresh host).
  const incompleteDocker = ["containersStatus", "volumesStatus", "networksStatus"].filter((key) => observation[key] === "unavailable");
  if (incompleteDocker.length > 0) {
    return blocked("docker", `Docker's ${incompleteDocker.join("/")} listing could not be read - refusing to plan against an incomplete observation`);
  }
  if (observation.generatedArtifactsStatus !== "available") {
    return blocked("artifacts", "generated-artifact checksums could not be read - refusing to plan against an incomplete observation");
  }

  // Step 4 (baseline): resolveBaseline() itself already scopes a
  // bootstrap candidate to all three managed-resource kinds and folds
  // any conflicting/foreign/corrupt ownership into its own fail-closed
  // refusal (a thrown error) rather than a silently wrong baseline -
  // surfaced here as a normal blocked result, not an uncaught exception.
  let baseline;
  try {
    baseline = resolveBaseline({ managedState: snapshot.managedState, catalog, observation });
  } catch (error) {
    return blocked("state", error instanceof Error ? error.message : String(error));
  }

  if (baseline.mode === "bootstrap") {
    // Step 5v2: the exact same plan-v2 document `hofctl apply` itself
    // recomputes and requires --approve-plan-id/--plan to match. Target
    // binding, recovery recipient, and supplied-TLS fingerprint mirror
    // apply.mjs's own identical derivation exactly - a real value here,
    // not a caller-suppliable override, is what makes an operator-
    // approved planId actually mean something (see ADR 0004).
    let suppliedTls;
    try {
      suppliedTls = await suppliedTlsCertificateFingerprint(manifest);
    } catch (error) {
      return blocked("tls", error instanceof Error ? error.message : String(error));
    }
    if (!options.recoveryAgeRecipient) {
      return blocked("recovery", "--recovery-age-recipient is required (a bootstrap plan always needs one, see ADR 0004)");
    }

    const generation = 1;
    let desiredRendered;
    try {
      desiredRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId: BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER, generation });
    } catch (error) {
      return blocked("render", error instanceof Error ? error.message : String(error));
    }

    let plan;
    try {
      plan = buildPlanV2({
        baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift: options.repairDrift ?? false,
        target: { mode: targetMode, host, port, user, hostKeySha256: snapshot.transport.trustDigest },
        recoveryAgeRecipient: options.recoveryAgeRecipient,
        suppliedTlsCertificateFingerprint: suppliedTls,
      });
    } catch (error) {
      return blocked("plan", error instanceof Error ? error.message : String(error));
    }

    const validatePlanV2 = await planV2Validator();
    if (!validatePlanV2(plan)) {
      return blocked("internal", `buildPlanV2 produced a result that does not satisfy schemas/plan-v2.schema.json: ${JSON.stringify(validatePlanV2.errors)}`);
    }

    return { blocked: false, plan };
  }

  // baseline.mode === "applied": item 9 (applied-mode reconciliation)
  // doesn't exist yet, and hofctl apply only ever supports a bootstrap
  // plan (ADR 0004) - there is nothing for a v2 plan to be approved for
  // on an already-applied host. Stays the historical plan-v1 shape,
  // informational only.
  const installationId = baseline.installationId;
  const generation = baseline.generation + 1;
  let desiredRendered;
  try {
    desiredRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId, generation });
  } catch (error) {
    return blocked("render", error instanceof Error ? error.message : String(error));
  }

  // Step 6: buildPlan() itself - the pure core, unchanged by this CLI.
  const plan = buildPlan({ baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift: options.repairDrift ?? false });

  // Step 7: the plan this command is about to print must itself satisfy
  // its own published contract - an internal bug in buildPlan (or a
  // schema edited out of sync with it) must never reach a caller as a
  // plan-shaped object that isn't actually plan-v1.
  const validate = await planValidator();
  if (!validate(plan)) {
    return blocked("internal", `buildPlan produced a result that does not satisfy schemas/plan-v1.schema.json: ${JSON.stringify(validate.errors)}`);
  }

  return { blocked: false, plan };
}
