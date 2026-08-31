#!/usr/bin/env node
// hofctl apply - delivery item 8's own executor, wiring every contract
// PR #24-26 already landed (plan-v2, the operation lock/journal/event
// schemas, the bootstrap action whitelist, the pinned Execution
// Environment) into the real thing ADR 0004 describes. Deliberately its
// own module, matching every other subcommand (plan-command.mjs,
// preflight.mjs, render-topology.mjs) - hofctl.mjs stays a thin
// dispatcher.
//
// --target-mode local is refused outright (see the check below) - the
// Execution Environment runs as a container, and a local Ansible
// connection inside that container would mutate the CONTAINER's own
// filesystem, never the real host's. A loopback SSH target (the way
// this module's own real acceptance test - test/apply-acceptance.mjs -
// exercises it) is the genuine way to test apply locally; there is no
// shortcut around a real SSH transport here the way target-inspector.mjs's
// read-only local mode has.

import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { sha256 } from "./digest.mjs";
import { verifyExecutionEnvironmentSignature } from "./execution-environment.mjs";
import {
  assertEventValid, assertJournalResumable, assertJournalValid, assertLockValid, buildEvent, buildJournalDocument, buildLockDocument,
  currentOperator, decideStepResumption, newOperationId, withJournalStatus,
} from "./operation-journal.mjs";
import { checkArchitecture, checkManagedStateReadable, checkOs, observationFromSnapshot } from "./preflight.mjs";
import { validateBootstrapActions } from "./bootstrap-actions.mjs";
import { buildPlanV2, computePlanId, planV2Validator } from "./plan-v2.mjs";
import { BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER } from "./plan-command.mjs";
import {
  enabledServiceIds, renderedFilesContents, renderTopology,
  SUPPLIED_TLS_CERTIFICATE_SECRET_NAME, SUPPLIED_TLS_PRIVATE_KEY_SECRET_NAME,
} from "./render-topology.mjs";
import { readSecretsStore, requiredSecrets } from "./secrets.mjs";
import { resolveBaseline } from "./state.mjs";
import { readSuppliedTlsMaterial } from "./supplied-tls.mjs";
import { inspectTarget } from "./target-inspector.mjs";
import * as realMutate from "./target-mutate.mjs";
import { loadAndValidateDeployment } from "./validate-deployment.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function blocked(reason, message) {
  return { blocked: true, reason, diagnostics: [message] };
}

// A narrow, local validator for one read path only: resume's own
// state.commit crash-recovery check (see below) reads current.json off
// the target through target-mutate.mjs, a different transport than
// target-inspector.mjs's own (already schema-validating) read of the
// same file - this file's own conventions deliberately duplicate a
// schema check like this locally rather than share one across modules
// (see target-mutate.mjs's own SSH_HARDENING comment for the same
// reasoning applied elsewhere).
let stateV1Validator;
async function validateStateV1(value) {
  stateV1Validator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/state-v1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  if (!stateV1Validator(value)) {
    throw new Error(`current.json read from the target does not satisfy schemas/state-v1.schema.json: ${JSON.stringify(stateV1Validator.errors)}`);
  }
  return value;
}

// Every plan-v2 action this executor ever dispatches maps to exactly
// one of the ten roles baked into the Execution Environment (see
// ansible/roles/) - bootstrap-actions.mjs's own whitelist is what
// actually keeps `operation.action` restricted to this set before
// dispatch ever sees it; this map has no fallback/default entry on
// purpose; an action outside it is a genuine internal bug, never
// silently skipped.
const ACTION_TO_ROLE = {
  "host.prepare": "host",
  "secret.ensure": "secret",
  "volume.ensure": "volume",
  "network.ensure": "network",
  "image.verify": "image",
  "image.pull": "image",
  "config.write": "config",
  "database.migrate": "database",
  "service.start": "service",
  "readiness.wait": "readiness",
  "state.commit": "state",
};

// Builds this operation's own extra-vars, matching exactly the variable
// contract each role's own defaults/main.yml declares (see
// ansible/roles/*/defaults/main.yml). imageTrustByUnit carries forward
// an image.verify operation's own trust policy to the image.pull
// operation plan.mjs always emits immediately after it for the same
// unit (image.pull itself carries no imageTrust field of its own - see
// plan-v2.schema.json's own comment: "Only for image.verify").
// installationId/generation are the exact same values renderTopology()
// was called with - volume.ensure/network.ensure must label a resource
// identically to how Compose would have labeled it itself. secret.ensure
// and config.write don't carry their own real content here at all -
// dispatchOperation() below mounts it in separately (see its own
// comment on why: never through extra-vars/argv).
function buildExtraVars(operation, { commitGeneration, imageTrustByUnit, installationId, generation }) {
  const role = ACTION_TO_ROLE[operation.action];
  if (!role) throw new Error(`internal error: operation ${operation.id} has action ${operation.action}, which has no known Execution Environment role - this should have been rejected by the bootstrap action whitelist before dispatch`);
  const vars = { hof_role: role, hof_operation_id: operation.id };
  switch (operation.action) {
    case "host.prepare":
      break;
    case "secret.ensure":
      vars.hof_secrets_file = "/hof/secrets.json";
      break;
    case "volume.ensure":
      vars.hof_volume_name = operation.resource;
      vars.hof_installation_id = installationId;
      vars.hof_generation = generation;
      break;
    case "network.ensure":
      vars.hof_network_name = operation.resource;
      vars.hof_installation_id = installationId;
      vars.hof_generation = generation;
      break;
    case "image.verify":
      vars.hof_image_action = "verify";
      vars.hof_image_reference = operation.image;
      vars.hof_image_trust = operation.imageTrust;
      imageTrustByUnit.set(operation.resource, operation.imageTrust);
      break;
    case "image.pull": {
      const trust = imageTrustByUnit.get(operation.resource);
      if (!trust) throw new Error(`internal error: image.pull for ${operation.resource} (operation ${operation.id}) has no preceding image.verify in this plan - plan.mjs's own ordering invariant was violated`);
      vars.hof_image_action = "pull";
      vars.hof_image_reference = operation.image;
      vars.hof_image_trust = trust;
      break;
    }
    case "config.write":
      vars.hof_generated_files_dir = "/hof/generated";
      break;
    case "database.migrate":
      vars.hof_migrate_service = operation.resource;
      vars.hof_migrate_image = operation.image;
      vars.hof_migrate_argv = operation.argv;
      vars.hof_migrate_volume = operation.volume;
      vars.hof_migrate_schema = operation.schema;
      break;
    case "service.start":
      vars.hof_service_unit = operation.resource;
      vars.hof_service_image = operation.image;
      break;
    case "readiness.wait":
      vars.hof_readiness_unit = operation.resource;
      vars.hof_readiness_condition = operation.condition;
      break;
    case "state.commit":
      vars.hof_state_generation = commitGeneration;
      vars.hof_state_dir = "/hof/state";
      break;
    default:
      throw new Error(`internal error: no extra-vars mapping for action ${operation.action}`);
  }
  return vars;
}

function defaultExecFile(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { maxBuffer: 8 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
  });
}

// Never a raw exception dump into the journal/stdout event stream (see
// operation-event-v1.schema.json's own comment on `error`) - the last
// handful of lines only, truncated, nothing from the environment.
function sanitizeError(error) {
  const raw = [error?.stdout, error?.stderr, error?.message].filter(Boolean).join("\n");
  const lines = raw.split("\n").filter((line) => line.trim().length > 0);
  const tail = lines.slice(-8).join("\n");
  return (tail || "operation failed with no further diagnostic detail").slice(0, 2000);
}

// Runs one operation inside a fresh, throwaway Execution Environment
// container - never a long-running one (see ansible/Dockerfile's own
// "no ENTRYPOINT/CMD that runs anything on its own" comment). dockerRun
// is a testing seam (see apply.test.mjs); the real acceptance test
// (test/apply-acceptance.mjs) runs a genuine `docker run` against a
// genuine sudo-enabled ephemeral target.
async function dispatchOperation(operation, context) {
  const extraVars = buildExtraVars(operation, context);
  const args = ["run", "--rm"];
  // executionEnvironmentDockerNetwork is a narrow testing seam only
  // (see test/apply-acceptance.mjs) - a real target is a real remote
  // host, reached over the ordinary internet from Docker's own default
  // bridge network; there is no Docker network to join. The
  // acceptance test's own target runs on a private, test-only Docker
  // bridge network precisely so it never needs a published host port,
  // and the Execution Environment container must join that same
  // network to reach it - Docker's own inter-network isolation
  // otherwise refuses that traffic (confirmed for real: this container
  // could not reach the target's own bridge IP at all until it joined
  // the same network).
  if (context.dockerNetwork) args.push("--network", context.dockerNetwork);
  args.push(
    "--volume", `${context.identityFile}:/hof/identity:ro`,
    "--volume", `${context.knownHostsFile}:/hof/known_hosts:ro`,
    "--volume", `${context.inventoryFile}:/hof/inventory.ini:ro`,
  );
  // secret.ensure/config.write are the only two operations that need
  // real content mounted in beyond the fixed transport files above -
  // never through extra-vars/argv (visible to anything that can list
  // processes or inspect this container while it runs), and never
  // mounted for every OTHER operation that has no use for it.
  if (operation.action === "secret.ensure") {
    args.push("--volume", `${context.secretsFile}:/hof/secrets.json:ro`);
  }
  if (operation.action === "config.write") {
    args.push("--volume", `${context.generatedFilesDir}:/hof/generated:ro`);
  }
  if (operation.action === "state.commit") {
    args.push("--volume", `${context.stateDir}:/hof/state:ro`);
  }
  args.push(
    context.image,
    "ansible-playbook", "/ansible/playbook.yml",
    "-i", "/hof/inventory.ini",
    "-e", JSON.stringify(extraVars),
  );
  // A generous, flat budget covering every operation kind, not just a
  // quick SSH round trip: readiness.wait's own retry budget alone can
  // run up to 2 minutes (see ansible/roles/readiness/tasks/main.yml),
  // and host.prepare's real apt-get install of Docker or a real
  // database.migrate can each legitimately take a while too.
  await context.dockerRun("docker", args, { timeout: (context.connectTimeoutSeconds + 300) * 1000 });
}

function buildInventory({ host, port, user, connectTimeoutSeconds }) {
  const sshCommonArgs = [
    "-o StrictHostKeyChecking=yes",
    "-o UserKnownHostsFile=/hof/known_hosts",
    "-o GlobalKnownHostsFile=/dev/null",
    "-o BatchMode=yes",
    `-o ConnectTimeout=${connectTimeoutSeconds}`,
    // Same reasoning as target-inspector.mjs's/target-mutate.mjs's own
    // identical hardening (a 2026-08-28 review found this exact
    // Ansible-facing connection - carrying every real mutation and
    // secret delivery - was the one SSH channel this platform makes
    // that had been missed) - never let a stray ~/.ssh/config
    // ProxyJump/ProxyCommand for this hostname silently route the
    // Execution Environment's own connection through an intermediary
    // the target binding never recorded.
    "-o ProxyCommand=none",
    "-o ProxyJump=none",
  ].join(" ");
  return `target ansible_host=${host} ansible_port=${port} ansible_user=${user} ansible_ssh_private_key_file=/hof/identity ansible_ssh_common_args="${sshCommonArgs}"\n`;
}

// A shallow, top-level-key diff between two plan-v2 documents whose
// planIds differ - purely a diagnostic aid (which section actually
// changed: baseline? desired? operations? the recovery recipient?),
// never itself part of the actual equality decision (planId equality
// already is that, since planId = sha256(JSON.stringify(plan)) - see
// plan-v2.mjs). If every top-level key looks identical despite a
// different planId, that itself is worth surfacing (a canonicalization
// bug, not a real content change).
function summarizePlanDiff(approved, recomputed) {
  const keys = new Set([...Object.keys(approved), ...Object.keys(recomputed)]);
  const differing = [...keys].filter((key) => JSON.stringify(approved[key]) !== JSON.stringify(recomputed[key]));
  return differing.length > 0
    ? `differs in: ${differing.join(", ")}`
    : "every top-level field looks identical despite a different planId - this points at a canonicalization bug, not a real content change";
}

// The one real plan-v2 computation a fresh (non-resume) apply run needs
// twice: once before the lock is ever acquired (so a plan that's
// already stale doesn't cost a wasted lock round trip), and once again
// after the lock is held, against a second, genuinely fresh inspection
// (ADR 0004's own stale-plan recheck, now a full canonical-document
// recompute rather than a 3-field comparison - see PLATFORM-OPS-PLAN.md's
// "Item 8 reopened" entry). Factored out once rather than duplicated so
// the two calls can never quietly drift apart from each other.
// Returns either a blocked() result or { plan }.
// Reports whether releaseLock() genuinely cleared the target's own lock
// file - never swallowed into a bare `.catch(() => {})` and never
// discarded the { released: false } case either, the way this file used
// to (a further, 2026-08-31 review found that pattern could report
// blocked: false to the caller while the target stayed genuinely
// locked: a real transport failure was silently discarded, and even a
// clean "mismatch" response was never looked at).
async function tryReleaseLock(m, mutateConn, operationId) {
  try {
    const result = await m.releaseLock(mutateConn, operationId);
    return result.released
      ? { released: true }
      : { released: false, note: `releaseLock reported a mismatch for operation ${operationId} - the target's own lock file no longer matches this operationId (held by a different operation, or already removed by hand)` };
  } catch (error) {
    return { released: false, note: `releaseLock failed: ${error instanceof Error ? error.message : error}` };
  }
}

async function computeLivePlanV2({ snapshot, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, targetMode, host, port, user, recoveryAgeRecipient, repairDrift }) {
  // `hofctl preflight` already runs this exact check, but apply itself
  // never required a successful preflight run first, and the Ansible
  // roles' own OS assert (host role) only runs AFTER host.prepare has
  // already started a real apt-get install - too late to be the actual
  // mutating boundary. Checked here, on every live recompute (so it's
  // re-verified under the lock too, not just once at the very start),
  // before anything about this target's own topology is even resolved.
  const osCheck = checkOs(snapshot);
  if (osCheck.status !== "pass") return blocked("platform", osCheck.message);
  const architectureCheck = checkArchitecture(snapshot);
  if (architectureCheck.status !== "pass") return blocked("platform", architectureCheck.message);

  const readable = checkManagedStateReadable(snapshot);
  if (readable.status !== "pass") return blocked("state", readable.message);
  const observation = observationFromSnapshot(snapshot);
  const incompleteDocker = ["containersStatus", "volumesStatus", "networksStatus"].filter((key) => observation[key] === "unavailable");
  if (incompleteDocker.length > 0) return blocked("docker", `Docker's ${incompleteDocker.join("/")} listing could not be read - refusing to apply against an incomplete observation`);
  if (observation.generatedArtifactsStatus !== "available") return blocked("artifacts", "generated-artifact checksums could not be read - refusing to apply against an incomplete observation");

  let baseline;
  try {
    baseline = resolveBaseline({ managedState: snapshot.managedState, catalog, observation });
  } catch (error) {
    return blocked("state", error instanceof Error ? error.message : String(error));
  }
  if (baseline.mode !== "bootstrap") return blocked("scope", "hofctl apply only supports a bootstrap plan in this delivery item (see ADR 0004) - this target already has an applied installation");

  let suppliedTls;
  try {
    suppliedTls = await readSuppliedTlsMaterial(manifest, catalog);
  } catch (error) {
    return blocked("tls", error instanceof Error ? error.message : String(error));
  }
  if (!recoveryAgeRecipient) {
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
      baseline, desiredRendered, manifest, releaseLock, catalog, observation, repairDrift: repairDrift ?? false,
      target: { mode: targetMode, host, port, user, hostKeySha256: snapshot.transport.trustDigest },
      recoveryAgeRecipient,
      suppliedTlsCertificateFingerprint: suppliedTls?.certificateFingerprint,
      suppliedTlsPrivateKeyFingerprint: suppliedTls?.privateKeyFingerprint,
    });
  } catch (error) {
    return blocked("plan", error instanceof Error ? error.message : String(error));
  }

  const validatePlanV2 = await planV2Validator();
  if (!validatePlanV2(plan)) return blocked("internal", `buildPlanV2 produced a result that does not satisfy schemas/plan-v2.schema.json: ${JSON.stringify(validatePlanV2.errors)}`);
  if (!plan.executable) return blocked("plan", `plan has blockers, refusing to apply: ${plan.blockers.join("; ")}`);

  const whitelistErrors = validateBootstrapActions(plan);
  if (whitelistErrors.length > 0) return blocked("bootstrap-actions", whitelistErrors.join("; "));

  return { plan };
}

// options: everything runPlan() itself takes (manifestPath, catalogPath?,
//   releaseLockPath, releaseLockIdentity, releaseLockOidcIssuer?,
//   targetMode, host, port, user, knownHostsFile?, hostKeySha256?,
//   identityFile, connectTimeoutSeconds?, repairDrift?), plus:
//   recoveryAgeRecipient - required, even on resume (buildPlanV2 needs
//     the exact same value again to reproduce the identical planId).
//   secretsStorePath - the operator's own secrets.sops.yaml (see
//     scripts/secrets.mjs) - required whenever this deployment's own
//     requiredSecrets() is non-empty, ignored otherwise.
//   secretsAgeIdentityFile - optional age identity file for decrypting
//     secretsStorePath (SOPS_AGE_KEY_FILE); omitted, sops falls back to
//     its own default identity resolution.
//   planPath - path to the exact plan-v2 JSON document being approved
//     (required unless resume: true) - `hofctl plan` against a
//     bootstrap target now prints exactly this document (see
//     plan-command.mjs); approvePlanId must equal ITS OWN planId, and
//     apply's own live recompute (both before and, again, under the
//     lock) must match it byte-for-byte, or apply refuses to proceed.
//   approvePlanId - required unless resume: true.
//   resume - reclaim an existing, interrupted operation instead of
//     starting a new one; no new approval, see ADR 0004. Never re-derives
//     a live baseline/diff (see the resume branch below for why) -
//     trusts the journal's own embedded plan document completely, after
//     confirming the underlying inputs and target identity haven't
//     silently changed since it was written.
//   emit(event) - called once per operation-event-v1 (and a few
//     apply-specific informational lines) as they happen, for bounded
//     NDJSON streaming to stdout. Defaults to a no-op.
//   inspect, verifyEeSignature, dockerRun, mutate, run,
//   executionEnvironmentImageOverride, executionEnvironmentDockerNetwork,
//   readSecretsStore - testing seams; the real CLI never passes them.
export async function runApply(options) {
  const emit = options.emit ?? (() => {});
  // The target-mutate layer's own transport correctness (script
  // shape, base64 payload encoding, response parsing) is already
  // covered directly by target-mutate.test.mjs - `m` lets apply.test.mjs
  // inject a lightweight in-memory fake instead of re-driving all of
  // that through a second layer of mocked SSH calls, so its own tests
  // stay focused on this module's own orchestration (lock/resume/
  // stale-plan/failure handling).
  const m = options.mutate ?? realMutate;
  const targetMode = options.targetMode ?? "ssh";
  if (targetMode !== "ssh") {
    return blocked("target-mode", "hofctl apply only supports --target-mode ssh - the Execution Environment runs in a container, and a local Ansible connection inside it would mutate the container's own filesystem, never the real host's");
  }
  if (!options.identityFile) {
    return blocked("identity", "hofctl apply requires --identity-file - the Execution Environment container needs a real key file to mount, an SSH agent is not supported");
  }
  if (!options.resume && (!options.approvePlanId || !options.planPath)) {
    return blocked("approval", "hofctl apply requires both --approve-plan-id and --plan (the exact plan-v2 document being approved) unless --resume is given - approving a plan approves that exact content, see ADR 0004");
  }

  const { errors, manifest, catalog, catalogBytes, releaseLock, releaseLockBytes, servicesBytes, servicesSchema, catalogSchema, releaseLockSchema } =
    await loadAndValidateDeploymentWithBytes(options);
  if (errors.length > 0) return { blocked: true, reason: "deployment", diagnostics: errors };
  if (!releaseLock.ansibleEnvironment) return blocked("execution-environment", "release lock has no ansibleEnvironment - cannot apply");

  // Fails fast, before ever touching the network: the Execution
  // Environment's own signature doesn't depend on the target at all.
  const verifyEeSignature = options.verifyEeSignature ?? verifyExecutionEnvironmentSignature;
  try {
    await verifyEeSignature(releaseLock.ansibleEnvironment);
  } catch (error) {
    return blocked("execution-environment", error instanceof Error ? error.message : String(error));
  }

  // Fails fast, before ever touching the network, when this deployment
  // needs secrets but wasn't given a store to read them from - the same
  // real `sops --decrypt` scripts/secrets.mjs's own hofctl secrets
  // ensure already uses, never a second, independently-maintained
  // decryption path.
  const enabledIds = enabledServiceIds(manifest, catalog);
  const required = requiredSecrets(manifest, enabledIds);
  let secretValues = {};
  if (required.length > 0) {
    if (!options.secretsStorePath) {
      return blocked("secrets", `this deployment needs ${required.length} secret(s) (${required.map((s) => s.name).join(", ")}) but --secrets-store was not given`);
    }
    let decrypted;
    try {
      const readStore = options.readSecretsStore ?? readSecretsStore;
      decrypted = await readStore({ storePath: options.secretsStorePath, identityFile: options.secretsAgeIdentityFile });
    } catch (error) {
      return blocked("secrets", `could not decrypt ${options.secretsStorePath}: ${error instanceof Error ? error.message : error}`);
    }
    const missing = required.filter((s) => !(s.name in decrypted)).map((s) => s.name);
    if (missing.length > 0) {
      return blocked("secrets", `${options.secretsStorePath} is missing required secret(s): ${missing.join(", ")} - run "hofctl secrets ensure" first`);
    }
    // Only the subset this deployment actually needs - a store that
    // also carries secrets for an unrelated, disabled service must
    // never leak those into the Execution Environment container too.
    for (const { name } of required) secretValues[name] = decrypted[name];
  }

  // Fails fast, before ever touching the network: --plan is loaded and
  // matched against --approve-plan-id up front, on a fresh (non-resume)
  // run only - a resume never takes a new approval (see ADR 0004) and
  // reads its own plan straight from the journal further down instead.
  let approvedPlan;
  if (!options.resume) {
    let approvedPlanRaw;
    try {
      approvedPlanRaw = JSON.parse(await readFile(options.planPath, "utf8"));
    } catch (error) {
      return blocked("plan-file", `could not read/parse --plan ${options.planPath}: ${error instanceof Error ? error.message : error}`);
    }
    const validatePlanV2 = await planV2Validator();
    if (!validatePlanV2(approvedPlanRaw)) {
      return blocked("plan-file", `--plan ${options.planPath} does not satisfy schemas/plan-v2.schema.json: ${JSON.stringify(validatePlanV2.errors)}`);
    }
    // Schema validity alone doesn't prove the file's own `planId` field
    // is honest - a hand-edited, still schema-valid plan (any field
    // changed, the original `planId` left in place) would otherwise be
    // silently accepted here, only ever caught later by the live
    // recompute below (which is real protection, but "approving a plan
    // approves that exact content" - ADR 0004 - deserves catching a
    // tampered file at the file itself, not just downstream).
    // computePlanId() canonicalizes before hashing (recursively sorted
    // object keys, array order preserved) - a document with the same
    // content but differently ordered keys still recomputes to the same
    // planId; any actual content change never does.
    const recomputedFileId = computePlanId(approvedPlanRaw);
    if (recomputedFileId !== approvedPlanRaw.planId) {
      return blocked("plan-file", `--plan ${options.planPath}'s own planId field (${approvedPlanRaw.planId}) does not match its own content (recomputes to ${recomputedFileId}) - refusing to trust a plan file whose own identity doesn't match its content`);
    }
    approvedPlan = approvedPlanRaw;
    if (options.approvePlanId !== approvedPlan.planId) {
      return blocked("approval", `--approve-plan-id ${options.approvePlanId} does not match the plan file's own planId ${approvedPlan.planId} (${options.planPath}) - approving a plan approves that exact content, see ADR 0004`);
    }
  }

  const host = manifest.target?.host;
  const port = manifest.target?.port ?? 22;
  const user = manifest.target?.user;
  const inspect = options.inspect ?? inspectTarget;
  const connectTimeoutSeconds = options.connectTimeoutSeconds ?? 10;

  let snapshot;
  try {
    snapshot = await inspect({
      targetMode, host, port, user,
      knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
      identityFile: options.identityFile, connectTimeoutSeconds,
    });
  } catch (error) {
    return blocked("transport", `could not inspect ${user}@${host}:${port}: ${error instanceof Error ? error.message : error}`);
  }
  if (!snapshot.host.sudoNonInteractive) {
    return blocked("sudo", "passwordless sudo is required for apply (see hofctl preflight) - it was not confirmed on this target");
  }

  const mutateRun = options.run;
  const mutateConn = { mode: "ssh", host, port, user, hostKeySha256: snapshot.transport.trustDigest, identityFile: options.identityFile, connectTimeoutSeconds, run: mutateRun };

  const generation = 1; // apply only ever supports a bootstrap plan (ADR 0004) - a bootstrap always commits generation 1.

  let operationId;
  let plan;
  let journal;
  let inputDigests;

  if (options.resume) {
    // Deliberately never re-derives a live baseline/diff here (unlike
    // the fresh path below) - once any real mutation has already
    // happened (a created volume/network/container, before
    // state.commit), a fresh resolveBaseline() would see an
    // already-applied host and wrongly refuse to resume at all, which
    // is exactly the case resume exists for (see PLATFORM-OPS-PLAN.md's
    // "Item 8 reopened" entry, finding #2). Trusts the journal's own
    // embedded plan document completely instead, after confirming the
    // inputs it was journaled against haven't silently changed.
    const { status, lock } = await m.readLock(mutateConn);
    if (status !== "present") return blocked("resume", "no lock found on this target - there is nothing to resume");
    // target-mutate.mjs's own readLock() only ever JSON.parses the raw
    // bytes it reads back - a hand-tampered or genuinely corrupted lock
    // document must never be silently trusted before this run acts on
    // its own operationId field.
    try {
      await assertLockValid(lock);
    } catch (error) {
      return blocked("resume", `the lock on the target does not satisfy its own schema - refusing to trust it: ${error instanceof Error ? error.message : error}`);
    }
    operationId = lock.operationId;

    const { status: journalStatus, journal: existing } = await m.readJournal(mutateConn, operationId);
    if (journalStatus !== "present") {
      // Lock and journal are now always created together, as one remote
      // operation (see acquireLockAndJournal()'s own comment) - no
      // operation is EVER dispatched before both durably exist, so a
      // lock with no journal proves nothing has actually run yet. Safe
      // to clean up and hand the operator back to a fresh apply - this
      // isn't "guessing" about a real operation outcome, there wasn't
      // one (a further, 2026-08-31 review found this case used to
      // refuse forever, with no recovery path at all).
      const release = await tryReleaseLock(m, mutateConn, operationId);
      return blocked("resume", `lock references operation ${operationId} but its journal could not be read (status: ${journalStatus}) - since no operation ever dispatches before both are created together, nothing has actually run yet; ${release.released ? "the stale lock has been released - run a fresh (non-resume) apply" : `the stale lock could not be released (${release.note}) - investigate the target directly`}`);
    }
    try {
      await assertJournalValid(existing);
    } catch (error) {
      return blocked("resume", `the journal for operation ${operationId} does not satisfy its own schema - refusing to trust it: ${error instanceof Error ? error.message : error}`);
    }

    // Every durable document this resume is about to trust must first
    // agree about WHICH operation this is and WHAT was approved - a
    // further, 2026-08-31 review found this cross-binding used to be
    // partial (only the plan/journal/target triple below) and, worse,
    // entirely skipped by the succeeded fast path further down. Checked
    // here, unconditionally, before anything branches on journal status.
    if (existing.operationId !== lock.operationId) {
      return blocked("resume", `the journal's own operationId (${existing.operationId}) does not match the lock's (${lock.operationId}) - refusing to trust either`);
    }
    if (existing.approvedPlanId !== lock.approvedPlanId) {
      return blocked("resume", `the journal's own approvedPlanId (${existing.approvedPlanId}) does not match the lock's (${lock.approvedPlanId}) - refusing to trust either`);
    }

    // The journal's own embedded plan is what every later step in this
    // resume run trusts completely (operations[], the real installation
    // id, the target binding) - assertJournalValid() above only checked
    // the OUTER journal shape (plan itself is loosely typed there on
    // purpose, see that schema's own comment), so a hand-tampered or
    // corrupted embedded plan would otherwise reach dispatch unchecked.
    // Also moved ahead of the succeeded fast path below, for the same
    // reason as the cross-binding checks just above.
    const validateEmbeddedPlan = await planV2Validator();
    if (!validateEmbeddedPlan(existing.plan)) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan that does not satisfy schemas/plan-v2.schema.json - refusing to trust it: ${JSON.stringify(validateEmbeddedPlan.errors)}`);
    }
    if (computePlanId(existing.plan) !== existing.plan.planId || existing.plan.planId !== existing.approvedPlanId || existing.plan.planId !== lock.approvedPlanId) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan whose own planId does not match its content, its own approvedPlanId, or the lock's approvedPlanId - refusing to trust it`);
    }
    const embeddedWhitelistErrors = validateBootstrapActions(existing.plan);
    if (embeddedWhitelistErrors.length > 0) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan that fails the bootstrap action whitelist - refusing to trust it: ${embeddedWhitelistErrors.join("; ")}`);
    }
    if (JSON.stringify(existing.plan.target) !== JSON.stringify(existing.target) || JSON.stringify(existing.target) !== JSON.stringify(lock.target)) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan/journal/lock whose own target bindings disagree - refusing to trust it`);
    }

    // A journal already marked "succeeded" means state.commit's own
    // real effect landed AND the journal update itself landed - the
    // only thing that could still be outstanding is releasing the lock
    // (a crash between the journal update and the lock release). Below,
    // assertJournalResumable() would otherwise throw "nothing to
    // resume" and leave that lock stuck forever, since nothing else
    // ever calls releaseLock() for an already-succeeded journal.
    // Finishing that one remaining step here is not "guessing" - both
    // durable facts this run cares about (the journal's own terminal
    // status, already schema- and cross-binding-validated above) already
    // say it's done. Only reached AFTER every check above, not before -
    // see those comments for why.
    if (existing.status === "succeeded") {
      const release = await tryReleaseLock(m, mutateConn, operationId);
      if (!release.released) {
        // The operation itself genuinely did succeed - but claiming
        // blocked: false here anyway would silently misreport a target
        // that is still locked. A further, 2026-08-31 review found the
        // old code did exactly that: a bare `.catch(() => {})` discarded
        // a real transport failure, and even a clean { released: false }
        // response was never looked at.
        return blocked("resume", `operation ${operationId} already succeeded (committed generation ${existing.committedGeneration}), but its lock could not be confirmed released: ${release.note} - the target may still be locked; investigate directly rather than retrying`);
      }
      emit({ type: "apply.committed", operationId, committedGeneration: existing.committedGeneration });
      return { blocked: false, operationId, committedGeneration: existing.committedGeneration, planId: existing.approvedPlanId };
    }
    assertJournalResumable(existing);

    // The exact same platform check the fresh path runs (see
    // computeLivePlanV2) - resume must never skip it just because it
    // also, deliberately, skips baseline resolution.
    const resumeOsCheck = checkOs(snapshot);
    if (resumeOsCheck.status !== "pass") return blocked("platform", resumeOsCheck.message);
    const resumeArchitectureCheck = checkArchitecture(snapshot);
    if (resumeArchitectureCheck.status !== "pass") return blocked("platform", resumeArchitectureCheck.message);

    const currentDigests = {
      manifestDigest: sha256(servicesBytes),
      releaseLockDigest: sha256(releaseLockBytes),
      catalogDigest: sha256(catalogBytes),
      composeTemplateDigest: sha256(await readFile(path.join(root, "scripts/render-topology.mjs"))),
      executionEnvironmentDigest: releaseLock.ansibleEnvironment.image.slice(releaseLock.ansibleEnvironment.image.indexOf("@") + 1),
    };
    const changedDigest = Object.keys(currentDigests).find((key) => currentDigests[key] !== existing.inputDigests[key]);
    if (changedDigest) {
      return blocked("resume", `${changedDigest} has changed since operation ${operationId} was journaled (was ${existing.inputDigests[changedDigest]}, now ${currentDigests[changedDigest]}) - refusing to resume against changed inputs, see ADR 0004`);
    }
    if (snapshot.transport.trustDigest !== existing.target.hostKeySha256) {
      return blocked("stale-plan", `host key changed since operation ${operationId} was journaled (was ${existing.target.hostKeySha256}, now ${snapshot.transport.trustDigest}) - refusing to resume`);
    }

    plan = existing.plan;
    journal = existing;
    inputDigests = currentDigests; // already proven identical to existing.inputDigests above
  } else {
    operationId = newOperationId();

    // Pre-lock: a plan that's already stale doesn't cost a wasted lock
    // round trip.
    const firstResult = await computeLivePlanV2({ snapshot, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, targetMode, host, port, user, recoveryAgeRecipient: options.recoveryAgeRecipient, repairDrift: options.repairDrift });
    if (firstResult.blocked) return firstResult;
    if (firstResult.plan.planId !== approvedPlan.planId) {
      return blocked("stale-plan", `the plan recomputed from the target's current live state (${firstResult.plan.planId}) does not match the approved plan (${approvedPlan.planId}, ${options.planPath}) - refusing to apply: ${summarizePlanDiff(approvedPlan, firstResult.plan)}`);
    }
    plan = firstResult.plan;

    inputDigests = {
      manifestDigest: sha256(servicesBytes),
      releaseLockDigest: sha256(releaseLockBytes),
      catalogDigest: sha256(catalogBytes),
      composeTemplateDigest: sha256(await readFile(path.join(root, "scripts/render-topology.mjs"))),
      // Same slice build-release-lock.mjs's own verifySupplyChain already
      // uses to pull a digest back out of a repo@sha256:... reference.
      executionEnvironmentDigest: releaseLock.ansibleEnvironment.image.slice(releaseLock.ansibleEnvironment.image.indexOf("@") + 1),
    };
    const lockDoc = await buildLockDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, acquiredBy: currentOperator() });
    journal = await buildJournalDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests });
    // Created together, as ONE remote operation (see
    // acquireLockAndJournal()'s own comment) - a further, 2026-08-31
    // review found that two separate round trips left a real window
    // where a crash of THIS process itself (not the SSH session) between
    // them left a lock durably created with no journal at all, which
    // resume then had nothing to do but refuse forever, since it
    // requires an existing journal before it will trust anything.
    const { acquired, lock: held } = await m.acquireLockAndJournal(mutateConn, lockDoc, journal);
    if (!acquired) {
      try {
        await assertLockValid(held);
      } catch (error) {
        return blocked("lock", `target is locked by a document that does not satisfy its own schema - refusing to trust it: ${error instanceof Error ? error.message : error}`);
      }
      return blocked("lock", `target is already locked by operation ${held.operationId} (started ${held.acquiredAt} by ${held.acquiredBy?.user}@${held.acquiredBy?.workstation}) - use --resume to continue it, or investigate why it's stuck`);
    }

    // ADR 0004: "Once the lock is held, apply re-verifies the plan's own
    // target binding... against a fresh, real inspection of the target
    // before running a single operation." A second, genuinely fresh
    // inspectTarget() call plus a full canonical-document recompute -
    // never just the 3 scalar fields this used to compare (see
    // PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry). Runs after the
    // lock+journal are both already durably created - a recheck failure
    // below only ever releases the lock, deliberately leaving behind a
    // harmless, never-referenced-again "in-progress" journal for an
    // operationId whose lock is gone (nothing in this codebase ever
    // resumes a lockless journal - readLock() failing is resume's own
    // very first gate, before a journal is ever read at all).
    let recheckSnapshot;
    try {
      recheckSnapshot = await inspect({
        targetMode, host, port, user,
        knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
        identityFile: options.identityFile, connectTimeoutSeconds,
      });
    } catch (error) {
      await m.releaseLock(mutateConn, operationId).catch(() => {});
      return blocked("stale-plan", `could not re-inspect the target under the lock: ${error instanceof Error ? error.message : error}`);
    }
    const recheckResult = await computeLivePlanV2({ snapshot: recheckSnapshot, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, targetMode, host, port, user, recoveryAgeRecipient: options.recoveryAgeRecipient, repairDrift: options.repairDrift });
    if (recheckResult.blocked) {
      await m.releaseLock(mutateConn, operationId).catch(() => {});
      return recheckResult;
    }
    if (recheckResult.plan.planId !== plan.planId) {
      await m.releaseLock(mutateConn, operationId).catch(() => {});
      return blocked("stale-plan", `the target changed underneath this plan since it was locked - refusing to apply: ${summarizePlanDiff(plan, recheckResult.plan)}`);
    }
  }

  emit({ type: "apply.locked", operationId, resumed: Boolean(options.resume), planId: plan.planId });

  // The REAL installation id every actually-dispatched operation labels
  // real Docker resources with, and state.commit finally records -
  // deliberately never the planning-time placeholder above (see its own
  // comment on why that one is fixed and shared with `hofctl plan`).
  // Deterministically reusing this run's own operationId (rather than a
  // second, separately-generated random value) needs no extra durable
  // storage at all to stay correct across a resume: a resume already
  // recovers the exact same operationId from the target's own lock, so
  // it recomputes the exact same real installation id too, without ever
  // having to persist it anywhere new.
  const realInstallationId = operationId;
  let appliedRendered;
  try {
    appliedRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId: realInstallationId, generation });
  } catch (error) {
    if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
    return blocked("render", error instanceof Error ? error.message : String(error));
  }

  // The EE container's own network access, known_hosts, identity, and
  // inventory are all resolved ONCE per apply run (the host key is
  // pinned for the whole run - it cannot legitimately change mid-run,
  // the stale-plan recheck above already confirmed that) and reused for
  // every operation's own docker run, rather than re-resolved per
  // operation.
  const workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-"));
  const dockerRun = options.dockerRun ?? defaultExecFile;
  try {
    const { file: knownHostsFile, cleanup: cleanupKnownHosts } = await m.pinnedKnownHosts({ host, port, hostKeySha256: plan.target.hostKeySha256, connectTimeoutSeconds, run: mutateRun ?? defaultExecFile });
    try {
      const inventoryFile = path.join(workDir, "inventory.ini");
      await writeFile(inventoryFile, buildInventory({ host, port, user, connectTimeoutSeconds }), { mode: 0o600 });

      // A supplied TLS certificate+private key are real, sensitive
      // content, delivered exactly like any other secret - through the
      // secret role's own mount, never through extra-vars or the
      // journal, never through the generic config.write/generated-files
      // path (that one is scoped to the operator's own declared-desired-
      // state-derived, non-secret files). Read fresh here (never reused
      // from computeLivePlanV2's own earlier, fingerprint-only reads) -
      // the same "read the real content once, right before it's
      // actually delivered" pattern secretValues/generatedFiles below
      // already follow. render-topology.mjs's own compose gateway
      // volumes reference these exact two fixed secret names.
      let suppliedTlsForDelivery;
      try {
        suppliedTlsForDelivery = await readSuppliedTlsMaterial(manifest, catalog);
      } catch (error) {
        if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
        return blocked("tls", error instanceof Error ? error.message : String(error));
      }
      if (suppliedTlsForDelivery) {
        // TOCTOU close: the plan's own approved suppliedTls fingerprints
        // (checked as part of the full canonical-document recompute
        // both pre-lock and, again, under the lock) describe the
        // certificate/key pair at THOSE two moments - this is a THIRD,
        // later read, right before real delivery. Without comparing
        // fingerprints here too, a certificate/key swapped on the
        // workstation between the post-lock recheck and this exact
        // delivery step (or, on --resume, since resume never repeats
        // the live recompute at all) would be delivered to the target
        // without ever having been part of what was actually approved.
        const deliveredCertificateFingerprint = sha256(Buffer.from(suppliedTlsForDelivery.certificatePem));
        const deliveredPrivateKeyFingerprint = sha256(Buffer.from(suppliedTlsForDelivery.privateKeyPem));
        if (
          deliveredCertificateFingerprint !== plan.suppliedTls?.certificateFingerprint
          || deliveredPrivateKeyFingerprint !== plan.suppliedTls?.privateKeyFingerprint
        ) {
          if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
          return blocked("tls", `the supplied TLS certificate/private key read at delivery time no longer match the fingerprints the approved plan recorded - refusing to deliver unapproved material (certificatePath/privateKeyPath may have changed since the plan was approved)`);
        }
        secretValues[SUPPLIED_TLS_CERTIFICATE_SECRET_NAME] = suppliedTlsForDelivery.certificatePem;
        secretValues[SUPPLIED_TLS_PRIVATE_KEY_SECRET_NAME] = suppliedTlsForDelivery.privateKeyPem;
      }

      // Written unconditionally (even when required is empty, or this
      // plan has no config-affecting change) - plan.mjs's own
      // buildOperations always emits secret.ensure/config.write
      // together with host.prepare for any bootstrap with anyChange,
      // regardless of whether this particular deployment actually
      // needs any secrets - the secret role's own copy loop over an
      // empty map is simply a no-op in that case, never an error.
      const secretsFile = path.join(workDir, "secrets.json");
      await writeFile(secretsFile, JSON.stringify(secretValues), { mode: 0o600 });

      const generatedFilesDir = path.join(workDir, "generated");
      const generatedFiles = renderedFilesContents(appliedRendered);
      await mkdir(generatedFilesDir, { recursive: true });
      await Promise.all(Object.entries(generatedFiles).map(([name, contents]) => writeFile(path.join(generatedFilesDir, name), contents)));

      // state.commit's own real content - current.json matches
      // schemas/state-v1.schema.json; topology.json is the FULL
      // renderTopology() wrapper ({compose, caddyfile, topology, backup,
      // ...}), never just the inner `topology` object generatedFiles
      // above already delivers under that same filename for a
      // completely different purpose (see state.mjs's own
      // assertRenderedShape comment on why those two must never be
      // confused). topologyDigest is deliberately plan.desired's own
      // already-computed value, not recomputed from appliedRendered -
      // that digest's own formula excludes the installation id by
      // design (see state.mjs's own unitConfigFingerprint comment: "a
      // real apply changes it"), so it's identical either way, and
      // reusing the plan's own value keeps this from ever silently
      // drifting out of sync with what buildPlanV2 already validated.
      const stateDir = path.join(workDir, "state");
      await mkdir(stateDir, { recursive: true });
      const currentState = {
        apiVersion: "hof.dev/state/v1",
        installationId: realInstallationId,
        generation,
        lastSuccessfulOperationId: operationId,
        appliedAt: new Date().toISOString(),
        release: releaseLock.release,
        manifestDigest: inputDigests.manifestDigest,
        releaseLockDigest: inputDigests.releaseLockDigest,
        catalogDigest: inputDigests.catalogDigest,
        composeTemplateDigest: inputDigests.composeTemplateDigest,
        topologyDigest: plan.desired.topologyDigest,
        generatedArtifacts: Object.fromEntries(Object.entries(generatedFiles).map(([name, contents]) => [name, sha256(Buffer.from(contents))])),
      };
      await writeFile(path.join(stateDir, "current.json"), JSON.stringify(currentState));
      await writeFile(path.join(stateDir, "topology.json"), JSON.stringify(appliedRendered));

      // executionEnvironmentImageOverride is a narrow testing seam only
      // (see test/apply-acceptance.mjs) - a real `docker run` of the
      // release lock's own schema-required repo@sha256:... reference
      // needs the image to actually be pullable from a real registry;
      // a locally-built-and-never-pushed test image has no such
      // reference Docker can reliably resolve the same way across
      // every Docker storage backend (confirmed: works against a
      // containerd-backed local daemon, fails on the classic
      // overlay2-backed one CI runners use). The real CLI never passes
      // this - inputDigests.executionEnvironmentDigest below is always
      // computed from the real release-lock field regardless, since
      // that's what a real apply run is actually bound to.
      const context = {
        image: options.executionEnvironmentImageOverride ?? releaseLock.ansibleEnvironment.image, identityFile: options.identityFile,
        knownHostsFile, inventoryFile, connectTimeoutSeconds, dockerRun, secretsFile, generatedFilesDir, stateDir,
        installationId: realInstallationId, generation, dockerNetwork: options.executionEnvironmentDockerNetwork,
      };

      let eventsByStep = new Map();
      if (options.resume) {
        let rawEvents;
        try {
          rawEvents = await m.readEvents(mutateConn, operationId);
        } catch (error) {
          return blocked("resume", `could not read operation events for ${operationId}: ${error instanceof Error ? error.message : error}`);
        }
        // target-mutate.mjs's own readEvents() only ever JSON.parses
        // each NDJSON line - a hand-tampered or foreign event (a
        // different operationId, or a step that isn't even part of this
        // approved plan) must never be silently trusted, since
        // decideStepResumption() below acts directly on phase:
        // "succeeded" to skip a step outright.
        const knownStepIds = new Set(plan.operations.map((operation) => operation.id));
        for (const event of rawEvents) {
          try {
            await assertEventValid(event);
          } catch (error) {
            return blocked("resume", `a recorded event for operation ${operationId} does not satisfy its own schema - refusing to trust it: ${error instanceof Error ? error.message : error}`);
          }
          if (event.operationId !== operationId) {
            return blocked("resume", `a recorded event claims operationId ${event.operationId}, but this resume is for ${operationId} - refusing to trust it`);
          }
          if (!knownStepIds.has(event.step)) {
            return blocked("resume", `a recorded event references step ${event.step}, which isn't part of the approved plan's own operations - refusing to trust it`);
          }
        }
        eventsByStep = groupByStep(rawEvents);
      }
      const imageTrustByUnit = new Map();

      for (const operation of plan.operations) {
        let outcome = decideStepResumption(eventsByStep.get(operation.id) ?? []);
        // state.commit's own target-side effect (current.json/
        // topology.json, written via an idempotent, atomic
        // ansible.builtin.copy) is independently, durably verifiable on
        // the target itself - unlike every other operation, an
        // ambiguous "started, no resolution" outcome for this ONE step
        // doesn't have to stay a permanent dead end (the real crash
        // window this closes: dispatch succeeding but the succeeded
        // event never getting durably appended). Never guessed at for
        // any OTHER step, and never trusted here either without
        // independently confirming it against the target's own real,
        // schema-valid record for THIS exact operationId/generation.
        if (outcome === "blocked" && operation.action === "state.commit" && options.resume) {
          const { status: currentStatus, current } = await m.readCurrentState(mutateConn);
          if (currentStatus === "present") {
            try {
              await validateStateV1(current);
            } catch (error) {
              return blocked("resume", error instanceof Error ? error.message : String(error));
            }
            // A full comparison against the exact document THIS run's own
            // state.commit would itself have written - every digest, the
            // real installation id, the real release, not just
            // operationId/generation. A further, 2026-08-31 review found
            // the narrower two-field check let a schema-valid but
            // otherwise-unrelated current.json (matching operationId and
            // generation by pure coincidence) pass as "proof" of a real
            // commit. appliedAt is the one field excluded from the
            // comparison on purpose: it timestamps the ORIGINAL, crashed
            // attempt's own real commit moment, never expected to equal
            // this rerun's freshly generated one.
            const { appliedAt: _expectedAppliedAt, ...expectedWithoutTimestamp } = currentState;
            const { appliedAt: _actualAppliedAt, ...actualWithoutTimestamp } = current;
            const currentMatches = JSON.stringify(actualWithoutTimestamp) === JSON.stringify(expectedWithoutTimestamp);
            // current.json's own topologyDigest already ties it to a
            // specific topology, but only by trusting current.json's own
            // honesty about that digest - independently re-reading the
            // real topology.json the target actually holds and comparing
            // it byte for byte against this run's own appliedRendered
            // closes that one remaining gap for real, not just on paper.
            let topologyMatches = false;
            if (currentMatches) {
              const { status: topologyStatus, topology: actualTopology } = await m.readTopology(mutateConn);
              topologyMatches = topologyStatus === "present" && JSON.stringify(actualTopology) === JSON.stringify(appliedRendered);
            }
            if (currentMatches && topologyMatches) {
              const recovered = await buildEvent({ operationId, step: operation.id, attempt: 1, phase: "succeeded" });
              await m.appendEvent(mutateConn, operationId, recovered);
              emit(recovered);
              outcome = "skip";
            }
          }
        }
        if (outcome === "skip") {
          emit({ type: "apply.resume-skip", operationId, step: operation.id });
          if (operation.action === "image.verify") imageTrustByUnit.set(operation.resource, operation.imageTrust);
          continue;
        }
        if (outcome === "blocked" || outcome === "failed" || outcome === "corrupted") {
          const detail = outcome === "corrupted"
            ? "its own recorded event history is structurally invalid (a duplicate, out-of-order, or standalone terminal event) and is never silently resolved one way or the other"
            : "refusing to guess whether it's safe to retry or skip";
          return blocked("resume", `step ${operation.id} has an unresolved, failed, or corrupted outcome from a previous attempt (${outcome}) - ${detail}; investigate the target directly (the lock remains held)`);
        }

        const attempt = 1;
        const started = await buildEvent({ operationId, step: operation.id, attempt, phase: "started" });
        await m.appendEvent(mutateConn, operationId, started);
        emit(started);

        try {
          await dispatchOperation(operation, { ...context, commitGeneration: generation, imageTrustByUnit });
        } catch (error) {
          const failed = await buildEvent({ operationId, step: operation.id, attempt, phase: "failed", error: sanitizeError(error) });
          await m.appendEvent(mutateConn, operationId, failed);
          emit(failed);
          const failedJournal = await withJournalStatus(journal, { status: "failed" });
          await m.updateJournalStatus(mutateConn, failedJournal);
          await m.releaseLock(mutateConn, operationId).catch(() => {});
          return blocked("operation", `operation ${operation.id} failed: ${failed.error} - a fresh bootstrap is required after diagnosis, this operation cannot be resumed (see ADR 0004)`);
        }

        const succeeded = await buildEvent({ operationId, step: operation.id, attempt, phase: "succeeded" });
        await m.appendEvent(mutateConn, operationId, succeeded);
        emit(succeeded);
      }

      const committedJournal = await withJournalStatus(journal, { status: "succeeded", committedGeneration: generation });
      await m.updateJournalStatus(mutateConn, committedJournal);
      await m.releaseLock(mutateConn, operationId);
      emit({ type: "apply.committed", operationId, committedGeneration: generation });

      return { blocked: false, operationId, committedGeneration: generation, planId: plan.planId };
    } finally {
      await cleanupKnownHosts();
    }
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

function groupByStep(events) {
  const byStep = new Map();
  for (const event of events) {
    if (!byStep.has(event.step)) byStep.set(event.step, []);
    byStep.get(event.step).push(event);
  }
  return byStep;
}

// loadAndValidateDeployment() itself only ever returns the parsed
// objects, not the raw bytes each was read from - apply needs the raw
// bytes too (to compute the journal's own inputDigests, and because
// hashing a re-serialized JS object is not the same digest as hashing
// the original file's exact bytes). Re-reads the same three files a
// second time rather than reaching into validate-deployment.mjs's own
// internals - simple, and the files are small.
async function loadAndValidateDeploymentWithBytes(options) {
  // loadAndValidateDeployment() itself expects servicesPath (matching
  // its own standalone CLI's option shape) - runApply's own public
  // options use manifestPath, matching runPlan()'s convention, so this
  // remaps the same way plan-command.mjs's own runPlan() already does.
  const result = await loadAndValidateDeployment({
    servicesPath: options.manifestPath,
    catalogPath: options.catalogPath,
    releaseLockPath: options.releaseLockPath,
    releaseLockIdentity: options.releaseLockIdentity,
    releaseLockOidcIssuer: options.releaseLockOidcIssuer,
    skipSignature: false,
  });
  const catalogPath = options.catalogPath ?? path.join(root, "catalog/services-v1.yaml");
  const [servicesBytes, catalogBytes, releaseLockBytes] = await Promise.all([
    readFile(options.manifestPath).catch(() => Buffer.alloc(0)),
    readFile(catalogPath).catch(() => Buffer.alloc(0)),
    readFile(options.releaseLockPath).catch(() => Buffer.alloc(0)),
  ]);
  return { ...result, servicesBytes, catalogBytes, releaseLockBytes };
}
