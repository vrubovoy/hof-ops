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
  assertJournalResumable, buildEvent, buildJournalDocument, buildLockDocument,
  currentOperator, decideStepResumption, newOperationId, withJournalStatus,
} from "./operation-journal.mjs";
import { checkManagedStateReadable, observationFromSnapshot } from "./preflight.mjs";
import { validateBootstrapActions } from "./bootstrap-actions.mjs";
import { buildPlanV2 } from "./plan-v2.mjs";
import { BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER } from "./plan-command.mjs";
import { enabledServiceIds, renderedFilesContents, renderTopology } from "./render-topology.mjs";
import { readSecretsStore, requiredSecrets } from "./secrets.mjs";
import { resolveBaseline } from "./state.mjs";
import { suppliedTlsCertificateFingerprint } from "./supplied-tls.mjs";
import { inspectTarget } from "./target-inspector.mjs";
import * as realMutate from "./target-mutate.mjs";
import { loadAndValidateDeployment } from "./validate-deployment.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let compiledPlanV2Validator;
async function planV2Validator() {
  compiledPlanV2Validator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/plan-v2.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  return compiledPlanV2Validator;
}

function blocked(reason, message) {
  return { blocked: true, reason, diagnostics: [message] };
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
  const args = [
    "run", "--rm",
    "--volume", `${context.identityFile}:/hof/identity:ro`,
    "--volume", `${context.knownHostsFile}:/hof/known_hosts:ro`,
    "--volume", `${context.inventoryFile}:/hof/inventory.ini:ro`,
  ];
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
  args.push(
    context.image,
    "ansible-playbook", "/ansible/playbook.yml",
    "-i", "/hof/inventory.ini",
    "-e", JSON.stringify(extraVars),
  );
  await context.dockerRun("docker", args, { timeout: (context.connectTimeoutSeconds + 60) * 1000 });
}

function buildInventory({ host, port, user, connectTimeoutSeconds }) {
  const sshCommonArgs = [
    "-o StrictHostKeyChecking=yes",
    "-o UserKnownHostsFile=/hof/known_hosts",
    "-o GlobalKnownHostsFile=/dev/null",
    "-o BatchMode=yes",
    `-o ConnectTimeout=${connectTimeoutSeconds}`,
  ].join(" ");
  return `target ansible_host=${host} ansible_port=${port} ansible_user=${user} ansible_ssh_private_key_file=/hof/identity ansible_ssh_common_args="${sshCommonArgs}"\n`;
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
//   approvePlanId - required unless resume: true.
//   resume - reclaim an existing, interrupted operation instead of
//     starting a new one; no new approval, see ADR 0004.
//   emit(event) - called once per operation-event-v1 (and a few
//     apply-specific informational lines) as they happen, for bounded
//     NDJSON streaming to stdout. Defaults to a no-op.
//   inspect, verifyEeSignature, dockerRun, mutate, run,
//   executionEnvironmentImageOverride, readSecretsStore - testing seams;
//   the real CLI never passes them.
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
  if (!options.resume && !options.approvePlanId) {
    return blocked("approval", "hofctl apply requires --approve-plan-id unless --resume is given");
  }

  const { errors, manifest, catalog, catalogBytes, releaseLock, releaseLockBytes, servicesBytes, servicesSchema, catalogSchema, releaseLockSchema } =
    await loadAndValidateDeploymentWithBytes(options);
  if (errors.length > 0) return { blocked: true, reason: "deployment", diagnostics: errors };
  if (!releaseLock.ansibleEnvironment) return blocked("execution-environment", "release lock has no ansibleEnvironment - cannot apply");

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
    // Reads manifest.tls.certificatePath itself (already declared in
    // services.yml, on the operator's own workstation per ADR 0001) -
    // no separate CLI flag needed; returns undefined for every mode but
    // "supplied".
    suppliedTls = await suppliedTlsCertificateFingerprint(manifest);
  } catch (error) {
    return blocked("tls", error instanceof Error ? error.message : String(error));
  }
  // Required on resume too, not just a fresh apply: buildPlanV2 below
  // needs the exact same recipient again to reproduce the identical
  // planId - a resume that omitted it (or supplied a different one)
  // would recompute a different plan and correctly be refused by the
  // approvedPlanId comparison further down, but this fails faster, with
  // a clearer message.
  if (!options.recoveryAgeRecipient) {
    return blocked("recovery", "--recovery-age-recipient is required (a bootstrap plan always needs one, see ADR 0004)");
  }

  const installationId = BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER;
  const generation = 1;
  let desiredRendered;
  try {
    desiredRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId, generation });
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
  const validatePlan = await planV2Validator();
  if (!validatePlan(plan)) return blocked("internal", `buildPlanV2 produced a result that does not satisfy schemas/plan-v2.schema.json: ${JSON.stringify(validatePlan.errors)}`);
  if (!plan.executable) return blocked("plan", `plan has blockers, refusing to apply: ${plan.blockers.join("; ")}`);

  const whitelistErrors = validateBootstrapActions(plan);
  if (whitelistErrors.length > 0) return blocked("bootstrap-actions", whitelistErrors.join("; "));

  if (!options.resume && options.approvePlanId !== plan.planId) {
    return blocked("approval", `--approve-plan-id ${options.approvePlanId} does not match the freshly computed plan's own planId ${plan.planId} - approving a plan approves those exact bytes, see ADR 0004`);
  }

  const verifyEeSignature = options.verifyEeSignature ?? verifyExecutionEnvironmentSignature;
  try {
    await verifyEeSignature(releaseLock.ansibleEnvironment);
  } catch (error) {
    return blocked("execution-environment", error instanceof Error ? error.message : String(error));
  }

  const mutateRun = options.run;
  const mutateConn = { mode: "ssh", host, port, user, hostKeySha256: plan.target.hostKeySha256, identityFile: options.identityFile, connectTimeoutSeconds, run: mutateRun };

  let operationId;
  if (options.resume) {
    const { status, lock } = await m.readLock(mutateConn);
    if (status !== "present") return blocked("resume", "no lock found on this target - there is nothing to resume");
    operationId = lock.operationId;
  } else {
    operationId = newOperationId();
    const lockDoc = await buildLockDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, acquiredBy: currentOperator() });
    const { acquired, lock: held } = await m.acquireLock(mutateConn, lockDoc);
    if (!acquired) {
      return blocked("lock", `target is already locked by operation ${held.operationId} (started ${held.acquiredAt} by ${held.acquiredBy?.user}@${held.acquiredBy?.workstation}) - use --resume to continue it, or investigate why it's stuck`);
    }
  }

  // ADR 0004: "Once the lock is held, apply re-verifies the plan's own
  // target binding... against a fresh, real inspection of the target
  // before running a single operation." A second, genuinely fresh
  // inspectTarget() call - never reusing the snapshot the plan above was
  // computed from.
  let recheckSnapshot;
  try {
    recheckSnapshot = await inspect({
      targetMode, host, port, user,
      knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
      identityFile: options.identityFile, connectTimeoutSeconds,
    });
  } catch (error) {
    if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
    return blocked("stale-plan", `could not re-inspect the target under the lock: ${error instanceof Error ? error.message : error}`);
  }
  const recheckObservation = observationFromSnapshot(recheckSnapshot);
  let recheckBaseline;
  try {
    recheckBaseline = resolveBaseline({ managedState: recheckSnapshot.managedState, catalog, observation: recheckObservation });
  } catch (error) {
    if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
    return blocked("stale-plan", `could not re-resolve the baseline under the lock: ${error instanceof Error ? error.message : error}`);
  }
  const staleReasons = [];
  if (recheckSnapshot.transport.trustDigest !== plan.target.hostKeySha256) staleReasons.push(`host key changed (was ${plan.target.hostKeySha256}, now ${recheckSnapshot.transport.trustDigest})`);
  if (recheckBaseline.installationId !== plan.target.installationId) staleReasons.push(`installation id changed (was ${plan.target.installationId}, now ${recheckBaseline.installationId})`);
  if (recheckBaseline.generation !== plan.target.baselineGeneration) staleReasons.push(`baseline generation changed (was ${plan.target.baselineGeneration}, now ${recheckBaseline.generation})`);
  if (staleReasons.length > 0) {
    if (!options.resume) await m.releaseLock(mutateConn, operationId).catch(() => {});
    return blocked("stale-plan", `the target changed underneath this plan since it was computed - refusing to apply: ${staleReasons.join("; ")}`);
  }

  const inputDigests = {
    manifestDigest: sha256(servicesBytes),
    releaseLockDigest: sha256(releaseLockBytes),
    catalogDigest: sha256(catalogBytes),
    composeTemplateDigest: sha256(await readFile(path.join(root, "scripts/render-topology.mjs"))),
    // Same slice build-release-lock.mjs's own verifySupplyChain already
    // uses to pull a digest back out of a repo@sha256:... reference.
    executionEnvironmentDigest: releaseLock.ansibleEnvironment.image.slice(releaseLock.ansibleEnvironment.image.indexOf("@") + 1),
  };

  let journal;
  if (options.resume) {
    const { status, journal: existing } = await m.readJournal(mutateConn, operationId);
    if (status !== "present") return blocked("resume", `lock references operation ${operationId} but its journal could not be read (status: ${status})`);
    assertJournalResumable(existing);
    if (existing.approvedPlanId !== plan.planId) {
      return blocked("resume", `the plan recomputed from the current inputs (${plan.planId}) no longer matches the approved plan this operation was locked against (${existing.approvedPlanId}) - refusing to resume against changed inputs`);
    }
    journal = existing;
  } else {
    journal = await buildJournalDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, inputDigests });
    await m.writeJournal(mutateConn, journal);
  }

  emit({ type: "apply.locked", operationId, resumed: Boolean(options.resume), planId: plan.planId });

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
      const generatedFiles = renderedFilesContents(desiredRendered);
      await mkdir(generatedFilesDir, { recursive: true });
      await Promise.all(Object.entries(generatedFiles).map(([name, contents]) => writeFile(path.join(generatedFilesDir, name), contents)));

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
        knownHostsFile, inventoryFile, connectTimeoutSeconds, dockerRun, secretsFile, generatedFilesDir,
        installationId, generation,
      };

      const eventsByStep = options.resume ? groupByStep(await m.readEvents(mutateConn, operationId)) : new Map();
      const imageTrustByUnit = new Map();

      for (const operation of plan.operations) {
        const outcome = decideStepResumption(eventsByStep.get(operation.id) ?? []);
        if (outcome === "skip") {
          emit({ type: "apply.resume-skip", operationId, step: operation.id });
          if (operation.action === "image.verify") imageTrustByUnit.set(operation.resource, operation.imageTrust);
          continue;
        }
        if (outcome === "blocked" || outcome === "failed") {
          return blocked("resume", `step ${operation.id} has an unresolved or failed outcome from a previous attempt (${outcome}) - refusing to guess whether it's safe to retry or skip; investigate the target directly (the lock remains held)`);
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
