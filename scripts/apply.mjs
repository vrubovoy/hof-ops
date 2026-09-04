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
import { validateAppliedActions } from "./applied-actions.mjs";
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
// label (item 9 THIRD review fix, finding 7): defaults to describing
// current.json (this function's original, and still most common, call
// site) - readGenerationSnapshotArtifacts() below passes its own,
// accurate label for the immutable snapshot's own state.json instead, so
// a real validation failure names the actual file that failed, not a
// different one that happened to share this same validator.
async function validateStateV1(value, label = "current.json read from the target") {
  stateV1Validator ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const schema = JSON.parse(await readFile(path.join(root, "schemas/state-v1.schema.json"), "utf8"));
    return ajv.compile(schema);
  })();
  if (!stateV1Validator(value)) {
    throw new Error(`${label} does not satisfy schemas/state-v1.schema.json: ${JSON.stringify(stateV1Validator.errors)}`);
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
  "service.stop": "service",
  "service.remove": "service",
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
// was called with - volume.ensure must label a resource identically to
// how Compose would have labeled it itself (network.ensure deliberately
// no longer does - item 9 review, network lifecycle finding: a network
// is long-lived, shared infrastructure the Ansible network role now
// owns exclusively, and never carries a per-generation label - see that
// role's own comment on why). secret.ensure and config.write don't
// carry their own real content here at all - dispatchOperation() below
// mounts it in separately (see its own comment on why: never through
// extra-vars/argv).
//
// Exported (unlike this file's other pure helpers not already exported
// for test/apply-acceptance.mjs's own use - see computeExpectedCommittedState()'s
// own comment on why) - a further review found its own real, direct
// state.commit dispatches used to build extra-vars by hand instead,
// which had ALREADY silently drifted from what a real dispatch actually
// sends: hof_operation_id here is the STEP's own id (operation.id, e.g.
// "009.state.commit" - a real plan-v2 document's own step id, which the
// state role's own staging-directory name embeds), never the whole
// apply RUN's own UUID the hand-built version had been passing instead.
export function buildExtraVars(operation, { commitGeneration, imageTrustByUnit, installationId, generation }) {
  const role = ACTION_TO_ROLE[operation.action];
  if (!role) throw new Error(`internal error: operation ${operation.id} has action ${operation.action}, which has no known Execution Environment role - this should have been rejected by the action whitelist (bootstrap-actions.mjs or applied-actions.mjs) before dispatch`);
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
      // Item 9 review (network lifecycle finding): no hof_generation
      // here - unlike volume.ensure, this network is long-lived, shared
      // infrastructure the Ansible network role now owns exclusively
      // (see that role's own comment on why a per-generation label used
      // to make Compose fight it for ownership). operation.internal is
      // only ever true for wachter-internal (plan.mjs's own
      // network.ensure dispatch); absent (never explicitly false) for
      // every other network, and the role's own default(false) handles
      // that.
      if (operation.internal) vars.hof_network_internal = true;
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
      vars.hof_service_action = "start";
      vars.hof_service_unit = operation.resource;
      vars.hof_service_image = operation.image;
      break;
    // Item 9 (ADR 0005): applied-mode-only, never dispatched for a
    // bootstrap plan (bootstrap-actions.mjs's own whitelist has neither
    // action at all). installationId here is the exact same value this
    // whole apply is bound to (bootstrap's own fresh operationId, or an
    // already-applied installation's own permanent id) - discovery in
    // the service role's own tasks must scope to exactly this
    // installation, never a foreign one sharing the same host and unit
    // name.
    case "service.stop":
    case "service.remove":
      vars.hof_service_action = operation.action === "service.stop" ? "stop" : "remove";
      vars.hof_service_unit = operation.resource;
      vars.hof_installation_id = installationId;
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
//
// Item 9 review (operation ordering finding): 8 lines/2000 chars turned
// out to be too aggressive for real diagnosis - a real CI failure
// investigating a readiness.wait timeout found the surviving tail was
// just ansible's own generic Python-interpreter-discovery warning
// (printed once, early, but still the last few lines of the WHOLE
// combined stdout when a long `until` retry loop's own "FAILED -
// RETRYING" spam pushes everything actually useful (the failing
// container's own last docker-inspect health status/log, which the
// readiness role's own assert now surfaces explicitly - see that role's
// own comment) further back than 8 lines could ever reach. Widened, not
// removed - still bounded, still truncated, never a raw unbounded dump.
function sanitizeError(error) {
  const raw = [error?.stdout, error?.stderr, error?.message].filter(Boolean).join("\n");
  const lines = raw.split("\n").filter((line) => line.trim().length > 0);
  // Item 9 review (wachter finding, second pass): widened again - the
  // readiness role's own assert now also carries the failing unit's own
  // captured `docker logs` output alongside the State/Health JSON, and
  // both together routinely exceed the previous 40-line/4000-char
  // budget, silently dropping exactly the application-level detail this
  // whole diagnostic chain exists to surface.
  //
  // Real bug found via a real CI run (item 9 review, third pass):
  // `.slice(0, N)` keeps the FIRST N characters of the tail, not the
  // last - backwards from the intent. The tail is already the last few
  // lines chronologically, so the most recent, most relevant content
  // (this role's own final assert - the whole reason this function
  // takes a tail at all) sits at the END of that string; a single long
  // line earlier in the tail (docker inspect's own escaped-JSON output)
  // was enough to push it past a start-anchored cutoff and silently
  // drop it, exactly as it did here.
  const tail = lines.slice(-80).join("\n");
  return (tail || "operation failed with no further diagnostic detail").slice(-8000);
}

// Runs one operation inside a fresh, throwaway Execution Environment
// container - never a long-running one (see ansible/Dockerfile's own
// "no ENTRYPOINT/CMD that runs anything on its own" comment). dockerRun
// is a testing seam (see apply.test.mjs); the real acceptance test
// (test/apply-acceptance.mjs) runs a genuine `docker run` against a
// genuine sudo-enabled ephemeral target.
// Exported (unlike dispatchOperation() itself, which stays private -
// see its own comment on why only this narrower piece is) so
// test/apply-acceptance.mjs's own real, direct state.commit dispatches
// build the exact same `docker run` argv this module's own
// dispatchOperation() would for that one action, from ONE real
// implementation - never a second, independently-maintained copy that
// can silently drift from this one (a further review found the
// original hand-built version already had, in more than one way - see
// buildExtraVars()'s own comment on the operation-id mixup this exact
// extraction closes for good).
export function buildDockerRunArgs(operation, extraVars, context) {
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
  return args;
}

async function dispatchOperation(operation, context) {
  const extraVars = buildExtraVars(operation, context);
  const args = buildDockerRunArgs(operation, extraVars, context);
  // A generous, flat budget covering every operation kind, not just a
  // quick SSH round trip: readiness.wait's own retry budget alone can
  // run up to 2 minutes (see ansible/roles/readiness/tasks/main.yml),
  // and host.prepare's real apt-get install of Docker or a real
  // database.migrate can each legitimately take a while too.
  await context.dockerRun("docker", args, { timeout: (context.connectTimeoutSeconds + 300) * 1000 });
}

// Exported for the same reason computeExpectedCommittedState() is (see
// its own comment) - test/apply-acceptance.mjs's own crash/retry
// scenarios need to dispatch a single, real Execution Environment role
// invocation directly, against the exact same Ansible inventory shape a
// real apply run builds, never a second, independently-maintained copy.
export function buildInventory({ host, port, user, connectTimeoutSeconds }) {
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

// Item 9 (ADR 0005): the commit generation a plan document itself
// implies - never a hardcoded constant, and never re-derived from a
// SEPARATE live baseline lookup (resume in particular must never do
// that - see its own comment on why). A bootstrap plan always commits
// generation 1 (ADR 0004 - unconditional, regardless of what
// target.baselineGeneration happens to hold for a bootstrap plan, which
// is always 0 anyway, see plan-v2.mjs's own bootstrap target-binding).
// An applied plan always commits target.baselineGeneration + 1 - the
// exact same value plan-command.mjs's own runPlan() used to render this
// plan's own desired state in the first place, so a plan and the
// generation it eventually commits can never disagree.
function commitGenerationFor(planDoc) {
  return planDoc.mode === "bootstrap" ? 1 : planDoc.target.baselineGeneration + 1;
}

// Item 9 (ADR 0005): whitelist validation is chosen by the plan's own
// declared mode, never assumed - a plan that claims "bootstrap" but
// somehow carries an applied-only action (or vice versa) must fail
// here, not slip through validated against the wrong vocabulary
// entirely.
function validateActionsForPlan(planDoc) {
  return planDoc.mode === "bootstrap" ? validateBootstrapActions(planDoc) : validateAppliedActions(planDoc);
}

// The exact current.json/topology.json a real state.commit dispatch for
// this operationId/generation would itself produce - shared between the
// real dispatch/commit code and resume's own succeeded-journal
// verification, so the two can never independently drift out of sync.
//
// Item 9 (ADR 0005): installationId and operationId are no longer
// always the same value - a bootstrap plan still uses the fresh
// operationId as the first, permanent installation id (unchanged, ADR
// 0004); an applied plan reuses the baseline's own already-permanent
// installationId, which never changes again for the life of the
// installation (lastSuccessfulOperationId still always records the
// REAL operationId that performed this particular commit, whichever
// mode). retainedServices and the supplied-TLS fingerprints are carried
// forward from the plan's own already-computed desired state (see
// plan.mjs's own computeRetainedServices/buildPlan) - without this, a
// retained service's own volume/schema-version record would be lost
// the moment the very next generation committed, and a supplied-TLS
// installation's own baseline fingerprint would revert to null on the
// next resolveBaseline() (see state.mjs's own resolveBaseline() comment
// on why that would silently break every later no-op).
// Item 9 review fix (finding 11): every field a real commit writes fresh
// on each attempt and that a resume verification must therefore NOT
// expect to reproduce bit-for-bit - appliedAt (the original commit
// instant) and every retainedServices[*].retainedAt (the instant a
// service was first disabled-with-retain). Stripping them here keeps a
// genuine, healthy retry/resume from failing an equality check for the
// wrong reason, while the real current.json on disk still carries them.
export function withoutVolatileStateFields(state) {
  const { appliedAt: _appliedAt, retainedServices, ...rest } = state ?? {};
  return {
    ...rest,
    retainedServices: Object.fromEntries(
      Object.entries(retainedServices ?? {}).map(([id, entry]) => {
        const { retainedAt: _retainedAt, ...entryRest } = entry ?? {};
        return [id, entryRest];
      }),
    ),
  };
}

// Exported (unlike every other pure helper in this file, which stays
// module-private) specifically so test/apply-acceptance.mjs's own real,
// crash/retry acceptance scenarios (item 9 review, findings 1-2) can
// construct the EXACT document a real state.commit for a given
// operation/generation would produce, directly, rather than
// independently re-deriving (and risking silently drifting from) this
// exact shape a second time in a test file.
export function computeExpectedCommittedState({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, plan, operationId, installationId, generation, inputDigests, operationStartedAt, now = new Date() }) {
  // Item 9 THIRD review fix (finding 6): required, not defaulted. A
  // caller that forgot to pass it would otherwise silently spread
  // `retainedAt: undefined` into a newly-retained entry - not merely
  // "missing" (the schema's own optional field, harmless) but an own
  // enumerable property whose value fails the schema's `type: string`
  // check the instant a later validateStateV1() looks at it. Every real
  // call site passes the journal's own startedAt - fixed once, read back
  // unchanged on every --resume of the same operation (see below).
  if (typeof operationStartedAt !== "string" || !operationStartedAt) {
    throw new Error("computeExpectedCommittedState requires operationStartedAt (the journal's own startedAt) to deterministically fill retainedServices[*].retainedAt across retries");
  }
  const appliedRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId, generation });
  const generatedFiles = renderedFilesContents(appliedRendered);
  // Item 9 review fix (finding 11): state-v1.schema.json promises apply
  // fills in retainedServices[*].retainedAt at commit time (plan.mjs's
  // own pure planning core never reads the clock). A service still
  // retained from an earlier generation keeps its original timestamp; a
  // service this very commit is disabling-with-retain gets a fresh one.
  // resolveBaseline()/withoutVolatileStateFields() both treat a missing
  // retainedAt as harmless, so state written before this fix stays valid.
  //
  // Item 9 THIRD review fix (finding 6): that fresh timestamp must be
  // operationStartedAt (the journal's own startedAt - fixed once at
  // journal creation and read back unchanged by every later --resume of
  // the SAME operation), never `now` (a new Date() on every single call
  // to this function). ansible/roles/state/tasks/main.yml's own
  // already-published-generation comparison excludes appliedAt ONLY -
  // it has no way to know about a nested retainedAt drifting between two
  // separate calls of this function for the same operationId/generation.
  // A crash between publishing the immutable generation snapshot and
  // writing the current.json pointer (see that file's own finding-2
  // comment) used to mean the retry's re-render of current.json got a
  // BRAND NEW retainedAt for any service retained for the first time by
  // this very commit, which the target-side assert then correctly (but
  // wrongly, from the operator's perspective) refused as if the
  // generation had been reused for two different commits. Anchoring on
  // operationStartedAt instead makes this call's own output byte-for-byte
  // reproducible across every retry of the same operation, which is
  // exactly what the immutable-snapshot re-publish comparison assumes.
  // appliedAt (below) is deliberately left on `now` - it genuinely is a
  // fresh per-attempt timestamp, and is separately excluded from every
  // comparison that matters (withoutVolatileStateFields on the JS side,
  // the Ansible role's own combine({'appliedAt': ...}) on the target
  // side) for exactly that reason.
  const baselineRetained = plan.baseline?.retainedServices ?? {};
  const retainedServices = Object.fromEntries(
    Object.entries(plan.desired.retainedServices ?? {}).map(([id, entry]) => [
      id,
      { ...entry, retainedAt: baselineRetained[id]?.retainedAt ?? operationStartedAt },
    ]),
  );
  // topologyDigest is deliberately the plan's own already-computed
  // value, not recomputed from appliedRendered here - that digest's own
  // formula excludes the installation id by design (a real apply
  // changes it), so it's identical either way, and reusing the plan's
  // own value keeps this from ever silently drifting out of sync with
  // what buildPlanV2 already validated.
  const currentState = {
    apiVersion: "hof.dev/state/v1",
    installationId,
    generation,
    lastSuccessfulOperationId: operationId,
    appliedAt: now.toISOString(),
    release: releaseLock.release,
    manifestDigest: inputDigests.manifestDigest,
    releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest,
    composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: plan.desired.topologyDigest,
    generatedArtifacts: Object.fromEntries(Object.entries(generatedFiles).map(([name, contents]) => [name, sha256(Buffer.from(contents))])),
    retainedServices,
    suppliedTlsCertificateFingerprint: plan.desired.suppliedTlsCertificateFingerprint ?? null,
    suppliedTlsPrivateKeyFingerprint: plan.desired.suppliedTlsPrivateKeyFingerprint ?? null,
  };
  return { currentState, appliedRendered, generatedFiles };
}

// Reads and validates every durable event for operationId - schema,
// operationId, known-step membership, PHYSICAL append order (see
// decideStepResumption()'s own comment), and the plan's own dispatch
// order in the RAW stream, not just per-step (a real run only ever
// dispatches plan.operations strictly in array order - every one of a
// step's own events, in the raw file, forms one contiguous block, and
// the next step's own block can never begin until the previous one's
// already resolved to a genuine success). Returns eventsByStep on
// success, throws a plain Error carrying a human message on any
// violation - the caller turns that into blocked("resume", ...).
async function readAndValidateEvents(m, mutateConn, operationId, plan) {
  let rawEvents;
  try {
    rawEvents = await m.readEvents(mutateConn, operationId);
  } catch (error) {
    throw new Error(`could not read operation events for ${operationId}: ${error instanceof Error ? error.message : error}`);
  }
  const stepIndex = new Map(plan.operations.map((operation, index) => [operation.id, index]));
  for (const event of rawEvents) {
    try {
      await assertEventValid(event);
    } catch (error) {
      throw new Error(`a recorded event for operation ${operationId} does not satisfy its own schema - refusing to trust it: ${error instanceof Error ? error.message : error}`);
    }
    if (event.operationId !== operationId) {
      throw new Error(`a recorded event claims operationId ${event.operationId}, but this resume is for ${operationId} - refusing to trust it`);
    }
    if (!stepIndex.has(event.step)) {
      throw new Error(`a recorded event references step ${event.step}, which isn't part of the approved plan's own operations - refusing to trust it`);
    }
  }
  // A further, 2026-08-31 review found the per-step physical-order check
  // (decideStepResumption() itself) and the old prefix-only gap check
  // here together still missed the RAW stream's own cross-step order -
  // two concrete, schema-valid-but-impossible shapes: a later step's
  // own [started, succeeded] pair appearing in the file entirely BEFORE
  // an earlier step's own events even begin, and two steps' events
  // genuinely interleaved (```A.started, B.started, B.succeeded,
  // A.succeeded```) - neither is a gap (both steps have events) and
  // neither breaks EITHER step's own per-step ordering in isolation, so
  // both survived every check PR #46 added. Walking the raw stream once,
  // in order, and requiring every event to belong to either the step
  // currently "open" or the next one in plan order - and requiring the
  // previous step's own accumulated history to already resolve to
  // "skip" before the next one may open - catches both: a real run's
  // own dispatch loop can never legitimately produce anything else.
  let openIndex = -1;
  let openStepEvents = [];
  for (const event of rawEvents) {
    const index = stepIndex.get(event.step);
    if (index === openIndex) {
      openStepEvents.push(event);
    } else if (index === openIndex + 1) {
      if (openIndex >= 0 && decideStepResumption(openStepEvents) !== "skip") {
        throw new Error(`step ${plan.operations[openIndex].id}'s own recorded events don't resolve to a genuine success before step ${event.step}'s own events begin in the raw stream - refusing to trust an event history that isn't a valid append-order record of the plan's own dispatch order`);
      }
      openIndex = index;
      openStepEvents = [event];
    } else {
      throw new Error(`step ${event.step}'s own event appears out of the plan's own dispatch order in the raw event stream - refusing to trust an event history that isn't a valid append-order record of the plan's own dispatch order`);
    }
  }
  return groupByStep(rawEvents);
}

// Item 9 review fix (finding 8): reads all three files of a per-
// generation snapshot directory and reports whether the directory is a
// COMPLETE, MATCHING immutable record - every recovery path that trusts
// a generation snapshot as an independent oracle must confirm the whole
// directory, not just its state.json.
//
// Item 9 SECOND review fix (finding 3): a further review found this
// used to stop at "complete" (all three files present and readable) and
// leave the actual CONTENT comparison to each of its three call sites
// separately - which is exactly how the bug happened: state.json's own
// content was compared everywhere, but release-lock.json's own value
// was read here and then silently discarded (only its `status` was ever
// looked at), so a topology.json or release-lock.json that was
// present, parseable, non-empty, and still belonged to a genuinely
// different commit than the one on disk would have passed unnoticed.
// Fixed by folding the WHOLE three-file comparison into this one
// function - `expected{State,Topology,ReleaseLock}` are the exact
// documents this exact operation/generation would itself have written
// (state.json's own appliedAt/retainedAt are excluded via
// withoutVolatileStateFields, exactly like every other state.json
// comparison in this file - topology.json/release-lock.json carry no
// such volatile field at all) - so no future call site can independently
// forget to compare one of the three ever again.
//
// Item 9 THIRD review fix (finding 7): state.json is now schema-checked
// (validateStateV1()) before it is trusted as a recovery oracle - the
// exact same gate the target's own MUTABLE current.json already goes
// through everywhere it's read for this purpose (see this function's own
// two callers). A hand-tampered or genuinely corrupted, but still valid
// JSON, state.json inside an otherwise "complete" (all three files
// present, non-empty) immutable snapshot directory used to be trusted
// as-is here - compared field-by-field against expectedState, which
// would either (best case) simply fail to match, or - if the corruption
// happened to strip a required field entirely while leaving every
// COMPARED field looking equal - be silently accepted as a match anyway.
async function readGenerationSnapshotArtifacts(m, mutateConn, generation, { expectedState, expectedTopology, expectedReleaseLock }) {
  const [{ status: stateStatus, snapshot }, { status: topologyStatus, topology }, { status: releaseLockStatus, releaseLock }] = await Promise.all([
    m.readGenerationSnapshot(mutateConn, generation),
    m.readGenerationSnapshotTopology(mutateConn, generation),
    m.readGenerationSnapshotReleaseLock(mutateConn, generation),
  ]);
  const missing = [
    stateStatus !== "present" ? `state.json (${stateStatus})` : null,
    topologyStatus !== "present" ? `topology.json (${topologyStatus})` : null,
    releaseLockStatus !== "present" ? `release-lock.json (${releaseLockStatus})` : null,
  ].filter(Boolean);
  if (missing.length > 0) {
    return { complete: false, matches: false, detail: `missing/unreadable: ${missing.join(", ")}` };
  }
  try {
    await validateStateV1(snapshot, `generation ${generation}'s own immutable snapshot state.json`);
  } catch (error) {
    // Corruption of an immutable record, exactly like the "missing"
    // case above - never merely "doesn't match", which would understate
    // it (a schema-invalid document was never a valid commit to begin
    // with, whatever it happens to compare equal or unequal to).
    return { complete: false, matches: false, detail: error instanceof Error ? error.message : String(error) };
  }
  const mismatched = [
    JSON.stringify(withoutVolatileStateFields(snapshot)) !== JSON.stringify(withoutVolatileStateFields(expectedState)) ? "state.json" : null,
    JSON.stringify(topology) !== JSON.stringify(expectedTopology) ? "topology.json" : null,
    JSON.stringify(releaseLock) !== JSON.stringify(expectedReleaseLock) ? "release-lock.json" : null,
  ].filter(Boolean);
  return {
    complete: true,
    matches: mismatched.length === 0,
    detail: mismatched.length === 0 ? "all three files present and match" : `content mismatch: ${mismatched.join(", ")}`,
  };
}

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

// Item 9 review fix (finding 9): every post-lock error path used to
// release the lock with a bare `await m.releaseLock(...).catch(() => {})`
// - a real transport failure (or a clean { released: false } mismatch)
// was discarded, so the returned result could name only the stale-plan/
// TLS/render error while the target stayed genuinely locked. This runs
// the release, and when it did NOT clear the lock, folds that fact into
// the diagnostics the caller returns, so the operator is told the target
// is still locked.
async function releaseLockThenAnnotate(m, mutateConn, operationId, blockedResult) {
  const release = await tryReleaseLock(m, mutateConn, operationId);
  if (!release.released) {
    return {
      ...blockedResult,
      diagnostics: [
        ...(blockedResult.diagnostics ?? []),
        `WARNING: the operation lock for ${operationId} could not be released after this failure - the target may still be locked: ${release.note}`,
      ],
    };
  }
  return blockedResult;
}

// Item 9 (ADR 0005): secrets are decrypted only once the actual plan is
// known to be a real, non-no-op run - moved out of the old unconditional
// "always decrypt whenever this deployment needs any secrets at all"
// gate, which ran BEFORE the target was ever inspected or a plan ever
// computed. That used to mean a deployment that genuinely needs secrets
// would fail on a missing --secrets-store even for what turns out to be
// a genuine applied no-op - nothing would ever have been delivered.
// required is still the full deployment-wide set (plan.mjs's own
// secret.ensure is unconditional on anyChange, never scoped to just the
// touched service - see its own comment: "keep every required secret
// current, including any this change newly needs"), so this still
// validates against exactly what a real secret.ensure dispatch would
// need, just no longer eagerly for a run that will never reach one.
async function ensureSecretsAvailable({ manifest, enabledIds, options }) {
  const required = requiredSecrets(manifest, enabledIds);
  if (required.length === 0) return { secretValues: {} };
  if (!options.secretsStorePath) {
    return { blockedResult: blocked("secrets", `this deployment needs ${required.length} secret(s) (${required.map((s) => s.name).join(", ")}) but --secrets-store was not given`) };
  }
  let decrypted;
  try {
    const readStore = options.readSecretsStore ?? readSecretsStore;
    decrypted = await readStore({ storePath: options.secretsStorePath, identityFile: options.secretsAgeIdentityFile });
  } catch (error) {
    return { blockedResult: blocked("secrets", `could not decrypt ${options.secretsStorePath}: ${error instanceof Error ? error.message : error}`) };
  }
  const missing = required.filter((s) => !(s.name in decrypted)).map((s) => s.name);
  if (missing.length > 0) {
    return { blockedResult: blocked("secrets", `${options.secretsStorePath} is missing required secret(s): ${missing.join(", ")} - run "hofctl secrets ensure" first`) };
  }
  // Only the subset this deployment actually needs - a store that also
  // carries secrets for an unrelated, disabled service must never leak
  // those into the Execution Environment container too.
  const secretValues = {};
  for (const { name } of required) secretValues[name] = decrypted[name];
  return { secretValues };
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

  // Item 9 (ADR 0005): resolveBaseline() itself already covers both
  // modes - the bootstrap-only guard this used to have right here is
  // gone. Everything below now mirrors plan-command.mjs's own runPlan()
  // step 5v2 exactly (the exact same document `hofctl plan` itself
  // already prints, for either mode) - the two must never independently
  // drift apart, since an operator approves whatever `hofctl plan`
  // showed them.
  let baseline;
  try {
    baseline = resolveBaseline({ managedState: snapshot.managedState, catalog, observation });
  } catch (error) {
    return blocked("state", error instanceof Error ? error.message : String(error));
  }

  let suppliedTls;
  try {
    suppliedTls = await readSuppliedTlsMaterial(manifest, catalog);
  } catch (error) {
    return blocked("tls", error instanceof Error ? error.message : String(error));
  }
  // recoveryAgeRecipient stays required for bootstrap only - an applied
  // plan never re-derives a fresh secrets.sops.yaml recovery recipient,
  // it already has one, untouched by an ordinary applied change (see
  // ADR 0005, and plan-v2.mjs's own identical check).
  if (baseline.mode === "bootstrap" && !recoveryAgeRecipient) {
    return blocked("recovery", "--recovery-age-recipient is required (a bootstrap plan always needs one, see ADR 0004)");
  }

  const installationId = baseline.mode === "bootstrap" ? BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER : baseline.installationId;
  const generation = baseline.mode === "bootstrap" ? 1 : baseline.generation + 1;
  let desiredRendered;
  try {
    desiredRendered = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId, generation });
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

  // Item 9 (ADR 0005): whitelist validation is chosen by the plan's own
  // declared mode - a bootstrap plan is validated against
  // bootstrap-actions.mjs's own whitelist, an applied plan against
  // applied-actions.mjs's own (never backup.create, never host.prepare -
  // see that module's own comment).
  const whitelistErrors = validateActionsForPlan(plan);
  if (whitelistErrors.length > 0) return blocked(plan.mode === "bootstrap" ? "bootstrap-actions" : "applied-actions", whitelistErrors.join("; "));

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

  const { errors, manifest, catalog, catalogBytes, releaseLock, releaseLockBytes, servicesBytes, composeTemplateBytes, servicesSchema, catalogSchema, releaseLockSchema } =
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

  // Item 9 review fix (finding 7): a deployment that needs secrets but
  // was given NO --secrets-store at all is a plain operator mistake -
  // still caught here, eagerly, before the network. But the actual
  // DECRYPTION of that store (which can fail transiently - a SOPS/age
  // identity momentarily unavailable) is deferred to the real
  // ensureSecretsAvailable() call further down, AFTER the applied no-op
  // early-return: an unchanged deployment must not read or deliver any
  // secret, so it must not fail on being unable to.
  const enabledIds = enabledServiceIds(manifest, catalog);
  const requiredSecretsForDeployment = requiredSecrets(manifest, enabledIds);
  if (requiredSecretsForDeployment.length > 0 && !options.secretsStorePath) {
    return blocked("secrets", `this deployment needs ${requiredSecretsForDeployment.length} secret(s) (${requiredSecretsForDeployment.map((s) => s.name).join(", ")}) but --secrets-store was not given`);
  }
  let secretValues = {};

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

  // Item 9 THIRD review fix (findings 1 & 2): a PROCESS-LIFETIME
  // execution lease on top of the durable lock, acquired HERE - before a
  // single decision-affecting read (resume's own readLock/readJournal/
  // event-history validation below) or mutating action (fresh's own
  // lock+journal creation below) happens. An earlier revision acquired
  // this lease much later, after both branches had already run to
  // completion; a further review found that let two independent
  // `hofctl apply --resume` processes race each other all the way
  // through reading and DECIDING off the exact same resume-state before
  // whichever one lost the lease race ever found out - and on the fresh
  // path, a loser could by then already have durably created a
  // lock+journal, which its own (late) lease-failure handler
  // unconditionally released, racing a legitimate concurrent resumer
  // that might already be relying on that very lock (a real,
  // independently reachable split-brain window). The durable lock only
  // ever proves an operation exists to resume - it does not by itself
  // stop two processes from running at once, each re-dispatching the
  // same step; this lease is held by a long-lived child for exactly as
  // long as this process lives and is dropped by the kernel the instant
  // it (or its SSH connection) dies. Acquiring it first, unconditionally,
  // before either branch even begins, makes every read and every
  // mutation below strictly lease-holder-exclusive for BOTH branches - a
  // losing process now finds out before it has read or touched anything
  // at all, so there is never a lock for ITS OWN failure path to release
  // (every remaining releaseLockThenAnnotate() call site further down is
  // strictly AFTER a lock this same process itself already created).
  // Optional on the mutate seam so apply.test.mjs's in-memory fake can
  // opt in or out.
  let executionLease = null;
  if (m.acquireExecutionLease) {
    try {
      executionLease = await m.acquireExecutionLease(mutateConn);
    } catch (error) {
      return blocked("lease", `could not acquire the execution lease for this target: ${error instanceof Error ? error.message : error}`);
    }
    // Item 9 FOURTH review fix (finding 1): a lease that resolves
    // already known lost must never be accepted and used. A further
    // review found a real gap: a stdin error on the lease helper's own
    // connection arriving BEFORE HOF_LEASE_HELD/BUSY only recorded
    // isLost() via markLost(), never claimed or rejected the still-open
    // acquisition itself - so a buffered HOF_LEASE_HELD arriving right
    // after could still resolve successfully, and this process would
    // then run its ENTIRE resume-read / fresh-lock-creation / dispatch
    // lifecycle behind a lease already known dead, with the very first
    // isLost() check buried deep inside the dispatch loop. Fixed at the
    // source (target-mutate.mjs's own acquireExecutionLease() now throws
    // instead of ever returning such a lease - see its own comment) and
    // checked again here too, defensively: never trust "the lease helper
    // returned without throwing" alone as proof of a healthy lease, for
    // any mutate implementation, real or faked.
    if (executionLease?.isLost?.()) {
      const reason = executionLease.lostReason?.() ?? "unknown";
      await executionLease.release?.().catch(() => {});
      return blocked("lease", `the execution lease for this target resolved already lost (${reason}) - refusing to proceed with a lease that was never actually healthy`);
    }
  }
  try {
    return await runUnderLease();
  } finally {
    // Item 9 THIRD review fix (finding 8): released here, in a single
    // unconditional outer finally, however runUnderLease() below returns
    // OR throws - a later resume of the SAME operation is a fresh
    // process that acquires its own. The OLD code released the lease
    // only after a separate, sequential `await rm(workDir, ...)`
    // succeeded (see that cleanup further down): a real failure removing
    // workDir (disk full, a permissions problem) used to skip lease
    // release entirely, leaking it for the rest of this process's own
    // lifetime, not just this run.
    if (executionLease) await executionLease.release().catch(() => {});
  }

  // Nested closure - captures every binding already in scope above
  // (options, m, emit, manifest/catalog/releaseLock/*Schema, mutateConn,
  // executionLease, secretValues, enabledIds, requiredSecretsForDeployment,
  // approvedPlan, etc.) automatically, so the entire pre-existing resume/
  // fresh/dispatch body below keeps every one of its own many `return`
  // statements completely unchanged; only the outer try/finally just
  // above now guarantees the lease is always released, however this
  // returns. (Function declarations are hoisted, so calling this above
  // its own definition is valid.)
  async function runUnderLease() {
  // Item 9 (ADR 0005): the commit generation is no longer a hardcoded
  // constant - derived per-branch below (commitGenerationFor()), from
  // whichever plan document this run actually trusts (a fresh live
  // recompute, or the journal's own embedded plan on resume), never
  // from a second, independent baseline lookup.
  let operationId;
  let plan;
  let journal;
  let inputDigests;
  let eventsByStep = new Map();

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
    if (journalStatus === "absent") {
      // Lock and journal are now always created together, as one remote
      // operation (see acquireLockAndJournal()'s own comment) - no
      // operation is EVER dispatched before both durably exist, so a
      // journal PROVABLY ABSENT (not merely unreadable - see below)
      // proves nothing has actually run yet. Safe to clean up and hand
      // the operator back to a fresh apply - this isn't "guessing"
      // about a real operation outcome, there wasn't one (a further,
      // 2026-08-31 review found this case used to refuse forever, with
      // no recovery path at all).
      const release = await tryReleaseLock(m, mutateConn, operationId);
      return blocked("resume", `lock references operation ${operationId} but its journal is absent - since no operation ever dispatches before both are created together, nothing has actually run yet; ${release.released ? "the stale lock has been released - run a fresh (non-resume) apply" : `the stale lock could not be released (${release.note}) - investigate the target directly`}`);
    }
    if (journalStatus !== "present") {
      // "unreadable" (the file exists but couldn't be read/parsed) does
      // NOT prove nothing ran - unlike "absent", it's a genuinely
      // ambiguous state (a permission problem, real on-disk corruption)
      // that must never be auto-cleaned. A further, 2026-08-31 review
      // found this used to be treated identically to "absent", silently
      // releasing a lock that might be guarding a real, unresolved
      // operation.
      return blocked("resume", `lock references operation ${operationId} but its journal could not be read (status: ${journalStatus}) - refusing to guess whether it's safe to release the lock; investigate the target directly (the lock remains held)`);
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
    // Item 9 (ADR 0005): chosen by the embedded plan's own declared
    // mode - never assumed bootstrap just because that used to be the
    // only mode this function ever saw.
    const embeddedWhitelistErrors = validateActionsForPlan(existing.plan);
    if (embeddedWhitelistErrors.length > 0) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan that fails the ${existing.plan.mode} action whitelist - refusing to trust it: ${embeddedWhitelistErrors.join("; ")}`);
    }
    if (JSON.stringify(existing.plan.target) !== JSON.stringify(existing.target) || JSON.stringify(existing.target) !== JSON.stringify(lock.target)) {
      return blocked("resume", `the journal for operation ${operationId} carries a plan/journal/lock whose own target bindings disagree - refusing to trust it`);
    }

    // Every check below - platform, input digests, host key, the event
    // stream itself - now runs UNCONDITIONALLY, before ever branching on
    // journal status, including for an already-"succeeded" journal. A
    // further, 2026-08-31 review found the succeeded fast path used to
    // run before all of this: platform validation, live host-key
    // comparison, input digest comparison, and event validation were
    // all skipped outright, and the target's own current.json/
    // topology.json were never independently confirmed to back up the
    // journal's own claim at all.

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
      // The exact bytes loadAndValidateDeployment() already read - never
      // an independent second read of the same file (see
      // loadAndValidateDeploymentWithBytes()'s own comment on the
      // TOCTOU that used to leave open).
      composeTemplateDigest: sha256(composeTemplateBytes),
      executionEnvironmentDigest: releaseLock.ansibleEnvironment.image.slice(releaseLock.ansibleEnvironment.image.indexOf("@") + 1),
    };
    const changedDigest = Object.keys(currentDigests).find((key) => currentDigests[key] !== existing.inputDigests[key]);
    if (changedDigest) {
      return blocked("resume", `${changedDigest} has changed since operation ${operationId} was journaled (was ${existing.inputDigests[changedDigest]}, now ${currentDigests[changedDigest]}) - refusing to resume against changed inputs, see ADR 0004`);
    }
    if (snapshot.transport.trustDigest !== existing.target.hostKeySha256) {
      return blocked("stale-plan", `host key changed since operation ${operationId} was journaled (was ${existing.target.hostKeySha256}, now ${snapshot.transport.trustDigest}) - refusing to resume`);
    }

    let resumeEventsByStep;
    try {
      resumeEventsByStep = await readAndValidateEvents(m, mutateConn, operationId, existing.plan);
    } catch (error) {
      return blocked("resume", error instanceof Error ? error.message : String(error));
    }

    // A journal already marked "succeeded" means state.commit's own
    // real effect landed AND the journal update itself landed - the
    // only thing that could still be outstanding is releasing the lock
    // (a crash between the journal update and the lock release). Below,
    // assertJournalResumable() would otherwise throw "nothing to
    // resume" and leave that lock stuck forever, since nothing else
    // ever calls releaseLock() for an already-succeeded journal.
    // Finishing that one remaining step here is not "guessing" - every
    // durable fact this run can check (schema, cross-binding, platform,
    // digests, host key, the event stream's own internal consistency,
    // AND the target's own real current.json/topology.json - not just
    // the journal's bare `status` field) already says it's done. Only
    // reached AFTER every check above, not before - see those comments
    // for why.
    if (existing.status === "succeeded") {
      const allStepsResolved = existing.plan.operations.every((operation) => decideStepResumption(resumeEventsByStep.get(operation.id) ?? []) === "skip");
      if (!allStepsResolved) {
        return blocked("resume", `the journal for operation ${operationId} claims status "succeeded", but its own recorded event history doesn't show every operation actually resolved - refusing to trust a completion claim its own evidence doesn't support`);
      }
      // Item 9 (ADR 0005): derived from the journal's own embedded plan,
      // never a hardcoded constant or a fresh baseline lookup - the
      // exact same derivation the fresh path used to arrive at this
      // plan's own commit in the first place (commitGenerationFor/
      // plan.target.installationId), so this can never disagree with
      // what the plan itself implies.
      const commitGeneration = commitGenerationFor(existing.plan);
      const commitInstallationId = existing.plan.mode === "bootstrap" ? operationId : existing.plan.target.installationId;
      if (existing.committedGeneration !== undefined && existing.committedGeneration !== commitGeneration) {
        return blocked("resume", `the journal for operation ${operationId} claims committedGeneration ${existing.committedGeneration}, but its own embedded plan implies ${commitGeneration} - refusing to trust a completion claim its own evidence doesn't support`);
      }
      const { currentState: expectedCurrentState, appliedRendered: expectedTopology } = computeExpectedCommittedState({
        manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema,
        plan: existing.plan, operationId, installationId: commitInstallationId, generation: commitGeneration, inputDigests: currentDigests,
        // Item 9 THIRD review fix (finding 6): existing.startedAt, never
        // `now` - this recomputation must reproduce EXACTLY what the
        // original commit wrote, including any retainedAt it invented
        // for a service retained for the first time.
        operationStartedAt: existing.startedAt,
      });
      const { status: liveCurrentStatus, current: liveCurrent } = await m.readCurrentState(mutateConn);
      if (liveCurrentStatus !== "present") {
        return blocked("resume", `the journal for operation ${operationId} claims status "succeeded", but the target's own current.json could not be confirmed present (status: ${liveCurrentStatus}) - refusing to trust a completion claim its own evidence doesn't support`);
      }
      try {
        await validateStateV1(liveCurrent);
      } catch (error) {
        return blocked("resume", error instanceof Error ? error.message : String(error));
      }
      // appliedAt and retainedServices[*].retainedAt are the fields
      // excluded from the comparison on purpose (see
      // withoutVolatileStateFields) - they timestamp the ORIGINAL commit
      // moment, never expected to equal a value freshly computed now.
      const expectedWithoutTimestamp = withoutVolatileStateFields(expectedCurrentState);
      if (JSON.stringify(withoutVolatileStateFields(liveCurrent)) !== JSON.stringify(expectedWithoutTimestamp)) {
        return blocked("resume", `the journal for operation ${operationId} claims status "succeeded", but the target's own current.json doesn't match what this exact operation would have committed - refusing to trust a completion claim its own evidence doesn't support`);
      }
      const { status: liveTopologyStatus, topology: liveTopology } = await m.readTopology(mutateConn);
      if (liveTopologyStatus !== "present" || JSON.stringify(liveTopology) !== JSON.stringify(expectedTopology)) {
        return blocked("resume", `the journal for operation ${operationId} claims status "succeeded", but the target's own topology.json could not be confirmed to match - refusing to trust a completion claim its own evidence doesn't support`);
      }
      // Item 9 (ADR 0005): a THIRD independent oracle - the state role's
      // own immutable per-generation snapshot (see
      // ansible/roles/state/tasks/main.yml). Item 9 SECOND review fix
      // (finding 3): all THREE files of that snapshot directory are
      // confirmed AND content-compared now (state.json, topology.json,
      // release-lock.json) - a corrupt or genuinely different
      // topology.json/release-lock.json used to pass unnoticed, since
      // only presence (never content) was ever checked for the latter
      // two.
      const snapshotArtifacts = await readGenerationSnapshotArtifacts(m, mutateConn, commitGeneration, {
        expectedState: expectedCurrentState, expectedTopology, expectedReleaseLock: releaseLock,
      });
      if (!snapshotArtifacts.complete || !snapshotArtifacts.matches) {
        return blocked("resume", `the journal for operation ${operationId} claims status "succeeded", but generation ${commitGeneration}'s own immutable snapshot is incomplete or does not match what this exact operation would have committed - refusing to trust a completion claim its own evidence doesn't support (${snapshotArtifacts.detail})`);
      }

      const release = await tryReleaseLock(m, mutateConn, operationId);
      if (!release.released) {
        // The operation itself genuinely did succeed - but claiming
        // blocked: false here anyway would silently misreport a target
        // that is still locked. A further, 2026-08-31 review found the
        // old code did exactly that: a bare `.catch(() => {})` discarded
        // a real transport failure, and even a clean { released: false }
        // response was never looked at.
        return blocked("resume", `operation ${operationId} already succeeded (committed generation ${commitGeneration}), but its lock could not be confirmed released: ${release.note} - the target may still be locked; investigate directly rather than retrying`);
      }
      emit({ type: "apply.committed", operationId, committedGeneration: commitGeneration });
      return { blocked: false, operationId, committedGeneration: commitGeneration, planId: existing.approvedPlanId };
    }
    assertJournalResumable(existing);

    plan = existing.plan;
    journal = existing;
    inputDigests = currentDigests; // already proven identical to existing.inputDigests above
    eventsByStep = resumeEventsByStep; // already read and validated above - never re-read further down
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

    // Item 9 (ADR 0005): a genuine applied no-op - requires the exact
    // approved plan (already confirmed above), takes no lock, creates
    // no journal, runs no Execution Environment, never bumps generation.
    // Bootstrap is deliberately excluded here - it always mutates a
    // clean host (ADR 0004's own always-locked contract, already
    // reviewed, stays untouched); only an applied plan can legitimately
    // have zero operations at all.
    if (plan.mode === "applied" && plan.operations.length === 0) {
      // No lock/journal was ever created, so there is no operationId
      // for this run either - CLI result shape:
      // {"type": "apply.result", "noOp": true, "committedGeneration": N, "planId": "sha256:..."}
      // (see hofctl.mjs's own final print of the returned result).
      return { blocked: false, noOp: true, committedGeneration: plan.target.baselineGeneration, planId: plan.planId };
    }

    inputDigests = {
      manifestDigest: sha256(servicesBytes),
      releaseLockDigest: sha256(releaseLockBytes),
      catalogDigest: sha256(catalogBytes),
      // The exact bytes loadAndValidateDeployment() already read - never
      // an independent second read of the same file (see
      // loadAndValidateDeploymentWithBytes()'s own comment on the
      // TOCTOU that used to leave open).
      composeTemplateDigest: sha256(composeTemplateBytes),
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
      return releaseLockThenAnnotate(m, mutateConn, operationId, blocked("stale-plan", `could not re-inspect the target under the lock: ${error instanceof Error ? error.message : error}`));
    }
    const recheckResult = await computeLivePlanV2({ snapshot: recheckSnapshot, manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, targetMode, host, port, user, recoveryAgeRecipient: options.recoveryAgeRecipient, repairDrift: options.repairDrift });
    if (recheckResult.blocked) {
      return releaseLockThenAnnotate(m, mutateConn, operationId, recheckResult);
    }
    if (recheckResult.plan.planId !== plan.planId) {
      return releaseLockThenAnnotate(m, mutateConn, operationId, blocked("stale-plan", `the target changed underneath this plan since it was locked - refusing to apply: ${summarizePlanDiff(plan, recheckResult.plan)}`));
    }
  }

  emit({ type: "apply.locked", operationId, resumed: Boolean(options.resume), planId: plan.planId });

  // Item 9 review fix (finding 7): NOW decrypt the operator's secrets
  // store - the run is past the applied no-op early-return, so this is a
  // real apply that will actually dispatch operations (including a
  // secret.ensure) and genuinely needs the values. A true no-op returned
  // above without ever reaching this, so a temporarily-unavailable SOPS
  // identity no longer fails an apply that would have delivered nothing.
  // The lock is already held on the fresh path (a blocked result must
  // release it and say so); resume legitimately keeps the lock.
  {
    const secretsResult = await ensureSecretsAvailable({ manifest, enabledIds, options });
    if (secretsResult.blockedResult) {
      return options.resume ? secretsResult.blockedResult : releaseLockThenAnnotate(m, mutateConn, operationId, secretsResult.blockedResult);
    }
    secretValues = secretsResult.secretValues;
  }

  // Item 9 (ADR 0005): derived from the plan this run actually trusts
  // (a fresh live recompute, or the journal's own embedded plan on
  // resume) - never a hardcoded constant, and never re-derived from a
  // second, independent baseline lookup (resume in particular must
  // never do that - see its own comment further up on why).
  const generation = commitGenerationFor(plan);

  // The REAL installation id every actually-dispatched operation labels
  // real Docker resources with, and state.commit finally records.
  // Bootstrap: deliberately never the planning-time placeholder above
  // (see its own comment on why that one is fixed and shared with
  // `hofctl plan`) - a fresh operationId becomes the first, PERMANENT
  // installation id (ADR 0004). Deterministically reusing this run's
  // own operationId (rather than a second, separately-generated random
  // value) needs no extra durable storage at all to stay correct across
  // a resume: a resume already recovers the exact same operationId from
  // the target's own lock, so it recomputes the exact same real
  // installation id too, without ever having to persist it anywhere new.
  // Applied (ADR 0005): installationId is permanent forever - this run's
  // own operationId never replaces it, whatever mode. Reused directly
  // from the plan's own target binding (baseline.installationId,
  // already resolved once by resolveBaseline/computeLivePlanV2, or by
  // plan-command.mjs's own runPlan for a --plan file an operator
  // approved) - never re-derived from a second, independent lookup.
  const realInstallationId = plan.mode === "bootstrap" ? operationId : plan.target.installationId;
  let appliedRendered, currentState, generatedFiles;
  try {
    ({ appliedRendered, currentState, generatedFiles } = computeExpectedCommittedState({
      manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema,
      plan, operationId, installationId: realInstallationId, generation, inputDigests,
      // Item 9 THIRD review fix (finding 6): journal.startedAt - on the
      // fresh path this is the moment buildJournalDocument() just
      // stamped it (this is that operation's first and only commit
      // attempt so far); on resume, `journal` was aliased to `existing`
      // above and carries the ORIGINAL operation's startedAt forward
      // unchanged, so a retried state.commit re-render is byte-for-byte
      // identical to the one already (partially) published on the
      // target - see this function's own comment on why that matters.
      operationStartedAt: journal.startedAt,
    }));
  } catch (error) {
    const result = blocked("render", error instanceof Error ? error.message : String(error));
    return options.resume ? result : releaseLockThenAnnotate(m, mutateConn, operationId, result);
  }

  // The EE container's own network access, known_hosts, identity, and
  // inventory are all resolved ONCE per apply run (the host key is
  // pinned for the whole run - it cannot legitimately change mid-run,
  // the stale-plan recheck above already confirmed that) and reused for
  // every operation's own docker run, rather than re-resolved per
  // operation.
  //
  // The execution lease itself (item 9 review fix, finding 3) is now
  // acquired much earlier - see runApply()'s own top, right after
  // mutateConn is built (item 9 THIRD review fix, findings 1 & 2) - and
  // captured here purely via this closure, not re-acquired.

  // workDir itself is now created INSIDE the try/finally below (a
  // second review found it used to be created BEFORE it, so a failure
  // in mkdtemp() itself - rare, but real: disk full, a permissions
  // problem - skipped the finally entirely and leaked the just-acquired
  // execution lease helper for the rest of this process's own lifetime,
  // not just this run).
  let workDir;
  const dockerRun = options.dockerRun ?? defaultExecFile;
  try {
    workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-"));
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
        const result = blocked("tls", error instanceof Error ? error.message : String(error));
        return options.resume ? result : releaseLockThenAnnotate(m, mutateConn, operationId, result);
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
          const result = blocked("tls", `the supplied TLS certificate/private key read at delivery time no longer match the fingerprints the approved plan recorded - refusing to deliver unapproved material (certificatePath/privateKeyPath may have changed since the plan was approved)`);
          return options.resume ? result : releaseLockThenAnnotate(m, mutateConn, operationId, result);
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
      //
      // Item 9 review fix (finding 6): the file carries ONLY the secrets
      // the approved secret.ensure operation actually names (bootstrap:
      // all of them; applied: just the ones consumed by units this plan
      // restarts). A required secret this plan never touches is left
      // exactly as it is on the target - never silently overwritten
      // outside what was approved. The supplied-TLS material added above
      // is always kept: the gateway it belongs to is (re)started by any
      // plan that delivers it.
      const secretEnsureOp = plan.operations.find((op) => op.action === "secret.ensure");
      const approvedSecretNames = secretEnsureOp?.secrets;
      const deliveredSecretValues = Array.isArray(approvedSecretNames)
        ? Object.fromEntries(Object.entries(secretValues).filter(([name]) =>
          approvedSecretNames.includes(name) || name === SUPPLIED_TLS_CERTIFICATE_SECRET_NAME || name === SUPPLIED_TLS_PRIVATE_KEY_SECRET_NAME))
        : secretValues;
      const secretsFile = path.join(workDir, "secrets.json");
      await writeFile(secretsFile, JSON.stringify(deliveredSecretValues), { mode: 0o600 });

      const generatedFilesDir = path.join(workDir, "generated");
      await mkdir(generatedFilesDir, { recursive: true });
      await Promise.all(Object.entries(generatedFiles).map(([name, contents]) => writeFile(path.join(generatedFilesDir, name), contents)));

      // state.commit's own real content - current.json matches
      // schemas/state-v1.schema.json; topology.json is the FULL
      // renderTopology() wrapper ({compose, caddyfile, topology, backup,
      // ...}), never just the inner `topology` object generatedFiles
      // above already delivers under that same filename for a
      // completely different purpose (see state.mjs's own
      // assertRenderedShape comment on why those two must never be
      // confused). Both currentState and appliedRendered were already
      // computed once, above, by computeExpectedCommittedState() - the
      // exact same construction resume's own succeeded-journal
      // verification uses, so the two can never drift apart.
      // Item 9 (ADR 0005): release-lock.json - the exact release lock
      // this commit was actually applied under, written alongside
      // current.json/topology.json for the state role's own immutable
      // per-generation snapshot (generations/NNNNNN/*) - a later item
      // (10/11) reads this history back; item 9 itself never does.
      const stateDir = path.join(workDir, "state");
      await mkdir(stateDir, { recursive: true });
      await writeFile(path.join(stateDir, "current.json"), JSON.stringify(currentState));
      await writeFile(path.join(stateDir, "topology.json"), JSON.stringify(appliedRendered));
      await writeFile(path.join(stateDir, "release-lock.json"), JSON.stringify(releaseLock));

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

      // eventsByStep was already read and validated (schema, operationId,
      // known-step membership, physical append order, plan-dispatch-order
      // gap check - see readAndValidateEvents()) up in the resume branch
      // itself, before it was ever trusted for the succeeded-journal fast
      // path either - never re-read here. Stays the empty Map its outer
      // declaration defaults to on a fresh (non-resume) apply.
      const imageTrustByUnit = new Map();

      for (const operation of plan.operations) {
        // Item 9 SECOND review fix: fail-closed on a lease already known
        // lost (see acquireExecutionLease()'s own comment on what
        // "known" means and its own honest limit - an operation THIS
        // process already dispatched cannot be recalled either way, but
        // no FURTHER one is ever queued once this process itself knows
        // its lease is gone).
        // Item 9 THIRD review fix (finding 3): checked here, at the top
        // of every iteration, AND again immediately before each of this
        // iteration's own possible dispatchOperation() calls below (see
        // both call sites' own use of refuseIfLeaseLost()) - real awaits
        // sit between this top check and either dispatch call
        // (readGenerationSnapshotArtifacts, readCurrentState,
        // readTopology, appendEvent), each one a real window for the
        // lease to be lost mid-iteration; a loss discovered in that
        // window must stop THIS dispatch too, not merely be noticed at
        // the next iteration's own top check or at the end of the run.
        const refuseIfLeaseLost = () => executionLease?.isLost?.()
          ? blocked("lease", `the execution lease for this target was lost mid-run (${executionLease.lostReason()}) - refusing to dispatch operation ${operation.id} or any further one; the target may now be held by a different process, investigate directly (the lock remains held)`)
          : null;
        {
          const lost = refuseIfLeaseLost();
          if (lost) return lost;
        }
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
          const expectedWithoutTimestamp = JSON.stringify(withoutVolatileStateFields(currentState));
          // The state role's own immutable per-generation snapshot -
          // published as one atomic directory BEFORE either mutable
          // pointer file is touched (see ansible/roles/state/tasks/main.yml).
          // Item 9 SECOND review fix (finding 3): the WHOLE directory is
          // confirmed AND content-compared (state.json + topology.json +
          // release-lock.json), not just state.json's own content.
          const snapshotArtifacts = await readGenerationSnapshotArtifacts(m, mutateConn, generation, {
            expectedState: currentState, expectedTopology: appliedRendered, expectedReleaseLock: releaseLock,
          });
          const snapshotMatches = snapshotArtifacts.complete && snapshotArtifacts.matches;

          // The two mutable pointer files. A full comparison against the
          // exact document THIS run's own state.commit would itself have
          // written - a 2026-08-31 review found a narrower check let a
          // schema-valid but unrelated current.json pass as "proof".
          const { status: currentStatus, current } = await m.readCurrentState(mutateConn);
          let currentMatches = false;
          if (currentStatus === "present") {
            try {
              await validateStateV1(current);
            } catch (error) {
              return blocked("resume", error instanceof Error ? error.message : String(error));
            }
            currentMatches = JSON.stringify(withoutVolatileStateFields(current)) === expectedWithoutTimestamp;
          }
          let topologyMatches = false;
          {
            const { status: topologyStatus, topology: actualTopology } = await m.readTopology(mutateConn);
            topologyMatches = topologyStatus === "present" && JSON.stringify(actualTopology) === JSON.stringify(appliedRendered);
          }

          if (currentMatches && topologyMatches && snapshotMatches) {
            // The whole commit landed - just the succeeded event was lost.
            const recovered = await buildEvent({ operationId, step: operation.id, attempt: 1, phase: "succeeded" });
            // Item 9 FIFTH review fix (finding 1): checked HERE, after
            // buildEvent() has already resolved, not before it - a
            // further review found buildEvent() is itself genuinely
            // async (operation-journal.mjs's own assertValid() awaits
            // AJV schema validation, and on this process's first ever
            // call, a real readFile() of the event schema too), so a
            // check placed before it left exactly the same real await
            // window this whole line of fixes exists to close, just one
            // call earlier than intended. The three real awaits further
            // above (readGenerationSnapshotArtifacts, readCurrentState,
            // readTopology) are covered by this same check now being the
            // very next thing that runs after all of them, with nothing
            // async in between it and appendEvent() below.
            {
              const lost = refuseIfLeaseLost();
              if (lost) return lost;
            }
            await m.appendEvent(mutateConn, operationId, recovered);
            emit(recovered);
            outcome = "skip";
          } else if (snapshotMatches) {
            // Item 9 review fix (finding 2): the immutable generation
            // snapshot for THIS exact generation already landed atomically
            // and in full, but current.json/topology.json were only
            // partially (or not yet) published before the crash - the
            // recoverable authoritative-pair window. state.commit is fully
            // idempotent (the generation directory already exists and
            // matches, so the role skips re-publishing it and only
            // re-writes the atomic pointers), so re-dispatching it here
            // finishes the commit rather than dead-ending resume forever.
            emit({ type: "apply.resume-finish-commit", operationId, step: operation.id, generation });
            // Item 9 THIRD review fix (finding 3): re-checked immediately
            // before this re-dispatch - the three real awaits just above
            // (readGenerationSnapshotArtifacts, readCurrentState,
            // readTopology) are a real window for the lease to be lost
            // since the top-of-iteration check.
            {
              const lost = refuseIfLeaseLost();
              if (lost) return lost;
            }
            await dispatchOperation(operation, { ...context, commitGeneration: generation, imageTrustByUnit });
            const { status: reCurrentStatus, current: reCurrent } = await m.readCurrentState(mutateConn);
            const { status: reTopologyStatus, topology: reTopology } = await m.readTopology(mutateConn);
            const reArtifacts = await readGenerationSnapshotArtifacts(m, mutateConn, generation, {
              expectedState: currentState, expectedTopology: appliedRendered, expectedReleaseLock: releaseLock,
            });
            const finished = reCurrentStatus === "present"
              && JSON.stringify(withoutVolatileStateFields(reCurrent)) === expectedWithoutTimestamp
              && reTopologyStatus === "present" && JSON.stringify(reTopology) === JSON.stringify(appliedRendered)
              && reArtifacts.complete && reArtifacts.matches;
            if (!finished) {
              return blocked("resume", `step ${operation.id}: re-dispatched state.commit to finish an interrupted commit for generation ${generation}, but the target's own current.json/topology.json still don't match afterward - investigate the target directly (the lock remains held)`);
            }
            const recovered = await buildEvent({ operationId, step: operation.id, attempt: 1, phase: "succeeded" });
            // Item 9 FOURTH review fix (finding 2): re-checked again here,
            // immediately before THIS journal write - dispatchOperation()
            // and the three re-reads just above are each their own real
            // window since the check that guarded the re-dispatch itself.
            // Note: the re-dispatch above already durably committed this
            // generation for real (state.commit is what just ran) - a
            // loss discovered here only stops the SUCCEEDED event from
            // being recorded, exactly like a lease lost right after any
            // other real dispatch; it never un-does the commit itself.
            //
            // Item 9 FIFTH review fix (finding 1): moved to AFTER
            // buildEvent() (not before it) - see the sibling check a few
            // dozen lines above for why: buildEvent() is itself a real
            // async boundary (AJV validation, and a real readFile() on
            // this process's first call ever), so a check placed before
            // it left the exact same real await window open, one call
            // too early.
            {
              const lost = refuseIfLeaseLost();
              if (lost) return lost;
            }
            await m.appendEvent(mutateConn, operationId, recovered);
            emit(recovered);
            outcome = "skip";
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
        // Item 9 FOURTH review fix (finding 2): re-checked immediately
        // before appendEvent(started) itself, not just before the
        // dispatch it precedes - appendEvent() is itself a real target
        // mutation. Checking here, BEFORE writing "started" is recorded
        // at all, is strictly better than only checking right before
        // dispatch: if the lease is already known lost, refusing here
        // means this step is never journaled as started in the first
        // place, so a later resume sees a clean, untouched step
        // (decideStepResumption() returns "run", same as if this attempt
        // had never happened) - never the permanently ambiguous
        // "started, no resolution" state that writing it anyway would
        // leave behind for no benefit (this process was never going to
        // dispatch on a known-lost lease).
        //
        // Item 9 FIFTH review fix (finding 1): moved to AFTER
        // buildEvent() (not before it) - buildEvent() is itself a real
        // async boundary (operation-journal.mjs's own assertValid()
        // awaits AJV schema validation, and a real readFile() of the
        // event schema on this process's first call ever), so a check
        // placed before it left exactly the same real await window this
        // whole line of fixes exists to close, just one call too early.
        {
          const lost = refuseIfLeaseLost();
          if (lost) return lost;
        }
        await m.appendEvent(mutateConn, operationId, started);
        emit(started);

        // Item 9 THIRD review fix (finding 3): re-checked AGAIN here,
        // immediately before dispatch itself - the appendEvent() await
        // just above is its own real window for the lease to be lost
        // since the check just above it. A started-but-never-resolved
        // event is exactly what decideStepResumption()'s own "blocked"
        // outcome already handles correctly on a later resume (manual
        // investigation, never auto-retried) - refusing here (before
        // dispatch, after started was already written) never needs a
        // compensating event of its own.
        {
          const lost = refuseIfLeaseLost();
          if (lost) return lost;
        }
        try {
          await dispatchOperation(operation, { ...context, commitGeneration: generation, imageTrustByUnit });
        } catch (error) {
          const failed = await buildEvent({ operationId, step: operation.id, attempt, phase: "failed", error: sanitizeError(error) });
          await m.appendEvent(mutateConn, operationId, failed);
          emit(failed);
          const failedJournal = await withJournalStatus(journal, { status: "failed" });
          await m.updateJournalStatus(mutateConn, failedJournal);
          // Item 9 (ADR 0005): a failed applied reconciliation attempt
          // never talks about "a fresh bootstrap" - there's already a
          // real installation on this target; a failure here calls for
          // manual diagnosis, then a fresh reconciliation attempt
          // against the SAME installation, never treating it as a clean
          // slate again.
          const diagnosis = plan.mode === "bootstrap"
            ? "a fresh bootstrap is required after diagnosis, this operation cannot be resumed (see ADR 0004)"
            : "diagnose the target manually, then run a fresh hofctl plan/hofctl apply reconciliation against this same installation - this operation cannot be resumed (see ADR 0005)";
          // Item 9 review fix (finding 9): fold a failed lock release into
          // the diagnostics rather than swallowing it with `.catch(() => {})`.
          return releaseLockThenAnnotate(m, mutateConn, operationId, blocked("operation", `operation ${operation.id} failed: ${failed.error} - ${diagnosis}`));
        }

        const succeeded = await buildEvent({ operationId, step: operation.id, attempt, phase: "succeeded" });
        await m.appendEvent(mutateConn, operationId, succeeded);
        emit(succeeded);
      }

      const committedJournal = await withJournalStatus(journal, { status: "succeeded", committedGeneration: generation });
      await m.updateJournalStatus(mutateConn, committedJournal);
      const release = await tryReleaseLock(m, mutateConn, operationId);
      if (!release.released) {
        // The operation itself genuinely did succeed - state committed,
        // journal marked succeeded - but claiming blocked: false here
        // anyway would silently misreport a target that might still be
        // locked. A further, 2026-08-31 review found this exact call
        // used to discard its own return value outright, the same gap
        // already closed for the resume-side succeeded fast path.
        return blocked("lock", `operation ${operationId} committed successfully (generation ${generation}), but its lock could not be confirmed released: ${release.note} - the target may still be locked; investigate directly rather than assuming a clean run`);
      }
      emit({ type: "apply.committed", operationId, committedGeneration: generation });

      return { blocked: false, operationId, committedGeneration: generation, planId: plan.planId };
    } finally {
      await cleanupKnownHosts();
    }
  } finally {
    // The execution lease itself is released by runApply()'s own outer
    // finally, once this whole closure returns or throws (item 9 THIRD
    // review fix, finding 8) - never here, and never a second time.
    if (workDir) await rm(workDir, { recursive: true, force: true });
  }
  } // end runUnderLease()
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
  // loadAndValidateDeployment() itself now returns the exact bytes it
  // read services.yml/catalog/release-lock/render-topology.mjs from -
  // this function used to independently re-read all three deployment
  // files a SECOND time here, just for their digests; a further,
  // 2026-08-31 review found that a real TOCTOU (a file edited on the
  // workstation between the two reads could mean planning happened
  // against different bytes than the journal ends up recording a
  // digest of). Reusing the same read closes it by construction.
  return loadAndValidateDeployment({
    servicesPath: options.manifestPath,
    catalogPath: options.catalogPath,
    releaseLockPath: options.releaseLockPath,
    releaseLockIdentity: options.releaseLockIdentity,
    releaseLockOidcIssuer: options.releaseLockOidcIssuer,
    skipSignature: false,
  });
}
