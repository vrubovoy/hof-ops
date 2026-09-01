// Unit-level coverage for scripts/apply.mjs's runApply() - orchestration
// only (approval/lock/stale-plan-recheck/dispatch/resume decisions),
// exercised with a real (fake) cosign binary on PATH so the release
// lock's own blob signature gate genuinely runs (same technique as
// plan-command.test.mjs), an injected `inspect` seam standing in for a
// real SSH inspection, an injected `mutate` seam (a small in-memory
// fake of target-mutate.mjs's own functions - that module's real
// transport/script-building correctness is already covered directly by
// target-mutate.test.mjs), and an injected `dockerRun` seam standing in
// for a real Execution Environment container run. See
// test/apply-acceptance.mjs for the complementary real-subprocess,
// real-container, real-SSH coverage.
//
// The approval flow itself is exercised through the REAL `hofctl plan`
// pipeline (runPlan(), from plan-command.mjs), not a hand-built plan
// object - computeApprovedPlan() below runs it with the exact same
// manifest/catalog/release-lock/inspect a given test's own runApply()
// call will use, writes its real plan-v2 output to a temp file, and
// hands back both the object and the file path. This is deliberate: it
// is what actually proves the PR #31 fix (a real `hofctl plan` run's
// own planId is the ID `hofctl apply` needs) rather than merely
// asserting it in prose - see PLATFORM-OPS-PLAN.md's "Item 8 reopened"
// entry, finding #1.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readFile as readFileText, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { runApply } from "../scripts/apply.mjs";
import { sha256 } from "../scripts/digest.mjs";
import { runPlan } from "../scripts/plan-command.mjs";
import { computePlanId } from "../scripts/plan-v2.mjs";
import { enabledServiceIds, renderedFilesContents, renderTopology } from "../scripts/render-topology.mjs";
import { requiredSecrets } from "../scripts/secrets.mjs";
import { topologyToServiceState } from "../scripts/state.mjs";
import { loadContracts } from "../scripts/contracts.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");
const examplesServices = path.join(root, "examples/services.yml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");
const catalogDefaultPath = path.join(root, "catalog/services-v1.yaml");
const composeTemplatePath = path.join(root, "scripts/render-topology.mjs");
const RECOVERY_AGE_RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

let workDir;
let signedReleaseLockPath;
let fakeSecretValues;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-test-"));
  signedReleaseLockPath = path.join(workDir, "release-lock.json");
  await writeFile(signedReleaseLockPath, await readFile(examplesReleaseLock));
  await writeFile(`${signedReleaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${signedReleaseLockPath}.pem`, "fake-certificate\n");

  // examples/services.yml's own real requiredSecrets() list, not a
  // hand-maintained copy - stays correct if that fixture's enabled
  // services ever change.
  const { manifest, catalog } = await loadContracts();
  fakeSecretValues = Object.fromEntries(requiredSecrets(manifest, enabledServiceIds(manifest, catalog)).map((s) => [s.name, `fake-value-${s.name}`]));
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

async function withFakeCosign(outcome, fn) {
  const originalPath = process.env.PATH;
  const originalOutcome = process.env.HOF_TEST_COSIGN_OUTCOME;
  process.env.PATH = `${fakeCosignDir}${path.delimiter}${originalPath}`;
  process.env.HOF_TEST_COSIGN_OUTCOME = outcome;
  try {
    return await fn();
  } finally {
    process.env.PATH = originalPath;
    if (originalOutcome === undefined) delete process.env.HOF_TEST_COSIGN_OUTCOME;
    else process.env.HOF_TEST_COSIGN_OUTCOME = originalOutcome;
  }
}

const HOST_KEY = "SHA256:" + "a".repeat(43);

function cleanSnapshot(overrides = {}) {
  return {
    mode: "ssh", transport: { verified: true, trustDigest: HOST_KEY },
    host: {
      os: { id: "debian", versionId: "12" }, architecture: "x86_64", cpuCores: 4,
      totalMemoryBytes: 8 * 1024 ** 3, freeDiskBytes: 40 * 1024 ** 3, clockSynchronized: true, sudoNonInteractive: true,
    },
    ports: [],
    docker: {
      engineStatus: "available", composeAvailable: true,
      containersStatus: "available", resources: [],
      volumesStatus: "available", volumes: [],
      networksStatus: "available", networks: [],
    },
    managedState: { currentStatus: "absent", current: null, topologyStatus: "absent", topology: null },
    generatedArtifactsStatus: "available", generatedArtifacts: {},
    ...overrides,
  };
}

// A small, self-contained in-memory stand-in for target-mutate.mjs's own
// exported functions - real script/transport correctness is
// target-mutate.test.mjs's own job; this just needs to behave like a
// real target would.
function makeFakeMutate() {
  const state = { lock: null, journals: new Map(), events: new Map(), current: null, topology: null, generationSnapshots: new Map() };
  return {
    state,
    async acquireLock(_conn, lockDocument) {
      if (state.lock) return { acquired: false, lock: state.lock };
      state.lock = lockDocument;
      return { acquired: true };
    },
    // Mirrors target-mutate.mjs's own acquireLockAndJournal() - lock and
    // journal created together, or neither, matching the real single
    // remote-script semantics closely enough for these tests (a real
    // client-crash-mid-way is target-mutate.test.mjs's own concern).
    async acquireLockAndJournal(_conn, lockDocument, journalDocument) {
      if (state.lock) return { acquired: false, lock: state.lock };
      state.lock = lockDocument;
      state.journals.set(journalDocument.operationId, journalDocument);
      return { acquired: true };
    },
    async readLock() {
      return state.lock ? { status: "present", lock: state.lock } : { status: "absent", lock: null };
    },
    async releaseLock(_conn, operationId) {
      if (state.lock?.operationId === operationId) { state.lock = null; return { released: true }; }
      return { released: false };
    },
    async writeJournal(_conn, journalDocument) {
      if (state.journals.has(journalDocument.operationId)) throw new Error(`a journal for operation ${journalDocument.operationId} already exists on the target - refusing to overwrite it`);
      state.journals.set(journalDocument.operationId, journalDocument);
    },
    async readJournal(_conn, operationId) {
      const journal = state.journals.get(operationId);
      return journal ? { status: "present", journal } : { status: "absent", journal: null };
    },
    async updateJournalStatus(_conn, journalDocument) {
      state.journals.set(journalDocument.operationId, journalDocument);
    },
    async appendEvent(_conn, operationId, event) {
      if (!state.events.has(operationId)) state.events.set(operationId, []);
      state.events.get(operationId).push(event);
    },
    async readEvents(_conn, operationId) {
      return state.events.get(operationId) ?? [];
    },
    async readCurrentState() {
      return state.current ? { status: "present", current: state.current } : { status: "absent", current: null };
    },
    async readTopology() {
      return state.topology ? { status: "present", topology: state.topology } : { status: "absent", topology: null };
    },
    // Item 9 (ADR 0005): the state role's own immutable per-generation
    // snapshot - a test that wants a resume recovery path to actually
    // succeed populates state.generationSnapshots.set(generation, ...)
    // itself, exactly like state.current/state.topology above.
    async readGenerationSnapshot(_conn, generation) {
      return state.generationSnapshots.has(generation)
        ? { status: "present", snapshot: state.generationSnapshots.get(generation) }
        : { status: "absent", snapshot: null };
    },
    async pinnedKnownHosts() {
      return { file: "/dev/null", cleanup: async () => {} };
    },
  };
}

function baseApplyOptions(overrides = {}) {
  return {
    manifestPath: examplesServices, releaseLockPath: signedReleaseLockPath,
    releaseLockIdentity: "test@example.com", identityFile: "/dev/null",
    recoveryAgeRecipient: RECOVERY_AGE_RECIPIENT,
    verifyEeSignature: async () => {},
    dockerRun: async () => ({ stdout: "", stderr: "" }),
    secretsStorePath: "/dev/null", // never actually read - readSecretsStore is stubbed below
    readSecretsStore: async () => fakeSecretValues,
    ...overrides,
  };
}

// Runs the REAL hofctl plan pipeline (runPlan()) with the exact same
// manifest/catalog/release-lock/inspect/recoveryAgeRecipient a test's
// own runApply() call will use, and writes its real plan-v2 output to a
// temp file - the exact artifact a real operator would produce with
// `hofctl plan > plan.json` and later hand to `hofctl apply --plan
// plan.json --approve-plan-id <id>`. Returns both the parsed plan object
// (for tests that want to inspect/mutate it) and the file path.
async function computeApprovedPlan(options) {
  const { blocked, plan, diagnostics } = await withFakeCosign("success", () => runPlan({
    manifestPath: options.manifestPath, catalogPath: options.catalogPath, releaseLockPath: options.releaseLockPath,
    releaseLockIdentity: options.releaseLockIdentity, releaseLockOidcIssuer: options.releaseLockOidcIssuer,
    targetMode: options.targetMode, knownHostsFile: options.knownHostsFile, hostKeySha256: options.hostKeySha256,
    identityFile: options.identityFile, connectTimeoutSeconds: options.connectTimeoutSeconds,
    repairDrift: options.repairDrift, inspect: options.inspect, recoveryAgeRecipient: options.recoveryAgeRecipient ?? RECOVERY_AGE_RECIPIENT,
  }));
  assert.ok(!blocked, `computeApprovedPlan: hofctl plan itself was blocked: ${JSON.stringify(diagnostics)}`);
  const planPath = path.join(workDir, `plan-${randomUUID()}.json`);
  await writeFile(planPath, JSON.stringify(plan));
  return { plan, planPath };
}

// The exact inputDigests runApply() itself computes from these fixtures'
// own real files - needed to hand-build a resume journal fixture that
// the resume path's own digest-match gate (PR #31 fix) will actually
// accept, rather than correctly (but unhelpfully, for these tests)
// refusing it as "inputs changed since this was journaled".
let cachedInputDigests;
async function realInputDigests() {
  // Always a fresh shallow copy - a caller (see the "input that changed"
  // test below) mutates the object it gets back to simulate a stale
  // digest, and must never corrupt every other test's own cached copy
  // by doing so.
  cachedInputDigests ??= await (async () => {
    const [manifestBytes, releaseLockBytes, catalogBytes, composeTemplateBytes] = await Promise.all([
      readFile(examplesServices), readFile(signedReleaseLockPath), readFile(catalogDefaultPath), readFile(composeTemplatePath),
    ]);
    const releaseLock = JSON.parse(await readFile(examplesReleaseLock, "utf8"));
    return {
      manifestDigest: sha256(manifestBytes), releaseLockDigest: sha256(releaseLockBytes), catalogDigest: sha256(catalogBytes),
      composeTemplateDigest: sha256(composeTemplateBytes),
      executionEnvironmentDigest: releaseLock.ansibleEnvironment.image.slice(releaseLock.ansibleEnvironment.image.indexOf("@") + 1),
    };
  })();
  return { ...cachedInputDigests };
}

// The exact current.json/topology.json a real state.commit dispatch
// would itself produce for a given approved plan/operationId - calls
// the same renderTopology()/renderedFilesContents() apply.mjs's own
// dispatch loop calls, with the same inputs (installationId is always
// the operationId itself, generation is always 1 for a bootstrap - see
// apply.mjs's own realInstallationId/generation). Used to build a
// resume-recovery fixture that survives the full-document comparison a
// further, 2026-08-31 review found necessary (the old, narrower
// two-field check was too easy to fool with an unrelated but
// coincidentally-matching current.json).
// A full, honest [started, succeeded] event history for every single
// operation in a plan, in the plan's own real order - the exact shape
// apply.mjs's own dispatch loop would leave behind after a genuinely
// complete, successful run. Used to build a "this journal really did
// succeed" fixture that survives the full verification a further,
// 2026-08-31 review added to the resume-side succeeded fast path
// (every step resolving to skip, not just a bare status: "succeeded"
// field).
function fullySucceededEvents(operationId, plan) {
  return plan.operations.flatMap((operation) => [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: operation.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: operation.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
  ]);
}

async function realCommittedState({ plan, operationId, inputDigests }) {
  const { manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema } = await loadContracts();
  const topology = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId: operationId, generation: 1 });
  const generatedFiles = renderedFilesContents(topology);
  const current = {
    apiVersion: "hof.dev/state/v1", installationId: operationId, generation: 1, lastSuccessfulOperationId: operationId,
    appliedAt: "2026-08-27T09:01:00Z", release: releaseLock.release,
    manifestDigest: inputDigests.manifestDigest, releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest, composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: plan.desired.topologyDigest,
    generatedArtifacts: Object.fromEntries(Object.entries(generatedFiles).map(([name, contents]) => [name, sha256(Buffer.from(contents))])),
    // Item 9 (ADR 0005): every bootstrap test fixture in this file uses
    // examples/services.yml as-is - no retained service (nothing could
    // have been disabled-with-retain before a bootstrap even ran) and
    // acme-http01 tls (never "supplied"), so these three always match
    // computeExpectedCommittedState()'s own real output exactly.
    retainedServices: {}, suppliedTlsCertificateFingerprint: null, suppliedTlsPrivateKeyFingerprint: null,
  };
  return { current, topology };
}

// Item 9 (ADR 0005): a real, schema-matching "already applied"
// inspectTarget() snapshot - genuinely no-op against `contracts` as
// given (an unmodified loadContracts() copy renders a genuine no-op;
// a caller-mutated one, or a run against a DIFFERENT manifest file,
// produces a real diff). installationId/generation are the caller's
// own fixed choice, exactly like a real installation's own permanent
// id and its last-committed generation would be. Mirrors
// plan-command.test.mjs's own identical "genuine applied no-op"
// fixture construction.
async function appliedSnapshotFor({ contracts, installationId, generation, inputDigests }) {
  const rendered = renderTopology({ ...contracts, installationId, generation });
  const state = topologyToServiceState(rendered, contracts.catalog);
  const current = {
    apiVersion: "hof.dev/state/v1", installationId, generation,
    lastSuccessfulOperationId: "seed-operation", appliedAt: "2026-08-27T08:00:00Z",
    release: state.release,
    manifestDigest: inputDigests.manifestDigest, releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest, composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: state.topologyDigest, generatedArtifacts: {},
  };
  const resources = Object.entries(state.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({ service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true, installationId }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId, kind, composeProject: "hof" });
  const snapshot = cleanSnapshot({
    managedState: { currentStatus: "present", current, topologyStatus: "present", topology: rendered },
    docker: {
      engineStatus: "available", composeAvailable: true,
      containersStatus: "available", resources,
      volumesStatus: "available", volumes: state.volumes.map((name) => asResourceRecord(name, "volume")),
      networksStatus: "available", networks: state.networks.map((name) => asResourceRecord(name, "network")),
    },
  });
  return { rendered, state, current, snapshot };
}

// Pulls the -e extra-vars JSON payload back out of one dockerRun() call's
// own args array (see apply.mjs's own dispatchOperation - always
// `args.push("-e", JSON.stringify(extraVars))`).
function extraVarsFrom(args) {
  return JSON.parse(args[args.indexOf("-e") + 1]);
}

// Item 9 (ADR 0005): the exact current.json/topology.json a real
// applied state.commit dispatch for this exact plan/operationId/
// installationId/generation would itself produce - the applied-mode
// counterpart to realCommittedState() above (which stays bootstrap-only,
// unchanged, still used by its own 3 existing call sites). Takes the
// full contracts explicitly (never re-fetches loadContracts() itself)
// so a caller using a custom manifestPath/mutated contracts controls
// exactly what this renders against.
async function appliedCommittedStateFor({ contracts, plan, operationId, installationId, generation, inputDigests }) {
  const { manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema } = contracts;
  const topology = renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId, generation });
  const generatedFiles = renderedFilesContents(topology);
  const current = {
    apiVersion: "hof.dev/state/v1", installationId, generation, lastSuccessfulOperationId: operationId,
    appliedAt: "2026-08-27T09:01:00Z", release: releaseLock.release,
    manifestDigest: inputDigests.manifestDigest, releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest, composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: plan.desired.topologyDigest,
    generatedArtifacts: Object.fromEntries(Object.entries(generatedFiles).map(([name, contents]) => [name, sha256(Buffer.from(contents))])),
    retainedServices: plan.desired.retainedServices ?? {},
    suppliedTlsCertificateFingerprint: plan.desired.suppliedTlsCertificateFingerprint ?? null,
    suppliedTlsPrivateKeyFingerprint: plan.desired.suppliedTlsPrivateKeyFingerprint ?? null,
  };
  return { current, topology };
}

test("refuses --target-mode local outright - the Execution Environment cannot mutate the real local host", async () => {
  const result = await runApply(baseApplyOptions({ targetMode: "local", approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null" }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "target-mode");
});

test("requires --identity-file", async () => {
  const result = await runApply(baseApplyOptions({ identityFile: undefined, approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null" }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "identity");
});

test("requires both --approve-plan-id and --plan together unless resuming", async () => {
  const withNeither = await runApply(baseApplyOptions({}));
  assert.equal(withNeither.blocked, true);
  assert.equal(withNeither.reason, "approval");

  const withOnlyId = await runApply(baseApplyOptions({ approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(withOnlyId.blocked, true);
  assert.equal(withOnlyId.reason, "approval");

  const withOnlyPlan = await runApply(baseApplyOptions({ planPath: "/dev/null" }));
  assert.equal(withOnlyPlan.blocked, true);
  assert.equal(withOnlyPlan.reason, "approval");
});

test("sudo blocked: apply refuses a target where passwordless sudo was not confirmed", async () => {
  const mutate = makeFakeMutate();
  const inspect = async () => cleanSnapshot({ host: { ...cleanSnapshot().host, sudoNonInteractive: false } });
  const options = baseApplyOptions({ mutate, inspect });
  // hofctl plan itself never checks sudo (it's read-only) - only apply
  // does, and only after loading the --plan file, so a real plan can
  // still be computed against this same snapshot.
  const { plan, planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "sudo");
});

test("approval mismatch: --approve-plan-id must match the --plan file's own planId, not just any value", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: "sha256:" + "0".repeat(64), planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "approval");
  assert.match(result.diagnostics[0], /does not match the plan file's own planId/);
  assert.equal(mutate.state.lock, null, "never acquires the lock before approval is confirmed");
});

test("--plan pointing at a file that isn't valid JSON is refused with a clear diagnostic", async () => {
  const mutate = makeFakeMutate();
  const planPath = path.join(workDir, `bad-plan-${randomUUID()}.json`);
  await writeFile(planPath, "not json");
  const result = await withFakeCosign("success", () => runApply(baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(), approvePlanId: "sha256:" + "0".repeat(64), planPath,
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "plan-file");
});

test("--plan pointing at a document that doesn't satisfy plan-v2 at all is refused, not partially trusted", async () => {
  const mutate = makeFakeMutate();
  const planPath = path.join(workDir, `not-a-plan-${randomUUID()}.json`);
  await writeFile(planPath, JSON.stringify({ hello: "world" }));
  const result = await withFakeCosign("success", () => runApply(baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(), approvePlanId: "sha256:" + "0".repeat(64), planPath,
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "plan-file");
  assert.match(result.diagnostics[0], /does not satisfy schemas\/plan-v2\.schema\.json/);
});

test("stale-plan (pre-lock): a plan approved earlier no longer matches a live recompute - refused before ever touching the lock", async () => {
  const mutate = makeFakeMutate();
  const planOptions = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(planOptions);

  // The live target has since changed (host key rotated) - apply's own
  // fresh pre-lock recompute must catch this before ever acquiring the
  // lock, not just after (see the post-lock recheck test below for the
  // other half of this same fix).
  const staleInspect = async () => cleanSnapshot({ transport: { verified: true, trustDigest: "SHA256:" + "f".repeat(43) } });
  const result = await withFakeCosign("success", () => runApply({
    ...baseApplyOptions({ mutate, inspect: staleInspect }), approvePlanId: plan.planId, planPath,
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "stale-plan");
  assert.match(result.diagnostics[0], /does not match the approved plan/);
  assert.equal(mutate.state.lock, null, "never even attempts to acquire the lock for an already-stale plan");
});

test("a genuine, approved, signature-verified bootstrap apply runs every operation, commits, and releases the lock", async () => {
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { dockerCalls.push({ command, args }); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);

  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath, emit: (event) => events.push(event) }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, plan.planId);
  assert.equal(mutate.state.lock, null, "lock is released on a successful commit");
  assert.equal(mutate.state.journals.get(result.operationId).status, "succeeded");
  assert.equal(mutate.state.journals.get(result.operationId).committedGeneration, 1);
  assert.ok(dockerCalls.length > 0, "every operation dispatched through a real docker run invocation");
  assert.ok(dockerCalls.every((call) => call.command === "docker" && call.args[0] === "run"));
  // Every operation-event-v1 emitted matches what was actually appended
  // to the journal - the live stdout stream is never a lossy or
  // reformatted view of what's durable (see operation-event-v1.schema.json).
  const journalEvents = mutate.state.events.get(result.operationId);
  const streamedOperationEvents = events.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  assert.deepEqual(streamedOperationEvents, journalEvents);
  assert.ok(streamedOperationEvents.every((event) => event.phase === "succeeded" || event.phase === "started"));
  assert.ok(events.some((event) => event.type === "apply.committed"));
});

test("a normal (non-resume) successful commit whose final lock release fails is reported blocked, never silently blocked: false", async () => {
  // A further, 2026-08-31 review found this exact path - the ordinary,
  // non-resume successful-commit case, not the resume-side succeeded
  // fast path PR #46 already fixed - still discarded releaseLock()'s
  // own return value outright (`await m.releaseLock(...)`, no check at
  // all).
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async () => ({ stdout: "", stderr: "" }),
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  mutate.releaseLock = async () => { throw new Error("simulated transport failure"); };
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lock");
  assert.match(result.diagnostics[0], /committed successfully.*lock could not be confirmed released/s);
  // The operation itself genuinely did succeed - the journal is still
  // marked succeeded, real state that must never be silently undone
  // just because the final cleanup step couldn't be confirmed.
  assert.equal(mutate.state.journals.size, 1);
  assert.equal([...mutate.state.journals.values()][0].status, "succeeded");
});

test("state.commit's own extra-vars carry the real commit generation (1, for a bootstrap)", async () => {
  const mutate = makeFakeMutate();
  const seen = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { seen.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  const commitVars = seen.find((vars) => vars.hof_role === "state");
  assert.ok(commitVars, "a state.commit operation was dispatched");
  assert.equal(commitVars.hof_state_generation, 1);
});

test("image.pull inherits its own hof_image_trust from the preceding image.verify for the same unit", async () => {
  const mutate = makeFakeMutate();
  const seen = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { seen.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  const verifies = seen.filter((vars) => vars.hof_role === "image" && vars.hof_image_reference && "policy" in (vars.hof_image_trust ?? {}));
  assert.ok(verifies.length > 0, "at least one image.verify/pull pair was dispatched");
  for (const vars of verifies) assert.ok(vars.hof_image_trust, JSON.stringify(vars));
  // Both actions are always tagged so the role can tell them apart.
  const actions = new Set(verifies.map((vars) => vars.hof_image_action));
  assert.deepEqual(actions, new Set(["verify", "pull"]));
});

test("volume.ensure/network.ensure carry the real (never the planning-placeholder) installationId, and the real generation", async () => {
  const mutate = makeFakeMutate();
  const seen = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { seen.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  const volumeVars = seen.filter((vars) => vars.hof_role === "volume");
  assert.ok(volumeVars.length > 0, "at least one volume.ensure was dispatched for this multi-service topology");
  for (const vars of volumeVars) {
    // The real installation id this run actually used - deliberately
    // never the fixed BOOTSTRAP_INSTALLATION_ID_PLACEHOLDER planning
    // uses (see apply.mjs's own comment on why those two must differ):
    // every real resource this run labels must carry a genuinely unique
    // id, not a value every other bootstrap run would share.
    assert.equal(vars.hof_installation_id, result.operationId);
    assert.notEqual(vars.hof_installation_id, "00000000-0000-0000-0000-000000000000");
    assert.equal(vars.hof_generation, 1);
  }
});

test("secrets blocked: a deployment needing secrets refuses without --secrets-store, before ever touching the network", async () => {
  const result = await withFakeCosign("success", () => runApply({
    ...baseApplyOptions(), secretsStorePath: undefined, inspect: async () => { throw new Error("must never be called"); },
    approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null",
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "secrets");
  assert.match(result.diagnostics[0], /--secrets-store was not given/);
});

test("secrets blocked: a store missing a required secret refuses, naming which one", async () => {
  const result = await withFakeCosign("success", () => runApply({
    ...baseApplyOptions(), readSecretsStore: async () => ({}), inspect: async () => { throw new Error("must never be called"); },
    approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null",
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "secrets");
  assert.match(result.diagnostics[0], /missing required secret/);
});

// Both of the next two tests read the mounted file's content from
// WITHIN the dockerRun mock itself, not after runApply() returns -
// runApply() deletes its own workDir (and everything mounted from it)
// in a finally block before ever returning.
test("secret.ensure mounts a real, correctly-scoped secrets file into the Execution Environment container - never through extra-vars", async () => {
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  let mountedSecrets;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => {
      dockerCalls.push(args);
      const mountArg = args.find((a) => a.endsWith(":/hof/secrets.json:ro"));
      if (mountArg) mountedSecrets = JSON.parse(await readFileText(mountArg.slice(0, -":/hof/secrets.json:ro".length), "utf8"));
      return { stdout: "", stderr: "" };
    },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  const secretCall = dockerCalls.find((args) => JSON.parse(args.at(-1)).hof_role === "secret");
  assert.ok(secretCall, "a secret.ensure operation was dispatched");
  const vars = JSON.parse(secretCall.at(-1));
  assert.equal(vars.hof_secrets_file, "/hof/secrets.json");
  assert.ok(!("hof_secrets" in vars) && !JSON.stringify(vars).includes("fake-value-"), "no secret value ever appears in extra-vars");
  assert.deepEqual(mountedSecrets, fakeSecretValues);

  // Every OTHER operation's own docker run never mounts the secrets
  // file at all - it's scoped to exactly the one operation that needs it.
  const otherCalls = dockerCalls.filter((args) => JSON.parse(args.at(-1)).hof_role !== "secret");
  assert.ok(otherCalls.every((args) => !args.some((a) => a.includes("secrets.json"))));
});

test("config.write mounts the real rendered file contents into the Execution Environment container", async () => {
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  let mountedNames;
  let mountedCompose;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => {
      dockerCalls.push(args);
      const mountArg = args.find((a) => a.endsWith(":/hof/generated:ro"));
      if (mountArg) {
        const hostDir = mountArg.slice(0, -":/hof/generated:ro".length);
        mountedNames = (await (await import("node:fs/promises")).readdir(hostDir)).sort();
        mountedCompose = await readFileText(path.join(hostDir, "compose.yml"), "utf8");
      }
      return { stdout: "", stderr: "" };
    },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  const configCall = dockerCalls.find((args) => JSON.parse(args.at(-1)).hof_role === "config");
  assert.ok(configCall, "a config.write operation was dispatched");
  const vars = JSON.parse(configCall.at(-1));
  assert.equal(vars.hof_generated_files_dir, "/hof/generated");
  assert.deepEqual(mountedNames, ["Caddyfile", "backup-inventory.json", "compose.yml", "runtime-config.json", "service.env", "topology.json"]);
  assert.match(mountedCompose, /services:/);
});

test("lock already held by another operation refuses, without touching the journal", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(options);
  // A real, schema-valid lock document - target-mutate.mjs's own
  // acquireLock() now has its response validated against
  // operation-lock-v1 before apply ever reads a field off it.
  mutate.state.lock = {
    apiVersion: "hof.dev/operation-lock/v1", operationId: "11111111-1111-1111-1111-111111111111",
    approvedPlanId: "sha256:" + "9".repeat(64), target: plan.target,
    acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { user: "someone", workstation: "elsewhere", pid: 1 },
  };
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lock");
  assert.ok(result.diagnostics[0].includes("11111111-1111-1111-1111-111111111111"));
  assert.equal(mutate.state.journals.size, 0);
});

test("lock held by a document that fails its own schema is refused, not silently trusted for its operationId", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(options);
  // Missing apiVersion/approvedPlanId/target - not a real lock document.
  mutate.state.lock = { operationId: "11111111-1111-1111-1111-111111111111", acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { user: "someone", workstation: "elsewhere", pid: 1 } };
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lock");
  assert.match(result.diagnostics[0], /does not satisfy its own schema/);
});

test("stale-plan recheck: a host-key change between lock acquisition and the post-lock recheck is refused, and the freshly-acquired lock is released", async () => {
  const mutate = makeFakeMutate();
  const planOptions = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(planOptions);

  // The real run: the first inspectTarget() call (used for the sudo
  // check and the pre-lock plan recompute) still sees the real pinned
  // key; only the SECOND call (the post-lock stale-plan recheck) sees a
  // different one.
  let call = 0;
  const inspect = async () => {
    call += 1;
    return cleanSnapshot({ transport: { verified: true, trustDigest: call === 1 ? HOST_KEY : "SHA256:" + "f".repeat(43) } });
  };
  const result = await withFakeCosign("success", () => runApply({ ...baseApplyOptions({ mutate, inspect }), approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "stale-plan");
  assert.match(result.diagnostics[0], /changed underneath this plan since it was locked/);
  assert.equal(mutate.state.lock, null, "the freshly-acquired lock is released after a failed recheck");
});

test("an operation failure marks the journal failed, releases the lock, and stops the run", async () => {
  const mutate = makeFakeMutate();
  let calls = 0;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async () => { calls += 1; if (calls === 2) throw Object.assign(new Error("ansible-playbook exited 2"), { stdout: "TASK [assert]\nfatal: [target]: FAILED!" }); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath, emit: (event) => events.push(event) }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "operation");
  assert.equal(mutate.state.lock, null, "lock is released after a definitive failure");
  const journal = [...mutate.state.journals.values()][0];
  assert.equal(journal.status, "failed");
  const failedEvent = events.find((event) => event.phase === "failed");
  assert.ok(failedEvent);
  assert.match(failedEvent.error, /fatal/);
  assert.ok(!failedEvent.error.includes("undefined"));
});

test("resume: an already-succeeded step is skipped, never re-dispatched, and the run still commits", async () => {
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { dockerCalls.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();

  // Set up a lock+journal as if a prior run got partway through and was
  // interrupted cleanly after its very first step's own success. The
  // journal now embeds the FULL approved plan (PR #31 fix) - resume
  // reads operations straight from it, never re-derives a live
  // baseline/diff (see apply.mjs's own comment on why: a genuinely
  // partial bootstrap would otherwise look like an already-applied host
  // to a fresh resolveBaseline() call, and resume would wrongly refuse).
  const operationId = "22222222-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: "001.host.prepare", attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
  ]);

  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true, emit: (event) => events.push(event) }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.operationId, operationId);
  assert.equal(result.committedGeneration, 1);
  assert.ok(events.some((event) => event.type === "apply.resume-skip" && event.step === "001.host.prepare"));
  assert.ok(!dockerCalls.some((vars) => vars.hof_operation_id === "001.host.prepare"), "the already-succeeded step is never re-dispatched");
});

test("resume: a genuinely partial bootstrap (a real mutation already happened, state not yet committed) is resumable - the ordinary bootstrap-baseline check is never consulted", async () => {
  // The exact regression PLATFORM-OPS-PLAN.md's \"Item 8 reopened\" entry
  // names as finding #2: an inspect() snapshot that looks like an
  // already-applied host (a managed volume genuinely exists) must not
  // make resume refuse - that is exactly the case resume exists for.
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  const partiallyMutatedSnapshot = () => cleanSnapshot({
    docker: {
      engineStatus: "available", composeAvailable: true,
      containersStatus: "available", resources: [],
      volumesStatus: "available",
      volumes: [{ resource: "hof-kuvert-backend-data", name: "hof-kuvert-backend-data", managed: true, installationId: "22222222-2222-2222-2222-222222222222", kind: "volume", composeProject: "hof" }],
      networksStatus: "available", networks: [],
    },
  });
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { dockerCalls.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();

  const operationId = "55555555-5555-5555-5555-555555555555";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  // Every step up through the last volume.ensure, in the plan's own
  // real dispatch order - not just steps matching those two action
  // names cherry-picked out of order. A further, 2026-08-31 review
  // found apply.mjs now refuses an event history where a later step has
  // recorded events while an earlier one in plan order has none at all
  // (never a shape a real run could produce) - this fixture must be a
  // valid PREFIX of the plan's own operations, matching what a real
  // partial bootstrap would actually leave behind.
  const succeededThroughIndex = plan.operations.findLastIndex((operation) => operation.action === "host.prepare" || operation.action === "volume.ensure");
  const succeededSteps = plan.operations.slice(0, succeededThroughIndex + 1).map((operation) => operation.id);
  mutate.state.events.set(operationId, succeededSteps.flatMap((step) => [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
  ]));

  // The RESUME run's own inspect() sees the target with the real volume
  // already created - if resume still called resolveBaseline() against
  // this, it would see "managed resources exist" and refuse outright.
  const result = await withFakeCosign("success", () => runApply({ ...options, inspect: partiallyMutatedSnapshot, resume: true }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.operationId, operationId);
  for (const step of succeededSteps) assert.ok(!dockerCalls.some((vars) => vars.hof_operation_id === step), `${step} must not be re-dispatched`);
});

test("resume: an input that changed since this operation was journaled is refused, naming which one", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  inputDigests.manifestDigest = "sha256:" + "9".repeat(64); // no longer the real one

  const operationId = "66666666-6666-6666-6666-666666666666";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /manifestDigest has changed/);
});

test("resume: a journal that fails its own schema is refused, not silently trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const operationId = "77777777-7777-7777-7777-777777777777";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  // Missing plan/inputDigests entirely - not a real journal document.
  mutate.state.journals.set(operationId, { apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /does not satisfy its own schema/);
});

test("resume: a step with an unresolved (started, never confirmed) outcome blocks the whole run and keeps the lock held", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();

  const operationId = "33333333-3333-3333-3333-333333333333";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: "001.host.prepare", attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
  ]);

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.ok(result.diagnostics[0].includes("unresolved"));
  assert.equal(mutate.state.lock?.operationId, operationId, "the lock is never released on an ambiguous, unresolved outcome");
});

test("resume: an already-succeeded journal completes cleanly - finishing the one thing that could still be outstanding (releasing the lock), never refusing outright", async () => {
  // Real regression coverage for ADR 0004's own errata: a crash between
  // the journal being marked "succeeded" and the lock actually being
  // released used to leave that lock stuck forever, since the old
  // behavior (assertJournalResumable throwing "nothing to resume" for
  // any succeeded journal) never gave this case a path to finish.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-4444-4444-4444-444444444444";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 1,
  });
  // A full, honest event history AND the real target-side current.json/
  // topology.json - a further, 2026-08-31 review found the succeeded
  // fast path must independently confirm both, not just trust the
  // journal's own bare status field.
  mutate.state.events.set(operationId, fullySucceededEvents(operationId, plan));
  const { current, topology } = await realCommittedState({ plan, operationId, inputDigests });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(1, current);
  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true, emit: (event) => events.push(event) }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.operationId, operationId);
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, plan.planId);
  assert.equal(mutate.state.lock, null, "the lock is released as the one remaining cleanup step");
  assert.ok(events.some((event) => event.type === "apply.committed" && event.committedGeneration === 1));
});

test("resume: an already-succeeded journal whose lock release fails is reported blocked, never silently blocked: false", async () => {
  // A further, 2026-08-31 review found the old code discarded a real
  // releaseLock() failure via a bare `.catch(() => {})`, and even a
  // clean { released: false } response was never looked at - either
  // way, blocked: false was returned regardless, silently misreporting
  // a target that stayed genuinely locked.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-5555-5555-5555-555555555555";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 1,
  });
  mutate.state.events.set(operationId, fullySucceededEvents(operationId, plan));
  const { current, topology } = await realCommittedState({ plan, operationId, inputDigests });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(1, current);
  mutate.releaseLock = async () => { throw new Error("simulated transport failure"); };
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /lock could not be confirmed released/);
  assert.notEqual(mutate.state.lock, null, "the lock is never silently forgotten just because release failed - the target may still be locked");
});

test("resume: a lock with no journal at all is refused, and the stale lock is released - nothing could have run yet", async () => {
  // A further, 2026-08-31 review found this case used to refuse forever
  // with no recovery path: lock and journal are now always created
  // together (see acquireLockAndJournal()), so a lock with no journal
  // proves no operation was ever dispatched - safe to clean up.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const operationId = "44444444-6666-6666-6666-666666666666";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: "sha256:" + "0".repeat(64), target: { mode: "ssh", host: "h", port: 22, user: "u", hostKeySha256: HOST_KEY, installationId: null, baselineGeneration: 0 }, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  // mutate.state.journals stays empty for this operationId.
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /nothing has actually run yet/);
  assert.equal(mutate.state.lock, null, "the stale lock is released, not left stuck forever");
});

test("resume: a journal that is present but unreadable is refused WITHOUT auto-releasing the lock - unlike absent, it doesn't prove nothing ran", async () => {
  // A further, 2026-08-31 review found "unreadable" (the file exists
  // but couldn't be read/parsed - a permission problem, real on-disk
  // corruption) used to be treated identically to "absent" (provably
  // never created at all), silently releasing a lock that might be
  // guarding a real, unresolved operation.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const operationId = "44444444-7777-8888-9999-000000000000";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: "sha256:" + "0".repeat(64), target: { mode: "ssh", host: "h", port: 22, user: "u", hostKeySha256: HOST_KEY, installationId: null, baselineGeneration: 0 }, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.readJournal = async () => ({ status: "unreadable", journal: null });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /refusing to guess whether it's safe to release the lock/);
  assert.notEqual(mutate.state.lock, null, "an unreadable journal never auto-releases the lock - it isn't proof nothing ran");
});

test("resume: a journal whose own embedded operationId disagrees with the lock's is refused, not trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-7777-7777-7777-777777777777";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    // Read back by the lock's own operationId (the map key), but the
    // journal DOCUMENT's own embedded operationId field disagrees - a
    // real cross-binding gap a further, 2026-08-31 review found:
    // nothing ever compared this field against the lock's.
    apiVersion: "hof.dev/operation-journal/v1", operationId: "44444444-9999-9999-9999-999999999999", approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /journal's own operationId .* does not match the lock's/);
});

test("resume: a journal whose own approvedPlanId disagrees with the lock's is refused, before the embedded plan is even trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-8888-8888-8888-888888888888";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: "sha256:" + "0".repeat(64), target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /journal's own approvedPlanId .* does not match the lock's/);
});

test("resume: a standalone succeeded event with no preceding started is refused as corrupted, never trusted to skip a step that never ran", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-1111-2222-3333-444444444444";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const realStep = plan.operations[0].id;
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: realStep, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:00Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /corrupted/);
  assert.equal(mutate.state.lock?.operationId, operationId, "the lock is never released on a corrupted history either - never guessed at");
});

test("resume: post-commit recovery refuses a current.json that merely coincides on operationId/generation but disagrees on real content", async () => {
  // A further, 2026-08-31 review found the old recovery check compared
  // only two fields (lastSuccessfulOperationId, generation) - a
  // schema-valid but otherwise-unrelated current.json matching those by
  // coincidence would have passed as "proof" of a real commit.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "44444444-2222-3333-4444-555555555555";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);
  const { current, topology } = await realCommittedState({ plan, operationId, inputDigests });
  // Schema-valid (still a real sha256 digest string), matches
  // operationId and generation, but claims a manifestDigest that
  // doesn't actually correspond to this run's own real inputs - the
  // exact kind of mismatch the old two-field check could never see.
  mutate.state.current = { ...current, manifestDigest: "sha256:" + "0".repeat(64) };
  mutate.state.topology = topology;

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /unresolved/);
  assert.equal(mutate.state.lock?.operationId, operationId, "never releases the lock on an unconfirmed recovery");
});

test("resume: no lock at all on the target refuses cleanly", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /nothing to resume/);
});

test("Execution Environment signature verification failure refuses before ever acquiring the lock", async () => {
  const mutate = makeFakeMutate();
  const result = await withFakeCosign("success", () => runApply(baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(), approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null",
    verifyEeSignature: async () => { throw new Error("no matching signatures"); },
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "execution-environment");
  assert.equal(mutate.state.lock, null);
});

test("a real cosign signature failure on the release lock itself is reported, not silently ignored", async () => {
  const mutate = makeFakeMutate();
  const result = await withFakeCosign("failure", () => runApply(baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(), approvePlanId: "sha256:" + "0".repeat(64), planPath: "/dev/null",
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "deployment");
});

// --- Remediation for the 2026-08-28 "real invariants still violated"
// review (ADR 0004's own errata, second round): post-commit recovery,
// resume trusting an unvalidated embedded plan/events, plan-file
// self-consistency, supplied-TLS delivery-time TOCTOU, platform
// checking on resume, and SSH proxy hardening on the Ansible inventory
// itself. -------------------------------------------------------------

test("resume: state.commit's own real effect already landed on the target (current.json confirms it) but the succeeded event never made it durably - resume recovers instead of blocking forever", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "88888888-8888-8888-8888-888888888888";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    // state.commit itself: only "started" - the crash window this
    // recovers from is dispatch succeeding but the succeeded event
    // never making it durably.
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);
  // The real, durable, target-side record - written by the state role's
  // own atomic copy - already confirms state.commit's own effect
  // genuinely landed, independent of the event log. A full, real
  // current.json/topology.json pair (not just a two-field stand-in) -
  // apply.mjs's own recovery now compares the whole document.
  const { current, topology } = await realCommittedState({ plan, operationId, inputDigests });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(1, current);

  const dockerCalls = [];
  const result = await withFakeCosign("success", () => runApply({
    ...options, resume: true, dockerRun: async (command, args) => { dockerCalls.push(args); return { stdout: "", stderr: "" }; },
  }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 1);
  assert.equal(mutate.state.lock, null, "the lock is released once recovery confirms the real commit");
  assert.equal(mutate.state.journals.get(operationId).status, "succeeded");
  assert.ok(!dockerCalls.some((args) => JSON.parse(args.at(-1)).hof_role === "state"), "state.commit is never re-dispatched once the target's own record confirms it already landed");
  const stateCommitEvents = mutate.state.events.get(operationId).filter((event) => event.step === stateCommitOp.id);
  assert.equal(stateCommitEvents.filter((event) => event.phase === "succeeded").length, 1, "the missing succeeded event is synthesized, keeping the durable record honest");
});

test("resume: state.commit blocked with no confirming current.json on the target stays blocked - recovery is never guessed, only confirmed", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "88888888-9999-9999-9999-999999999999";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);
  // mutate.state.current stays null (target-mutate.mjs's own "absent")
  // - the real ambiguous case: no independent confirmation either way.

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.ok(result.diagnostics[0].includes("unresolved"));
  assert.equal(mutate.state.lock?.operationId, operationId, "the lock is never released on a genuinely unresolved outcome");
});

test("resume: a journal whose own embedded plan's planId doesn't match its own content is refused, not trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-2222-2222-2222-222222222222";
  // Schema-valid, but content changed with the original (now stale)
  // planId left in place.
  const tamperedPlan = { ...plan, policy: { repairDrift: true } };
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan: tamperedPlan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /planId does not match/);
});

test("resume: an event claiming a different operationId than this run's own lock/journal is refused", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-3333-3333-3333-333333333333";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const realStep = plan.operations[0].id;
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId: "00000000-0000-0000-0000-000000000000", step: realStep, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:00Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /claims operationId/);
});

test("resume: an event referencing a step that isn't part of the approved plan is refused", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-4444-4444-4444-444444444444";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: "999.made.up.step", attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:00Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /isn't part of the approved plan/);
});

test("resume: a later plan step has recorded events while an earlier one has none at all is refused - never a shape a real run could produce", async () => {
  // A real run only ever dispatches plan.operations strictly in order -
  // a further, 2026-08-31 review found nothing checked this globally,
  // even though every individual event was already schema/operationId/
  // step-membership valid.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-6666-6666-6666-666666666666";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  // Only the LAST step gets events - every earlier step in the plan's
  // own real order has none at all.
  const lastStep = plan.operations.at(-1).id;
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: lastStep, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /out of the plan's own dispatch order/);
});

test("resume: a later step's own fully-resolved events appearing in the raw stream entirely BEFORE an earlier step's is refused, even though neither step's own history has a gap", async () => {
  // A further, 2026-08-31 review found the gap check above still missed
  // this: both steps have events, neither individual step's own history
  // is malformed, so both the gap check and the per-step physical-order
  // check pass - only walking the RAW stream's own cross-step order
  // catches it.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-8888-8888-8888-888888888888";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const [stepA, stepB] = plan.operations; // stepA comes before stepB in the plan's own real order
  mutate.state.events.set(operationId, [
    // stepB's own events, fully resolved, appear FIRST in the file -
    // stepA's own don't even begin until after.
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepB.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepB.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepA.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:02Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepA.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:03Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /out of the plan's own dispatch order/);
});

test("resume: two steps' own events genuinely interleaved in the raw stream is refused, even though each step's own isolated history looks fine", async () => {
  // A.started, B.started, B.succeeded, A.succeeded - a real run's own
  // dispatch loop can never produce this (it never starts step B until
  // step A has already resolved), but neither the per-step physical-
  // order check (each step's OWN filtered sub-list is still internally
  // [started, succeeded], in order) nor the old gap check (both steps
  // have events) would have caught it.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-9999-9999-9999-999999999999";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const [stepA, stepB] = plan.operations;
  mutate.state.events.set(operationId, [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepA.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepB.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:01Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepB.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:02Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stepA.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:03Z" },
  ]);
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /out of the plan's own dispatch order|don't resolve to a genuine success/);
});

test("--plan pointing at a schema-valid file whose own planId doesn't match its own content is refused, not trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  // Schema-valid (still a real plan-v2 shape), content changed, but the
  // original (now stale) planId field left in place - exactly the kind
  // of tampering schema validation alone can never catch.
  const tamperedPlan = { ...plan, policy: { repairDrift: true } };
  assert.notEqual(computePlanId(tamperedPlan), tamperedPlan.planId, "fixture assumption: this tampering must actually change the recomputed id");
  const tamperedPath = path.join(workDir, `tampered-plan-${randomUUID()}.json`);
  await writeFile(tamperedPath, JSON.stringify(tamperedPlan));
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath: tamperedPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "plan-file");
  assert.match(result.diagnostics[0], /does not match its own content/);
});

test("resume: an unsupported platform is refused - the same check the fresh path runs, never skipped just because resume also skips baseline resolution", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "77777777-5555-5555-5555-555555555555";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  // Same real HOST_KEY (so the resume run's own host-key check still
  // passes) - only the OS changes, to an unsupported one.
  const unsupportedSnapshot = cleanSnapshot({ host: { ...cleanSnapshot().host, os: { id: "ubuntu", versionId: "20.04" } } });
  const result = await withFakeCosign("success", () => runApply({ ...options, inspect: async () => unsupportedSnapshot, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "platform");
});

test("the Ansible inventory this run builds disables SSH ProxyCommand/ProxyJump - the same hardening the real inspection/mutation transports already have", async () => {
  const mutate = makeFakeMutate();
  let inventoryContent;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => {
      const mountArg = args.find((a) => a.endsWith(":/hof/inventory.ini:ro"));
      if (mountArg) inventoryContent = await readFileText(mountArg.slice(0, -":/hof/inventory.ini:ro".length), "utf8");
      return { stdout: "", stderr: "" };
    },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.ok(inventoryContent, "the inventory file was mounted into at least one real docker run");
  assert.match(inventoryContent, /ProxyCommand=none/);
  assert.match(inventoryContent, /ProxyJump=none/);
});

test("supplied TLS delivery-time TOCTOU: a certificate swapped between approval and resume is refused, never delivered", async () => {
  // A fresh (non-resume) run's own two live recomputes (pre-lock and,
  // again, under the lock - see computeLivePlanV2) already re-read TLS
  // material fresh each time, so a swap before either of those already
  // trips the ordinary stale-plan check first. --resume is the one path
  // that never repeats that live recompute at all - the delivery-time
  // fingerprint check is the ONLY thing standing between a swapped
  // certificate and real delivery there, so that's the path this test
  // actually needs to exercise to prove the check is load-bearing.
  const mutate = makeFakeMutate();
  const certDir = await mkdtemp(path.join(tmpdir(), "hof-apply-tls-toctou-"));
  const certificatePath = path.join(certDir, "cert.pem");
  const privateKeyPath = path.join(certDir, "key.pem");

  async function generateCert() {
    await exec("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", privateKeyPath, "-out", certificatePath,
      "-days", "1", "-subj", "/CN=example.com",
      "-addext", "subjectAltName=DNS:example.com,DNS:*.example.com",
    ]);
  }
  await generateCert();

  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.tls = { mode: "supplied", certificatePath, privateKeyPath };
  const manifestPath = path.join(certDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.suppliedTls, "fixture assumption: a supplied-TLS manifest must actually produce plan.suppliedTls");
  // realInputDigests() itself is hardcoded to examplesServices' own
  // digest - this test uses a different, custom manifest file (the
  // supplied-TLS override above), so its own manifestDigest has to be
  // computed fresh, against the real file apply.mjs will actually read.
  const inputDigests = { ...(await realInputDigests()), manifestDigest: sha256(await readFile(manifestPath)) };

  const operationId = "77777777-6666-6666-6666-666666666666";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  // Swap in a DIFFERENT, still-valid certificate/key pair (same SAN, so
  // it would pass every other check) after the plan was already
  // approved and journaled.
  await generateCert();

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "tls");
  assert.match(result.diagnostics[0], /no longer match the fingerprints/);
  assert.equal(mutate.state.lock?.operationId, operationId, "the lock stays held - a blocked resume never releases it");
  await rm(certDir, { recursive: true, force: true });
});

// --- Item 9 (ADR 0005): applied-mode reconciliation - runApply()'s own
// generalized, mode-aware flow. The lock/journal/event mechanics
// themselves (resume recovery, stale-plan rejection, lock-release
// failures, an operation failure never committing state) are SHARED
// code with bootstrap, already exercised exhaustively above; the tests
// below focus on what's genuinely NEW or mode-DEPENDENT: the no-op
// short-circuit, generation/installationId derivation, the applied
// action whitelist, and mode-aware diagnostics. -----------------------

test("applied: a genuine no-op invokes zero mutation methods (no lock, no journal, no Execution Environment) and reports noOp: true, never bumping generation", async () => {
  const mutate = makeFakeMutate();
  let acquireCalls = 0;
  const originalAcquire = mutate.acquireLockAndJournal;
  mutate.acquireLockAndJournal = async (...args) => { acquireCalls++; return originalAcquire(...args); };
  let dockerRunCalls = 0;

  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-1111-1111-1111-111111111111";
  const contracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation: 4, inputDigests });

  const options = baseApplyOptions({ mutate, inspect: async () => snapshot, dockerRun: async () => { dockerRunCalls++; return { stdout: "", stderr: "" }; } });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.equal(plan.mode, "applied");
  assert.deepEqual(plan.operations, [], "fixture assumption: unmodified contracts against their own rendered baseline must be a genuine no-op");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.noOp, true);
  assert.equal(result.committedGeneration, 4, "never bumps generation for a no-op");
  assert.equal(result.operationId, undefined, "no lock/journal was ever created - there is no operationId for a no-op");
  assert.equal(acquireCalls, 0, "a no-op takes no lock");
  assert.equal(dockerRunCalls, 0, "a no-op runs no Execution Environment");
  assert.equal(mutate.state.journals.size, 0, "a no-op creates no journal");
  assert.equal(mutate.state.lock, null);
});

test("applied: disabling a persistent service with retain commits baseline.generation + 1, dispatches service.stop/service.remove bound to the exact permanent installationId (never the fresh operationId), and never touches the volume or dispatches backup.create", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-2222-2222-2222-222222222222";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-retain-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.services.kuvert.enabled = false;
  manifest.services.kuvert.dataRetention = "retain";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const dockerCalls = [];
  const options = baseApplyOptions({
    mutate, manifestPath, inspect: async () => snapshot,
    dockerRun: async (command, args) => { dockerCalls.push(args); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.equal(plan.mode, "applied");
  assert.equal(plan.summary.remove, 2, "fixture assumption: kuvert-backend + kuvert-frontend");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 5, "generation 4 -> 5, exactly once");

  const dispatchedVars = dockerCalls.map(extraVarsFrom);
  const removeCalls = dispatchedVars.filter((v) => v.hof_role === "service" && v.hof_service_action === "remove");
  const stopCalls = dispatchedVars.filter((v) => v.hof_role === "service" && v.hof_service_action === "stop");
  assert.equal(removeCalls.length, 2, "kuvert-backend + kuvert-frontend, the only two units actually being removed");
  // Every unit removed gets its own stop first (2), PLUS every OTHER
  // unit whose own config cascades from kuvert's removal (its CORS
  // origins shifting) gets stopped and restarted too - a real
  // cascading update, not just the two units actually going away.
  assert.ok(stopCalls.length > removeCalls.length, "at least one cascaded config-only unit is stopped too, beyond the two actually removed");
  for (const vars of [...removeCalls, ...stopCalls]) {
    assert.equal(vars.hof_installation_id, installationId, "the service role's own discovery is bound to the baseline's own PERMANENT installationId");
    assert.notEqual(vars.hof_installation_id, result.operationId, "never the fresh operationId used only for this run's own lock/journal bookkeeping");
  }
  assert.ok(!dispatchedVars.some((v) => v.hof_role === "backup"), "backup.create is never in the applied whitelist - never dispatched");
  assert.ok(!dispatchedVars.some((v) => v.hof_role === "volume" && v.hof_volume_name === "kuvert-data"), "retain-only removal never touches the volume itself");

  await rm(scratchDir, { recursive: true, force: true });
});

test("resume: a journal whose embedded plan claims mode: applied but still carries a bootstrap-only action (host.prepare) fails the applied whitelist, not silently trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan: bootstrapPlan } = await computeApprovedPlan(options);
  assert.ok(bootstrapPlan.operations.some((o) => o.action === "host.prepare"), "fixture assumption: a real bootstrap plan always carries host.prepare");
  // recovery is required for bootstrap and FORBIDDEN for applied (see
  // plan-v2.schema.json's own allOf) - dropped here so the tampered
  // document stays schema-valid under its new claimed mode, isolating
  // the whitelist check itself (never the schema gate) as what actually
  // catches this.
  const { recovery: _recovery, ...withoutRecovery } = bootstrapPlan;
  const tampered = {
    ...withoutRecovery, mode: "applied",
    target: { ...bootstrapPlan.target, installationId: "aaaaaaaa-5555-5555-5555-555555555555", baselineGeneration: 4 },
  };
  const tamperedWithId = { ...tampered, planId: computePlanId(tampered) };

  const inputDigests = await realInputDigests();
  const operationId = "99999999-1111-1111-1111-111111111111";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: tamperedWithId.planId, target: tamperedWithId.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: tamperedWithId.planId, target: tamperedWithId.target, plan: tamperedWithId,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /fails the applied action whitelist/);
});

test("resume: a journal whose embedded plan claims mode: bootstrap but carries an applied-only action (service.stop) fails the bootstrap whitelist, not silently trusted", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan: bootstrapPlan } = await computeApprovedPlan(options);
  const startOp = bootstrapPlan.operations.find((o) => o.action === "service.start");
  assert.ok(startOp, "fixture assumption: a real bootstrap plan always starts at least one service");
  const tampered = {
    ...bootstrapPlan,
    operations: bootstrapPlan.operations.map((op) => (op.id === startOp.id ? { ...op, action: "service.stop" } : op)),
  };
  const tamperedWithId = { ...tampered, planId: computePlanId(tampered) };

  const inputDigests = await realInputDigests();
  const operationId = "99999999-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: tamperedWithId.planId, target: tamperedWithId.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: tamperedWithId.planId, target: tamperedWithId.target, plan: tamperedWithId,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /fails the bootstrap action whitelist/);
});

test("applied: resume of an interrupted reconciliation attempt completes it, committing baseline.generation + 1 against the SAME installation", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-3333-3333-3333-333333333333";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 6, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-resume-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "04:30"; // a real, minimal config-only change
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const changedInputDigests = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot, dockerRun: async () => ({ stdout: "", stderr: "" }) });
  const { plan } = await computeApprovedPlan(options);
  assert.equal(plan.mode, "applied");
  assert.ok(plan.operations.length > 0, "fixture assumption: a backup-schedule change is a real diff");

  const operationId = "99999999-3333-3333-3333-333333333333";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: changedInputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  // No events at all - nothing has been dispatched yet, resume must run
  // the whole plan from the start.

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.operationId, operationId);
  assert.equal(result.committedGeneration, 7, "generation 6 -> 7");
  const journal = mutate.state.journals.get(operationId);
  assert.equal(journal.status, "succeeded");
  assert.equal(journal.committedGeneration, 7);
  assert.equal(mutate.state.lock, null, "the lock is released once the resumed run genuinely completes");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: the succeeded fast path recovers cleanly at an arbitrary (non-1) generation, confirming current.json, topology.json, AND the immutable generation snapshot all independently agree", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-4444-4444-4444-444444444444";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 9, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-succeeded-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "05:15";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const changedInputDigests = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0, "fixture assumption: a backup-schedule change is a real diff");

  const operationId = "99999999-4444-4444-4444-444444444444";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: changedInputDigests, startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 10,
  });
  mutate.state.events.set(operationId, fullySucceededEvents(operationId, plan));

  const { current, topology } = await appliedCommittedStateFor({
    contracts: { ...baselineContracts, manifest }, plan, operationId, installationId, generation: 10, inputDigests: changedInputDigests,
  });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(10, current);

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 10);
  assert.equal(mutate.state.lock, null);
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: the succeeded fast path refuses when the immutable generation snapshot doesn't match, even though current.json/topology.json both do", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-6666-6666-6666-666666666666";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 3, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-snapshot-mismatch-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "06:45";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const changedInputDigests = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0);

  const operationId = "99999999-6666-6666-6666-666666666666";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: changedInputDigests, startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 4,
  });
  mutate.state.events.set(operationId, fullySucceededEvents(operationId, plan));

  const { current, topology } = await appliedCommittedStateFor({
    contracts: { ...baselineContracts, manifest }, plan, operationId, installationId, generation: 4, inputDigests: changedInputDigests,
  });
  mutate.state.current = current;
  mutate.state.topology = topology;
  // The generation snapshot itself is simply never written (a real gap:
  // the state role's own three snapshot writes happen BEFORE the two
  // pointer files - see ansible/roles/state/tasks/main.yml - so any
  // crash between them and the two pointer writes leaves exactly this
  // shape on a real target).
  mutate.state.generationSnapshots.clear();

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /immutable snapshot could not be confirmed present/);
  assert.notEqual(mutate.state.lock, null, "never releases the lock on an unconfirmed recovery");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: supplied TLS delivery-time TOCTOU - a certificate swapped between approval and resume is refused, never delivered, on an already-applied installation too", async () => {
  const mutate = makeFakeMutate();
  const certDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-tls-toctou-"));
  const certificatePath = path.join(certDir, "cert.pem");
  const privateKeyPath = path.join(certDir, "key.pem");

  async function generateCert() {
    await exec("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", privateKeyPath, "-out", certificatePath,
      "-days", "1", "-subj", "/CN=example.com",
      "-addext", "subjectAltName=DNS:example.com,DNS:*.example.com",
    ]);
  }
  await generateCert();

  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.tls = { mode: "supplied", certificatePath, privateKeyPath };
  const manifestPath = path.join(certDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const inputDigests = { ...(await realInputDigests()), manifestDigest: sha256(await readFile(manifestPath)) };
  const installationId = "aaaaaaaa-7777-7777-7777-777777777777";
  const baselineContracts = structuredClone(await loadContracts());
  baselineContracts.manifest = manifest;
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 2, inputDigests });

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.suppliedTls, "fixture assumption: a supplied-TLS manifest must actually produce plan.suppliedTls");

  const operationId = "99999999-7777-7777-7777-777777777777";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });

  // Swap in a DIFFERENT, still-valid certificate/key pair (same SAN)
  // after the plan was already approved and journaled - the exact TOCTOU
  // window the delivery-time fingerprint check exists to close, now
  // proven for an applied target too, not just bootstrap.
  await generateCert();

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "tls");
  assert.match(result.diagnostics[0], /no longer match the fingerprints/);
  assert.equal(mutate.state.lock?.operationId, operationId, "the lock stays held - a blocked resume never releases it");
  await rm(certDir, { recursive: true, force: true });
});

test("applied: a stale plan (the target already moved on before this run even starts) is rejected pre-lock, before ever taking the lock", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-8888-8888-8888-888888888888";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot: approvedSnapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-stale-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "07:30";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  // Approve a plan against the target as it looked a moment ago...
  const approveOptions = baseApplyOptions({ mutate, manifestPath, inspect: async () => approvedSnapshot });
  const { plan, planPath } = await computeApprovedPlan(approveOptions);
  assert.ok(plan.operations.length > 0);

  // ...but by the time apply actually runs, the target has ALREADY moved
  // on to a later generation - a real concurrent change (a different
  // operator, a different tool) this plan was never computed against.
  const laterManifest = YAML.parse(await readFile(examplesServices, "utf8"));
  laterManifest.backup.schedule = "07:30";
  laterManifest.services.wachter.enabled = false;
  const { manifest: _m, ...restBaselineContracts } = baselineContracts;
  const laterContracts = { ...restBaselineContracts, manifest: laterManifest };
  const { snapshot: laterSnapshot } = await appliedSnapshotFor({ contracts: laterContracts, installationId, generation: 5, inputDigests });

  const runOptions = baseApplyOptions({ mutate, manifestPath, inspect: async () => laterSnapshot, dockerRun: async () => ({ stdout: "", stderr: "" }) });
  const result = await withFakeCosign("success", () => runApply({ ...runOptions, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "stale-plan");
  assert.equal(mutate.state.lock, null, "a pre-lock stale-plan rejection never takes the lock at all");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: a stale plan (the target changes AFTER the pre-lock check but BEFORE the post-lock recheck) is caught by the recheck, and the freshly-acquired lock is released", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-9999-9999-9999-999999999999";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot: approvedSnapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-stale-recheck-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "08:15";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const approveOptions = baseApplyOptions({ mutate, manifestPath, inspect: async () => approvedSnapshot });
  const { plan, planPath } = await computeApprovedPlan(approveOptions);
  assert.ok(plan.operations.length > 0);

  // The first inspect() call (the pre-lock recompute) still sees the
  // exact target this plan was approved against; only the SECOND call
  // (the post-lock stale-plan recheck) sees a target that has already
  // moved on - a real concurrent change landing in the narrow window
  // between this run's own pre-lock check and its lock actually being
  // acquired.
  let call = 0;
  const laterManifest = YAML.parse(await readFile(examplesServices, "utf8"));
  laterManifest.backup.schedule = "08:15";
  laterManifest.services.wachter.enabled = false;
  const { manifest: _m, ...restBaselineContracts } = baselineContracts;
  const laterContracts = { ...restBaselineContracts, manifest: laterManifest };
  const { snapshot: laterSnapshot } = await appliedSnapshotFor({ contracts: laterContracts, installationId, generation: 5, inputDigests });
  const inspect = async () => (call++ === 0 ? approvedSnapshot : laterSnapshot);

  const runOptions = baseApplyOptions({ mutate, manifestPath, inspect, dockerRun: async () => ({ stdout: "", stderr: "" }) });
  const result = await withFakeCosign("success", () => runApply({ ...runOptions, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "stale-plan");
  assert.match(result.diagnostics[0], /changed underneath this plan since it was locked/);
  assert.equal(mutate.state.lock, null, "the freshly-acquired lock is released after a failed recheck");
  await rm(scratchDir, { recursive: true, force: true });
});
