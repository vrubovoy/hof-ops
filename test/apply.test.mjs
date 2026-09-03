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

import { computeExpectedCommittedState, runApply } from "../scripts/apply.mjs";
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
// Item 9 review fix (finding 3): a real target-side flock lease is
// per-HOST, held for the lifetime of the apply PROCESS. This models that
// across every fake built from the same `heldLeases` set - two runApply()
// calls that overlap on the same host genuinely contend, exactly like
// two real apply processes would.
function makeFakeMutate({ heldLeases = new Set(), leaseHost = "target-host", leaseLostAfterAcquire = null } = {}) {
  const state = { lock: null, journals: new Map(), events: new Map(), current: null, topology: null, generationSnapshots: new Map(), generationSnapshotTopologies: new Map(), generationSnapshotReleaseLocks: new Map() };
  return {
    state,
    async acquireExecutionLease() {
      if (heldLeases.has(leaseHost)) {
        throw new Error(`another apply process already holds the execution lease for this target - refusing to run a second, concurrent apply/resume against the same host`);
      }
      heldLeases.add(leaseHost);
      // Item 9 SECOND review fix (finding 1): the real isLost()/
      // lostReason() shape, so a test can simulate the lease being lost
      // partway through a real dispatch loop, never just at acquisition
      // time - leaseLostAfterAcquire is a plain, test-only mutable flag
      // a caller flips (e.g. from inside its own dockerRun) to simulate
      // exactly that.
      let released = false;
      return {
        release: async () => { released = true; heldLeases.delete(leaseHost); },
        isLost: () => !released && Boolean(leaseLostAfterAcquire && leaseLostAfterAcquire()),
        lostReason: () => "simulated lease loss for this test",
        onLost: () => {},
      };
    },
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
    // Item 9 review fix (finding 8): the snapshot directory's other two
    // files. By default they mirror the mutable topology.json and a
    // present release-lock whenever a generation snapshot exists at all,
    // so a test that only cares about the state.json oracle keeps
    // working; a test exercising an incomplete-directory case populates
    // state.generationSnapshotTopologies / state.generationSnapshotReleaseLocks
    // (a null value there means "this file is absent").
    async readGenerationSnapshotTopology(_conn, generation) {
      if (!state.generationSnapshots.has(generation)) return { status: "absent", topology: null };
      const override = state.generationSnapshotTopologies?.get(generation);
      const topology = override === undefined ? state.topology : override;
      return topology ? { status: "present", topology } : { status: "absent", topology: null };
    },
    async readGenerationSnapshotReleaseLock(_conn, generation) {
      if (!state.generationSnapshots.has(generation)) return { status: "absent", releaseLock: null };
      const override = state.generationSnapshotReleaseLocks?.get(generation);
      if (override === null) return { status: "absent", releaseLock: null };
      // Item 9 SECOND review fix (finding 3): the default now mirrors
      // the REAL release-lock document apply.mjs itself expects to find
      // (see realReleaseLock()'s own comment) - a bare placeholder
      // object would fail the new content comparison for every test
      // that never explicitly overrides this.
      return { status: "present", releaseLock: override ?? await realReleaseLock() };
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

// The exact parsed release-lock.json document a real apply run's own
// `releaseLock` variable holds (signedReleaseLockPath's own content is
// byte-identical to examplesReleaseLock - see before(), above) - used
// as makeFakeMutate()'s own default readGenerationSnapshotReleaseLock()
// answer, so the item 9 SECOND review's own content-comparison fix
// (readGenerationSnapshotArtifacts() now compares release-lock.json's
// real content, not just its presence) has something real to match
// against by default, not a placeholder object that could never equal
// what apply.mjs itself expects.
let cachedReleaseLock;
async function realReleaseLock() {
  cachedReleaseLock ??= JSON.parse(await readFile(examplesReleaseLock, "utf8"));
  return cachedReleaseLock;
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
// retainedServices (item 9, ADR 0005): a chained multi-step lifecycle
// test threads the PREVIOUS step's own approved plan.desired.retainedServices
// straight into the NEXT step's own "before" snapshot here - exactly
// what a real target's current.json would actually carry forward,
// thanks to computeExpectedCommittedState()'s own fix (see apply.mjs).
// Without it, a retained service's own volume would incorrectly look
// "missing" from baseline.volumes, and a later re-enable would
// incorrectly plan a fresh volume.ensure/migration instead of reusing
// the real, already-existing one.
async function appliedSnapshotFor({ contracts, installationId, generation, inputDigests, retainedServices = {} }) {
  const rendered = renderTopology({ ...contracts, installationId, generation });
  const state = topologyToServiceState(rendered, contracts.catalog);
  const current = {
    apiVersion: "hof.dev/state/v1", installationId, generation,
    lastSuccessfulOperationId: "seed-operation", appliedAt: "2026-08-27T08:00:00Z",
    release: state.release,
    manifestDigest: inputDigests.manifestDigest, releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest, composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: state.topologyDigest, generatedArtifacts: {}, retainedServices,
  };
  const resources = Object.entries(state.services).flatMap(([service, definition]) =>
    definition.enabled
      ? Object.entries(definition.units).map(([unit, entry]) => ({ service, unit, artifact: entry.artifact, image: entry.image, state: "running", managed: true, installationId }))
      : [],
  );
  const asResourceRecord = (name, kind) => ({ resource: name, name, managed: true, installationId, kind, composeProject: "hof" });
  // A retained service's own volume is genuinely still present in
  // Docker even though it renders no compose entry at all while
  // disabled - mirrors resolveBaseline()'s own identical fold.
  const volumeNames = [...new Set([...state.volumes, ...Object.values(retainedServices).map((entry) => entry.volume)])].sort();
  const snapshot = cleanSnapshot({
    managedState: { currentStatus: "present", current, topologyStatus: "present", topology: rendered },
    docker: {
      engineStatus: "available", composeAvailable: true,
      containersStatus: "available", resources,
      volumesStatus: "available", volumes: volumeNames.map((name) => asResourceRecord(name, "volume")),
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
  // Item 9 review fix (finding 7): the store is DECRYPTED only once the
  // run is known to be a real, non-no-op apply - so "missing a required
  // secret" is now discovered after the target is inspected and the
  // no-op check has passed, not before the network. A real approved plan
  // and a clean target get this run to that point; the deferred check
  // then blocks with the same reason and message as before.
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot(), readSecretsStore: async () => ({}) });
  const { plan, planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, planPath, approvePlanId: plan.planId }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "secrets");
  assert.match(result.diagnostics[0], /missing required secret/);
  assert.equal(mutate.state.lock, null, "the lock is released when the deferred secrets check blocks a fresh apply");
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

test("resume: an interrupted commit that published the immutable generation snapshot in full but only partially wrote the pointer files is finished by re-dispatching the idempotent state.commit (item 9 review, finding 2)", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "b2b2b2b2-0000-0000-0000-00000000ffff";
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
  // The immutable per-generation snapshot landed IN FULL (all three
  // files)...
  mutate.state.generationSnapshots.set(1, current);
  mutate.state.generationSnapshotTopologies.set(1, topology);
  // ...but the mutable pointer pair did not: current.json is still
  // absent (the crash was between the topology.json write and the
  // current.json write).
  mutate.state.current = null;
  mutate.state.topology = topology;

  const dockerCalls = [];
  const result = await withFakeCosign("success", () => runApply({
    ...options, resume: true,
    dockerRun: async (command, args) => {
      const vars = JSON.parse(args.at(-1));
      dockerCalls.push(vars);
      // A real state.commit re-dispatch finishes the atomic pointer
      // writes - the fake reflects that.
      if (vars.hof_role === "state") { mutate.state.current = current; mutate.state.topology = topology; }
      return { stdout: "", stderr: "" };
    },
  }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 1);
  assert.equal(mutate.state.lock, null, "the lock is released once the commit is finished");
  assert.equal(mutate.state.journals.get(operationId).status, "succeeded");
  assert.ok(dockerCalls.some((vars) => vars.hof_role === "state"), "state.commit IS re-dispatched here - only the immutable snapshot was complete, the pointers were not");
  const stateCommitEvents = mutate.state.events.get(operationId).filter((event) => event.step === stateCommitOp.id);
  assert.equal(stateCommitEvents.filter((event) => event.phase === "succeeded").length, 1);
});

test("resume: the succeeded fast path refuses when the immutable generation snapshot's own topology.json/release-lock.json are missing, even though its state.json matches (item 9 review, finding 8)", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "f8f8f8f8-0000-0000-0000-00000000aaaa";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests, startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 1,
  });
  mutate.state.events.set(operationId, fullySucceededEvents(operationId, plan));
  const { current, topology } = await realCommittedState({ plan, operationId, inputDigests });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(1, current);        // state.json is fine...
  mutate.state.generationSnapshotTopologies.set(1, null);  // ...but topology.json is missing
  mutate.state.generationSnapshotReleaseLocks.set(1, null); // ...and so is release-lock.json

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /snapshot is incomplete or does not match/);
  assert.match(result.diagnostics[0], /topology\.json.*absent.*release-lock\.json.*absent/);
  assert.notEqual(mutate.state.lock, null, "the lock is kept - a completion claim its own evidence doesn't fully support is never trusted");
});

// Item 9 SECOND review fix (finding 3): a further review found
// readGenerationSnapshotArtifacts() used to discard the actual
// release-lock.json VALUE it read, checking only its presence - a
// snapshot whose release-lock.json is present, parseable, and non-empty
// but belongs to a genuinely DIFFERENT release than the one this
// operation would have committed used to pass unnoticed. state.json and
// topology.json both still match here on purpose, isolating the one
// artifact this test actually cares about.
test("resume: the succeeded fast path refuses when the immutable generation snapshot's own release-lock.json is present but its CONTENT genuinely differs, even though state.json and topology.json both match", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan } = await computeApprovedPlan(options);
  const inputDigests = await realInputDigests();
  const operationId = "b1b1b1b1-0000-0000-0000-00000000eeee";
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
  // state.json and topology.json both match (the default fallbacks) -
  // only release-lock.json is deliberately wrong: present, real JSON,
  // simply a different document than the one this operation actually
  // committed under.
  mutate.state.generationSnapshotReleaseLocks.set(1, { apiVersion: "hof.dev/release-lock/v1", release: "9.9.9-not-the-real-one" });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /snapshot is incomplete or does not match/);
  assert.match(result.diagnostics[0], /content mismatch: release-lock\.json/);
  assert.notEqual(mutate.state.lock, null, "the lock is kept - a completion claim its own evidence doesn't fully support is never trusted");
});

test("a second concurrent apply/resume against the same target is refused by the process-lifetime execution lease, WITHOUT touching the durable lock the first one legitimately holds (item 9 review, finding 3)", async () => {
  const heldLeases = new Set();
  const inputDigests = await realInputDigests();
  const installationId = "3e3e3e3e-0000-0000-0000-00000000cccc";
  const contracts = structuredClone(await loadContracts());

  // A first apply process is already running against this host - it holds
  // the target-side execution lease for its whole lifetime.
  heldLeases.add("target-host");

  const mutate = makeFakeMutate({ heldLeases });
  const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation: 4, inputDigests });
  // Force a real (executable, non-no-op) change so this run gets past
  // the applied no-op return and actually reaches the lease acquisition.
  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-lease-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.services.kuvert.enabled = false;
  manifest.services.kuvert.dataRetention = "retain";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan, planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.match(result.diagnostics[0], /execution lease/);
  assert.equal(mutate.state.lock, null, "the durable lock is never released by the loser - it belongs to the other live process");
  assert.ok(heldLeases.has("target-host"), "the other process still holds the lease");
  await rm(scratchDir, { recursive: true, force: true });
});

// Item 9 THIRD review fix (findings 1 & 2): the PREVIOUS test above only
// proves the lock ends up null - true either way, whether the lease is
// acquired before any lock is ever created (the fix) or a lock is
// created and then correctly released again (the bug the third review
// actually found: a real target-side lock+journal briefly exists, which
// a genuinely concurrent legitimate resumer could already be reading by
// the time this loser's own failure handler releases it out from under
// it). This test instead spies directly on acquireLockAndJournal() to
// prove it is never even CALLED when the lease is busy - the only way to
// tell the fixed ordering (lease first, unconditionally, before either
// branch begins) apart from the old, buggy one (lease acquired deep
// inside the fresh branch, after the lock already exists).
test("a second concurrent FRESH apply refused by the execution lease never even calls acquireLockAndJournal - the lease is acquired before any lock-creating mutation is attempted, not created-then-released (item 9 third review, findings 1 & 2)", async () => {
  const heldLeases = new Set();
  heldLeases.add("target-host");
  const mutate = makeFakeMutate({ heldLeases });
  let acquireLockAndJournalCalls = 0;
  const realAcquireLockAndJournal = mutate.acquireLockAndJournal.bind(mutate);
  mutate.acquireLockAndJournal = async (...args) => { acquireLockAndJournalCalls++; return realAcquireLockAndJournal(...args); };

  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(options);
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.equal(acquireLockAndJournalCalls, 0, "acquireLockAndJournal() is never even attempted once the lease is known busy - the fresh branch never starts");
  assert.equal(mutate.state.lock, null);
});

// Same proof, on the RESUME branch: readLock()/readJournal() (resume's
// own decision-affecting reads - see runApply()'s own comment on why
// these specifically must never run before the lease is held) must never
// even be attempted when the lease is busy.
test("a second concurrent RESUME apply refused by the execution lease never even calls readLock/readJournal - no decision-affecting read happens before the lease is held (item 9 third review, findings 1 & 2)", async () => {
  const heldLeases = new Set();
  heldLeases.add("target-host");
  const mutate = makeFakeMutate({ heldLeases });
  let readLockCalls = 0;
  let readJournalCalls = 0;
  const realReadLock = mutate.readLock.bind(mutate);
  const realReadJournal = mutate.readJournal.bind(mutate);
  mutate.readLock = async (...args) => { readLockCalls++; return realReadLock(...args); };
  mutate.readJournal = async (...args) => { readJournalCalls++; return realReadJournal(...args); };

  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.equal(readLockCalls, 0, "readLock() is never even attempted once the lease is known busy - resume's own decision-affecting reads never start");
  assert.equal(readJournalCalls, 0);
});

// Item 9 SECOND review fix (finding 1): a lease loss discovered AFTER
// acquisition used to be fail-OPEN - apply.mjs never looked at it again
// once the lease was first confirmed held, so a real loss mid-run
// (target-mutate.mjs's own isLost()/onLost()) went completely unnoticed
// and this dispatch loop kept queuing new operations with no live lease
// behind them at all. Fixed: checked at the top of every iteration.
test("a lease lost mid-run (isLost() flips true between two operations) stops the dispatch loop fail-closed before the NEXT operation - never mid-flight, never silently ignored", async () => {
  const mutate = makeFakeMutate();
  let dispatchCount = 0;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async () => { dispatchCount++; return { stdout: "", stderr: "" }; },
  });
  // The lease reports itself lost only once at least one real operation
  // has already been dispatched - simulating the loss being discovered
  // strictly BETWEEN two steps of an in-progress run, never before the
  // first one.
  mutate.acquireExecutionLease = async () => ({
    release: async () => {},
    isLost: () => dispatchCount >= 1,
    lostReason: () => "simulated: the remote heartbeat loop timed out",
    onLost: () => {},
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 1, "fixture assumption: a real bootstrap has more than one operation");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.match(result.diagnostics[0], /lost mid-run/);
  assert.equal(dispatchCount, 1, "exactly one operation was dispatched before the loss was noticed and the loop stopped - never a second one");
  assert.notEqual(mutate.state.lock, null, "the durable lock is left exactly as it is - a lease loss is never guessed at, the target is investigated directly");
});

// Item 9 THIRD review fix (finding 3): the PREVIOUS test only proves
// isLost() is checked again at the TOP of the next iteration - it says
// nothing about a loss discovered strictly WITHIN one iteration, between
// that top check and the dispatch call it guards. This test simulates
// exactly that: isLost() lies (false) on its first call of the run (the
// very first iteration's own top-of-loop check) and tells the truth
// (true) on every call after - so if the ONLY check were the one at the
// top of the loop, this run would sail straight through to a real
// dispatch on operation #1 itself; if the fix (a second check
// immediately before the dispatch call, within the SAME iteration) is in
// place, operation #1 is refused before dockerRun is ever invoked.
test("a lease lost strictly WITHIN the first iteration (between its own appendEvent(started) and its own dispatch call) still stops that dispatch, not just the next iteration's (item 9 third review, finding 3)", async () => {
  const mutate = makeFakeMutate();
  let dispatchCount = 0;
  let appendEventCalls = 0;
  const realAppendEvent = mutate.appendEvent.bind(mutate);
  mutate.appendEvent = async (...args) => { appendEventCalls++; return realAppendEvent(...args); };
  let isLostCalls = 0;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async () => { dispatchCount++; return { stdout: "", stderr: "" }; },
  });
  mutate.acquireExecutionLease = async () => ({
    release: async () => {},
    // false on the first THREE calls (runApply()'s own immediately-
    // after-acquisition check - item 9 fourth review, finding 1 -
    // then operation #1's own top-of-loop check, then operation #1's
    // own pre-appendEvent(started) check - item 9 fourth review,
    // finding 2, which must ALSO see a healthy lease here, or this
    // scenario degenerates into the finding-2 test above and no longer
    // isolates THIS check at all) - true on every call after, including
    // the very next one (operation #1's own pre-dispatch check, this
    // fix's own original target).
    isLost: () => { isLostCalls++; return isLostCalls > 3; },
    lostReason: () => "simulated: lost strictly between appendEvent(started) and the dispatch it guards",
    onLost: () => {},
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 1, "fixture assumption: a real bootstrap has more than one operation");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.match(result.diagnostics[0], /lost mid-run/);
  assert.equal(appendEventCalls, 1, "fixture check: the started event for operation #1 WAS appended - the lease was still healthy at that earlier check, isolating the later pre-dispatch check as what actually catches this");
  assert.equal(dispatchCount, 0, "the very first operation is refused before dockerRun is ever invoked - a loss discovered between appendEvent(started) and this dispatch call must stop THIS dispatch too");
});

// Item 9 FOURTH review fix (finding 1): a further review found runApply()
// never checked isLost() immediately after acquiring the lease at all -
// only deep inside the dispatch loop, per the tests above. A lease that
// somehow resolves already lost (target-mutate.mjs's own
// acquireExecutionLease() is now fixed to never do this for real - see
// its own test suite - but this is checked again here too, defensively,
// for any mutate implementation) used to be accepted and USED: this test
// proves runApply() refuses it immediately, before resume's own
// readLock/readJournal or fresh's own acquireLockAndJournal ever runs -
// not merely before the dispatch loop, several steps later.
test("a lease that resolves already known lost is refused immediately after acquisition - never used to read/create a lock, not just refused inside the dispatch loop later (item 9 fourth review, finding 1)", async () => {
  const mutate = makeFakeMutate();
  let acquireLockAndJournalCalls = 0;
  const realAcquireLockAndJournal = mutate.acquireLockAndJournal.bind(mutate);
  mutate.acquireLockAndJournal = async (...args) => { acquireLockAndJournalCalls++; return realAcquireLockAndJournal(...args); };
  let released = false;
  mutate.acquireExecutionLease = async () => ({
    release: async () => { released = true; },
    isLost: () => true, // already lost the instant acquisition resolves
    lostReason: () => "simulated: resolved already lost",
    onLost: () => {},
  });
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(options);

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.match(result.diagnostics[0], /resolved already lost/);
  assert.equal(acquireLockAndJournalCalls, 0, "never even attempted - refused before the fresh branch starts, not merely before the dispatch loop several steps later");
  assert.equal(released, true, "the already-lost lease is still released, never left dangling");
  assert.equal(mutate.state.lock, null);
});

// Item 9 FOURTH review fix (finding 2): a further review found several
// journal-writing appendEvent() calls in the dispatch loop were only
// guarded by the checks immediately before dispatchOperation() itself -
// appendEvent() is its own real target mutation, and building/appending
// the "started" event happens BEFORE that check, not after. This test
// proves the lease is checked before appendEvent(started) itself: a loss
// discovered strictly between the top-of-loop check and that append
// stops it from ever being written, leaving the target's own journal
// exactly as it was (no dangling, permanently-ambiguous "started, no
// resolution" event for an operation that was never actually going to be
// dispatched anyway).
test("a lease lost strictly between the top-of-loop check and appendEvent(started) stops that append from ever happening, not just the dispatch after it (item 9 fourth review, finding 2)", async () => {
  const mutate = makeFakeMutate();
  let appendEventCalls = 0;
  const realAppendEvent = mutate.appendEvent.bind(mutate);
  mutate.appendEvent = async (...args) => { appendEventCalls++; return realAppendEvent(...args); };
  let isLostCalls = 0;
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  mutate.acquireExecutionLease = async () => ({
    release: async () => {},
    // false on the first TWO calls (runApply()'s own immediately-after-
    // acquisition check - item 9 fourth review, finding 1 - then
    // operation #1's own top-of-loop check) - true on every call after,
    // including the very next one (the pre-appendEvent(started) check
    // this fix adds).
    isLost: () => { isLostCalls++; return isLostCalls > 2; },
    lostReason: () => "simulated: lost strictly between the top-of-loop check and appendEvent(started)",
    onLost: () => {},
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 1, "fixture assumption: a real bootstrap has more than one operation");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.equal(appendEventCalls, 0, "appendEvent() is never even attempted - the started event for operation #1 is never written once the lease is known lost, even before dispatch is reached");
});

// Item 9 SECOND review fix (finding 7 in the second review's own
// numbering): mkdtemp() used to run BEFORE the try/finally that
// releases the lease, so a failure there (rare, but real: disk full, a
// permissions problem) skipped that finally entirely and leaked the
// lease helper for the rest of this process's own lifetime. Exercised
// here via a different, but equally "fails somewhere inside the now-
// widened try, before any operation is ever dispatched" scenario
// (pinnedKnownHosts() throwing) - the exact invariant this closes is
// "anything failing between lease acquisition and the end of this run
// still releases it", not specifically mkdtemp's own real filesystem
// behavior, which has no seam to fake here.
//
// Item 9 THIRD review fix (finding 8): this same test now also covers a
// further gap a third review found: the OLD code released the lease as
// the SECOND of two sequential statements in one finally block (`await
// rm(workDir, ...)` first, the lease second), so a real failure removing
// workDir itself (disk full, a permissions problem - `rm`'s own
// `force: true` swallows ENOENT, but not those) skipped lease release
// entirely, same class of bug as the mkdtemp one just above, just later
// in the same function. The fix moved lease release to a wrapping OUTER
// try/finally around the ENTIRE resume/fresh/dispatch body (this
// function's own runUnderLease() closure - see apply.mjs), so it now
// releases on ANY exception propagating out of that closure, from
// wherever it originates - which is exactly what this test already
// demonstrates via pinnedKnownHosts() below (workDir's own rm() has no
// fake-able seam, but the outer-try/finally mechanism this closes does
// not care which statement inside runUnderLease() actually threw).
test("the execution lease is released even when something fails immediately after acquisition, before any operation is ever dispatched", async () => {
  const heldLeases = new Set();
  const mutate = makeFakeMutate({ heldLeases });
  mutate.pinnedKnownHosts = async () => { throw new Error("simulated: could not resolve pinned known_hosts"); };
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const { plan, planPath } = await computeApprovedPlan(options);

  await assert.rejects(
    () => withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath })),
    /simulated: could not resolve pinned known_hosts/,
  );
  assert.ok(!heldLeases.has("target-host"), "the lease must be released even though the run itself failed before ever dispatching an operation - mkdtemp() (and everything after acquisition) now runs inside the same try/finally that releases it");
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

test("applied: a genuine no-op succeeds even when the secrets store cannot be decrypted - it never reads or delivers a secret (item 9 review, finding 7)", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-2222-2222-2222-222222222222";
  const contracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation: 4, inputDigests });

  let readStoreCalls = 0;
  const options = baseApplyOptions({
    mutate,
    inspect: async () => snapshot,
    // A SOPS/age identity momentarily unavailable - decryption throws.
    readSecretsStore: async () => { readStoreCalls++; throw new Error("no matching age identity found"); },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.deepEqual(plan.operations, [], "fixture assumption: a genuine no-op");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.noOp, true);
  assert.equal(readStoreCalls, 0, "the store is never even read for a no-op");
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
  let committedCurrent;
  let deliveredSecrets;
  const options = baseApplyOptions({
    mutate, manifestPath, inspect: async () => snapshot,
    dockerRun: async (command, args) => {
      dockerCalls.push(args);
      const stateMount = args.find((a) => a.endsWith(":/hof/state:ro"));
      if (stateMount) committedCurrent = JSON.parse(await readFileText(path.join(stateMount.slice(0, -":/hof/state:ro".length), "current.json"), "utf8"));
      const secretsMount = args.find((a) => a.endsWith(":/hof/secrets.json:ro"));
      if (secretsMount) deliveredSecrets = JSON.parse(await readFileText(secretsMount.slice(0, -":/hof/secrets.json:ro".length), "utf8"));
      return { stdout: "", stderr: "" };
    },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.equal(plan.mode, "applied");
  assert.equal(plan.summary.remove, 2, "fixture assumption: kuvert-backend + kuvert-frontend");

  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 5, "generation 4 -> 5, exactly once");

  // Item 9 review fix (finding 11): apply stamps retainedAt onto the
  // entry it is disabling-with-retain, at real commit time.
  assert.ok(committedCurrent, "state.commit's own current.json was mounted for inspection");
  assert.ok(committedCurrent.retainedServices.kuvert, "kuvert is now recorded as retained");
  assert.match(committedCurrent.retainedServices.kuvert.retainedAt, /^\d{4}-\d\d-\d\dT/, "retainedAt is an ISO timestamp, filled in by apply");

  // Item 9 review fix (finding 6): the delivered secrets file carries
  // exactly the plan's approved, scoped set - never the whole store.
  const secretEnsureOp = plan.operations.find((o) => o.action === "secret.ensure");
  assert.ok(Array.isArray(secretEnsureOp.secrets), "the applied secret.ensure carries an explicit scoped list");
  assert.deepEqual(
    Object.keys(deliveredSecrets ?? {}).sort(),
    [...secretEnsureOp.secrets].sort(),
    "apply delivers exactly the scoped secret set the approved plan names, nothing more",
  );

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

// Item 9 THIRD review fix (finding 6): computeExpectedCommittedState()'s
// own retainedAt for a service retained for the FIRST time by this
// commit (no matching plan.baseline.retainedServices entry yet) must be
// a deterministic function of operationStartedAt, not the wall clock at
// call time - a real apply.mjs calls this function TWICE for the exact
// same operation on a real resume of a commit interrupted between the
// immutable generation snapshot and its two mutable pointer files (once
// on the original dispatch, again re-rendering current.json for the
// retry - see ansible/roles/state/tasks/main.yml's own already-published
// comparison, which excludes appliedAt only and would otherwise wrongly
// refuse the retry as if the generation had been reused for two
// different commits).
test("computeExpectedCommittedState: retainedAt for a newly-retained service is a deterministic function of operationStartedAt, not wall-clock time at call time (item 9 third review, finding 6)", async () => {
  const contracts = structuredClone(await loadContracts());
  const manifest = structuredClone(contracts.manifest);
  manifest.services.kuvert.enabled = false;
  manifest.services.kuvert.dataRetention = "retain";
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-6666-6666-6666-666666666666";
  // baseline has no retainedServices at all - kuvert is retained for the
  // very first time by this plan, exactly the case whose retainedAt used
  // to come from `now` (see this function's own comment in apply.mjs).
  const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation: 4, inputDigests });
  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-retainedat-determinism-"));
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const options = baseApplyOptions({ mutate: makeFakeMutate(), manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.desired.retainedServices?.kuvert, "fixture assumption: kuvert is retained by this plan");
  assert.ok(!plan.baseline?.retainedServices?.kuvert, "fixture assumption: kuvert has no PRIOR retainedAt to carry forward - this is the first-time-retain case finding 6 is about");

  const operationStartedAt = "2026-08-27T09:00:00.000Z"; // fixed, as a real journal.startedAt would be across every retry of the same operation
  // manifest here is deliberately the LOCAL, kuvert-retained copy (the
  // one computeApprovedPlan actually planned against via manifestPath) -
  // never contracts.manifest, which is loadContracts()'s own unmodified
  // fixture and would desync appliedRendered from what `plan` itself
  // describes.
  const call = () => computeExpectedCommittedState({
    ...contracts, manifest, plan, operationId: "op-a", installationId, generation: 5, inputDigests, operationStartedAt,
  });
  const first = call();
  // A real wall-clock gap between the original dispatch and a later
  // --resume retry - `now` (appliedAt's own source) genuinely differs;
  // operationStartedAt (retainedAt's own source) is passed unchanged
  // both times, exactly like a real resume re-reading the same journal.
  await new Promise((resolve) => setTimeout(resolve, 5));
  const second = call();

  assert.equal(first.currentState.retainedServices.kuvert.retainedAt, operationStartedAt, "retainedAt is derived from operationStartedAt, not the wall clock");
  assert.equal(
    first.currentState.retainedServices.kuvert.retainedAt,
    second.currentState.retainedServices.kuvert.retainedAt,
    "two calls for the same operation (original dispatch + resume retry) must produce byte-identical retainedAt, or the target-side immutable-snapshot comparison in ansible/roles/state/tasks/main.yml wrongly refuses the retry as corruption",
  );

  // The required-parameter guard itself (also finding 6): a caller that
  // forgets operationStartedAt must fail loudly, never silently spread
  // `retainedAt: undefined` into a schema-checked field.
  assert.throws(
    () => computeExpectedCommittedState({ ...contracts, plan, operationId: "op-a", installationId, generation: 5, inputDigests }),
    /operationStartedAt/,
    "omitting operationStartedAt throws rather than silently producing an invalid retainedAt",
  );

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
  assert.match(result.diagnostics[0], /snapshot is incomplete or does not match/);
  assert.notEqual(mutate.state.lock, null, "never releases the lock on an unconfirmed recovery");
  await rm(scratchDir, { recursive: true, force: true });
});

// Item 9 THIRD review fix (finding 7): a generation snapshot's own
// state.json is now schema-checked before it is trusted as a recovery
// oracle - same shape as the test just above (an incomplete/mismatched
// snapshot is refused), but here the snapshot's state.json is PRESENT,
// non-empty, and would otherwise be silently trusted: it is missing a
// schema-REQUIRED field (lastSuccessfulOperationId) entirely, which - by
// construction - can never equal the expected value on either side of a
// naive field-by-field comparison, so this specific corruption would
// happen to be caught either way; what this test actually proves is that
// readGenerationSnapshotArtifacts() reports it via its own schema-error
// path (a distinct, more specific complaint), not merely as an
// unexplained "content mismatch".
test("applied: the succeeded fast path refuses when the immutable generation snapshot's own state.json fails its schema, even though it is present, non-empty, and parses as JSON", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-7777-7777-7777-777777777777";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 3, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-snapshot-schema-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "07:15";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const changedInputDigests = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0);

  const operationId = "99999999-7777-7777-7777-777777777777";
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
  // A schema-required field is simply absent from the snapshot's own
  // state.json - still valid JSON, still non-empty, still "complete" in
  // the sense the old code checked (present, readable, non-empty) - but
  // never a document validateStateV1() accepts.
  const { lastSuccessfulOperationId: _dropped, ...corruptedSnapshot } = current;
  mutate.state.generationSnapshots.set(4, corruptedSnapshot);

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "resume");
  assert.match(result.diagnostics[0], /does not satisfy schemas\/state-v1\.schema\.json/, "the schema failure is named specifically, not folded into a generic content-mismatch message");
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

// --- Item 9 (ADR 0005): local integration and recovery matrix - a real
// bootstrap, followed by a chain of real applied runs against the SAME
// simulated installation, each one's own approved plan.desired.retainedServices
// threaded into the next step's own "before" snapshot exactly like a
// real target's current.json would carry it forward (see
// appliedSnapshotFor's own comment, and computeExpectedCommittedState's
// own fix in apply.mjs). No privileged local mutations anywhere - dockerRun
// stays a stub throughout, matching every other test in this file. -----

test("applied lifecycle: bootstrap -> no-op -> enable -> disable-with-retain -> repeated disable (no-op) -> re-enable, generation progresses 1,1,2,3,3,4, reusing the SAME retained volume with no migration on re-enable", async () => {
  const mutate = makeFakeMutate();
  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-lifecycle-"));
  const manifestPath = path.join(scratchDir, "services.yml");
  const runOptions = () => baseApplyOptions({ mutate, manifestPath, dockerRun: async () => ({ stdout: "", stderr: "" }) });

  async function writeManifest(mutator) {
    const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
    mutator(manifest);
    await writeFile(manifestPath, YAML.stringify(manifest));
    const contracts = structuredClone(await loadContracts());
    contracts.manifest = manifest;
    return contracts;
  }

  // Step 0: bootstrap - schrank starts disabled, so enabling it later is
  // a real, deliberate diff, not just examples/services.yml's own
  // default.
  const bootstrapContracts = await writeManifest((m) => { m.services.schrank.enabled = false; });
  const bootstrapOptions = { ...runOptions(), inspect: async () => cleanSnapshot() };
  const { plan: bootstrapPlan, planPath: bootstrapPlanPath } = await computeApprovedPlan(bootstrapOptions);
  assert.equal(bootstrapPlan.mode, "bootstrap");
  const bootstrapResult = await withFakeCosign("success", () => runApply({ ...bootstrapOptions, approvePlanId: bootstrapPlan.planId, planPath: bootstrapPlanPath }));
  assert.equal(bootstrapResult.blocked, false, JSON.stringify(bootstrapResult));
  assert.equal(bootstrapResult.committedGeneration, 1);
  const installationId = bootstrapResult.operationId;

  const inputDigests = await realInputDigests();
  let generation = 1;
  let retainedServices = {};
  let contracts = bootstrapContracts;

  // Step 1: a genuine no-op - unchanged manifest, unchanged generation.
  {
    const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
    const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation, inputDigests: inputDigestsHere, retainedServices });
    const options = { ...runOptions(), inspect: async () => snapshot };
    const { plan, planPath } = await computeApprovedPlan(options);
    assert.equal(plan.mode, "applied");
    assert.deepEqual(plan.operations, [], "fixture assumption: an unchanged manifest against its own just-bootstrapped baseline is a genuine no-op");
    const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
    assert.equal(result.blocked, false, JSON.stringify(result));
    assert.equal(result.noOp, true);
    assert.equal(result.committedGeneration, 1, "a no-op never bumps generation");
  }

  // Step 2: enable schrank - a genuinely new, optional, persistent
  // service - generation 1 -> 2.
  {
    const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
    const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation, inputDigests: inputDigestsHere, retainedServices });
    contracts = await writeManifest((m) => { m.services.schrank.enabled = true; });
    const options = { ...runOptions(), inspect: async () => snapshot };
    const { plan, planPath } = await computeApprovedPlan(options);
    assert.equal(plan.summary.create, 2, "schrank-backend + schrank-frontend");
    assert.equal(plan.summary.migrate, 1, "schrank's own database, initialized for the first time");
    const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
    assert.equal(result.blocked, false, JSON.stringify(result));
    assert.equal(result.committedGeneration, 2, "generation 1 -> 2");
    generation = 2;
    retainedServices = plan.desired.retainedServices;
    assert.deepEqual(retainedServices, {}, "schrank is live now, not retained");
  }

  // Step 3: disable schrank WITH retain - generation 2 -> 3, its own
  // volume/schema recorded in retainedServices for a future re-enable.
  {
    const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
    const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation, inputDigests: inputDigestsHere, retainedServices });
    contracts = await writeManifest((m) => { m.services.schrank.enabled = false; m.services.schrank.dataRetention = "retain"; });
    const options = { ...runOptions(), inspect: async () => snapshot };
    const { plan, planPath } = await computeApprovedPlan(options);
    assert.equal(plan.summary.remove, 2);
    assert.ok(!plan.operations.some((o) => o.action === "backup.create"));
    const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
    assert.equal(result.blocked, false, JSON.stringify(result));
    assert.equal(result.committedGeneration, 3, "generation 2 -> 3");
    generation = 3;
    retainedServices = plan.desired.retainedServices;
    assert.ok(retainedServices.schrank, "schrank's own volume/schema is now recorded as retained");
    assert.equal(retainedServices.schrank.volume, "schrank-data");
  }

  // Step 4: repeated disable (already disabled+retained, manifest
  // unchanged) - a genuine no-op again, generation stays 3.
  {
    const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
    const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation, inputDigests: inputDigestsHere, retainedServices });
    const options = { ...runOptions(), inspect: async () => snapshot };
    const { plan, planPath } = await computeApprovedPlan(options);
    assert.deepEqual(plan.operations, [], "fixture assumption: re-planning an already-retained-disable is a genuine no-op");
    const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
    assert.equal(result.blocked, false, JSON.stringify(result));
    assert.equal(result.noOp, true);
    assert.equal(result.committedGeneration, 3, "still 3 - a repeated no-op never bumps generation");
  }

  // Step 5: re-enable schrank - generation 3 -> 4, reusing the SAME
  // retained volume (no volume.ensure) with no migration at all (the
  // retained schema already matches what's desired).
  {
    const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
    const { snapshot } = await appliedSnapshotFor({ contracts, installationId, generation, inputDigests: inputDigestsHere, retainedServices });
    contracts = await writeManifest((m) => { m.services.schrank.enabled = true; });
    const dockerCalls = [];
    const options = { ...runOptions(), inspect: async () => snapshot, dockerRun: async (command, args) => { dockerCalls.push(args); return { stdout: "", stderr: "" }; } };
    const { plan, planPath } = await computeApprovedPlan(options);
    assert.equal(plan.summary.create, 2, "schrank-backend + schrank-frontend, started again");
    assert.equal(plan.summary.migrate, 0, "the retained schema already matches - no migration needed");
    assert.equal(plan.desired.retainedServices.schrank, undefined, "no longer retained once re-enabled");
    const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: plan.planId, planPath }));
    assert.equal(result.blocked, false, JSON.stringify(result));
    assert.equal(result.committedGeneration, 4, "generation 3 -> 4");
    assert.notEqual(result.operationId, installationId, "this run's own fresh operationId is never the permanent installationId");

    const dispatchedVars = dockerCalls.map(extraVarsFrom);
    assert.ok(!dispatchedVars.some((v) => v.hof_role === "volume" && v.hof_volume_name === "schrank-data"), "the retained volume is reused, never recreated");
    assert.ok(!dispatchedVars.some((v) => v.hof_role === "database"), "no migration is dispatched on a retained re-enable at the already-current schema");
    const startCalls = dispatchedVars.filter((v) => v.hof_role === "service" && v.hof_service_unit?.startsWith("schrank"));
    assert.equal(startCalls.length, 2, "schrank-backend + schrank-frontend both restart");
  }

  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: an operation interrupted partway through (some steps already genuinely succeeded, state.commit not yet reached) resumes and completes without re-dispatching what already ran", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-partial-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.services.schrank.enabled = true; // a genuinely new, multi-operation diff
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const dockerCalls = [];
  const options = baseApplyOptions({
    mutate, manifestPath, inspect: async () => snapshot,
    dockerRun: async (command, args) => { dockerCalls.push(args); return { stdout: "", stderr: "" }; },
  });
  const { plan, planPath } = await computeApprovedPlan(options);
  assert.ok(plan.operations.some((o) => o.action === "state.commit"));
  assert.ok(plan.operations.length > 3, "fixture assumption: enabling schrank is a genuinely multi-operation plan");

  const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };
  const operationId = "bbbbbbbb-1111-1111-1111-111111111111";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: inputDigestsHere, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  // Every step up to (but not including) config.write already resolved
  // to a genuine success - a real prefix of the plan's own dispatch
  // order, well before state.commit is even reached.
  const configWriteIndex = plan.operations.findIndex((o) => o.action === "config.write");
  const alreadyDone = plan.operations.slice(0, configWriteIndex);
  mutate.state.events.set(operationId, alreadyDone.flatMap((op) => [
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
  ]));

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 5, "generation 4 -> 5");

  const dispatchedActions = dockerCalls.map(extraVarsFrom);
  for (const op of alreadyDone) {
    assert.ok(!dispatchedActions.some((v) => v.hof_operation_id === op.id), `${op.id} already succeeded before resume - it must never be re-dispatched`);
  }
  assert.ok(dispatchedActions.some((v) => v.hof_operation_id === plan.operations[configWriteIndex].id), "config.write itself, not yet resolved, must actually be dispatched");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: post-commit/pre-event recovery - state.commit's own real effect already landed on the target but the succeeded event never made it durably, resume recovers instead of blocking forever", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 7, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-postcommit-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "09:00";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0);

  const operationId = "bbbbbbbb-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: inputDigestsHere, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    // state.commit itself: only "started" - the real crash window this
    // recovers from is dispatch succeeding but the succeeded event
    // never making it durably.
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);

  const { current, topology } = await appliedCommittedStateFor({
    contracts: { ...baselineContracts, manifest }, plan, operationId, installationId, generation: 8, inputDigests: inputDigestsHere,
  });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(8, current);

  const dockerCalls = [];
  const result = await withFakeCosign("success", () => runApply({
    ...options, resume: true, dockerRun: async (command, args) => { dockerCalls.push(args); return { stdout: "", stderr: "" }; },
  }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 8, "generation 7 -> 8");
  assert.ok(!dockerCalls.map(extraVarsFrom).some((v) => v.hof_operation_id === stateCommitOp.id), "state.commit is recovered from its own independent target-side record, never re-dispatched");
  await rm(scratchDir, { recursive: true, force: true });
});

// Item 9 FOURTH review fix (finding 2): the exact same post-commit/
// pre-event recovery scenario as the test just above, but the lease is
// lost strictly between the recovery block's own top-of-loop check
// (state.commit's own iteration, which must still see a healthy lease -
// every earlier already-succeeded operation's own iteration also checks
// once, at its own top) and the point where it independently confirms
// current.json/topology.json/the immutable snapshot all already match
// and is about to append a SYNTHETIC succeeded event recording that. A
// further review found this exact append had no check of its own -
// fixed by adding one immediately before it (see apply.mjs's own
// comment there). Proven here by making isLost() lie exactly once, at
// the call count corresponding to that specific check, and confirming
// appendEvent() is never reached for it.
test("a lease lost strictly between the top-of-loop check and the post-commit recovery block's own synthetic succeeded-event append stops that append too (item 9 fourth review, finding 2)", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-cccc-cccc-cccc-cccccccccccc";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 7, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-postcommit-lease-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "09:30";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  const options = baseApplyOptions({ mutate, manifestPath, inspect: async () => snapshot });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0);

  const operationId = "cccccccc-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: inputDigestsHere, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const stateCommitIndex = plan.operations.findIndex((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);

  const { current, topology } = await appliedCommittedStateFor({
    contracts: { ...baselineContracts, manifest }, plan, operationId, installationId, generation: 8, inputDigests: inputDigestsHere,
  });
  mutate.state.current = current;
  mutate.state.topology = topology;
  mutate.state.generationSnapshots.set(8, current);

  let appendEventCalls = 0;
  const realAppendEvent = mutate.appendEvent.bind(mutate);
  mutate.appendEvent = async (...args) => { appendEventCalls++; return realAppendEvent(...args); };

  let isLostCalls = 0;
  // Call #1 is runApply()'s own immediately-after-acquisition check
  // (item 9 fourth review, finding 1) - must still see a healthy lease,
  // or this scenario never even reaches the dispatch loop at all. Every
  // operation BEFORE state.commit then takes the "skip" fast path (its
  // own event history already shows it succeeded) - each contributes
  // exactly one more isLost() call, at its own iteration's top-of-loop
  // check, and no other. state.commit's own iteration then makes ONE
  // MORE such call at ITS top - that is call number (stateCommitIndex +
  // 2), which must still see a healthy lease (false) so this scenario
  // actually reaches the recovery block being tested. Every call after
  // that - starting with the new check immediately before the recovery
  // block's own synthetic succeeded-event append - reports lost (true).
  mutate.acquireExecutionLease = async () => ({
    release: async () => {},
    isLost: () => { isLostCalls++; return isLostCalls > stateCommitIndex + 2; },
    lostReason: () => "simulated: lost strictly between the top-of-loop check and the post-commit recovery block's own synthetic succeeded-event append",
    onLost: () => {},
  });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.equal(appendEventCalls, 0, "the recovery block's own synthetic succeeded event is never appended once the lease is known lost, even though current.json/topology.json/the snapshot all already independently confirm the commit landed");
  await rm(scratchDir, { recursive: true, force: true });
});

// Item 9 FIFTH review fix (finding 3): the test above only covers the
// recovery block's FIRST synthetic-succeeded path (current.json/
// topology.json/the snapshot ALL already match - the whole commit
// landed, only the event was lost). A further review found the SECOND
// synthetic-succeeded path - reached when only the immutable snapshot
// matches (current.json/topology.json are still one generation behind -
// the crash window between the snapshot's own atomic publish and the
// two mutable pointer writes, see ansible/roles/state/tasks/main.yml's
// own comment), which re-dispatches state.commit for real and THEN
// appends its own synthetic succeeded event - was never separately
// exercised at all. This test builds exactly that: the snapshot for the
// new generation is already published, but current.json/topology.json
// still show the OLD one; the fake dockerRun for the resulting
// re-dispatch brings them up to date (simulating the role's own
// idempotent pointer-write), same as a real target would.
test("a lease lost strictly between the top-of-loop check and the post-commit recovery block's OWN RE-DISPATCH synthetic succeeded-event append stops that append too (item 9 fifth review, finding 3)", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-dddd-dddd-dddd-dddddddddddd";
  const baselineContracts = structuredClone(await loadContracts());
  const generation = 7;
  // The OLD, still-current pointer state - current.json/topology.json on
  // the target have not yet been rewritten to the new generation.
  const { current: staleCurrent, rendered: staleTopology, snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-postcommit-redispatch-lease-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "10:15";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));
  const inputDigestsHere = { ...inputDigests, manifestDigest: sha256(await readFile(manifestPath)) };

  let dispatchCount = 0;
  const options = baseApplyOptions({
    mutate, manifestPath, inspect: async () => snapshot,
    // The ONLY dispatch this whole scenario ever makes is state.commit's
    // own re-dispatch (every other operation already has a "succeeded"
    // event and takes the skip fast path) - simulates the role's own
    // idempotent pointer writes finally landing.
    dockerRun: async () => {
      dispatchCount++;
      mutate.state.current = newCurrent;
      mutate.state.topology = newTopology;
      return { stdout: "", stderr: "" };
    },
  });
  const { plan } = await computeApprovedPlan(options);
  assert.ok(plan.operations.length > 0);

  const operationId = "dddddddd-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: plan.planId, target: plan.target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: plan.planId, target: plan.target, plan,
    inputDigests: inputDigestsHere, startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
  });
  const stateCommitOp = plan.operations.find((op) => op.action === "state.commit");
  const stateCommitIndex = plan.operations.findIndex((op) => op.action === "state.commit");
  const otherOps = plan.operations.filter((op) => op.action !== "state.commit");
  mutate.state.events.set(operationId, [
    ...otherOps.flatMap((op) => [
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "started", at: "2026-08-27T09:00:00Z" },
      { apiVersion: "hof.dev/operation-event/v1", operationId, step: op.id, attempt: 1, phase: "succeeded", at: "2026-08-27T09:00:01Z" },
    ]),
    { apiVersion: "hof.dev/operation-event/v1", operationId, step: stateCommitOp.id, attempt: 1, phase: "started", at: "2026-08-27T09:01:00Z" },
  ]);

  const newGeneration = generation + 1;
  const { current: newCurrent, topology: newTopology } = await appliedCommittedStateFor({
    contracts: { ...baselineContracts, manifest }, plan, operationId, installationId, generation: newGeneration, inputDigests: inputDigestsHere,
  });
  // The immutable snapshot for the NEW generation is already published in
  // full - but the two mutable pointers still show the OLD one, exactly
  // the recoverable "snapshotMatches only" window this branch exists
  // for. generationSnapshotTopologies needs its own explicit override
  // here: makeFakeMutate()'s own readGenerationSnapshotTopology() falls
  // back to the CURRENT mutable state.topology when no override is set
  // for a generation (a convenience default every other snapshot-based
  // test in this file relies on, since their own mutable/immutable
  // topology always agree) - here they deliberately do NOT agree yet, so
  // the immutable snapshot's own topology must be recorded independently
  // or the fallback would wrongly report it as still matching the STALE
  // pointer.
  mutate.state.generationSnapshots.set(newGeneration, newCurrent);
  mutate.state.generationSnapshotTopologies.set(newGeneration, newTopology);
  mutate.state.current = staleCurrent;
  mutate.state.topology = staleTopology;

  let appendEventCalls = 0;
  const realAppendEvent = mutate.appendEvent.bind(mutate);
  mutate.appendEvent = async (...args) => { appendEventCalls++; return realAppendEvent(...args); };

  let isLostCalls = 0;
  // Call #1: runApply()'s own immediately-after-acquisition check. Calls
  // #2..#(stateCommitIndex+1): each prior (skip-fated) operation's own
  // top-of-loop check. Call #(stateCommitIndex+2): state.commit's own
  // top-of-loop check - must stay healthy to enter the recovery block.
  // Call #(stateCommitIndex+3): the check immediately before THIS
  // branch's own re-dispatch (item 9 third review, finding 3) - must
  // ALSO stay healthy, or the re-dispatch (and this test's own target
  // scenario) never happens at all. Only the call AFTER that - right
  // before the re-dispatch's own synthetic succeeded-event append - ever
  // reports lost.
  mutate.acquireExecutionLease = async () => ({
    release: async () => {},
    isLost: () => { isLostCalls++; return isLostCalls > stateCommitIndex + 3; },
    lostReason: () => "simulated: lost strictly between the re-dispatch and its own synthetic succeeded-event append",
    onLost: () => {},
  });

  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true }));

  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lease");
  assert.equal(dispatchCount, 1, "fixture check: state.commit WAS actually re-dispatched (the lease was still healthy for the check guarding that) - this test isolates the LATER append check specifically");
  assert.equal(appendEventCalls, 0, "the re-dispatch's own synthetic succeeded event is never appended once the lease is known lost, even though the re-dispatch itself already durably committed for real");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: a foreign installation's own same-named unit is a hard blocker, never silently ignored or adopted, and apply never dispatches anything against it", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-cccc-cccc-cccc-cccccccccccc";
  const foreignInstallationId = "ffffffff-cccc-cccc-cccc-cccccccccccc";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });
  // A foreign installation's own container, sharing the same service/
  // unit name and Compose project on a shared host - a real, if
  // unusual, scenario drift-detection must never mistake for ours
  // (plan.mjs's own computeDrift refuses this outright - see
  // "drift: a resource with a matching service/unit but a foreign
  // installationId is never treated as ours" in plan.test.mjs).
  const foreignSnapshot = {
    ...snapshot,
    docker: {
      ...snapshot.docker,
      resources: [
        ...snapshot.docker.resources,
        { service: "kuvert", unit: "kuvert-backend", artifact: "kuvert-backend", image: "ghcr.io/foreign/kuvert-backend@sha256:" + "9".repeat(64), state: "running", managed: true, installationId: foreignInstallationId },
      ],
    },
  };

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-foreign-"));
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.backup.schedule = "10:30";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  // Can't use computeApprovedPlan() here - it asserts success, and this
  // plan is genuinely expected to be blocked. Any OTHER schema-valid,
  // self-consistent plan-v2 document satisfies the CLI-level --plan/
  // --approve-plan-id requirement instead - the real blocker fires
  // inside computeLivePlanV2's own live recompute, before that
  // recomputed plan is ever compared against whatever was approved.
  const { plan: unrelatedPlan, planPath: unrelatedPlanPath } = await computeApprovedPlan(baseApplyOptions({ mutate, inspect: async () => snapshot }));

  let dockerRunCalls = 0;
  const options = baseApplyOptions({
    mutate, manifestPath, inspect: async () => foreignSnapshot,
    dockerRun: async () => { dockerRunCalls++; return { stdout: "", stderr: "" }; },
  });
  const result = await withFakeCosign("success", () => runApply({
    ...options, approvePlanId: unrelatedPlan.planId, planPath: unrelatedPlanPath,
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "plan");
  assert.match(result.diagnostics[0], new RegExp(foreignInstallationId), "the diagnostic names the foreign installation, not just a bare refusal");
  assert.equal(dockerRunCalls, 0, "never dispatches anything at all against a blocked plan");
  assert.equal(mutate.state.lock, null, "never takes the lock for a plan that's already blocked");
  await rm(scratchDir, { recursive: true, force: true });
});

test("applied: a release change on an existing installation is blocked by computeLivePlanV2 itself, never silently applied - items 10/11's own scope", async () => {
  const mutate = makeFakeMutate();
  const inputDigests = await realInputDigests();
  const installationId = "aaaaaaaa-dddd-dddd-dddd-dddddddddddd";
  const baselineContracts = structuredClone(await loadContracts());
  const { snapshot } = await appliedSnapshotFor({ contracts: baselineContracts, installationId, generation: 4, inputDigests });

  const scratchDir = await mkdtemp(path.join(tmpdir(), "hof-apply-applied-upgrade-"));
  // renderTopology() itself cross-checks manifest.release against
  // releaseLock.release (a real, EARLIER gate than the upgrade blocker
  // this test actually means to exercise) - both are bumped together
  // here so that check passes cleanly, and the live recompute reaches
  // computeUpgradeBlockers with a genuinely different desired.release
  // than the (unchanged) applied baseline's own recorded release.
  const manifest = YAML.parse(await readFile(examplesServices, "utf8"));
  manifest.release = "99.0.0";
  const manifestPath = path.join(scratchDir, "services.yml");
  await writeFile(manifestPath, YAML.stringify(manifest));

  const releaseLock = JSON.parse(await readFile(examplesReleaseLock, "utf8"));
  releaseLock.release = "99.0.0";
  const releaseLockPath = path.join(scratchDir, "release-lock.json");
  await writeFile(releaseLockPath, JSON.stringify(releaseLock));
  await writeFile(`${releaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${releaseLockPath}.pem`, "fake-certificate\n");

  // Any schema-valid, self-consistent plan-v2 document satisfies the
  // CLI-level --plan/--approve-plan-id requirement here - the real
  // blocker fires inside computeLivePlanV2's own live recompute, BEFORE
  // that recomputed plan is ever compared against whatever was
  // approved (`if (firstResult.blocked) return firstResult;`).
  const { plan: unrelatedPlan, planPath: unrelatedPlanPath } = await computeApprovedPlan(baseApplyOptions({ mutate, inspect: async () => snapshot }));

  const options = baseApplyOptions({ mutate, manifestPath, releaseLockPath, inspect: async () => snapshot });
  const result = await withFakeCosign("success", () => runApply({
    ...options, approvePlanId: unrelatedPlan.planId, planPath: unrelatedPlanPath,
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "plan");
  assert.match(result.diagnostics[0], /release change.*out of item 9's own scope/);
  assert.equal(mutate.state.lock, null, "never takes the lock for a plan that's already blocked");
  await rm(scratchDir, { recursive: true, force: true });
});
