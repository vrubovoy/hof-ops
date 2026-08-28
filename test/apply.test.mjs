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
import { enabledServiceIds } from "../scripts/render-topology.mjs";
import { requiredSecrets } from "../scripts/secrets.mjs";
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
  const state = { lock: null, journals: new Map(), events: new Map(), current: null };
  return {
    state,
    async acquireLock(_conn, lockDocument) {
      if (state.lock) return { acquired: false, lock: state.lock };
      state.lock = lockDocument;
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
  const succeededSteps = plan.operations.filter((operation) => operation.action === "host.prepare" || operation.action === "volume.ensure").map((operation) => operation.id);
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
  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, resume: true, emit: (event) => events.push(event) }));
  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.operationId, operationId);
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, plan.planId);
  assert.equal(mutate.state.lock, null, "the lock is released as the one remaining cleanup step");
  assert.ok(events.some((event) => event.type === "apply.committed" && event.committedGeneration === 1));
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
  // genuinely landed, independent of the event log.
  mutate.state.current = {
    apiVersion: "hof.dev/state/v1", installationId: operationId, generation: 1, lastSuccessfulOperationId: operationId,
    appliedAt: "2026-08-27T09:01:00Z", release: "1.0.0",
    manifestDigest: inputDigests.manifestDigest, releaseLockDigest: inputDigests.releaseLockDigest,
    catalogDigest: inputDigests.catalogDigest, composeTemplateDigest: inputDigests.composeTemplateDigest,
    topologyDigest: plan.desired.topologyDigest, generatedArtifacts: {},
  };

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
