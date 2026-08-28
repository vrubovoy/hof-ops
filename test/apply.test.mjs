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

import assert from "node:assert/strict";
import { mkdtemp, readFile as readFileText, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runApply } from "../scripts/apply.mjs";
import { enabledServiceIds } from "../scripts/render-topology.mjs";
import { requiredSecrets } from "../scripts/secrets.mjs";
import { loadContracts } from "../scripts/contracts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");
const examplesServices = path.join(root, "examples/services.yml");
const examplesReleaseLock = path.join(root, "examples/release-lock.json");

let workDir;
let signedReleaseLockPath;
let fakeSecretValues;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-test-"));
  const { readFile } = await import("node:fs/promises");
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
  const state = { lock: null, journals: new Map(), events: new Map() };
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
    async pinnedKnownHosts() {
      return { file: "/dev/null", cleanup: async () => {} };
    },
  };
}

function baseApplyOptions(overrides = {}) {
  return {
    manifestPath: examplesServices, releaseLockPath: signedReleaseLockPath,
    releaseLockIdentity: "test@example.com", identityFile: "/dev/null",
    recoveryAgeRecipient: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    verifyEeSignature: async () => {},
    dockerRun: async () => ({ stdout: "", stderr: "" }),
    secretsStorePath: "/dev/null", // never actually read - readSecretsStore is stubbed below
    readSecretsStore: async () => fakeSecretValues,
    ...overrides,
  };
}

test("refuses --target-mode local outright - the Execution Environment cannot mutate the real local host", async () => {
  const result = await runApply(baseApplyOptions({ targetMode: "local", approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "target-mode");
});

test("requires --identity-file", async () => {
  const result = await runApply(baseApplyOptions({ identityFile: undefined, approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "identity");
});

test("requires --approve-plan-id unless resuming", async () => {
  const result = await runApply(baseApplyOptions({}));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "approval");
});

test("sudo blocked: apply refuses a target where passwordless sudo was not confirmed", async () => {
  const mutate = makeFakeMutate();
  const result = await withFakeCosign("success", () => runApply(baseApplyOptions({
    approvePlanId: "sha256:" + "0".repeat(64), mutate,
    inspect: async () => cleanSnapshot({ host: { ...cleanSnapshot().host, sudoNonInteractive: false } }),
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "sudo");
});

test("approval mismatch: a stale or wrong --approve-plan-id is refused, not silently accepted", async () => {
  const mutate = makeFakeMutate();
  const result = await withFakeCosign("success", () => runApply(baseApplyOptions({
    approvePlanId: "sha256:" + "0".repeat(64), mutate, inspect: async () => cleanSnapshot(),
  })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "approval");
  assert.equal(mutate.state.lock, null, "never acquires the lock before approval is confirmed");
});

// Discovers the real planId by first running with a wrong id and reading
// it back out of the diagnostic message (runApply never exposes an
// "always accept" seam - the real planId must always be echoed back to
// the caller on a mismatch so a human/CLI can see what to approve).
async function discoverPlanId(options) {
  const probe = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(probe.reason, "approval", JSON.stringify(probe));
  const match = /own planId (sha256:[0-9a-f]{64})/.exec(probe.diagnostics[0]);
  assert.ok(match, probe.diagnostics[0]);
  return match[1];
}

test("a genuine, approved, signature-verified bootstrap apply runs every operation, commits, and releases the lock", async () => {
  const mutate = makeFakeMutate();
  const dockerCalls = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { dockerCalls.push({ command, args }); return { stdout: "", stderr: "" }; },
  });
  const planId = await discoverPlanId(options);

  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId, emit: (event) => events.push(event) }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, planId);
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
  const planId = await discoverPlanId(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));
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
  const planId = await discoverPlanId(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));
  const verifies = seen.filter((vars) => vars.hof_role === "image" && vars.hof_image_reference && "policy" in (vars.hof_image_trust ?? {}));
  assert.ok(verifies.length > 0, "at least one image.verify/pull pair was dispatched");
  for (const vars of verifies) assert.ok(vars.hof_image_trust, JSON.stringify(vars));
  // Both actions are always tagged so the role can tell them apart.
  const actions = new Set(verifies.map((vars) => vars.hof_image_action));
  assert.deepEqual(actions, new Set(["verify", "pull"]));
});

test("volume.ensure/network.ensure carry the real installationId/generation, matching what the renderer already labeled Compose's own volumes/networks with", async () => {
  const mutate = makeFakeMutate();
  const seen = [];
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async (command, args) => { seen.push(JSON.parse(args.at(-1))); return { stdout: "", stderr: "" }; },
  });
  const planId = await discoverPlanId(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));
  const volumeVars = seen.filter((vars) => vars.hof_role === "volume");
  assert.ok(volumeVars.length > 0, "at least one volume.ensure was dispatched for this multi-service topology");
  for (const vars of volumeVars) {
    assert.equal(vars.hof_installation_id, "00000000-0000-0000-0000-000000000000");
    assert.equal(vars.hof_generation, 1);
  }
});

test("secrets blocked: a deployment needing secrets refuses without --secrets-store, before ever touching the network", async () => {
  const result = await withFakeCosign("success", () => runApply({
    ...baseApplyOptions(), secretsStorePath: undefined, inspect: async () => { throw new Error("must never be called"); }, approvePlanId: "sha256:" + "0".repeat(64),
  }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "secrets");
  assert.match(result.diagnostics[0], /--secrets-store was not given/);
});

test("secrets blocked: a store missing a required secret refuses, naming which one", async () => {
  const result = await withFakeCosign("success", () => runApply({
    ...baseApplyOptions(), readSecretsStore: async () => ({}), inspect: async () => { throw new Error("must never be called"); },
    approvePlanId: "sha256:" + "0".repeat(64),
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
  const planId = await discoverPlanId(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));

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
  const planId = await discoverPlanId(options);
  await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));

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
  const planId = await discoverPlanId(options);
  mutate.state.lock = { operationId: "11111111-1111-1111-1111-111111111111", acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { user: "someone", workstation: "elsewhere", pid: 1 } };
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lock");
  assert.ok(result.diagnostics[0].includes("11111111-1111-1111-1111-111111111111"));
  assert.equal(mutate.state.journals.size, 0);
});

test("stale-plan recheck: a host-key change between planning and lock acquisition is refused, and the freshly-acquired lock is released", async () => {
  const mutate = makeFakeMutate();
  const planOptions = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const planId = await discoverPlanId(planOptions);

  // The real run: the first inspectTarget() call (used to recompute the
  // same plan) still sees the real pinned key; only the SECOND call (the
  // post-lock stale-plan recheck) sees a different one.
  let call = 0;
  const inspect = async () => {
    call += 1;
    return cleanSnapshot({ transport: { verified: true, trustDigest: call === 1 ? HOST_KEY : "SHA256:" + "f".repeat(43) } });
  };
  const result = await withFakeCosign("success", () => runApply({ ...baseApplyOptions({ mutate, inspect }), approvePlanId: planId }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "stale-plan");
  assert.ok(result.diagnostics[0].includes("host key changed"));
  assert.equal(mutate.state.lock, null, "the freshly-acquired lock is released after a failed recheck");
});

test("an operation failure marks the journal failed, releases the lock, and stops the run", async () => {
  const mutate = makeFakeMutate();
  let calls = 0;
  const options = baseApplyOptions({
    mutate, inspect: async () => cleanSnapshot(),
    dockerRun: async () => { calls += 1; if (calls === 2) throw Object.assign(new Error("ansible-playbook exited 2"), { stdout: "TASK [assert]\nfatal: [target]: FAILED!" }); return { stdout: "", stderr: "" }; },
  });
  const planId = await discoverPlanId(options);
  const events = [];
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId, emit: (event) => events.push(event) }));

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
  const planId = await discoverPlanId(options);

  // Set up a lock+journal as if a prior run got partway through and was
  // interrupted cleanly after its very first step's own success.
  const target = { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: HOST_KEY, installationId: "00000000-0000-0000-0000-000000000000", baselineGeneration: 0 };
  const operationId = "22222222-2222-2222-2222-222222222222";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: planId, target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: planId, target,
    inputDigests: { manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64), catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64), executionEnvironmentDigest: "sha256:" + "5".repeat(64) },
    startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
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

test("resume: a step with an unresolved (started, never confirmed) outcome blocks the whole run and keeps the lock held", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const planId = await discoverPlanId(options);

  const target = { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: HOST_KEY, installationId: "00000000-0000-0000-0000-000000000000", baselineGeneration: 0 };
  const operationId = "33333333-3333-3333-3333-333333333333";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: planId, target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: planId, target,
    inputDigests: { manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64), catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64), executionEnvironmentDigest: "sha256:" + "5".repeat(64) },
    startedAt: "2026-08-27T09:00:00Z", status: "in-progress", committedGeneration: null,
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

test("resume: an already-succeeded journal refuses (nothing to resume)", async () => {
  const mutate = makeFakeMutate();
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot() });
  const planId = await discoverPlanId(options);
  const target = { mode: "ssh", host: "hof.example.com", port: 22, user: "deploy", hostKeySha256: HOST_KEY, installationId: "00000000-0000-0000-0000-000000000000", baselineGeneration: 0 };
  const operationId = "44444444-4444-4444-4444-444444444444";
  mutate.state.lock = { apiVersion: "hof.dev/operation-lock/v1", operationId, approvedPlanId: planId, target, acquiredAt: "2026-08-27T09:00:00Z", acquiredBy: { workstation: "w", pid: 1, user: "u" } };
  mutate.state.journals.set(operationId, {
    apiVersion: "hof.dev/operation-journal/v1", operationId, approvedPlanId: planId, target,
    inputDigests: { manifestDigest: "sha256:" + "1".repeat(64), releaseLockDigest: "sha256:" + "2".repeat(64), catalogDigest: "sha256:" + "3".repeat(64), composeTemplateDigest: "sha256:" + "4".repeat(64), executionEnvironmentDigest: "sha256:" + "5".repeat(64) },
    startedAt: "2026-08-27T09:00:00Z", status: "succeeded", committedGeneration: 1,
  });
  await assert.rejects(
    () => withFakeCosign("success", () => runApply({ ...options, resume: true })).then((r) => { if (r.blocked) throw new Error(r.diagnostics[0]); }),
    /already succeeded/,
  );
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
  const options = baseApplyOptions({ mutate, inspect: async () => cleanSnapshot(), verifyEeSignature: async () => { throw new Error("no matching signatures"); } });
  const planId = await discoverPlanId({ ...options, verifyEeSignature: async () => {} });
  const result = await withFakeCosign("success", () => runApply({ ...options, approvePlanId: planId }));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "execution-environment");
  assert.equal(mutate.state.lock, null);
});

test("a real cosign signature failure on the release lock itself is reported, not silently ignored", async () => {
  const mutate = makeFakeMutate();
  const result = await withFakeCosign("failure", () => runApply(baseApplyOptions({ mutate, inspect: async () => cleanSnapshot(), approvePlanId: "sha256:" + "0".repeat(64) })));
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "deployment");
});
