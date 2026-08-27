// Real end-to-end acceptance test for hofctl apply - run via
// `pnpm test:apply-ssh`, deliberately NOT matched by `test/*.test.mjs`
// (needs Docker, takes noticeably longer, same reasoning as
// test/ssh-acceptance.mjs). Builds and starts a genuinely ephemeral,
// sudo-enabled, pinned Debian 12 sshd container (test/fixtures/
// apply-acceptance), builds the real pinned Execution Environment image
// from ansible/Dockerfile, and runs a real hofctl apply bootstrap
// through the ENTIRE real pipeline: real inspectTarget() over real SSH,
// a real plan-v2 build, real target-mutate lock/journal/event writes
// over real SSH (with sudo), a real `docker run` of the real EE image
// for every operation, reaching the real target over a real SSH
// connection FROM inside that container, running the real (skeleton,
// item 8 PR #26) roles.
//
// Both the ssh-fixture container and the Execution Environment
// container run on a shared, dedicated Docker bridge network so the EE
// container can reach the target directly by its real bridge IP - the
// exact same IP this test's own host-side SSH/target-mutate calls use,
// no DNS or hostname resolution needed on either side.
//
// The release lock's OWN blob signature (release-lock.json.sig/.pem) is
// verified with the same fake cosign already used by
// plan-command.test.mjs/apply.test.mjs (a real Sigstore/OIDC round trip
// isn't available outside a real GitHub Actions run) - but the
// Execution Environment image's OWN signature check is bypassed
// (verifyEeSignature) for the same reason: a locally-built image was
// never actually signed by the real execution-environment.yml workflow.
// Everything else here is genuinely real, including the pinned EE image
// build and every real docker run/SSH round trip it makes.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { runApply } from "../scripts/apply.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = path.join(root, "test/fixtures/apply-acceptance");
const fakeCosignDir = path.join(root, "test/fixtures/plan-cli");
const targetImageTag = "hof-ops-apply-acceptance-target:test";
const eeImageTag = "local/hof-ops-apply-acceptance-ee:test";
const containerName = `hof-apply-acceptance-${randomUUID()}`;
const networkName = `hof-apply-acceptance-${randomUUID()}`;

let workDir;
let targetIp;
let userKeyPath;
let hostKeyFingerprint;
let servicesPath;
let releaseLockPath;
let eeImageReference;

async function waitForSsh(ip, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await exec("ssh-keyscan", ["-p", "22", "-T", "2", ip]);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw new Error(`sshd on ${ip}:22 never became reachable within ${timeoutMs}ms`);
}

async function withFakeCosign(fn) {
  const originalPath = process.env.PATH;
  const originalOutcome = process.env.HOF_TEST_COSIGN_OUTCOME;
  process.env.PATH = `${fakeCosignDir}${path.delimiter}${originalPath}`;
  process.env.HOF_TEST_COSIGN_OUTCOME = "success";
  try {
    return await fn();
  } finally {
    process.env.PATH = originalPath;
    if (originalOutcome === undefined) delete process.env.HOF_TEST_COSIGN_OUTCOME;
    else process.env.HOF_TEST_COSIGN_OUTCOME = originalOutcome;
  }
}

before(async () => {
  await exec("docker", ["build", "--quiet", "--tag", targetImageTag, fixtureDir], { timeout: 180_000 });
  await exec("docker", ["build", "--quiet", "--tag", eeImageTag, "--file", path.join(root, "ansible/Dockerfile"), path.join(root, "ansible")], { timeout: 180_000 });
  // A plain local tag - passed to runApply() as
  // executionEnvironmentImageOverride, never as the release lock's own
  // ansibleEnvironment.image (see apply.mjs's own comment on that seam
  // for why: a locally-built, never-pushed image has no repo@sha256:...
  // reference every Docker storage backend resolves the same way, and
  // the release lock's own `image` field must stay schema-valid
  // regardless).
  eeImageReference = eeImageTag;

  await exec("docker", ["network", "create", networkName]);

  workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-acceptance-"));
  const hostKeyPath = path.join(workDir, "host_key");
  userKeyPath = path.join(workDir, "user_key");
  await exec("ssh-keygen", ["-t", "ed25519", "-f", hostKeyPath, "-N", "", "-q"]);
  await exec("ssh-keygen", ["-t", "ed25519", "-f", userKeyPath, "-N", "", "-q"]);
  const { stdout: publicKey } = await exec("cat", [`${userKeyPath}.pub`]);
  await writeFile(path.join(workDir, "authorized_keys"), publicKey, { mode: 0o644 });

  await exec("docker", [
    "run", "--detach", "--rm", "--name", containerName,
    "--network", networkName,
    "--volume", `${workDir}/host_key:/hof-keys/host_key:ro`,
    "--volume", `${workDir}/authorized_keys:/hof-keys/authorized_keys:ro`,
    targetImageTag,
  ]);
  const { stdout: ip } = await exec("docker", ["inspect", "--format", `{{(index .NetworkSettings.Networks "${networkName}").IPAddress}}`, containerName]);
  targetIp = ip.trim();
  await waitForSsh(targetIp, 30_000);

  const { stdout: fingerprintLine } = await exec("ssh-keygen", ["-l", "-E", "sha256", "-f", `${hostKeyPath}.pub`]);
  hostKeyFingerprint = fingerprintLine.trim().split(/\s+/)[1];

  const manifest = YAML.parse(await exec("cat", [path.join(root, "examples/services.yml")]).then((r) => r.stdout));
  manifest.target = { host: targetIp, user: "hofprobe", port: 22 };
  servicesPath = path.join(workDir, "services.yml");
  await writeFile(servicesPath, YAML.stringify(manifest));

  // The release lock's own ansibleEnvironment.image stays whatever
  // schema-valid, illustrative placeholder examples/release-lock.json
  // already carries - real Cosign verification of it is bypassed below
  // (verifyEeSignature) for the same reason, and the real docker run
  // target is the local build (executionEnvironmentImageOverride), not
  // this field.
  const releaseLock = JSON.parse(await exec("cat", [path.join(root, "examples/release-lock.json")]).then((r) => r.stdout));
  releaseLockPath = path.join(workDir, "release-lock.json");
  await writeFile(releaseLockPath, JSON.stringify(releaseLock));
  await writeFile(`${releaseLockPath}.sig`, "fake-signature\n");
  await writeFile(`${releaseLockPath}.pem`, "fake-certificate\n");
});

after(async () => {
  await exec("docker", ["rm", "--force", containerName]).catch(() => {});
  await exec("docker", ["network", "rm", networkName]).catch(() => {});
  await exec("docker", ["rmi", "--force", targetImageTag]).catch(() => {});
  await exec("docker", ["rmi", "--force", eeImageTag]).catch(() => {});
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

function baseOptions() {
  return {
    manifestPath: servicesPath, releaseLockPath, releaseLockIdentity: "test@example.com",
    hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 15,
    recoveryAgeRecipient: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    verifyEeSignature: async () => {},
    executionEnvironmentImageOverride: eeImageReference,
  };
}

test("a real, fully end-to-end bootstrap apply: real SSH, real lock/journal over SSH, real EE container dispatch reaching the real target, real commit", async () => {
  // Discover the real planId the same way the CLI's own operator
  // workflow does: run once with an intentionally wrong id, read the
  // real one back out of the refusal.
  const probe = await withFakeCosign(() => runApply({ ...baseOptions(), approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(probe.reason, "approval", JSON.stringify(probe));
  const planId = /own planId (sha256:[0-9a-f]{64})/.exec(probe.diagnostics[0])[1];

  const events = [];
  const result = await withFakeCosign(() => runApply({ ...baseOptions(), approvePlanId: planId, emit: (event) => events.push(event) }));

  assert.equal(result.blocked, false, JSON.stringify(result));
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, planId);

  const operationEvents = events.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  assert.ok(operationEvents.length > 10, "a real topology this size dispatches many real operations");
  assert.ok(operationEvents.every((event) => event.phase === "started" || event.phase === "succeeded"));
  assert.ok(events.some((event) => event.type === "apply.committed"));

  // The real, durable, on-target record - read directly, over a second,
  // independent real SSH connection (docker exec into the same
  // container, bypassing this module's own transport entirely) so this
  // assertion can't be fooled by a bug in target-mutate.mjs's own
  // reader.
  const { stdout: journalRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.json`]);
  const journal = JSON.parse(journalRaw);
  assert.equal(journal.status, "succeeded");
  assert.equal(journal.committedGeneration, 1);
  assert.equal(journal.approvedPlanId, planId);

  const { stdout: eventsRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.events.ndjson`]);
  const durableEvents = eventsRaw.trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(durableEvents, operationEvents, "the live NDJSON stream matches the durable journal exactly, event for event");

  // A successful commit always releases the lock (ADR 0004) - confirmed
  // by a real, independent `test -e` on the target, not just this
  // module's own readLock().
  await assert.rejects(() => exec("docker", ["exec", containerName, "test", "-e", "/var/lib/hof/state/lock.json"]));
});
