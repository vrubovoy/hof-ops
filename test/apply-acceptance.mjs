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
// connection FROM inside that container, running item 8's own real
// role implementations (PR #28: host, secret, volume, network, image,
// config).
//
// This run genuinely installs Docker on the target for real
// (host.prepare, apt), delivers real secret files over real SSH
// (secret.ensure), and creates real Hof-labeled Docker volumes
// (volume.ensure) - all the way through, successfully. It then hits a
// REAL, EXPECTED failure at the first image operation: examples/
// release-lock.json is illustrative (fake digests/signing identities,
// see contracts.mjs's own comment on that fixture), so a real `cosign
// verify`/`docker pull` against those references genuinely fails - the
// same way it would against any release lock whose images don't
// actually exist. This is deliberately NOT patched around: it's real
// coverage of apply.mjs's own failure path (a real operation failure
// marking the journal failed and releasing the lock), exercised here
// for the first time against a genuinely real failure rather than a
// mocked one (see test/apply.test.mjs's own mocked failure test for
// the complementary orchestration-level coverage). config.write and
// every role after it (database/service/readiness/state, still PR #26
// skeletons, real implementation is PR #29) are consequently never
// reached by this run - a real image pull is a real prerequisite the
// rest of a real bootstrap must have, exactly like it would in
// production.
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
// The secrets store is a plain in-memory stub (readSecretsStore) - real
// `sops`/`age` mechanics are already exercised for real in PR #25's own
// secrets.test.mjs; what this test needs to prove is that apply.mjs's
// own delivery of decrypted values into the Execution Environment and
// through to the target (never through extra-vars/the journal) works
// for real, not that SOPS itself works. Everything else here is
// genuinely real, including the pinned EE image build (with its own
// real cosign binary) and every real docker run/SSH round trip it
// makes.

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
import { enabledServiceIds } from "../scripts/render-topology.mjs";
import { requiredSecrets } from "../scripts/secrets.mjs";
import { loadContracts } from "../scripts/contracts.mjs";

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
let fakeSecretValues;

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
  // A real, actionable failure - dump the container's own status and
  // boot log so a CI failure here is diagnosable from the log alone,
  // never a bare timeout with no further clue. Status matters as much
  // as the log itself: systemd's own boot messages don't necessarily
  // reach `docker logs` at all (they go to the journal, not the
  // container's stdout/stderr, unless it correctly detects it's
  // containerized - see the fixture's own ENV container=docker) - an
  // empty log with status "running" means something different from an
  // empty log with a real exit code.
  const status = await exec("docker", ["inspect", "--format", "{{json .State}}", containerName]).then((r) => r.stdout).catch((error) => `(could not inspect container: ${error.message})`);
  const logs = await exec("docker", ["logs", containerName]).then((r) => r.stdout + r.stderr).catch((error) => `(could not read container logs: ${error.message})`);
  throw new Error(`sshd on ${ip}:22 never became reachable within ${timeoutMs}ms - container state: ${status} - boot log:\n${logs}`);
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
    // No --rm here (unlike the target-less ssh-acceptance fixture) -
    // if systemd crashes on boot, `after()`'s own `docker rm --force`
    // still cleans it up, but --rm would otherwise auto-remove a
    // crashed container before waitForSsh()'s own diagnostic `docker
    // logs` call ever got to read its boot log.
    "run", "--detach", "--name", containerName,
    "--network", networkName,
    // The target fixture runs real systemd as PID 1 (see its own
    // Dockerfile comment on why). Deliberately NOT --privileged and NOT
    // --cgroupns=host - both were tried during this PR's own
    // development and caused a real, serious incident (a privileged,
    // host-cgroup-namespace-sharing systemd container reached real host
    // tty devices and interfered with real host services/cgroups on the
    // machine it was run on). This is the documented, narrower,
    // non-privileged recipe instead (confirmed against Docker/systemd's
    // own guidance on cgroup v2 hosts - see this PR's own history for
    // the sources): --cgroupns=private (the default, left unspecified)
    // keeps the container's own cgroup namespace fully isolated from
    // the host's, and Docker itself automatically delegates a private,
    // writable cgroup2 mount for it - manually bind-mounting the host's
    // own /sys/fs/cgroup (an earlier version of this recipe did) is
    // explicitly the WRONG thing to do here, since it fights Docker's
    // own delegation instead of using it. --cap-add SYS_ADMIN is the
    // one real capability systemd needs to manage its own mounts inside
    // that isolated namespace - a real, narrow grant, nowhere near
    // `--privileged`'s full capability set plus host device access.
    "--tmpfs", "/run", "--tmpfs", "/run/lock",
    "--cap-add", "SYS_ADMIN",
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

  const { catalog } = await loadContracts();
  fakeSecretValues = Object.fromEntries(
    requiredSecrets(manifest, enabledServiceIds(manifest, catalog)).map((s) => [s.name, `fake-value-${s.name}`]),
  );

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
    secretsStorePath: "/dev/null", // never actually read - readSecretsStore is stubbed below
    readSecretsStore: async () => fakeSecretValues,
  };
}

test("a real bootstrap apply: real Docker install, real secret delivery, real volume creation, then a real, expected image failure", async () => {
  // Discover the real planId the same way the CLI's own operator
  // workflow does: run once with an intentionally wrong id, read the
  // real one back out of the refusal.
  const probe = await withFakeCosign(() => runApply({ ...baseOptions(), approvePlanId: "sha256:" + "0".repeat(64) }));
  assert.equal(probe.reason, "approval", JSON.stringify(probe));
  const planId = /own planId (sha256:[0-9a-f]{64})/.exec(probe.diagnostics[0])[1];

  const events = [];
  const result = await withFakeCosign(() => runApply({ ...baseOptions(), approvePlanId: planId, emit: (event) => events.push(event) }));

  // examples/release-lock.json's own images/signing identities are
  // illustrative (fake digests/identities - see this file's own top
  // comment) - a real cosign verify or docker pull against them
  // genuinely fails. This IS the expected outcome, not a bug: it's real
  // coverage of apply.mjs's own failure path.
  assert.equal(result.blocked, true, JSON.stringify(result));
  assert.equal(result.reason, "operation");
  assert.match(result.diagnostics[0], /operation \d{3}\.image\.(verify|pull)/);

  const operationEvents = events.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  const succeeded = operationEvents.filter((event) => event.phase === "succeeded").map((event) => event.step);
  const failed = operationEvents.filter((event) => event.phase === "failed");

  // host.prepare (real apt-installed Docker), secret.ensure (a real
  // secret file delivered over real SSH), and every volume.ensure (a
  // real, Hof-labeled Docker volume) all genuinely succeeded before the
  // run ever reached an image operation - network.ensure never appears
  // at all in a bootstrap plan (see plan.mjs's own computeMissingResources:
  // a synthetic empty baseline has no networks to find "missing").
  assert.ok(succeeded.some((step) => step.endsWith(".host.prepare")), "host.prepare succeeded for real");
  assert.ok(succeeded.some((step) => step.endsWith(".secret.ensure")), "secret.ensure succeeded for real");
  assert.ok(succeeded.some((step) => step.includes(".volume.ensure.")), "at least one volume.ensure succeeded for real");
  assert.equal(failed.length, 1, "exactly one real, expected failure - the run stops at the first one");
  assert.match(failed[0].step, /\.image\.(verify|pull)\./);

  // The real, durable, on-target record - read directly, over a second,
  // independent real SSH connection (docker exec into the same
  // container, bypassing this module's own transport entirely) so this
  // assertion can't be fooled by a bug in target-mutate.mjs's own
  // reader.
  const { stdout: journalRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.json`]);
  const journal = JSON.parse(journalRaw);
  assert.equal(journal.status, "failed");
  assert.equal(journal.approvedPlanId, planId);

  const { stdout: eventsRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.events.ndjson`]);
  const durableEvents = eventsRaw.trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(durableEvents, operationEvents, "the live NDJSON stream matches the durable journal exactly, event for event");

  // A real secret genuinely landed on the target, root-owned, mode 0400
  // - delivered via ansible.builtin.copy over the real SSH/SFTP
  // connection, never through extra-vars (see the secret role's own
  // tasks/main.yml).
  const firstSecretName = Object.keys(fakeSecretValues)[0];
  const { stdout: secretRaw } = await exec("docker", ["exec", containerName, "cat", `/etc/hof/secrets/${firstSecretName}`]);
  assert.equal(secretRaw, fakeSecretValues[firstSecretName]);
  const { stdout: secretStat } = await exec("docker", ["exec", containerName, "stat", "--format", "%a %U", `/etc/hof/secrets/${firstSecretName}`]);
  assert.equal(secretStat.trim(), "400 root");

  // Docker itself was genuinely installed by host.prepare, not merely
  // reported as installed.
  const { stdout: dockerVersion } = await exec("docker", ["exec", containerName, "docker", "--version"]);
  assert.match(dockerVersion, /Docker version/);

  // A real, definitive operation failure releases the lock (ADR 0004) -
  // confirmed by a real, independent `test -e` on the target, not just
  // this module's own readLock().
  await assert.rejects(() => exec("docker", ["exec", containerName, "test", "-e", "/var/lib/hof/state/lock.json"]));
});
