// Real end-to-end acceptance test for hofctl apply - run via
// `pnpm test:apply-ssh`, deliberately NOT matched by `test/*.test.mjs`
// (needs Docker, takes noticeably longer, same reasoning as
// test/ssh-acceptance.mjs). Builds and starts a genuinely ephemeral,
// sudo-enabled, pinned Debian 12 sshd container (test/fixtures/
// apply-acceptance) and runs a real hofctl apply bootstrap through the
// ENTIRE real pipeline, start to finish, for the first time: real
// inspectTarget() over real SSH, a real plan-v2 build, real
// target-mutate lock/journal/event writes over real SSH (with sudo), a
// real `docker run` of the real, published, independently-signed
// Execution Environment image for every operation (no local build, no
// signature bypass, no image override - see baseOptions() below),
// reaching the real target over a real SSH connection FROM inside that
// container, running every one of item 8's ten real role
// implementations against real application images.
//
// This is the "full disposable-VM acceptance" PLATFORM-OPS-PLAN.md's
// "Item 8 reopened" entry named as missing (finding #9): earlier
// versions of this file stopped at a real, expected image-pull failure
// (examples/release-lock.json's own images were illustrative). This one
// uses the real, published, real-Cosign-signed platform release lock
// instead - downloaded fresh in before() via `gh release download` - so
// every image reference in it is genuinely pullable and genuinely
// signed. The manifest enables only the platform's own mandatory core
// (schlussel, schloss - see catalog/services-v1.yaml's own `mandatory:
// true` entries; every optional service disabled, matching
// test/fixtures/topologies/core.yml's own shape) - a real, deliberate
// scope choice: `hofctl apply`'s own correctness is what this test
// exists to prove, not each application's own runtime behavior (already
// proven separately and repeatedly by scripts/integration-matrix.mjs's
// own real `docker compose up --wait` runs against the full topology).
// A real self-signed TLS certificate/private key (manifest.tls.mode
// "supplied", not acme-http01) is included too, exercising the real
// delivery path a 2026-08-28 review found completely missing (see
// render-topology.mjs's own fixed-secret-path fix and
// scripts/supplied-tls.mjs's own real parse/key-match/validity/SAN
// validation). With only mandatory core enabled, requiredSecrets()
// itself is empty - no application secret store is needed at all.
//
// Both the ssh-fixture container and the Execution Environment
// container run on a shared, dedicated Docker bridge network so the EE
// container can reach the target directly by its real bridge IP - the
// exact same IP this test's own host-side SSH/target-mutate calls use,
// no DNS or hostname resolution needed on either side.
//
// The release lock's own blob signature and the Execution Environment
// image's own signature are BOTH verified for real here (a real cosign
// binary - see .github/workflows/test.yml's own cosign-installer step
// added alongside this test) - a real Sigstore/OIDC round trip, exactly
// like a real operator's own `hofctl apply` run would do. Nothing about
// verification is bypassed or stubbed in this file.
//
// GH_TOKEN must be set in the environment (see .github/workflows/
// test.yml) - `gh release download` needs it to reach the GitHub API.
//
// Assertions cover every one of PLATFORM-OPS-PLAN.md's own PR #33
// promises for real, not just some of them (a 2026-08-28 review found
// this file under-delivered on that promise at first): current.json is
// schema-validated against schemas/state-v1.schema.json, not just
// spot-checked field by field; topology.json's own full snapshot is
// read and sanity-checked; and a second real `hofctl apply` reusing the
// same approved bootstrap plan against the now-applied host is
// confirmed refused (reason: "stale-plan") - never re-applying a stale
// bootstrap approval against a host that has already moved on. Item 9
// (ADR 0005) removed the categorical "apply only supports a bootstrap
// plan" scope refusal this used to hit (an applied target is now a
// real, legitimate `hofctl apply` target of its own) - a bootstrap
// plan reused against an already-applied host is still refused, just
// because it's genuinely stale (the live recompute now correctly comes
// back mode: "applied", never matching the old bootstrap plan's own
// planId), not because applied targets are out of scope.
//
// Item 9's own real applied-mode acceptance - the actual "PR6" promise
// of ADR 0005's own delivery plan - continues in the SAME test, against
// the SAME already-bootstrapped target, once the bootstrap half above
// finishes: enable an optional persistent service, write a real marker
// into its own real volume, a genuine applied no-op, disable with
// dataRetention: retain, another no-op, re-enable, confirming the exact
// same marker/volume survive the whole round trip, real readiness, and
// every immutable per-generation snapshot the state role now writes
// (ansible/roles/state/tasks/main.yml, item 9's own new behavior baked
// into ee-v0.1.4 - see PR #53's real, independently-verified cut).

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

import { buildDockerRunArgs, buildExtraVars, buildInventory, computeExpectedCommittedState, runApply, withoutVolatileStateFields } from "../scripts/apply.mjs";
import { sha256 } from "../scripts/digest.mjs";
import { buildEvent, buildJournalDocument, buildLockDocument, currentOperator, newOperationId } from "../scripts/operation-journal.mjs";
import { runPlan } from "../scripts/plan-command.mjs";
import { HOF_NETWORK_NAME, SUPPLIED_TLS_CERTIFICATE_SECRET_NAME, SUPPLIED_TLS_PRIVATE_KEY_SECRET_NAME } from "../scripts/render-topology.mjs";
import { generateSecretValue } from "../scripts/secrets.mjs";
import {
  acquireExecutionLease, acquireLockAndJournal, appendEvent, pinnedKnownHosts,
  readCurrentState as readCurrentStateViaMutate, readGenerationSnapshot, readGenerationSnapshotReleaseLock, readGenerationSnapshotTopology, readTopology,
} from "../scripts/target-mutate.mjs";
import { loadAndValidateDeployment } from "../scripts/validate-deployment.mjs";

const RECOVERY_AGE_RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
// The real platform release this test downloads and applies - see
// releases/0.2.1.yml (reuses releases/0.2.0.yml's own app-component
// selections unchanged; only ansibleEnvironment moves to ee-v0.1.5,
// item 9's own five review rounds - PR #57 - baking in the process-
// lifetime execution lease, the Wachter startup-ordering fix, and every
// other real, independently-verified fix that PR's own five ADR 0005
// errata sections document). Verification PR: 0.2.0's own release-lock
// pinned the pre-PR-#57 composeTemplateDigest, which PR #57's own
// Wachter-ordering fix (a compose.services insertion-order change)
// broke - apply's own supply-chain check correctly refused to run this
// file's real acceptance against the stale release, exactly as
// intended; this bump is what re-pins it. `workflow_dispatch` signs
// with the DISPATCHING branch's own ref, never a tag (confirmed for
// real by inspecting the v0.1.1 release's own certificate -
// `@refs/heads/main`, not `@refs/tags/v0.1.1`), unlike
// execution-environment.yml's own tag-triggered identity below.
const RELEASE_VERSION = "0.2.1";
const RELEASE_LOCK_IDENTITY = "https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/heads/main";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = path.join(root, "test/fixtures/apply-acceptance");
const targetImageTag = "hof-ops-apply-acceptance-target:test";
const containerName = `hof-apply-acceptance-${randomUUID()}`;
const networkName = `hof-apply-acceptance-${randomUUID()}`;
// Item 9 review (findings 1-2): a LOCAL Execution Environment image
// built fresh from THIS working tree's own ansible/ (the exact same
// `docker build --file ansible/Dockerfile ansible` the "Execution
// Environment image builds" CI check already runs), used ONLY via
// apply.mjs's own executionEnvironmentImageOverride seam for the two
// scenarios below that specifically need the FIXED state role's real
// atomic-publish/retry behavior. This seam predates ee-v0.1.5 - at the
// time it was written, ee-v0.1.4 (the real, published image every other
// scenario in this file used) did not have that fix baked in yet (it's
// an Ansible role, baked in at image-build time, not a control-plane
// script). Verification PR (0.2.1/ee-v0.1.5): the real, published image
// now DOES have it too, since it's built from the exact same
// ansible/roles/state/tasks/main.yml this working tree's own local
// build reads - making this override strictly redundant for those two
// scenarios specifically. Left as-is here: removing it is a real
// simplification, but out of scope for this narrow release-version
// bump. Every other new scenario below (the execution lease, secret
// scoping, Wächter ordering) is entirely control-plane code (scripts/,
// never ansible/roles/) and needs no override at all - it runs against
// the real, published, signed image, same as the rest of this file.
const localEeImageTag = "hof-ops-apply-acceptance-local-ee:test";

let workDir;
let targetIp;
let userKeyPath;
let hostKeyFingerprint;
let servicesPath;
let releaseLockPath;
let suppliedTlsCertificatePath;
let suppliedTlsPrivateKeyPath;
let suppliedTlsCertificatePem;
let suppliedTlsPrivateKeyPem;

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

before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-apply-acceptance-"));

  // The real, published, real-Cosign-signed release lock for
  // RELEASE_VERSION - downloaded fresh, never checked into this repo
  // (release-lock.json is a build artifact of a real GitHub Release,
  // not source). `--clobber` because a retried CI attempt reuses the
  // same workDir naming pattern only per-process, but a stale local dev
  // run's own leftover file must never silently be trusted instead.
  await exec("gh", [
    "release", "download", `v${RELEASE_VERSION}`, "--repo", "vrubovoy/hof-ops",
    "--pattern", "release-lock.json*", "--dir", workDir, "--clobber",
  ]);
  releaseLockPath = path.join(workDir, "release-lock.json");

  // Built once, from THIS working tree's own ansible/ - see this file's
  // own top-level comment on localEeImageTag for why only two scenarios
  // below actually use it.
  await exec("docker", ["build", "--quiet", "--tag", localEeImageTag, "--file", path.join(root, "ansible/Dockerfile"), path.join(root, "ansible")], { timeout: 300_000 });

  await exec("docker", ["build", "--quiet", "--tag", targetImageTag, fixtureDir], { timeout: 180_000 });
  await exec("docker", ["network", "create", networkName]);

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
    // Dockerfile comment on why). A real, serious incident happened
    // during this PR's own LOCAL development: `--privileged
    // --cgroupns=host`, run on what turned out to be a real desktop (not
    // an isolated sandbox), gave a test container real host tty/cgroup
    // access and disrupted a real login session. The narrower,
    // non-privileged alternative tried afterward (--cap-add SYS_ADMIN,
    // no --privileged, no --cgroupns=host) is the documented way to run
    // systemd in Docker without full privilege - but it did not
    // actually work here: systemd itself exited silently (code 255,
    // no output even with --log-target=console --log-level=debug)
    // within ~100ms on this specific runner/kernel/Docker combination,
    // confirmed by CI, not guessed at. `--privileged` is used here
    // instead, deliberately scoped to ONLY this CI-run acceptance test
    // (pnpm test:apply-ssh, never run locally in this session again,
    // by the same standing decision the earlier incident produced) -
    // a GitHub Actions runner is a genuinely disposable, single-purpose
    // VM with nothing else on it a stray device/tty access could ever
    // disrupt, unlike a developer's own real desktop. --cgroupns=host
    // is still deliberately NOT added - --privileged alone is
    // sufficient and keeps this from being the exact flag combination
    // that caused the original incident.
    "--privileged",
    "--tmpfs", "/run", "--tmpfs", "/run/lock",
    "--volume", `${workDir}/host_key:/hof-keys/host_key:ro`,
    "--volume", `${workDir}/authorized_keys:/hof-keys/authorized_keys:ro`,
    targetImageTag,
  ]);
  const { stdout: ip } = await exec("docker", ["inspect", "--format", `{{(index .NetworkSettings.Networks "${networkName}").IPAddress}}`, containerName]);
  targetIp = ip.trim();
  await waitForSsh(targetIp, 30_000);

  const { stdout: fingerprintLine } = await exec("ssh-keygen", ["-l", "-E", "sha256", "-f", `${hostKeyPath}.pub`]);
  hostKeyFingerprint = fingerprintLine.trim().split(/\s+/)[1];

  // Mandatory core only (schlussel + schloss - every optional service
  // disabled), matching test/fixtures/topologies/core.yml's own shape -
  // see this file's own top comment for why. requiredSecrets() against
  // this manifest is empty, so no secrets store is needed at all.
  const manifest = YAML.parse(await readFile(path.join(root, "test/fixtures/topologies/core.yml"), "utf8"));
  manifest.target = { host: targetIp, user: "hofprobe", port: 22 };
  manifest.domains = { base: "example.com" };
  // render-topology.mjs asserts manifest.release === releaseLock.release
  // - the fixture's own placeholder ("1.0.0") must be replaced with the
  // real downloaded lock's own release, the same way
  // integration-matrix.mjs's own real runtime pass already does.
  manifest.release = JSON.parse(await readFile(releaseLockPath, "utf8")).release;

  // Real supplied TLS material - a genuine self-signed cert/key pair
  // (openssl, real X.509 content, real SAN covering exactly the
  // hostnames this manifest's own catalog serves), not acme-http01 -
  // exercises the real delivery path a 2026-08-28 review found
  // completely missing (the rendered Compose file bind-mounted a
  // WORKSTATION path directly into the target-side volume definition,
  // meaningless on the actual target - see render-topology.mjs's own
  // fixed-secret-path fix, and scripts/supplied-tls.mjs's own real
  // parse/key-match/validity/SAN validation).
  suppliedTlsCertificatePath = path.join(workDir, "tls-certificate.pem");
  suppliedTlsPrivateKeyPath = path.join(workDir, "tls-private-key.pem");
  await exec("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", suppliedTlsPrivateKeyPath, "-out", suppliedTlsCertificatePath,
    "-days", "1", "-subj", "/CN=example.com",
    "-addext", `subjectAltName=DNS:${manifest.domains.base},DNS:*.${manifest.domains.base}`,
  ]);
  suppliedTlsCertificatePem = await exec("cat", [suppliedTlsCertificatePath]).then((r) => r.stdout);
  suppliedTlsPrivateKeyPem = await exec("cat", [suppliedTlsPrivateKeyPath]).then((r) => r.stdout);
  manifest.tls = { mode: "supplied", certificatePath: suppliedTlsCertificatePath, privateKeyPath: suppliedTlsPrivateKeyPath };

  servicesPath = path.join(workDir, "services.yml");
  await writeFile(servicesPath, YAML.stringify(manifest));
});

after(async () => {
  await exec("docker", ["rm", "--force", containerName]).catch(() => {});
  await exec("docker", ["network", "rm", networkName]).catch(() => {});
  await exec("docker", ["rmi", "--force", targetImageTag]).catch(() => {});
  await exec("docker", ["rmi", "--force", localEeImageTag]).catch(() => {});
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

// apply.mjs's own sanitizeError() only ever keeps the last 8 lines of a
// failed operation's raw output (by design - never a raw dump into the
// journal/stdout event stream) - useful for a real operator, but it can
// hide the actually-useful failure detail (confirmed for real: an
// unrelated trailing interpreter-discovery warning pushed the real
// "fatal:" line out of that 8-line window during this test's own
// earlier development). Wraps the real dockerRun with the exact same
// argv/behavior, logging the complete, untruncated stdout/stderr of
// only a FAILED operation to this process's own stderr - never reaches
// apply.mjs's own journal/NDJSON stream.
function loggingDockerRun(command, args, options) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { maxBuffer: 8 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        console.error(`--- docker ${args.join(" ")} failed ---\nstdout:\n${stdout}\nstderr:\n${stderr}\n--- end ---`);
        reject(Object.assign(error, { stdout, stderr }));
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

function baseOptions() {
  return {
    manifestPath: servicesPath, releaseLockPath, releaseLockIdentity: RELEASE_LOCK_IDENTITY,
    hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 30,
    recoveryAgeRecipient: RECOVERY_AGE_RECIPIENT,
    dockerRun: loggingDockerRun,
    // No executionEnvironmentImageOverride, no verifyEeSignature stub -
    // the real, published Execution Environment image referenced by the
    // real release lock above, with its real Cosign signature genuinely
    // verified.
    //
    // The target only exists on this test's own private Docker bridge
    // network (never a published host port) - the Execution
    // Environment container must join that same network to reach it at
    // all (confirmed for real: Docker refuses inter-network traffic
    // between two separate bridge networks by default).
    executionEnvironmentDockerNetwork: networkName,
  };
}

// Item 9 (ADR 0005): the exact same runPlan() call every plan below this
// point makes - manifestPath/servicesPath is re-read fresh off disk each
// time (this file's own applied-lifecycle steps rewrite it in place
// between calls), so this always reflects whatever the manifest
// currently says, never a stale in-memory copy.
function planOptions() {
  return {
    manifestPath: servicesPath, releaseLockPath, releaseLockIdentity: RELEASE_LOCK_IDENTITY,
    hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 30,
  };
}

// A single, real, independent SSH round trip to the target - `docker
// exec` into the SAME real container this whole file already
// bootstraps, bypassing this codebase's own target-mutate.mjs/
// target-inspector.mjs transports entirely, so a real assertion here
// can never be fooled by a bug in either of those.
async function onTarget(...args) {
  const { stdout } = await exec("docker", ["exec", containerName, ...args]);
  return stdout;
}

async function readCurrentState() {
  return JSON.parse(await onTarget("cat", "/var/lib/hof/state/current.json"));
}

test("a real, full bootstrap apply against the real, published, signed v0.2.1 release, then a real applied-mode reconciliation lifecycle against the same target - every real role, start to finish, generation 1 through 4", async () => {
  // The real operator workflow, exercised for real: a genuine `hofctl
  // plan` run (real inspectTarget() over the real SSH transport this
  // whole fixture already sets up, real cosign verification of the
  // release lock's own blob signature) produces the exact plan-v2
  // document `hofctl apply` itself will be asked to approve - written to
  // a real file, exactly like `hofctl plan > plan.json` would.
  const { blocked, plan, diagnostics } = await runPlan({
    manifestPath: servicesPath, releaseLockPath, releaseLockIdentity: RELEASE_LOCK_IDENTITY,
    hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 30,
    recoveryAgeRecipient: RECOVERY_AGE_RECIPIENT,
  });
  assert.ok(!blocked, `hofctl plan itself was blocked: ${JSON.stringify(diagnostics)}`);
  assert.ok(plan.executable, `the real plan against mandatory core alone was not executable: ${JSON.stringify(plan.blockers)}`);
  const planPath = path.join(workDir, "plan.json");
  await writeFile(planPath, JSON.stringify(plan));

  const events = [];
  const result = await runApply({ ...baseOptions(), approvePlanId: plan.planId, planPath, emit: (event) => events.push(event) });

  assert.equal(result.blocked, false, `a real bootstrap against real mandatory-core images did not succeed: ${JSON.stringify(result)}`);
  assert.equal(result.committedGeneration, 1);
  assert.equal(result.planId, plan.planId);

  const operationEvents = events.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  const succeeded = operationEvents.filter((event) => event.phase === "succeeded").map((event) => event.step);
  const failed = operationEvents.filter((event) => event.phase === "failed");
  assert.equal(failed.length, 0, `every operation must succeed in a real, full bootstrap: ${JSON.stringify(failed)}`);

  // Every real phase actually ran, for real - not just the ones an
  // earlier, illustrative-lock version of this test could reach. Each
  // step id is `NNN.<action>` with no resource suffix when there is
  // only ever one instance in a bootstrap plan (host.prepare,
  // secret.ensure, config.write, state.commit) - `.endsWith` is exact
  // there - but `NNN.<action>.<resource...>` when plan.mjs emits one
  // per resource (database.migrate, volume.ensure, image.verify,
  // service.start, readiness.wait all included below via `.includes`,
  // never `.endsWith`, since a real resource name always follows).
  for (const suffix of [".host.prepare", ".secret.ensure", ".config.write", ".state.commit"]) {
    assert.ok(succeeded.some((step) => step.endsWith(suffix)), `${suffix} must have succeeded for real`);
  }
  assert.ok(succeeded.some((step) => step.includes(".database.migrate.")), "schlussel's own database.migrate must have succeeded for real");
  assert.ok(succeeded.some((step) => step.includes(".volume.ensure.")), "at least one volume.ensure succeeded for real");
  assert.ok(succeeded.some((step) => step.includes(".image.verify.") && step.includes("schlussel")), "schlussel's own image.verify (real cosign, real workflow identity) succeeded for real");
  assert.ok(succeeded.some((step) => step.includes(".service.start.")), "at least one service.start succeeded for real");
  assert.ok(succeeded.some((step) => step.includes(".readiness.wait.")), "at least one readiness.wait (real docker inspect polling, real Health.Status) succeeded for real");

  // The real, durable, on-target record - read directly, over a second,
  // independent real SSH connection (docker exec into the same
  // container, bypassing this module's own transport entirely) so this
  // assertion can't be fooled by a bug in target-mutate.mjs's own reader.
  const { stdout: journalRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.json`]);
  const journal = JSON.parse(journalRaw);
  // Schema-valid, not just spot-checked field by field - a further,
  // 2026-08-31 review found this test only ever parsed the live journal
  // and compared three of its fields, never actually validating it
  // against schemas/operation-journal-v1.schema.json the way current.json
  // already was below (PLATFORM-OPS-PLAN.md's own PR #33 promise, still
  // under-delivered here until this).
  const journalSchema = JSON.parse(await readFile(path.join(root, "schemas/operation-journal-v1.schema.json"), "utf8"));
  const journalAjv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(journalAjv);
  const validateJournal = journalAjv.compile(journalSchema);
  assert.ok(validateJournal(journal), `the live journal does not satisfy schemas/operation-journal-v1.schema.json: ${JSON.stringify(validateJournal.errors)}`);
  assert.equal(journal.status, "succeeded");
  assert.equal(journal.committedGeneration, 1);
  assert.equal(journal.approvedPlanId, plan.planId);

  const { stdout: eventsRaw } = await exec("docker", ["exec", containerName, "cat", `/var/lib/hof/state/journal/${result.operationId}.events.ndjson`]);
  const durableEvents = eventsRaw.trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(durableEvents, operationEvents, "the live NDJSON stream matches the durable journal exactly, event for event");
  // Independently schema-valid too, not just equal to what this run's
  // own emit() callback happened to produce - the same gap the journal
  // check just above closed, for every individual durable event.
  const eventSchema = JSON.parse(await readFile(path.join(root, "schemas/operation-event-v1.schema.json"), "utf8"));
  // strictRequired: false - operation-event-v1's own conditional
  // (allOf[0].then.required: ["error"]) requires a property declared in
  // the schema's OUTER properties block, not repeated locally in
  // `then` - the same pattern test/apply-contracts.test.mjs's own
  // validatorFor() already documents needing this for.
  const eventAjv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(eventAjv);
  const validateEvent = eventAjv.compile(eventSchema);
  for (const event of durableEvents) {
    assert.ok(validateEvent(event), `a durable event does not satisfy schemas/operation-event-v1.schema.json: ${JSON.stringify(validateEvent.errors)} (${JSON.stringify(event)})`);
  }

  // A real, schema-valid current.json genuinely landed on the target -
  // generation 1, this exact operation, this exact release. Validated
  // against the real schema, not just spot-checked field by field
  // (PLATFORM-OPS-PLAN.md's own PR #33 promise, under-delivered until a
  // 2026-08-28 review named it).
  const { stdout: currentRaw } = await exec("docker", ["exec", containerName, "cat", "/var/lib/hof/state/current.json"]);
  const current = JSON.parse(currentRaw);
  const stateSchema = JSON.parse(await readFile(path.join(root, "schemas/state-v1.schema.json"), "utf8"));
  const stateAjv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(stateAjv);
  const validateState = stateAjv.compile(stateSchema);
  assert.ok(validateState(current), `current.json does not satisfy schemas/state-v1.schema.json: ${JSON.stringify(validateState.errors)}`);
  assert.equal(current.generation, 1);
  assert.equal(current.lastSuccessfulOperationId, result.operationId);
  assert.equal(current.release, RELEASE_VERSION);
  assert.match(current.installationId, /^[0-9a-f-]{36}$/);

  // A real, full topology.json snapshot landed too - the entire
  // renderTopology() wrapper (compose/caddyfile/topology/backup), not
  // just the inner generated files config.write separately delivers
  // under the same filename for a different purpose (see state.mjs's
  // own assertRenderedShape comment on why those two are never
  // confused).
  const { stdout: topologyRaw } = await exec("docker", ["exec", containerName, "cat", "/var/lib/hof/state/topology.json"]);
  const topology = JSON.parse(topologyRaw);
  assert.ok(topology.compose && typeof topology.compose === "object", "topology.json must carry the full rendered compose object");
  assert.ok(topology.caddyfile && typeof topology.caddyfile === "string", "topology.json must carry the rendered Caddyfile");
  assert.ok(topology.compose.services.schlussel && topology.compose.services.schloss, "the real mandatory-core services must appear in the delivered topology");

  // The real supplied TLS certificate/private key genuinely landed on
  // the target too, byte-for-byte, root-owned, mode 0444. (A real gap a
  // 2026-08-28 review found - Compose's own file-based secrets are a
  // plain bind-mount, so 0400 root-owned is invisible to any non-root
  // consuming container, e.g. Wächter's own `USER node` agent - fixed
  // in ansible/roles/secret/tasks/main.yml (#39), delivered for real as
  // of ee-v0.1.2/v0.1.3 (#39's source change alone had zero effect on
  // the previously-pinned ee-v0.1.1 image, since roles/ is baked in at
  // image-build time). Safe specifically because the containing
  // directory, /etc/hof/secrets, stays root-only 0700 - checked below.
  const { stdout: deliveredCertificate } = await exec("docker", ["exec", containerName, "cat", "/etc/hof/secrets/hof.tls.certificate"]);
  assert.equal(deliveredCertificate, suppliedTlsCertificatePem);
  const { stdout: deliveredPrivateKey } = await exec("docker", ["exec", containerName, "cat", "/etc/hof/secrets/hof.tls.privateKey"]);
  assert.equal(deliveredPrivateKey, suppliedTlsPrivateKeyPem);
  const { stdout: tlsCertStat } = await exec("docker", ["exec", containerName, "stat", "--format", "%a %U", "/etc/hof/secrets/hof.tls.certificate"]);
  assert.equal(tlsCertStat.trim(), "444 root");
  const { stdout: tlsKeyStat } = await exec("docker", ["exec", containerName, "stat", "--format", "%a %U", "/etc/hof/secrets/hof.tls.privateKey"]);
  assert.equal(tlsKeyStat.trim(), "444 root");
  const { stdout: secretsDirStat } = await exec("docker", ["exec", containerName, "stat", "--format", "%a %U", "/etc/hof/secrets"]);
  assert.equal(secretsDirStat.trim(), "700 root");

  // Docker itself was genuinely installed by host.prepare, and the real
  // application containers are genuinely running under it - not just
  // reported as such.
  const { stdout: dockerVersion } = await exec("docker", ["exec", containerName, "docker", "--version"]);
  assert.match(dockerVersion, /Docker version/);
  const { stdout: psOutput } = await exec("docker", ["exec", containerName, "docker", "ps", "--format", "{{.Names}} {{.Status}}"]);
  assert.match(psOutput, /schlussel/);
  assert.match(psOutput, /schloss/);
  assert.match(psOutput, /gateway/);

  // The lock is released after a successful commit (ADR 0004) -
  // confirmed by a real, independent `test -e` on the target, not just
  // this module's own readLock().
  await assert.rejects(() => exec("docker", ["exec", containerName, "test", "-e", "/var/lib/hof/state/lock.json"]));

  // A second `hofctl plan` against this now-applied host sees a real
  // applied baseline, not a bootstrap one - the real, closed loop this
  // whole delivery item exists to prove: a genuine generation-1 commit
  // is genuinely observable afterward, not merely claimed.
  const secondPlan = await runPlan({
    manifestPath: servicesPath, releaseLockPath, releaseLockIdentity: RELEASE_LOCK_IDENTITY,
    hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 30,
  });
  assert.ok(!secondPlan.blocked, `the second plan against the now-applied host was blocked: ${JSON.stringify(secondPlan.diagnostics)}`);
  assert.equal(secondPlan.plan.mode, "applied");
  assert.equal(secondPlan.plan.baseline.installationId, current.installationId);
  assert.equal(secondPlan.plan.baseline.generation, 1);

  // A second real `hofctl apply` against the same, now-applied host -
  // reusing the exact same approved bootstrap plan/id the first,
  // successful run used - is correctly refused, never re-applying a
  // bootstrap plan against a host that already has one (PLATFORM-OPS-
  // PLAN.md's own PR #33 promise; under-delivered - only a second PLAN
  // was checked - until a 2026-08-28 review named it). Item 9 (ADR
  // 0005) generalized apply's own live recompute to cover an applied
  // target for real - a bootstrap-only "scope" refusal no longer
  // exists, but the OLD bootstrap plan is still refused, now correctly
  // as "stale-plan": the live recompute against this now-applied host
  // comes back mode: "applied", which can never match the old
  // bootstrap plan's own planId.
  const secondApply = await runApply({ ...baseOptions(), approvePlanId: plan.planId, planPath });
  assert.equal(secondApply.blocked, true, "a second bootstrap apply against an already-applied host must be refused");
  assert.equal(secondApply.reason, "stale-plan");

  // === Item 9 (ADR 0005): real applied-mode reconciliation, against
  // this SAME already-bootstrapped target - enable an optional
  // persistent service, write a real marker into its own real volume, a
  // genuine applied no-op, disable-with-retain (containers genuinely
  // gone, the volume and its marker genuinely survive), another no-op,
  // re-enable (the SAME volume reused, the SAME marker still there, no
  // migration, real readiness confirmed), generation progressing
  // 1 -> 2 -> 3 -> 4, every immutable per-generation snapshot confirmed
  // present and schema-valid on the target. Never run locally - see
  // this file's own top comment. ===================================

  // before()'s own `manifest` local is scoped there, not to this test()
  // callback - read fresh off the same real file it already wrote,
  // exactly like every other real caller of servicesPath does.
  const manifest = YAML.parse(await readFile(servicesPath, "utf8"));

  // Enable kuvert (an optional, persistent, database-owning service) -
  // a real, deliberate diff on top of the mandatory-core-only baseline
  // bootstrap above.
  manifest.services.kuvert.enabled = true;
  await writeFile(servicesPath, YAML.stringify(manifest));

  const enablePlan = await runPlan(planOptions());
  assert.ok(!enablePlan.blocked, `enabling kuvert was blocked: ${JSON.stringify(enablePlan.diagnostics)}`);
  assert.equal(enablePlan.plan.mode, "applied");
  assert.ok(enablePlan.plan.summary.create > 0, "enabling kuvert must create real units");
  const enablePlanPath = path.join(workDir, "plan-enable-kuvert.json");
  await writeFile(enablePlanPath, JSON.stringify(enablePlan.plan));
  const enableResult = await runApply({ ...baseOptions(), approvePlanId: enablePlan.plan.planId, planPath: enablePlanPath });
  assert.equal(enableResult.blocked, false, `enabling kuvert failed: ${JSON.stringify(enableResult)}`);
  assert.equal(enableResult.committedGeneration, 2, "generation 1 -> 2");

  const psAfterEnable = await onTarget("docker", "ps", "--format", "{{.Names}}");
  assert.match(psAfterEnable, /kuvert-backend/);
  assert.match(psAfterEnable, /kuvert-frontend/);

  // A real marker, written directly into kuvert's own real Docker
  // volume via a throwaway container on the target - the literal volume
  // name (render-topology.mjs pins compose.volumes[...].name to the
  // catalog's own raw name, never Compose's own project-prefixed
  // default), never anything routed through the application itself.
  const markerContent = `hof-item9-acceptance-${randomUUID()}`;
  await onTarget("docker", "run", "--rm", "--volume", "kuvert-data:/hof-marker-check", "alpine", "sh", "-c", `echo -n '${markerContent}' > /hof-marker-check/.hof-acceptance-marker`);
  const readMarker = () => onTarget("docker", "run", "--rm", "--volume", "kuvert-data:/hof-marker-check", "alpine", "cat", "/hof-marker-check/.hof-acceptance-marker");
  assert.equal(await readMarker(), markerContent, "fixture assumption: the marker was actually written");

  // A genuine applied no-op - unchanged manifest, must take no lock,
  // create no journal, never bump generation.
  const noOpPlan1 = await runPlan(planOptions());
  assert.ok(!noOpPlan1.blocked, JSON.stringify(noOpPlan1.diagnostics));
  assert.deepEqual(noOpPlan1.plan.operations, [], "fixture assumption: an unchanged manifest against its own just-committed baseline is a genuine no-op");
  const noOpPlanPath1 = path.join(workDir, "plan-noop-1.json");
  await writeFile(noOpPlanPath1, JSON.stringify(noOpPlan1.plan));
  const noOpResult1 = await runApply({ ...baseOptions(), approvePlanId: noOpPlan1.plan.planId, planPath: noOpPlanPath1 });
  assert.equal(noOpResult1.blocked, false, JSON.stringify(noOpResult1));
  assert.equal(noOpResult1.noOp, true);
  assert.equal(noOpResult1.committedGeneration, 2, "a no-op never bumps generation");
  assert.equal(noOpResult1.operationId, undefined, "no lock/journal was ever created for a no-op");
  assert.equal((await readCurrentState()).generation, 2, "current.json's own generation, read fresh, genuinely never moved");

  // Disable kuvert WITH retain - containers gone for real, the volume
  // and its real marker survive, generation 2 -> 3.
  manifest.services.kuvert.enabled = false;
  manifest.services.kuvert.dataRetention = "retain";
  await writeFile(servicesPath, YAML.stringify(manifest));
  const disablePlan = await runPlan(planOptions());
  assert.ok(!disablePlan.blocked, JSON.stringify(disablePlan.diagnostics));
  assert.equal(disablePlan.plan.summary.remove, 2, "kuvert-backend + kuvert-frontend");
  assert.ok(!disablePlan.plan.operations.some((o) => o.action === "backup.create"), "item 9 never backs anything up on removal - it isn't even in the applied whitelist");
  const disablePlanPath = path.join(workDir, "plan-disable-kuvert.json");
  await writeFile(disablePlanPath, JSON.stringify(disablePlan.plan));
  const disableResult = await runApply({ ...baseOptions(), approvePlanId: disablePlan.plan.planId, planPath: disablePlanPath });
  assert.equal(disableResult.blocked, false, `disabling kuvert with retain failed: ${JSON.stringify(disableResult)}`);
  assert.equal(disableResult.committedGeneration, 3, "generation 2 -> 3");

  const psAfterDisable = await onTarget("docker", "ps", "-a", "--format", "{{.Names}}");
  assert.doesNotMatch(psAfterDisable, /kuvert-backend/, "kuvert's own containers are genuinely gone, not just stopped");
  assert.doesNotMatch(psAfterDisable, /kuvert-frontend/, "kuvert's own containers are genuinely gone, not just stopped");
  const volumesAfterDisable = await onTarget("docker", "volume", "ls", "--format", "{{.Name}}");
  assert.match(volumesAfterDisable, /^kuvert-data$/m, "the volume itself genuinely survives a retain-disable");
  assert.equal(await readMarker(), markerContent, "the real data inside the retained volume survives, byte for byte");

  const currentAfterDisable = await readCurrentState();
  assert.ok(currentAfterDisable.retainedServices?.kuvert, "current.json genuinely records kuvert as retained");
  assert.equal(currentAfterDisable.retainedServices.kuvert.volume, "kuvert-data");

  // Another no-op - already disabled+retained, manifest unchanged.
  const noOpPlan2 = await runPlan(planOptions());
  assert.ok(!noOpPlan2.blocked, JSON.stringify(noOpPlan2.diagnostics));
  assert.deepEqual(noOpPlan2.plan.operations, [], "fixture assumption: re-planning an already-retained-disable is a genuine no-op");
  const noOpPlanPath2 = path.join(workDir, "plan-noop-2.json");
  await writeFile(noOpPlanPath2, JSON.stringify(noOpPlan2.plan));
  const noOpResult2 = await runApply({ ...baseOptions(), approvePlanId: noOpPlan2.plan.planId, planPath: noOpPlanPath2 });
  assert.equal(noOpResult2.blocked, false, JSON.stringify(noOpResult2));
  assert.equal(noOpResult2.noOp, true);
  assert.equal(noOpResult2.committedGeneration, 3, "still 3 - a repeated no-op never bumps generation");

  // Re-enable - the SAME retained volume and marker, no migration, real
  // readiness, generation 3 -> 4.
  manifest.services.kuvert.enabled = true;
  await writeFile(servicesPath, YAML.stringify(manifest));
  const reenablePlan = await runPlan(planOptions());
  assert.ok(!reenablePlan.blocked, JSON.stringify(reenablePlan.diagnostics));
  assert.equal(reenablePlan.plan.summary.migrate, 0, "the retained schema already matches - no migration needed");
  assert.ok(!reenablePlan.plan.operations.some((o) => o.action === "volume.ensure" && o.resource === "kuvert-data"), "the retained volume is reused, never recreated");
  const reenablePlanPath = path.join(workDir, "plan-reenable-kuvert.json");
  await writeFile(reenablePlanPath, JSON.stringify(reenablePlan.plan));
  const reenableEvents = [];
  const reenableResult = await runApply({ ...baseOptions(), approvePlanId: reenablePlan.plan.planId, planPath: reenablePlanPath, emit: (event) => reenableEvents.push(event) });
  assert.equal(reenableResult.blocked, false, `re-enabling kuvert failed: ${JSON.stringify(reenableResult)}`);
  assert.equal(reenableResult.committedGeneration, 4, "generation 3 -> 4");

  const reenableOperationEvents = reenableEvents.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  const reenableSucceeded = reenableOperationEvents.filter((event) => event.phase === "succeeded").map((event) => event.step);
  assert.ok(!reenableSucceeded.some((step) => step.includes(".database.migrate.")), "no migration ran for real on a retained re-enable at the already-current schema");
  assert.ok(reenableSucceeded.some((step) => step.includes(".readiness.wait.") && step.includes("kuvert")), "kuvert's own readiness (real docker inspect polling) was actually confirmed for real");

  assert.equal(await readMarker(), markerContent, "the exact same real data survives a full disable-with-retain -> re-enable round trip");
  const psAfterReenable = await onTarget("docker", "ps", "--format", "{{.Names}}");
  assert.match(psAfterReenable, /kuvert-backend/);
  assert.match(psAfterReenable, /kuvert-frontend/);

  const currentAfterReenable = await readCurrentState();
  assert.equal(currentAfterReenable.generation, 4);
  assert.equal(currentAfterReenable.retainedServices?.kuvert, undefined, "no longer retained once re-enabled");

  // Every immutable per-generation snapshot genuinely exists on the
  // target, for every real generation this test committed - written
  // BEFORE the two mutable pointer files, per the state role's own
  // ordering (see ansible/roles/state/tasks/main.yml).
  for (const generation of [1, 2, 3, 4]) {
    const padded = String(generation).padStart(6, "0");
    const snapshot = JSON.parse(await onTarget("cat", `/var/lib/hof/state/generations/${padded}/state.json`));
    assert.ok(validateState(snapshot), `generation ${generation}'s own immutable snapshot does not satisfy schemas/state-v1.schema.json: ${JSON.stringify(validateState.errors)}`);
    assert.equal(snapshot.generation, generation);
    JSON.parse(await onTarget("cat", `/var/lib/hof/state/generations/${padded}/topology.json`)); // must at least parse
    JSON.parse(await onTarget("cat", `/var/lib/hof/state/generations/${padded}/release-lock.json`)); // must at least parse
  }
});

// ===========================================================================
// Item 9 review (2026-09-01): real acceptance coverage for the review's own
// Required Gate, continuing reconciliation against the SAME already-
// bootstrapped target the test above leaves at generation 4 (kuvert
// enabled, unlocked) - never a fresh target, matching this whole file's
// own established "one real target, one continuous real lifecycle"
// convention. Each test below assumes the ones before it (in file order,
// node:test's own default) already ran and left the target in the state
// its own comment describes.
// ===========================================================================

// A minimal `run` matching target-mutate.mjs's own (unexported) default -
// only ever needed here to satisfy pinnedKnownHosts()'s own required `run`
// parameter, exactly the way apply.mjs's own real CLI path does it
// (defaultExecFile there, never surfaced to a caller).
function defaultRun(command, args, { input, timeout } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 8 * 1024 * 1024, timeout }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

function mutateConn() {
  return { mode: "ssh", host: targetIp, port: 22, user: "hofprobe", hostKeySha256: hostKeyFingerprint, identityFile: userKeyPath, connectTimeoutSeconds: 30, run: defaultRun };
}

// Everything computeExpectedCommittedState()/buildJournalDocument() need
// that isn't already carried by a real plan-v2 document itself - read
// fresh off the same real files this whole file's own runPlan()/runApply()
// calls already use, exactly the way apply.mjs's own real CLI path reads
// them (loadAndValidateDeploymentWithBytes there) - so this can never
// silently drift from what a real apply run would itself compute.
async function loadRealDeploymentInputs() {
  const { manifest, catalog, catalogBytes, releaseLock: lock, releaseLockBytes, servicesBytes, composeTemplateBytes, servicesSchema, catalogSchema, releaseLockSchema } =
    await loadAndValidateDeployment({ servicesPath, releaseLockPath, releaseLockIdentity: RELEASE_LOCK_IDENTITY, skipSignature: false });
  const inputDigests = {
    manifestDigest: sha256(servicesBytes),
    releaseLockDigest: sha256(releaseLockBytes),
    catalogDigest: sha256(catalogBytes),
    composeTemplateDigest: sha256(composeTemplateBytes),
    executionEnvironmentDigest: lock.ansibleEnvironment.image.slice(lock.ansibleEnvironment.image.indexOf("@") + 1),
  };
  return { manifest, catalog, releaseLock: lock, servicesSchema, catalogSchema, releaseLockSchema, inputDigests };
}

// Directly dispatches ONE real state.commit - never through the full
// runApply() orchestration, so a test can dispatch it a second time
// against an ALREADY-committed generation (the real retry apply.mjs's
// own resume path would otherwise take, exercised here directly and
// synchronously instead) or against a deliberately-incomplete on-target
// snapshot directory, and see its real, raw exit/output either way.
//
// Item 9 SECOND review fix (finding 11): builds the extra-vars AND the
// docker run argv via apply.mjs's own real, EXPORTED buildExtraVars()/
// buildDockerRunArgs() - the exact same two functions a real
// dispatchOperation() call uses internally - rather than reconstructing
// either by hand a second time. That hand-built version had already,
// silently, drifted from production in a real way this extraction now
// makes structurally impossible: `stepId` here is a plan-v2 STEP id
// shape ("999.state.commit", matching plan.mjs's own real `NNN.<action>`
// convention for a state.commit operation) - never the whole apply RUN's
// own UUID, which the state role's own staging-directory name embeds via
// hof_operation_id and which the hand-built version had been passing
// instead.
async function dispatchStateRoleForReal({ image, stepId, generation, stateDir }) {
  const { file: knownHostsFile, cleanup } = await pinnedKnownHosts({ host: targetIp, port: 22, hostKeySha256: hostKeyFingerprint, connectTimeoutSeconds: 30, run: defaultRun });
  try {
    const inventoryFile = path.join(workDir, `inventory-${randomUUID()}.ini`);
    await writeFile(inventoryFile, buildInventory({ host: targetIp, port: 22, user: "hofprobe", connectTimeoutSeconds: 30 }), { mode: 0o600 });
    const operation = { id: stepId, phase: "state", action: "state.commit", resource: "state/current.json", reason: "test/apply-acceptance.mjs's own direct real dispatch" };
    const extraVars = buildExtraVars(operation, { commitGeneration: generation });
    const context = {
      image, identityFile: userKeyPath, knownHostsFile, inventoryFile, stateDir, dockerNetwork: networkName,
    };
    const args = buildDockerRunArgs(operation, extraVars, context);
    return await exec("docker", args, { timeout: 60_000 });
  } finally {
    await cleanup();
  }
}

// Written under workDir (never a separate OS-level temp dir) so
// after()'s own single `rm(workDir, ...)` cleans these up too, exactly
// like every other scratch file this whole test already creates.
async function writeStateDir({ current, topology, releaseLock: lock }) {
  const dir = path.join(workDir, `state-${randomUUID()}`);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "current.json"), JSON.stringify(current));
  await writeFile(path.join(dir, "topology.json"), JSON.stringify(topology));
  await writeFile(path.join(dir, "release-lock.json"), JSON.stringify(lock));
  return dir;
}

test("an applied change delivers ONLY the secrets its own scoped set names (never an unrelated required secret), and Wächter's agent unit starts and becomes ready before its API unit (item 9 review, findings 4 and 6)", async () => {
  // Enables herold AND wachter together - herold-credential-encryption-key
  // and wachter-agent-token are both newly required. A real,
  // deterministically-generated value for each (scripts/secrets.mjs's own
  // real generateSecretValue(), never test noise) is handed in via the
  // documented readSecretsStore testing seam (apply.mjs's own comment:
  // "the real CLI never passes them") - this is the one, official,
  // real-SOPS-bypassing seam apply.mjs exposes; SOPS/age's own real
  // encrypt/decrypt round trip is already covered elsewhere
  // (test/secrets.test.mjs, test/hofctl-secrets-cli.test.mjs), not this
  // file's own concern (which is apply's own delivery-scoping logic).
  const heroldSecretName = "herold-credential-encryption-key";
  const wachterSecretName = "wachter-agent-token";
  const heroldValue = generateSecretValue("token");
  const wachterValue = generateSecretValue("token");

  // Item 9 review (network lifecycle finding): kuvert is already
  // enabled and running here (the bootstrap+lifecycle test above this
  // one leaves it that way - see this section's own top comment), and
  // completely unrelated to herold/wachter - this real target is
  // exactly the scenario that found the bug in the first place:
  // enabling herold's own database.migrate used to trip Compose into
  // trying to remove-then-recreate the "hof" network mid-apply, which
  // Docker correctly refused because kuvert's own containers were still
  // attached to it. Captured here, before the apply below, and compared
  // again after it: kuvert's own containers and the network itself must
  // be the exact same real Docker objects throughout - untouched,
  // unrestarted, never recreated - by an apply that never had any
  // reason to touch either.
  const kuvertContainerIdsBefore = await Promise.all(
    ["kuvert-backend", "kuvert-frontend"].map((name) => onTarget("docker", "inspect", "--format", "{{.Id}}", name)),
  );
  const hofNetworkIdBefore = await onTarget("docker", "network", "inspect", "--format", "{{.Id}}", HOF_NETWORK_NAME);

  const manifest = YAML.parse(await readFile(servicesPath, "utf8"));
  manifest.services.herold.enabled = true;
  manifest.services.wachter.enabled = true;
  await writeFile(servicesPath, YAML.stringify(manifest));

  const enablePlan = await runPlan(planOptions());
  assert.ok(!enablePlan.blocked, JSON.stringify(enablePlan.diagnostics));
  const secretEnsureOp = enablePlan.plan.operations.find((o) => o.action === "secret.ensure");
  assert.ok(secretEnsureOp, "fixture assumption: enabling two secret-consuming services emits secret.ensure");
  assert.deepEqual([...secretEnsureOp.secrets].sort(), [heroldSecretName, wachterSecretName].sort());

  let deliveredSecrets;
  const events = [];
  const planPath = path.join(workDir, "plan-enable-herold-wachter.json");
  await writeFile(planPath, JSON.stringify(enablePlan.plan));
  const result = await runApply({
    ...baseOptions(), approvePlanId: enablePlan.plan.planId, planPath, emit: (event) => events.push(event),
    // Item 9 SECOND review fix (finding 2): secretsStorePath itself is
    // required by apply.mjs's own eager "was a store even given at all"
    // gate BEFORE it ever calls readSecretsStore - without it this run
    // was refused with reason "secrets" before ever reaching the
    // interesting part of this scenario. Never actually read (the seam
    // below bypasses that), but its mere presence is what the gate
    // checks.
    secretsStorePath: "/dev/null",
    readSecretsStore: async () => ({ [heroldSecretName]: heroldValue, [wachterSecretName]: wachterValue }),
    dockerRun: async (command, args, options) => {
      const mountArg = args.find((a) => a.endsWith(":/hof/secrets.json:ro"));
      if (mountArg) deliveredSecrets = JSON.parse(await readFile(mountArg.slice(0, -":/hof/secrets.json:ro".length), "utf8"));
      return loggingDockerRun(command, args, options);
    },
  });
  assert.equal(result.blocked, false, `enabling herold+wachter failed: ${JSON.stringify(result)}`);

  // Item 9 SECOND review fix (finding 5): this fixture uses supplied TLS
  // (see before()'s own manifest.tls.mode = "supplied") - apply.mjs
  // ALWAYS folds the two fixed supplied-TLS secret names into whatever
  // secret.ensure delivers, on top of (never instead of) the plan's own
  // scoped list, since the gateway consuming them is (re)started by any
  // plan that delivers them at all (see apply.mjs's own delivery code,
  // right after computing suppliedTlsForDelivery). The PLAN's own scoped
  // list (secretEnsureOp.secrets, asserted above) correctly stays just
  // [herold, wachter] - TLS names are never part of THAT scoping - but
  // the DELIVERED file also carries the two TLS names on top.
  assert.deepEqual(
    Object.keys(deliveredSecrets).sort(),
    [heroldSecretName, wachterSecretName, SUPPLIED_TLS_CERTIFICATE_SECRET_NAME, SUPPLIED_TLS_PRIVATE_KEY_SECRET_NAME].sort(),
    "delivered: the plan's own scoped secrets, PLUS the two fixed supplied-TLS names always carried alongside them - nothing else",
  );
  const { stdout: deliveredHerold } = await exec("docker", ["exec", containerName, "cat", `/etc/hof/secrets/${heroldSecretName}`]);
  assert.equal(deliveredHerold, heroldValue);
  const { stdout: deliveredWachter } = await exec("docker", ["exec", containerName, "cat", `/etc/hof/secrets/${wachterSecretName}`]);
  assert.equal(deliveredWachter, wachterValue);
  const { stdout: heroldStat } = await exec("docker", ["exec", containerName, "stat", "--format", "%a %U", `/etc/hof/secrets/${heroldSecretName}`]);
  assert.equal(heroldStat.trim(), "444 root");

  // Item 9 review fix (finding 4): wachter-agent's own service.start AND
  // readiness.wait must both resolve, for real, BEFORE wachter's own
  // service.start is even dispatched - with the OLD ordering this exact
  // scenario used to hang readiness.wait's full retry budget and then
  // fail outright (the API's own /ready needs the agent already up).
  const operationEvents = events.filter((event) => event.apiVersion === "hof.dev/operation-event/v1");
  const failed = operationEvents.filter((event) => event.phase === "failed");
  assert.equal(failed.length, 0, `every operation must succeed: ${JSON.stringify(failed)}`);
  const agentReadySucceeded = operationEvents.find((event) => event.step.includes(".readiness.wait.") && event.step.includes("wachter-agent") && event.phase === "succeeded");
  const apiStartStarted = operationEvents.find((event) => event.step.includes(".service.start.") && event.step.endsWith(".wachter") && event.phase === "started");
  assert.ok(agentReadySucceeded && apiStartStarted, "fixture assumption: both events exist in a successful enable");
  assert.ok(new Date(agentReadySucceeded.at).getTime() <= new Date(apiStartStarted.at).getTime(), "the agent must be confirmed ready before the API unit is even started");

  // Item 9 SECOND review fix (finding 10): exact container names, not a
  // substring/word-boundary regex - /wachter\b/ also matches inside
  // "wachter-agent" (the boundary lands on the hyphen), so it could
  // never actually distinguish "the API's own container exists" from
  // "only the agent's does". The real ordering proof is the event-
  // timestamp assertion above; this is just a liveness confirmation, now
  // an exact one.
  const namesAfter = (await onTarget("docker", "ps", "--format", "{{.Names}}")).split("\n").map((name) => name.trim()).filter(Boolean);
  // herold-backend/herold-frontend - catalog/services-v1.yaml's own two
  // artifacts for herold, not a single "herold" unit.
  for (const expected of ["wachter-agent", "wachter", "herold-backend", "herold-frontend"]) {
    assert.ok(namesAfter.includes(expected), `expected an exact container named "${expected}" among ${JSON.stringify(namesAfter)}`);
  }
  // kuvert must never have restarted (this apply had no reason to touch
  // it at all - see this test's own comment on the network-race bug
  // this pins), and the "hof" network itself must never have been
  // recreated. If either drops, some future regression is doing exactly
  // what the network-lifecycle bug used to do: treating this stable,
  // unrelated infrastructure as if a completely different operation
  // owned it.
  for (const name of ["kuvert-backend", "kuvert-frontend"]) {
    assert.ok(namesAfter.includes(name), `kuvert's own ${name} must still be running - this apply never had any reason to touch it`);
  }
  const kuvertContainerIdsAfter = await Promise.all(
    ["kuvert-backend", "kuvert-frontend"].map((name) => onTarget("docker", "inspect", "--format", "{{.Id}}", name)),
  );
  assert.deepEqual(kuvertContainerIdsAfter, kuvertContainerIdsBefore, "kuvert's own containers are the exact same real Docker objects - never restarted or recreated by enabling herold/wachter");
  const hofNetworkIdAfter = await onTarget("docker", "network", "inspect", "--format", "{{.Id}}", HOF_NETWORK_NAME);
  assert.equal(hofNetworkIdAfter, hofNetworkIdBefore, "the \"hof\" network is the exact same real Docker object - Compose never recreated it (item 9 review, network lifecycle finding)");

  // A FURTHER, unrelated applied change (another config-only backup
  // edit, touching no secret-consuming unit) must NEVER re-deliver
  // herold's own secret, even when the store now holds a DIFFERENT
  // (simulating a workstation-side rotation) value for it.
  const rotatedHeroldValue = generateSecretValue("token");
  const manifestAfter = YAML.parse(await readFile(servicesPath, "utf8"));
  manifestAfter.backup.schedule = "05:15";
  await writeFile(servicesPath, YAML.stringify(manifestAfter));
  const unrelatedPlan = await runPlan(planOptions());
  assert.ok(!unrelatedPlan.blocked, JSON.stringify(unrelatedPlan.diagnostics));
  const unrelatedSecretOp = unrelatedPlan.plan.operations.find((o) => o.action === "secret.ensure");
  assert.deepEqual(unrelatedSecretOp?.secrets ?? [], [], "a change touching no secret-consuming unit delivers no secret at all");
  const unrelatedPlanPath = path.join(workDir, "plan-unrelated-backup.json");
  await writeFile(unrelatedPlanPath, JSON.stringify(unrelatedPlan.plan));
  const unrelatedResult = await runApply({
    ...baseOptions(), approvePlanId: unrelatedPlan.plan.planId, planPath: unrelatedPlanPath,
    secretsStorePath: "/dev/null",
    readSecretsStore: async () => ({ [heroldSecretName]: rotatedHeroldValue, [wachterSecretName]: wachterValue }),
  });
  assert.equal(unrelatedResult.blocked, false, JSON.stringify(unrelatedResult));
  const { stdout: heroldAfterUnrelated } = await exec("docker", ["exec", containerName, "cat", `/etc/hof/secrets/${heroldSecretName}`]);
  assert.equal(heroldAfterUnrelated, heroldValue, "herold's own secret file is byte-identical to what was delivered before - the rotated value was never written");
});

// Item 9 SECOND review fix (finding 9): named and scoped honestly now -
// this exercises RETRY-safety (a repeat, identical-content dispatch),
// an INCOMPLETE-directory refusal, and ORPHAN-STAGING-directory cleanup,
// all via directly reproduced ON-DISK STATES a crash could leave behind
// (never a literal process kill mid-flight - see this whole section's
// own top comment on why: a timing-based kill race is exactly what the
// live, hands-on validation that redesigned target-mutate.mjs's own
// execution lease this review round found genuinely unreliable to
// script, even locally). It does NOT prove interruption strictly
// between two specific role tasks (the staging-copy loop and the atomic
// rename) - the orphan-staging case below is the closest real proxy for
// that: a staging directory left behind by an attempt that got exactly
// that far and no further.
test("crash/retry of the atomic generation-snapshot publish is real and safe: a repeat, identical-content dispatch is idempotent; an incomplete existing snapshot directory is refused; an orphan staging directory from an interrupted publish is cleaned up and superseded (item 9 review, finding 1)", async () => {
  const { status: liveStatus, current: liveCurrent } = await readCurrentStateViaMutate(mutateConn());
  assert.equal(liveStatus, "present", "fixture assumption: the target already has a committed generation from the tests above");
  const generation = liveCurrent.generation;

  // Re-read the SAME generation's own real, already-published snapshot
  // (its own real, already-produced content - never hand-built) and
  // dispatch state.commit a SECOND time for it, via the FIXED local EE
  // image - directly targets the concrete bug this finding fixed: the
  // old role compared an existing snapshot with a controller-side
  // lookup('file') of a path that only exists on the TARGET, crashing
  // every retry outright.
  const { snapshot: existingState } = await readGenerationSnapshot(mutateConn(), generation);
  const { topology: existingTopology } = await readGenerationSnapshotTopology(mutateConn(), generation);
  const { releaseLock: existingReleaseLock } = await readGenerationSnapshotReleaseLock(mutateConn(), generation);
  const retryStateDir = await writeStateDir({ current: existingState, topology: existingTopology, releaseLock: existingReleaseLock });
  await dispatchStateRoleForReal({ image: localEeImageTag, stepId: "999.state.commit", generation, stateDir: retryStateDir });
  // No throw above means the retry genuinely succeeded (a real
  // ansible-playbook run failure would reject with a real, non-zero
  // exit). Independently re-confirm nothing on the target actually
  // changed - a true no-op retry, not a silent overwrite.
  const { snapshot: afterRetry } = await readGenerationSnapshot(mutateConn(), generation);
  assert.deepEqual(withoutVolatileStateFields(afterRetry), withoutVolatileStateFields(existingState));

  // A genuinely NEW, never-before-used generation number whose own
  // snapshot directory is deliberately INCOMPLETE (only state.json)
  // must be refused outright, never silently "completed" by a later
  // dispatch. Item 9 SECOND review fix (finding 4): the mounted
  // current.json fed to THIS dispatch must itself claim
  // hof_state_generation's own value (poisonedGeneration) - the role's
  // very FIRST task cross-checks the mounted current.json's own
  // generation against hof_state_generation before it ever reaches the
  // incomplete-directory check, so reusing the real generation's own
  // current.json unmodified (as this test originally did) tripped THAT
  // earlier assertion instead, never actually reaching the one this
  // test means to exercise.
  const poisonedGeneration = generation + 100; // definitely never legitimately committed
  const poisonedDir = `/var/lib/hof/state/generations/${String(poisonedGeneration).padStart(6, "0")}`;
  await onTarget("mkdir", "-p", poisonedDir);
  await onTarget("sh", "-c", `cat > '${poisonedDir}/state.json' <<'JSON'\n${JSON.stringify(existingState)}\nJSON`);
  const poisonedCurrent = { ...existingState, generation: poisonedGeneration };
  const poisonStateDir = await writeStateDir({ current: poisonedCurrent, topology: existingTopology, releaseLock: existingReleaseLock });
  // ansible-playbook's own human-readable task failure output (including
  // a failed assert's fail_msg) goes to stdout, not stderr - checked
  // directly here rather than via assert.rejects' own message match
  // (which only ever looks at the rejected Error's own .message, built
  // from stderr - see node:child_process's own execFile error shape).
  let poisonError;
  try {
    await dispatchStateRoleForReal({ image: localEeImageTag, stepId: "999.state.commit", generation: poisonedGeneration, stateDir: poisonStateDir });
  } catch (error) {
    poisonError = error;
  }
  assert.ok(poisonError, "an incomplete existing generation directory must be refused, not silently completed");
  assert.match(poisonError.stdout ?? "", /is incomplete/);
  await onTarget("rm", "-rf", poisonedDir);

  // Item 9 SECOND review fix (finding 9): an ORPHAN STAGING directory -
  // exactly what a crash strictly between the staging-copy loop and the
  // atomic `mv -T` rename leaves behind (see ansible/roles/state/tasks/
  // main.yml's own "Remove any orphan staging directory left by a
  // crashed earlier attempt" task) - for a DIFFERENT never-legitimately-
  // committed generation, so the final generations/NNNNNN/ directory
  // does not exist yet. A real, later dispatch for that same generation
  // must remove the orphan and publish its own complete, correct
  // snapshot in its place, never trip on - or silently reuse bytes from
  // - the leftover.
  const crashedGeneration = generation + 200;
  const crashedStepId = "999.state.commit";
  // The staging directory's own name embeds hof_operation_id VERBATIM
  // (ansible/roles/state/tasks/main.yml's own Jinja) - matching it here
  // to the exact SAME stepId this dispatch below will itself send is
  // what makes this a real "the SAME retried operation's own leftover",
  // not an unrelated stale directory that happens to share a generation.
  const orphanStagingDir = `/var/lib/hof/state/generations/.staging-${crashedStepId}-${String(crashedGeneration).padStart(6, "0")}`;
  await onTarget("mkdir", "-p", orphanStagingDir);
  await onTarget("sh", "-c", `printf 'not a real snapshot file - an orphan from an interrupted publish' > '${orphanStagingDir}/state.json'`);
  const crashedCurrent = { ...existingState, generation: crashedGeneration };
  const crashedStateDir = await writeStateDir({ current: crashedCurrent, topology: existingTopology, releaseLock: existingReleaseLock });
  await dispatchStateRoleForReal({ image: localEeImageTag, stepId: crashedStepId, generation: crashedGeneration, stateDir: crashedStateDir });
  await assert.rejects(() => exec("docker", ["exec", containerName, "test", "-e", orphanStagingDir]), "the orphan staging directory is removed, never left behind or reused");
  const { status: crashedSnapshotStatus, snapshot: crashedSnapshot } = await readGenerationSnapshot(mutateConn(), crashedGeneration);
  assert.equal(crashedSnapshotStatus, "present");
  assert.deepEqual(withoutVolatileStateFields(crashedSnapshot), withoutVolatileStateFields(crashedCurrent));
  await onTarget("rm", "-rf", `/var/lib/hof/state/generations/${String(crashedGeneration).padStart(6, "0")}`);
});

test("a concurrent --resume is refused by the real execution lease while the operation is still in flight; once free, resume finishes a commit interrupted between the immutable generation snapshot and its two mutable pointer files - real target, real Ansible role, real re-dispatch (item 9 review, findings 2 and 3)", async () => {
  // The real, already-committed baseline this scenario builds forward
  // from.
  const { current: baselineCurrent } = await readCurrentStateViaMutate(mutateConn());
  const baselineGeneration = baselineCurrent.generation;

  // A real, legitimate next change - one more config-only backup edit,
  // kept deliberately small (no unit restart) so this scenario's own
  // operations list is short and its own real state.commit dispatch
  // below is the only thing this test cares about timing precisely.
  const manifest2 = YAML.parse(await readFile(servicesPath, "utf8"));
  manifest2.backup.schedule = "06:00";
  await writeFile(servicesPath, YAML.stringify(manifest2));
  // Item 9 SECOND review fix (finding 2): read AFTER the manifest edit
  // just above, never before it - inputDigests.manifestDigest must
  // reflect the SAME servicesPath content this scenario's own plan,
  // journal, and later resume all actually see, or resume's own "input
  // changed since journaled" digest-match gate refuses it outright (a
  // real bug a further review found: this used to be read too early).
  const { manifest, catalog, releaseLock: lock, servicesSchema, catalogSchema, releaseLockSchema, inputDigests } = await loadRealDeploymentInputs();
  const { blocked, plan, diagnostics } = await runPlan(planOptions());
  assert.ok(!blocked, JSON.stringify(diagnostics));
  assert.equal(plan.target.baselineGeneration, baselineGeneration);
  const generation = baselineGeneration + 1;
  const installationId = plan.target.installationId;

  // A REAL, full, uninterrupted dispatch of this exact commit's own
  // state.commit - using the FIXED local EE image - lands the immutable
  // snapshot AND both pointers for real (nothing is hand-built past this
  // point; everything from here on is real, role-produced content). This
  // is the exact same document a real state.commit dispatch for this
  // operationId/generation would itself produce and is what this whole
  // scenario's own final assertions compare the target back against.
  const operationId = newOperationId();
  // Item 9 THIRD review fix (finding 6): computeExpectedCommittedState()
  // now requires operationStartedAt explicitly (a real apply run passes
  // its own journal's startedAt - see apply.mjs). This scenario never
  // builds a real journal document at all, so it stands in the same
  // fixed instant a real journal.startedAt would be for this operation -
  // any fixed string does, since nothing here calls this function a
  // second time to compare against a divergent one.
  const operationStartedAt = new Date().toISOString();
  const { currentState: expectedCurrent, appliedRendered: expectedTopology } = computeExpectedCommittedState({
    manifest, catalog, releaseLock: lock, servicesSchema, catalogSchema, releaseLockSchema,
    plan, operationId, installationId, generation, inputDigests, operationStartedAt,
  });
  const stateDir = await writeStateDir({ current: expectedCurrent, topology: expectedTopology, releaseLock: lock });
  // plan.operations.at(-1) - a real applied plan's own LAST operation is
  // always state.commit (see plan.mjs's own buildOperations) - its own
  // .id is the real plan-v2 STEP id this dispatch's own extra-vars
  // must carry as hof_operation_id (see buildExtraVars()'s own comment;
  // never the whole apply run's UUID, `operationId` above, which is a
  // different thing computeExpectedCommittedState() needs for a
  // different reason).
  assert.equal(plan.operations.at(-1).action, "state.commit", "fixture assumption: an applied plan's own last operation is always state.commit");
  await dispatchStateRoleForReal({ image: localEeImageTag, stepId: plan.operations.at(-1).id, generation, stateDir });

  // Confirmed genuinely landed - both pointers AND the immutable
  // snapshot, all real.
  const { current: landedCurrent } = await readCurrentStateViaMutate(mutateConn());
  assert.equal(landedCurrent.generation, generation);
  const { snapshot: landedSnapshot } = await readGenerationSnapshot(mutateConn(), generation);
  assert.ok(landedSnapshot);

  // NOW reconstruct the exact crash window this finding fixes: a real
  // apply crashing strictly between the atomic topology.json write and
  // the atomic current.json write. The immutable snapshot (published
  // BEFORE either pointer - see ansible/roles/state/tasks/main.yml) and
  // topology.json already, genuinely, say generation N; only
  // current.json is manually reverted here, to its own real, previously-
  // committed generation N-1 bytes - the ONE deliberate step in this
  // whole scenario that isn't itself a direct role dispatch, standing in
  // for the timing a real process kill can't be scripted to land on
  // precisely and reproducibly.
  await onTarget("sh", "-c", `cat > /var/lib/hof/state/current.json <<'JSON'\n${JSON.stringify(baselineCurrent)}\nJSON`);
  const { current: crashWindowCurrent } = await readCurrentStateViaMutate(mutateConn());
  assert.equal(crashWindowCurrent.generation, baselineGeneration, "fixture assumption: the manual revert landed");

  // A real lock+journal+event history for this exact operationId,
  // written directly via target-mutate.mjs's own real functions. Item 9
  // SECOND review fix (finding 8): named honestly - every operation
  // BEFORE state.commit is marked started+succeeded SYNTHETICALLY here
  // (this scenario never actually dispatched host.prepare/secret.ensure/
  // config.write/etc for real under THIS operationId; only state.commit
  // was, directly, above), matching what a real journal would show for
  // an interrupted apply that had genuinely gotten that far - but this
  // is a narrow, deliberate proof of state.commit's OWN resume recovery
  // specifically, not a claim that every generated artifact a full,
  // genuinely end-to-end interrupted apply would have produced is
  // present and self-consistent here too (config.write's own real
  // output, in particular, was never actually generated under this
  // operationId at all).
  const conn = mutateConn();
  const lockDoc = await buildLockDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, acquiredBy: currentOperator() });
  const journalDoc = await buildJournalDocument({ operationId, approvedPlanId: plan.planId, target: plan.target, plan, inputDigests });
  const { acquired } = await acquireLockAndJournal(conn, lockDoc, journalDoc);
  assert.ok(acquired, "fixture assumption: the target is unlocked before this scenario constructs its own");
  for (const operation of plan.operations.slice(0, -1)) {
    await appendEvent(conn, operationId, await buildEvent({ operationId, step: operation.id, attempt: 1, phase: "started" }));
    await appendEvent(conn, operationId, await buildEvent({ operationId, step: operation.id, attempt: 1, phase: "succeeded" }));
  }
  const stateCommitOp = plan.operations.at(-1);
  assert.equal(stateCommitOp.action, "state.commit");
  await appendEvent(conn, operationId, await buildEvent({ operationId, step: stateCommitOp.id, attempt: 1, phase: "started" }));

  // Item 9 review fix (finding 3): "process A" - already running,
  // holding the real execution lease for this exact target - before
  // "process B" (a second, independent --resume of the SAME operation)
  // gets anywhere near dispatching its own remaining step.
  // Item 9 SECOND review fix (finding 2): herold/wachter are still
  // enabled from the previous test (this file's own continuous, real
  // lifecycle - see this section's own top comment), so requiredSecrets()
  // for THIS deployment is non-empty and apply.mjs's own eager secrets
  // gate runs BEFORE the lease check below on every call here, resume or
  // not - without a store, both would be refused with reason "secrets"
  // instead of ever reaching what this scenario actually tests. Neither
  // call below dispatches secret.ensure for real (a backup-only change
  // scopes to no secret-consuming unit - see the previous test's own
  // "unrelated change" case), so the exact values handed back here are
  // never delivered anywhere; they only need to satisfy the gate.
  const secretsOptions = {
    secretsStorePath: "/dev/null",
    readSecretsStore: async () => ({
      "herold-credential-encryption-key": generateSecretValue("token"),
      "wachter-agent-token": generateSecretValue("token"),
    }),
  };

  const heldLease = await acquireExecutionLease(conn);
  try {
    const concurrentResume = await runApply({ ...baseOptions(), ...secretsOptions, resume: true, executionEnvironmentImageOverride: localEeImageTag });
    assert.equal(concurrentResume.blocked, true, "a concurrent resume must be refused");
    assert.equal(concurrentResume.reason, "lease");
    assert.match(concurrentResume.diagnostics[0], /execution lease/);
    // Refused WITHOUT touching the durable lock A still legitimately
    // holds - confirmed directly on the target, not just via the
    // returned result.
    await exec("docker", ["exec", containerName, "test", "-e", "/var/lib/hof/state/lock.json"]);
  } finally {
    await heldLease.release();
  }

  // A is "done" now (in a real crash, its own process - and the lease
  // with it - would simply be gone) - the real, production
  // `hofctl apply --resume`, using the FIXED local EE image so the
  // re-dispatch below runs the real, retry-safe role, not the old,
  // published, still-broken one.
  const dockerCalls = [];
  const resumeResult = await runApply({
    ...baseOptions(), ...secretsOptions, resume: true, executionEnvironmentImageOverride: localEeImageTag,
    dockerRun: async (command, args, options) => { dockerCalls.push(args); return loggingDockerRun(command, args, options); },
  });
  assert.equal(resumeResult.blocked, false, `resume should finish the interrupted commit: ${JSON.stringify(resumeResult)}`);
  assert.equal(resumeResult.committedGeneration, generation);
  assert.ok(dockerCalls.some((args) => JSON.parse(args.at(-1)).hof_role === "state"), "state.commit must genuinely be RE-dispatched here - only the immutable snapshot was already complete, the pointers were not");

  const { current: finalCurrent } = await readCurrentStateViaMutate(mutateConn());
  assert.equal(finalCurrent.generation, generation);
  assert.deepEqual(withoutVolatileStateFields(finalCurrent), withoutVolatileStateFields(expectedCurrent));
  const { topology: finalTopology } = await readTopology(mutateConn());
  assert.deepEqual(finalTopology, expectedTopology);
  await assert.rejects(() => exec("docker", ["exec", containerName, "test", "-e", "/var/lib/hof/state/lock.json"]), "the lock is released once the commit genuinely finishes");
});
