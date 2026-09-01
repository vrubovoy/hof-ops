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
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

import { runApply } from "../scripts/apply.mjs";
import { runPlan } from "../scripts/plan-command.mjs";

const RECOVERY_AGE_RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
// The real platform release this test downloads and applies - see
// releases/0.2.0.yml (reuses releases/0.1.4.yml's own app-component
// selections unchanged; only ansibleEnvironment moves to ee-v0.1.4, item
// 9's own real, independently-verified cut - PR #53 - baking in the new
// service-role start|stop|remove actions and the state role's own
// immutable per-generation snapshots this file's own applied-lifecycle
// half below exercises for real). `workflow_dispatch` signs with the
// DISPATCHING branch's own ref, never a tag (confirmed for real by
// inspecting the v0.1.1 release's own certificate - `@refs/heads/main`,
// not `@refs/tags/v0.1.1`), unlike execution-environment.yml's own
// tag-triggered identity below.
const RELEASE_VERSION = "0.2.0";
const RELEASE_LOCK_IDENTITY = "https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/heads/main";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = path.join(root, "test/fixtures/apply-acceptance");
const targetImageTag = "hof-ops-apply-acceptance-target:test";
const containerName = `hof-apply-acceptance-${randomUUID()}`;
const networkName = `hof-apply-acceptance-${randomUUID()}`;

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

test("a real, full bootstrap apply against the real, published, signed v0.2.0 release, then a real applied-mode reconciliation lifecycle against the same target - every real role, start to finish, generation 1 through 4", async () => {
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
