#!/usr/bin/env node

import { execFile } from "node:child_process";
import { statSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { loadContracts, validateContracts } from "./contracts.mjs";
import { sha256 as digest } from "./digest.mjs";
import { enabledServiceIds, HOF_NETWORK_NAME, renderTopology, WACHTER_INTERNAL_NETWORK_NAME } from "./render-topology.mjs";
import { generateSecretValue, requiredSecrets, vapidPublicKeyFor } from "./secrets.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Item 9 review (network lifecycle finding): render-topology.mjs's own
// two networks are now `external: true`, referencing a fixed physical
// name a real apply's own Ansible network role creates before Compose
// ever runs (see that role's own comment on why - Compose must never
// create, update, or reconcile them itself). This matrix has no
// Ansible role at all - it drives `docker compose` directly - so it
// must create the same physical networks itself, exactly once per run
// (every fixture below still gets its own uniquely-named Compose
// PROJECT - hof-gate6-<fixtureId> - but they run strictly sequentially,
// never concurrently, so sharing these two real network objects across
// fixtures is safe and mirrors how one real target's own long-lived
// networks are shared across every real apply against it).
async function ensureNetwork(name) {
  await exec("docker", ["network", "create", name]).catch((error) => {
    if (!/already exists/.test(error.stderr ?? "")) throw error;
  });
}
async function removeNetwork(name) {
  await exec("docker", ["network", "rm", name]).catch(() => {});
}

function parseArgs(argv) {
  const args = { lock: "examples/release-lock.json", runtime: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--lock") args.lock = argv[++i];
    else if (argv[i] === "--runtime") args.runtime = true;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

async function dockerCompose(file, project, args, environment = process.env) {
  return exec("docker", ["compose", "--project-name", project, "--file", file, ...args], {
    maxBuffer: 16 * 1024 * 1024,
    env: environment,
  });
}

export async function runIntegrationMatrix({ lock: lockPath, runtime }) {
  const contracts = await loadContracts();
  const fixtureDirectory = path.join(root, "test/fixtures/topologies");
  const fixtureNames = (await readdir(fixtureDirectory)).filter((name) => name.endsWith(".yml")).sort();
  if (fixtureNames.length < 2) throw new Error("integration matrix requires at least two topology fixtures");

  const [lockBytes, catalogBytes, templateBytes] = await Promise.all([
    readFile(path.resolve(root, lockPath)),
    readFile(path.join(root, "catalog/services-v1.yaml")),
    readFile(path.join(root, "scripts/render-topology.mjs")),
  ]);
  const lock = JSON.parse(lockBytes);
  const catalog = YAML.parse(catalogBytes.toString("utf8"));
  if (lock.catalogDigest !== digest(catalogBytes)) throw new Error("release lock catalog digest does not match");
  if (lock.composeTemplateDigest !== digest(templateBytes)) {
    throw new Error("release lock Compose-template digest does not match");
  }

  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "hof-gate6-"));
  // Only needed once real containers actually run (`docker compose run`/
  // `up`) - `config`/`config --images` are static, offline checks that
  // never touch a real network at all, and the non-runtime matrix
  // (`pnpm integration`, no `--runtime`) has no docker daemon
  // requirement to preserve.
  if (runtime) await ensureNetwork(HOF_NETWORK_NAME);
  try {
    for (const fixtureName of fixtureNames) {
      const manifest = YAML.parse(await readFile(path.join(fixtureDirectory, fixtureName), "utf8"));
      // Topology fixtures are release-agnostic by design - they exercise a
      // shape of services.yml (core-only, everything enabled, ...), not one
      // specific release. Stamp in whatever release is actually pinned
      // rather than requiring every fixture file to be kept in sync with
      // it (renderTopology's own manifest/lock release-match check is a
      // real safety property for an operator's actual services.yml; it
      // isn't meaningful for these).
      manifest.release = lock.release;
      const errors = validateContracts({ ...contracts, manifest, catalog, releaseLock: lock });
      if (errors.length > 0) throw new Error(`${fixtureName}:\n${errors.join("\n")}`);

      const fixtureId = path.basename(fixtureName, ".yml");
      // Generated once per fixture regardless of whether this one
      // actually enables browserPush - renderTopology() only ever uses
      // vapidPublicKey when it does, so an unused extra value here is
      // harmless, and every fixture's own secrets.mjs-generated values
      // stay realistic (real >=32-byte tokens, a real matching P-256
      // pair) rather than the old ad hoc placeholder strings.
      const secretValues = Object.fromEntries(
        requiredSecrets(manifest, enabledServiceIds(manifest, catalog)).map((secret) => [secret.name, generateSecretValue(secret.kind)]),
      );
      const vapidPrivateKey = secretValues["glocke-vapid-private-key"];
      const rendered = renderTopology({ ...contracts, manifest, catalog, releaseLock: lock, vapidPublicKey: vapidPrivateKey ? vapidPublicKeyFor(vapidPrivateKey) : undefined });
      const compose = rendered.compose;
      compose.name = `hof-gate6-${fixtureId}`;
      for (const service of Object.values(compose.services)) {
        if (!service.image?.includes("@sha256:")) throw new Error(`${fixtureName}: image is not digest-pinned`);
        if (!Object.values(lock.components).some((component) => component.image === service.image)) {
          throw new Error(`${fixtureName}: generated Compose image is absent from the pinned lock`);
        }
      }
      const composePath = path.join(temporaryDirectory, `${fixtureId}.json`);
      await writeFile(composePath, JSON.stringify(compose, null, 2) + "\n");
      // The gateway service's ./Caddyfile volume is relative to the
      // Compose project directory (the compose file's own directory,
      // since none is set explicitly) - without writing the real one
      // there too, Docker silently creates an empty directory at that
      // path and the bind mount fails at container start.
      if (compose.services.gateway) await writeFile(path.join(temporaryDirectory, "Caddyfile"), rendered.caddyfile);
      const environment = { ...process.env };
      // The rendered fallback (${DOCKER_GID:-998}) is only ever a guess -
      // wachter-agent got a real EACCES connecting to the Docker socket
      // once actually started, because this runner's real group ID isn't
      // 998. Read it the same way an operator's own setup would
      // (`stat -c '%g' /var/run/docker.sock`, per Tor's README).
      if (compose.services["wachter-agent"]) {
        try {
          environment.DOCKER_GID = String(statSync("/var/run/docker.sock").gid);
        } catch {
          // No local Docker socket to introspect - leave the rendered
          // fallback in place rather than failing the whole matrix over it.
        }
      }
      // Every secret went through render-topology.mjs's own `_FILE`
      // wiring now, except GLOCKE_VAPID_PUBLIC_KEY (glocke's own app
      // reads it as a plain value, not `_FILE`-aware - see
      // render-topology.mjs's own comment) - a regression guard, not
      // just a convenience: if a future change reintroduced a raw
      // `${VAR:?required}` secret placeholder by mistake, this fails
      // loudly here instead of silently needing yet another ad hoc
      // environment entry.
      for (const match of JSON.stringify(compose).matchAll(/\\?\$\{([A-Z0-9_]+):\?required\}/g)) {
        if (match[1] !== "GLOCKE_VAPID_PUBLIC_KEY") {
          throw new Error(`${fixtureName}: unexpected unmigrated secret placeholder \${${match[1]}:?required} - every real secret must go through the _FILE convention (see render-topology.mjs's wireSecret())`);
        }
      }
      if (rendered.compose.services["glocke-backend"]?.environment.GLOCKE_VAPID_PUBLIC_KEY?.includes(":?required")) {
        environment.GLOCKE_VAPID_PUBLIC_KEY = vapidPublicKeyFor(vapidPrivateKey);
      }
      await dockerCompose(composePath, compose.name, ["config", "--quiet"], environment);
      const { stdout } = await dockerCompose(composePath, compose.name, ["config", "--images"], environment);
      const renderedImages = new Set(stdout.trim().split("\n").filter(Boolean));
      for (const service of Object.values(compose.services)) {
        if (!renderedImages.has(service.image)) throw new Error(`${fixtureName}: Compose dropped ${service.image}`);
      }

      if (runtime) {
        // Real files this fixture's own containers will actually read at
        // `up` time - config/--images (above) never touch the
        // filesystem for a secret's `file:` path, but a real container
        // start does. HOF_SECRETS_DIR overrides render-topology.mjs's
        // own `${HOF_SECRETS_DIR:-/etc/hof/secrets}` default, so this
        // never needs real root or `/etc` write access.
        // render-topology.mjs's own wireSecret() uses Compose's native
        // file-based `secrets:` provider, which docker compose (outside
        // Swarm mode) implements as a plain bind-mount of the host file
        // into /run/secrets/<name> - the container sees the HOST file's
        // own uid/gid/mode exactly as-is, never normalized to a fixed
        // in-container value the way Swarm's own tmpfs-distributed
        // secrets are. mode 0600 (this process's own uid only) is
        // invisible to any container process that isn't root - which
        // most of these images' main processes are, but not all: a real
        // CI failure found wachter-agent specifically (deliberately
        // hardened to run as a non-root user, since it holds the Docker
        // socket) getting a genuine EACCES reading its own token file.
        // 0644 (world-readable) is safe here specifically because these
        // are synthetic, throwaway fixture values on an ephemeral CI
        // runner, never real secrets - it is NOT the mode a real target
        // uses (ansible/roles/secret/tasks/main.yml's own real delivery
        // stays root:root 0400, a real, separate, still-open question
        // for whichever future service needs its own consuming
        // container to run as non-root against a real secret).
        const secretsDirectory = path.join(temporaryDirectory, "secrets", fixtureId);
        await mkdir(secretsDirectory, { recursive: true });
        await Promise.all(Object.entries(secretValues).map(([name, value]) => writeFile(path.join(secretsDirectory, name), value, { mode: 0o644 })));
        environment.HOF_SECRETS_DIR = secretsDirectory;

        // Only this fixture's own wachter-agent/wachter reference it
        // (compose.networks["wachter-internal"] only exists at all when
        // Wachter is enabled - see render-topology.mjs) - created and
        // torn down per-fixture, unlike the shared "hof" network above,
        // since which fixture needs it varies.
        if (compose.services["wachter-agent"]) await ensureNetwork(WACHTER_INTERNAL_NETWORK_NAME);

        await dockerCompose(composePath, compose.name, ["pull", "--quiet"], environment);
        // render-topology.mjs now renders MIGRATE_ON_STARTUP=false - a
        // fresh volume's schema is only ever brought current by an
        // explicit migration job, matching hofctl plan's own
        // database.migrate operation (see PLATFORM-OPS-PLAN.md). Run one
        // per persistent service before `up --wait`, or /ready never
        // passes and every one of these fixtures times out.
        for (const service of catalog.services) {
          if (!service.database || !compose.services[service.database.component]) continue;
          await dockerCompose(
            composePath, compose.name,
            ["run", "--rm", "--no-deps", service.database.component, ...service.database.command],
            environment,
          );
        }
        try {
          // --wait blocks until every service with a healthcheck reports
          // healthy (or fails loudly if one doesn't within the timeout) -
          // this is what actually exercises the wrong-port/wrong-command/
          // migration-never-runs class of bug that `create` alone (no
          // process ever starts) and `config` alone (static text only)
          // both silently pass.
          await dockerCompose(composePath, compose.name, ["up", "--detach", "--wait", "--wait-timeout", "180"], environment);
        } catch (error) {
          const { stdout: logs } = await dockerCompose(composePath, compose.name, ["logs", "--no-color", "--tail", "40"], environment)
            .catch(() => ({ stdout: "(could not fetch logs)" }));
          throw new Error(`${fixtureName}: services did not become healthy\n${logs}\n${error.message}`);
        } finally {
          await dockerCompose(composePath, compose.name, ["down", "--remove-orphans", "--volumes"], environment);
          if (compose.services["wachter-agent"]) await removeNetwork(WACHTER_INTERNAL_NETWORK_NAME);
        }
      }
      console.log(`${fixtureName}: pinned Compose ${runtime ? "config/runtime" : "config"} contract passed`);
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
    if (runtime) await removeNetwork(HOF_NETWORK_NAME);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runIntegrationMatrix(parseArgs(process.argv.slice(2))).catch((error) => {
    console.error(error.stack ?? String(error));
    process.exitCode = 1;
  });
}
