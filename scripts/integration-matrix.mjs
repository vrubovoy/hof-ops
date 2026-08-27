#!/usr/bin/env node

import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { statSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import YAML from "yaml";

import { loadContracts, validateContracts } from "./contracts.mjs";
import { sha256 as digest } from "./digest.mjs";
import { renderTopology } from "./render-topology.mjs";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = { lock: "examples/release-lock.json", runtime: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--lock") args.lock = argv[++i];
    else if (argv[i] === "--runtime") args.runtime = true;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

// GLOCKE_VAPID_PUBLIC_KEY/PRIVATE_KEY need real, matching P-256 key
// material - Glocke's own config validates the key format, not just its
// presence, so a generic placeholder string fails the same way a
// too-short or non-distinct one did for the other secrets. VAPID's usual
// encoding (the "web-push" package's own convention): the public key is
// the uncompressed SEC1 point (0x04 || X || Y), the private key is the
// raw scalar - both base64url, no padding.
function generateVapidKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const uncompressedPoint = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(publicJwk.x, "base64url"),
    Buffer.from(publicJwk.y, "base64url"),
  ]);
  return {
    publicKey: uncompressedPoint.toString("base64url"),
    privateKey: Buffer.from(privateJwk.d, "base64url").toString("base64url"),
  };
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
      const rendered = renderTopology({ ...contracts, manifest, catalog, releaseLock: lock });
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
      // Unique per variable name, not one shared constant, and at least
      // 32 bytes - both found by actually running this against schlussel
      // with Glocke enabled: its own directional-secret distinctness
      // check ("Directional HMAC secrets must be distinct") rejected
      // every producer sharing one placeholder value, and resolveSecret()
      // separately enforces a 32-byte minimum on each of them.
      const vapidKeyPair = generateVapidKeyPair();
      for (const match of JSON.stringify(compose).matchAll(/\\?\$\{([A-Z0-9_]+):\?required\}/g)) {
        if (match[1] === "GLOCKE_VAPID_PUBLIC_KEY") environment[match[1]] = vapidKeyPair.publicKey;
        else if (match[1] === "GLOCKE_VAPID_PRIVATE_KEY") environment[match[1]] = vapidKeyPair.privateKey;
        else environment[match[1]] = `gate6-contract-placeholder-${match[1].toLowerCase()}-0123456789`;
      }
      // WACHTER_AGENT_TOKEN is an either/or with _FILE, so the render
      // template can't mark it `:?required` (Compose has no "one of"
      // syntax) - it's genuinely required by the running agent/API,
      // though, and must clear its own 32-byte minimum.
      if (compose.services.wachter) environment.WACHTER_AGENT_TOKEN = "gate6-integration-matrix-wachter-agent-token";
      await dockerCompose(composePath, compose.name, ["config", "--quiet"], environment);
      const { stdout } = await dockerCompose(composePath, compose.name, ["config", "--images"], environment);
      const renderedImages = new Set(stdout.trim().split("\n").filter(Boolean));
      for (const service of Object.values(compose.services)) {
        if (!renderedImages.has(service.image)) throw new Error(`${fixtureName}: Compose dropped ${service.image}`);
      }

      if (runtime) {
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
        }
      }
      console.log(`${fixtureName}: pinned Compose ${runtime ? "config/runtime" : "config"} contract passed`);
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runIntegrationMatrix(parseArgs(process.argv.slice(2))).catch((error) => {
    console.error(error.stack ?? String(error));
    process.exitCode = 1;
  });
}
