import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import YAML from "yaml";

import { loadContracts } from "../scripts/contracts.mjs";
import { renderFiles, renderTopology } from "../scripts/render-topology.mjs";

async function contractsWith(selection) {
  const contracts = structuredClone(await loadContracts());
  for (const service of Object.keys(contracts.manifest.services)) {
    contracts.manifest.services[service].enabled = selection.includes(service);
  }
  contracts.manifest.features.browserPush.enabled = selection.includes("glocke");
  return contracts;
}

test("full topology renders every selected service and integration", async () => {
  const contracts = await contractsWith(["kuvert", "tafel", "zettel", "glocke", "schrank", "herold", "wachter"]);
  const rendered = renderTopology(contracts);

  assert.deepEqual(rendered.topology.enabledServices, ["tor", "schlussel", "schloss", "kuvert", "tafel", "zettel", "glocke", "schrank", "herold", "wachter"]);
  assert.deepEqual(rendered.topology.glockeProducers, ["schlussel", "kuvert", "tafel", "zettel"]);
  assert.equal(rendered.topology.backupVolumes.length, 8);
  assert.equal(rendered.compose.services.schloss.environment.WACHTER_ENABLED, "true");
  assert.equal(rendered.compose.services["glocke-backend"].environment.GLOCKE_EVENT_SOURCES, "schlussel,kuvert,tafel,zettel");
  assert.equal(rendered.compose.services["glocke-backend"].environment.ALLOWED_ORIGINS, rendered.topology.trustedOrigins.join(","));
  assert.match(rendered.compose.services["herold-backend"].environment.HEROLD_CREDENTIAL_ENCRYPTION_KEY, /required/);
  assert.deepEqual(rendered.compose.services["wachter-agent"].networks, ["wachter-internal"]);
  assert.ok(rendered.compose.services["wachter-agent"].volumes.includes("/var/run/docker.sock:/var/run/docker.sock"));
  assert.match(rendered.caddyfile, /glocke\.example\.com/);
  assert.ok(rendered.compose.services.wachter);
  assert.ok(rendered.compose.services["wachter-agent"]);
});

test("Wächter's two containers get their real port, command, and hardening", async () => {
  const rendered = renderTopology(await contractsWith(["wachter"]));
  const { wachter, "wachter-agent": agent } = rendered.compose.services;

  // The regression this guards against: APP_PORTS had no "wachter" entry,
  // so this rendered as the literal string "undefined" and the
  // healthcheck URL was http://localhost:undefined/ready.
  assert.equal(wachter.environment.PORT, "3007");
  assert.deepEqual(wachter.healthcheck.test, ["CMD", "wget", "-qO-", "http://localhost:3007/ready"]);
  assert.equal(wachter.environment.DATABASE_PATH, undefined, "Wächter has no database");

  // The agent shares an image with the API - only its command differs.
  // Without an explicit command it silently ran the API's default CMD.
  assert.deepEqual(agent.command, ["node", "backend/dist/agent.js"]);
  assert.equal(agent.environment.PORT, "3008");

  for (const service of [wachter, agent]) {
    assert.equal(service.read_only, true);
    assert.deepEqual(service.cap_drop, ["ALL"]);
    assert.deepEqual(service.security_opt, ["no-new-privileges:true"]);
    assert.deepEqual(service.tmpfs, ["/tmp"]);
    assert.equal(service.labels["hof.wachter.critical"], "true");
    assert.equal(service.labels["hof.managed"], "true");
    assert.equal(service.labels["hof.service"], "wachter");
    assert.equal(service.labels["hof.artifact"], "wachter-backend");
  }
});

test("every non-frontend service is restart-critical, every frontend is restartable", async () => {
  const rendered = renderTopology(await contractsWith(["kuvert", "wachter"]));
  const restartable = Object.entries(rendered.compose.services)
    .filter(([, service]) => service.labels?.["hof.wachter.restartable"] === "true")
    .map(([name]) => name);
  const critical = Object.entries(rendered.compose.services)
    .filter(([, service]) => service.labels?.["hof.wachter.critical"] === "true")
    .map(([name]) => name);

  assert.deepEqual(restartable.sort(), ["kuvert-frontend", "schlussel-frontend"]);
  assert.deepEqual(
    critical.sort(),
    ["gateway", "kuvert-backend", "schloss", "schlussel", "wachter", "wachter-agent"].sort(),
  );
  // No service is ever labeled both - the agent gives critical precedence,
  // but a service double-labeled would signal a rendering bug, not a
  // real-world case to tolerate.
  for (const service of Object.values(rendered.compose.services)) {
    assert.ok(!(service.labels?.["hof.wachter.restartable"] === "true" && service.labels?.["hof.wachter.critical"] === "true"));
  }
});

test("core-only topology contains no disabled service references", async () => {
  const rendered = renderTopology(await contractsWith([]));
  const serialized = JSON.stringify(rendered);

  assert.deepEqual(Object.keys(rendered.compose.services), ["gateway", "schlussel", "schlussel-frontend", "schloss"]);
  assert.deepEqual(Object.keys(rendered.compose.volumes), ["caddy-data", "schlussel-data"]);
  assert.deepEqual(rendered.topology.exportTargets, {});
  assert.deepEqual(rendered.topology.deletionTargets, {});
  assert.deepEqual(rendered.topology.glockeProducers, []);
  assert.equal(rendered.compose.services.schlussel.environment.GLOCKE_ENABLED, "false");
  assert.equal(rendered.compose.services.schloss.environment.WACHTER_ENABLED, "false");
  assert.doesNotMatch(serialized, /glocke-backend|kuvert-backend|wachter-agent/);
  assert.doesNotMatch(rendered.caddyfile, /kuvert\.|glocke\.|herold\./);
});

test("partial topology scopes Glocke producers, registries, CORS, links, health, and backups", async () => {
  const rendered = renderTopology(await contractsWith(["tafel", "glocke"]));

  assert.deepEqual(rendered.topology.glockeProducers, ["schlussel", "tafel"]);
  assert.deepEqual(Object.keys(rendered.topology.exportTargets), ["tafel", "glocke"]);
  assert.equal(rendered.runtimeConfig.services.kuvert, false);
  assert.equal(rendered.runtimeConfig.services.tafel, true);
  assert.equal(rendered.runtimeConfig.services.glocke, true);
  assert.equal(rendered.compose.services["glocke-backend"].environment.KUVERT_ORIGIN, undefined);
  assert.equal(rendered.compose.services["glocke-backend"].environment.TAFEL_ORIGIN, "https://tafel.example.com");
  assert.ok(rendered.topology.healthTargets.some((target) => target.service === "tafel"));
  assert.ok(!rendered.topology.healthTargets.some((target) => target.service === "kuvert"));
  assert.deepEqual(rendered.topology.backupVolumes.map(({ volume }) => volume), ["caddy-data", "schlussel-data", "tafel-data", "glocke-data"]);
});

test("render output is deterministic and Compose is parseable", async () => {
  const out = await mkdtemp(path.join(tmpdir(), "hof-render-"));
  const options = {
    services: path.resolve("examples/services.yml"), catalog: path.resolve("catalog/services-v1.yaml"),
    releaseLock: path.resolve("examples/release-lock.json"), out,
  };
  const names = await renderFiles(options);
  const first = await Promise.all(names.map((name) => readFile(path.join(out, name), "utf8")));
  await renderFiles(options);
  const second = await Promise.all(names.map((name) => readFile(path.join(out, name), "utf8")));

  assert.deepEqual(second, first);
  const compose = YAML.parse(first[names.indexOf("compose.yml")]);
  assert.equal(compose.services["schrank-backend"], undefined);
  assert.match(compose.services["kuvert-backend"].image, /@sha256:/);
});

test("renderer rejects mismatched manifest and release-lock releases", async () => {
  const contracts = await contractsWith([]);
  contracts.manifest.release = "2.0.0";
  assert.throws(() => renderTopology(contracts), /does not match release lock/);
});

test("every generated service is labeled with hofctl plan's ownership metadata", async () => {
  const contracts = await contractsWith(["kuvert", "wachter"]);
  const rendered = renderTopology({ ...contracts, installationId: "installation-42", generation: 7 });

  for (const [name, service] of Object.entries(rendered.compose.services)) {
    assert.equal(service.labels["hof.managed"], "true", name);
    assert.equal(service.labels["hof.installation-id"], "installation-42", name);
    assert.equal(service.labels["hof.generation"], "7", name);
    assert.ok(service.labels["hof.service"], name);
    assert.ok(service.labels["hof.artifact"], name);
    // hof.unit must be the actual Compose key - the one thing guaranteed
    // unique within one Compose file, unlike hof.artifact (Wachter's two
    // containers share one).
    assert.equal(service.labels["hof.unit"], name, name);
  }
  assert.equal(rendered.compose.services["kuvert-backend"].labels["hof.service"], "kuvert");
  assert.equal(rendered.compose.services["kuvert-backend"].labels["hof.artifact"], "kuvert-backend");
  // Wachter's API and agent must be distinguishable even though they
  // share one catalog artifact.
  assert.equal(rendered.compose.services.wachter.labels["hof.artifact"], "wachter-backend");
  assert.equal(rendered.compose.services["wachter-agent"].labels["hof.artifact"], "wachter-backend");
  assert.notEqual(rendered.compose.services.wachter.labels["hof.unit"], rendered.compose.services["wachter-agent"].labels["hof.unit"]);
});

test("every named volume and network is also labeled for orphan detection", async () => {
  const contracts = await contractsWith(["kuvert", "wachter"]);
  const rendered = renderTopology({ ...contracts, installationId: "installation-42", generation: 7 });

  for (const [name, volume] of Object.entries(rendered.compose.volumes)) {
    assert.equal(volume.labels["hof.managed"], "true", name);
    assert.equal(volume.labels["hof.installation-id"], "installation-42", name);
    assert.equal(volume.labels["hof.generation"], "7", name);
    assert.equal(volume.labels["hof.kind"], "volume", name);
    assert.equal(volume.labels["hof.resource"], name, name);
  }
  assert.ok(rendered.compose.volumes["kuvert-data"], "kuvert's own volume is rendered and labeled");

  for (const [name, network] of Object.entries(rendered.compose.networks)) {
    assert.equal(network.labels["hof.managed"], "true", name);
    assert.equal(network.labels["hof.kind"], "network", name);
    assert.equal(network.labels["hof.resource"], name, name);
  }
  assert.ok(rendered.compose.networks["wachter-internal"], "wachter's own internal network is rendered and labeled");
});

test("ownership labels default to an empty installation id and generation zero when unset", async () => {
  const rendered = renderTopology(await contractsWith([]));
  assert.equal(rendered.compose.services.schloss.labels["hof.installation-id"], "");
  assert.equal(rendered.compose.services.schloss.labels["hof.generation"], "0");
});
