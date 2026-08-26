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
