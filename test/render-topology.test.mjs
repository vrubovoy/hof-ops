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
  assert.equal(rendered.compose.services["herold-backend"].environment.HEROLD_CREDENTIAL_ENCRYPTION_KEY_FILE, "/run/secrets/herold-credential-encryption-key");
  assert.ok(rendered.compose.services["herold-backend"].secrets.includes("herold-credential-encryption-key"));
  assert.deepEqual(rendered.compose.secrets["herold-credential-encryption-key"], { file: "${HOF_SECRETS_DIR:-/etc/hof/secrets}/herold-credential-encryption-key" });
  assert.deepEqual(rendered.compose.services["wachter-agent"].networks, ["wachter-internal"]);
  assert.ok(rendered.compose.services["wachter-agent"].volumes.includes("/var/run/docker.sock:/var/run/docker.sock"));
  assert.match(rendered.caddyfile, /glocke\.example\.com/);
  assert.ok(rendered.compose.services.wachter);
  assert.ok(rendered.compose.services["wachter-agent"]);
});

test("secret-safe rendering: every secret-bearing service gets the _FILE convention, never a raw env var, and compose.secrets covers exactly what's wired", async () => {
  const contracts = await contractsWith(["kuvert", "tafel", "zettel", "glocke", "schrank", "herold", "wachter"]);
  const rendered = renderTopology(contracts);
  const { compose } = rendered;

  // Every secret this configuration needs is declared once, at a fixed,
  // overridable-for-testing path - never a literal /etc path baked in
  // with no way to point it elsewhere.
  const expectedSecretNames = [
    "schlussel-to-glocke-hmac-secret", "kuvert-to-glocke-hmac-secret", "tafel-to-glocke-hmac-secret", "zettel-to-glocke-hmac-secret",
    "glocke-to-schlussel-hmac-secret", "glocke-vapid-private-key", "herold-credential-encryption-key", "wachter-agent-token",
  ];
  assert.deepEqual(Object.keys(compose.secrets).sort(), expectedSecretNames.sort());
  for (const name of expectedSecretNames) {
    assert.deepEqual(compose.secrets[name], { file: `\${HOF_SECRETS_DIR:-/etc/hof/secrets}/${name}` });
  }

  // schlussel: both of its own two HMAC secrets, _FILE only.
  assert.deepEqual(compose.services.schlussel.secrets.slice().sort(), ["glocke-to-schlussel-hmac-secret", "schlussel-to-glocke-hmac-secret"].sort());
  assert.equal(compose.services.schlussel.environment.SCHLUSSEL_TO_GLOCKE_HMAC_SECRET_FILE, "/run/secrets/schlussel-to-glocke-hmac-secret");
  assert.equal(compose.services.schlussel.environment.GLOCKE_TO_SCHLUSSEL_HMAC_SECRET_FILE, "/run/secrets/glocke-to-schlussel-hmac-secret");
  assert.ok(!("SCHLUSSEL_TO_GLOCKE_HMAC_SECRET" in compose.services.schlussel.environment));
  assert.ok(!("GLOCKE_TO_SCHLUSSEL_HMAC_SECRET" in compose.services.schlussel.environment));

  // Each glocke producer gets its own outgoing secret, _FILE only.
  for (const producer of ["kuvert", "tafel", "zettel"]) {
    const unit = `${producer}-backend`;
    const envVar = `${producer.toUpperCase()}_TO_GLOCKE_HMAC_SECRET`;
    assert.equal(compose.services[unit].environment[`${envVar}_FILE`], `/run/secrets/${producer}-to-glocke-hmac-secret`);
    assert.ok(!(envVar in compose.services[unit].environment));
    assert.ok(compose.services[unit].secrets.includes(`${producer}-to-glocke-hmac-secret`));
  }

  // glocke-backend: every producer's own secret (under its own
  // GLOCKE_SOURCE_SECRET_* key), the reverse HMAC secret, and the VAPID
  // private key - six secrets total, all _FILE.
  const glockeEnv = compose.services["glocke-backend"].environment;
  assert.deepEqual(
    compose.services["glocke-backend"].secrets.slice().sort(),
    ["schlussel-to-glocke-hmac-secret", "kuvert-to-glocke-hmac-secret", "tafel-to-glocke-hmac-secret", "zettel-to-glocke-hmac-secret", "glocke-to-schlussel-hmac-secret", "glocke-vapid-private-key"].sort(),
  );
  for (const producer of ["schlussel", "kuvert", "tafel", "zettel"]) {
    assert.equal(glockeEnv[`GLOCKE_SOURCE_SECRET_${producer.toUpperCase()}_FILE`], `/run/secrets/${producer}-to-glocke-hmac-secret`);
  }
  assert.equal(glockeEnv.GLOCKE_VAPID_PRIVATE_KEY_FILE, "/run/secrets/glocke-vapid-private-key");
  assert.ok(!("GLOCKE_VAPID_PRIVATE_KEY" in glockeEnv));
  // GLOCKE_PUSH_ALLOWED_ENDPOINT_HOSTS is a real config value, not a
  // secret at all - a plain manifest-driven value, never routed through
  // compose.secrets.
  assert.equal(glockeEnv.GLOCKE_PUSH_ALLOWED_ENDPOINT_HOSTS, "fcm.googleapis.com,updates.push.services.mozilla.com");
  // The one deliberate exception: glocke's own app reads the VAPID
  // *public* key as a plain value, not _FILE-aware - a bare render with
  // no vapidPublicKey supplied keeps the old require-a-value placeholder
  // rather than silently emitting nothing.
  assert.match(glockeEnv.GLOCKE_VAPID_PUBLIC_KEY, /GLOCKE_VAPID_PUBLIC_KEY:\?required/);

  // A real, supplied vapidPublicKey is rendered as the literal value,
  // never the placeholder.
  const withRealVapid = renderTopology({ ...contracts, vapidPublicKey: "real-derived-public-key-value" });
  assert.equal(withRealVapid.compose.services["glocke-backend"].environment.GLOCKE_VAPID_PUBLIC_KEY, "real-derived-public-key-value");

  // herold: its own encryption key, _FILE only.
  assert.equal(compose.services["herold-backend"].environment.HEROLD_CREDENTIAL_ENCRYPTION_KEY_FILE, "/run/secrets/herold-credential-encryption-key");
  assert.ok(!("HEROLD_CREDENTIAL_ENCRYPTION_KEY" in compose.services["herold-backend"].environment));

  // wachter + wachter-agent: the SAME shared token, _FILE only, no
  // leftover bind-mount workaround.
  for (const unit of ["wachter", "wachter-agent"]) {
    assert.equal(compose.services[unit].environment.WACHTER_AGENT_TOKEN_FILE, "/run/secrets/wachter-agent-token");
    assert.ok(!("WACHTER_AGENT_TOKEN" in compose.services[unit].environment));
    assert.ok(compose.services[unit].secrets.includes("wachter-agent-token"));
  }
  assert.ok(!compose.services.wachter.volumes?.some((v) => v.includes("WACHTER_AGENT_TOKEN_FILE")), "no leftover identity bind-mount workaround");
});

test("secret-safe rendering: with everything optional disabled, no secrets are required at all", async () => {
  const rendered = renderTopology(await contractsWith([]));
  assert.deepEqual(rendered.compose.secrets, {});
  for (const service of Object.values(rendered.compose.services)) assert.ok(!("secrets" in service));
});

test("Wächter's agent unit renders BEFORE its API unit so hofctl plan starts (and waits on) the agent first", async () => {
  const rendered = renderTopology(await contractsWith(["wachter"]));
  const unitOrder = Object.keys(rendered.compose.services);
  // Item 9 review fix (finding 4): the API's /ready health endpoint only
  // reports healthy once its sampler can reach the agent, and the
  // service role starts each unit with --no-deps - so the agent must
  // render (and therefore start + become healthy) first.
  assert.ok(
    unitOrder.indexOf("wachter-agent") < unitOrder.indexOf("wachter"),
    `wachter-agent must precede wachter in compose.services, got ${JSON.stringify(unitOrder)}`,
  );
  // The API still declares its dependency on the agent explicitly.
  assert.deepEqual(rendered.compose.services.wachter.depends_on, { "wachter-agent": { condition: "service_healthy" } });
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
