import assert from "node:assert/strict";
import test from "node:test";

import { loadContracts, validateContracts } from "../scripts/contracts.mjs";
import { assertReleaseVersion } from "../scripts/build-release-lock.mjs";

test("repository contract examples are valid", async () => {
  const contracts = await loadContracts();
  assert.deepEqual(validateContracts(contracts), []);
});

test("browser push requires Glocke", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.manifest.services.glocke.enabled = false;

  assert.match(validateContracts(contracts).join("\n"), /browserPush requires glocke/);
});

test("browser push requires a subject", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.manifest.features.browserPush.subject;

  assert.match(validateContracts(contracts).join("\n"), /browserPush\.enabled requires subject/);
});

test("browser push requires at least one allowedEndpointHosts entry - not itself a secret, but a real config value with no safe default", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.manifest.features.browserPush.allowedEndpointHosts;
  assert.match(validateContracts(contracts).join("\n"), /browserPush\.enabled requires at least one allowedEndpointHosts entry/);

  const empty = structuredClone(await loadContracts());
  empty.manifest.features.browserPush.allowedEndpointHosts = [];
  assert.match(validateContracts(empty).join("\n"), /browserPush\.enabled requires at least one allowedEndpointHosts entry/);
});

test("browser push disabled needs neither subject nor allowedEndpointHosts", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.manifest.features.browserPush = { enabled: false };
  contracts.manifest.services.glocke.enabled = false;
  assert.deepEqual(validateContracts(contracts), []);
});

test("mandatory core cannot be downgraded in the catalog", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.catalog.services.find((service) => service.id === "schlussel").mandatory = false;

  assert.match(validateContracts(contracts).join("\n"), /schlussel must be mandatory/);
});

test("catalog dependency cycles fail validation", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.catalog.services.find((service) => service.id === "tor").dependsOn = ["schloss"];

  assert.match(validateContracts(contracts).join("\n"), /dependency cycle/);
});

test("secrets and image overrides fail desired-state validation", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.manifest.secrets = { password: "unsafe" };
  contracts.manifest.services.kuvert.image = "example.invalid/kuvert:latest";

  const errors = validateContracts(contracts).join("\n");
  assert.match(errors, /must NOT have additional properties/);
});

test("duplicate backup destination names fail cross-contract validation", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.manifest.backup.destinations[1].name = "local-primary";

  assert.match(validateContracts(contracts).join("\n"), /duplicate backup destination/);
});

test("release lock must resolve every catalog artifact", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.releaseLock.components["kuvert-frontend"];

  assert.match(validateContracts(contracts).join("\n"), /missing catalog artifact kuvert-frontend/);
});

test("a third-party release-lock component cannot also claim a Hof signature", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.releaseLock.components.gateway.signatureIdentity = "https://github.com/vrubovoy/hof-ops";

  const errors = validateContracts(contracts).join("\n");
  assert.match(errors, /release lock\/components\/gateway: must match exactly one schema in oneOf/);
});

test("a self-built release-lock component cannot skip its signature", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.releaseLock.components["kuvert-backend"].signatureIdentity;

  const errors = validateContracts(contracts).join("\n");
  assert.match(errors, /release lock\/components\/kuvert-backend: must have required property 'signatureIdentity'/);
});

test("release selection requires every catalog artifact", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.releaseSelection.components["tafel-frontend"];
  assert.match(validateContracts(contracts).join("\n"), /release selection: missing catalog artifact tafel-frontend/);
});

test("component image tags equal their explicitly selected versions", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.releaseSelection.components.schloss.image = "ghcr.io/vrubovoy/schloss:1.0.1";
  assert.match(validateContracts(contracts).join("\n"), /image tag must equal v plus selected version/);
});

test("release versions are canonical stable semver", () => {
  assert.doesNotThrow(() => assertReleaseVersion("1.2.3"));
  for (const invalid of ["v1.2.3", "01.2.3", "1.2", "1.2.3-rc.1", "1.2.3+build"]) {
    assert.throws(() => assertReleaseVersion(invalid), /canonical stable semver/);
  }
});

test("third-party selections declare digest-only trust limitations", async () => {
  const contracts = structuredClone(await loadContracts());
  delete contracts.releaseSelection.components.gateway.trust.limitation;
  assert.match(validateContracts(contracts).join("\n"), /must have required property 'limitation'/);
});

test("persistent backend selections require database compatibility metadata", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.releaseSelection.components["kuvert-backend"].databaseArtifact = false;
  delete contracts.releaseSelection.components["kuvert-backend"].database;
  assert.match(validateContracts(contracts).join("\n"), /databaseArtifact does not match catalog persistence/);
});
