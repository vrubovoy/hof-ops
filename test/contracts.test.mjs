import assert from "node:assert/strict";
import test from "node:test";

import { loadContracts, validateContracts } from "../scripts/contracts.mjs";

test("repository contract examples are valid", async () => {
  const contracts = await loadContracts();
  assert.deepEqual(validateContracts(contracts), []);
});

test("browser push requires Glocke", async () => {
  const contracts = structuredClone(await loadContracts());
  contracts.manifest.services.glocke.enabled = false;

  assert.match(validateContracts(contracts).join("\n"), /browserPush requires glocke/);
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
