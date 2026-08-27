import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import YAML from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(root, relativePath), "utf8"));
}

async function readYaml(relativePath) {
  return YAML.parse(await readFile(path.join(root, relativePath), "utf8"));
}

export async function loadContracts() {
  const [servicesSchema, catalogSchema, releaseLockSchema, releaseSelectionSchema, stableChannelSchema, manifest, catalog, releaseLock, releaseSelection, stableChannel] =
    await Promise.all([
      readJson("schemas/services-v1alpha1.schema.json"),
      readJson("schemas/service-catalog-v1.schema.json"),
      readJson("schemas/release-lock-v1.schema.json"),
      readJson("schemas/release-selection-v1.schema.json"),
      readJson("schemas/stable-channel-v1.schema.json"),
      readYaml("examples/services.yml"),
      readYaml("catalog/services-v1.yaml"),
      readJson("examples/release-lock.json"),
      readYaml("examples/release-selection.yml"),
      readJson("examples/stable-channel.json")
    ]);

  return {
    servicesSchema, catalogSchema, releaseLockSchema, releaseSelectionSchema, stableChannelSchema,
    manifest, catalog, releaseLock, releaseSelection, stableChannel,
  };
}

export function validateContracts(contracts) {
  // strictRequired is relaxed only for the release-lock schema's
  // component "third-party pin" branch, which intentionally requires
  // `thirdParty` without also declaring it in a `properties` block of
  // its own (that block lives one level up, shared by both branches).
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);

  const errors = [];
  const checks = [
    [contracts.servicesSchema, contracts.manifest, "services.yml"],
    [contracts.catalogSchema, contracts.catalog, "service catalog"],
    [contracts.releaseLockSchema, contracts.releaseLock, "release lock"]
  ];
  if (contracts.releaseSelectionSchema && contracts.releaseSelection) {
    checks.push([contracts.releaseSelectionSchema, contracts.releaseSelection, "release selection"]);
  }
  if (contracts.stableChannelSchema && contracts.stableChannel) {
    checks.push([contracts.stableChannelSchema, contracts.stableChannel, "stable channel"]);
  }

  for (const [schema, value, label] of checks) {
    const validate = ajv.compile(schema);
    if (!validate(value)) {
      for (const error of validate.errors ?? []) {
        errors.push(`${label}${error.instancePath || "/"}: ${error.message}`);
      }
    }
  }

  errors.push(...validateCatalog(contracts.catalog));
  errors.push(...validateManifest(contracts.manifest, contracts.catalog));
  errors.push(...validateReleaseLock(contracts.releaseLock, contracts.catalog));
  if (contracts.releaseSelection) errors.push(...validateReleaseSelection(contracts.releaseSelection, contracts.catalog));
  return errors;
}

function validateReleaseSelection(selection, catalog) {
  const errors = [];
  const expected = new Set((catalog.services ?? []).flatMap((service) => service.artifacts ?? []));
  const databaseArtifacts = new Set(
    (catalog.services ?? [])
      .filter((service) => service.id !== "tor" && service.volumes.length > 0)
      .map((service) => service.health.component)
  );
  const actual = new Set(Object.keys(selection.components ?? {}));
  for (const artifact of expected) {
    if (!actual.has(artifact)) errors.push(`release selection: missing catalog artifact ${artifact}`);
  }
  for (const artifact of actual) {
    if (!expected.has(artifact)) errors.push(`release selection: unknown catalog artifact ${artifact}`);
    const component = selection.components[artifact];
    if (!component.thirdParty && !component.image.endsWith(`:v${component.version}`)) {
      errors.push(`release selection: ${artifact} image tag must equal v plus selected version`);
    }
    if (!component.thirdParty && component.databaseArtifact !== databaseArtifacts.has(artifact)) {
      errors.push(`release selection: ${artifact} databaseArtifact does not match catalog persistence`);
    }
  }
  return errors;
}

function validateCatalog(catalog) {
  const errors = [];
  const services = new Map();
  const artifacts = new Set();

  for (const service of catalog.services ?? []) {
    if (services.has(service.id)) {
      errors.push(`service catalog: duplicate service ${service.id}`);
    }
    services.set(service.id, service);

    for (const artifact of service.artifacts ?? []) {
      if (artifacts.has(artifact)) {
        errors.push(`service catalog: duplicate artifact ${artifact}`);
      }
      artifacts.add(artifact);
    }
  }

  for (const id of ["tor", "schlussel", "schloss"]) {
    if (!services.get(id)?.mandatory) {
      errors.push(`service catalog: ${id} must be mandatory`);
    }
  }

  for (const service of services.values()) {
    for (const dependency of service.dependsOn ?? []) {
      if (!services.has(dependency)) {
        errors.push(`service catalog: ${service.id} has unknown dependency ${dependency}`);
      }
      if (dependency === service.id) {
        errors.push(`service catalog: ${service.id} depends on itself`);
      }
    }
    if (!(service.artifacts ?? []).includes(service.health?.component)) {
      errors.push(`service catalog: ${service.id} health component is not its artifact`);
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) {
      errors.push(`service catalog: dependency cycle includes ${id}`);
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of services.get(id)?.dependsOn ?? []) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of services.keys()) visit(id);

  return errors;
}

function validateManifest(manifest, catalog) {
  const errors = [];
  const optionalServices = new Set(
    (catalog.services ?? []).filter((service) => !service.mandatory).map((service) => service.id)
  );

  for (const service of Object.keys(manifest.services ?? {})) {
    if (!optionalServices.has(service)) {
      errors.push(`services.yml: ${service} is not an optional catalog service`);
    }
  }

  if (manifest.features?.browserPush?.enabled) {
    if (!manifest.services?.glocke?.enabled) errors.push("services.yml: browserPush requires glocke");
    if (!manifest.features.browserPush.subject) errors.push("services.yml: browserPush.enabled requires subject");
    if (!manifest.features.browserPush.allowedEndpointHosts?.length) {
      errors.push("services.yml: browserPush.enabled requires at least one allowedEndpointHosts entry");
    }
  }

  const destinations = new Set();
  for (const destination of manifest.backup?.destinations ?? []) {
    if (destinations.has(destination.name)) {
      errors.push(`services.yml: duplicate backup destination ${destination.name}`);
    }
    destinations.add(destination.name);
  }

  return errors;
}

function validateReleaseLock(releaseLock, catalog) {
  const errors = [];
  const expected = new Set((catalog.services ?? []).flatMap((service) => service.artifacts ?? []));
  const actual = new Set(Object.keys(releaseLock.components ?? {}));

  for (const artifact of expected) {
    if (!actual.has(artifact)) errors.push(`release lock: missing catalog artifact ${artifact}`);
  }
  for (const artifact of actual) {
    if (!expected.has(artifact)) errors.push(`release lock: unknown catalog artifact ${artifact}`);
  }

  return errors;
}
