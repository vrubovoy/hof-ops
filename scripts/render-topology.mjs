import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

import { validateContracts } from "./contracts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APP_PORTS = { kuvert: 3001, tafel: 3002, zettel: 3003, glocke: 3004, schrank: 3005, herold: 3006 };
const EXPORT_SERVICES = ["kuvert", "tafel", "zettel", "glocke", "schrank", "herold"];
const GLOCKE_PRODUCERS = ["schlussel", "kuvert", "tafel", "zettel"];

function publicOrigin(service, manifest, catalogById) {
  const hostname = catalogById.get(service)?.hostname;
  return `https://${hostname ? `${hostname}.` : ""}${manifest.domains.base}`;
}

function envName(service) {
  return service.toUpperCase().replaceAll("-", "_");
}

function composeService(image, environment = {}) {
  return {
    image,
    restart: "unless-stopped",
    environment,
    networks: ["hof"],
  };
}

function healthcheck(port, healthPath) {
  return {
    test: ["CMD", "wget", "-qO-", `http://localhost:${port}${healthPath}`],
    interval: "30s",
    timeout: "5s",
    retries: 3,
  };
}

function healthyDependencies(service, catalogById) {
  return Object.fromEntries(
    service.dependsOn
      .filter((id) => id !== "tor")
      .map((id) => [catalogById.get(id).health.component, { condition: "service_healthy" }]),
  );
}

export function renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema }) {
  const errors = validateContracts({
    servicesSchema,
    catalogSchema,
    releaseLockSchema,
    manifest,
    catalog,
    releaseLock,
  });
  if (errors.length) throw new Error(`contracts are invalid:\n${errors.join("\n")}`);
  if (manifest.release !== releaseLock.release) {
    throw new Error(`services.yml release ${manifest.release} does not match release lock ${releaseLock.release}`);
  }

  const catalogById = new Map(catalog.services.map((service) => [service.id, service]));
  const enabledIds = catalog.services
    .filter((service) => service.mandatory || manifest.services?.[service.id]?.enabled === true)
    .map((service) => service.id);
  const enabled = new Set(enabledIds);
  for (const id of enabled) {
    for (const dependency of catalogById.get(id).dependsOn) {
      if (!enabled.has(dependency)) throw new Error(`enabled service ${id} requires disabled service ${dependency}`);
    }
  }

  const origins = Object.fromEntries(enabledIds.map((id) => [id, publicOrigin(id, manifest, catalogById)]));
  const browserOrigins = enabledIds.filter((id) => id !== "tor" && catalogById.get(id).hostname !== null).map((id) => origins[id]);
  const trustedOrigins = [origins.schloss, ...browserOrigins.filter((origin) => origin !== origins.schloss)];
  const appFlags = Object.fromEntries(catalog.services.filter((service) => !service.mandatory).map((service) => [service.id, enabled.has(service.id)]));
  const compose = { name: "hof", services: {}, volumes: {}, networks: { hof: {} } };

  compose.services.gateway = composeService(releaseLock.components.gateway.image, { DOMAIN: manifest.domains.base });
  compose.services.gateway.ports = ["80:80", "443:443"];
  compose.services.gateway.volumes = ["./Caddyfile:/etc/caddy/Caddyfile:ro", "caddy-data:/data"];
  if (manifest.tls.mode === "supplied") {
    compose.services.gateway.volumes.push(
      `${manifest.tls.certificatePath}:/run/hof/tls/certificate.pem:ro`,
      `${manifest.tls.privateKeyPath}:/run/hof/tls/private-key.pem:ro`,
    );
  }
  compose.services.gateway.healthcheck = healthcheck(80, "/");

  const exportTargets = {};
  const deletionTargets = {};
  for (const id of EXPORT_SERVICES.filter((service) => enabled.has(service))) {
    const port = APP_PORTS[id];
    exportTargets[id] = `http://${id}-backend:${port}/exports/me`;
    deletionTargets[id] = `http://${id}-backend:${port}/internal/v1/account-deletions`;
  }
  const producers = GLOCKE_PRODUCERS.filter((service) => enabled.has("glocke") && enabled.has(service));

  for (const id of enabledIds.filter((service) => service !== "tor")) {
    const service = catalogById.get(id);
    for (const artifact of service.artifacts) {
      const component = composeService(releaseLock.components[artifact].image);
      const isFrontend = artifact.endsWith("-frontend");
      const isBackend = artifact.endsWith("-backend");
      let port = isFrontend || artifact === "schloss" ? 80 : id === "schlussel" ? 4000 : APP_PORTS[id];

      if (artifact === "schlussel") {
        component.environment = {
          PORT: "4000", DATABASE_PATH: "/data/schlussel.db", KEYS_DIR: "/data/keys", EXPORT_DIR: "/data/exports",
          JWT_ISSUER: "schlussel", ALLOWED_ORIGINS: trustedOrigins.join(","),
          ...Object.fromEntries(Object.entries(exportTargets).map(([name, url]) => [`${envName(name)}_EXPORT_URL`, url])),
          ...Object.fromEntries(Object.entries(deletionTargets).map(([name, url]) => [`${envName(name)}_DELETION_URL`, url])),
          GLOCKE_ENABLED: String(enabled.has("glocke")),
        };
        if (enabled.has("glocke")) Object.assign(component.environment, {
          GLOCKE_BASE_URL: `http://glocke-backend:${APP_PORTS.glocke}`,
          SCHLUSSEL_TO_GLOCKE_HMAC_KEY_ID: "schlussel-v1",
          SCHLUSSEL_TO_GLOCKE_HMAC_SECRET: "${SCHLUSSEL_TO_GLOCKE_HMAC_SECRET:?required}",
          GLOCKE_TO_SCHLUSSEL_HMAC_KEY_ID: "glocke-v1",
          GLOCKE_TO_SCHLUSSEL_HMAC_SECRET: "${GLOCKE_TO_SCHLUSSEL_HMAC_SECRET:?required}",
        });
      } else if (artifact === "schlussel-frontend") {
        component.environment = {
          ALLOWED_RETURN_ORIGINS: trustedOrigins.join(","), DEFAULT_APP_URL: origins.schloss,
          GLOCKE_ENABLED: String(enabled.has("glocke")), ...(enabled.has("glocke") ? { GLOCKE_URL: origins.glocke } : {}),
        };
      } else if (artifact === "schloss") {
        component.environment = { SCHLUSSEL_WEB_URL: origins.schlussel, WACHTER_ENABLED: String(enabled.has("wachter")) };
        for (const optional of EXPORT_SERVICES) if (enabled.has(optional)) component.environment[`${envName(optional)}_URL`] = origins[optional];
      } else if (isBackend) {
        component.environment = {
          PORT: String(APP_PORTS[id]), DATABASE_PATH: `/data/${id}.db`, JWT_ISSUER: "schlussel",
          SCHLUSSEL_JWKS_URL: "http://schlussel:4000/.well-known/jwks.json",
          ALLOWED_ORIGINS: [origins.schloss, origins.schlussel, origins[id]].filter(Boolean).join(","),
        };
        if (enabled.has("glocke") && producers.includes(id)) Object.assign(component.environment, {
          GLOCKE_BASE_URL: `http://glocke-backend:${APP_PORTS.glocke}`,
          [`${envName(id)}_TO_GLOCKE_HMAC_KEY_ID`]: `${id}-v1`,
          [`${envName(id)}_TO_GLOCKE_HMAC_SECRET`]: `\${${envName(id)}_TO_GLOCKE_HMAC_SECRET:?required}`,
        });
        if (id === "glocke") {
          component.environment = {
            ...component.environment, ALLOWED_ORIGINS: trustedOrigins.join(","), SCHLUSSEL_INTERNAL_URL: "http://schlussel:4000",
            GLOCKE_PUBLIC_URL: origins.glocke, GLOCKE_EVENT_SOURCES: producers.join(","),
            GLOCKE_TO_SCHLUSSEL_HMAC_KEY_ID: "glocke-v1",
            GLOCKE_TO_SCHLUSSEL_HMAC_SECRET: "${GLOCKE_TO_SCHLUSSEL_HMAC_SECRET:?required}",
            GLOCKE_BROWSER_PUSH_ENABLED: String(manifest.features?.browserPush?.enabled === true),
          };
          for (const producer of producers) Object.assign(component.environment, {
            [`GLOCKE_SOURCE_KEY_ID_${envName(producer)}`]: `${producer}-v1`,
            [`GLOCKE_SOURCE_SECRET_${envName(producer)}`]: `\${${envName(producer)}_TO_GLOCKE_HMAC_SECRET:?required}`,
          });
          if (enabled.has("kuvert")) component.environment.KUVERT_ORIGIN = origins.kuvert;
          if (enabled.has("tafel")) component.environment.TAFEL_ORIGIN = origins.tafel;
          if (manifest.features?.browserPush?.enabled) Object.assign(component.environment, {
            GLOCKE_VAPID_SUBJECT: manifest.features.browserPush.subject,
            GLOCKE_VAPID_PUBLIC_KEY: "${GLOCKE_VAPID_PUBLIC_KEY:?required}",
            GLOCKE_VAPID_PRIVATE_KEY: "${GLOCKE_VAPID_PRIVATE_KEY:?required}",
            GLOCKE_PUSH_ALLOWED_ENDPOINT_HOSTS: "${GLOCKE_PUSH_ALLOWED_ENDPOINT_HOSTS:?required}",
          });
        }
        if (id === "herold") component.environment.HEROLD_CREDENTIAL_ENCRYPTION_KEY = "${HEROLD_CREDENTIAL_ENCRYPTION_KEY:?required}";
      } else if (isFrontend) {
        component.environment = {
          SCHLUSSEL_WEB_URL: origins.schlussel, SCHLOSS_URL: origins.schloss,
          GLOCKE_ENABLED: String(enabled.has("glocke")), ...(enabled.has("glocke") ? { GLOCKE_URL: origins.glocke } : {}),
        };
      }

      if (service.volumes.length && !isFrontend && artifact !== "schloss") component.volumes = service.volumes.map((volume) => `${volume}:/data`);
      if (artifact === service.health.component) component.healthcheck = healthcheck(port, service.health.path);
      else if (isFrontend || artifact === "schloss") component.healthcheck = healthcheck(80, "/");
      const dependencies = healthyDependencies(service, catalogById);
      if (isFrontend && service.artifacts.some((name) => name.endsWith("-backend"))) dependencies[`${id}-backend`] = { condition: "service_healthy" };
      if (Object.keys(dependencies).length) component.depends_on = dependencies;
      compose.services[artifact] = component;
    }
  }

  if (enabled.has("wachter")) {
    const image = releaseLock.components["wachter-backend"].image;
    compose.services.wachter = compose.services["wachter-backend"];
    delete compose.services["wachter-backend"];
    compose.services["wachter-agent"] = composeService(image, { PORT: "3008" });
    compose.networks["wachter-internal"] = { internal: true };
    compose.services["wachter-agent"].environment.WACHTER_AGENT_TOKEN = "${WACHTER_AGENT_TOKEN:?required}";
    compose.services["wachter-agent"].environment.WACHTER_PROC_DIR = "/host/proc";
    compose.services["wachter-agent"].environment.WACHTER_ROOT_DIR = "/host/rootfs-probe";
    compose.services["wachter-agent"].environment.WACHTER_DOCKER_SOCKET = "/var/run/docker.sock";
    compose.services["wachter-agent"].networks = ["wachter-internal"];
    compose.services["wachter-agent"].volumes = ["/proc:/host/proc:ro", "/etc/hostname:/host/rootfs-probe:ro", "/var/run/docker.sock:/var/run/docker.sock"];
    compose.services["wachter-agent"].group_add = ["${DOCKER_GID:-998}"];
    compose.services["wachter-agent"].healthcheck = healthcheck(3008, "/health");
    compose.services.wachter.environment.WACHTER_AGENT_URL = "http://wachter-agent:3008";
    compose.services.wachter.environment.WACHTER_AGENT_TOKEN = "${WACHTER_AGENT_TOKEN:?required}";
    compose.services.wachter.networks = ["hof", "wachter-internal"];
    compose.services.wachter.depends_on = { "wachter-agent": { condition: "service_healthy" } };
  }
  for (const id of enabledIds) for (const volume of catalogById.get(id).volumes) compose.volumes[volume] = { name: volume };

  const healthTargets = enabledIds.map((id) => {
    const service = catalogById.get(id);
    const port = id === "tor" ? 80 : id === "schlussel" ? 4000 : service.health.component.endsWith("-frontend") || id === "schloss" ? 80 : APP_PORTS[id] ?? 3007;
    const component = id === "wachter" ? "wachter" : service.health.component;
    return { service: id, component, url: `http://${component}:${port}${service.health.path}`, dependsOn: service.dependsOn };
  });
  const backupVolumes = enabledIds.flatMap((id) => catalogById.get(id).volumes.map((volume) => ({ service: id, volume })));
  const topology = {
    apiVersion: "hof.dev/rendered-topology/v1", release: releaseLock.release, enabledServices: enabledIds,
    serviceFlags: appFlags, publicOrigins: origins, trustedOrigins, exportTargets, deletionTargets,
    glockeProducers: producers, healthTargets, backupVolumes,
  };

  return {
    compose,
    caddyfile: renderCaddy(manifest, enabledIds, catalogById),
    runtimeConfig: { schemaVersion: 1, services: appFlags, links: origins },
    environment: renderEnv(topology, manifest),
    topology,
    backup: { schedule: manifest.backup.schedule, retention: manifest.backup.retention, destinations: manifest.backup.destinations, volumes: backupVolumes },
  };
}

function renderCaddy(manifest, enabledIds, catalogById) {
  const lines = manifest.tls.mode === "acme-http01" ? [`{`, `\temail ${manifest.tls.email}`, `}`, ""] : [];
  for (const id of enabledIds.filter((service) => service === "schloss" || catalogById.get(service).hostname !== null)) {
    const service = catalogById.get(id);
    const host = service.hostname ? `${service.hostname}.${manifest.domains.base}` : manifest.domains.base;
    const upstream = id === "schlussel" ? "schlussel-frontend" : id === "schloss" ? "schloss" : `${id}-frontend`;
    lines.push(`${host} {`);
    if (manifest.tls.mode === "supplied") lines.push("\ttls /run/hof/tls/certificate.pem /run/hof/tls/private-key.pem");
    lines.push("\theader {", '\t\tX-Content-Type-Options "nosniff"', '\t\tReferrer-Policy "strict-origin-when-cross-origin"', "\t}");
    if (id === "glocke") {
      lines.push("\t@serviceWorker path /sw.js", "\treverse_proxy @serviceWorker glocke-frontend:80 {", '\t\theader_down Content-Type "application/javascript; charset=utf-8"', '\t\theader_down Cache-Control "no-cache"', "\t}");
    }
    lines.push(`\treverse_proxy ${upstream}:80`, "}", "");
  }
  return `${lines.join("\n")}\n`;
}

function renderEnv(topology, manifest) {
  const lines = [`HOF_RELEASE=${topology.release}`, `HOF_DOMAIN=${manifest.domains.base}`, `HOF_ENABLED_SERVICES=${topology.enabledServices.join(",")}`];
  for (const [service, enabled] of Object.entries(topology.serviceFlags)) lines.push(`HOF_SERVICE_${envName(service)}_ENABLED=${enabled}`);
  lines.push(`SCHLUSSEL_ALLOWED_ORIGINS=${topology.trustedOrigins.join(",")}`);
  lines.push(`ALLOWED_RETURN_ORIGINS=${topology.trustedOrigins.join(",")}`);
  lines.push(`GLOCKE_EVENT_SOURCES=${topology.glockeProducers.join(",")}`);
  return `${lines.join("\n")}\n`;
}

export async function renderFiles(options) {
  const [manifestText, catalogText, lockText, servicesSchema, catalogSchema, releaseLockSchema] = await Promise.all([
    readFile(options.services, "utf8"), readFile(options.catalog, "utf8"), readFile(options.releaseLock, "utf8"),
    readFile(path.join(root, "schemas/services-v1alpha1.schema.json"), "utf8"),
    readFile(path.join(root, "schemas/service-catalog-v1.schema.json"), "utf8"),
    readFile(path.join(root, "schemas/release-lock-v1.schema.json"), "utf8"),
  ]);
  const rendered = renderTopology({
    manifest: YAML.parse(manifestText), catalog: YAML.parse(catalogText), releaseLock: JSON.parse(lockText),
    servicesSchema: JSON.parse(servicesSchema), catalogSchema: JSON.parse(catalogSchema), releaseLockSchema: JSON.parse(releaseLockSchema),
  });
  await mkdir(options.out, { recursive: true });
  const files = {
    "compose.yml": YAML.stringify(rendered.compose, { sortMapEntries: true }), "Caddyfile": rendered.caddyfile,
    "runtime-config.json": `${JSON.stringify(rendered.runtimeConfig, null, 2)}\n`, "service.env": rendered.environment,
    "topology.json": `${JSON.stringify(rendered.topology, null, 2)}\n`, "backup-inventory.json": `${JSON.stringify(rendered.backup, null, 2)}\n`,
  };
  await Promise.all(Object.entries(files).map(([name, contents]) => writeFile(path.join(options.out, name), contents)));
  return Object.keys(files);
}
