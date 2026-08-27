import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

import { validateContracts } from "./contracts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APP_PORTS = { kuvert: 3001, tafel: 3002, zettel: 3003, glocke: 3004, schrank: 3005, herold: 3006, wachter: 3007 };
// Matches Wächter's own restart-control contract (see its README/SECURITY):
// only stateless frontend containers may ever be restarted through it, and
// every other declared service is critical - the agent gives critical=true
// precedence if a container is ever labeled both.
function restartLabels(isFrontend) {
  return isFrontend
    ? { "hof.wachter.restartable": "true", "hof.wachter.critical": "false" }
    : { "hof.wachter.critical": "true" };
}
// Matches wachter/docker-compose.yml's own hardening for both of its
// containers - a read-only root filesystem, no Linux capabilities, and no
// privilege escalation, since one of them (the agent) holds the Docker
// socket.
// hofctl plan's drift diff (see PLATFORM-OPS-PLAN.md) needs a stable way
// to tell "a Docker resource this platform generated" apart from
// anything else on the host, and to tell which installation/service/
// artifact/generation it belongs to - without ever reading
// container env (which can hold secrets). installationId/generation are
// supplied by the caller (state.mjs, once that owns generation numbers);
// a bare `hofctl render` with neither has no real installation yet, so
// they default to an empty/zero placeholder rather than failing.
function ownershipLabels({ installationId, generation, service, artifact }) {
  return {
    "hof.managed": "true",
    "hof.installation-id": installationId ?? "",
    "hof.service": service,
    "hof.artifact": artifact,
    "hof.generation": String(generation ?? 0),
  };
}
function wachterHardening() {
  return {
    read_only: true,
    tmpfs: ["/tmp"],
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
  };
}
const EXPORT_SERVICES = ["kuvert", "tafel", "zettel", "glocke", "schrank", "herold"];
const GLOCKE_PRODUCERS = ["schlussel", "kuvert", "tafel", "zettel"];

function publicOrigin(service, manifest, catalogById) {
  const hostname = catalogById.get(service)?.hostname;
  return `https://${hostname ? `${hostname}.` : ""}${manifest.domains.base}`;
}

// Shared with hofctl preflight's DNS check, which needs the exact same
// "which services get their own public hostname" answer renderCaddy
// already computes, without pulling in a release lock (preflight has
// no need for one - it's checking the host, not the release).
export function enabledServiceIds(manifest, catalog) {
  return catalog.services
    .filter((service) => service.mandatory || manifest.services?.[service.id]?.enabled === true)
    .map((service) => service.id);
}

export function publicHostnames(manifest, catalog) {
  const catalogById = new Map(catalog.services.map((service) => [service.id, service]));
  const hostnames = enabledServiceIds(manifest, catalog)
    .filter((id) => id === "schloss" || catalogById.get(id).hostname !== null)
    .map((id) => {
      const hostname = catalogById.get(id).hostname;
      return hostname ? `${hostname}.${manifest.domains.base}` : manifest.domains.base;
    });
  return [...new Set(hostnames)];
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

export function renderTopology({ manifest, catalog, releaseLock, servicesSchema, catalogSchema, releaseLockSchema, installationId = null, generation = 0 }) {
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
  const enabledIds = enabledServiceIds(manifest, catalog);
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
  compose.services.gateway.labels = { ...restartLabels(false), ...ownershipLabels({ installationId, generation, service: "tor", artifact: "gateway" }) };
  compose.services.gateway.ports = ["80:80", "443:443"];
  compose.services.gateway.volumes = ["./Caddyfile:/etc/caddy/Caddyfile:ro", "caddy-data:/data"];
  if (manifest.tls.mode === "supplied") {
    compose.services.gateway.volumes.push(
      `${manifest.tls.certificatePath}:/run/hof/tls/certificate.pem:ro`,
      `${manifest.tls.privateKeyPath}:/run/hof/tls/private-key.pem:ro`,
    );
  }
  // Deliberately no healthcheck here, matching Tor's own real
  // docker-compose.yml (it has none for the gateway) - a wget-based probe
  // can't meaningfully validate ACME certificate acquisition (which can
  // legitimately take time, retry, or fail transiently against a real
  // CA, and auto-HTTPS's HTTP->HTTPS redirect means a plain-HTTP probe
  // doesn't even reach a stable answer either way), and
  // healthyDependencies() below already excludes "tor" from any other
  // service's own service_healthy condition, so nothing needs this.

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
          // hofctl plan now owns migrations as an explicit, visible
          // database.migrate operation (see PLATFORM-OPS-PLAN.md) instead
          // of the app silently migrating itself on every boot - startup
          // only ever schema-checks.
          MIGRATE_ON_STARTUP: "false",
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
          // See the identical comment on schlussel above. (Kuvert and
          // Tafel don't yet read this var at all and always self-migrate
          // regardless - see the catalog's own database.command comment
          // on those two services.)
          MIGRATE_ON_STARTUP: "false",
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
      // Schloss shares the port-80/no-healthcheck-path shape of a
      // frontend artifact below, but per the platform's own restart
      // convention it is NOT restartable - it's the entry point itself.
      component.labels = { ...restartLabels(isFrontend), ...ownershipLabels({ installationId, generation, service: id, artifact }) };
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

    // Full replacement, not a patch on top of the generic isBackend
    // branch above - Wächter has no database and isn't a browser-facing
    // CORS target, so it doesn't take DATABASE_PATH/ALLOWED_ORIGINS, and
    // it needs its own agent-specific vars the generic branch has no
    // notion of.
    Object.assign(compose.services.wachter, {
      environment: {
        PORT: String(APP_PORTS.wachter), SCHLUSSEL_JWKS_URL: "http://schlussel:4000/.well-known/jwks.json",
        JWT_ISSUER: "schlussel", WACHTER_AGENT_URL: "http://wachter-agent:3008",
        WACHTER_AGENT_TOKEN: "${WACHTER_AGENT_TOKEN:-}", WACHTER_AGENT_TOKEN_FILE: "${WACHTER_AGENT_TOKEN_FILE:-}",
      },
      networks: ["hof", "wachter-internal"],
      depends_on: { "wachter-agent": { condition: "service_healthy" } },
      volumes: ["${WACHTER_AGENT_TOKEN_FILE:-/dev/null}:${WACHTER_AGENT_TOKEN_FILE:-/dev/null}:ro"],
      labels: { ...restartLabels(false), ...ownershipLabels({ installationId, generation, service: "wachter", artifact: "wachter-backend" }) },
      ...wachterHardening(),
    });

    compose.services["wachter-agent"] = {
      ...composeService(image, {
        PORT: "3008", WACHTER_AGENT_TOKEN: "${WACHTER_AGENT_TOKEN:-}", WACHTER_AGENT_TOKEN_FILE: "${WACHTER_AGENT_TOKEN_FILE:-}",
        WACHTER_PROC_DIR: "/host/proc", WACHTER_ROOT_DIR: "/host/rootfs-probe", WACHTER_DOCKER_SOCKET: "/var/run/docker.sock",
      }),
      // The API and its agent share one image (see the catalog's own
      // comment) - only the command differs. Without this the agent
      // container runs the API's default CMD instead of the agent.
      command: ["node", "backend/dist/agent.js"],
      networks: ["wachter-internal"],
      volumes: [
        "${WACHTER_AGENT_TOKEN_FILE:-/dev/null}:${WACHTER_AGENT_TOKEN_FILE:-/dev/null}:ro",
        "/proc:/host/proc:ro", "/etc/hostname:/host/rootfs-probe:ro", "/var/run/docker.sock:/var/run/docker.sock",
      ],
      group_add: ["${DOCKER_GID:-998}"],
      healthcheck: healthcheck(3008, "/health"),
      labels: { ...restartLabels(false), ...ownershipLabels({ installationId, generation, service: "wachter", artifact: "wachter-backend" }) },
      ...wachterHardening(),
    };
    compose.networks["wachter-internal"] = { internal: true };
  }
  for (const id of enabledIds) for (const volume of catalogById.get(id).volumes) compose.volumes[volume] = { name: volume };

  const healthTargets = enabledIds.map((id) => {
    const service = catalogById.get(id);
    const port = id === "tor" ? 80 : id === "schlussel" ? 4000 : service.health.component.endsWith("-frontend") || id === "schloss" ? 80 : APP_PORTS[id] ?? 3007;
    const component = id === "wachter" ? "wachter" : service.health.component;
    return { service: id, component, url: `http://${component}:${port}${service.health.path}`, dependsOn: service.dependsOn };
  });
  const backupVolumes = enabledIds.flatMap((id) => catalogById.get(id).volumes.map((volume) => ({ service: id, volume })));
  // hofctl plan's database.migrate operations (see PLATFORM-OPS-PLAN.md)
  // need to know, per enabled persistent service, which schema version
  // this release's pinned image actually expects - the release lock
  // already carries that per component (build-release-lock.mjs's own
  // schema check depends on it), this just surfaces it alongside the
  // rest of the rendered topology instead of making plan.mjs reach back
  // into the release lock a second time.
  const databaseSchemas = Object.fromEntries(
    enabledIds
      .map((id) => catalogById.get(id))
      .filter((service) => service.database)
      .map((service) => [service.id, releaseLock.components[service.database.component].database]),
  );
  const topology = {
    apiVersion: "hof.dev/rendered-topology/v1", release: releaseLock.release, enabledServices: enabledIds,
    serviceFlags: appFlags, publicOrigins: origins, trustedOrigins, exportTargets, deletionTargets,
    glockeProducers: producers, healthTargets, backupVolumes, databaseSchemas,
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
