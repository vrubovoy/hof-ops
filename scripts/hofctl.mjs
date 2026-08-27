#!/usr/bin/env node
import path from "node:path";
import process from "node:process";

import { runPlan } from "./plan-command.mjs";
import { runPreflight } from "./preflight.mjs";
import { renderFiles } from "./render-topology.mjs";
import { validateDeployment } from "./validate-deployment.mjs";

const BOOLEAN_FLAGS = new Set(["--skip-signature"]);

function usage(message) {
  if (message) console.error(message);
  console.error("usage: hofctl render --services <services.yml> --release-lock <release-lock.json> --catalog <catalog.yaml> --out <directory>");
  console.error("       hofctl validate --services <services.yml> --release-lock <release-lock.json> [--catalog <catalog.yaml>] [--release-selection <file>] [--stable-channel <file>] [--release-lock-signature <file>] [--release-lock-certificate <file>] [--release-lock-identity <identity>] [--release-lock-oidc-issuer <issuer>] [--skip-signature]");
  console.error("       hofctl preflight --services <services.yml> [--catalog <catalog.yaml>] [--target-mode ssh|local] [--known-hosts <file> | --host-key-sha256 <sha>] [--identity-file <path>] [--connect-timeout-seconds <n>] [--min-free-disk-gb <n>] [--min-memory-gb <n>] [--min-cpu-cores <n>]");
  console.error("       hofctl plan --services <services.yml> --release-lock <release-lock.json> --release-lock-identity <identity> (--known-hosts <file> | --host-key-sha256 <sha>) [--catalog <catalog.yaml>] [--identity-file <path>] [--target-mode ssh|local] [--connect-timeout-seconds <n>] [--repair-drift]");
  process.exitCode = 2;
}

// Shared "--flag value" (or bare boolean "--flag") parser for every
// subcommand - `--release-lock-identity` becomes `releaseLockIdentity`,
// matching validateDeployment's own option shape.
function parseFlags(args) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!flag?.startsWith("--")) { usage(`unexpected argument: ${flag}`); return null; }
    const key = flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (BOOLEAN_FLAGS.has(flag)) { options[key] = true; continue; }
    const value = args[++index];
    if (!value) { usage(`${flag} requires a value`); return null; }
    options[key] = value;
  }
  return options;
}

// Every path-valued option gets resolved against the CWD up front so the
// rest of each subcommand never has to think about relative paths.
function resolvePaths(options, keys) {
  for (const key of keys) {
    if (typeof options[key] === "string") options[key] = path.resolve(options[key]);
  }
  return options;
}

// Number("nope") is NaN, and NaN < anything is false - a garbage
// --min-free-disk-gb would otherwise make every threshold check
// silently pass instead of failing loudly on bad input. Returns
// undefined when the flag wasn't given at all; throws a flagName-
// tagged error (caught by the caller, turned into one usage() call) on
// a given-but-invalid value.
function parsePositiveNumber(rawValue, flagName) {
  if (rawValue === undefined) return undefined;
  const value = Number(rawValue);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${flagName} must be a non-negative number, got ${JSON.stringify(rawValue)}`);
  return value;
}

// target-inspector.mjs's own connectTimeoutSeconds contract is a
// positive integer (0 or fractional seconds both rejected there too) -
// this must reject the same values here, at the CLI boundary, rather
// than let a "5.5" or "0" through only to fail deeper inside a real SSH
// connection attempt.
function parsePositiveInteger(rawValue, flagName) {
  if (rawValue === undefined) return undefined;
  const value = Number(rawValue);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${flagName} must be a positive integer, got ${JSON.stringify(rawValue)}`);
  return value;
}

// plan gets its own, stricter flag parser rather than reusing
// parseFlags() above - plan is the one subcommand where a silently
// accepted duplicate or unknown flag (e.g. a typo'd --skip-signature,
// which parseFlags would just fold into options and ignore since it
// only maps flags it's told to look at) could make an operator believe
// a plan was computed under different, safer conditions than the ones
// that actually ran. --skip-signature specifically is rejected with its
// own message - plan always verifies the release lock's real signature,
// unlike validate.
const PLAN_FLAGS = new Set([
  "--services", "--release-lock", "--release-lock-identity", "--known-hosts", "--host-key-sha256",
  "--catalog", "--identity-file", "--target-mode", "--connect-timeout-seconds", "--repair-drift",
]);
const PLAN_BOOLEAN_FLAGS = new Set(["--repair-drift"]);

function parsePlanFlags(args) {
  const options = {};
  const seen = new Set();
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!flag?.startsWith("--")) { usage(`unexpected argument: ${flag}`); return null; }
    if (flag === "--skip-signature") { usage("plan does not accept --skip-signature - it always verifies the release lock's real signature"); return null; }
    if (!PLAN_FLAGS.has(flag)) { usage(`unknown flag for plan: ${flag}`); return null; }
    if (seen.has(flag)) { usage(`duplicate flag: ${flag}`); return null; }
    seen.add(flag);
    const key = flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (PLAN_BOOLEAN_FLAGS.has(flag)) { options[key] = true; continue; }
    const value = args[++index];
    if (!value) { usage(`${flag} requires a value`); return null; }
    options[key] = value;
  }
  return options;
}

const [command, ...args] = process.argv.slice(2);

if (command === "render") {
  const options = parseFlags(args);
  if (options) {
    resolvePaths(options, ["services", "releaseLock", "catalog", "out"]);
    const normalized = { services: options.services, releaseLock: options.releaseLock, catalog: options.catalog, out: options.out };
    if (Object.values(normalized).some((value) => !value)) usage("render requires --services, --release-lock, --catalog, and --out");
    else {
      try {
        const files = await renderFiles(normalized);
        console.log(`rendered ${files.join(", ")} to ${normalized.out}`);
      } catch (error) {
        console.error(error instanceof Error ? error.message : error);
        process.exitCode = 1;
      }
    }
  }
} else if (command === "validate") {
  const options = parseFlags(args);
  if (options) {
    resolvePaths(options, [
      "servicesPath", "catalogPath", "releaseLockPath", "releaseSelectionPath", "stableChannelPath",
      "releaseLockSignature", "releaseLockCertificate",
    ]);
    // hofctl's own CLI vocabulary matches render's (--services,
    // --release-lock, --catalog); validateDeployment's option names are
    // the more explicit *Path forms shared with its own standalone CLI.
    const normalized = {
      ...options,
      servicesPath: options.services ? path.resolve(options.services) : options.servicesPath,
      releaseLockPath: options.releaseLock ? path.resolve(options.releaseLock) : options.releaseLockPath,
      catalogPath: options.catalog ? path.resolve(options.catalog) : options.catalogPath,
    };
    if (!normalized.servicesPath || !normalized.releaseLockPath) {
      usage("validate requires --services and --release-lock");
    } else {
      try {
        const errors = await validateDeployment(normalized);
        for (const error of errors) console.log(JSON.stringify({ type: "validate.error", message: error }));
        console.log(JSON.stringify({ type: "validate.result", valid: errors.length === 0, errorCount: errors.length }));
        if (errors.length > 0) process.exitCode = 1;
      } catch (error) {
        console.log(JSON.stringify({ type: "validate.fatal", message: error instanceof Error ? error.message : String(error) }));
        process.exitCode = 1;
      }
    }
  }
} else if (command === "preflight") {
  const options = parseFlags(args);
  if (options) {
    resolvePaths(options, ["services", "catalog", "knownHosts", "identityFile"]);
    const targetMode = options.targetMode ?? "ssh";
    if (!options.services) {
      usage("preflight requires --services");
    } else if (!["ssh", "local"].includes(targetMode)) {
      usage("--target-mode must be ssh or local");
    } else if (targetMode === "ssh" && Boolean(options.knownHosts) === Boolean(options.hostKeySha256)) {
      usage("ssh mode requires exactly one of --known-hosts or --host-key-sha256");
    } else if (targetMode === "local" && (options.knownHosts || options.hostKeySha256 || options.identityFile)) {
      usage("--target-mode local does not accept --known-hosts/--host-key-sha256/--identity-file");
    } else {
      try {
        const connectTimeoutSeconds = parsePositiveInteger(options.connectTimeoutSeconds, "--connect-timeout-seconds");
        const minFreeDiskGb = parsePositiveNumber(options.minFreeDiskGb, "--min-free-disk-gb");
        const minMemoryGb = parsePositiveNumber(options.minMemoryGb, "--min-memory-gb");
        const minCpuCores = parsePositiveNumber(options.minCpuCores, "--min-cpu-cores");
        const preflightOptions = {
          manifestPath: options.services,
          catalogPath: options.catalog,
          targetMode,
          knownHostsFile: options.knownHosts,
          hostKeySha256: options.hostKeySha256,
          identityFile: options.identityFile,
          connectTimeoutSeconds,
          ...(minFreeDiskGb !== undefined ? { minFreeDiskBytes: minFreeDiskGb * 1024 ** 3 } : {}),
          ...(minMemoryGb !== undefined ? { minTotalMemoryBytes: minMemoryGb * 1024 ** 3 } : {}),
          ...(minCpuCores !== undefined ? { minCpuCores } : {}),
        };
        const { checks, ok } = await runPreflight(preflightOptions);
        for (const entry of checks) console.log(JSON.stringify({ type: "preflight.check", ...entry }));
        console.log(JSON.stringify({ type: "preflight.result", ok }));
        if (!ok) process.exitCode = 1;
      } catch (error) {
        if (/must be a (non-negative number|positive integer)/.test(error?.message ?? "")) {
          usage(error.message);
        } else {
          console.log(JSON.stringify({ type: "preflight.fatal", message: error instanceof Error ? error.message : String(error) }));
          process.exitCode = 1;
        }
      }
    }
  }
} else if (command === "plan") {
  const options = parsePlanFlags(args);
  if (options) {
    resolvePaths(options, ["services", "releaseLock", "catalog", "knownHosts", "identityFile"]);
    const targetMode = options.targetMode ?? "ssh";
    if (!options.services || !options.releaseLock || !options.releaseLockIdentity) {
      usage("plan requires --services, --release-lock, and --release-lock-identity");
    } else if (!["ssh", "local"].includes(targetMode)) {
      usage("--target-mode must be ssh or local");
    } else if (targetMode === "ssh" && Boolean(options.knownHosts) === Boolean(options.hostKeySha256)) {
      usage("ssh mode requires exactly one of --known-hosts or --host-key-sha256");
    } else if (targetMode === "local" && (options.knownHosts || options.hostKeySha256 || options.identityFile)) {
      usage("--target-mode local does not accept --known-hosts/--host-key-sha256/--identity-file");
    } else {
      try {
        const connectTimeoutSeconds = parsePositiveInteger(options.connectTimeoutSeconds, "--connect-timeout-seconds");
        const { blocked, plan, diagnostics } = await runPlan({
          manifestPath: options.services,
          catalogPath: options.catalog,
          releaseLockPath: options.releaseLock,
          releaseLockIdentity: options.releaseLockIdentity,
          targetMode,
          knownHostsFile: options.knownHosts,
          hostKeySha256: options.hostKeySha256,
          identityFile: options.identityFile,
          connectTimeoutSeconds,
          repairDrift: options.repairDrift === true,
        });
        if (blocked) {
          // Diagnostics only - stdout must stay reserved for exactly
          // one raw plan-v1 document, or nothing at all.
          for (const line of diagnostics) console.error(line);
          process.exitCode = 1;
        } else {
          console.log(JSON.stringify(plan));
          if (!plan.executable) process.exitCode = 1;
        }
      } catch (error) {
        if (/must be a positive integer/.test(error?.message ?? "")) {
          usage(error.message);
        } else {
          console.error(error instanceof Error ? error.message : String(error));
          process.exitCode = 1;
        }
      }
    }
  }
} else {
  usage(command ? `unknown command: ${command}` : "a command is required");
}
