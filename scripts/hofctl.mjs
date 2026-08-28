#!/usr/bin/env node
import path from "node:path";
import process from "node:process";

import { runApply } from "./apply.mjs";
import { runPlan } from "./plan-command.mjs";
import { runPreflight } from "./preflight.mjs";
import { renderFiles } from "./render-topology.mjs";
import { runSecretsEnsure } from "./secrets.mjs";
import { validateDeployment } from "./validate-deployment.mjs";

const BOOLEAN_FLAGS = new Set(["--skip-signature"]);

function usage(message) {
  if (message) console.error(message);
  console.error("usage: hofctl render --services <services.yml> --release-lock <release-lock.json> --catalog <catalog.yaml> --out <directory>");
  console.error("       hofctl validate --services <services.yml> --release-lock <release-lock.json> [--catalog <catalog.yaml>] [--release-selection <file>] [--stable-channel <file>] [--release-lock-signature <file>] [--release-lock-certificate <file>] [--release-lock-identity <identity>] [--release-lock-oidc-issuer <issuer>] [--skip-signature]");
  console.error("       hofctl preflight --services <services.yml> [--catalog <catalog.yaml>] [--target-mode ssh|local] [--known-hosts <file> | --host-key-sha256 <sha>] [--identity-file <path>] [--connect-timeout-seconds <n>] [--min-free-disk-gb <n>] [--min-memory-gb <n>] [--min-cpu-cores <n>]");
  console.error("       hofctl plan --services <services.yml> --release-lock <release-lock.json> --release-lock-identity <identity> (--known-hosts <file> | --host-key-sha256 <sha>) [--catalog <catalog.yaml>] [--identity-file <path>] [--target-mode ssh|local] [--connect-timeout-seconds <n>] [--repair-drift] [--recovery-age-recipient <age1...>]");
  console.error("       hofctl secrets ensure --services <services.yml> --store <secrets.sops.yaml> --operator-age-recipient <age1...> --recovery-age-recipient <age1...> [--catalog <catalog.yaml>] [--identity-file <path>]");
  console.error("       hofctl apply --services <services.yml> --release-lock <release-lock.json> --release-lock-identity <identity> (--known-hosts <file> | --host-key-sha256 <sha>) --identity-file <path> --recovery-age-recipient <age1...> (--approve-plan-id <exact-plan-id> --plan <plan-v2.json> | --resume) [--catalog <catalog.yaml>] [--connect-timeout-seconds <n>] [--repair-drift] [--secrets-store <secrets.sops.yaml>] [--secrets-age-identity-file <path>]");
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
  "--recovery-age-recipient",
]);
const PLAN_BOOLEAN_FLAGS = new Set(["--repair-drift"]);

// apply gets the same strict treatment as plan - a silently accepted
// typo'd or unknown flag here (an operator's own approval/resume
// intent, in particular) must never be simply ignored. Never accepts
// --target-mode at all (unlike plan/preflight) - apply only ever
// supports ssh (see apply.mjs's own comment on why local can't work
// here), so there is no flag exposed for a mode that would just be
// refused.
const APPLY_FLAGS = new Set([
  "--services", "--release-lock", "--release-lock-identity", "--known-hosts", "--host-key-sha256",
  "--catalog", "--identity-file", "--connect-timeout-seconds", "--repair-drift",
  "--recovery-age-recipient", "--approve-plan-id", "--plan", "--resume",
  "--secrets-store", "--secrets-age-identity-file",
]);
const APPLY_BOOLEAN_FLAGS = new Set(["--repair-drift", "--resume"]);

// Shared by plan and apply - both need every flag explicitly
// whitelisted (rather than parseFlags()'s generic "map whatever looks
// like a flag" behavior) since a mistyped or unknown flag for either of
// them could otherwise make an operator believe something ran under
// different, safer conditions than what they actually approved.
function makeStrictFlagParser(commandName, allowedFlags, booleanFlags, { onDisallowed } = {}) {
  return (args) => {
    const options = {};
    const seen = new Set();
    for (let index = 0; index < args.length; index++) {
      const flag = args[index];
      if (!flag?.startsWith("--")) { usage(`unexpected argument: ${flag}`); return null; }
      if (onDisallowed?.(flag)) return null;
      if (!allowedFlags.has(flag)) { usage(`unknown flag for ${commandName}: ${flag}`); return null; }
      if (seen.has(flag)) { usage(`duplicate flag: ${flag}`); return null; }
      seen.add(flag);
      const key = flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (booleanFlags.has(flag)) { options[key] = true; continue; }
      const value = args[++index];
      if (!value) { usage(`${flag} requires a value`); return null; }
      options[key] = value;
    }
    return options;
  };
}

const parsePlanFlags = makeStrictFlagParser("plan", PLAN_FLAGS, PLAN_BOOLEAN_FLAGS, {
  onDisallowed: (flag) => {
    if (flag === "--skip-signature") { usage("plan does not accept --skip-signature - it always verifies the release lock's real signature"); return true; }
    return false;
  },
});
const parseApplyFlags = makeStrictFlagParser("apply", APPLY_FLAGS, APPLY_BOOLEAN_FLAGS, {
  onDisallowed: (flag) => {
    if (flag === "--skip-signature") { usage("apply does not accept --skip-signature - it always verifies the release lock's real signature"); return true; }
    if (flag === "--target-mode") { usage("apply does not accept --target-mode - it only ever supports ssh (see ansible/README.md)"); return true; }
    return false;
  },
});

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
    // hofctl's own CLI vocabulary matches render's (--services,
    // --release-lock, --catalog, --release-selection, --stable-channel);
    // validateDeployment's own option names are the more explicit *Path
    // forms shared with its own standalone CLI - every one of these five
    // needs remapping, not just the first three (a --release-selection/
    // --stable-channel value was previously resolved to a key
    // (releaseSelectionPath/stableChannelPath) that parseFlags() never
    // actually produced, so the file was silently never read at all).
    resolvePaths(options, ["services", "catalog", "releaseLock", "releaseSelection", "stableChannel", "releaseLockSignature", "releaseLockCertificate"]);
    const normalized = {
      ...options,
      servicesPath: options.services,
      releaseLockPath: options.releaseLock,
      catalogPath: options.catalog,
      releaseSelectionPath: options.releaseSelection,
      stableChannelPath: options.stableChannel,
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
          recoveryAgeRecipient: options.recoveryAgeRecipient,
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
} else if (command === "secrets") {
  const [subcommand, ...secretsArgs] = args;
  if (subcommand !== "ensure") {
    usage(subcommand ? `unknown secrets subcommand: ${subcommand}` : "a secrets subcommand is required (ensure)");
  } else {
    const options = parseFlags(secretsArgs);
    if (options) {
      resolvePaths(options, ["services", "catalog", "store", "identityFile"]);
      if (!options.services || !options.store || !options.operatorAgeRecipient || !options.recoveryAgeRecipient) {
        usage("secrets ensure requires --services, --store, --operator-age-recipient, and --recovery-age-recipient");
      } else {
        try {
          const { addedNames, totalCount } = await runSecretsEnsure({
            servicesPath: options.services, catalogPath: options.catalog, storePath: options.store,
            operatorAgeRecipient: options.operatorAgeRecipient, recoveryAgeRecipient: options.recoveryAgeRecipient,
            identityFile: options.identityFile,
          });
          // Names only, ever - the CLI layer must never be able to
          // accidentally print a real secret value.
          for (const name of addedNames) console.log(JSON.stringify({ type: "secrets.added", name }));
          console.log(JSON.stringify({ type: "secrets.result", added: addedNames.length, total: totalCount }));
        } catch (error) {
          console.error(error instanceof Error ? error.message : String(error));
          process.exitCode = 1;
        }
      }
    }
  }
} else if (command === "apply") {
  const options = parseApplyFlags(args);
  if (options) {
    resolvePaths(options, ["services", "releaseLock", "catalog", "knownHosts", "identityFile", "secretsStore", "secretsAgeIdentityFile", "plan"]);
    const hasResume = options.resume === true;
    if (!options.services || !options.releaseLock || !options.releaseLockIdentity || !options.identityFile || !options.recoveryAgeRecipient) {
      usage("apply requires --services, --release-lock, --release-lock-identity, --identity-file, and --recovery-age-recipient");
    } else if (Boolean(options.knownHosts) === Boolean(options.hostKeySha256)) {
      usage("apply requires exactly one of --known-hosts or --host-key-sha256");
    } else if (hasResume ? (options.approvePlanId || options.plan) : (!options.approvePlanId || !options.plan)) {
      usage("apply requires --resume alone, or both --approve-plan-id and --plan together (never a mix) - approving a plan approves those exact bytes, a resume never takes a new approval (see ADR 0004)");
    } else {
      try {
        const connectTimeoutSeconds = parsePositiveInteger(options.connectTimeoutSeconds, "--connect-timeout-seconds");
        const result = await runApply({
          manifestPath: options.services,
          catalogPath: options.catalog,
          releaseLockPath: options.releaseLock,
          releaseLockIdentity: options.releaseLockIdentity,
          knownHostsFile: options.knownHosts,
          hostKeySha256: options.hostKeySha256,
          identityFile: options.identityFile,
          connectTimeoutSeconds,
          repairDrift: options.repairDrift === true,
          recoveryAgeRecipient: options.recoveryAgeRecipient,
          secretsStorePath: options.secretsStore,
          secretsAgeIdentityFile: options.secretsAgeIdentityFile,
          planPath: options.plan,
          approvePlanId: options.approvePlanId,
          resume: hasResume,
          // Bounded NDJSON on stdout, one line per event - nothing else
          // is ever printed there (see operation-event-v1.schema.json's
          // own comment on this exact contract).
          emit: (event) => console.log(JSON.stringify(event)),
        });
        if (result.blocked) {
          for (const line of result.diagnostics) console.error(line);
          process.exitCode = 1;
        } else {
          console.log(JSON.stringify({ type: "apply.result", operationId: result.operationId, committedGeneration: result.committedGeneration, planId: result.planId }));
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
