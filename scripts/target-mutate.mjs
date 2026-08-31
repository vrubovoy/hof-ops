// Fixed, narrow, target-side WRITE primitives for hofctl apply's own
// control-plane bookkeeping - the operation lock and journal under
// /var/lib/hof/state (see schemas/operation-{lock,journal,event}-v1
// and ADR 0004's "durable host lock"/"durable operation journal"
// decisions). Deliberately separate from target-inspector.mjs
// (read-only, target-probe.sh) and from the Ansible Execution
// Environment (which mutates actual host/Docker/application state, per
// a plan's own operations - never Hof's own lock/journal bookkeeping,
// which is the control plane's own responsibility, not a role's).
//
// Like target-probe.sh, every command here is one of a small fixed
// vocabulary, never a caller-built shell string - the only value ever
// embedded into a script is a base64 payload (produced by this module
// itself from an already schema-validated document) or an operationId
// (already regex-validated to a bare UUID before it ever reaches here),
// both safe to place directly inside single quotes.
//
// Unlike target-inspector.mjs (which supports both known-hosts-file and
// host-key-sha256 trust modes, since it runs before any host key has
// ever been accepted), every connection here uses host-key-sha256
// pinning ONLY, against the exact fingerprint the caller already has
// from an approved plan-v2's own `target.hostKeySha256` - target-mutate
// never independently negotiates or discovers trust of its own, exactly
// like target-inspector.mjs's own transport (ADR 0004: "apply never
// re-trusts a target on the caller's say-so alone").
//
// Every mutation runs as `sudo -n sh -s` (not plain `sh -s`) - by the
// time apply ever calls this module, hofctl preflight's own checkSudo
// has already confirmed passwordless sudo is available (apply.mjs
// re-asserts this from the same snapshot before ever reaching here), so
// there is no "plain first, sudo second" fallback to write here at all
// (unlike target-probe.sh, which must also work before that's been
// confirmed).

import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const SSH_HARDENING = [
  "-o", "BatchMode=yes",
  "-o", "PasswordAuthentication=no",
  "-o", "KbdInteractiveAuthentication=no",
  "-o", "ClearAllForwardings=yes",
  "-o", "PermitLocalCommand=no",
  "-o", "RequestTTY=no",
  "-o", "ConnectionAttempts=1",
  // Same reasoning as target-inspector.mjs's own identical hardening
  // list (duplicated deliberately, not imported - see this file's own
  // top comment): never let a stray ~/.ssh/config ProxyJump/ProxyCommand
  // for this hostname silently route target-mutate's own real mutations
  // through an intermediary the target binding never recorded.
  "-o", "ProxyCommand=none",
  "-o", "ProxyJump=none",
];

const HOSTNAME_PATTERN = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;
const USERNAME_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;
const OPERATION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOST_KEY_SHA256_PATTERN = /^SHA256:[A-Za-z0-9+/]+=*$/;

function validateSshDestination(host, user, port) {
  if (typeof host !== "string" || !HOSTNAME_PATTERN.test(host)) throw new Error(`refusing to connect: "${host}" is not a valid hostname`);
  if (typeof user !== "string" || !USERNAME_PATTERN.test(user)) throw new Error(`refusing to connect: "${user}" is not a valid SSH username`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`refusing to connect: ${port} is not a valid port number`);
}

function validateOperationId(operationId) {
  if (!OPERATION_ID_PATTERN.test(operationId)) throw new Error(`"${operationId}" is not a valid operationId`);
  return operationId;
}

function defaultRun(command, args, { input, timeout } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { maxBuffer: 8 * 1024 * 1024, timeout }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
    if (input !== undefined) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

function b64(jsonValue) {
  return Buffer.from(JSON.stringify(jsonValue), "utf8").toString("base64");
}

// Resolves exactly one known_hosts line matching the caller's pinned
// fingerprint - the same real ssh-keyscan-then-match logic
// target-inspector.mjs's own resolveKnownHosts already established as
// safe, deliberately duplicated here (not imported - that module
// exports nothing beyond inspectTarget(), by design) so this file's own
// trust handling is fully self-contained and reviewable without
// cross-referencing another module.
// Exported (unlike everything else here, this one is also used directly
// by apply.mjs to build the Ansible inventory's own known_hosts file for
// the Execution Environment container - the exact same pinned-trust
// resolution, not a third independently-maintained copy of it).
export async function pinnedKnownHosts({ host, port, hostKeySha256, connectTimeoutSeconds, run }) {
  const { stdout } = await run("ssh-keyscan", ["-p", String(port), "-T", String(connectTimeoutSeconds), "-t", "rsa,ed25519,ecdsa", host], {});
  const candidates = stdout.split("\n").filter((line) => line && !line.startsWith("#"));
  const match = candidates.find((line) => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) return false;
    const digest = "SHA256:" + createHash("sha256").update(Buffer.from(parts[2], "base64")).digest("base64").replace(/=+$/, "");
    return digest === hostKeySha256;
  });
  if (!match) throw new Error(`no host key offered by ${host}:${port} matches the pinned fingerprint ${hostKeySha256} - refusing to connect (a host-key change invalidates the plan this operation was approved against, see ADR 0004)`);
  const file = path.join(tmpdir(), `hof-mutate-known-hosts-${randomUUID()}`);
  await writeFile(file, match + "\n", { mode: 0o600 });
  return { file, cleanup: () => unlink(file).catch(() => {}) };
}

// Runs one fixed script (built by this module, never the caller) either
// over the pinned SSH transport or locally, always as root. Returns raw
// stdout - each command function below parses its own fixed response
// shape from it.
async function runScript(conn, scriptText) {
  const { mode, host, port, user, hostKeySha256, identityFile, connectTimeoutSeconds = 10, run = defaultRun } = conn;
  if (mode === "local") {
    const { stdout } = await run("sudo", ["-n", "sh", "-s"], { input: scriptText, timeout: 30_000 });
    return stdout;
  }
  validateSshDestination(host, user, port);
  if (!HOST_KEY_SHA256_PATTERN.test(hostKeySha256 ?? "")) throw new Error("a pinned hostKeySha256 is required for ssh mode");
  const { file: knownHostsFile, cleanup } = await pinnedKnownHosts({ host, port, hostKeySha256, connectTimeoutSeconds, run });
  try {
    const args = [
      ...SSH_HARDENING,
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${knownHostsFile}`,
      "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", `ConnectTimeout=${connectTimeoutSeconds}`,
      "-p", String(port),
      ...(identityFile ? ["-i", identityFile, "-o", "IdentitiesOnly=yes"] : []),
      "--",
      `${user}@${host}`,
      "sudo", "-n", "sh", "-s",
    ];
    const { stdout } = await run("ssh", args, { input: scriptText, timeout: (connectTimeoutSeconds + 20) * 1000 });
    return stdout;
  } finally {
    await cleanup();
  }
}

// set -C (noclobber) makes a plain `>` redirection fail if the target
// already exists, using the same O_EXCL semantics a real exclusive
// create needs - genuinely atomic at the kernel level, safe under real
// concurrent attempts (two operators racing for the same lock), not
// merely "check then write".
function exclusiveCreateScript(targetPath, payload) {
  return `set -eu
payload='${payload}'
mkdir -p "$(dirname '${targetPath}')"
umask 077
if (set -C; printf '%s' "$payload" | base64 -d > '${targetPath}') 2>/dev/null; then
  echo HOF_MUTATE_CREATED
else
  echo HOF_MUTATE_EXISTS
  if [ -r '${targetPath}' ]; then
    cat '${targetPath}'
  fi
fi
`;
}

function acquireLockAndJournalScript(lockPayload, journalTargetPath, journalPayload) {
  return `set -eu
lock_payload='${lockPayload}'
journal_payload='${journalPayload}'
mkdir -p "$(dirname '${LOCK_PATH}')"
mkdir -p "$(dirname '${journalTargetPath}')"
umask 077
if (set -C; printf '%s' "$lock_payload" | base64 -d > '${LOCK_PATH}') 2>/dev/null; then
  if (set -C; printf '%s' "$journal_payload" | base64 -d > '${journalTargetPath}') 2>/dev/null; then
    echo HOF_MUTATE_CREATED
  else
    echo HOF_MUTATE_JOURNAL_CONFLICT
    rm -f '${LOCK_PATH}'
  fi
else
  echo HOF_MUTATE_EXISTS
  if [ -r '${LOCK_PATH}' ]; then
    cat '${LOCK_PATH}'
  fi
fi
`;
}

function readScript(targetPath) {
  return `set -eu
if [ -r '${targetPath}' ]; then
  echo HOF_MUTATE_PRESENT
  cat '${targetPath}'
elif [ -e '${targetPath}' ]; then
  echo HOF_MUTATE_UNREADABLE
else
  echo HOF_MUTATE_ABSENT
fi
`;
}

function parseCreateResponse(stdout) {
  const [tag, ...rest] = stdout.split("\n");
  if (tag === "HOF_MUTATE_CREATED") return { created: true };
  if (tag === "HOF_MUTATE_EXISTS") return { created: false, existing: rest.join("\n").trim() ? JSON.parse(rest.join("\n")) : null };
  throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

function parseReadResponse(stdout) {
  const [tag, ...rest] = stdout.split("\n");
  if (tag === "HOF_MUTATE_PRESENT") return { status: "present", value: JSON.parse(rest.join("\n")) };
  if (tag === "HOF_MUTATE_UNREADABLE") return { status: "unreadable", value: null };
  if (tag === "HOF_MUTATE_ABSENT") return { status: "absent", value: null };
  throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

const LOCK_PATH = "/var/lib/hof/state/lock.json";
const CURRENT_STATE_PATH = "/var/lib/hof/state/current.json";
const TOPOLOGY_PATH = "/var/lib/hof/state/topology.json";
const journalPath = (operationId) => `/var/lib/hof/state/journal/${validateOperationId(operationId)}.json`;
const eventsPath = (operationId) => `/var/lib/hof/state/journal/${validateOperationId(operationId)}.events.ndjson`;

// conn: { mode: "ssh" | "local", host, port, user, hostKeySha256,
//   identityFile, connectTimeoutSeconds, run? } - run is a testing seam
// (see target-mutate.test.mjs); hofctl apply itself always gets the
// real process runner.

// Returns { acquired: true } on success, or { acquired: false, lock }
// (the ALREADY-HELD lock document, so the caller can tell "held by this
// same operationId - a resume" from "held by someone else - refuse")
// when the target is already locked. Never throws for the ordinary
// "already locked" case - only for a genuine transport/protocol failure.
export async function acquireLock(conn, lockDocument) {
  const stdout = await runScript(conn, exclusiveCreateScript(LOCK_PATH, b64(lockDocument)));
  const result = parseCreateResponse(stdout);
  return result.created ? { acquired: true } : { acquired: false, lock: result.existing };
}

// Creates the lock AND the journal as ONE remote script invocation - a
// single SSH round trip, not two - so there is no window between them
// where the LOCAL apply.mjs process itself (not the SSH session) could
// crash after the lock is durably created but before the journal write
// is even issued (a real gap a further, 2026-08-31 review found: a
// resume then reads a lock referencing an operationId whose journal
// genuinely doesn't exist yet, and had nothing to do but refuse
// forever). The remote script itself creates the journal only once the
// lock create has already succeeded, and rolls the lock back if the
// journal create then somehow still fails (structurally this should be
// impossible - journalDocument.operationId is always a fresh
// randomUUID, so no journal file at that exact path can already exist -
// but a script that can't happen is not the same as a script that
// doesn't check). A crash strictly inside the remote script's own
// execution (between its two file creates) remains possible in
// principle, same as any single remote command - not something a
// client-side reordering could ever fully close - but it's the same
// class of risk every other single-runScript call in this module
// already carries, not a new one this function introduces.
export async function acquireLockAndJournal(conn, lockDocument, journalDocument) {
  const stdout = await runScript(conn, acquireLockAndJournalScript(b64(lockDocument), journalPath(journalDocument.operationId), b64(journalDocument)));
  const [tag, ...rest] = stdout.split("\n");
  if (tag === "HOF_MUTATE_CREATED") return { acquired: true };
  if (tag === "HOF_MUTATE_EXISTS") return { acquired: false, lock: rest.join("\n").trim() ? JSON.parse(rest.join("\n")) : null };
  if (tag === "HOF_MUTATE_JOURNAL_CONFLICT") throw new Error(`a journal for operation ${journalDocument.operationId} already existed on the target even though its lock did not - structurally impossible for a freshly generated operationId, points at real target-side corruption; the lock write was rolled back`);
  throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

export async function readLock(conn) {
  const stdout = await runScript(conn, readScript(LOCK_PATH));
  const { status, value } = parseReadResponse(stdout);
  return { status, lock: value };
}

// Only ever removes the lock when it's still owned by operationId - a
// defense-in-depth check even though this is control-plane code, not
// adversarial input (the lock could, in principle, already have been
// hand-removed and replaced by a stuck operator's manual recovery).
export async function releaseLock(conn, operationId) {
  const script = `set -eu
op='${validateOperationId(operationId)}'
if [ -r '${LOCK_PATH}' ] && grep -qF "\\"operationId\\":\\"$op\\"" '${LOCK_PATH}'; then
  rm -f '${LOCK_PATH}'
  echo HOF_MUTATE_RELEASED
else
  echo HOF_MUTATE_MISMATCH
fi
`;
  const stdout = await runScript(conn, script);
  const tag = stdout.split("\n")[0];
  if (tag === "HOF_MUTATE_RELEASED") return { released: true };
  if (tag === "HOF_MUTATE_MISMATCH") return { released: false };
  throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

// Journal creation is exclusive too (like the lock) - a resume must
// never accidentally re-create (and thereby reset) an existing journal;
// it always goes through readJournal + updateJournalStatus instead.
export async function writeJournal(conn, journalDocument) {
  const stdout = await runScript(conn, exclusiveCreateScript(journalPath(journalDocument.operationId), b64(journalDocument)));
  const result = parseCreateResponse(stdout);
  if (!result.created) throw new Error(`a journal for operation ${journalDocument.operationId} already exists on the target - refusing to overwrite it`);
}

export async function readJournal(conn, operationId) {
  const stdout = await runScript(conn, readScript(journalPath(operationId)));
  const { status, value } = parseReadResponse(stdout);
  return { status, journal: value };
}

// The state role's own real, durable result (see
// ansible/roles/state/tasks/main.yml) - the one independent, target-side
// oracle for "did state.commit's own real effect actually land", used by
// apply.mjs's own resume path to recover from the narrow crash window
// between state.commit's dispatch succeeding and its own succeeded event
// being durably appended (see ADR 0004's errata on post-commit recovery).
export async function readCurrentState(conn) {
  const stdout = await runScript(conn, readScript(CURRENT_STATE_PATH));
  const { status, value } = parseReadResponse(stdout);
  return { status, current: value };
}

// The same real, durable oracle as readCurrentState() above, for
// topology.json - used alongside it by apply.mjs's post-commit recovery
// so a recovered state.commit is confirmed against the FULL real record
// the target holds, not just current.json's own topologyDigest field.
export async function readTopology(conn) {
  const stdout = await runScript(conn, readScript(TOPOLOGY_PATH));
  const { status, value } = parseReadResponse(stdout);
  return { status, topology: value };
}

// Atomic write-then-rename (ADR 0004: "only ever atomically") - the
// caller always hands the FULL, already-schema-valid updated document
// (see operation-journal.mjs's own withJournalStatus), never a partial
// patch for this script to merge itself.
export async function updateJournalStatus(conn, journalDocument) {
  const targetPath = journalPath(journalDocument.operationId);
  const script = `set -eu
payload='${b64(journalDocument)}'
tmp='${targetPath}.tmp'
printf '%s' "$payload" | base64 -d > "$tmp"
mv -f "$tmp" '${targetPath}'
echo HOF_MUTATE_UPDATED
`;
  const stdout = await runScript(conn, script);
  if (stdout.split("\n")[0] !== "HOF_MUTATE_UPDATED") throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

// Append-only NDJSON - one line per event, never rewritten or reordered.
export async function appendEvent(conn, operationId, event) {
  const targetPath = eventsPath(operationId);
  const script = `set -eu
payload='${b64(event)}'
mkdir -p "$(dirname '${targetPath}')"
printf '%s\\n' "$(printf '%s' "$payload" | base64 -d)" >> '${targetPath}'
echo HOF_MUTATE_APPENDED
`;
  const stdout = await runScript(conn, script);
  if (stdout.split("\n")[0] !== "HOF_MUTATE_APPENDED") throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

// A brand new operationId's own events file simply doesn't exist yet -
// that's normal (zero events so far), not an error state, so this
// returns an empty array rather than distinguishing absent/unreadable
// the way the lock/journal readers do.
export async function readEvents(conn, operationId) {
  const targetPath = eventsPath(operationId);
  const script = `set -eu
if [ -r '${targetPath}' ]; then
  echo HOF_MUTATE_PRESENT
  cat '${targetPath}'
else
  echo HOF_MUTATE_ABSENT
fi
`;
  const stdout = await runScript(conn, script);
  const newlineIndex = stdout.indexOf("\n");
  const tag = newlineIndex === -1 ? stdout : stdout.slice(0, newlineIndex);
  if (tag === "HOF_MUTATE_ABSENT") return [];
  if (tag !== "HOF_MUTATE_PRESENT") throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
  const body = stdout.slice(newlineIndex + 1);
  return body.split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line));
}
