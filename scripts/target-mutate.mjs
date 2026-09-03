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

import { execFile, spawn } from "node:child_process";
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

// Every script that touches lock.json's own critical section (create or
// release) runs inside this same target-side flock - a further,
// 2026-08-31 review found releaseLock()'s own grep-then-rm was a real
// compare-and-delete race without it: another releaser removing the
// same lock, and a brand new apply acquiring the NEXT one, could both
// land in the tiny window between one releaser's own grep and its rm,
// making it delete a completely unrelated, currently-live lock. The
// flock is held only for the duration of the ONE script process that
// takes it (fd 9, opened and locked here, released automatically when
// that script's shell exits) - no persistent session is needed across
// separate SSH round trips for this to serialize them against each
// other.
function withLockGuard(criticalSection) {
  return `set -eu
mkdir -p "$(dirname '${LOCK_GUARD_PATH}')"
umask 077
exec 9>'${LOCK_GUARD_PATH}'
flock -x 9
${criticalSection}
`;
}

// Atomically creates targetPath with the exact given payload, or leaves
// it untouched and reports failure if it already exists - writes the
// FULL content to a fresh temp file in the same directory first, then
// `ln`s (never `mv`s) it into place: `ln` fails outright with EEXIST
// rather than silently overwriting, and - unlike the plain `set -C; ...
// > targetPath` redirection this used to be - never exposes a partial
// or empty file at targetPath at any point (a `>` redirection opens and
// truncates/creates the destination the instant the shell parses it,
// before the writing pipeline even runs). A further, 2026-08-31 review
// found that old form left exactly that window open: a crash of the
// remote script mid-transfer (a dropped connection, an OOM-kill, a
// power loss) could leave a truncated lock or journal file behind.
//
// The temp name itself is a genuinely unique `mktemp`, never a fixed
// `targetPath.tmp` - a STILL FURTHER, 2026-08-31 review found reusing a
// fixed name was itself a real corruption path: if a PRIOR, crashed
// invocation's own `ln` had already succeeded but its own `rm` never
// ran (dying in that exact gap), the fixed tmp name and targetPath were
// left as two hard links to the SAME inode - a LATER invocation's own
// `printf ... > targetPath.tmp` would then truncate that shared inode,
// silently corrupting the already-live, currently-held targetPath, even
// though the later invocation's own `ln` would (correctly) then refuse
// with EEXIST. Reproduced and confirmed for real against a scratch
// directory before this fix, and confirmed fixed after it. Only safe to
// call from within a script already holding the lock guard above (the
// opportunistic cleanup of any orphaned prior mktemp files relies on
// that same mutual exclusion - no live invocation could be using one).
function atomicExclusiveCreateStep(targetPath, payloadVar, resultVar) {
  return `mkdir -p "$(dirname '${targetPath}')"
rm -f '${targetPath}'.??????
${resultVar}_tmp=$(mktemp '${targetPath}.XXXXXX')
printf '%s' "$${payloadVar}" | base64 -d > "$${resultVar}_tmp"
if ln "$${resultVar}_tmp" '${targetPath}' 2>/dev/null; then
  rm -f "$${resultVar}_tmp"
  ${resultVar}=1
else
  rm -f "$${resultVar}_tmp"
  ${resultVar}=0
fi`;
}

// Creates the journal FIRST, then the lock - the reverse of this
// module's own original order. A further, 2026-08-31 review found the
// original lock-then-journal order still left a real (if much smaller)
// window: even bundled into one remote script, a crash strictly inside
// that script's own execution, between the lock's own create and the
// journal's, left a lock with no journal - exactly the state resume had
// no recovery path for. Journal-first makes that state structurally
// unreachable through the normal path instead: by the time the lock
// (the sole real exclusivity gate - the journal's own path is already
// unique per fresh operationId, no exclusivity of its own is needed for
// correctness) is ever observed present, the journal it names is
// GUARANTEED to already have been durably created, in this exact same
// script, moments earlier. If the lock step still somehow fails (target
// already locked by another operation), the just-created journal is
// rolled back - it was never actually claimed by anything.
function acquireLockAndJournalScript(lockPayload, journalTargetPath, journalPayload) {
  return withLockGuard(`lock_payload='${lockPayload}'
journal_payload='${journalPayload}'
${atomicExclusiveCreateStep(journalTargetPath, "journal_payload", "journal_created")}
if [ "$journal_created" != 1 ]; then
  echo HOF_MUTATE_JOURNAL_CONFLICT
  exit 0
fi
${atomicExclusiveCreateStep(LOCK_PATH, "lock_payload", "lock_created")}
if [ "$lock_created" = 1 ]; then
  echo HOF_MUTATE_CREATED
else
  rm -f '${journalTargetPath}'
  echo HOF_MUTATE_EXISTS
  if [ -r '${LOCK_PATH}' ]; then
    cat '${LOCK_PATH}'
  fi
fi`);
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
const LOCK_GUARD_PATH = "/var/lib/hof/state/lock.flock";
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
// No longer used by apply.mjs's own live path (superseded by
// acquireLockAndJournal() below) - kept for its own narrow test
// coverage and as a documented building block. Deliberately NOT wrapped
// in the flock guard acquireLockAndJournal()/releaseLock() share (there
// is nothing else touching lock.json for it to race against once it's
// no longer part of the live path) - a future caller reintroducing this
// into any real code path would need to add that back.
export async function acquireLock(conn, lockDocument) {
  const stdout = await runScript(conn, exclusiveCreateScript(LOCK_PATH, b64(lockDocument)));
  const result = parseCreateResponse(stdout);
  return result.created ? { acquired: true } : { acquired: false, lock: result.existing };
}

// Creates the lock AND the journal as ONE remote script invocation - a
// single SSH round trip, not two - so there is no window between them
// where the LOCAL apply.mjs process itself (not the SSH session) could
// crash after one is durably created but before the other is even
// issued (a real gap a further, 2026-08-31 review found: a resume then
// reads a lock referencing an operationId whose journal genuinely
// doesn't exist yet, and had nothing to do but refuse forever). The
// remote script itself (see acquireLockAndJournalScript()'s own
// comment) creates the JOURNAL first, then the lock, atomically -
// rolling the journal back if the lock step then fails (target already
// locked by another operation). A further, 2026-08-31 review found even
// the single-round-trip, lock-then-journal version of this still left a
// real (if much smaller) window: a crash strictly inside the remote
// script's own execution, between its two creates, could leave a lock
// with no journal. Journal-first removes that specific window
// structurally, not just probabilistically - see the script's own
// comment for why.
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
// hand-removed and replaced by a stuck operator's manual recovery). The
// check-then-delete itself is still two shell statements, not one atomic
// syscall - safe against a genuine compare-and-delete race (a different
// releaser removing this exact lock, and a brand new apply acquiring
// the NEXT one, both landing between this grep and this rm) only
// because it now runs inside the SAME target-side flock
// acquireLockAndJournal() takes - see withLockGuard()'s own comment.
export async function releaseLock(conn, operationId) {
  const script = withLockGuard(`op='${validateOperationId(operationId)}'
if [ -r '${LOCK_PATH}' ] && grep -qF "\\"operationId\\":\\"$op\\"" '${LOCK_PATH}'; then
  rm -f '${LOCK_PATH}'
  echo HOF_MUTATE_RELEASED
else
  echo HOF_MUTATE_MISMATCH
fi`);
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

// Item 9 (ADR 0005): the state role's own immutable, permanent per-
// generation snapshot (generations/NNNNNN/state.json - see
// ansible/roles/state/tasks/main.yml) - a THIRD independent oracle,
// alongside current.json/topology.json, that apply.mjs's own succeeded-
// journal recovery reads back to confirm a claimed commit actually
// landed. generation must already be a genuine positive integer (the
// same invariant plan-v2.schema.json's own baselineGeneration/generation
// fields already enforce before this is ever called) - never accepted
// as free-form text, the same "no caller-built shell string" discipline
// every other path in this module follows.
function generationSnapshotDir(generation) {
  if (!Number.isInteger(generation) || generation < 1) {
    throw new Error(`readGenerationSnapshot requires a positive integer generation, got ${JSON.stringify(generation)}`);
  }
  return `/var/lib/hof/state/generations/${String(generation).padStart(6, "0")}`;
}

export async function readGenerationSnapshot(conn, generation) {
  const stdout = await runScript(conn, readScript(`${generationSnapshotDir(generation)}/state.json`));
  const { status, value } = parseReadResponse(stdout);
  return { status, snapshot: value };
}

// Item 9 review fix (finding 8): recovery used to confirm ONLY the
// per-generation snapshot's state.json - a corrupt or missing
// topology.json/release-lock.json in the same directory could still be
// accepted as a complete immutable record. These two readers let
// apply.mjs's recovery paths check the whole directory, not just one
// file of it.
export async function readGenerationSnapshotTopology(conn, generation) {
  const stdout = await runScript(conn, readScript(`${generationSnapshotDir(generation)}/topology.json`));
  const { status, value } = parseReadResponse(stdout);
  return { status, topology: value };
}

export async function readGenerationSnapshotReleaseLock(conn, generation) {
  const stdout = await runScript(conn, readScript(`${generationSnapshotDir(generation)}/release-lock.json`));
  const { status, value } = parseReadResponse(stdout);
  return { status, releaseLock: value };
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

const EXECUTION_LEASE_PATH = "/var/lib/hof/state/exec.lease";

// How often the local side writes one heartbeat byte, and how long the
// remote side waits for the next one before giving up - see
// acquireExecutionLease()'s own comment for why a heartbeat, not a bare
// "block on stdin until it closes", is what this needs.
const LEASE_HEARTBEAT_INTERVAL_MS = 10_000;
const LEASE_HEARTBEAT_TIMEOUT_S = 30;

// Item 9 review fix (finding 3): the durable lock.json is a PERSISTENCE
// lock - it survives a crash so --resume can find an interrupted
// operation. It is NOT a liveness lease: two `hofctl apply --resume`
// processes both read the same lock, both see the same events, and both
// go on to dispatch the same step. This is a PROCESS-LIFETIME execution
// lease on top of it: a long-lived SSH (or local) child holds an
// exclusive flock on EXECUTION_LEASE_PATH for exactly as long as this
// apply process lives, and releases it within a bounded time of this
// process (or its connection) actually going away.
//
// Three real, live rounds of validation against a real sudo-enabled
// sshd target (a sudo NOPASSWD child, same as every other mutation in
// this module - a fake mutate/run seam can't catch a real OS/sudo/SSH
// interaction like the two gaps found here) drove this exact design,
// each one a genuine bug the previous attempt did not have on paper:
//   1. `while :; do sleep 3600; done`, meant to die when the SSH
//      connection is closed, provably does NOT: `sudo` starts its own
//      child in a NEW session specifically to isolate it from the
//      invoking terminal/session's own signals, so the SIGHUP a closed
//      channel would normally deliver never reaches it - confirmed by
//      killing the local SSH client and finding the remote flock-holder
//      still running, independently, minutes later.
//   2. Blocking on the remote script's OWN stdin instead (closing it -
//      `child.stdin.end()` - to release, relying on the underlying
//      transport closing to propagate EOF on a crash, since `sudo`
//      isolates signals but still faithfully connects stdin/stdout/
//      stderr through) fixed the SIGNAL problem and made an explicit,
//      clean release() fast (~10ms, confirmed) - but a genuine crash
//      (this process SIGKILLed) left the remote side hanging for over a
//      minute before the transport's own teardown was ever noticed,
//      confirmed by timed, repeated measurement, not assumed. Prompt
//      teardown notice depends on `sudo`, the local `ssh` client, this
//      specific network path, and the target's own kernel all
//      cooperating quickly - not something this module can guarantee
//      for a real, arbitrary target.
// Both gaps are closed the same way SSH's own ServerAliveInterval/
// ClientAliveInterval solve this exact problem, applied at this
// module's own application layer instead (since a real target's own
// sshd_config - ClientAliveInterval in particular - is outside this
// module's control): the local side writes one fixed heartbeat byte
// every LEASE_HEARTBEAT_INTERVAL_MS; the remote side, holding the flock,
// loops reading exactly one byte with a LEASE_HEARTBEAT_TIMEOUT_S
// bound (`timeout N head -c 1` - portable POSIX sh, not bash's own
// `read -t`, which Debian's default /bin/sh, dash, does not implement -
// confirmed by hitting exactly that "Illegal option -t" before landing
// on this). A byte arriving loops again; the read TIMING OUT (rc 124 -
// no heartbeat within the bound, however that silence came about) or
// hitting real EOF (rc 0, but nothing read - release() ends stdin, or
// the connection genuinely died and something already noticed) both
// exit the loop, ending the script, closing fd 9 and the flock with it.
// This bounds every disconnection - clean or not - to
// LEASE_HEARTBEAT_TIMEOUT_S, never dependent on how promptly (if ever)
// the transport itself gets around to tearing down.
//
// A second concurrent apply/resume fails `flock -n` immediately and is
// refused, WITHOUT ever entering the heartbeat loop at all (the busy
// branch exits on its own, unconditionally, the instant it prints).
//
// How long acquisition itself is allowed to take before this gives up -
// a second review found the ORIGINAL version of this function had no
// bound here at all: a hung ssh connection (no HOF_LEASE_HELD/BUSY, no
// exit, no error - just silence) left acquireExecutionLease() awaiting
// forever. Generous (matches dispatchOperation()'s own EE budget
// reasoning) since a slow but genuine connection must never be mistaken
// for a hung one.
const LEASE_ACQUIRE_TIMEOUT_MS = 60_000;

// Returns { release, isLost, lostReason, onLost } on success. Throws on
// contention (another live apply holds it) or a transport failure - the
// caller turns the former into blocked("lease", ...) and must NOT
// release the durable lock (the other process legitimately owns the
// operation).
//
// Item 9 SECOND review fix: acquiring the lease once and never looking
// at it again is fail-OPEN, not fail-closed - a further review found
// that once HOF_LEASE_HELD resolved this function's own returned
// promise, `settled` was already true, so the SAME child's own later
// `exit`/`error` handlers (a genuine loss of the lease - the remote
// heartbeat loop timed out, the ssh connection itself died, anything)
// were silently discarded by the `if (!settled)` guard built for a
// DIFFERENT purpose (never resolving/rejecting the acquisition promise
// twice) - apply.mjs kept dispatching real mutations with no live lease
// at all behind them, exactly the double-dispatch risk this whole
// mechanism exists to prevent. Fixed: a lease loss discovered AFTER
// acquisition (the child exits or errors, and release() was never
// called) is now recorded (`isLost()`/`lostReason()`) and broadcast
// (`onLost(callback)`), and apply.mjs's own dispatch loop checks it
// before every operation and refuses to start a new one once lost (see
// its own comment there) - fail-closed for every step this process has
// not yet dispatched.
//
// This still does NOT provide true distributed fencing (a monotonic
// token every target-side mutation independently checks before acting,
// the textbook fix for a lease that can expire while its holder is
// merely paused - GC, SIGSTOP, a scheduler delay - rather than actually
// gone): building that would mean every one of the ten Ansible roles
// itself becoming lease-aware, not just this control-plane module, and
// is out of this fix's own scope. What this DOES close for real: the
// operation this process already dispatched to the target cannot be
// recalled either way (true of ANY lease design, fenced or not), but
// this process now provably stops queuing new ones the moment it knows
// its own lease is gone, rather than never finding out at all.
//
// Item 9 THIRD review fix (findings 4 & 5): two further races in this
// same acquire/lose lifecycle, both closed below (see each one's own
// comment at its exact fix site):
//   4. A timeout/late-success race in the acquisition promise itself -
//      the timeout path used to start its own async release() BEFORE
//      marking itself settled, leaving a real window for an
//      already-in-flight HOF_LEASE_HELD to win the race and resolve
//      successfully with a lease this function had already begun
//      releasing. Fixed with a synchronous claim() gate, closed the
//      instant any one of the four settling paths starts running -
//      never after its own async cleanup finishes.
//   5. A stdin EPIPE used to only ever set a local `stdinErrored` flag
//      (read by the heartbeat and by release()) and otherwise wait for
//      the child's own, separate "exit" event to eventually call
//      markLost() - a real gap whenever that event's own delivery lagged
//      behind the stream error that had already, independently, proven
//      the lease gone. markLost() is now called directly from the stdin
//      error handler itself.
//
// spawnFn: a testing seam only (see test/target-mutate.test.mjs's own
// fake spawn) - defaults to node:child_process's real spawn, exactly
// like every other run/exec seam in this codebase; the real CLI never
// passes it. A long-lived, streaming child (heartbeats in, output
// watched as it arrives) can't reuse this module's own one-shot
// runScript()/mockRun() convention, which is why this takes its own
// seam rather than the shared `run` one.
export async function acquireExecutionLease(conn, spawnFn = spawn) {
  const {
    mode, host, port, user, hostKeySha256, identityFile, connectTimeoutSeconds = 10, run = defaultRun,
    // Overridable only so test/target-mutate.test.mjs's own timeout test
    // doesn't have to wait out the real, generous default - the real
    // CLI never sets this.
    executionLeaseAcquireTimeoutMs = LEASE_ACQUIRE_TIMEOUT_MS,
  } = conn;
  const remote = `set -eu
mkdir -p "$(dirname '${EXECUTION_LEASE_PATH}')"
exec 9>'${EXECUTION_LEASE_PATH}'
if flock -n -x 9; then
  echo HOF_LEASE_HELD
  while :; do
    got=$(timeout ${LEASE_HEARTBEAT_TIMEOUT_S} head -c 1 2>/dev/null) || break
    [ -z "$got" ] && break
  done
else
  echo HOF_LEASE_BUSY
  exit 0
fi
`;

  let child;
  let knownHostsCleanup = () => {};
  if (mode === "local") {
    child = spawnFn("sudo", ["-n", "sh", "-s"], { stdio: ["pipe", "pipe", "pipe"] });
  } else {
    validateSshDestination(host, user, port);
    if (!HOST_KEY_SHA256_PATTERN.test(hostKeySha256 ?? "")) throw new Error("a pinned hostKeySha256 is required for ssh mode");
    const { file: knownHostsFile, cleanup } = await pinnedKnownHosts({ host, port, hostKeySha256, connectTimeoutSeconds, run });
    knownHostsCleanup = cleanup;
    const args = [
      ...SSH_HARDENING,
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${knownHostsFile}`,
      "-o", "GlobalKnownHostsFile=/dev/null",
      "-o", `ConnectTimeout=${connectTimeoutSeconds}`,
      // A second, complementary layer to the application-level heartbeat
      // above: if the SERVER itself stops answering (not merely quiet -
      // genuinely down/unreachable), the local ssh client gives up and
      // exits on its own within ~45s, rather than sitting idle
      // indefinitely believing the lease is still held.
      "-o", "ServerAliveInterval=15",
      "-o", "ServerAliveCountMax=3",
      "-p", String(port),
      ...(identityFile ? ["-i", identityFile, "-o", "IdentitiesOnly=yes"] : []),
      "--",
      `${user}@${host}`,
      "sudo", "-n", "sh", "-s",
    ];
    child = spawnFn("ssh", args, { stdio: ["pipe", "pipe", "pipe"] });
  }

  // Moved above the stdin error handler just below (item 9 THIRD review
  // fix, finding 5) - markLost() itself only ever touches lost/
  // lostReasonValue/lostCallbacks/voluntarilyReleased, none of which
  // depend on anything declared further down (release, heartbeat), so
  // hoisting this block costs nothing and lets that handler call it
  // directly instead of only setting a flag nothing else ever acted on
  // promptly.
  let voluntarilyReleased = false;
  let lost = false;
  let lostReasonValue = null;
  const lostCallbacks = [];
  const markLost = (reason) => {
    if (lost || voluntarilyReleased) return;
    lost = true;
    lostReasonValue = reason;
    for (const callback of lostCallbacks) {
      try { callback(reason); } catch { /* a caller's own onLost callback misbehaving must never break lease bookkeeping itself */ }
    }
  };

  // Item 9 FOURTH review fix (finding 1): claim()/settled/the acquisition
  // promise's own resolve+reject are now set up HERE, before the stdin
  // error handler just below - not, as a third review had it, only
  // inside the later `new Promise((resolve, reject) => {...})` executor,
  // which the stdin handler (registered earlier, so it can catch an
  // error raised by the very first `child.stdin.write(remote)` call)
  // could not reach at all. A further review found that gap real: a
  // stdin error arriving BEFORE HOF_LEASE_HELD/BUSY used to only call
  // markLost() - recording a loss, but neither claiming nor rejecting
  // the still-open acquisition - so a buffered HOF_LEASE_HELD arriving
  // right after could still win claim() farther down and resolve
  // successfully, handing the caller a lease that reports isLost() ===
  // true from the very first check. `acquireTimeout` is declared (but
  // not yet assigned) before claim() too - clearTimeout(undefined) is a
  // harmless no-op, so claim() being called before acquireTimeout exists
  // (only possible if a stdin error fires this early, before the timer
  // below is even armed) is always safe.
  let settled = false;
  let acquireTimeout;
  const claim = () => {
    if (settled) return false;
    settled = true;
    clearTimeout(acquireTimeout);
    return true;
  };
  let resolveAcquire, rejectAcquire;
  const acquirePromise = new Promise((resolve, reject) => { resolveAcquire = resolve; rejectAcquire = reject; });

  // A write to a pipe whose read end (or the whole remote process) is
  // already gone raises EPIPE asynchronously as an 'error' EVENT on the
  // stream, not a thrown exception from .write() itself - a second
  // review found the original try/catch around child.stdin.write(".")
  // in the heartbeat below could not and did not catch this, leaving an
  // unhandled stream error free to crash the whole process. Handled
  // exactly once, here, for the stream's entire lifetime.
  //
  // Item 9 THIRD review fix (finding 5): this used to only set
  // stdinErrored (read by the heartbeat interval, to stop retrying a
  // dead pipe, and by release(), to know child.stdin.end() would itself
  // throw) and otherwise wait for the SEPARATE child "exit" event to
  // eventually call markLost() - a real gap: a remote process that is
  // gone but whose own OS-level exit notification is merely delayed
  // (nothing here promises "at the same instant" for two independent
  // event sources on two different streams of the same child) left
  // isLost() reporting false for that whole window, even though the
  // stdin error had already, independently, proven the pipe - and so the
  // lease - is gone. markLost() is now called here directly and
  // immediately; markLost()'s own idempotency guard (lost ||
  // voluntarilyReleased) makes the later, likely-redundant call from
  // "exit" (if it still fires) harmless.
  //
  // Item 9 FOURTH review fix (finding 1): if acquisition itself has not
  // settled yet, THIS stdin error IS the acquisition's own outcome - it
  // now claims the promise and rejects it (after the same release()
  // teardown every other pre-acquisition failure path already uses),
  // exactly like the child's own "error"/"exit" handlers below already
  // do. Without this, a stdin error arriving before HOF_LEASE_HELD only
  // recorded a lost flag nothing yet consumed, leaving the race described
  // above wide open. release() itself is safe to call here even though
  // it is defined a few lines further down - this handler only ever
  // FIRES asynchronously, well after this function's own synchronous
  // setup (including release()'s own assignment) has completed.
  let stdinErrored = false;
  child.stdin.on("error", (error) => {
    stdinErrored = true;
    const message = `stdin error on the execution-lease helper's own connection: ${error instanceof Error ? error.message : error}`;
    markLost(message);
    if (claim()) {
      release().finally(() => rejectAcquire(new Error(message)));
    }
  });

  // Deliberately NOT ended here (unlike every other one-shot script in
  // this module) - see this function's own top comment. The heartbeat
  // below keeps writing to it; release() is what finally ends it.
  child.stdin.write(remote);
  const heartbeat = setInterval(() => {
    if (stdinErrored) return;
    try { child.stdin.write("."); } catch { /* the child may already be gone - release()/exit handle that */ }
  }, LEASE_HEARTBEAT_INTERVAL_MS);
  // Never keeps the whole Node process alive on its own - only real work
  // (an in-flight apply run) does that; this is bookkeeping.
  heartbeat.unref?.();

  const release = async () => {
    voluntarilyReleased = true;
    clearInterval(heartbeat);
    knownHostsCleanup();
    if (child.exitCode === null && child.signalCode === null) {
      // Sends EOF, not a signal - see this function's own top comment
      // on why a signal alone never reliably reached a `sudo`-isolated
      // remote child. The remote heartbeat loop notices (an EOF read
      // there breaks it immediately, well inside its own timeout
      // bound) and exits on its own; the SIGTERM/SIGKILL fallback
      // below is only for the local ssh/sudo child itself, in case the
      // remote side is somehow still not exiting promptly - never the
      // primary release mechanism.
      if (!stdinErrored) { try { child.stdin.end(); } catch { /* already gone */ } }
      await new Promise((res) => {
        const t = setTimeout(() => { child.kill("SIGTERM"); setTimeout(() => { child.kill("SIGKILL"); res(); }, 3000); }, 5000);
        child.once("exit", () => { clearTimeout(t); res(); });
      });
    }
  };

  let out = "";
  let err = "";
  // Item 9 THIRD review fix (finding 4): claim() SYNCHRONOUSLY decides
  // who wins the race to settle this promise, and does so the instant
  // whichever handler runs first starts running - separated from
  // actually calling resolve/reject, which may need to `await
  // release()` first. The OLD code (a single `finish(fn, arg)` that
  // checked-and-set `settled` only ONCE it was already ready to call
  // fn(arg)) had a real gap here: the timeout path calls release()
  // (async - clearInterval, knownHostsCleanup, then possibly an awaited
  // child teardown) BEFORE it ever touched `settled`, leaving a real
  // window, for the whole duration of that await, during which
  // `settled` was still false. A HOF_LEASE_HELD chunk already in
  // flight and delivered to the stdout "data" handler during exactly
  // that window would see `!settled`, call its OWN finish(resolve,
  // {...}), and WIN - resolving this call successfully with a lease
  // object for a lease this function had already committed to
  // releasing and was about to reject as timed out (a real,
  // independently reachable split-brain source: the CALLER believes it
  // holds the lease while release() is concurrently, genuinely
  // dropping it on the target). claim() closes this: `settled` is now
  // set (and the timeout cleared) synchronously, before ANY async work
  // begins, on every one of the five paths now sharing it (the stdin
  // error handler above included) - whichever one actually runs first is
  // decided the instant it starts running (JS has no interleaving
  // mid-callback), and every later claim() call is then a guaranteed
  // no-op, however long that first caller's own async cleanup goes on to
  // take.
  acquireTimeout = setTimeout(() => {
    if (!claim()) return;
    const timeoutError = new Error(`execution-lease helper confirmed neither held nor busy within ${executionLeaseAcquireTimeoutMs}ms - the target may be unreachable or hung; refusing to wait indefinitely`);
    release().finally(() => rejectAcquire(timeoutError));
  }, executionLeaseAcquireTimeoutMs);

  child.stdout.on("data", (chunk) => {
    out += chunk.toString();
    if (out.includes("HOF_LEASE_HELD")) {
      if (!claim()) return;
      resolveAcquire({
        release,
        isLost: () => lost,
        lostReason: () => lostReasonValue,
        onLost: (callback) => { lostCallbacks.push(callback); },
      });
    } else if (out.includes("HOF_LEASE_BUSY")) {
      if (!claim()) return;
      release().finally(() => rejectAcquire(new Error(`another apply process already holds the execution lease for this target (${EXECUTION_LEASE_PATH}) - refusing to run a second, concurrent apply/resume against the same host`)));
    }
  });
  child.stderr.on("data", (chunk) => { err += chunk.toString(); });
  child.on("error", (error) => {
    clearInterval(heartbeat);
    knownHostsCleanup();
    if (claim()) { rejectAcquire(error); return; }
    markLost(error instanceof Error ? error.message : String(error));
  });
  child.on("exit", (code, signal) => {
    clearInterval(heartbeat);
    knownHostsCleanup();
    const exitError = new Error(`execution-lease helper exited before the lease was confirmed (code ${code}, signal ${signal})${err.trim() ? `: ${err.trim().split("\n").slice(-3).join("; ")}` : ""}`);
    if (claim()) { rejectAcquire(exitError); return; }
    markLost(`the execution-lease helper process exited unexpectedly (code ${code}, signal ${signal}) - the lease is no longer held`);
  });

  // Item 9 FOURTH review fix (finding 1): a caller must never receive a
  // lease that is already known lost - possible if markLost() fired
  // (post-claim, from the child's own "exit"/"error" handlers above) in
  // the narrow window between resolveAcquire() being called and this
  // await actually returning control here (both are plain microtask
  // continuations, so the window is tiny, but not provably zero - a
  // caller acting on isLost() only inside its own dispatch loop, as
  // apply.mjs used to, is exactly the fail-open runApply() itself now
  // additionally guards against, see its own comment on why THIS check
  // alone is not sufficient by itself). Checked here too, as the
  // cheapest possible place to close it for every caller at once: a
  // lease that resolved lost is released immediately and reported as an
  // acquisition failure, never handed back as if it were healthy.
  const lease = await acquirePromise;
  if (lease.isLost()) {
    await lease.release().catch(() => {});
    throw new Error(`execution lease resolved already lost (${lease.lostReason()}) - refusing to hand back a lease that was never actually healthy`);
  }
  return lease;
}
