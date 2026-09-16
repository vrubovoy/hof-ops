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
// Same shape as an operationId (randomUUID()) but a genuinely separate
// concept - see acquireMutex()'s own comment on what a mutex token
// identifies. Validated with its own pattern (not OPERATION_ID_PATTERN
// reused) so a caller passing the wrong kind of id to the wrong
// validator gets a message naming the thing it actually is.
const MUTEX_TOKEN_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function validateSshDestination(host, user, port) {
  if (typeof host !== "string" || !HOSTNAME_PATTERN.test(host)) throw new Error(`refusing to connect: "${host}" is not a valid hostname`);
  if (typeof user !== "string" || !USERNAME_PATTERN.test(user)) throw new Error(`refusing to connect: "${user}" is not a valid SSH username`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`refusing to connect: ${port} is not a valid port number`);
}

function validateOperationId(operationId) {
  if (!OPERATION_ID_PATTERN.test(operationId)) throw new Error(`"${operationId}" is not a valid operationId`);
  return operationId;
}

function validateLeaseToken(leaseToken) {
  if (!MUTEX_TOKEN_PATTERN.test(leaseToken)) throw new Error(`"${leaseToken}" is not a valid execution-lease token`);
  return leaseToken;
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
// leaseToken (optional): PR 2 (item 10) second review, high finding 2 -
// without this, a holder that already lost the physical mutex (self-
// expired, or explicitly released) could still create a brand new
// lock+journal pair afterward, since nothing here ever checked whether
// the caller was still the genuine mutex owner. Fenced the same way
// every other lease-gated write already is - see leaseFencingScript()'s
// own comment - and, since this already runs inside withLockGuard(),
// costs nothing extra to add: the SAME critical section that now also
// serializes every owner-record read/write (acquireMutex()'s own held
// script, heartbeat, and release all take this identical guard).
function acquireLockAndJournalScript(leaseToken, lockPayload, journalTargetPath, journalPayload) {
  return fencedWriteScript(leaseToken, `lock_payload='${lockPayload}'
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
const EXECUTION_LEASE_PATH = "/var/lib/hof/state/exec.lease";
const EXECUTION_LEASE_OWNER_PATH = "/var/lib/hof/state/exec.lease.owner";

// PR 2 (item 10) fifth review, high finding 1: extracts a PID's own
// CURRENT start time - field 22 of /proc/<pid>/stat - into resultVar
// (left empty if that pid doesn't exist, or never existed). Kernel-
// synchronous and immediate, unlike `systemctl is-active` (see
// leaseFencingScript()'s own comment on why that mattered). Robust
// against /proc/<pid>/stat's own 2nd field (`comm`, in parens) itself
// containing spaces or even parens - a well-known parsing pitfall this
// avoids by stripping everything through the LAST ") " before splitting
// the remaining, always-simple numeric fields on whitespace (confirmed
// against a deliberately pathological comm value before landing on
// this). Returned as an array of plain shell statements (never a single
// nested $(...) expression - this file's own scripts are transmitted as
// flat text with no compatibility guarantee for deeply nested command
// substitution across every shell this might ever run under) - a caller
// joins them with "; " (an array-based script, like heldScript) or "\n"
// (a multi-line template literal, like every other script here).
function procStartTimeStatements(pidExpr, resultVar) {
  return [
    `${resultVar}=""`,
    `if [ -r /proc/${pidExpr}/stat ]; then`,
    `stat_line=$(cat /proc/${pidExpr}/stat 2>/dev/null) || stat_line=""`,
    "after_comm=${stat_line##*\\) }",
    "set -- $after_comm",
    `${resultVar}=\${20:-}`,
    "fi",
  ];
}

// PR 2 (item 10) review: appendEvent()/updateJournalStatus() used to
// trust their own CALLER's cached isLost() check alone - a real
// TOCTOU gap (a lease genuinely lost strictly between that check and
// this write actually reaching the target, or a caller that simply
// never checked at all) let a stale lease-holder's own write land on
// the target with nothing there to refuse it. This is the real,
// target-side fencing check every lease-gated write now runs INSIDE
// its own flock guard (the same one acquireMutex()'s held script uses
// to serialize acquisition against release - see that function's own
// comment): the write proceeds only if the owner record still holds
// EXACTLY this leaseToken AND its own claimed PID is genuinely still
// alive with a matching start time - otherwise nothing is written at
// all, atomically, decided under the same mutual exclusion the mutex
// itself already provides - never merely a client-side, best-effort
// check. leaseToken is optional (omitted entirely for a caller with no
// lease concept at all) - when omitted, this returns an empty string
// and the write proceeds unguarded, exactly like before this review.
//
// PR 2 fourth review, high finding 1's own fix (a `systemctl is-active`
// check) was itself superseded by the fifth review: ActiveState is an
// ASYNCHRONOUS, userspace-bookkeeping signal - after a hard kill, the
// KERNEL releases every flock the dying process held IMMEDIATELY (as
// part of process exit itself), but systemd's own ActiveState
// transition is a SEPARATE, unsynchronized event on systemd's own event
// loop - a real window where the kernel already freed the mutex but
// `systemctl is-active` still answers "active". The fourth review's own
// attempted fix - a kernel-level, non-blocking EXCLUSIVE probe taken
// BEFORE this write's own shared hold - turned out to have its own,
// different race: the probe only proves the state at the INSTANT it
// runs, with no link to the write's own LATER shared-lock acquisition
// and fencing decision - the real holder could die in the gap between
// the probe succeeding (finding it alive) and this write actually
// taking its own shared fd, and the STILL-unmodified owner record would
// then pass the very next check regardless.
//
// This is fixed for real by moving the liveness check to run AFTER
// fencedWriteScript() has ALREADY taken this write's own shared hold on
// EXECUTION_LEASE_PATH (see that function's own comment on why that
// hold is what actually matters) - once held, NO new acquisition can
// possibly complete its own handoff (write a fresh token into the owner
// record) until this write releases, so a liveness check made from
// HERE ON stays valid for the rest of this write's own lifetime, not
// merely at one earlier instant. The check itself no longer asks
// systemd at all: the owner record now carries the holder's own PID and
// start time (written by heldScript below) alongside the token -
// procStartTimeStatements() re-derives that PID's CURRENT start time
// fresh from /proc, kernel-synchronous and immediate. A PID that no
// longer exists at all, or one that does but whose start time no longer
// matches (the PID number was reused by a genuinely different process
// in the meantime - a real, if rare, possibility this guards against
// deliberately, not a hypothetical), both mean the claimed holder is
// definitively gone; only a start time that still matches is trusted.
function leaseFencingScript(leaseToken) {
  if (leaseToken === undefined) return "";
  validateLeaseToken(leaseToken);
  return `if [ ! -r '${EXECUTION_LEASE_OWNER_PATH}' ]; then
  echo HOF_MUTATE_LEASE_MISMATCH
  exit 0
fi
read -r owner_token owner_pid owner_starttime < '${EXECUTION_LEASE_OWNER_PATH}' || true
if [ "$owner_token" != '${leaseToken}' ]; then
  echo HOF_MUTATE_LEASE_MISMATCH
  exit 0
fi
${procStartTimeStatements("$owner_pid", "current_starttime").join("\n")}
if [ -z "$current_starttime" ] || [ "$current_starttime" != "$owner_starttime" ]; then
  echo HOF_MUTATE_LEASE_MISMATCH
  exit 0
fi
`;
}

// How long a fenced write's own shared flock on EXECUTION_LEASE_PATH
// (see fencedWriteScript() below) waits to be granted before giving up -
// bounded rather than an unbounded blocking wait, matching this whole
// module's own "never wait indefinitely" discipline. Generous relative
// to how long the brief exclusive-then-downgrade window a genuine
// acquisition/self-expiry ever needs actually takes (fractions of a
// second) - a wait anywhere near this bound already means something is
// genuinely wrong, not merely contended.
const LEASE_SHARED_FLOCK_WAIT_S = 10;

// PR 2 (item 10) third review, critical finding 1: leaseFencingScript()
// alone still made the WHOLE correctness guarantee rest on every single
// owner-record-touching code path remembering to take LOCK_GUARD_PATH's
// guard, forever, with no independent backstop - a real gap if a future
// write path (or a bug in an existing one) ever forgot. This adds a
// second, kernel-enforced barrier that doesn't depend on that discipline
// alone: a fenced write now ALSO takes a SHARED flock on
// EXECUTION_LEASE_PATH itself (a separate fd from LOCK_GUARD_PATH's own),
// held for the write's ENTIRE remaining script (the fencing check AND
// the actual mutation) - and acquireMutex()'s own held script (see its
// own comment) now holds that SAME file with a SHARED flock too
// (downgraded from an initial EXCLUSIVE check, atomically, on the same
// fd - see flock(2): "subsequent flock() calls on an already locked
// file will convert an existing lock to the new lock mode"), instead of
// holding it exclusively for its whole lifetime. Multiple SHARED
// holders (the current holder, plus any number of in-flight fenced
// writes) coexist freely - flock's own kernel semantics guarantee a NEW
// acquisition's own EXCLUSIVE attempt on this same file cannot succeed
// while ANY of them - the current holder OR any write still in flight,
// regardless of which token it carries - still holds it. This closes
// the residual window a lock.flock-only design left structurally open:
// once this hold is taken, no new acquisition can even begin to take
// over until this write finishes (or fails on its own terms) - never
// interleaved with one, regardless of whether every future write path
// remembers LOCK_GUARD_PATH correctly on its own.
//
// PR 2 fourth review, high finding 1 added (and the fifth review then
// REMOVED) a kernel-level, non-blocking EXCLUSIVE probe taken BEFORE
// this shared hold - see leaseFencingScript()'s own comment on why that
// probe had its own, different race (a snapshot with no link to this
// write's own later shared-lock acquisition) and was superseded by
// moving liveness verification to run AFTER this hold instead, inside
// leaseFencingScript() itself.
function fencedWriteScript(leaseToken, criticalSection) {
  if (leaseToken === undefined) return withLockGuard(criticalSection);
  return `set -eu
mkdir -p "$(dirname '${EXECUTION_LEASE_PATH}')"
exec 7>'${EXECUTION_LEASE_PATH}'
flock -w ${LEASE_SHARED_FLOCK_WAIT_S} -s 7
${withLockGuard(`${leaseFencingScript(leaseToken)}${criticalSection}`)}`;
}

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
export async function acquireLockAndJournal(conn, lockDocument, journalDocument, leaseToken) {
  const stdout = await runScript(conn, acquireLockAndJournalScript(leaseToken, b64(lockDocument), journalPath(journalDocument.operationId), b64(journalDocument)));
  const [tag, ...rest] = stdout.split("\n");
  if (tag === "HOF_MUTATE_LEASE_MISMATCH") throw new Error(`refusing to create lock/journal for operation ${journalDocument.operationId}: the execution lease no longer matches this write's own token on the target - another process may now hold it, or it has already self-expired`);
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
//
// PR 2 (item 10) review: this used to write via a FIXED `targetPath.tmp`
// name with no serialization of its own at all - two writers racing the
// same fixed name (a genuine bug, a hand-run recovery script, or this
// same function called for two different but overlapping reasons) could
// each clobber the other's still-in-flight tmp file before its own
// rename ran, exactly the class of bug acquireLockAndJournalScript()'s
// own mktemp+ln fix already closed for lock/journal CREATION. Now runs
// inside the SAME target-side flock guard that serializes lock/journal
// creation (withLockGuard() - see its own comment), and uses a genuinely
// unique mktemp name rather than a fixed one, for the same defense-in-
// depth reason. Shared by both apply (v1) and backup/restore (v2) -
// target-mutate.mjs's own raw persistence functions carry no
// schema-specific logic at all (see this file's own top comment), so a
// v2 journal update needs no separate implementation.
//
// leaseToken (optional): when given, the write is target-side fenced
// against the current execution-lease owner record BEFORE it happens,
// atomically, under this same flock guard - see leaseFencingScript()'s
// own comment on why this closes a real gap a caller-side isLost()
// check alone cannot (a lease lost strictly between that check and this
// write actually reaching the target). Omitted only by a caller with no
// lease concept of its own.
//
// expectedPreviousDocument (optional): PR 2 (item 10) second review,
// high finding 4 - a caller (operation-v2.mjs's own writeJournalStatus())
// typically reads the persisted journal, validates a candidate
// transition against it in JS, and only THEN calls this - two separate
// round trips, with a real gap between them where a DIFFERENT writer
// could land its own transition first. leaseToken alone does not close
// this (both writers could legitimately hold the SAME lease sequentially,
// or this could simply be a caller bug) - a real compare-and-swap does:
// when given, the write proceeds only if the target's CURRENT content at
// this exact targetPath is still byte-for-byte identical to
// expectedPreviousDocument, checked atomically, under this same flock
// guard, immediately before the write - if anything already changed it,
// this refuses with HOF_MUTATE_CAS_CONFLICT rather than blindly
// overwriting whatever is actually there now.
// PR 2 review, Low finding (third round, proactively applied here too -
// same bug pattern the reviewer found in journalGuardForEventScript()
// below): compares the base64-ENCODED form of the file's actual bytes,
// not the decoded text - see that function's own comment for why a
// decoded-text comparison is not genuinely byte-for-byte (command
// substitution strips every trailing newline from both sides alike).
function journalCasCheckScript(targetPath, expectedPreviousDocument) {
  if (expectedPreviousDocument === undefined) return "";
  return `expected_payload='${b64(expectedPreviousDocument)}'
if [ ! -r '${targetPath}' ] || [ "$(base64 < '${targetPath}' | tr -d '\\n')" != "$expected_payload" ]; then
  echo HOF_MUTATE_CAS_CONFLICT
  exit 0
fi
`;
}

export async function updateJournalStatus(conn, journalDocument, leaseToken, expectedPreviousDocument) {
  const targetPath = journalPath(journalDocument.operationId);
  const script = fencedWriteScript(leaseToken, `${journalCasCheckScript(targetPath, expectedPreviousDocument)}payload='${b64(journalDocument)}'
tmp=$(mktemp '${targetPath}.XXXXXX')
printf '%s' "$payload" | base64 -d > "$tmp"
mv -f "$tmp" '${targetPath}'
echo HOF_MUTATE_UPDATED`);
  const stdout = await runScript(conn, script);
  const tag = stdout.split("\n")[0];
  if (tag === "HOF_MUTATE_LEASE_MISMATCH") throw new Error(`refusing to update the journal for operation ${journalDocument.operationId}: the execution lease no longer matches this write's own token on the target - another process may now hold it, or it has already self-expired`);
  if (tag === "HOF_MUTATE_CAS_CONFLICT") throw new Error(`refusing to update the journal for operation ${journalDocument.operationId}: the persisted document on the target no longer matches what was last read - another writer already landed a different transition first`);
  if (tag !== "HOF_MUTATE_UPDATED") throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
}

// PR 2 (item 10) third review, high finding 4: appendEvent()'s own
// caller (operation-v2.mjs's own writeEvent()) reads the persisted
// journal, validates the event's own step/destination against it, and
// only THEN calls this - the exact same two-round-trip gap
// updateJournalStatus()'s own journalCasCheckScript() above already
// closes for journal WRITES, now closed for EVENT writes too: the
// append proceeds only if the journal is (a) still exactly
// expectedJournalSnapshot, byte-for-byte (a real compare-and-swap,
// catching ANY change, benign or not, since the read) and (b), checked
// independently and reported distinctly for a clearer diagnosis, not
// already terminal (a case CAS alone would also catch, but reported as
// a generic conflict rather than the more specific, more actionable
// "this operation already finished" it actually is). `"status":"..."`
// is a fixed, compact substring JSON.stringify always produces
// verbatim, regardless of surrounding key order - safe to match with a
// plain case pattern, no JSON parser needed in shell.
// PR 2 review, Low finding (third round): the CAS comparison used to
// decode both sides ($(cat targetPath) and $(printf ... | base64 -d))
// before comparing them - but $(...) command substitution strips EVERY
// trailing newline from its own output, on BOTH sides alike. A journal
// file altered by nothing but an appended trailing newline (a real,
// if narrow, tampering/corruption case) would compare EQUAL despite its
// true bytes genuinely differing - not the byte-for-byte comparison
// this function's own name and comment claimed. Fixed: compare the
// base64-ENCODED form of the file's actual bytes instead of the decoded
// text - base64 encodes every input byte (a trailing \n included) into
// its own alphabet, never as a literal newline character in the
// encoded output itself, so encoding-then-comparing is immune to
// command substitution's own trailing-newline stripping (which only
// ever removes base64's own single, cosmetic, format-level trailing
// newline - not anything reflecting the FILE's real content). Piped
// through `tr -d '\n'` (never GNU coreutils' own `base64 -w0` - the
// same portable technique target-probe.sh's own base64 encoding already
// uses elsewhere in this repo, rather than adding an unnecessary
// platform-specific dependency of this primitive's own). The terminal-
// status check below still safely uses the decoded text - a substring
// match is unaffected by trailing-newline-stripping either way, since
// it never depends on matching the very end of the string.
function journalGuardForEventScript(journalTargetPath, expectedJournalSnapshot) {
  if (expectedJournalSnapshot === undefined) return "";
  return `expected_journal_payload='${b64(expectedJournalSnapshot)}'
if [ ! -r '${journalTargetPath}' ]; then
  echo HOF_MUTATE_CAS_CONFLICT
  exit 0
fi
case "$(cat '${journalTargetPath}')" in
  *'"status":"succeeded"'*|*'"status":"failed"'*)
    echo HOF_MUTATE_JOURNAL_TERMINAL
    exit 0
    ;;
esac
current_journal_payload=$(base64 < '${journalTargetPath}' | tr -d '\\n')
if [ "$current_journal_payload" != "$expected_journal_payload" ]; then
  echo HOF_MUTATE_CAS_CONFLICT
  exit 0
fi
`;
}

// Append-only NDJSON - one line per event, never rewritten or reordered.
// PR 2 (item 10) review: now also serialized through the same target-
// side flock guard as updateJournalStatus()/acquireLockAndJournal() -
// see that function's own comment on why. A single `>>` append is
// already atomic at the syscall level for a write this small, but
// serializing it too keeps every writer to one operationId's own
// journal/events pair strictly ordered against every other one, never
// relying on that syscall-level guarantee alone.
//
// leaseToken (optional): same target-side fencing as
// updateJournalStatus() above - see its own comment.
//
// expectedJournalSnapshot (optional): PR 2 third review, high finding 4
// - see journalGuardForEventScript()'s own comment. Required by
// operation-v2.mjs's own writeEvent() (the v2-wrapped path); omitted by
// v1/apply.mjs, which has no such journal-CAS concept of its own.
export async function appendEvent(conn, operationId, event, leaseToken, expectedJournalSnapshot) {
  const targetPath = eventsPath(operationId);
  const journalTargetPath = journalPath(operationId);
  const script = fencedWriteScript(leaseToken, `${journalGuardForEventScript(journalTargetPath, expectedJournalSnapshot)}payload='${b64(event)}'
mkdir -p "$(dirname '${targetPath}')"
printf '%s\\n' "$(printf '%s' "$payload" | base64 -d)" >> '${targetPath}'
echo HOF_MUTATE_APPENDED`);
  const stdout = await runScript(conn, script);
  const tag = stdout.split("\n")[0];
  if (tag === "HOF_MUTATE_LEASE_MISMATCH") throw new Error(`refusing to append an event for operation ${operationId}: the execution lease no longer matches this write's own token on the target - another process may now hold it, or it has already self-expired`);
  if (tag === "HOF_MUTATE_JOURNAL_TERMINAL") throw new Error(`refusing to append an event for operation ${operationId}: the persisted journal is already terminal - no further events are ever appended once an operation has genuinely finished`);
  if (tag === "HOF_MUTATE_CAS_CONFLICT") throw new Error(`refusing to append an event for operation ${operationId}: the persisted journal on the target no longer matches what was last read - another writer already changed it`);
  if (tag !== "HOF_MUTATE_APPENDED") throw new Error(`unexpected target-mutate response: ${JSON.stringify(stdout)}`);
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

const MUTEX_UNIT_PREFIX = "hof-exec-lease-";

// How often the local side re-confirms ownership (a heartbeat, not a
// passive read - see assertMutexScript()'s own comment: each call
// refreshes the owner record's own mtime), and how long the target-side
// unit waits without a fresh one before voluntarily giving up the flock
// itself. Same two numbers item 9's own SSH-heartbeat design used - not
// copied for nostalgia, but because they were already the result of
// real, live validation against a real target (see PR2's own review
// history) and there is no reason to pick new ones now that the
// TRANSPORT carrying the heartbeat changed, not the operational
// tradeoff itself (how quickly a genuinely dead local process should
// free the mutex for a fresh --resume, versus how much transient
// network jitter must be tolerated first).
const LEASE_HEARTBEAT_INTERVAL_MS = 10_000;
const LEASE_HEARTBEAT_TIMEOUT_S = 30;
// How often the held unit itself re-checks its own owner record's mtime
// against LEASE_HEARTBEAT_TIMEOUT_S - a fraction of that bound, so
// expiry is noticed promptly once it's actually due, not polled so
// tightly it burns real target-side CPU for no reason.
const LEASE_SELF_CHECK_INTERVAL_S = 5;
// How long (and how often) the acquire script itself polls the
// transient unit's own systemd state before giving up - this is a
// purely LOCAL, near-instantaneous systemd state transition (flock -n
// is non-blocking by construction), never network-bound the way the old
// design's heartbeat-timeout was, so this bound is short; the SSH
// connection's own connectTimeoutSeconds is what actually bounds a
// genuinely unreachable or hung target, exactly like every other
// target-mutate function (this one reuses the same runScript()/`run`
// seam, unlike the old design's own separate long-lived spawn).
const LEASE_ACQUIRE_POLL_ATTEMPTS = 100;
const LEASE_ACQUIRE_POLL_INTERVAL_S = "0.1";

function mutexUnitName(token) {
  if (!MUTEX_TOKEN_PATTERN.test(token)) throw new Error(`internal error: "${token}" is not a valid mutex token`);
  return `${MUTEX_UNIT_PREFIX}${token}`;
}

// Item 9 review fix (finding 3), superseded by PR2 (item 10): the
// durable lock.json is a PERSISTENCE lock - it survives a crash so
// --resume can find an interrupted operation. It is NOT a liveness
// lease: two `hofctl apply --resume` processes both read the same lock,
// both see the same events, and both go on to dispatch the same step.
// This is a PROCESS-LIFETIME execution mutex on top of it, shared by
// apply/backup/restore alike (ADR 0006's own "one physical execution
// mutex across all three kinds") - held by a target-side, TRANSIENT
// SYSTEMD UNIT, never by a long-lived local SSH/spawn child the way the
// original ADR 0004 design did.
//
// That original design (a foreground child holding flock via an SSH
// heartbeat - see git history for its own three-review-round account of
// why a bare signal, then a bare stdin-EOF, both provably failed to
// notice a dead local process promptly) tied the mutex's own lifetime to
// ONE specific SSH channel staying open for the whole run. This design
// decouples them: a systemd unit is a real, durable target-side
// resource, independent of any one SSH connection - acquiring, checking,
// and releasing it are all ordinary, bounded, ONE-SHOT round trips
// through the exact same runScript()/`run` seam every other function in
// this module already uses (no persistent streaming child, no spawnFn
// seam, no signal/EPIPE/session-isolation complexity at all). The same
// crash-safety property the old design had is preserved differently: the
// unit itself is the one that self-expires (LEASE_HEARTBEAT_TIMEOUT_S
// after its own owner record's mtime stops advancing), not a remote
// process reacting to a closed pipe - so a local process that dies
// uncleanly (SIGKILL, a lost laptop) still leaves the target free for a
// fresh --resume within the same bound the old design promised, without
// depending on sudo/ssh/the kernel promptly noticing a closed connection
// at all.
//
// acquireMutex(conn) returns { release, isLost, lostReason, onLost,
// assertOwnership } on success. Throws on contention (another live
// apply/backup/restore holds it) or a transport failure - the caller
// turns the former into blocked("lease", ...) and must NOT release the
// durable lock (the other process legitimately owns the operation).
// isLost()/lostReason()/onLost() work exactly like the old design's own
// (apply.mjs's own dispatch loop checks isLost() before every operation
// and refuses to start a new one once lost - fail-closed, unchanged);
// assertOwnership() is additionally exposed so a caller (or a test) can
// force an immediate check rather than waiting on the background
// interval below.
export async function acquireMutex(conn) {
  const {
    mode, host, port, user, hostKeySha256, identityFile, connectTimeoutSeconds = 10, run = defaultRun,
    // Overridable only so test/target-mutate.test.mjs's own tests don't
    // have to wait out the real, generous default - the real CLI never
    // sets this.
    mutexHeartbeatIntervalMs = LEASE_HEARTBEAT_INTERVAL_MS,
  } = conn;
  const scriptConn = { mode, host, port, user, hostKeySha256, identityFile, connectTimeoutSeconds, run };
  const token = randomUUID();
  const unit = mutexUnitName(token);

  // The held unit's own script - never wrapped in an outer single-quoted
  // /bin/sh -c argument that also contains single quotes of its own (a
  // real quoting hazard): every literal this embeds (the fixed lease/
  // owner/guard paths, the token, the two bounds) is quote-free by
  // construction (no spaces, no shell metacharacters), so the whole
  // thing can be safely wrapped in a single pair of outer single quotes
  // by acquireMutexScript() below without any nested-quote escaping.
  //
  // PR 2 (item 10) second review, critical finding 1: the ORIGINAL
  // version of this script wrote the owner record (`printf ... >
  // OWNER_PATH`) with no guard at all, and - the real, always-
  // reproducible bug, not a narrow timing race - its self-expiry branch
  // was a bare `exit 0`: it never cleared the owner record at all. A
  // stale token therefore stayed "fencing-valid" on the target FOREVER
  // after the unit that wrote it had already self-expired and exited
  // (releasing the real flock) - any delayed write still carrying that
  // token would pass the fencing check in leaseFencingScript() even
  // though nothing was actually holding the mutex any more. Fixed: fd 8
  // (LOCK_GUARD_PATH, the SAME guard every fenced write already takes -
  // see leaseFencingScript()'s own comment) now serializes every single
  // read-or-write of the owner record this unit ever performs - the
  // initial write (only after flock -n -x 9 on fd 9 has genuinely
  // succeeded) and, critically, the self-expiry branch now actually
  // REMOVES the owner record before exiting, under that same guard, so
  // a fencing check run after self-expiry sees an absent owner record
  // (leaseFencingScript()'s own `[ ! -r OWNER_PATH ]` branch) rather
  // than a stale, still-matching token.
  // PR 2 (item 10) third review, critical finding 1: still holds
  // EXECUTION_LEASE_PATH's own fd 9 EXCLUSIVELY only for the brief
  // instant needed to prove no one else currently holds ANY lock on it
  // (neither another holder nor an in-flight fenced write, which now
  // also takes a lock on this same file - see fencedWriteScript()'s own
  // comment) - then immediately, atomically downgrades the SAME fd to
  // SHARED (`flock -s 9`, converting in place per flock(2), never
  // releasing it even momentarily) for the rest of its own lifetime.
  // Shared coexists with every fenced write's own shared hold; it does
  // NOT coexist with a FUTURE acquisition's own exclusive check, which
  // is exactly the point - see fencedWriteScript()'s own comment for
  // the full reasoning.
  // PR 2 (item 10) fifth review, high finding 1: the owner record now
  // carries this unit's own PID and start time alongside its token -
  // see procStartTimeStatements()'s own comment - so a fenced write's
  // own leaseFencingScript() can verify genuine, current liveness via
  // /proc directly, kernel-synchronous and immediate, never through
  // systemd's own asynchronous ActiveState.
  const heldScript = [
    `exec 9>${EXECUTION_LEASE_PATH}`,
    "if flock -n -x 9; then",
    "flock -s 9",
    `exec 8>${LOCK_GUARD_PATH}`,
    "flock -x 8",
    "umask 077",
    ...procStartTimeStatements("$$", "own_starttime"),
    // No quotes available here (heldScript is wrapped whole in a single
    // pair of outer single quotes by acquireMutexScript() below) - a
    // multi-word printf format string like '%s %s %s' would need
    // quoting to survive as ONE argument, so this uses echo with
    // backslash-escaped (not quoted) spaces between the three fields
    // instead, confirmed correct against a real POSIX sh (dash) before
    // landing on it: unquoted `\ ` always produces a literal space
    // within one argument word, for any command, without needing
    // quotes at all - and echo's own default trailing newline is what
    // makes read -r (in leaseFencingScript() below) return a clean 0
    // status reading this file back, rather than the >0 status read
    // returns when it hits EOF with no trailing newline (confirmed:
    // read -r still populates every variable correctly even then, but
    // set -eu would abort the whole script on that spurious nonzero
    // status regardless).
    `echo ${token}\\ $$\\ "$own_starttime" > ${EXECUTION_LEASE_OWNER_PATH}`,
    "flock -u 8",
    "while :; do",
    `sleep ${LEASE_SELF_CHECK_INTERVAL_S}`,
    "flock -x 8",
    `mtime=$(stat -c %Y ${EXECUTION_LEASE_OWNER_PATH} 2>/dev/null) || { flock -u 8; exit 0; }`,
    "now=$(date +%s)",
    `if [ $((now - mtime)) -gt ${LEASE_HEARTBEAT_TIMEOUT_S} ]; then rm -f ${EXECUTION_LEASE_OWNER_PATH}; flock -u 8; exit 0; fi`,
    "flock -u 8",
    "done",
    "else",
    "exit 1",
    "fi",
  ].join("; ");

  // PR 2 (item 10) review, Critical finding 1: systemctl reporting a
  // unit "active" does NOT by itself prove ITS OWN flock -n -x actually
  // succeeded - Type=simple/exec both report ActiveState=active the
  // instant the process starts (forks/execs), which happens well before
  // the script inside it ever reaches its own `flock -n -x 9` line. Two
  // genuinely concurrent acquisitions can both observe "active" during
  // that shared window and both conclude HOF_LEASE_HELD - a real,
  // reproducible double-acquisition, not a hypothetical one. flock -n -x
  // itself IS atomic at the kernel level (only one process total can
  // ever be inside the winning branch of heldScript's own `if` at a
  // time) - the bug was purely in how this poll interpreted "active" as
  // proof, without ever confirming THIS acquisition is the one that
  // actually won it. Fixed: "active" alone is never enough - the owner
  // record must ALSO already hold this exact acquisition's own token,
  // which heldScript's own winning branch only ever writes AFTER
  // flock -n -x 9 has genuinely succeeded. Observing "active" with a
  // owner record that isn't (yet, or ever) this token is deliberately
  // NOT treated as busy either - the real winner (whoever it is) may
  // simply not have reached its own printf yet; only this specific
  // unit's own later "failed" state (the losing branch's `exit 1`,
  // reached once its own flock -n -x has genuinely resolved negatively)
  // is trusted as proof of loss.
  //
  // This poll's own `cat` of the owner record deliberately does NOT take
  // the LOCK_GUARD_PATH guard heldScript's own write (and every fenced
  // write/expiry/release) now does - not an oversight, a real, checked
  // property: the write is a single `printf '%s' TOKEN > FILE`, one
  // write() syscall for a fixed ~36-byte token, which is atomic at the
  // filesystem level for a regular file this small - a concurrent,
  // unguarded reader can only ever observe either the FULL old content,
  // the FULL new content, or (during the `>` redirection's own initial
  // truncate) an EMPTY file; it can never observe a torn, partial token
  // that happens to coincidentally equal this acquisition's own real
  // token. The comparison below is therefore never a false POSITIVE
  // (only ever a false negative - "not yet visible, keep polling" -
  // which the loop already handles correctly), so guarding this
  // particular read buys no additional correctness, only extra round
  // trips on every one of up to LEASE_ACQUIRE_POLL_ATTEMPTS poll
  // iterations.
  const acquireScript = `set -eu
mkdir -p "$(dirname '${EXECUTION_LEASE_PATH}')"
systemd-run --unit='${unit}' --quiet -- /bin/sh -c '${heldScript}' >/dev/null 2>&1
i=0
while [ "$i" -lt ${LEASE_ACQUIRE_POLL_ATTEMPTS} ]; do
  state=$(systemctl is-active '${unit}.service' 2>/dev/null || true)
  if [ "$state" = active ]; then
    owner_token=""
    read -r owner_token _ _ < '${EXECUTION_LEASE_OWNER_PATH}' 2>/dev/null || true
    if [ "$owner_token" = '${token}' ]; then
      echo HOF_LEASE_HELD
      exit 0
    fi
  fi
  if [ "$state" = failed ]; then
    systemctl reset-failed '${unit}.service' >/dev/null 2>&1 || true
    echo HOF_LEASE_BUSY
    exit 0
  fi
  i=$((i + 1))
  sleep ${LEASE_ACQUIRE_POLL_INTERVAL_S}
done
systemctl reset-failed '${unit}.service' >/dev/null 2>&1 || true
echo HOF_LEASE_TIMEOUT
`;

  let stdout;
  try {
    stdout = await runScript(scriptConn, acquireScript);
  } catch (error) {
    throw new Error(`could not acquire the execution lease for this target: ${error instanceof Error ? error.message : error}`);
  }
  const tag = stdout.split("\n")[0];
  if (tag === "HOF_LEASE_BUSY") {
    throw new Error(`another apply/backup/restore process already holds the execution lease for this target (${EXECUTION_LEASE_PATH}) - refusing to run a second, concurrent operation against the same host`);
  }
  if (tag === "HOF_LEASE_TIMEOUT") {
    throw new Error(`the execution-lease helper unit confirmed neither held nor busy within its own acquire poll - the target's systemd may be unreachable or hung; refusing to wait indefinitely`);
  }
  if (tag !== "HOF_LEASE_HELD") {
    throw new Error(`unexpected target-mutate response acquiring the execution lease: ${JSON.stringify(stdout)}`);
  }

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

  // The heartbeat AND the liveness check are the same call: this
  // doesn't just READ the owner record, it re-touches its mtime,
  // exactly what the held unit's own self-check loop is watching for
  // (see heldScript above) - a passive read-only check here would let
  // the unit expire out from under a caller that dutifully polled
  // isLost() but never actually refreshed liveness on the target.
  //
  // PR 2 (item 10) second review, critical finding 1: the check-and-
  // touch here now also runs under the SAME LOCK_GUARD_PATH guard
  // heldScript's own self-check loop takes - without it, a heartbeat
  // landing at EXACTLY the wrong instant (heldScript has already read a
  // stale mtime and decided to expire, but hasn't yet removed the owner
  // record) could touch the file a moment before heldScript's own `rm`
  // still ran anyway - a legitimate, just-arrived heartbeat silently
  // lost to a self-expiry decision already made. Serializing both
  // through fd 8 makes "read mtime, decide, clear" (heldScript) and
  // "verify token, touch" (here) strictly ordered relative to each
  // other, never interleaved.
  // PR 2 (item 10) fifth review, high finding 1: no longer consults
  // `systemctl is-active` at all - the same asynchronous-lag reasoning
  // leaseFencingScript() itself was fixed for (see that function's own
  // comment) applies just as much here, even though this is only ever
  // the client's own periodic heartbeat/self-check, never the actual
  // write-time gate. Reads the owner record's own PID+start time back
  // and re-verifies them fresh against /proc, kernel-synchronous and
  // immediate - the exact same technique, for consistency and because a
  // check that can itself lag has no real value as an early-warning
  // signal either.
  async function assertOwnership() {
    // Once a loss is already known (voluntary release, or a prior
    // assertOwnership()/background-interval tick already found it gone),
    // every later call is a genuine no-op - never another real round
    // trip confirming the same already-known outcome over and over for
    // whatever remains of this process's own lifetime.
    if (voluntarilyReleased || lost) return;
    let assertStdout;
    try {
      assertStdout = await runScript(scriptConn, `set -eu
exec 8>'${LOCK_GUARD_PATH}'
flock -x 8
if [ ! -r '${EXECUTION_LEASE_OWNER_PATH}' ]; then
  flock -u 8
  echo HOF_LEASE_LOST
  exit 0
fi
owner_token=""
owner_pid=""
read -r owner_token owner_pid owner_starttime < '${EXECUTION_LEASE_OWNER_PATH}' || true
if [ "$owner_token" != '${token}' ]; then
  flock -u 8
  echo HOF_LEASE_LOST
  exit 0
fi
${procStartTimeStatements("$owner_pid", "current_starttime").join("\n")}
if [ -z "$current_starttime" ] || [ "$current_starttime" != "$owner_starttime" ]; then
  flock -u 8
  echo HOF_LEASE_LOST
  exit 0
fi
touch '${EXECUTION_LEASE_OWNER_PATH}'
flock -u 8
echo HOF_LEASE_OK
`);
    } catch (error) {
      markLost(`could not confirm the execution lease is still held: ${error instanceof Error ? error.message : error}`);
      return;
    }
    if (assertStdout.split("\n")[0] !== "HOF_LEASE_OK") {
      markLost("the execution lease for this target is no longer held (its systemd unit is gone, or the owner record no longer matches this acquisition's own token)");
    }
  }

  const heartbeat = setInterval(() => { assertOwnership().catch(() => {}); }, mutexHeartbeatIntervalMs);
  // Never keeps the whole Node process alive on its own - only real work
  // (an in-flight apply/backup/restore run) does that; this is
  // bookkeeping.
  heartbeat.unref?.();

  const release = async () => {
    voluntarilyReleased = true;
    clearInterval(heartbeat);
    // Best-effort: a transport failure here must never throw back into
    // the caller's own cleanup path - an unreleased unit still
    // self-expires on its own within LEASE_HEARTBEAT_TIMEOUT_S once
    // nothing heartbeats it again, so a failed release here degrades to
    // "a later --resume waits out the same bound a genuine crash
    // would", never to a permanently stuck mutex.
    //
    // PR 2 (item 10) second review, critical finding 1: this check-
    // then-clear now also runs under the same LOCK_GUARD_PATH guard as
    // every other owner-record operation - see this function's own
    // sibling comments (heldScript above, assertOwnership() above) for
    // why a shared guard is what actually makes the whole owner-record
    // lifecycle (write, heartbeat-touch, self-expiry-clear, release-
    // clear) mutually exclusive, not merely "usually fast enough".
    try {
      await runScript(scriptConn, `set -eu
exec 8>'${LOCK_GUARD_PATH}'
flock -x 8
owner_token=""
read -r owner_token _ _ < '${EXECUTION_LEASE_OWNER_PATH}' 2>/dev/null || true
if [ "$owner_token" = '${token}' ]; then
  rm -f '${EXECUTION_LEASE_OWNER_PATH}'
  flock -u 8
  systemctl stop '${unit}.service' >/dev/null 2>&1 || true
  systemctl reset-failed '${unit}.service' >/dev/null 2>&1 || true
  echo HOF_LEASE_RELEASED
else
  flock -u 8
  echo HOF_LEASE_MISMATCH
fi
`);
    } catch { /* best-effort, see this function's own comment above */ }
  };

  return {
    release,
    isLost: () => lost,
    lostReason: () => lostReasonValue,
    onLost: (callback) => { lostCallbacks.push(callback); },
    assertOwnership,
    // Testing-only seam (PR 2 review, medium finding 6) - stops just
    // this LOCAL process's own heartbeat interval, without ever telling
    // the target anything (unlike release(), which actively clears the
    // owner record and stops the unit). Lets a real acceptance test
    // prove the held unit's own self-check loop genuinely,
    // independently notices a heartbeat has stopped and gives up its
    // own flock on its own, within LEASE_HEARTBEAT_TIMEOUT_S - a
    // materially different, and materially more important, guarantee
    // than "killing the unit directly releases its flock" (which the
    // OS would do for ANY dead process, self-expiry logic or not). The
    // real CLI never calls this.
    stopHeartbeatForTesting: () => clearInterval(heartbeat),
    // PR 2 (item 10) review, Critical finding 2: exposed so a caller
    // (apply.mjs's own dispatch loop, and operation-v2.mjs's own write
    // wrappers) can pass it into updateJournalStatus()/appendEvent()'s
    // own leaseToken parameter for real, target-side fencing on every
    // write - a client-side isLost() check alone cannot close a loss
    // that happens strictly between that check and the write actually
    // reaching the target. Never written into a durable lock/journal/
    // event document, and never logged by anything in this codebase -
    // a caller threading it into a write's own fencing parameter is not
    // "persisting" it, the target-side check reads it once per write and
    // discards it.
    token,
  };
}

// Compatibility API for apply.mjs, which has never needed to know this
// is now a general, kind-agnostic mutex rather than something apply-
// specific - a future backup/restore runner (PR 4/5) calls acquireMutex()
// directly instead, against the exact same flock path and protocol, per
// ADR 0006's own "one physical execution mutex across all three kinds".
export async function acquireExecutionLease(conn) {
  return acquireMutex(conn);
}
