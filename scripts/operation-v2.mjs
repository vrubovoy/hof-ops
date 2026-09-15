// Pure builders/validators for the two new operation-*-v2 contracts (see
// schemas/operation-{lock,journal,event}-v2.schema.json and ADR 0006) -
// no I/O here at all, exactly like operation-journal.mjs's own v1
// equivalent, which this module is deliberately the SIBLING of, never a
// replacement for: apply's own state machine stays on operation-*-v1
// forever (scripts/operation-journal.mjs, untouched by this item), and
// this module is scoped strictly to operationKind backup/restore.
//
// PR 2 (item 10) scope: this module provides the safe read/write/binding
// PRIMITIVES a later PR's real backup/restore runner (PR 4/5) builds on
// - it does not itself implement backup/restore reconciliation, a CLI
// surface, or any target-side dispatch. What it adds beyond a bare
// schema check:
//   - assertLockValid/assertJournalValid/assertEventValid - the same
//     "never trust a document read off a real target" AJV gate v1 has,
//     against the v2 schemas.
//   - isV2Lock - lets a caller (apply.mjs's own fresh/resume paths, in
//     particular) distinguish "this lock.json is a schema-valid v2
//     backup/restore lock" from "this doesn't satisfy v1 OR v2 - it's
//     genuinely corrupt" without conflating the two into one confusing
//     "does not satisfy schema" message.
//   - buildLockDocument/buildJournalDocument/buildEvent - the v2
//     equivalents of operation-journal.mjs's own builders, including the
//     kind-specific inputDigests shape operation-journal-v2.schema.json
//     itself requires (backup: releaseLockDigest/backupToolLockDigest/
//     backupPolicyId; restore: releaseLockDigest/backupToolLockDigest/
//     manifestDigest/recoveryKitDigest - never both, never mixed).
//   - withJournalStatus - like v1's, but additionally asserts every
//     field OTHER than status/committedGeneration is byte-for-byte
//     unchanged (v1 trusts its caller for this; v2 checks it directly,
//     per this item's own PR2 plan: "immutable fields never change"),
//     and refuses outright once a journal is already terminal (a v2
//     journal's terminal status is never rewritten - a retry is always a
//     fresh operationId, see operation-journal-v2.schema.json's own
//     status description).
//   - assertBundleBinding - runs scripts/backup-flow.mjs's own
//     validateBackupBundle()/validateRestoreBundle() over whatever
//     subset of {policy, plan, manifest, evidence, kit, lock, journal,
//     events} a caller is about to write, throwing on any violation.
//     This is new relative to v1, which has no equivalent gate at all -
//     v1's own cross-document invariants are enforced by prose and by
//     apply.mjs's own inline checks, never by a shared, reusable
//     validator every write path can be routed through.

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { validateBackupBundle, validateRestoreBundle } from "./backup-flow.mjs";
import { currentOperator, newOperationId } from "./operation-journal.mjs";

export { currentOperator, newOperationId };

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let validators;
async function loadValidators() {
  validators ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
    addFormats(ajv);
    const [lock, journal, event] = await Promise.all([
      readFile(path.join(root, "schemas/operation-lock-v2.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-journal-v2.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-event-v2.schema.json"), "utf8").then(JSON.parse),
    ]);
    return { lock: ajv.compile(lock), journal: ajv.compile(journal), event: ajv.compile(event) };
  })();
  return validators;
}

async function assertValid(kind, value) {
  const { [kind]: validate } = await loadValidators();
  if (!validate(value)) {
    throw new Error(`built ${kind} document does not satisfy schemas/operation-${kind}-v2.schema.json: ${JSON.stringify(validate.errors)}`);
  }
  return value;
}

// Same reasoning as operation-journal.mjs's own assertReadValid - a
// document READ off a real target (target-mutate.mjs's own readLock()/
// readJournal() only ever JSON.parse the raw bytes, no schema check of
// their own) must never be trusted before a caller reads a field off it.
async function assertReadValid(kind, value) {
  const { [kind]: validate } = await loadValidators();
  if (!validate(value)) {
    throw new Error(`the ${kind} read from the target does not satisfy schemas/operation-${kind}-v2.schema.json: ${JSON.stringify(validate.errors)}`);
  }
  return value;
}

export function assertLockValid(lock) {
  return assertReadValid("lock", lock);
}

export function assertJournalValid(journal) {
  return assertReadValid("journal", journal);
}

export function assertEventValid(event) {
  return assertReadValid("event", event);
}

// Lets a caller distinguish "this is a genuine, schema-valid v2
// backup/restore lock" from "this doesn't satisfy v1 or v2 at all - it's
// really corrupt", without throwing - apply.mjs's own fresh/resume paths
// use this to give an explicit, accurate blocked() reason when the
// target's shared lock.json turns out to belong to a concurrent
// backup/restore rather than to a stale or corrupted apply lock (v1 and
// v2 lock.json share the exact same target path - see
// operation-lock-v2.schema.json's own top-level description - so a v1
// exclusive-create failure hands back whatever is actually there,
// unconditionally).
export async function isV2Lock(value) {
  const { lock: validate } = await loadValidators();
  return Boolean(validate(value));
}

function requireOperationKind(operationKind, fnName) {
  if (operationKind !== "backup" && operationKind !== "restore") {
    throw new Error(`internal error: ${fnName} requires operationKind "backup" or "restore", got ${JSON.stringify(operationKind)}`);
  }
}

// target: the plan's own `target` object - identical shape across every
// operation-*-v2 schema (mode/host/port/user/hostKeySha256/
// installationId/baselineGeneration), duplicated across schemas
// deliberately (see each schema's own comment: no schema in this repo
// cross-references another by $id).
export async function buildLockDocument({ operationKind, operationId, approvedPlanId, target, acquiredBy = currentOperator() }) {
  requireOperationKind(operationKind, "buildLockDocument");
  return assertValid("lock", {
    apiVersion: "hof.dev/operation-lock/v2",
    operationKind, operationId, approvedPlanId, target,
    acquiredAt: new Date().toISOString(),
    acquiredBy,
  });
}

// operation-journal-v2.schema.json's own inputDigests shape is a closed,
// kind-specific set (additionalProperties: false on each branch) - this
// picks exactly the fields the target kind needs from whatever the
// caller passed, so an accidental extra field on the caller's own object
// (e.g. a restore-shaped inputDigests handed to a backup build by
// mistake) is dropped rather than silently smuggled through and only
// caught later by the schema check.
function inputDigestsFor(operationKind, inputDigests) {
  if (operationKind === "backup") {
    const { releaseLockDigest, backupToolLockDigest, backupPolicyId } = inputDigests ?? {};
    return { releaseLockDigest, backupToolLockDigest, backupPolicyId };
  }
  const { releaseLockDigest, backupToolLockDigest, manifestDigest, recoveryKitDigest } = inputDigests ?? {};
  return { releaseLockDigest, backupToolLockDigest, manifestDigest, recoveryKitDigest };
}

// plan is the FULL approved backup-plan-v1/restore-plan-v1 document (not
// just its planId) - same reasoning as operation-journal.mjs's own v1
// builder: a resume trusts operations[] straight from here. approvedPlanId
// is asserted to equal plan.planId rather than trusted separately.
export async function buildJournalDocument({ operationKind, operationId, approvedPlanId, target, plan, inputDigests }) {
  requireOperationKind(operationKind, "buildJournalDocument");
  if (plan.planId !== approvedPlanId) {
    throw new Error(`internal error: buildJournalDocument called with approvedPlanId ${approvedPlanId} but plan.planId ${plan.planId} - these must always be the same value`);
  }
  return assertValid("journal", {
    apiVersion: "hof.dev/operation-journal/v2",
    operationKind, operationId, approvedPlanId, target, plan,
    inputDigests: inputDigestsFor(operationKind, inputDigests),
    startedAt: new Date().toISOString(),
    status: "in-progress",
    committedGeneration: null,
  });
}

// Every field a v2 journal document carries except status/
// committedGeneration - see operation-journal-v2.schema.json's own top
// description: "Written once at operation start (immutable except
// status/committedGeneration...)". withJournalStatus() below enforces
// this directly, rather than trusting the caller the way v1's own
// equivalent does - the function signature itself only ever reads
// `status`/`committedGeneration` off its second argument, so no other
// field can reach the candidate document through it, whatever else a
// caller's own options object happens to carry.
//
// PR 2 (item 10) plan: "a terminal journal is only ever written with a
// full, schema-valid document; immutable fields never change." The
// second half is enforced structurally, by the destructuring above; the
// first half - refusing outright once the ORIGINAL journal is already
// terminal (succeeded/failed), since a v2 journal's terminal status is
// never rewritten (a retry is always a fresh operationId, per
// operation-journal-v2.schema.json's own status field description) - is
// checked explicitly below, before the candidate is ever built.
export async function withJournalStatus(journal, { status, committedGeneration = null }) {
  if (journal.status === "succeeded" || journal.status === "failed") {
    throw new Error(`internal error: journal ${journal.operationId} is already terminal (status: ${journal.status}) - a v2 journal's terminal status is never rewritten, a retry is always a fresh operationId`);
  }
  return assertValid("journal", { ...journal, status, committedGeneration });
}

export async function buildEvent({ operationKind, operationId, step, attempt, phase, error, destination }) {
  requireOperationKind(operationKind, "buildEvent");
  const event = { apiVersion: "hof.dev/operation-event/v2", operationKind, operationId, step, attempt, phase, at: new Date().toISOString() };
  if (phase === "failed") event.error = error;
  if (destination !== undefined) event.destination = destination;
  return assertValid("event", event);
}

// Runs scripts/backup-flow.mjs's own validateBackupBundle()/
// validateRestoreBundle() over whatever subset of the bundle a caller
// is about to write, and throws on any violation - the "before every
// write" gate PR 2's own plan calls for, that v1 has no equivalent of.
// bundle is exactly the { policy?, plan, manifest?, evidence?, kit?,
// lock?, journal?, events? } shape those two functions already take;
// operationKind selects which one runs (policy/kit/manifest are backup-
// or restore-specific already, harmless to pass the wrong optional key -
// each validator simply ignores fields it doesn't know about, the same
// way it already does when a caller supplies a partial bundle for an
// in-progress operation that doesn't have a manifest/evidence yet).
export function assertBundleBinding(operationKind, bundle) {
  const violations = operationKind === "backup" ? validateBackupBundle(bundle) : validateRestoreBundle(bundle);
  if (violations.length > 0) {
    throw new Error(`refusing to write: this ${operationKind} operation's own bundle binding is violated: ${violations.join("; ")}`);
  }
}

// --- Write wrappers (PR 2 item 5: "move v2 writes into wrappers that
// require an active lease and validate documents before ever calling
// the raw transport") ---
//
// Named writeLockAndJournal/writeJournalStatus/writeEvent - deliberately
// NOT acquireLockAndJournal/updateJournalStatus/appendEvent, the raw
// target-mutate.mjs names, even though target-mutate.mjs's own
// functions ARE what these ultimately call: those raw names must stay
// reachable on their own (v1/apply.mjs calls them directly, unwrapped,
// and always will), so giving this module's own gated equivalents the
// same names would invite a future caller to import the wrong one by
// mistake. mutate is target-mutate.mjs's own exports (or a test fake) -
// the same style seam apply.mjs's own `m` parameter already uses. lease
// is whatever acquireMutex()/acquireExecutionLease() returned - checked
// for isLost() before ever attempting a mutation, exactly like
// apply.mjs's own dispatch loop already does for v1 (fail-closed, see
// target-mutate.mjs's own acquireMutex() comment).

// PR 2 review, High finding 5: this used to accept `lease?.isLost?.()`
// - if `lease` were undefined, or any object lacking an isLost method,
// optional chaining silently evaluated to undefined (falsy), and this
// function returned normally as if the lease were healthy. A caller
// that forgot to pass a lease at all - or passed something that merely
// LOOKED like one - sailed straight through with no lease check
// whatsoever. Now requires a real lease object exposing both isLost AND
// assertOwnership, and always calls assertOwnership() FIRST - a fresh,
// real round trip immediately before this write, not the possibly-
// stale cached flag isLost() alone reflects (isLost() only updates when
// something - the background heartbeat interval, or an explicit
// assertOwnership() call - last happened to check; a lease genuinely
// lost in between is invisible to a bare isLost() read until something
// checks again).
async function assertLeaseHealthy(lease) {
  if (!lease || typeof lease.isLost !== "function" || typeof lease.assertOwnership !== "function") {
    throw new Error("refusing to write: a real, active execution lease (exposing isLost/assertOwnership) is required - none was given");
  }
  await lease.assertOwnership();
  if (lease.isLost()) {
    throw new Error(`refusing to write: the execution lease for this target is no longer held (${lease.lostReason?.() ?? "unknown"}) - a lost lease means another process may already be mutating this same target`);
  }
}

// Re-validates lockDoc/journalDoc (defense in depth - a caller may have
// hand-built rather than gone through buildLockDocument/
// buildJournalDocument above) and their own bundle binding against
// `bundle` (the rest of the operation's own known documents - typically
// at minimum { policy?, plan } for a fresh backup, or { plan, manifest }
// for a fresh restore) before ever reaching the raw transport.
export async function writeLockAndJournal(mutate, conn, lease, { operationKind, lockDoc, journalDoc, bundle = {} }) {
  await assertLeaseHealthy(lease);
  await assertLockValid(lockDoc);
  await assertJournalValid(journalDoc);
  assertBundleBinding(operationKind, { ...bundle, plan: journalDoc.plan, lock: lockDoc, journal: journalDoc });
  return mutate.acquireLockAndJournal(conn, lockDoc, journalDoc);
}

// Every field a v2 journal carries except status/committedGeneration -
// see operation-journal-v2.schema.json's own "immutable except status/
// committedGeneration" description.
const IMMUTABLE_JOURNAL_FIELDS = ["apiVersion", "operationKind", "operationId", "approvedPlanId", "target", "plan", "inputDigests", "startedAt"];

// PR 2 review, High finding 3: this used to validate only the
// CANDIDATE document's own schema/bundle-binding and write it straight
// through - nothing here ever compared it against what is ACTUALLY,
// currently persisted on the target, so a caller passing a stale or
// tampered candidate (an already-terminal journal rewritten again, or
// one field's own value quietly drifted from the real record) would
// simply overwrite it. Now reads the real, persisted journal fresh
// (under the same lease this write is about to use), confirms it is
// not already terminal, and confirms the candidate is byte-for-byte
// identical to it on every field except status/committedGeneration -
// only THEN does the write reach the raw transport. `journal` is the
// FULL candidate document (already produced by withJournalStatus()
// above, or equivalent).
export async function writeJournalStatus(mutate, conn, lease, { operationKind, journal, bundle = {} }) {
  await assertLeaseHealthy(lease);
  await assertJournalValid(journal);

  const { status: readStatus, journal: persisted } = await mutate.readJournal(conn, journal.operationId);
  if (readStatus !== "present") {
    throw new Error(`refusing to write: no persisted journal for operation ${journal.operationId} was found on the target to update (read status: ${readStatus})`);
  }
  await assertJournalValid(persisted);
  if (persisted.status === "succeeded" || persisted.status === "failed") {
    throw new Error(`refusing to write: the persisted journal for operation ${journal.operationId} is already terminal (status: ${persisted.status}) - a v2 journal's terminal status is never rewritten, a retry is always a fresh operationId`);
  }
  for (const field of IMMUTABLE_JOURNAL_FIELDS) {
    if (JSON.stringify(journal[field]) !== JSON.stringify(persisted[field])) {
      throw new Error(`refusing to write: the candidate journal's own ${field} does not match the persisted document's - only status/committedGeneration may ever change`);
    }
  }

  assertBundleBinding(operationKind, { ...bundle, plan: journal.plan, journal });
  return mutate.updateJournalStatus(conn, journal, lease.token);
}

// PR 2 review, High finding 4: this used to append whatever `event` it
// was given under the caller-supplied `operationId`, with no check that
// the two actually agreed - a caller (or a bug) could hand this an
// event whose own operationId field names a DIFFERENT operation than
// the one whose events file it is about to be appended to (target-
// mutate.mjs's own appendEvent() targets the path purely from the
// `operationId` parameter, never from the event body). Also never
// checked the event's own step (and, for a per-destination step, its
// destination) against the plan it actually belongs to, so a fabricated
// event for a step that isn't even part of the plan could be appended
// without complaint. `plan` is now required - the same full plan
// document this operation's own journal already embeds.
export async function writeEvent(mutate, conn, lease, { operationKind, operationId, event, plan }) {
  await assertLeaseHealthy(lease);
  await assertEventValid(event);
  if (!plan) {
    throw new Error("refusing to write: writeEvent requires the operation's own plan, to bind the event's step (and destination, if any) against it");
  }
  if (event.operationId !== operationId) {
    throw new Error(`refusing to write: event.operationId (${event.operationId}) does not match the operationId this write is for (${operationId}) - refusing a possible operation-id substitution`);
  }
  if (event.operationKind !== operationKind) {
    throw new Error(`refusing to write: event.operationKind (${event.operationKind}) does not match this write's own operationKind (${operationKind})`);
  }
  const step = plan.operations.find((operation) => operation.id === event.step);
  if (!step) {
    throw new Error(`refusing to write: event names step "${event.step}", which is not part of the plan's own operations`);
  }
  if (event.destination !== undefined && event.destination !== step.destination) {
    throw new Error(`refusing to write: event.destination (${event.destination}) does not match the plan's own step ${event.step}'s destination (${step.destination ?? "none"})`);
  }
  return mutate.appendEvent(conn, operationId, event, lease.token);
}
