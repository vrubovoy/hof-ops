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
//   - assertBundleBinding - runs assertPlanValid() (below) against
//     bundle.plan, THEN scripts/backup-flow.mjs's own
//     validateBackupBundle()/validateRestoreBundle() over whatever
//     subset of {policy, plan, manifest, evidence, kit, lock, journal,
//     events} a caller is about to write, throwing on any violation.
//     This is new relative to v1, which has no equivalent gate at all -
//     v1's own cross-document invariants are enforced by prose and by
//     apply.mjs's own inline checks, never by a shared, reusable
//     validator every write path can be routed through.
//   - assertPlanValid - schema-validates a backup/restore plan against
//     backup-plan-v1/restore-plan-v1 AND runs backup-flow.mjs's own
//     validateBackupPlanOperations()/validateRestorePlanOperations()
//     (flow completeness/ordering - a pre-PR4 review found nothing in
//     this module ever ran either check, so a plan's own operations
//     array could be incomplete or wrongly ordered and still pass every
//     v2 write gate). Runs automatically inside assertBundleBinding()
//     above, so every write (and, since writeJournalStatus/writeEvent
//     re-validate the PERSISTED journal's own plan on every call, every
//     resume) is covered without a separate call; also exported on its
//     own for a later PR's planner to validate a candidate plan before
//     ever proposing it for approval.

import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { validateBackupBundle, validateBackupPlanOperations, validateRestoreBundle, validateRestorePlanOperations } from "./backup-flow.mjs";
import { currentOperator, newOperationId } from "./operation-journal.mjs";

export { currentOperator, newOperationId };

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let validators;
async function loadValidators() {
  validators ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
    addFormats(ajv);
    const [lock, journal, event, backupPlan, restorePlan] = await Promise.all([
      readFile(path.join(root, "schemas/operation-lock-v2.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-journal-v2.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-event-v2.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/backup-plan-v1.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/restore-plan-v1.schema.json"), "utf8").then(JSON.parse),
    ]);
    return {
      lock: ajv.compile(lock), journal: ajv.compile(journal), event: ajv.compile(event),
      backupPlan: ajv.compile(backupPlan), restorePlan: ajv.compile(restorePlan),
    };
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

// PR 3 review, "pre-PR4 gap" finding: assertBundleBinding() below ran
// backup-flow.mjs's own validateBackupBundle()/validateRestoreBundle() -
// cross-document id/digest bindings - but NOTHING in this module ever
// schema-validated the plan itself against backup-plan-v1/restore-plan-v1,
// nor ever called validateBackupPlanOperations()/
// validateRestorePlanOperations() (the flow-completeness/ordering
// validators - see backup-flow.mjs's own comment on them). A schema-valid
// LOCK/JOURNAL/EVENT wrapped around a plan whose own operations array was
// incomplete, wrongly ordered, or carried a duplicate step could still
// sail through every v2 write gate (writeLockAndJournal/
// writeJournalStatus/writeEvent all route through assertBundleBinding()
// below) undetected - the plan-level semantic contract this ADR's own
// Decision text describes was never actually enforced at the one choke
// point every v2 write already goes through. Exported on its own,
// matching assertLockValid/assertJournalValid/assertEventValid's own
// style, so a later PR's planner (`hofctl backup plan`, in particular)
// can validate a freshly-built candidate plan before ever proposing it
// for approval, not only at write time.
export async function assertPlanValid(operationKind, plan) {
  requireOperationKind(operationKind, "assertPlanValid");
  const kind = operationKind === "backup" ? "backupPlan" : "restorePlan";
  const { [kind]: validate } = await loadValidators();
  if (!validate(plan)) {
    throw new Error(`the ${operationKind} plan does not satisfy schemas/${operationKind}-plan-v1.schema.json: ${JSON.stringify(validate.errors)}`);
  }
  const violations = operationKind === "backup" ? validateBackupPlanOperations(plan) : validateRestorePlanOperations(plan);
  if (violations.length > 0) {
    throw new Error(`refusing to trust this ${operationKind} plan: its own operations sequence is incoherent: ${violations.join("; ")}`);
  }
  return plan;
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

// First runs assertPlanValid() above against bundle.plan (a pre-PR4
// review found this never ran anywhere - see that function's own
// comment), THEN scripts/backup-flow.mjs's own validateBackupBundle()/
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
export async function assertBundleBinding(operationKind, bundle) {
  if (bundle.plan) {
    await assertPlanValid(operationKind, bundle.plan);
  }
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

// PR 2 review, High finding 5 (first round): this used to accept
// `lease?.isLost?.()` - if `lease` were undefined, or any object lacking
// an isLost method, optional chaining silently evaluated to undefined
// (falsy), and this function returned normally as if the lease were
// healthy. A caller that forgot to pass a lease at all - or passed
// something that merely LOOKED like one - sailed straight through with
// no lease check whatsoever. Now requires a real lease object exposing
// isLost, assertOwnership, AND a genuine token, and always calls
// assertOwnership() FIRST - a fresh, real round trip immediately before
// this write, not the possibly-stale cached flag isLost() alone
// reflects (isLost() only updates when something - the background
// heartbeat interval, or an explicit assertOwnership() call - last
// happened to check; a lease genuinely lost in between is invisible to
// a bare isLost() read until something checks again).
//
// PR 2 review, High finding 3 (second round): the token requirement was
// missing entirely from this first fix - a tokenless, lease-SHAPED
// object (isLost/assertOwnership present, but no token at all) still
// passed this check, and the raw target-mutate.mjs write then received
// `undefined` as its own leaseToken parameter - which that module's own
// leaseFencingScript() deliberately treats as "no lease concept at all,
// proceed unguarded" (see its own comment: this is intentional for
// callers with genuinely no lease concept). A caller here DOES have a
// lease concept - it just forgot the token - so silently falling
// through to "unguarded" defeats every other fencing fix in this same
// review. Checked explicitly now, distinctly from the isLost/
// assertOwnership shape check, so the error names exactly what's
// missing.
async function assertLeaseHealthy(lease) {
  if (!lease || typeof lease.isLost !== "function" || typeof lease.assertOwnership !== "function") {
    throw new Error("refusing to write: a real, active execution lease (exposing isLost/assertOwnership) is required - none was given");
  }
  if (typeof lease.token !== "string" || lease.token.length === 0) {
    throw new Error("refusing to write: the given lease exposes no token of its own - target-side fencing would silently be disabled for this write, refusing rather than writing unguarded");
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
// for a fresh restore) before ever reaching the raw transport. The
// create itself is target-side fenced by lease.token too (PR 2 review,
// high finding 2, second round) - target-mutate.mjs's own
// acquireLockAndJournalScript() now takes the same leaseFencingScript()
// gate every other lease-gated write already had, closing the gap where
// a holder that had already lost the physical mutex could still create
// a brand new lock+journal pair.
export async function writeLockAndJournal(mutate, conn, lease, { operationKind, lockDoc, journalDoc, bundle = {} }) {
  await assertLeaseHealthy(lease);
  await assertLockValid(lockDoc);
  await assertJournalValid(journalDoc);
  await assertBundleBinding(operationKind, { ...bundle, plan: journalDoc.plan, lock: lockDoc, journal: journalDoc });
  return mutate.acquireLockAndJournal(conn, lockDoc, journalDoc, lease.token);
}

// Every field a v2 journal carries except status/committedGeneration -
// see operation-journal-v2.schema.json's own "immutable except status/
// committedGeneration" description.
const IMMUTABLE_JOURNAL_FIELDS = ["apiVersion", "operationKind", "operationId", "approvedPlanId", "target", "plan", "inputDigests", "startedAt"];

// PR 2 review, High finding 3 (first round) / High finding 4 (second
// round): the first fix read the persisted journal and validated a
// candidate transition against it in JS, then wrote separately - two
// round trips with a real, independently reachable gap between them: a
// second, concurrent writeJournalStatus() call could read the SAME
// persisted (in-progress) journal, also pass this exact validation, and
// then whichever of the two writes reaches the target SECOND would
// silently overwrite the first's own genuinely-landed transition
// (including a terminal one) - the lease.token fencing alone doesn't
// close this, since both callers could legitimately be holding the
// SAME lease sequentially, or this could simply be a caller bug, not an
// adversarial one. Closed for real now: `persisted` (read fresh here)
// is passed straight through to target-mutate.mjs's own
// updateJournalStatus() as its own expectedPreviousDocument - the
// actual read-compare-write for "is the target still exactly what I
// last saw" now happens atomically, on the target, immediately before
// the write, under the same flock guard - not as two independently
// racing JS-orchestrated round trips. A second writer's own attempt
// after the first already landed gets a clean HOF_MUTATE_CAS_CONFLICT
// refusal instead of silently clobbering it.
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

  await assertBundleBinding(operationKind, { ...bundle, plan: journal.plan, journal });
  return mutate.updateJournalStatus(conn, journal, lease.token, persisted);
}

// PR 2 review, High finding 4 (first round) / High finding 5 (second
// round): the first fix required a `plan` parameter and bound the
// event's step/destination against it - but still trusted whatever
// plan object the CALLER happened to pass, with nothing tying it to the
// real, approved plan this operation is actually bound to. A caller (or
// a bug) could pass a fabricated plan document containing exactly the
// step/destination the fabricated event needed, and this would happily
// validate a schema-valid event for a step that was never really part
// of the real, approved operation. Closed for real now: `plan` is no
// longer accepted as a parameter at all - this reads the persisted
// journal (the same one appendEvent()'s own operationId targets) and
// uses ITS OWN embedded plan, the one actually bound to this operation
// by writeLockAndJournal() at creation time and never rewritable since
// (operation-journal-v2.schema.json's own immutability, enforced by
// withJournalStatus()/writeJournalStatus() above) - not anything a
// caller can substitute.
// PR 2 review, High finding 3 (third round): two further gaps in the
// same journal-bound design. First, nothing ever refused an event
// against a journal that was already terminal (succeeded/failed) - an
// event genuinely has no business being appended once an operation has
// already, honestly finished (ADR 0006's own terminal-journal
// semantics); checked explicitly here, before ever reaching the raw
// transport (target-mutate.mjs's own appendEvent() independently
// re-checks this too, atomically, against whatever is ACTUALLY
// persisted at write time - see its own journalGuardForEventScript()
// comment; this JS-side check is the fast, early rejection for the
// common case). Second, `persisted.plan` was trusted directly, with
// only assertJournalValid()'s own schema check behind it -
// operation-journal-v2.schema.json's own `plan` field is deliberately
// loosely typed (no schema in this repo cross-references another by
// $id), so a hand-tampered-but-still-schema-valid persisted journal
// could carry a plan whose own `operations` array doesn't actually
// match what its own `planId` claims. assertBundleBinding() runs the
// real cross-document/content checks (backup-flow.mjs's own
// validateBackupBundle()/validateRestoreBundle()) - including
// recomputing plan.planId from its own content - before that plan is
// ever trusted for the step/destination binding below.
export async function writeEvent(mutate, conn, lease, { operationKind, operationId, event }) {
  await assertLeaseHealthy(lease);
  await assertEventValid(event);

  const { status: readStatus, journal: persisted } = await mutate.readJournal(conn, operationId);
  if (readStatus !== "present") {
    throw new Error(`refusing to write: no persisted journal for operation ${operationId} was found on the target to bind this event against`);
  }
  await assertJournalValid(persisted);
  if (persisted.operationKind !== operationKind) {
    throw new Error(`refusing to write: the persisted journal's own operationKind (${persisted.operationKind}) does not match this write's own operationKind (${operationKind})`);
  }
  if (persisted.status !== "in-progress") {
    throw new Error(`refusing to write: the persisted journal for operation ${operationId} is already terminal (status: ${persisted.status}) - no further events are ever appended once an operation has genuinely finished`);
  }
  await assertBundleBinding(operationKind, { plan: persisted.plan, journal: persisted });
  if (event.operationId !== operationId) {
    throw new Error(`refusing to write: event.operationId (${event.operationId}) does not match the operationId this write is for (${operationId}) - refusing a possible operation-id substitution`);
  }
  if (event.operationKind !== operationKind) {
    throw new Error(`refusing to write: event.operationKind (${event.operationKind}) does not match this write's own operationKind (${operationKind})`);
  }
  const step = persisted.plan.operations.find((operation) => operation.id === event.step);
  if (!step) {
    throw new Error(`refusing to write: event names step "${event.step}", which is not part of the persisted journal's own plan operations`);
  }
  if (event.destination !== undefined && event.destination !== step.destination) {
    throw new Error(`refusing to write: event.destination (${event.destination}) does not match the persisted journal's own plan step ${event.step}'s destination (${step.destination ?? "none"})`);
  }
  // PR 2 review, High finding 4 (third round): `persisted` - the EXACT
  // snapshot just read and validated above - is passed straight through
  // as target-mutate.mjs's own expectedJournalSnapshot, so the real
  // compare-and-swap (and the independent terminal-status re-check) runs
  // atomically, on the target, immediately before the append - not as
  // two independently racing JS-orchestrated round trips.
  return mutate.appendEvent(conn, operationId, event, lease.token, persisted);
}
