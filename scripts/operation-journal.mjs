// Pure builders/validators for the three apply-time contracts (see
// schemas/operation-{lock,journal,event}-v1.schema.json and ADR 0004) -
// no I/O here at all. Reading/writing these documents on a real target
// is target-mutate.mjs's own job; this module only ever shapes and
// reasons about the documents themselves, so the resumability decision
// (the one genuinely subtle piece of logic ADR 0004 describes) is
// exercised directly, with plain objects, in the fast test suite.

import { randomUUID } from "node:crypto";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let validators;
async function loadValidators() {
  validators ??= await (async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
    addFormats(ajv);
    const [lock, journal, event] = await Promise.all([
      readFile(path.join(root, "schemas/operation-lock-v1.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-journal-v1.schema.json"), "utf8").then(JSON.parse),
      readFile(path.join(root, "schemas/operation-event-v1.schema.json"), "utf8").then(JSON.parse),
    ]);
    return { lock: ajv.compile(lock), journal: ajv.compile(journal), event: ajv.compile(event) };
  })();
  return validators;
}

async function assertValid(kind, value) {
  const { [kind]: validate } = await loadValidators();
  if (!validate(value)) {
    throw new Error(`built ${kind} document does not satisfy schemas/operation-${kind}-v1.schema.json: ${JSON.stringify(validate.errors)}`);
  }
  return value;
}

// The same schema, but for a document READ off a real target rather
// than one this module itself just built - target-mutate.mjs's own
// readLock()/readJournal() only ever JSON.parse the raw bytes they read
// back, with no schema check of their own (see that module's own top
// comment on why: it's a narrow, fixed-vocabulary transport layer, not
// a validator). A hand-tampered, corrupted, or simply stale-shaped
// document must never be silently trusted as if it were schema-valid -
// callers (apply.mjs's own resume path in particular) validate here
// before ever reading a field off it.
async function assertReadValid(kind, value) {
  const { [kind]: validate } = await loadValidators();
  if (!validate(value)) {
    throw new Error(`the ${kind} read from the target does not satisfy schemas/operation-${kind}-v1.schema.json: ${JSON.stringify(validate.errors)}`);
  }
  return value;
}

export function assertLockValid(lock) {
  return assertReadValid("lock", lock);
}

export function assertJournalValid(journal) {
  return assertReadValid("journal", journal);
}

// Same reasoning as assertLockValid/assertJournalValid, for the
// append-only NDJSON event log - target-mutate.mjs's own readEvents()
// only ever JSON.parses each line, with no schema check of its own (a
// real gap a 2026-08-28 review found: a hand-tampered event, or one with
// phase: "succeeded" for a step id that doesn't belong to this plan at
// all, would otherwise be silently trusted by decideStepResumption()).
export function assertEventValid(event) {
  return assertReadValid("event", event);
}

export function newOperationId() {
  return randomUUID();
}

// acquiredBy is informational only (see operation-lock-v1.schema.json's
// own comment - never used for an actual security decision), but still
// real, useful data for a human debugging a stuck lock.
export function currentOperator() {
  return { workstation: process.env.HOSTNAME || process.env.COMPUTERNAME || "unknown", pid: process.pid, user: process.env.USER || process.env.USERNAME || "unknown" };
}

// target: the plan-v2 document's own `target` object - identical shape
// across all three schemas (mode/host/port/user/hostKeySha256/
// installationId/baselineGeneration), duplicated across the three
// schemas deliberately (see each schema's own comment: no schema in
// this repo cross-references another by $id).
export async function buildLockDocument({ operationId, approvedPlanId, target, acquiredBy = currentOperator() }) {
  return assertValid("lock", {
    apiVersion: "hof.dev/operation-lock/v1",
    operationId, approvedPlanId, target,
    acquiredAt: new Date().toISOString(),
    acquiredBy,
  });
}

// plan is the FULL approved plan-v2 document (not just its planId) - see
// operation-journal-v1.schema.json's own comment on why: --resume reads
// operations[] straight from here, never re-derives a live baseline.
// approvedPlanId is asserted to equal plan.planId rather than trusted
// separately from the caller - the two must never be able to disagree.
export async function buildJournalDocument({ operationId, approvedPlanId, target, plan, inputDigests }) {
  if (plan.planId !== approvedPlanId) {
    throw new Error(`internal error: buildJournalDocument called with approvedPlanId ${approvedPlanId} but plan.planId ${plan.planId} - these must always be the same value`);
  }
  return assertValid("journal", {
    apiVersion: "hof.dev/operation-journal/v1",
    operationId, approvedPlanId, target, plan, inputDigests,
    startedAt: new Date().toISOString(),
    status: "in-progress",
    committedGeneration: null,
  });
}

// Never mutates the caller's own journal object - apply.mjs's own
// in-memory copy and what actually reaches the target must be produced
// by the exact same builder, not two independently-maintained shapes.
export async function withJournalStatus(journal, { status, committedGeneration = null }) {
  return assertValid("journal", { ...journal, status, committedGeneration });
}

export async function buildEvent({ operationId, step, attempt, phase, error }) {
  const event = { apiVersion: "hof.dev/operation-event/v1", operationId, step, attempt, phase, at: new Date().toISOString() };
  if (phase === "failed") event.error = error;
  return assertValid("event", event);
}

// The one genuinely subtle piece of logic ADR 0004 describes for resume:
// given every recorded operation-event-v1 for ONE step (any attempt),
// decide what apply --resume does with it.
//   run:     never attempted at all - dispatch it, attempt 1.
//   skip:    a "succeeded" event exists - already done, move on.
//   blocked: a "started" event exists with no later "succeeded"/"failed"
//     for the SAME attempt - the process died mid-operation, before or
//     after the target-side effect actually landed, with no way to tell
//     which. Never guessed at - resume stops here, the whole apply run
//     refuses to proceed further, and the operator must investigate the
//     target directly.
//   failed:  a "failed" event exists. Should never actually be reached
//     in practice - a failed step already marks the whole journal
//     "failed" (see apply.mjs), and a "failed" journal refuses resume
//     outright before ever walking individual steps. Kept as an
//     explicit, named outcome rather than falling through to "blocked"
//     or "run", so a future caller that reaches it anyway (a hand-edited
//     journal, a bug) gets a clear, distinct signal instead of a
//     misleading one.
export function decideStepResumption(events) {
  if (events.length === 0) return "run";
  if (events.some((event) => event.phase === "succeeded")) return "skip";
  if (events.some((event) => event.phase === "failed")) return "failed";
  return "blocked";
}

// journal-level gate, checked once before any per-step resumption logic
// even runs - a journal that already reached a terminal state is never
// resumed, regardless of what its individual step events say.
export function assertJournalResumable(journal) {
  if (journal.status === "succeeded") {
    throw new Error(`operation ${journal.operationId} already succeeded (committed generation ${journal.committedGeneration}) - nothing to resume`);
  }
  if (journal.status === "failed") {
    throw new Error(`operation ${journal.operationId} already failed - resume is refused, a fresh bootstrap is required after the target is manually diagnosed (see ADR 0004)`);
  }
}
