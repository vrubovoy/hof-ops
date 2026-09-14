// Pure, no-I/O contract helpers for ADR 0006 (item 10, PR 1) - shared by
// the backup/restore schemas' own field descriptions and by this item's
// contract tests. No target access, no clock, no randomness: every
// function here is a deterministic function of its own arguments,
// exactly like plan-v2.mjs's own computePlanId(). None of this allocates
// or persists a backupSequence - that allocation, and the under-mutex
// recheck of it, is target-side executor work a later PR in this item's
// own sequence adds (ADR 0006's own Decision explicitly scopes this PR
// to contracts and schemas only).

import { canonicalize, sha256 } from "./digest.mjs";

// The generic canonical content-id formula plan-v2.mjs's own
// computePlanId() already established: canonicalize the document minus
// its own id field, then hash. Shared here so backup-plan-v1's planId,
// restore-plan-v1's planId, and backup-policy-v1's policyId all compute
// identically to plan-v2's own planId - one formula, not three parallel
// reimplementations that could quietly drift apart.
export function canonicalContentId(docWithoutId, idField) {
  const { [idField]: _ignored, ...rest } = docWithoutId;
  return sha256(Buffer.from(JSON.stringify(canonicalize(rest))));
}

// backupId is deliberately NOT a canonicalContentId of the whole backup
// plan - a plan built from unchanged inputs (same installation, same
// generation, same consistency set, same destinations) is a completely
// realistic repeat: an operator re-running `hofctl backup` right after
// an earlier manual run, or a scheduled run firing twice in one
// generation. A content-id over plan content alone would give both runs
// the exact same backupId, and two independently-taken snapshots sharing
// one id is exactly the ambiguity ADR 0006's own resume/retry semantics
// must never allow (which destinations already have a snapshot "under
// this backupId" becomes undecidable). backupId is instead a
// domain-separated digest of only the four facts that must legitimately
// distinguish one backup attempt from every other one for the same
// installation: the installation itself, the generation being backed
// up, the exact approved backup policy in force (backup-policy-v1 is
// created/updated whenever an apply commits a services.yml carrying a
// backup: section - manual and scheduled runs alike are always bound to
// whichever policy is currently applied, never a plan-local synthetic
// one), and a monotonic, per-installation backupSequence a
// later PR's executor allocates and rechecks under the mutex before
// this id is ever computed. The domain-separation tag is fixed and
// versioned (not the schema's own apiVersion) so this formula can change
// independently of backup-plan-v1's own document shape.
const BACKUP_ID_DOMAIN = "hof.dev/backup-id/v1";

export function computeBackupId({ installationId, generation, backupPolicyId, backupSequence }) {
  if (typeof installationId !== "string" || installationId.length === 0) {
    throw new TypeError("computeBackupId: installationId must be a non-empty string");
  }
  if (!Number.isInteger(generation) || generation < 1) {
    throw new TypeError("computeBackupId: generation must be a positive integer");
  }
  if (typeof backupPolicyId !== "string" || backupPolicyId.length === 0) {
    throw new TypeError("computeBackupId: backupPolicyId must be a non-empty string");
  }
  if (!Number.isInteger(backupSequence) || backupSequence < 1) {
    throw new TypeError("computeBackupId: backupSequence must be a positive integer");
  }
  const input = { domain: BACKUP_ID_DOMAIN, installationId, generation, backupPolicyId, backupSequence };
  return sha256(Buffer.from(JSON.stringify(canonicalize(input))));
}

// Exact set equality between two arrays of documents, order-independent,
// duplicate-sensitive (a set with an item appearing twice is NOT equal
// to one where it appears once - this compares multisets, not
// mathematical sets, since a genuine duplicate consistency-set entry is
// itself a bug a binding check like this must catch, never silently
// collapse). keyFn reduces each item to the string this comparison is
// actually over (e.g. an entry's own volume name, or a whole entry's
// canonical JSON) - callers decide what "the same member" means for
// their own document shape.
export function exactSetEquals(itemsA, itemsB, keyFn) {
  const keysA = itemsA.map(keyFn).sort();
  const keysB = itemsB.map(keyFn).sort();
  if (keysA.length !== keysB.length) return false;
  return keysA.every((key, index) => key === keysB[index]);
}

// Whether any two items share the same key - a plan/policy generator (a
// later PR) or a contract test can use this to refuse a duplicate
// destination name, a duplicate consistencySet volume, or a duplicate
// operation id before ever trusting the document that contains it.
export function hasDuplicates(items, keyFn) {
  const seen = new Set();
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) return true;
    seen.add(key);
  }
  return false;
}

// A consistencySet entry's own natural comparison key (service+unit+
// volume - retained is metadata about the entry, never part of its own
// identity) - shared so every caller comparing two consistencySets
// (backup-plan-v1 vs its own backup-manifest-v1, or a manifest vs the
// restore-plan-v1 restoring it) uses the exact same notion of "the same
// volume", rather than each reimplementing its own key shape.
export function consistencySetEntryKey(entry) {
  return `${entry.service}/${entry.unit}/${entry.volume}`;
}
