import { createHash } from "node:crypto";

export function sha256(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

// A genuinely canonical JSON serialization - object keys sorted
// recursively at every depth, array element order always preserved
// (order there is semantically meaningful; key order in an object never
// is). Moved here from plan-v2.mjs (ADR 0006, item 10) so backup-plan-v1
// and restore-plan-v1's own planId, and backup-policy-v1's own policyId,
// compute identically to plan-v2's own planId - the exact same formula,
// not a parallel reimplementation. Behavior is unchanged from the
// original plan-v2.mjs-local version; plan-v2's own regression tests
// (test/plan-v2.test.mjs) cover it.
export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalize(value[key]);
    return sorted;
  }
  return value;
}
