// Pure whitelist for delivery item 9's own scope (ADR 0005): hofctl
// apply against an already-applied host - config changes, drift repair,
// enable/disable of an optional service, retain-only removal, all
// within the currently-approved release. Deliberately its own module,
// independent of scripts/bootstrap-actions.mjs (never shared, matching
// this repo's own "no cross-module coupling for a fixed vocabulary"
// convention) - the two whitelists differ in both directions: applied
// excludes host.prepare (nothing to prepare on a host that's already
// been bootstrapped) but includes service.stop/service.remove
// (meaningless before a first apply, necessary for drift repair and
// disable here). backup.create is in NEITHER whitelist - item 9 never
// backs anything up (see ADR 0005); it's item 10's own action to
// reintroduce once backup/restore actually exists to make it
// meaningful.

export const APPLIED_ALLOWED_ACTIONS = new Set([
  "secret.ensure", "volume.ensure", "network.ensure",
  "image.verify", "image.pull", "config.write", "database.migrate",
  "service.start", "service.stop", "service.remove", "readiness.wait", "state.commit",
]);

// Present in plan-v1/v2's own action vocabulary but never valid for an
// applied plan - named explicitly (rather than only relying on "not in
// the allow-list") so a rejection message says why, not just that it
// wasn't found on a list.
const BOOTSTRAP_ONLY_ACTIONS = new Set(["host.prepare"]);
const NEVER_ALLOWED_ACTIONS = new Set(["backup.create"]);

// plan: a plan-v1 or plan-v2 document ({mode, operations, ...}) - this
// module has no opinion on which version, matching bootstrap-actions.mjs's
// own. Returns an array of human-readable errors (empty when the plan is
// genuinely safe for an applied apply to run), never throws for an
// ordinary validation failure.
export function validateAppliedActions(plan) {
  const errors = [];
  if (plan?.mode !== "applied") {
    errors.push(`plan mode is ${JSON.stringify(plan?.mode)}, not "applied" - an applied apply only ever runs an applied plan`);
  }
  for (const operation of plan?.operations ?? []) {
    if (NEVER_ALLOWED_ACTIONS.has(operation.action)) {
      errors.push(`operation ${operation.id} (${operation.action}) is outside item 9's own scope entirely (see ADR 0005) - refusing to run it`);
    } else if (BOOTSTRAP_ONLY_ACTIONS.has(operation.action)) {
      errors.push(`operation ${operation.id} (${operation.action}) only ever makes sense on a genuinely clean bootstrap host - an applied plan must never contain it`);
    } else if (!APPLIED_ALLOWED_ACTIONS.has(operation.action)) {
      errors.push(`operation ${operation.id} (${operation.action}) is not in the applied action whitelist - refusing to run it`);
    }
  }
  return errors;
}
