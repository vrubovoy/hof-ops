// Pure whitelist for delivery item 8's own scope: hofctl apply only ever
// runs a bootstrap plan against a genuinely clean host (see ADR 0004 -
// applied-mode reconciliation is delivery item 9, not this one). This is
// deliberately narrower than plan-v1/v2's own full action vocabulary
// (already enforced by the plan schema itself) - a bootstrap plan that
// somehow contained an applied-mode-only action (backup.create,
// service.stop, service.remove - nothing to back up, stop, or remove on
// a host with nothing running yet) must be rejected outright, never
// silently skipped or executed anyway. No generic command, path,
// playbook, tag, or environment variable ever reaches this - every
// action here is one of the fixed types plan.mjs itself already emits.

export const BOOTSTRAP_ALLOWED_ACTIONS = new Set([
  "host.prepare", "secret.ensure", "volume.ensure", "network.ensure",
  "image.verify", "image.pull", "config.write", "database.migrate",
  "service.start", "readiness.wait", "state.commit",
]);

// Present in plan-v1/v2's own action vocabulary but never valid for a
// bootstrap - named explicitly (rather than only relying on "not in the
// allow-list") so a rejection message says why, not just that it wasn't
// found on a list.
const APPLIED_ONLY_ACTIONS = new Set(["backup.create", "service.stop", "service.remove"]);

// plan: a plan-v1 or plan-v2 document ({mode, operations, ...}) - this
// module has no opinion on which version, since the action vocabulary
// and the bootstrap-only restriction are identical for both. Returns an
// array of human-readable errors (empty when the plan is genuinely safe
// for a bootstrap apply to run), the same convention validateDeployment/
// validateContracts already use - never throws for an ordinary
// validation failure.
export function validateBootstrapActions(plan) {
  const errors = [];
  if (plan?.mode !== "bootstrap") {
    errors.push(`plan mode is ${JSON.stringify(plan?.mode)}, not "bootstrap" - a bootstrap apply only ever runs a bootstrap plan`);
  }
  for (const operation of plan?.operations ?? []) {
    if (APPLIED_ONLY_ACTIONS.has(operation.action)) {
      errors.push(`operation ${operation.id} (${operation.action}) only ever makes sense against an already-applied host - a bootstrap plan must never contain it`);
    } else if (!BOOTSTRAP_ALLOWED_ACTIONS.has(operation.action)) {
      errors.push(`operation ${operation.id} (${operation.action}) is not in the bootstrap action whitelist - refusing to run it`);
    }
  }
  return errors;
}
