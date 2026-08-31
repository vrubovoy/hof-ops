# ADR 0005: Applied reconciliation contract

- Status: Accepted
- Date: 2026-08-31

## Context

Delivery item 8 (ADR 0004) landed `hofctl apply` for bootstrap only - a
genuinely clean host, no prior Hof state. Delivery item 9 is the first
piece that mutates a host that already has real, applied state and,
often, real user data on it: config changes, drift repair, enabling or
disabling an optional service, and retain-only removal, all within the
currently-approved release. Backup/restore, data deletion, and release
or schema upgrades are explicitly out of scope here - items 10 and 11.

Much of the pure diff engine this needs already exists: `plan.mjs`'s own
`buildPlan()` already computes create/update/remove, drift, and
migration entries for an `applied` baseline (used today only to print
the informational `plan-v1` document against an already-applied host -
`hofctl apply` itself has never been able to execute one). This item's
job is narrower than "build a reconciler from scratch": make the
already-proven bootstrap machinery (`plan-v2`, the durable lock/journal/
event contract, the signed Execution Environment, the fixed action
whitelist) also cover an applied baseline, while drawing several new,
explicit boundaries drift repair and service enable/disable must never
cross on their own.

## Decision

**`hofctl plan` always prints an executable `plan-v2`, for either
baseline mode.** The `mode: "applied"` branch that used to print the
historical, informational `plan-v1` now calls the same `buildPlanV2()`
bootstrap already uses - no `plan-v3`; `plan-v2`'s own `mode` field,
target binding, and applied-compatible `$defs` shapes already cover
both. `plan-v1` and `buildPlan()` (the pure v1 core `buildPlanV2` still
wraps) stay unchanged, still directly schema-tested on their own.

**An applied no-op takes no lock, writes no journal, runs no Execution
Environment, and never bumps the generation.** Unlike a bootstrap (which
always has at least `host.prepare`/`secret.ensure` to run on a genuinely
clean host), a real "nothing to do" applied plan has zero operations at
all - `apply` recognizes this before ever touching the target's own
lock file and returns immediately. A real change always commits
`baseline.generation + 1`, exactly once, only after every prior
operation in the plan has already succeeded - the same "atomic, last
commit" invariant ADR 0004 already established, now for any positive
generation, not just 1.

**`installationId` is permanent.** Assigned once, at the first
successful bootstrap, from that operation's own UUID (ADR 0004) - an
applied operation's own operationId is a completely separate value
(scoped to that one apply run, like every bootstrap operationId always
was) and never replaces or is confused with it.

**Release, schema, and image changes to an already-applied unit are
out of scope, not silently executed.** `apply` refuses a plan whose
`desired.release` differs from a non-null `baseline.release`, and
(defense in depth, since a per-unit image/schema change can only
happen via a release change in this platform's own architecture)
refuses any individual `update` entry whose image changed for a unit
that was already enabled. A newly-enabled optional service is not an
upgrade - it always uses the current release's own already-approved
image, and may run its own first-time `database.migrate` normally.

**Retain-only removal for persistent services - never a silent
default.** Disabling an already-enabled service that owns a database
requires the manifest to say so explicitly
(`services.<id>.dataRetention: retain`) - a bare `enabled: false` on a
persistent service is a blocker, not a quiet delete. Even authorized,
removal only ever stops and removes the service's own containers
(discovered by exact `hof.managed`/`hof.installation-id`/`hof.unit`/
Compose-project match - never a project-wide `docker compose down`);
its volume is never removed and never backed up (`backup.create` is
outside item 9's own action whitelist entirely - see below). The
retained volume's name, and the schema version it was last migrated
to, are carried forward in the newly-committed state
(`retainedServices`) so a later re-enable reuses the same volume and
never re-runs its initial migration against data that's already at the
current schema. There is deliberately no way to express "delete this
retained service's data" in this item's own schema at all (no
`dataRetention: purge` value exists yet) - that's item 10's own,
later, explicit decision to make.

**A fixed, typed applied action whitelist - narrower than bootstrap's
in one direction, wider in another.** `scripts/applied-actions.mjs`
defines its own vocabulary, independent of `scripts/bootstrap-actions.mjs`:
every action bootstrap allows except `host.prepare` (nothing to prepare
on a host that's already been bootstrapped), plus `service.stop`/
`service.remove` (meaningless before a first apply, necessary for
drift repair and disable). `backup.create` is in neither whitelist -
item 9 never backs anything up (an in-place migration's own backup step
in `plan.mjs` is dead code under this item's own upgrade blocker, and
removal never backs up at all by design above); it is item 10's own
action to reintroduce, deliberately, when backup/restore actually
exists to make it meaningful.

**Supplied TLS material is part of the reconciled state, not just a
bootstrap-time fingerprint.** `baseline`/`desired` both now carry the
certificate/private-key fingerprints (`null` when `tls.mode` isn't
`supplied`) - a workstation-side certificate rotation, with no other
config change at all, is a real, detected diff (the gateway unit's own
`configFingerprint` folds these fingerprints in, alongside the
Caddyfile it already covered - the Caddyfile's own text never changes
just because the referenced certificate file's bytes did), and
`apply`'s existing delivery-time TOCTOU fingerprint check (ADR 0004's
own errata) already covers the applied path unchanged.

**Unused secrets are never deleted.** A service disabled (retained or
not) keeps its own secret both in the operator's encrypted workstation
store and on the target - simpler, and required for a safe retained
re-enable; a real secret-pruning story, if one is ever needed, is a
later, separate decision.

**Resume keeps ADR 0004's own fail-closed model unchanged.** An
ambiguous, unresolved operation (interrupted before or after its own
target-side effect landed, with no confirming record either way) still
blocks resume rather than guessing - for either baseline mode, using
the exact same durable lock/journal/event machinery items 8's own
several remediation rounds already hardened. Item 9 does not carry any
bootstrap/resume defect forward - it inherits whatever that machinery's
own current, reviewed state actually is at the time this item starts,
nothing more.

## Consequences

- `schemas/operation-journal-v1.schema.json`'s own `committedGeneration`
  invariant relaxes from "always exactly 1" back to "any positive
  integer once `status` is `succeeded`" - a bootstrap still only ever
  commits 1 (enforced by `apply` itself, not the schema, since the same
  journal schema now serves both modes).
- `schemas/services-v1alpha1.schema.json` gains an optional
  `dataRetention: "retain"` on each service selection - never required
  merely by existing, only by an actual enabled-to-disabled transition
  for a persistent service (the planner's own job, not the schema's).
- `schemas/state-v1.schema.json`, `schemas/plan-v1.schema.json`, and
  `schemas/plan-v2.schema.json` gain the new, optional
  `retainedServices` (`state.json`/`baseline`: what was actually
  committed; `desired`: what the planner computes this plan itself will
  commit if it runs, carried forward from baseline minus any re-enable
  plus any newly-retained disable) and `suppliedTlsCertificateFingerprint`/
  `suppliedTlsPrivateKeyFingerprint` fields (`null` when not applicable)
  - every field is optional and additive, so an existing, real
  generation-1 `current.json` written before this item stays valid and
  readable.
- The Ansible `service` role gains a typed `hof_service_action:
  start|stop|remove`, with `stop`/`remove` requiring an exact,
  single-container match by label before acting - never a project-wide
  or best-guess command. The `state` role now keeps every generation's
  own immutable snapshot (`generations/NNNNNN/{state,topology,
  release-lock}.json`) alongside the existing "current" pointer files,
  publishing the immutable snapshot first, the pointer files last
  (topology before current, unchanged from ADR 0004) - a repeated
  commit for the same generation is idempotent only if byte-identical
  to what's already there; a genuinely different one for an
  already-used generation number is refused, never silently overwritten.
- `hofctl apply`'s own dispatch, whitelist selection, and resume logic
  become mode-aware (`plan.mode`) rather than bootstrap-only, reusing -
  never re-deriving - the exact installation id and generation the
  embedded plan itself already carries.
- A real executor for `service.stop`/`service.remove`, and the planner
  changes described above (upgrade blockers, retain-only removal,
  reordered operations, migration skipped on a retained re-enable), are
  out of scope for the contracts introduced here and land in the PRs
  that follow, exactly like ADR 0004's own sequencing.
