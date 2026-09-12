# ADR 0006: Backup and restore contract

- Status: Accepted
- Date: 2026-09-04

## Context

Delivery items 8 and 9 (ADRs 0004/0005) gave `hofctl apply` a durable
lock/journal/event contract, a signed Execution Environment, and a
fixed, typed action whitelist for bootstrap and applied reconciliation.
Neither ever backs anything up: item 9's own `applied-actions.mjs`
whitelist deliberately excludes `backup.create` (ADR 0005's own
Consequences), and `plan-v2.schema.json`'s `backup.create` action
(`operation.phase: "backup"`, `operation.volume`) has sat dormant since
item 8 - it was shaped for item 8's own in-place-migration safety net,
never for a real, standalone backup/restore subsystem, and cannot
express a consistency set, multiple required destinations, immutable
evidence, or a *second*, clean target instance for restore.

Item 10 is that subsystem: manual `hofctl backup`, a mandatory systemd
timer, local and S3-compatible restic destinations, a coordinated
offline whole-platform backup, clean-host whole-platform restore,
retained (disabled) volumes included in the consistency set, an
encrypted recovery copy of application/TLS/backup secrets, and an
automated disposable-VM restore drill. Upgrade/rollback and in-place
restore (item 11), partial volume restore, retained-data purge,
migrating runtime secrets into `/run/hof/secrets`, and unattended
upgrades are all explicitly out of scope here.

This item's own manifest-level config already exists and predates any
executor: `services-v1alpha1.schema.json`'s `backup` object (`schedule`,
`retention: {daily, weekly, monthly}`, `destinations` - a `local`/`s3`
discriminated union keyed by `type`, each with a unique `name` and a
`secretRef`, never a raw credential) and `render-topology.mjs`'s own
rendered `backup-inventory.json` (`schedule`, `retention`, `destinations`,
and every enabled service's own volumes). Item 10 consumes this
existing, already-contract-tested shape directly rather than inventing
a parallel one - it does not yet cover retained (disabled) volumes,
which this item's own consistency set must add.

The one hard sequencing constraint: `v0.2.3` (already published, no
backup path at all) must be able to get a real backup *before* item 11
(upgrade) exists, because upgrade needs a pre-upgrade backup and a
backup mechanism gated behind a new platform release would make
upgrade depend on backup depend on upgrade. The independent, separately
signed `backup-tool-lock` (below) exists specifically to break that
cycle - a backup/restore tool build can ship and be trusted without
cutting a new platform release at all.

This ADR covers scope, trust boundaries, the two new operation state
machines (backup, restore), and failure semantics - the contracts and
schemas only. No executor, target-side runner, Ansible role, or systemd
unit exists yet; those are later PRs in this item's own sequence,
exactly like ADR 0004's own sequencing.

## Decision

**`plan-v2`'s `backup.create` stays dormant, permanently.** It is not
extended, not activated, and not added to any whitelist by this item.
It cannot express a consistency set, multiple required destinations,
per-destination evidence, or a restore side at all - retrofitting it
would mean overloading one action's worth of schema with an entirely
different operation's shape. `plan-v2` and its own whitelist(s) are
otherwise untouched by this item.

**Two new, independent operation kinds - `backup` and `restore` -
alongside `apply`.** `operation-lock-v2.schema.json` and
`operation-journal-v2.schema.json` add a required `operationKind: enum
["apply", "backup", "restore"]` field; everything else about their
shape is unchanged from `operation-lock-v1`/`operation-journal-v1`. A
pre-existing on-target `lock.json`/journal document has no
`operationKind` field at all (it predates this ADR) - the executor a
later PR introduces must still read and safely resume it as an implicit
`apply`, never refuse it outright just because the field is absent.
`operation-event-v1` is reused completely unchanged for all three kinds
- its `step`/`phase`/`error` fields were already kind-agnostic (no
apply-specific enum baked in beyond the generic `NNN.action.resource`
id shape backup/restore plans use identically).

**One physical execution mutex, shared across all three kinds.** A
`backup` in progress refuses a concurrent `apply` or `restore` against
the same target, and vice versa, in every direction - not just
same-kind contention. The mutex is a lower-level primitive than any one
kind's own durable lock/journal (mirroring ADR 0004's own execution-lease
vs. durable-lock split): it is what lets an operation's own cleanup run
to completion even if the SSH connection or the operator's workstation
drops mid-backup, by moving execution onto a target-side, signed runner
process rather than depending on the workstation's own SSH session
staying open for the operation's entire duration.

**A target-side signed runner with a fixed action vocabulary - no
generic executor, matching ADR 0004's own decision.** The runner and
pinned `restic`/`sops`/`age` binaries are delivered from the signed
Execution Environment, dispatched only through the same fixed,
enumerated `action` values `backup-plan-v1.schema.json`/
`restore-plan-v1.schema.json` define below - never an arbitrary command.

**A separate, independently signed `backup-tool-lock`.** Pins the exact
EE image digest (and the exact `restic`/`sops`/`age` versions baked into
it) via the same Cosign keyless identity/issuer pair
`release-lock-v1.schema.json`'s own first-party components already use,
under its own tag namespace (`backup-tool-vX.Y.Z` - distinct from both
`vX.Y.Z` platform releases and `ee-vX.Y.Z` Execution Environment tags,
so none of the three can ever collide on one git tag). This is what
lets `v0.2.3` get a real, signed backup path without cutting a new
platform release, and lets a later backup-tool fix ship without one
either - breaking the upgrade-needs-backup-needs-upgrade cycle.

**Backup Flow - the fixed, typed operation whitelist
`backup-plan-v1.schema.json` encodes.** Planning-time (never dispatched
as operations; refused before the mutex is ever requested): verify the
signed platform release and the signed `backup-tool-lock`; read target
state and require no drift, no corruption, and no other operation
already in progress; build a deterministic plan bound to the target's
host key, `installationId`, generation, release-lock digest, the exact
consistency set (every enabled unit's volumes, per
`backup-inventory.json`, **plus** every `retainedServices` volume -
disabled-but-retained volumes are explicitly in scope, unlike a plain
apply), and every configured destination; require explicit approval for
a manual run (a scheduled run uses the already-approved backup policy
instead). Dispatched, in order, under the mutex: `maintenance.enter`
(marker written, public traffic closed); `service.stop`
(dependents-first, reusing `plan-v2`'s own action name and ordering
convention); a fresh, under-lock re-check of committed state before
anything further; `staging.build` (the allowlisted tree: generated
config, a sanitized manifest, the signed release lock, the encrypted
recovery store, the backup manifest, and every unit's own consistency-
set volume); `snapshot.create`, once per configured destination, sharing
one `backupId` across all of them, each independently metadata-verified;
`retention.apply`, namespaced by `installationId` so one installation's
retention can never touch another's snapshots in a shared repository;
in a `finally` regardless of outcome so far: `service.start`
(dependencies-first, gateway last), `readiness.wait`, `maintenance.exit`;
finally `evidence.write` (atomic, never touching `current.json` or the
generation). All configured destinations are required for overall
success - a partial result (some destinations succeeded, at least one
did not) is recorded faithfully in evidence but the operation itself
still returns failure, never a silent partial success.

**Restore Flow - the fixed, typed operation whitelist
`restore-plan-v1.schema.json` encodes, against a *second*, clean
target.** Planning-time: obtain the recovery kit, the recovery age
identity, the destination, and the `backupId`; verify the restic
snapshot, the backup manifest embedded in it, and the signed historical
release lock it names (a release lock from `v0.2.1`, say, restored onto
a target running today's tooling, still verifies against exactly the
signature identity it was originally signed with); pin the new target's
own freshly-observed SSH host key and require it be genuinely clean (no
prior Hof state at all - this is never an in-place restore); build and
require explicit approval of a restore plan naming the source
`installationId`/`generation`/`release` distinctly from the new target's
own identity. Dispatched under the mutex: `runner.install` (the signed
runner itself, from the `backup-tool-lock`); `target.verify-clean`
(re-checked once more under the mutex, not trusted from planning time
alone); `snapshot.verify`; `volume.create` (operation-owned volumes and
networks only - a restore never adopts or overwrites a resource it
didn't itself just create) and `data.restore` for the full consistency
set; `manifest.verify` and `database.integrity-check` against the
actually-restored files, before any container using them ever starts;
`checkpoint.data-restored` (a durable, resumable marker - see Failure
semantics); `config.restore` and `secret.materialize` (restored
generated config and encrypted secrets; runtime secret files are
materialized as their own distinct step, never conflated with restoring
the encrypted store itself); `state.restore` (the source
`installationId` and generation restored verbatim, **never
incremented** - this is not a new applied change, it is the same
installation's history continuing on new hardware; restore provenance -
that this generation's data arrived via a restore, from which backup,
onto which new host - is recorded separately from `current.json`,
never folded into the generation history itself); `service.start`
(dependencies-first, gateway last), `readiness.wait`; finally
`evidence.write`.

**Failure semantics and resumability.** All configured destinations are
required for a backup's own overall success, exactly as stated above.
Every checkpoint the two flows name above is a real crash/resume
boundary: backup may crash after `service.stop`, after `snapshot.create`
for some but not all destinations, during `retention.apply`, or before
`evidence.write` is durably recorded - a resumed or retried backup must
be safe to re-run from any of these without double-stopping an
already-stopped unit, creating a second inconsistent snapshot under the
same `backupId`, or applying retention twice. A backup failure, however
it happens, must still guarantee the `finally` block above actually
runs - units restarted, maintenance mode cleared, readiness confirmed -
never leaving a target stuck in maintenance mode because the failure
happened before the `finally`. Restore has exactly one privileged
checkpoint: `checkpoint.data-restored`. Before it, `--resume` may delete
only the volumes *this* restore operation itself created and start
materialization over from nothing; after it, restored data is never
rewritten or re-fetched again - `--resume` continues only with
provisioning, `service.start`, and `readiness.wait`, never touching data
a second time.

**`backup.schedule` is interpreted in the target's own local time; the
local destination is operator-pre-mounted.** Hof never mounts an
arbitrary filesystem on the target's behalf - a `local` destination's
`path` is assumed already mounted and writable by the operator's own
setup, exactly as it already was for `services-v1alpha1.schema.json`'s
existing `backup.destinations[].type: "local"`.

## Consequences

- Five new schemas: `backup-plan-v1`, `restore-plan-v1`,
  `backup-manifest-v1` (written into the snapshot itself),
  `backup-evidence-v1`, `restore-evidence-v1` - none cross-reference
  another schema file by `$id` (this repo's own convention; shared
  shapes like `targetBinding`, `identifier`, and the `local`/`s3`
  destination split are each copied independently).
- One new, independently signed lock schema, `backup-tool-lock-v1`,
  under its own `backup-tool-vX.Y.Z` tag namespace - a real signed
  artifact this item's later PRs must build a new CI workflow to
  produce, exactly as `execution-environment.yml`/`release.yml` already
  do for the Execution Environment and the platform release.
- `operation-lock-v1`/`operation-journal-v1` are superseded by
  `operation-lock-v2`/`operation-journal-v2` for every *new* operation
  from this item onward, but are never deleted or made unreadable - the
  executor PR that follows this one must keep reading and safely
  resuming a pre-existing v1 document with no `operationKind` field.
  `operation-event-v1` is not superseded at all; there is no
  `operation-event-v2`.
- `plan-v2.schema.json`'s own `backup.create` action, and the two
  bootstrap/applied action whitelists, are completely unchanged by this
  item - dead code remains dead code, on purpose.
- No executor, target-side runner, Ansible role, systemd unit, CLI
  surface (`hofctl backup`/`hofctl restore`), or CI workflow exists yet.
  The contracts and schemas introduced here, and the contract tests
  covering them, are this PR's entire scope - every later PR in this
  item's own sequence builds on top of them, never revisits this ADR's
  own Decision in place (only appends dated Errata, exactly like ADRs
  0004 and 0005 already do).
