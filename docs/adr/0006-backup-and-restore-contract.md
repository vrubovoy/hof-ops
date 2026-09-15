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
which this item's own consistency set must add. It also has no notion
yet of one *approved, versioned* policy an unattended scheduled run can
bind to without a fresh interactive approval - `backup-policy-v1`
(below) adds that.

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
exactly like ADR 0004's own sequencing. `scripts/backup-ids.mjs` and
`scripts/backup-flow.mjs` (below) are the one exception: small, pure,
no-I/O modules of id/binding/flow-shape formulas the schemas' own field
descriptions already depend on - they allocate nothing and touch no
target, so they belong with the contracts rather than with a later
executor PR. A second review round of this same PR found that JSON
Schema alone cannot express two classes of real, load-bearing invariant
this item needs: "this array's count of X must equal that other array's
own length" (no schema in this repo uses `$data` references), and "this
field over here must equal that field over there" (ditto) - a schema-
valid backup-plan-v1 with only one `snapshot.create` for two configured
destinations, or a schema-valid evidence document naming a manifest it
never actually came from, is not a contradiction the schemas themselves
can catch. `scripts/backup-flow.mjs`'s own operation-flow and bundle
validators exist specifically to close that gap, and this item's
contract tests build every "happy path" fixture by actually running it
through the real id-computation functions rather than an arbitrary,
unrelated placeholder value - a positive fixture that would fail its own
bundle validator proves nothing.

## Decision

**`plan-v2`'s `backup.create` stays dormant, permanently.** It is not
extended, not activated, and not added to any whitelist by this item.
It cannot express a consistency set, multiple required destinations,
per-destination evidence, or a restore side at all - retrofitting it
would mean overloading one action's worth of schema with an entirely
different operation's shape. `plan-v2` and its own whitelist(s) are
otherwise untouched by this item.

**Two new, independent operation kinds - `backup` and `restore` - each
with their own v2 lock/journal/event family, scoped to those two kinds
ONLY, never `apply`.** `operation-lock-v2.schema.json`,
`operation-journal-v2.schema.json`, and `operation-event-v2.schema.json`
add a required `operationKind: enum ["backup", "restore"]` field - a
second review round found the first draft's `enum ["apply", "backup",
"restore"]`, "schema-valid for completeness, just never produced by
apply" shape was an unresolved contradiction, not a harmless
generalization: the existing apply executor (`scripts/
operation-journal.mjs`, unchanged by this item) reads and writes
`operation-lock-v1`/`operation-journal-v1`/`operation-event-v1`
exclusively, for every apply run, old or new, forever within this
item's own scope - there is no migration path, no code that could ever
produce a `operationKind: "apply"` v2 document, and the v1/v2 schemas'
own descriptions disagreed with each other about which event schema
paired with which journal kind. Removing `apply` from all three v2
enums resolves that: `operation-lock-v1`/`operation-journal-v1`/
`operation-event-v1` are apply's own family, permanently, unchanged;
`operation-lock-v2`/`operation-journal-v2`/`operation-event-v2` are
backup/restore's own family, exclusively. Both v2 lock/journal also now
enforce the SSH-mode/`hostKeySha256` pairing their own `targetBinding`
already documented in prose but never actually enforced (a real, if
minor, schema gap `backup-plan-v1`/`restore-plan-v1` below do not
repeat) - `operation-lock-v1`/`operation-journal-v1` themselves are
untouched, gap and all, since this item never revisits a v1 schema in
place. A pre-existing on-target `lock.json`/journal document has no
`operationKind` field at all (it predates this ADR) - the executor a
later PR introduces must still read and safely resume it as an implicit
`apply`, never refuse it outright just because the field is absent;
that case is unaffected by v2 being backup/restore-only, since a
pre-ADR document was always an apply document anyway.
`operation-journal-v2` additionally checks, per `operationKind`, that
its own embedded `plan.apiVersion` (`backup-plan-v1` for backup,
`restore-plan-v1` for restore) and its own `inputDigests` shape (backup:
`releaseLockDigest`/`backupToolLockDigest`/`backupPolicyId`; restore:
`releaseLockDigest`/`backupToolLockDigest`/`manifestDigest`/
`recoveryKitDigest`) actually match - a backup journal can no longer
embed a restore plan, or vice versa, and inputDigests can no longer
silently mix the two kinds' own fixed input sets (this item's earlier
draft required all five of apply's own digest names unconditionally,
regardless of `operationKind` - a real gap this closes). `approvedPlanId
== plan.planId` (and `lock`/`journal`/`event` all actually agreeing with
the plan they claim to belong to, and with each other) is a class of
binding schema genuinely cannot check without a `$data` reference (none
are used anywhere in this repo). A second review round's own draft of
this ADR already claimed `scripts/backup-flow.mjs`'s bundle validators
enforced this; a third review round found that claim was false -
neither `validateBackupBundle()` nor `validateRestoreBundle()` accepted
a `lock`, `journal`, or `event` argument at all, so `operationId`,
`operationKind`, `target`, `approvedPlanId`, `inputDigests`, and every
event's own `step`/`operationId`/`operationKind` went entirely
unchecked. Both functions now take optional `lock`/`journal`/`events`
parameters and check all of the above when supplied - a fourth review
round then found `evidence` itself was still an island: nothing checked
`evidence.operationId` against `lock.operationId`/`journal.operationId`,
nor that a `journal`'s own terminal `status` actually reconciles with
what `evidence` claims (`journal.status: in-progress` can never coexist
with evidence at all - `evidence.write` is what terminates the journal;
`succeeded` must correspond to `evidence.status: succeeded`; `failed`
can never correspond to `evidence.status: succeeded`; `evidence.
abandoned: true` must correspond to `journal.status: failed`, since
abandonment is itself a terminal failure). Both bundle validators now
check this too. `operation-journal-v2.schema.json`'s own embedded `plan`
also required only `apiVersion` until this same round - a schema-valid
journal could omit `planId` entirely, contradicting the bundle
validators' own assumption that `journal.plan.planId` exists; `plan` now
requires both. A fifth review round found `planId`-only equality was
still not enough: a schema-valid journal could carry the CORRECT
`planId` while `journal.plan` itself stayed the same truncated
`{apiVersion, planId}` stub - matching the one declared field while
still not being "the full, exact plan document" this schema's own
description has always claimed. `validateBackupBundle()`/
`validateRestoreBundle()` now require `journal.plan` to structurally,
deep-equal the real `plan` object passed in, not merely share a
`planId`. `evidence.abandoned: true` also wasn't cross-checked against
the actual event log - a bundle whose events showed every one of the
plan's own operations already succeeded, including `evidence.write`
itself, could still honestly-looking claim abandonment; both bundle
validators rejected that specific contradiction when `events` was
supplied.

A sixth review round found that first `abandoned` fix was itself too
narrow: requiring every plan operation's event to show `succeeded`
before flagging the contradiction let a real counterexample straight
through - journal `failed`, `abandoned: true`, `evidence.write`'s own
event genuinely `succeeded`, but some unrelated earlier step's event
simply missing from the log. That still passed the "every step"
check even though a successful `evidence.write` is on its own the
flow's natural terminal completion - the one thing `abandoned: true`
asserts never happened, regardless of what else is or isn't present
in the log. Both bundle validators now look up the plan's own
`evidence.write` operation directly (`plan.operations.find(op =>
op.action === "evidence.write")` - both plan schemas' own ordering
rule guarantees it exists and is last) and reject `abandoned: true`
whenever that one step's own event shows `succeeded`, independent of
every other step.

**`operation-event-v2` exists alongside the unchanged
`operation-event-v1` for a semantic reason, not because lock/journal
happened to gain a v2 too.** `operation-event-v1` hard-codes apply's own
all-or-nothing rule directly into its prose contract: for a given step,
an unresolved `started` blocks resume entirely, and `failed` is always
fatal short of a fresh bootstrap. That rule is wrong for the two new
kinds by this ADR's own later design: a backup may crash after
`snapshot.create` succeeded for some destinations and not others, and a
resumed run must recognize exactly which, continuing the rest rather
than refusing outright; a restore has exactly one privileged checkpoint
(`checkpoint.data-restored`) and is otherwise safely restartable from
nothing before it, never rewritten after it (see Failure semantics
below) - neither shape fits "any unresolved step is a global block."
`operation-event-v2` is used for every `backup` and `restore` event; the
existing apply executor is unchanged and keeps emitting
`operation-event-v1` exclusively - there is no migration of apply's own
event stream in this item. Concretely, `operation-event-v2` drops v1's
own universal resumability verdict from its schema description; which
step+attempt is terminal versus resumable is decided by the journal's
own `operationKind`-specific reconciliation (a later PR's executor)
using this log purely as evidence, not by the event schema itself. It
also carries the new required `operationKind` field (so a consumer
reading raw stdout NDJSON can interpret `step`/`phase` without first
cross-referencing the journal, and can confirm an event's own claimed
kind actually matches the journal/lock it says it belongs to) and an
optional `destination` field for a backup-kind event about a
per-destination step, identifying a partial failure without
cross-referencing the plan.

**One physical execution mutex, shared across both new kinds and
`apply`.** A `backup` in progress refuses a concurrent `apply` or
`restore` against the same target, and vice versa, in every direction -
not just same-kind contention. This mutex is a genuinely separate,
lower-level primitive from any of the lock/journal document families
above (mirroring ADR 0004's own execution-lease vs. durable-lock split);
it is NOT `operation-lock-v2` itself, which is why scoping v2 to
backup/restore only (above) does not weaken this guarantee - apply's own
mutex acquisition (a later PR touches `scripts/operation-journal.mjs`
for this, unchanged today) and backup/restore's each acquire the one
shared, lower-level primitive before ever touching their own kind-
specific lock.json. It is what lets an operation's own cleanup run to
completion even if the SSH connection or the operator's workstation
drops mid-backup, by moving execution onto a target-side, signed runner
process rather than depending on the workstation's own SSH session
staying open for the operation's entire duration.

**A target-side signed runner with a fixed action vocabulary - no
generic executor, matching ADR 0004's own decision.** The runner and
pinned `restic`/`sops`/`age` binaries are delivered from the signed
Execution Environment, dispatched only through the same fixed,
enumerated `action` values `backup-plan-v1.schema.json`/
`restore-plan-v1.schema.json` define below - never an arbitrary command.

**A separate, independently signed `backup-tool-lock`, declaring its own
exact document compatibility.** Pins the exact EE image digest (and the
exact `restic`/`sops`/`age` versions baked into it) via the same Cosign
keyless identity/issuer pair `release-lock-v1.schema.json`'s own
first-party components already use, under its own tag namespace
(`backup-tool-vX.Y.Z` - distinct from both `vX.Y.Z` platform releases and
`ee-vX.Y.Z` Execution Environment tags, so none of the three can ever
collide on one git tag). This is what lets `v0.2.3` get a real, signed
backup path without cutting a new platform release, and lets a later
backup-tool fix ship without one either - breaking the
upgrade-needs-backup-needs-upgrade cycle. It also names, in a required
`compatibility` object, the exact `apiVersion` of every plan/policy/kit/
lock/journal/event document its pinned runner build actually understands
- a backup-tool build predating some later revision of any one of those
schemas must never be silently trusted against a document shape it was
never built to interpret; the runner refuses to start on a mismatch,
exactly as it already refuses to start on an unpinned `restic`/`sops`/
`age` binary.

**`backup-policy-v1` - the immutable, approved policy a scheduled run
binds to. `policyId` excludes its own freshness metadata.** Created or
replaced only when an apply commits a `services.yml` carrying a changed
`backup:` section, never per backup run - copies that section's
`schedule`/`destinations`/`retention` verbatim, plus the fixed platform
rule that every disabled-but-retained volume is always included
alongside every enabled unit's own volume (`includeRetainedVolumes`,
pinned `true` for this policy version). `appliedGeneration` and
`appliedManifestDigest` record which apply most recently reconfirmed
this policy as current - genuinely useful freshness metadata, but NOT
part of `policyId`'s own identity: a second review round found the
first draft's `policyId` included both, which meant an unrelated apply
(bumping the generation and the whole manifest's own digest while
leaving `backup:` itself byte-identical) would either go stale
(`appliedGeneration` no longer matching reality, if the policy document
is kept unchanged) or mint a new `policyId` for a policy whose actual
content never changed (if it's naively re-derived every apply) -
neither is coherent with "created or replaced only when `backup:`
itself changes." `policyId` is now a content-id over
`schedule`/`destinations`/`retention`/`includeRetainedVolumes`/
`installationId` alone (`scripts/backup-ids.mjs`'s `canonicalContentId`,
which now accepts more than one excluded field for exactly this case);
`appliedGeneration`/`appliedManifestDigest` are re-stamped every apply
that reconfirms the policy, whether or not `backup:` itself actually
changed that time, without ever perturbing `policyId`. Both a manual
`hofctl backup` and the systemd timer's own scheduled run bind to
whichever policy is currently applied via `backup-plan-v1`'s own
`backupPolicyId` - never a plan-local synthetic one - which is what lets
a scheduled run skip fresh interactive approval: the policy itself was
already approved when it was applied. That id binding alone is not
enough to stop the policy from being bypassed, though: a third review
round found a plan could reference the correct, real `backupPolicyId`
while quietly carrying its OWN, different `destinations` or `retention`
- the approved policy's own content was never actually compared against
what the plan does. `scripts/backup-flow.mjs`'s own `validateBackupBundle()`
now also requires `plan.destinations`/`plan.retention` to exactly,
structurally match the supplied policy's own - not merely share an id.
A fourth review round found one more way the same bypass could happen:
nothing checked `plan.generation === policy.appliedGeneration` either,
so a plan built at a NEWER generation than the policy's own last
reconfirmation could still be authorized by a genuinely stale policy -
exactly the freshness check `appliedGeneration`'s own field description
already promised but `validateBackupBundle()` never implemented. It now
does.

**`backupId` is a domain-separated digest, never a content-id of the
plan - and a new, monotonic `backupSequence` is why. `backupSequence`
is allocated once per NEW operationId, never once per attempt within
one.** Every other id in this repository (`planId`, and now `policyId`)
is a content-id: a canonicalized hash of the document's own fields.
`backupId` cannot be, because a content-id would make two genuinely
different backup attempts for an unchanged installation - an operator
starting a fresh `hofctl backup` after an earlier one already finished,
or a scheduled run firing again a day later, both completely realistic
- collide on the exact same id. `backup-plan-v1` instead adds a required
`backupSequence`: monotonic per installation, allocated and rechecked
under the mutex immediately before a plan is built (that allocation is
executor work, a later PR - this ADR fixes only the contract).
Critically, that allocation happens exactly once per NEW operationId -
a `--resume` of an EXISTING, still in-progress one (journal status
`in-progress`, meaning `evidence.write` has not yet run) reuses its own
already-allocated sequence, and so the same `backupId`, which is
precisely what lets it recognize which destinations already have a
snapshot under that id and continue rather than starting over; only a
genuinely new operationId, started after the previous one already
reached its own terminal, evidence-written state, allocates the next
sequence value. `backupId` is computed (`scripts/backup-ids.mjs`'s
`computeBackupId`) as a domain-separated digest of exactly
`installationId`, `generation`, `backupPolicyId`, and `backupSequence` -
never plan content, so two independently-taken snapshots never silently
share one id, and a genuinely repeated backup (as opposed to a resumed
one) always mints a fresh, distinguishable id.

**A journal's own `status: failed` always means `evidence.write` already
ran - it is never a mid-operation, still-resumable state.** `evidence.
write` is the fixed final step of both flows' own `finally` block, which
this ADR's own Failure semantics section (below) already requires to run
regardless of how a backup fails. So by construction, journal `status`
only ever transitions away from `in-progress` once evidence for
whatever this operationId actually achieved - including a real partial
backup result - is already durably, immutably recorded. `--resume` is
therefore only ever valid while `status` is still `in-progress`; a
`failed` (or `succeeded`) journal is always terminal, and a retried
attempt after either is always a genuinely new operationId (see
`backupSequence` above), never a `--resume` of the old one. This was a
real ambiguity in this item's own first draft, where `failed`'s prose
("never blindly retry this same journal") read as an absolute rule with
no stated reason, leaving open whether a mid-flight partial failure -
one destination's `snapshot.create` succeeding, another's crashing -
should also be `failed` and so non-resumable, contradicting this same
ADR's own promise that such a crash is safely resumable. It is not a
contradiction: that mid-flight crash never reaches `evidence.write` at
all, so its journal is still `in-progress`, not `failed` - `failed`
proper is reserved for the case where the whole operation, including its
own `finally` block, already concluded (however that conclusion reads in
`backup-evidence-v1`'s own honest `succeeded`/`partial`/`failed`
status).

**Restore has no guaranteed `finally` block the way backup does - an
explicit operator `abandoned` marker is its only path to a terminal
state when stuck. `committedGeneration` is NOT tied to overall status
for restore.** A third review round found two further, real gaps in the
above: first, backup's own `finally` block is a decision THIS ADR makes
(every backup dispatch always reaches `service.start`/`readiness.wait`/
`maintenance.exit`/`evidence.write` regardless of outcome so far) -
restore's own operation whitelist has no equivalent guarantee, so a
restore that gets genuinely stuck before its own natural `evidence.write`
(the target never comes back, say) has no other path to a terminal
state at all. Both `backup-evidence-v1` and `restore-evidence-v1` now
carry a required `abandoned` boolean - `true` only when this terminal
evidence exists because the operator explicitly gave up on a stuck,
still-`in-progress` operationId, `false` for every outcome (success, or
a real in-flow failure) that itself reached `evidence.write` naturally;
always `false` when `status: succeeded`. Second, `committedGeneration`'s
own succeeded-only conditional was actually WRONG for restore:
`state.restore` (which genuinely commits the generation) runs several
steps before the operation's own overall conclusion, so a restore can
legitimately reach `status: failed` (a later step - `service.start`,
`readiness.wait` - failed) while still correctly carrying a non-null
`committedGeneration`, because the generation really was committed
first; the schema's own earlier "succeeded requires it, everything else
forbids it" rule would have forced a dishonest `null` in exactly that
case. `operation-journal-v2.schema.json` no longer ties restore's own
`committedGeneration` to `status` at all - its real correctness (does it
match whether a `state.restore` succeeded event actually exists, and
does its VALUE actually equal the source generation being restored) is
checked by `scripts/backup-flow.mjs`'s own
`validateRestoreCommittedGeneration(journal, events, plan)`, wired into
`validateRestoreBundle()` itself (a fifth review round found it existed
but was never actually called from there). It identifies the real
`state.restore` step by looking up `plan.operations.find(op => op.action
=== "state.restore")` - never by pattern-matching an event's own `step`
text: a fourth round already replaced a loose `.includes()` substring
check with an anchored regex, but a fifth round found even that stayed
spoofable, since nothing ties an operation's own `id` to its own
`action` - a schema-valid plan could still name an unrelated operation
`id: "010.state.restore.decoy"`. Only the plan's own `action` field is a
trustworthy source for which step id is genuinely `state.restore`.

**`recovery-kit-v1` - the encrypted recovery envelope itself, private
identity always external. Schema alone cannot prove `ciphertext` is real
- `scripts/backup-flow.mjs`'s `verifyRecoveryKit()` does.** A
self-contained, portable document: public age recipient and its
fingerprint, a closed `contentInventory` of fixed categories only
(`application-secrets`, `tls-private-keys`,
`backup-destination-credentials` - never a specific secret's own name),
the age-encrypted ciphertext itself (base64), and an independent
`ciphertextDigest` of just that ciphertext. The matching private age
identity is never generated, stored, or transmitted by any Hof artifact
- it lives with the operator alone, for the entire lifetime of every
recovery kit this item ever produces. `ciphertext`'s own schema pattern
can only check its base64 alphabet, which any short plaintext string
(a leaked password, say) trivially satisfies too - `verifyRecoveryKit()`
is the real check: it decodes `ciphertext`, confirms the decoded bytes
actually begin with age's own real binary-format magic header
(`age-encryption.org/v1\n`), recomputes `ciphertextDigest` from those
same decoded bytes, and recomputes `ageRecipientFingerprint` from
`ageRecipient`. A document that is schema-valid but fails
`verifyRecoveryKit()` is never a real recovery kit, only a decoy shaped
like one. `verifyRecoveryKit()` only ever checks a kit's own INTERNAL
consistency, never whether it actually belongs to the plan using it - a
third review round found nothing bound a kit's own `installationId`/
`createdForGeneration` to the plan/manifest referencing it, nor its own
digest to the `recoveryKitDigest` a plan/manifest declares.
`validateBackupBundle()`/`validateRestoreBundle()` now accept an
optional `kit` and check exactly that.

**Backup Flow - the fixed, typed operation whitelist
`backup-plan-v1.schema.json` encodes.** Planning-time (never dispatched
as operations; refused before the mutex is ever requested): verify the
signed platform release and the signed `backup-tool-lock`; read target
state and require no drift, no corruption, and no other operation
already in progress; resolve the currently-applied `backup-policy-v1`
and allocate this installation's next `backupSequence`; build a
deterministic plan bound to the target's host key, `installationId`,
generation, release-lock digest, the exact consistency set (every
enabled unit's volumes, per `backup-inventory.json`, **plus** every
`retainedServices` volume - disabled-but-retained volumes are explicitly
in scope, unlike a plain apply), and every configured destination;
require explicit approval for a manual run (a scheduled run uses the
already-approved backup policy instead). Dispatched, in order, under the
mutex: `maintenance.enter` (marker written, public traffic closed);
`service.stop` (dependents-first, reusing `plan-v2`'s own action name
and ordering convention); a fresh, under-lock re-check of committed
state before anything further; `staging.build` (the allowlisted tree:
generated config, a sanitized manifest, the signed release lock, the
recovery kit, the backup manifest, and every unit's own consistency-set
volume); `snapshot.create`, once per configured destination, sharing one
`backupId` across all of them, each independently metadata-verified;
`retention.apply`, once per configured destination (a local repository
and an S3 repository each carry entirely independent retention state;
this is never one run-wide step), namespaced by `installationId` so one
installation's retention can never touch another's snapshots in a
shared repository; in a `finally` regardless of outcome so far:
`service.start` (dependencies-first, gateway last), `readiness.wait`,
`maintenance.exit`; finally `evidence.write` (atomic, never touching
`current.json` or the generation). All configured destinations are
required for overall success - a partial result (some destinations
succeeded, at least one did not) is recorded faithfully in evidence
(including, per destination, whether its own `retention.apply` actually
completed - independent of that destination's own snapshot outcome) but
the operation itself still returns failure, never a silent partial
success. `succeeded` additionally requires the `finally` block itself to
have genuinely completed (`backup-evidence-v1`'s own required
`readinessConfirmedAt`, non-null only on success) - every destination's
own snapshot succeeding is not the same claim as the platform actually
having been left healthy; a broken `service.start`/`readiness.wait`/
`maintenance.exit` must never hide behind a claimed backup success. And
because JSON Schema alone cannot check that `operations` actually
contains the complete, correctly-ordered, correctly-counted flow above
(the required count of `snapshot.create`/`retention.apply` legs depends
on `destinations`' own length, which no schema in this repo can
reference from a sibling array without a `$data` extension - none are
used anywhere in this repo), completeness and the FULL ordering chain
(every destination's own `retention.apply` strictly after that SAME
destination's own `snapshot.create` - not merely after snapshots/
retentions in aggregate; `service.start` before `readiness.wait` before
`maintenance.exit`; `service.stop` and `service.start` naming the exact
same set of units) are checked separately by `scripts/backup-flow.mjs`'s
own pure `validateBackupPlanOperations()`, exercised by this item's own
contract tests - a blocked plan (`executable: false`) is never analyzed
this way, since it never claims to have a real flow at all. This
function, and its schema-level duplicate check on `plan.destinations`/
`plan.consistencySet`, do NOT prove the plan's own stop/start unit set
or consistency set matches the platform's real, full topology - this
document carries no independent source-topology projection to check
that against, and adding one is out of this PR's own scope (see
Consequences).

**Restore Flow - the fixed, typed operation whitelist
`restore-plan-v1.schema.json` encodes, against a *second*, clean
target. Approval pins WHAT will be restored, not merely WHICH backup.**
Planning-time: obtain the recovery kit, the recovery age identity, the
destination, and the `backupId`; verify the restic snapshot, the backup
manifest embedded in it (confirming the manifest's own
`recoveryKitDigest` matches the kit actually obtained, before trusting
anything else in the snapshot - a fourth review round found this exact
check, despite being named right here since this ADR's own first draft,
had never actually been implemented in `validateRestoreBundle()`; it now
is), and the signed historical release lock
it names (a release lock from `v0.2.1`, say, restored onto a target
running today's tooling, still verifies against exactly the signature
identity it was originally signed with); pin the new target's own
freshly-observed SSH host key and confirm it is genuinely clean via a
real observation, structurally recorded (`cleanObservation`: containers/
volumes/networks/units/generatedArtifacts, every list required empty -
`target.installationId: null` and `target.baselineGeneration: 0` alone
were a claim a caller could satisfy without any real observation behind
it; `cleanObservation` is what an actual `target-verify-clean.mjs` a
later PR writes populates, re-checked once more under the mutex at
`target.verify-clean` dispatch time, exactly like the host key); build
and require explicit approval of a restore plan naming the source
`installationId`/`generation`/`release` distinctly from the new target's
own identity, and pinning the exact `snapshotId` `snapshot.verify`
resolved and the exact `manifestDigest` of the manifest embedded in it -
without both pinned at approval time, an operator approving a plan by
`backupId`+`destinationName` alone would be approving whatever the
repository happens to contain at EXECUTION time, not what they actually
reviewed; every other approved-then-dispatched document in this repo
already pins its own exact content via `planId`, and a restic repository
is not otherwise pinned that way. Dispatched under the mutex: `runner.install` (the signed
runner itself, from the `backup-tool-lock`); `target.verify-clean`
(re-checked once more under the mutex, not trusted from planning time
alone); `snapshot.verify`; `network.create` and `volume.create`
(operation-owned networks and volumes only - a restore never adopts or
overwrites a resource it didn't itself just create; a clean target has
none of Hof's usual long-lived, externally-provisioned network
infrastructure yet, unlike a plain apply, so restore is the one flow
that must actually create it - each network named by its own PHYSICAL
name, `render-topology.mjs`'s own `physicalNetworkName()` output, e.g.
`"hof-hof"`, matching `state-v1.schema.json`'s own committed `networks`
and `plan-v2`'s own `desired.networks`/`network.ensure` exactly, never
the bare logical Compose key; a third review round found the first two
drafts of this document used the logical key instead, which would have
made `restore-plan-v1` the one inconsistent network-naming contract in
the whole repo. Each network entry also carries its own `internal` flag
- `plan.mjs`'s own `network.ensure` sets it for exactly one network,
`hof-wachter-internal`, and restore must recreate that same property,
not merely the network's bare existence. A fourth review round found the
third round's own fix was still prose-only - `{name: "hof", internal:
false}` and `{name: "hof-wachter-internal", internal: false}` were both
still schema-valid. `restore-plan-v1.schema.json`'s own `network` $def
now really enforces both: `name` must match `^hof-[a-z][a-z0-9.-]{0,75}$`
(rejecting the bare logical key outright), and `internal` is `const true`
exactly when `name` is `"hof-wachter-internal"`, `const false` for every
other name) and `data.restore` for the full
consistency set; `manifest.verify` and `database.integrity-check`
against the actually-restored files, before any container using them
ever starts; `checkpoint.data-restored` (a durable, resumable marker -
see Failure semantics); `config.restore` and `secret.materialize`
(restored generated config and encrypted secrets; runtime secret files
are materialized as their own distinct step, never conflated with
restoring the encrypted store itself); `state.restore` (the source
`installationId` and generation restored verbatim, **never
incremented** - this is not a new applied change, it is the same
installation's history continuing on new hardware; restore provenance -
that this generation's data arrived via a restore, from which backup,
onto which new host - is recorded separately from `current.json`, never
folded into the generation history itself); `service.start`
(dependencies-first, gateway last), `readiness.wait`; finally
`evidence.write`. Completeness and the FULL ordering chain (`target.
verify-clean` before `snapshot.verify` before any `network.create` -
nothing is provisioned before the target and the snapshot are both
confirmed genuine; network before volume; volume before its own
`data.restore`; every `data.restore` before verification; verification
before the sole privileged checkpoint; config/secret/state restoration
before `service.start`; `service.start` before `readiness.wait`) are
checked by `scripts/backup-flow.mjs`'s own pure
`validateRestorePlanOperations()`, the restore-side sibling of the
backup one above - a third review round found the first two drafts of
this same function checked only a handful of these relationships (data.
restore-before-checkpoint, config/secret/state-after-checkpoint),
silently accepting volume.create after its own data.restore, network.
create after volume.create, or verification after the checkpoint it is
supposed to gate; a fourth round found it still let a restore create
networks/volumes or touch data before the target's own cleanliness or
the snapshot's own genuineness were ever confirmed. Both flow validators
also now detect a SECOND, uniquely-IDed operation quietly targeting a
destination/resource/network already covered - the earlier Map-based
cardinality check (one entry per key) silently let a second write
overwrite the first's own index, so the count-of-keys check alone never
actually caught the duplicate.

**Failure semantics and resumability.** All configured destinations are
required for a backup's own overall success, exactly as stated above.
Every checkpoint the two flows name above is a real crash/resume
boundary: backup may crash after `service.stop`, after `snapshot.create`
for some but not all destinations, during one destination's own
`retention.apply` while another's already completed, or before
`evidence.write` is durably recorded - a resumed or retried backup must
be safe to re-run from any of these without double-stopping an
already-stopped unit, creating a second inconsistent snapshot under the
same `backupId`, or applying retention twice for the same destination.
A backup failure, however it happens, must still guarantee the `finally`
block above actually runs - units restarted, maintenance mode cleared,
readiness confirmed - never leaving a target stuck in maintenance mode
because the failure happened before the `finally`. Restore has exactly
one privileged checkpoint: `checkpoint.data-restored`. Before it,
`--resume` may delete only the volumes *this* restore operation itself
created and start materialization over from nothing; after it, restored
data is never rewritten or re-fetched again - `--resume` continues only
with provisioning, `service.start`, and `readiness.wait`, never touching
data a second time. `operation-event-v2` is this resumability's own
evidence trail; which specific step/attempt a resumed run may safely
retry, skip, or must refuse is `operationKind`-specific journal logic a
later PR's executor implements - this ADR fixes the checkpoints and the
event shape, not the reconciliation algorithm itself.

**`backup.schedule` is interpreted in the target's own local time; the
local destination is operator-pre-mounted.** Hof never mounts an
arbitrary filesystem on the target's behalf - a `local` destination's
`path` is assumed already mounted and writable by the operator's own
setup, exactly as it already was for `services-v1alpha1.schema.json`'s
existing `backup.destinations[].type: "local"`.

## Consequences

- Eleven new or revised schemas:
  - New: `backup-plan-v1`, `restore-plan-v1`, `backup-manifest-v1`
    (written into the snapshot itself), `backup-evidence-v1`,
    `restore-evidence-v1`, `backup-tool-lock-v1` (independently signed,
    under its own `backup-tool-vX.Y.Z` tag namespace, now also declaring
    a required `compatibility` object), `backup-policy-v1` (the
    approved, applied policy a scheduled run binds to - `policyId`
    excludes its own freshness metadata), `recovery-kit-v1` (the
    encrypted envelope itself, `ciphertext` genuinely verified only by
    `scripts/backup-flow.mjs`'s own `verifyRecoveryKit()`), and
    `operation-event-v2` (backup/restore's own resumability contract -
    not merely a kind-tagged copy of v1, and scoped to those two kinds
    only). None cross-reference another schema file by `$id` (this
    repo's own convention; shared shapes like `targetBinding`,
    `identifier`, `destinationName`, and the `local`/`s3` destination
    split are each copied independently) - `destinationName` in
    particular is now its own, narrower $def (services-v1alpha1's exact
    `name` pattern) everywhere a real destination/secretRef name
    appears, distinct from the broader `identifier` pattern volumes/
    units/services use, and every `local`/`s3` destination's own
    `endpoint` now rejects an embedded credential via userinfo, query
    string, or fragment alike.
  - Revised: `operation-lock-v2`, `operation-journal-v2` (both already
    existed from an earlier draft of this same PR; this revision adds
    the SSH/local `hostKeySha256` conditional their own prose already
    claimed but never enforced, scopes `operationKind` to
    `["backup", "restore"]` only - removing `apply` entirely, closing an
    unresolved contradiction a second review round found - and, for
    `operation-journal-v2`, makes `plan.apiVersion` and `inputDigests`'
    own shape actually conditional on `operationKind` instead of always
    requiring apply's own five-digest shape regardless of kind).
- A real signed artifact, `backup-tool-lock-v1`, that this item's later
  PRs must build a new CI workflow to produce, exactly as
  `execution-environment.yml`/`release.yml` already do for the Execution
  Environment and the platform release.
- `operation-lock-v1`/`operation-journal-v1`/`operation-event-v1` remain
  apply's own family, permanently and exclusively - never superseded,
  never touched by this item, and never paired with any v2 document.
  `operation-lock-v2`/`operation-journal-v2`/`operation-event-v2` are
  backup/restore's own family, exclusively - the two families never mix,
  and a pre-existing on-target `lock.json`/journal document with no
  `operationKind` field is still read and safely resumed as an implicit
  apply v1 document by whatever executor PR follows this one.
- `plan-v2.schema.json`'s own `backup.create` action, and the two
  bootstrap/applied action whitelists, are completely unchanged by this
  item - dead code remains dead code, on purpose.
- `scripts/digest.mjs` gains a shared, exported `canonicalize()` (moved
  out of `plan-v2.mjs`, which now imports it - `computePlanId()`'s own
  behavior is unchanged, covered by its existing regression tests). Two
  new pure, no-I/O modules:
  - `scripts/backup-ids.mjs`: `canonicalContentId` (now accepting one or
    several excluded fields), `canonicalDocumentDigest` (a whole-document
    digest for `backup-manifest-v1`/`recovery-kit-v1`, which carry no
    self-referential id field to strip), `computeBackupId`,
    `exactSetEquals`, `consistencySetEntryKey`, `hasDuplicates`.
  - `scripts/backup-flow.mjs`: `validateBackupPlanOperations`/
    `validateRestorePlanOperations` (flow completeness, per-destination/
    per-network/per-volume cardinality, the FULL predecessor-ordering
    chain each flow's own Decision text above now spells out, and a
    blocked-plan (`executable: false`) short-circuit - none of this is
    checkable by schema alone without a `$data` extension),
    `validateBackupBundle`/`validateRestoreBundle` (cross-document id/
    digest/content bindings across policy/plan/manifest/evidence/kit,
    and now optionally lock/journal/events too - including that a
    `succeeded` backup's evidence names every configured destination
    exactly, that a plan bound to an approved policy actually uses that
    policy's own destinations/retention verbatim, that a restore plan's
    own `source` claim actually matches the manifest that is the real
    proof of what is being restored, and that a recovery kit is bound to
    the installation/generation actually using it), `verifyRecoveryKit`
    (ciphertext round-trip, age magic header, digest/fingerprint
    recomputation), and `validateRestoreCommittedGeneration` (checks
    `operation-journal-v2`'s own now-status-independent `committedGeneration`
    for restore against whether a real `state.restore` succeeded event
    exists - the one thing that formula's own correctness actually
    depends on). This item's own contract tests build every "happy path"
    fixture through these same functions rather than an arbitrary
    placeholder value, so a passing positive test is real evidence the
    fixture is internally coherent, not merely that each field's own
    shape is individually valid.
- `restore-plan-v1` now pins `snapshotId` and `manifestDigest` at
  approval time (not merely `backupId`+`destinationName`, which a
  repository's own contents are not otherwise bound to), and records a
  structural `cleanObservation` (five categories, all required empty) as
  proof the new target was actually observed clean, not merely claimed
  to be via `installationId: null`/`baselineGeneration: 0` alone.
  `backup-evidence-v1` now requires `readinessConfirmedAt`, non-null
  only when `status: succeeded` - a snapshot succeeding at every
  destination is not the same claim as the platform's own `finally`
  block (`service.start`/`readiness.wait`/`maintenance.exit`) actually
  completing; `restore-evidence-v1` now forbids a non-null
  `readinessConfirmedAt` on a `failed` restore, since `readiness.wait` is
  the step immediately before `evidence.write` - nothing legitimately
  fails an already-readiness-confirmed restore. Both evidence schemas
  now require `abandoned` (see the Decision section above).
- A fifth review round closed four more real gaps: `validateBackupBundle()`
  now unconditionally requires `plan.target.installationId`/
  `baselineGeneration` to match `plan.installationId`/`generation` (a
  plan's own SSH connection binding and its own top-level declared
  installation/generation could otherwise silently diverge, policy or no
  policy); both flow validators now catch a SYMMETRIC duplicate
  `service.stop`+`service.start` pair for the same unit (the set-equality
  check alone treats two matching duplicates as perfectly coherent, since
  both arrays hold the identical multiset), and `validateRestorePlanOperations()`
  catches a duplicate `service.start` the same way; `restore-plan-v1`'s
  own `network` `name` is now the literal closed `enum: ["hof-hof",
  "hof-wachter-internal"]` - the two, and only two, physical networks
  `render-topology.mjs` ever produces - not merely a `"hof-"` prefix
  pattern, which still accepted any other unproducible `"hof-something"`.
- What this item's own semantic validators deliberately still do NOT
  prove: that a plan's own `service.stop`/`service.start` unit set, or
  its own `consistencySet`, actually matches the platform's real, full
  topology (every enabled-plus-retained volume, the exact
  dependency-ordered service set) - only that a plan's OWN internal
  halves agree with each other (stop/start naming the same units; no
  duplicate destination/volume/network within one document). Proving
  real completeness would need a source-topology/inventory projection
  this item's own contracts do not currently carry, and building one is
  out of scope for a schema-only PR - a later PR, when a real executor
  exists to compare against, is the natural place to close this
  specific gap, not this one.
- No executor, target-side runner, Ansible role, systemd unit, CLI
  surface (`hofctl backup`/`hofctl restore`), or CI workflow exists yet.
  The `backupSequence` allocation-and-recheck-under-mutex logic
  `computeBackupId` depends on is explicitly executor work, not fixed
  here - this ADR fixes only that allocation happens once per new
  operationId, never once per `--resume` attempt within one. The
  contracts and schemas introduced here, and the contract tests covering
  them, are this PR's entire scope - every later PR in this item's own
  sequence builds on top of them, never revisits this ADR's own Decision
  in place (only appends dated Errata, exactly like ADRs 0004 and 0005
  already do).
