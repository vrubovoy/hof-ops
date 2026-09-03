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

## Errata (2026-09-01, item 9 review)

A review after item 9's own PRs (#48-56) landed found eleven gaps in the
implementation of the decisions above - two `Critical`, three `High`,
five `Medium`, one `Low`. All corrected without revisiting the design.

- **Generation-snapshot publication was not crash-safe, and its retry
  path was broken (Critical).** The `state` role wrote the three
  `generations/NNNNNN/` files one after another, and treated the mere
  presence of `state.json` as a complete snapshot - a crash in between
  left a "poisoned" generation directory. The retry comparison also read
  the on-target snapshot with a control-node `lookup('file')` of a path
  that only exists on the target, so every retry crashed. Fixed: the
  snapshot is written into a unique, operation-scoped staging directory,
  verified complete and non-empty, then published with a single atomic
  `rename(2)` (`mv -T ... creates:`); the retry comparison reads the
  existing snapshot target-side with `slurp`, and an existing-but-
  incomplete generation directory is refused, never completed in place.
- **A state commit interrupted between its two pointer writes wedged
  every future plan and could not be resumed (Critical).** `topology.json`
  is written before `current.json`; a crash in between leaves
  `topology.json` one generation ahead. `resolveBaseline()` used to treat
  the resulting digest mismatch as indistinguishable-from-corruption and
  refuse forever, and `apply --resume` had no way to finish the commit.
  Fixed: `resolveBaseline()` recognises "`topology.json` exactly one
  generation ahead of `current.json`" (the generation is carried in
  `topology.json`'s own `hof.generation` ownership labels) as a
  recoverable interrupted commit and points the operator at `apply
  --resume`; `apply --resume` re-dispatches the idempotent `state.commit`
  (the immutable generation snapshot is already published in full, so
  only the pointer writes are redone) to finish it. A mismatch that is
  *not* a one-generation skew is still the hard corruption stop.
- **Two concurrent `apply --resume` processes could each dispatch the
  same step (High).** The durable `lock.json` is a persistence record,
  not a liveness lease - both resumes read the same lock and events and
  both proceeded. Fixed: a process-lifetime execution lease - a
  long-lived SSH (or local) child holding an exclusive `flock` on
  `/var/lib/hof/state/exec.lease` for exactly as long as the `apply`
  process lives, released by the kernel the instant it (or its SSH
  connection) dies. A second concurrent `apply`/`resume` is refused
  without touching the durable lock the first one legitimately holds.
- **Wächter's units were guaranteed to start in the wrong order (High).**
  The renderer emitted the API unit before its agent, so the planner
  started (and waited on) the API first - whose `/ready` health endpoint
  cannot report healthy until its sampler can reach the agent, hanging
  `readiness.wait` to its full budget and failing every enable/repair of
  Wächter. Fixed: `render-topology.mjs` now emits `wachter-agent` before
  `wachter`, so the planner starts and readies the agent first (matching
  the API's own `depends_on`).
- **A retained service re-enabled with a mismatched schema version was
  treated as a first initialization (High).** The planner only blocked a
  schema change for the `enabled -> enabled` case; a `retained -> enabled`
  transition whose recorded schema disagreed with desired slipped through
  as an executable `database.migrate` with reason "initialize database",
  which would migrate real retained data as if it were new. Fixed:
  `computeUpgradeBlockers()` now also blocks a retained re-enable whose
  recorded schema version does not match desired - out of item 9's scope,
  items 10-11.
- **An applied change could silently overwrite every ordinary secret
  outside the approved plan (High).** Any applied `anyChange` emitted a
  `secret.ensure` that delivered the full current store for every
  deployment-wide required secret - so e.g. a backup-schedule edit could
  simultaneously replace HMAC keys with no coordinated restart. Fixed:
  `secret.ensure` now carries an explicit, sorted `secrets` list - every
  required secret on bootstrap, but on an applied plan only those
  consumed by units the plan actually starts/restarts/migrates - and
  `apply` delivers exactly that subset. A required secret this plan never
  touches is left exactly as it is on the target.
- **A genuine no-op still required a decryptable secrets store (Medium).**
  The store was decrypted before the target was inspected or a plan
  computed, so an unchanged deployment with a momentarily-unavailable
  SOPS identity failed hard even though it would deliver nothing. Fixed:
  the "no `--secrets-store` given at all" check stays eager (a plain
  operator mistake), but the decryption itself is deferred past the
  applied no-op return.
- **Recovery confirmed only a generation snapshot's `state.json`
  (Medium).** `topology.json` and `release-lock.json` in the same
  immutable directory were never checked, so a corrupt or missing one
  could be accepted as a complete record. Fixed: every recovery path that
  trusts a generation snapshot now confirms all three files and compares
  the snapshot's own `topology.json` against the expected rendered
  topology.
- **Post-lock error paths swallowed lock-release failures (Medium).**
  `await m.releaseLock(...).catch(() => {})` discarded both exceptions
  and a clean `{ released: false }`, so a result could report only the
  stale-plan/TLS/render error while the target stayed locked. Fixed:
  those paths now fold a failed release into the returned diagnostics.
- **The `service` role never asserted the installation id it scopes
  stop/remove discovery on (Medium).** A regression that let
  `hof_installation_id` through as `null` would make discovery match
  nothing and the role would commit state without removing the intended
  container. Fixed: `stop`/`remove` now assert `hof_installation_id is
  not none`.
- **`retainedServices[*].retainedAt` was promised by the schema but never
  written (Low).** Fixed: `apply` fills it in at real commit time -
  carried forward unchanged while a service stays retained, set fresh the
  commit that first disables it - and resume verification treats it (like
  `appliedAt`) as a volatile field excluded from equality checks.

Every other decision above is unchanged. A new EE/platform patch release
and a fresh real-acceptance run (including crash/retry and negative
scoping cases) still need to accompany these fixes before item 10.

## Errata (2026-09-02, item 9 review round 2)

A NO-GO review of the round-1 fixes above (still uncommitted, still only
in the local worktree) found the round's own new acceptance scenarios
could not reach the behavior they claimed to exercise, and - far more
seriously - that the round-1 execution lease (finding 3 above) was
itself fail-**open** after acquisition: a loss discovered once the lease
was already held was silently discarded, so a genuine mid-run loss (the
remote heartbeat loop timing out, the SSH connection itself dying) left
this process free to keep dispatching real mutations with no live lease
behind them at all - exactly the double-dispatch risk finding 3 exists
to prevent. Corrected, again without revisiting the underlying design:

- **Execution lease fail-open after acquisition (Critical).**
  `acquireExecutionLease()`'s own returned lease now exposes
  `isLost()`/`lostReason()`/`onLost()` - a loss discovered after
  `HOF_LEASE_HELD` (the same child's own later `exit`/`error`) is
  recorded and broadcast, never silently dropped by the guard meant only
  to stop the acquisition promise itself settling twice. `apply.mjs`'s
  own dispatch loop checks `isLost()` at the top of every iteration and
  refuses to start a new operation once it's true - fail-closed for
  every step not yet dispatched. This still stops short of true
  distributed fencing (a monotonic token every target-side mutation
  independently checks, the textbook answer to a lease that expires
  while its holder is merely paused - GC, `SIGSTOP`, a scheduler delay -
  rather than actually gone): that would mean every one of the ten
  Ansible roles becoming lease-aware itself, out of this fix's own
  scope, and is documented as such at the source.
- **Lease acquisition had no timeout, and a `child.stdin` write error
  was unhandled (High).** A hung connection (no `HOF_LEASE_HELD`/`BUSY`,
  no exit, no error) left `acquireExecutionLease()` awaiting forever;
  fixed with a bounded, overridable timeout. An EPIPE on the heartbeat's
  own `child.stdin.write(".")` surfaces asynchronously as an `'error'`
  event on the stream, which a `try`/`catch` around `.write()` itself
  cannot catch - fixed with a real `child.stdin.on('error', ...)`
  handler.
- **`mkdtemp()` ran before the lease's own protecting `finally`
  (Medium).** A failure there (rare, but real: disk full, a permissions
  problem) skipped that `finally` entirely and leaked the lease helper
  for the rest of this process's own lifetime. Fixed: it now runs inside
  the same `try` the lease's release lives in.
- **The immutable per-generation snapshot's own content comparison was
  still incomplete on both sides (High).** The `state` role compared
  only `state.json`'s content against an existing snapshot, never
  `topology.json`'s or `release-lock.json`'s (both were only checked for
  presence) - fixed to compare all three. `apply.mjs`'s own
  `readGenerationSnapshotArtifacts()` had the same gap one level up:
  `release-lock.json`'s real value was read and then discarded, only its
  `status` ever inspected - the three call sites were consolidated into
  one function that reads AND compares all three artifacts, so no future
  call site can independently forget one again.
- **Several of the round's own new acceptance scenarios were logically
  unreachable (Critical).** `runApply()`'s eager "was a secrets store
  even given" gate ran before `readSecretsStore`'s own test seam ever
  had a chance to answer, refusing several new scenarios with
  `reason: "secrets"` before they ever reached what they meant to test -
  fixed by passing `secretsStorePath` alongside every `readSecretsStore`
  override. One scenario computed its own journaled `inputDigests`
  *before* writing the manifest edit that journal was supposed to
  represent, guaranteeing resume's own "input changed since journaled"
  gate would refuse it - fixed by reading the digests after the edit.
  The "incomplete generation directory" scenario mounted a `current.json`
  whose own `generation` field didn't match the generation being
  dispatched, tripping the role's *earlier* cross-check assertion before
  ever reaching the incomplete-directory one it meant to exercise -
  fixed by making the mounted document's generation agree with the
  dispatch. The secret-scoping assertion expected exactly the plan's own
  scoped secret set, missing that this fixture's own supplied-TLS mode
  makes `apply.mjs` always deliver two further fixed secret names
  alongside it - fixed to expect both together, and to check the plan's
  own scoping (TLS names excluded) separately from what's actually
  delivered (TLS names included).
- **A Wächter container-name assertion could not tell the API from its
  agent (Medium).** `/wachter\b/` also matches inside `"wachter-agent"`
  (the word boundary lands on the hyphen) - fixed to check exact
  container names.
- **The "crash/retry" scenario didn't cover the one thing its own name
  promised (Medium).** Retry-of-an-already-complete-snapshot and an
  incomplete-directory refusal are both real and now correctly reached,
  but neither is an orphan *staging*-directory left behind by a publish
  interrupted before its own atomic rename - the role's own explicit
  cleanup task for exactly that. Added as a third case (a real orphan
  staging directory, constructed directly, that a real subsequent
  dispatch must remove and supersede) and the scenario's own name/
  comments now say plainly that none of this is a literal timed process
  kill (a real, hands-on attempt at exactly that during THIS round's own
  execution-lease work is what found the fail-open bug above - not
  something a scripted kill race can be trusted to reproduce reliably,
  including in CI).
- **The two acceptance-only helpers exported to avoid duplicating
  `dispatchOperation()` still left it reconstructed by hand for
  `state.commit` specifically (Medium).** `buildExtraVars()` and a newly
  extracted `buildDockerRunArgs()` are now both exported and used
  directly - `dispatchOperation()` itself now calls the same
  `buildDockerRunArgs()`. This surfaced a further real bug the
  duplication had already caused: the hand-built version was passing the
  whole apply RUN's own UUID as `hof_operation_id` (which the state
  role's own staging-directory name embeds), where a real dispatch
  always sends the plan-v2 STEP's own id instead.
- Five new unit tests were added directly against `acquireExecutionLease()`
  (post-acquisition loss via `exit`, loss via a child-level `error`
  event, a voluntary `release()` never mistaken for a loss, a `stdin`
  error event handled without crashing, and a bounded acquisition
  timeout) and two against `apply.mjs`'s own dispatch loop and lock/lease
  lifecycle (a lease lost mid-run stopping the loop fail-closed before
  the next operation, and the lease being released even when something
  fails immediately after acquisition, before `mkdtemp()`'s own real
  filesystem behavior can be faked directly).

Still not run for real: `pnpm test:apply-ssh` itself (this environment's
own standing decision against running its `--privileged` fixture
locally - see that file's own top comment - still applies; a real,
hands-on, non-privileged sudo-sshd fixture built just for this round IS
what found and fixed the execution-lease bugs above, live, several times
over, before landing here). First real CI run on this PR remains the
actual acceptance gate, exactly as this ADR's own round-1 errata already
said.

## Errata (2026-09-03, item 9 review round 3)

A further NO-GO review of the round-2 fixes above (still uncommitted)
found the round-2 execution lease, while now fail-closed *after*
acquisition, was acquired too **late**: two independent
`hofctl apply --resume` processes could both read and decide off the
exact same resume-state (or a fresh process could durably create a
lock+journal) before either one's own lease acquisition ever ran, plus
several narrower races in the lease's own acquire/lose lifecycle and one
non-determinism bug in what a real commit actually writes. Corrected,
again without revisiting the underlying design:

- **The execution lease was acquired after resume's own
  decision-affecting reads, and after fresh's own lock+journal creation
  (Critical, two findings).** `acquireExecutionLease()` is now called
  once, unconditionally, immediately after `mutateConn` is built - before
  `--resume`'s own `readLock`/`readJournal`/event-history validation, and
  before the fresh path's `computeLivePlanV2`/`acquireLockAndJournal`. A
  losing process now finds out before it has read or touched anything on
  the target at all, so its own failure path never has a lock to release
  in the first place - closing a real, independently reachable
  split-brain window where a fresh loser could already have durably
  created a lock+journal by the time its own (late) lease-failure handler
  unconditionally released it, racing a legitimate concurrent resumer
  that might already be relying on that very lock. Implemented as a
  nested `runUnderLease()` closure wrapping the entire pre-existing
  resume/fresh/dispatch body unchanged (it captures every enclosing
  binding automatically), called from a single outer `try`/`finally` that
  now owns lease release - letting every one of that body's own many
  `return` statements stay exactly as they were. Accepted trade-off: a
  would-be no-op fresh apply now also briefly acquires and releases the
  lease, which it previously never touched at all.
- **`isLost()` was only checked once per dispatch-loop iteration, not
  immediately before each of that iteration's own dispatch calls
  (High).** Several real `await`s (reading the immutable generation
  snapshot, `current.json`, `topology.json`; appending the `started`
  event) sit between the top-of-loop check and either of an iteration's
  two possible `dispatchOperation()` calls (the `state.commit` recovery
  re-dispatch, and the main per-operation dispatch) - each one a real
  window for the lease to be lost mid-iteration. `isLost()` is now
  re-checked immediately before both.
- **A timeout/late-success race inside `acquireExecutionLease()`'s own
  acquisition promise (High).** The timeout path used to start its own
  async `release()` *before* marking the promise settled, leaving a real
  window during which an already-in-flight `HOF_LEASE_HELD` could still
  win the race and resolve successfully with a lease this same call had
  already begun releasing. Fixed with a synchronous `claim()` gate that
  closes (and clears the timeout) the instant any one of the four
  settling paths - timeout, `HOF_LEASE_HELD`, `HOF_LEASE_BUSY`, child
  `exit`/`error` - starts running, decoupled from the asynchronous
  `release()`/`reject`/`resolve` work that may follow it.
- **A `stdin` write error only ever set a local flag, never called
  `markLost()` directly (High).** The separate child `exit` event was
  relied on to eventually report the loss, a real gap whenever that
  event's own delivery lagged behind the stream error that had already,
  independently, proven the lease gone. `markLost()` is now called
  directly from the `stdin` `'error'` handler itself (moved above it in
  the function so it's available to call); its own idempotency guard
  makes a later, likely-redundant call from `exit` harmless.
- **A newly-retained service's own `retainedAt` was non-deterministic
  across retries of the same operation (High).**
  `computeExpectedCommittedState()` filled a first-time `retainedAt` from
  `now.toISOString()` - a fresh value on every call - while
  `ansible/roles/state/tasks/main.yml`'s own already-published-generation
  comparison excludes `appliedAt` only. A crash between publishing the
  immutable generation snapshot and writing the two mutable pointer files
  meant the retry's own re-render of `current.json` got a brand new
  `retainedAt`, which the target-side assert then correctly (but
  wrongly, from the operator's perspective) refused as if the generation
  had been reused for two different commits. Fixed at the root: the
  function now takes a required `operationStartedAt` (every call site
  passes the journal's own `startedAt` - fixed once at journal creation,
  read back unchanged by every later `--resume` of the same operation),
  making its own output byte-for-byte reproducible across retries with no
  Ansible-side change needed at all. A caller that omits the new
  parameter now throws immediately, rather than silently spreading
  `retainedAt: undefined` into a schema-checked field.
- **The immutable generation snapshot's own `state.json` was never
  schema-checked before being trusted as a recovery oracle (High).**
  Unlike the mutable `current.json` path (already gated by
  `validateStateV1()` everywhere it's read for this purpose), a
  hand-tampered or corrupted-but-still-valid-JSON snapshot `state.json`
  was compared field-by-field as-is. `readGenerationSnapshotArtifacts()`
  now validates it first, reporting a schema failure as its own distinct,
  named complaint rather than folding it into a generic content-mismatch
  message.
- **A `workDir` cleanup failure could skip lease release (Medium).** The
  lease used to be released as the second of two sequential statements in
  one `finally` block, `await rm(workDir, ...)` first - a real failure
  removing it (disk full, a permissions problem; `force: true` swallows
  `ENOENT` but not those) skipped lease release entirely. Resolved as a
  direct consequence of the findings-1/2 restructuring above: lease
  release now lives in the single outer `finally` wrapping the entire
  `runUnderLease()` closure, which runs on any exception propagating out
  of it, from wherever it originated.
- Four new regression tests were added directly against this lifecycle:
  a fresh apply refused by a busy lease that never even calls
  `acquireLockAndJournal`, a resume refused by a busy lease that never
  even calls `readLock`/`readJournal`, a lease lost strictly *within* the
  first loop iteration (between its own top check and its own dispatch
  call) still stopping that dispatch, and the succeeded-fast-path
  refusing a snapshot whose `state.json` is present and parses but fails
  its own schema. `target-mutate.test.mjs`'s own fake child process was
  also fixed: its `stdin.end()` used to fire a synthetic `exit` event
  fully synchronously, which could reach `release()`'s own internal
  `exit` listener before that listener was even registered (a testing
  artifact the findings-4 fix exposed, not a production bug) - now fired
  on a microtask, close enough to keep every test fast while never
  outrunning a listener registered the line immediately after.

Still not run for real: `pnpm test:apply-ssh` itself, for the same
standing reason as every prior round. First real CI run on this PR
remains the actual acceptance gate.

## Errata (2026-09-03, item 9 review round 4)

A further NO-GO review of the round-3 fixes above (still uncommitted)
found the fixed-lease-ordering and re-checked-`isLost()` work still left
two fail-open windows: a stdin error arriving *before* acquisition was
confirmed could still let acquisition succeed with an already-dead lease,
and `runApply()` never checked `isLost()` immediately after acquiring it
- only deep inside the dispatch loop - so a lease that somehow resolved
already lost was still used to read/create a lock before anything caught
it; separately, several journal-writing `appendEvent()` calls were only
guarded by the checks immediately before `dispatchOperation()`, not
before the append itself. Corrected, again without revisiting the
underlying design:

- **A stdin error before acquisition confirmed could still resolve
  successfully (High, release blocker).** The stdin `'error'` handler
  only called `markLost()` - it never claimed or rejected the
  still-open acquisition promise, so a `HOF_LEASE_HELD` chunk already
  buffered/in flight could arrive right after, win `claim()` in the
  stdout handler (nothing had claimed it yet), and resolve successfully
  with a lease whose very first `isLost()` check already reports true.
  Fixed by moving `claim()`/`settled`/the acquisition promise's own
  `resolve`/`reject` above the stdin handler (previously only available
  inside the later `new Promise(...)` executor) so that handler can now
  win the same race the child's own `exit`/`error` handlers already do:
  claim, run the same `release()` teardown every other pre-acquisition
  failure path uses, then reject.
- **`runApply()` never checked `isLost()` immediately after acquiring
  the lease (High, release blocker).** The first check was buried
  several steps later, inside the dispatch loop - a lease that resolved
  already lost (defensively still checked for, even though
  `acquireExecutionLease()` itself is now fixed to never produce one)
  would otherwise run this process's entire resume-read/fresh-lock-
  creation/succeeded-fast-path lifecycle first. Fixed at both layers:
  `acquireExecutionLease()` itself now checks its own result after
  `await`ing the acquisition promise and throws rather than ever
  returning an already-lost lease; `runApply()` checks again,
  defensively, immediately after acquisition succeeds, for any mutate
  implementation, real or faked.
- **Several `appendEvent()` calls were guarded only by the checks
  immediately before `dispatchOperation()`, not before the append
  itself (High).** `appendEvent()` is its own real target mutation, not
  merely a decision that precedes one. Fixed by adding a check
  immediately before each of three appends that previously had none:
  the "started" event (checking here, before building or appending it
  at all, is strictly better than only checking before the dispatch it
  precedes - a step refused this early is never journaled as started in
  the first place, so a later resume sees it as untouched rather than
  permanently ambiguous) and both of the post-commit recovery block's
  own synthetic "succeeded" events (recording, independently of
  dispatch, that current.json/topology.json/the immutable snapshot
  already agree). The main per-operation "succeeded"/"failed" events
  recorded *after* a real dispatch already happened are deliberately
  left unguarded: that dispatch is irreversible either way, and
  refusing to record its true outcome would recreate the exact
  "ambiguous, no resolution" problem this fix exists to avoid, in the
  opposite direction.
- Seven new regression tests were added directly against this
  lifecycle, four of which were deliberately verified (by temporarily
  reverting each corresponding fix in isolation and confirming the test
  then fails, before restoring it) to actually catch the regression they
  claim to, not merely to pass: a stdin error arriving before
  `HOF_LEASE_HELD` still rejects acquisition even when a buffered
  `HOF_LEASE_HELD` chunk arrives right after; a lease that resolves
  already lost is refused before `acquireLockAndJournal`/`readLock` is
  ever attempted; the "started" event is never appended once the lease
  is known lost; and a loss discovered strictly between
  `appendEvent(started)` and the dispatch it guards still stops that
  dispatch specifically (this last one required fixing an off-by-one in
  the test's own call-counting simulation, introduced by the new
  post-acquisition and pre-append checks each consuming one more
  `isLost()` call before the pre-dispatch check's own turn - a mistake
  the verify-by-reverting step itself caught, the same discipline this
  errata's own tests were added to demonstrate). A fifth new test covers
  the post-commit recovery block's own append the same way, without the
  isolated revert-verification (its call-count arithmetic depends on the
  fixture's own operation count, computed at run time rather than
  hand-counted).

Still not run for real: `pnpm test:apply-ssh` itself, for the same
standing reason as every prior round. First real CI run on this PR
remains the actual acceptance gate.

## Errata (2026-09-03, item 9 review round 5)

A further NO-GO review of the round-4 fixes above (still uncommitted)
found the acquisition-race fix was confirmed correct in production code,
but the round-4 `appendEvent()` guards - all three of them - were placed
one `await` too early: immediately before `buildEvent()`, not
immediately before `appendEvent()` itself. `buildEvent()` is itself
genuinely async (`operation-journal.mjs`'s own `assertValid()` awaits AJV
schema validation, and a real `readFile()` of the event schema on this
process's first call ever), so the exact real-await window this whole
line of fixes exists to close was left open one call earlier than
intended. Separately, two test gaps were found: the round-4
acquisition-race regression test asserted only a bare `/stdin error/`
substring, which the OTHER (intentionally redundant) safety net's own
wrapped message also satisfies - reverting the specific fix that test
names left it green; and the post-commit recovery block's SECOND
synthetic-succeeded path (reached after a real re-dispatch, rather than
when everything already matched) had no regression test of its own at
all. Corrected, again without revisiting the underlying design:

- **All three `refuseIfLeaseLost()` guards were positioned before
  `buildEvent()`, not before `appendEvent()` (High, release blocker).**
  Fixed by building the event first, then checking, then appending - in
  all three places (the post-commit recovery block's own two synthetic
  succeeded-event appends, and the main dispatch loop's own
  `appendEvent(started)`). Nothing async now runs between the check and
  the mutation it guards, at any of the five `appendEvent()`/
  `dispatchOperation()` call sites in the loop.
- **The acquisition-race regression test didn't isolate the specific
  fix it named (Medium, test gap).** `assert.rejects(acquiring, /stdin
  error/)` matched both the intended handler-level `claim()`+reject
  fix's own message AND the separate, more general post-`await
  acquirePromise` safety net's own wrapped message (which embeds the
  same "stdin error..." string via `lostReason()`) - reverting only the
  handler-level fix left the test green, silently exercising the safety
  net instead. Fixed with a custom validator function checking
  `error.message.startsWith(...)` against the handler-level fix's own,
  more specific message prefix - and, while fixing it, found and fixed a
  second, unrelated bug in the SAME assertion: `assert.rejects()` tests
  a bare `RegExp` against `String(error)` ("Error: <message>"), not
  `error.message` directly, so even a `^`-anchored regex checking the
  right text could never have matched past the "Error: " prefix.
- **The post-commit recovery block's second (re-dispatch) synthetic-
  succeeded path had no regression test (Medium, test gap).** Added: a
  fixture where the immutable per-generation snapshot for the new
  generation is already published but the two mutable pointers still
  show the OLD generation (the exact crash window
  `ansible/roles/state/tasks/main.yml` describes), whose fake `dockerRun`
  brings the pointers up to date on the resulting re-dispatch, same as a
  real target would - then proves a lease lost strictly between that
  re-dispatch and its own synthetic succeeded-event append stops the
  append. Building this fixture surfaced a genuine gap in
  `makeFakeMutate()`'s own convenience default: `readGenerationSnapshot
  Topology()` falls back to the CURRENT mutable `state.topology` when no
  per-generation override is set, which every other snapshot-based test
  in this file relies on (their own mutable/immutable topology always
  agree) - but this new fixture deliberately keeps them apart, so it now
  sets `generationSnapshotTopologies` explicitly rather than relying on
  that fallback.
- Every one of the round-4 regression tests whose own call-count
  arithmetic depends on how many `isLost()` checks precede the one being
  isolated was re-verified against the corrected checks' positions (no
  count needed to change - moving a check across `buildEvent()`'s own
  await doesn't add or remove an `isLost()` call, only which awaits sit
  on which side of it).

Still not run for real: `pnpm test:apply-ssh` itself, for the same
standing reason as every prior round. First real CI run on this PR
remains the actual acceptance gate.
