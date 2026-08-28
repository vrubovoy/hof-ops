# ADR 0004: Apply execution contract

- Status: Accepted
- Date: 2026-08-27

## Context

Delivery item 7 landed a fully read-only planning plane (`hofctl
validate`/`preflight`/`plan`) that can compute a typed, ordered operation
list but never executes anything. Delivery item 8 is the first piece that
actually mutates a target host - a fresh install onto a clean Debian 12 or
Ubuntu 24.04 machine that may not even have Docker yet. Executing untrusted
or stale input against a real host is a fundamentally different risk than
computing a plan for an operator to read: a wrong or replayed operation here
can leave a host half-provisioned, apply the wrong release, or run against a
target that changed underneath the plan between planning and execution.

Item 8 is deliberately scoped to fresh install only - a clean host, no prior
Hof state, no Docker required to already be present, bootstrap plans only.
Applied-mode reconciliation (update/remove), backup/restore, upgrade/
rollback, first-admin bootstrap, and the installer UI are later delivery
items and must not be pulled forward here.

## Decision

**Exact target binding.** Every plan `hofctl apply` will ever execute
records exactly which target it was computed against: transport mode,
host/port/user, and - critically - the exact accepted SSH host-key
fingerprint from the same connection `inspectTarget()` used to observe the
host, not just the caller-supplied trust anchor. A host-key change (a
reinstalled OS, a MITM, a genuine key rotation) invalidates the plan and
requires a fresh one; `apply` never re-trusts a target on the caller's say-so
alone.

**Explicit, exact approval.** `apply` never runs "the latest plan" or
infers approval from a plan simply existing on disk. It requires
`--approve-plan-id <exact-plan-id>` matching the freshly (re)computed plan's
own deterministic `planId` byte-for-byte. Approving a plan is approving
those exact bytes, not a vague intent to proceed.

**Bootstrap-only in item 8.** `apply` refuses any plan whose `mode` is not
`bootstrap`. Applied-mode reconciliation needs the operation journal, lock,
and stale-plan-recheck machinery this item introduces, plus real production
experience running them, before it's safe to extend to a host that already
has real user data on it - that is delivery item 9, not this one.

**Signed Execution Environment, not local Ansible.** Every mutation on the
target runs inside a pinned, signed Ansible Execution Environment image
(matching this platform's existing signed-image supply chain for every
other component), never the operator's own local Ansible installation and
whatever collections happen to be on their workstation. `apply` verifies the
EE image's signature the same way `hofctl validate` verifies the release
lock's, before ever running it.

**Durable host lock.** `apply` acquires an exclusive, durable lock scoped to
the target host before touching it, and only one `apply` may hold it at a
time. The lock survives the invoking process dying (an operator's laptop
sleeping, a network drop) - a later `apply --resume` reclaims it rather than
racing a second, concurrent apply against the same host.

**Durable operation journal, no secrets.** Every operation `apply` runs is
recorded in a durable, on-target journal before and after execution -
operation id, the approved plan id, the target binding, immutable input
digests, status, attempt count, and a sanitized error on failure. The
journal never records a secret value, decrypted content, an environment
dump, or an SSH private key path - it is safe to read, copy, or attach to a
bug report without a second sanitization pass.

**Stale-plan recheck under the lock.** Once the lock is held, `apply`
re-verifies the plan's own target binding (host key, installation id,
baseline generation) against a fresh, real inspection of the target before
running a single operation. A plan approved five minutes ago against a host
that has since changed underneath it is rejected, not silently executed
against a target it no longer accurately describes.

**A fixed, typed operation whitelist - no generic executor.** `apply`
dispatches only the fixed action vocabulary `hofctl plan` already emits
(`host.prepare`, `secret.ensure`, `volume.ensure`, `network.ensure`,
`image.verify`, `image.pull`, `config.write`, `database.migrate`,
`service.start`, `readiness.wait`, `state.commit`), never a raw command,
playbook name, tag, or environment variable an operation could smuggle in.
Item 8's own whitelist additionally excludes every action that only ever
makes sense against an already-applied host (`backup.create`,
`service.stop`, `service.remove`) - a bootstrap plan that somehow contained
one is rejected outright, not silently skipped.

**Safe, bounded resume.** An interrupted bootstrap (crash, reboot, a
disconnected workstation) resumes from the same operation journal without a
new approval or a newly computed plan - `apply --resume` only. An operation
journal entry whose own outcome can't be determined (the process died
mid-operation, before or after the target-side effect actually landed, with
no confirming journal entry either way) blocks resume rather than guessing
whether it's safe to retry or skip.

**Atomic, last commit.** `/var/lib/hof/state/current.json` (generation 1,
for a bootstrap) is written only after every prior operation in the plan
has already succeeded, as the final journaled operation, and only ever
atomically (write-then-rename) - a host must never be observed in a state
where Docker resources exist but no generation has been committed, or where
a commit exists but a prior operation actually failed.

## Consequences

- `hofctl plan` continues emitting `plan-v1` unchanged; a new `plan-v2`
  contract (target binding, planning policy, image verification policy,
  the bootstrap recovery `age` recipient, a supplied TLS certificate's
  fingerprint) is introduced alongside it, not as a breaking replacement.
- Every apply-time contract (plan-v2, the operation journal/event/lock
  schemas, the bootstrap action whitelist) is designed and schema-validated
  in its own PR before `hofctl apply` itself exists to consume any of them -
  the contract is reviewable independent of the executor.
- Docker not yet being installed on the target must be distinguished from
  Docker being installed but unsafe to inspect - a fresh host with no
  Docker at all is a legitimate bootstrap candidate, not an inspection
  failure.
- A real executor (Ansible EE invocation, host/secret/volume/network/
  image/config/migration/service/readiness roles, the lock and journal
  implementations) is out of scope for the contracts introduced here and
  lands in the PRs that follow.

## Errata (2026-08-28, PR #31)

A review after item 8's own PRs (#24-30) landed found the approval and
resume decisions above were only partially implemented, in a way that
made "Explicit, exact approval" not actually hold in practice - filed as
"Item 8 reopened" in `PLATFORM-OPS-PLAN.md`. Both corrected here, without
revisiting the design itself:

- **"`hofctl plan` continues emitting `plan-v1` unchanged" was wrong in
  practice, not just imprecise.** `hofctl apply` requires approval of a
  `plan-v2` document (this ADR's own decision above), but `hofctl plan`
  never printed one - it always printed `plan-v1`, a structurally
  different document with a different `planId`. An operator's real
  `hofctl plan` output could therefore never be the exact bytes
  `--approve-plan-id` needed, defeating "approving a plan approves those
  exact bytes" at the one point a human is actually supposed to look at
  them. Fixed: `hofctl plan` against a bootstrap target now prints the
  real `plan-v2` document (requiring `--recovery-age-recipient`, and a
  supplied-TLS certificate fingerprint when `manifest.tls.mode` is
  `supplied`, exactly like `apply` itself needs); against an
  already-applied target it still prints `plan-v1` (item 9 doesn't exist
  yet to define what a `plan-v2` there would even mean). `apply` also
  gained an explicit `--plan <file>` flag - `--approve-plan-id` is
  checked against that file's own `planId`, and apply's live recompute
  (both before and, again, under the lock) is compared against the full
  file, not reconstructed from scratch with no record of what was
  actually reviewed.
- **"Safe, bounded resume" could not actually resume past the case it
  exists for.** `apply --resume`'s implementation ran the ordinary
  bootstrap-baseline check (`resolveBaseline()`) before ever reading the
  lock or journal. Once a real mutation had already happened under the
  lock (a created volume/network/container) but `state.commit` hadn't
  run yet - precisely the interruption resume is meant to recover from -
  that baseline check saw an already-partially-applied host and refused
  outright, never reaching the per-step resumption logic at all. Fixed:
  resume now reads the lock and journal first, always; the journal
  itself now embeds the full approved plan document (not just its
  `planId`), which resume reads operations from directly, and resume
  re-verifies only the immutable input digests and target host-key
  identity the journal was created against - it never re-derives a live
  baseline/diff.

Every other decision above (target binding, the signed Execution
Environment, the durable lock, the whitelist, the atomic last commit)
is unchanged.

## Errata (2026-08-28, PR #32)

The same review named five further, High-severity gaps in item 8's
bootstrap/apply scope, all closed without revisiting this ADR's own
decisions:

- **Supplied TLS material was fingerprinted into the plan but never
  actually delivered.** The rendered Compose file's gateway service
  bind-mounted `manifest.tls.certificatePath`/`privateKeyPath` directly
  - workstation paths, meaningless to Compose running on the target.
  `scripts/supplied-tls.mjs` also never validated the certificate/key at
  all (no parse, no key-match check, the private key was never even
  read). Fixed: that module now genuinely parses the certificate (Node's
  builtin `X509Certificate`), confirms the private key corresponds to it
  (`checkPrivateKey`), checks current validity, and confirms the SAN
  covers every public hostname the deployment serves (exact or wildcard
  match); `apply` delivers the real certificate/key content the same way
  it delivers any other secret (never through extra-vars/the journal,
  never through the generic config.write path); the rendered Compose
  file now bind-mounts the two fixed target-side paths that delivery
  actually writes to.
- **A target with Docker Engine already present but the Compose plugin
  specifically missing was never fixed.** The `host` role's install
  block only ever ran when `docker --version` failed - a target with a
  working Engine from an Engine-only install (or the old standalone
  `docker-compose` binary) silently never got the plugin. Fixed: the
  role now checks `docker compose version` independently of Engine's own
  presence, and installs the plugin in its own task, gated on that check
  alone.
- **`apply` never re-verified the exact supported platform itself.**
  `hofctl preflight` already checks Debian 12/Ubuntu 24.04/x86_64, but
  nothing required a successful preflight run before `apply`, and the
  Ansible host role's own OS assert only runs after `host.prepare` has
  already started a real `apt-get` install - too late to be the actual
  mutating boundary. Fixed: `apply`'s own live plan recompute (both
  before the lock and, again, under it) now runs the identical OS/
  architecture checks before resolving anything about the target's own
  topology.
- **Journal and lock documents read off the target were never schema-
  validated.** `target-mutate.mjs`'s own `readLock()`/`readJournal()`
  only ever `JSON.parse` the raw bytes they read back; a hand-tampered
  or corrupted document would have been silently trusted. Fixed: `apply`
  now validates both against their own schemas immediately after every
  read, before ever acting on a field from either.
- **A stray `~/.ssh/config` `ProxyJump`/`ProxyCommand` for the target
  hostname could silently route real bytes through an intermediary the
  target binding never recorded.** Neither `target-inspector.mjs` nor
  `target-mutate.mjs`'s own SSH hardening disabled either directive.
  Fixed: both now pass `-o ProxyCommand=none -o ProxyJump=none`
  (OpenSSH's own documented override), so a connection is always direct,
  matching the target binding's own literal host/port.
