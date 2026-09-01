# Hof Execution Environment

The pinned, signed container image `hofctl apply` runs every mutation on
a target through (see [ADR 0004](../docs/adr/0004-apply-execution-contract.md)).
Never the operator's own local Ansible installation and whatever
collections happen to be on their workstation - `hofctl apply` invokes
`ansible-playbook` inside a container from this exact, digest-pinned,
Cosign-signed image, the same way every other part of this platform
only ever runs signed, digest-pinned artifacts.

## Layout

- `Dockerfile` - `python:3.13-slim-bookworm` (digest-pinned) + `ansible-core`
  + the collections in `requirements.yml`, with `roles/` baked in.
  "Pinned Execution Environment" means the whole deployment logic is
  signed and immutable, not just the Ansible runtime underneath it -
  `hofctl apply` never mounts a live `roles/` directory from the
  operator's own workstation into a container at apply time.
- `requirements.yml` - the exact collection versions, resolved once at
  image-build time, never floated to "whatever's current" against a
  live target.
- `ansible.cfg` - `host_key_checking = true` (Ansible connects over a
  transport `target-inspector.mjs`'s own hardened SSH already
  authenticated - it never independently negotiates trust of its own);
  `retry_files_enabled = false` (the operation journal is the durable,
  structured record of what happened, not a second, cruder copy).
- `roles/` - one role per `plan-v1`/`plan-v2` operation phase
  (`host`, `secret`, `volume`, `network`, `image`, `config`, `database`,
  `service`, `readiness`, `state`) - see each role's own
  `defaults/main.yml` for its real variable contract. Every role asserts
  its own required variables before doing anything else, so a caller
  that got the typed operation-to-role mapping wrong fails loudly there,
  not deep inside a half-applied task. All ten have their real
  implementation (item 8's PR #28: `host`/`secret`/`volume`/`network`/
  `image`/`config`; PR #29: `database`/`service`/`readiness`/`state`),
  and - since PR #36 - every one of them is exercised end to end for
  real in CI (`test/apply-acceptance.mjs`, `pnpm test:apply-ssh`), not
  just some of them: a real, published, signed platform release lock
  (`v0.1.2`), a real, published, independently-signed Execution
  Environment (`ee-v0.1.1`, no local build, no signature bypass), real
  application images (`schlussel`/`schlussel-frontend`/`schloss` - the
  platform's own mandatory core), taken all the way through a real
  `database.migrate`, real `service.start`, real `readiness.wait` (real
  `docker inspect` `Health.Status` polling), and a real generation-1
  `state.commit` - confirmed afterward by a second real `hofctl plan`
  seeing a genuine `"applied"` baseline, not `"bootstrap"`. See
  PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry (and its own closure
  note once every finding there was fixed) for the full story.

## Versioning

The Execution Environment versions independently of the platform
release, exactly like every other component in
[`examples/release-selection.yml`](../examples/release-selection.yml) -
`scripts/build-release-lock.mjs` resolves it the same way (a real Git
tag, a real passing CI check, a real Cosign signature, real SBOM/
provenance attestations - see `resolveBuiltArtifact()`). Its own tag is
`ee-vX.Y.Z`, **not** plain `vX.Y.Z` - hof-ops's own platform release
(`.github/workflows/release.yml`) creates a plain `vX.Y.Z` tag on this
same repository via `gh release create`. `resolveBuiltArtifact()` takes
an explicit `tagPrefix` argument for exactly this reason - `"v"` for
every ordinary component, `"ee-v"` only for the Ansible Execution
Environment - so the two can never be able to collide on the same git
tag (a real gap a 2026-08-28 review found: `resolveRevision()` used to
always look up `v${version}` regardless of component, meaning a real
release build could never actually have resolved this component's own
real tag at all - see PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry).

```sh
git tag ee-v0.1.0
git push origin ee-v0.1.0
```

pushing that tag triggers `.github/workflows/execution-environment.yml`,
which builds, signs (keyless Cosign), and attests (SBOM + build
provenance) `ghcr.io/vrubovoy/hof-ops-ee:v0.1.0` - the `v0.1.0` image
tag (not `ee-v0.1.0`) is what `examples/release-selection.yml`'s own
`ansibleEnvironment.image` and `version: "0.1.0"` reference, matching
every other component's own `:v${version}` convention.

`ee-v0.1.0` was cut this way for real, closing out item 8's own
bootstrap/apply work initially. A 2026-08-28 review then found real
gaps in that scope (see PLATFORM-OPS-PLAN.md's "Item 8 reopened"
entry) - once they were fixed (PRs #31-33), `ee-v0.1.1` was cut the
same way, baking those fixes (in particular PR #32's own `host` role
Compose-plugin fix) into a real pinned image for the first time:
`ghcr.io/vrubovoy/hof-ops-ee@sha256:0ada8da1a7329ac72081b82a4d38ccac08897795c95cc768d1d74de3c5a16eda`,
independently re-verified with a real `cosign verify` against the exact
workflow identity above (real transparency-log/certificate-authority
checks, not skipped) and confirmed to carry both attestations
(`https://spdx.dev/Document/v2.3` and `https://slsa.dev/provenance/v1`).
`ee-v0.1.0`'s own image stays published, a historical artifact, not
deleted.

Item 9 (applied-mode reconciliation, ADR 0005) baked its own new
service-role `start|stop|remove` actions and the state role's own
immutable per-generation snapshots (`generations/NNNNNN/*`) into a real
pinned image the same way: `ee-v0.1.4`, cut once PRs #48-52 landed,
independently re-verified here exactly like every prior cut -
`ghcr.io/vrubovoy/hof-ops-ee@sha256:75e93b8afdd01a9279a62d9e5d98811c3402ac443e9774a5f916c88245ebf0a7`,
real `cosign verify` against the exact workflow identity above, both
attestations (`https://spdx.dev/Document/v2.3` and
`https://slsa.dev/provenance/v1`) confirmed present. Platform release
`v0.2.0` (`releases/0.2.0.yml`) selects it - the first release able to
apply against an already-applied installation, not just bootstrap one.
