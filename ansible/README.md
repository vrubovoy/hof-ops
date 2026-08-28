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
  not deep inside a half-applied task. All ten now have their real
  implementation (item 8's PR #28: `host`/`secret`/`volume`/`network`/
  `image`/`config`; PR #29: `database`/`service`/`readiness`/`state`).
  `host`/`secret`/`volume`/`network`/`image`/`config` and the whole
  apply pipeline around them (lock, journal, dispatch, a real failure
  path) are exercised end to end for real in CI
  (`test/apply-acceptance.mjs`, `pnpm test:apply-ssh`) against a
  genuinely ephemeral target - that run stops at a real, expected image
  pull failure (`examples/release-lock.json`'s own images are
  illustrative, not real published digests), so `database`/`service`/
  `readiness`/`state` are verified locally (real Jinja rendering, real
  `docker compose`/`docker inspect` argv construction, real
  `ansible.builtin.copy` byte-for-byte delivery confirmed via `--check
  --diff`) rather than through that same live target - see PR #29's own
  commit message for exactly what was checked.

## Versioning

The Execution Environment versions independently of the platform
release, exactly like every other component in
[`examples/release-selection.yml`](../examples/release-selection.yml) -
`scripts/build-release-lock.mjs` resolves it the same way (a real Git
tag, a real passing CI check, a real Cosign signature, real SBOM/
provenance attestations - see `resolveBuiltArtifact()`). Its own tag is
`ee-vX.Y.Z`, **not** plain `vX.Y.Z` - hof-ops's own platform release
(`.github/workflows/release.yml`) creates a plain `vX.Y.Z` tag on this
same repository via `gh release create`, and
`scripts/build-release-lock.mjs`'s `resolveRevision()` always looks up
a component's own tag as literally `v${version}` regardless of
component - two different things sharing the same repository must never
be able to collide on the same git tag.

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

`ee-v0.1.0` has actually been cut this way, for real, closing out item 8:
`ghcr.io/vrubovoy/hof-ops-ee@sha256:ff58ec8b377fe72f86317bad606c5412ea09e6a678f16c113b7b2be2c791b306`,
independently re-verified with a real `cosign verify` against the exact
workflow identity above (real transparency-log/certificate-authority
checks, not skipped) and confirmed to carry both attestations
(`https://spdx.dev/Document/v2.3` and `https://slsa.dev/provenance/v1`).
