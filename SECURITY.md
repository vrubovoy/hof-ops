# Security Policy

## Supported versions

hof-ops is deployed continuously from `main` — there are no maintained
release branches. Security fixes land on `main` and that is the only
supported version.

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities. Instead,
use GitHub's private reporting flow:

1. Go to the [Security tab](../../security) of this repository.
2. Click "Report a vulnerability".
3. Describe the issue, including reproduction steps if you have them.

This is a small, mostly-solo project, so response time is best-effort, not
contractual — but you can expect an initial reply within a few days.

## Release channel integrity

The two-stage release pipeline (`release.yml` builds an immutable
`vX.Y.Z-rc.N` candidate; `promote.yml` moves one to `stable` after signed,
provenance-checked acceptance — see [README](README.md#cutting-a-release))
depends on repository-level settings that live outside this repo's files.
These must be configured and kept in place:

- **GitHub Immutable Releases** enabled (repository Settings → General —
  not exposed by the REST API). `promote.yml` refuses to promote a
  candidate whose release is not immutable, so this is load-bearing, not
  advisory: promotion stays inoperable until it is on.
- **Tag ruleset** covering `refs/tags/v*` and `refs/tags/ee-v*` with
  `deletion`, `non_fast_forward`, and `update` blocked, so a
  `contents: write` token cannot delete or move a published tag or its
  release assets (configured: ruleset "Protect release and EE tags").
- **Require actions to be pinned to a full-length commit SHA** at the
  repository level (`actions/permissions` → `sha_pinning_required: true`,
  configured). Every workflow in this repo is already SHA-pinned; the
  setting stops a future unpinned `uses:` from running.
- **`main` branch protection** with the `contracts` check required and
  admins included (already configured).

`promote.yml` additionally enforces, in code, that a candidate commit is
an ancestor of `main`, that the candidate lock is schema-valid against
`main`'s own schema with catalog/renderer digests matching `main`, that
acceptance evidence is Cosign-signed by `acceptance.yml@refs/heads/main`
and its recorded run metadata matches the live GitHub run, and that the
stable `release-lock.json` is re-signed under `promote.yml@refs/heads/main`
as its own authorization signature. None of that removes the need for the
settings above — they are the layer that keeps an already-published
immutable artifact from being swapped underneath a valid signature.

## Scope

hof-ops does not hold end-user data — it deploys the services that do. Its
own highest-priority surface is host and supply-chain trust: anything that
could let a `services.yml` manifest smuggle in an unpinned or unsigned
image, an arbitrary command, or a secret value (image digests, tags, and
generated ports are deliberately rejected from that file — see
[ADR 0002](docs/adr/0002-versioned-deployment-contracts.md)); anything that
would let `hofctl` or the later `hof-opsd` execute more than its fixed,
typed operation set against a target host (see
[ADR 0001](docs/adr/0001-scope-and-trust-boundaries.md)); and, once secrets
handling and the installer land, anything that could leak SOPS/age key
material, SSH credentials, or a decrypted secret into logs, operation
history, or a backup artifact.
