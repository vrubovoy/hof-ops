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
  candidate whose release is not immutable **and** re-checks the stable
  release's own `immutable` flag after publishing, so this is
  load-bearing, not advisory: promotion stays inoperable until it is on.
- **Deployment Environments** `release`, `promote`, and
  `execution-environment` with deployment branch policies (configured):
  `release` / `promote` allow protected branches only;
  `execution-environment` allows the tag pattern `ee-v*` only.
- **A dedicated release GitHub App** (`HOF_RELEASE_APP_ID`, private key in
  the `HOF_RELEASE_APP_PRIVATE_KEY` Environment secret on `release` and
  `promote`). `release.yml` / `promote.yml` privileged jobs run with
  `contents: read` and do every tag/release write through a short-lived
  installation token for this App - never the built-in `GITHUB_TOKEN`.
- **Ruleset "Restrict v* tag creation to the release App"** (configured):
  `creation` on `refs/tags/v*` is blocked for every actor except that App.
  A feature-branch workflow only ever holds a `GITHUB_TOKEN`, so it cannot
  create a `v*` / `v*-rc.*` tag at all - and it cannot obtain the App key,
  which is bound to the `main`-only Environments.
- **Two tag rulesets** (configured): "Protect release and EE tags" blocks
  `deletion` / `non_fast_forward` / `update` on `refs/tags/v*` and
  `refs/tags/ee-v*` for everyone; "Restrict EE tag creation to a human
  admin" blocks `creation` on `refs/tags/ee-v*` for everyone but a
  repository admin, so a `contents: write` Actions token cannot introduce
  an `ee-v*` tag on an unreviewed commit.
- **Require actions to be pinned to a full-length commit SHA** at the
  repository level (`actions/permissions` → `sha_pinning_required: true`,
  configured). Every workflow here is already SHA-pinned; the setting
  stops a future unpinned `uses:` from running.
- **`main` branch protection** with the `contracts` check required and
  admins included (already configured).

`promote.yml` additionally enforces, in code (from the pinned dispatch
revision), that the candidate commit is an ancestor of that revision, that
the candidate lock is schema-valid and passes the full cross-contract
check against `main`'s own catalog, that both the candidate lock signature
and the acceptance-evidence signature carry the candidate commit's own
`github-workflow-sha`, that the evidence's recorded run metadata matches
the live GitHub run, that the stable tag is created atomically at the
candidate commit and re-verified before and after publishing, and that the
stable `release-lock.json` is re-signed under `promote.yml@refs/heads/main`
as its own authorization signature. None of that removes the need for the
settings above — they are the layer that keeps an already-published
immutable artifact from being swapped underneath a valid signature.
`execution-environment.yml` likewise checks in code that its tagged commit
is an ancestor of `origin/main`, and pushes + fully signs the immutable
digest *before* the consumable `ee-vX.Y.Z` tag is assigned to it.

### Residual notes

A collaborator who can push a branch and run a workflow can still, by
editing their branch's copy of a workflow, request `id-token: write` and
obtain a Sigstore certificate - but only ever with a
`@refs/heads/<their-branch>` identity, which no consumer trusts (`hofctl`
and `promote.yml` require `@refs/heads/main` for stable). They cannot
create a `v*` or `ee-v*` tag (rulesets), cannot obtain the release App
key (Environment-bound to `main`), and cannot publish a release without a
tag. The remaining effect is transparency-log noise from unusable
branch-identity certificates.

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
