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
