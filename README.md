# hof-ops

[![Test](https://github.com/vrubovoy/hof-ops/actions/workflows/test.yml/badge.svg)](https://github.com/vrubovoy/hof-ops/actions/workflows/test.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

Part of the [Hof platform](https://github.com/zudaR107/Hof) — a suite of
self-hosted personal services:

- [`schloss`](https://github.com/zudaR107/schloss) — home page / launcher
- [`schlussel`](https://github.com/zudaR107/schlussel) — auth: accounts, login, tokens
- [`kuvert`](https://github.com/zudaR107/kuvert) — envelope budgeting
- [`tafel`](https://github.com/zudaR107/tafel) — task/project tracking
- [`zettel`](https://github.com/zudaR107/zettel) — markdown note-taking
- [`glocke`](https://github.com/zudaR107/glocke) — in-app notification center and delivery foundation
- [`schrank`](https://github.com/zudaR107/schrank) — file storage with nested folders
- [`herold`](https://github.com/zudaR107/herold) — webmail client for external IMAP/SMTP accounts
- [`wachter`](https://github.com/vrubovoy/wachter) — server resource monitoring
- [`tor`](https://github.com/zudaR107/tor) — reverse-proxy gateway
- **`hof-ops`** (this repo) — deployment contracts and operations tooling
- [`schloss-ui`](https://github.com/zudaR107/schloss-ui) — shared frontend components
- [`schloss-server-kit`](https://github.com/zudaR107/schloss-server-kit) — shared backend auth/CORS kit

hof-ops turns "clone every repo and run `docker compose up`" into a
repeatable, single-host deployment product: an operator declares which
services they want in one small `services.yml`, and everything else —
image digests, container topology, health checks, secrets, backups,
upgrades — is derived and applied for them, without ever running the
application source directly on the target.

It owns the desired-state manifest, the release-owned service catalog, the
immutable release lock, and a deterministic `hofctl render` topology compiler.
Ansible host reconciliation, restic backup/restore, and a
local installer UI. It contains no application source code of its own and
does not extend any service with generic host access: Schlüssel, Schloss,
and Wächter never receive a Docker socket, an SSH key, or a shell from
this repo. See [ADR 0001](docs/adr/0001-scope-and-trust-boundaries.md) for
why, and [`Hof/PLATFORM-OPS-PLAN.md`](https://github.com/zudaR107/Hof/blob/main/PLATFORM-OPS-PLAN.md)
for the full plan this repo implements in stages.

## Status

The contract foundation is implemented and covered by tests: versioned
JSON Schemas, the first service catalog, and cross-contract
validation that schemas alone can't express. Every image-publishing repo
signs its published digests (keyless Cosign) and attests an SBOM and build
provenance; `scripts/build-release-lock.mjs` resolves and independently
re-verifies all of that into a real, schema-valid `release-lock.json`, and
[`.github/workflows/release.yml`](.github/workflows/release.yml) signs that
file itself and publishes it as a GitHub Release
(`gh release list --repo vrubovoy/hof-ops`). Host reconciliation,
backup/restore, upgrade/rollback, first-admin bootstrap, and the installer
are not implemented yet — see the Delivery Order in the plan linked above
for what comes next.

## The three contracts

hof-ops deliberately keeps operator intent, platform topology, and
immutable release artifacts in three separately versioned files rather
than one Compose project an operator hand-edits. See
[ADR 0002](docs/adr/0002-versioned-deployment-contracts.md) for the
reasoning; generated Compose/Caddy/systemd/env files are disposable
outputs of these contracts, never a second source of truth.

| Contract | Schema | Owner | Contains |
|---|---|---|---|
| Desired state | [`schemas/services-v1alpha1.schema.json`](schemas/services-v1alpha1.schema.json) | Operator | Which services are enabled, target host, domains, TLS mode, backup policy — never secrets, image tags/digests, or generated ports |
| Service catalog | [`schemas/service-catalog-v1.schema.json`](schemas/service-catalog-v1.schema.json) | Release | Mandatory vs. optional services, artifacts, dependencies, hostnames, volumes, health checks — see [`catalog/services-v1.yaml`](catalog/services-v1.yaml) |
| Release selection | [`schemas/release-selection-v1.schema.json`](schemas/release-selection-v1.schema.json) | Release engineer | Explicit component semver tags, required GitHub checks, expected signing identities, schema compatibility, and third-party trust policy |
| Release lock | [`schemas/release-lock-v1.schema.json`](schemas/release-lock-v1.schema.json) | Release | Immutable, signed mapping from every catalog artifact to a source commit and OCI image digest, plus catalog and Compose-template digests |
| Stable channel | [`schemas/stable-channel-v1.schema.json`](schemas/stable-channel-v1.schema.json) | Release | Signed pointer from `stable` to one exact release-lock digest |

An operator only ever writes the first one. Release engineers provide the
selection mapping; see [`examples/release-selection.yml`](examples/release-selection.yml),
[`examples/services.yml`](examples/services.yml) and
[`examples/release-lock.json`](examples/release-lock.json) for filled-in
examples.

## Rendering a topology

`hofctl render` validates the desired state, catalog, and release lock;
requires the manifest and release-lock releases to match, and writes
disposable deployment artifacts.
Optional services which are not enabled are omitted rather than emitted in a
degraded state. The output includes pinned-image Compose services and volumes,
Caddy routes, runtime frontend links and flags, Schlüssel export/deletion
registries, Glocke producers, trusted/CORS origins, readiness targets and
dependencies, and the backup volume inventory.

```sh
node scripts/hofctl.mjs render \
  --services examples/services.yml \
  --release-lock examples/release-lock.json \
  --catalog catalog/services-v1.yaml \
  --out build/rendered
```

The renderer writes `compose.yml`, `Caddyfile`, `runtime-config.json`,
`service.env`, `topology.json`, and `backup-inventory.json`. Re-running it with
identical inputs produces byte-identical files. Secret values are not part of
the contracts or generated files; Compose placeholders refer to the required
deployment environment only when the corresponding integration is enabled.

## Cutting a release

```sh
gh workflow run release.yml --repo vrubovoy/hof-ops \
  -f release=1.0.0 -f selection=examples/release-selection.yml
```

The workflow accepts only canonical stable semver and refuses an existing tag
or GitHub Release. For each explicit component selection it resolves the
immutable source tag and image tag to a commit and digest, directly checks the
named GitHub checks on that commit, runs `cosign verify` with the exact expected
workflow identity and OIDC issuer, verifies SBOM and SLSA provenance
attestations, and rejects subject, repository, or revision mismatches. It then
records config schema, database before/after and rollback compatibility where
applicable, minimum `hofctl`, catalog, Compose renderer, and optional Ansible
environment pins in `release-lock.json`.

The pinned lock is consumed by a core/full topology matrix. The production
renderer emits Compose for each fixture; `docker compose config`, pull, and
container-create contracts run against only the selected digests. The workflow
re-resolves everything to reject tag drift, signs the lock and stable-channel
metadata with keyless Cosign, and publishes them in one GitHub Release. Verify a
published lock file yourself:

```sh
cosign verify-blob \
  --certificate release-lock.json.pem --signature release-lock.json.sig \
  --certificate-identity 'https://github.com/vrubovoy/hof-ops/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-lock.json
```

Run the local, no-pull portion with `pnpm integration`. The release job adds
`--runtime`, which pulls and creates containers without starting a platform or
requiring the future reconciler.

Third-party artifacts are an explicit exception. The current Caddy gateway is
resolved and pinned by registry digest under a `digest-only` policy, but Hof
cannot assert its source commit, CI, workflow identity, SBOM, or provenance.
That limitation is mandatory in both selection and lock metadata; a Hof release
must not imply that digest pinning gives third-party artifacts first-party
supply-chain assurance.

## Development

```sh
pnpm install
pnpm validate   # schema + cross-contract validation
pnpm test       # node --test
pnpm integration # render fixtures and run pinned Compose config contracts
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
