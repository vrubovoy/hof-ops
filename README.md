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
immutable release lock, and — as they land — `hofctl` (a headless
reconciler), Ansible host reconciliation, restic backup/restore, and a
local installer UI. It contains no application source code of its own and
does not extend any service with generic host access: Schlüssel, Schloss,
and Wächter never receive a Docker socket, an SSH key, or a shell from
this repo. See [ADR 0001](docs/adr/0001-scope-and-trust-boundaries.md) for
why, and [`Hof/PLATFORM-OPS-PLAN.md`](https://github.com/zudaR107/Hof/blob/main/PLATFORM-OPS-PLAN.md)
for the full plan this repo implements in stages.

## Status

The contract foundation is implemented and covered by tests: three
versioned JSON Schemas, the first service catalog, and cross-contract
validation that schemas alone can't express. Host reconciliation, backup/
restore, upgrade/rollback, first-admin bootstrap, and the installer are not
implemented yet — see the Delivery Order in the plan linked above for what
comes next.

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
| Release lock | [`schemas/release-lock-v1.schema.json`](schemas/release-lock-v1.schema.json) | Release | Immutable, signed mapping from every catalog artifact to a source commit and OCI image digest |

An operator only ever writes the first one — see
[`examples/services.yml`](examples/services.yml) and
[`examples/release-lock.json`](examples/release-lock.json) for filled-in
examples of all three.

## Development

```sh
pnpm install
pnpm validate   # schema + cross-contract validation
pnpm test       # node --test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
