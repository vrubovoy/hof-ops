# hof-ops

Deployment contracts and operations tooling for the Hof platform.

This repository owns the desired-state manifest, release-owned service
catalog, immutable release lock, reconciliation tooling, and the later local
installer. It does not contain application source code and does not extend
Schlussel or Wachter with generic host access.

## Status

The contract foundation is implemented. Host reconciliation, backups,
upgrades, and the installer are not implemented yet.

## Contracts

- `schemas/services-v1alpha1.schema.json` validates operator-authored desired
  state.
- `schemas/service-catalog-v1.schema.json` validates release-owned topology.
- `schemas/release-lock-v1.schema.json` validates immutable release artifacts.
- `catalog/services-v1.yaml` is the first platform service catalog.
- `examples/` contains valid contract examples.

`services.yml` never contains credentials, image references, generated ports,
or internal container topology. Generated deployment files are disposable
artifacts and must not become a second source of truth.

## Development

```bash
pnpm install
pnpm validate
pnpm test
```

## License

AGPL-3.0-or-later.
