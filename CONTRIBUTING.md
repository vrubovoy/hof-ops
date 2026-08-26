# Contributing to hof-ops

Thanks for considering a contribution. hof-ops owns the Hof platform's
deployment contracts and operations tooling — desired-state, service
catalog, and release-lock schemas today; `hofctl`, Ansible reconciliation,
backup/restore, and the local installer as they land. It's a single Node.js
package, not a frontend/backend split — please keep changes focused.

## Getting set up

```sh
pnpm install
pnpm validate   # schema + cross-contract validation
pnpm test       # node --test
```

## Before opening a PR

- Run `pnpm validate` and `pnpm test` — CI runs both and will block merges
  that don't pass.
- If you change a schema in `schemas/`, update the matching example in
  `examples/` (and `catalog/services-v1.yaml` if it's the catalog schema)
  so `pnpm validate` still passes.
- A schema change that isn't backward-compatible needs a new major schema
  version, not an edit to the existing one — see
  [ADR 0002](docs/adr/0002-versioned-deployment-contracts.md).
- Add or update tests for any behavior change.
- Keep commits focused; one logical change per PR is easier to review than
  several bundled together.
- Write commit messages that explain *why*, not just *what* — the diff
  already shows what changed.
- A decision that changes scope, trust boundaries, or an established
  contract belongs in a new ADR under `docs/adr/`, not just a code change —
  see the existing ADRs for the expected shape.

## Opening a PR

- Branch from `main`.
- Reference the issue you're addressing if one exists (`Closes #123`).

## Reporting bugs / security issues

Open a regular issue for bugs. For anything that looks like a security
vulnerability, please use GitHub's private "Report a vulnerability" flow
under this repo's Security tab instead of a public issue.
