# ADR 0002: Versioned deployment contracts

- Status: Accepted
- Date: 2026-08-26

## Context

Operator intent, platform topology, and immutable release artifacts change at
different rates and have different owners. Combining them in one Compose file
would expose internal details, encourage manual edits, and make upgrades
ambiguous.

## Decision

Deployment uses three independently versioned contracts:

1. `services.yml` is operator-owned desired state. It contains the release,
   target, domains, TLS mode, optional services, features, and backup policy.
2. The service catalog is release-owned topology. It defines mandatory
   services, artifacts, dependencies, hostnames, volumes, and health paths.
3. The release lock is release-owned and immutable. It resolves every artifact
   to a signed OCI digest and records compatibility metadata.

JSON Schema is the structural source of truth. Cross-contract rules that JSON
Schema cannot express are enforced by the same validator used by `hofctl` and
CI.

Generated Compose, Caddy, systemd, and environment files are disposable
outputs. They are never accepted as configuration inputs.

## Consequences

- A schema major version is required for incompatible changes.
- Unknown fields fail validation instead of being silently ignored.
- Secrets are referenced by logical name and stored separately with SOPS and
  age.
- Release image tags and digests cannot be overridden from `services.yml`.
