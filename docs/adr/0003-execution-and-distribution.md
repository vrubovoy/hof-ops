# ADR 0003: Execution and distribution

- Status: Accepted
- Date: 2026-08-26

## Context

The installer must behave consistently on operator workstations while the
target should require no application build toolchain or source checkout.

## Decision

The control plane uses Node.js 22 and TypeScript, matching the Hof application
ecosystem. Deployment changes are performed by pinned Ansible content in a
signed Execution Environment image. The installer and command-line interface
consume the same library and emit the same structured operation events.

Production targets pull signed, digest-pinned images. The operator explicitly
approves every apply and upgrade plan. ACME HTTP-01 is the default TLS mode;
operator-supplied certificate and key files are also supported. DNS-01 and
air-gapped bundles are deferred.

## Consequences

- The operator workstation needs a compatible Docker engine for the first
  distribution format.
- The target needs only SSH/sudo during bootstrap and Docker at runtime.
- No generic command execution is exposed by the installer or future daemon.
