# ADR 0001: Scope and trust boundaries

- Status: Accepted
- Date: 2026-08-26

## Context

Hof needs repeatable deployment to a single server without turning an
application service into a general host administrator. The existing Tor
Compose project is an integration and development aggregator. Schlussel is an
authentication authority, Schloss owns the operational user interface, and
Wachter has a deliberately narrow monitoring and restart-agent boundary.

## Decision

`hof-ops` is a distributable operations product for a single rootful Docker
host running Debian 12 or Ubuntu 24.04 on amd64.

The first installer runs on the operator workstation, binds only to loopback,
and reaches the target through authenticated SSH and sudo. A headless,
idempotent reconciler is implemented before the installer UI.

Tor remains the gateway and development stack. Schlussel, Schloss, and
Wachter do not receive SSH credentials, a Docker socket, a shell, or generic
Ansible authority.

The later `hof-opsd` starts as read-only. Any mutation API requires a separate
security review and exposes only typed operations against signed releases.

## Consequences

- The v1 topology is single-host and uses coordinated downtime.
- Kubernetes, multi-host, rootless Docker, arm64, and unattended upgrades are
  out of scope.
- The contracts and verification matrix must work for installations other
  than the original developer's server.
