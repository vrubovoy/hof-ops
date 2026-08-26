# Changelog

## Foundation

- Versioned JSON Schemas for the operator-owned `services.yml` desired
  state, the release-owned service catalog, and the immutable release
  lock, plus cross-contract validation `services.yml` and the catalog
  cannot express alone (mandatory-core downgrade, dependency cycles,
  secrets/image overrides in `services.yml`, duplicate backup destination
  names, a release lock missing an artifact the catalog requires).
- First platform service catalog (`catalog/services-v1.yaml`) and matching
  `services.yml`/release-lock examples.
- Accepted ADRs on scope and trust boundaries, the three-contract split,
  and control-plane execution and distribution.
