// The "local supplied TLS" half of item 8's planning contract - reads
// and hashes the operator's own certificate file, exactly where
// services.yml's own tls.certificatePath already says it lives (on the
// WORKSTATION, matching ADR 0001 - the control plane runs there, not on
// the target). Never reads or touches the private key at all: a plan
// only ever needs to detect the certificate changing between planning
// and a future apply (see plan-v2.schema.json's own suppliedTls -
// ADR 0004), not to carry any key material itself.

import { readFile } from "node:fs/promises";

import { sha256 } from "./digest.mjs";

// manifest: a validated services.yml object. Returns undefined for
// every tls.mode except "supplied" (buildPlanV2() requires exactly
// that - present iff supplied, absent otherwise). Propagates a real
// read failure (missing/unreadable file) rather than treating it as
// "no certificate" - a supplied-mode deployment with an unreadable
// certificate must never silently plan as if TLS weren't configured.
export async function suppliedTlsCertificateFingerprint(manifest) {
  if (manifest.tls.mode !== "supplied") return undefined;
  const bytes = await readFile(manifest.tls.certificatePath);
  return sha256(bytes);
}
