// The "local supplied TLS" half of item 8's planning contract - reads,
// validates, and hashes the operator's own certificate+private key
// files, exactly where services.yml's own tls.certificatePath/
// privateKeyPath already say they live (on the WORKSTATION, matching
// ADR 0001 - the control plane runs there, not on the target).
//
// A 2026-08-28 review (PLATFORM-OPS-PLAN.md's "Item 8 reopened" entry)
// found this material was never actually validated at all - only the
// certificate's own bytes were hashed, the private key was never even
// read, and the rendered Compose file bind-mounted the WORKSTATION path
// directly into a target-side volume definition (a real, confirmed bug:
// Compose runs on the target, not the workstation - see
// render-topology.mjs's own fixed-path fix). Fixed here: this module
// now genuinely parses the certificate (Node's builtin X509Certificate,
// no new dependency), confirms the private key actually corresponds to
// it (X509Certificate.checkPrivateKey - the standard way to prove a key
// pair matches without hand-rolling ASN.1/modulus comparison), checks
// the certificate is currently valid, and confirms its Subject
// Alternative Name covers every public hostname this deployment will
// actually serve (exact or wildcard match) - not just the bare base
// domain, since most deployments serve several service subdomains under
// one shared gateway.

import { X509Certificate, createPrivateKey } from "node:crypto";
import { readFile } from "node:fs/promises";

import { sha256 } from "./digest.mjs";
import { publicHostnames } from "./render-topology.mjs";

function parseSanDnsEntries(subjectAltName) {
  return (subjectAltName ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("DNS:"))
    .map((entry) => entry.slice("DNS:".length));
}

// A single-label wildcard only (`*.example.com` matches `foo.example.com`,
// never `foo.bar.example.com` and never the bare `example.com` itself) -
// the same scope every real TLS client enforces (RFC 6125).
function sanCoversHostname(dnsEntries, hostname) {
  if (dnsEntries.includes(hostname)) return true;
  return dnsEntries.some((entry) => {
    if (!entry.startsWith("*.")) return false;
    const suffix = entry.slice(1); // ".example.com"
    if (!hostname.endsWith(suffix) || hostname.length <= suffix.length) return false;
    return !hostname.slice(0, -suffix.length).includes(".");
  });
}

// manifest/catalog: a validated services.yml object and the release-owned
// catalog (needed to compute the exact set of public hostnames this
// deployment serves - see publicHostnames()). Returns undefined for
// every tls.mode except "supplied". Throws a real, descriptive error for
// every other real problem (unreadable file, unparseable certificate/
// key, a key that doesn't match the certificate, an expired/not-yet-
// valid certificate, a SAN that doesn't cover every hostname this
// deployment will actually serve) - never silently treated as "no TLS
// configured" or "close enough".
export async function readSuppliedTlsMaterial(manifest, catalog) {
  if (manifest.tls.mode !== "supplied") return undefined;

  const [certificatePem, privateKeyPem] = await Promise.all([
    readFile(manifest.tls.certificatePath),
    readFile(manifest.tls.privateKeyPath),
  ]);

  let certificate;
  try {
    certificate = new X509Certificate(certificatePem);
  } catch (error) {
    throw new Error(`the supplied TLS certificate at ${manifest.tls.certificatePath} could not be parsed as a real X.509 certificate: ${error instanceof Error ? error.message : error}`);
  }

  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch (error) {
    throw new Error(`the supplied TLS private key at ${manifest.tls.privateKeyPath} could not be parsed as a real private key: ${error instanceof Error ? error.message : error}`);
  }

  if (!certificate.checkPrivateKey(privateKey)) {
    throw new Error(`the supplied TLS private key at ${manifest.tls.privateKeyPath} does not correspond to the certificate's own public key at ${manifest.tls.certificatePath} - refusing to plan or apply a mismatched key pair`);
  }

  const now = new Date();
  const validFrom = new Date(certificate.validFrom);
  const validTo = new Date(certificate.validTo);
  if (now < validFrom || now > validTo) {
    throw new Error(`the supplied TLS certificate at ${manifest.tls.certificatePath} is not currently valid (validFrom ${certificate.validFrom}, validTo ${certificate.validTo}, now ${now.toISOString()})`);
  }

  const dnsEntries = parseSanDnsEntries(certificate.subjectAltName);
  const hostnames = publicHostnames(manifest, catalog);
  const uncovered = hostnames.filter((hostname) => !sanCoversHostname(dnsEntries, hostname));
  if (uncovered.length > 0) {
    throw new Error(`the supplied TLS certificate at ${manifest.tls.certificatePath} does not cover ${uncovered.join(", ")} in its Subject Alternative Name (found: ${certificate.subjectAltName || "none"}) - the gateway would refuse to serve those hostnames over TLS`);
  }

  return {
    certificateFingerprint: sha256(certificatePem),
    // Never the key material's own digest reaching anywhere durable by
    // itself being sensitive - a sha256 of a private key is a public,
    // safe-to-record fingerprint (like a certificate's), not the key.
    privateKeyFingerprint: sha256(privateKeyPem),
    certificatePem: certificatePem.toString("utf8"),
    privateKeyPem: privateKeyPem.toString("utf8"),
  };
}
