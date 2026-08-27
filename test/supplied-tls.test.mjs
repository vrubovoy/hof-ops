import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { suppliedTlsCertificateFingerprint } from "../scripts/supplied-tls.mjs";

test("returns undefined for acme-http01 - never reads a certificatePath that doesn't apply", async () => {
  assert.equal(await suppliedTlsCertificateFingerprint({ tls: { mode: "acme-http01", email: "a@example.com" } }), undefined);
});

test("returns the real sha256 of the real certificate file, read from the workstation path services.yml itself names", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-supplied-tls-"));
  try {
    const certificatePath = path.join(directory, "fullchain.pem");
    const content = "-----BEGIN CERTIFICATE-----\nfake-but-real-file-content\n-----END CERTIFICATE-----\n";
    await writeFile(certificatePath, content);
    const expected = `sha256:${createHash("sha256").update(content).digest("hex")}`;

    const fingerprint = await suppliedTlsCertificateFingerprint({ tls: { mode: "supplied", certificatePath, privateKeyPath: "/unused/for/this/test" } });
    assert.equal(fingerprint, expected);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a genuinely missing certificate file propagates a real read error, never silently treated as 'no TLS configured'", async () => {
  await assert.rejects(
    () => suppliedTlsCertificateFingerprint({ tls: { mode: "supplied", certificatePath: "/definitely/does/not/exist.pem", privateKeyPath: "/unused" } }),
  );
});

test("never touches the private key - a certificatePath-only manifest still resolves fine", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hof-supplied-tls-nokey-"));
  try {
    const certificatePath = path.join(directory, "fullchain.pem");
    await writeFile(certificatePath, "cert-content");
    const fingerprint = await suppliedTlsCertificateFingerprint({ tls: { mode: "supplied", certificatePath, privateKeyPath: "/definitely/does/not/exist/private-key.pem" } });
    assert.match(fingerprint, /^sha256:[0-9a-f]{64}$/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
