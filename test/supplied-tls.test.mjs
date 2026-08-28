// Real self-signed certificates (via a real `openssl req -x509`), not
// fixture strings - a 2026-08-28 review found this module previously
// only ever hashed the certificate's raw bytes, never actually parsed
// or validated it, and never even read the private key at all (see
// this module's own top comment for the full history). Proving the fix
// needs a genuine X.509 certificate/key pair to parse, key-match,
// validity-check, and SAN-check against - a hand-written "cert-content"
// string (the old tests' own fixture) would prove nothing about any of
// that.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { loadContracts } from "../scripts/contracts.mjs";
import { readSuppliedTlsMaterial } from "../scripts/supplied-tls.mjs";

const exec = promisify(execFile);

let workDir;
let manifest;
let catalog;
let fileCounter = 0;

test.before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "hof-supplied-tls-"));
  ({ manifest, catalog } = structuredClone(await loadContracts()));
});

test.after(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

function opensslTimestamp(date) {
  // OpenSSL's own [CC]YYMMDDHHMMSSZ format - no "-"/":"/"T" separators.
  return date.toISOString().replace(/[-:T]/g, "").split(".")[0] + "Z";
}

// Every real hostname this repo's own bundled examples/services.yml +
// catalog actually serves - computed once, from the real manifest/
// catalog this whole file plans against, never hand-duplicated (see
// render-topology.mjs's own publicHostnames()).
async function realPublicHostnames() {
  const { publicHostnames } = await import("../scripts/render-topology.mjs");
  return publicHostnames(manifest, catalog);
}

async function generateKeyAndCert({ san, notBefore, notAfter } = {}) {
  fileCounter += 1;
  const keyPath = path.join(workDir, `key-${fileCounter}.pem`);
  const certPath = path.join(workDir, `cert-${fileCounter}.pem`);
  const args = [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath,
    "-subj", "/CN=example.com",
    "-addext", `subjectAltName=${san ?? "DNS:example.com,DNS:*.example.com"}`,
  ];
  if (notBefore) args.push("-not_before", notBefore);
  if (notAfter) args.push("-not_after", notAfter);
  else args.push("-days", "1");
  await exec("openssl", args);
  return { keyPath, certPath };
}

function suppliedManifest({ certificatePath, privateKeyPath }) {
  return { ...manifest, tls: { mode: "supplied", certificatePath, privateKeyPath } };
}

test("returns undefined for acme-http01 - never reads a certificatePath that doesn't apply", async () => {
  const result = await readSuppliedTlsMaterial({ ...manifest, tls: { mode: "acme-http01", email: "a@example.com" } }, catalog);
  assert.equal(result, undefined);
});

test("a real, valid, matching certificate+key whose SAN covers every public hostname resolves with real fingerprints and PEM content", async () => {
  const { keyPath, certPath } = await generateKeyAndCert();
  const material = await readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog);
  assert.match(material.certificateFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.match(material.privateKeyFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(material.certificateFingerprint, material.privateKeyFingerprint);
  assert.match(material.certificatePem, /-----BEGIN CERTIFICATE-----/);
  assert.match(material.privateKeyPem, /-----BEGIN (RSA )?PRIVATE KEY-----/);
});

test("a genuinely missing certificate file propagates a real read error, never silently treated as 'no TLS configured'", async () => {
  const { keyPath } = await generateKeyAndCert();
  await assert.rejects(() => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: "/definitely/does/not/exist.pem", privateKeyPath: keyPath }), catalog));
});

test("a genuinely missing private key file propagates a real read error - the key is now actually read, unlike before this fix", async () => {
  const { certPath } = await generateKeyAndCert();
  await assert.rejects(() => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: "/definitely/does/not/exist-key.pem" }), catalog));
});

test("a certificate file that isn't real X.509 content is refused, not silently trusted", async () => {
  const certPath = path.join(workDir, "not-a-cert.pem");
  await writeFile(certPath, "-----BEGIN CERTIFICATE-----\nnot real certificate content\n-----END CERTIFICATE-----\n");
  const { keyPath } = await generateKeyAndCert();
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    /could not be parsed as a real X\.509 certificate/,
  );
});

test("a private key file that isn't a real key is refused", async () => {
  const { certPath } = await generateKeyAndCert();
  const keyPath = path.join(workDir, "not-a-key.pem");
  await writeFile(keyPath, "-----BEGIN PRIVATE KEY-----\nnot real key content\n-----END PRIVATE KEY-----\n");
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    /could not be parsed as a real private key/,
  );
});

test("a private key that genuinely does not correspond to the certificate is refused - the real key-match check", async () => {
  const { certPath } = await generateKeyAndCert();
  const { keyPath: unrelatedKeyPath } = await generateKeyAndCert(); // a second, independent key pair
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: unrelatedKeyPath }), catalog),
    /does not correspond to the certificate's own public key/,
  );
});

test("an expired certificate is refused, not silently trusted", async () => {
  const { keyPath, certPath } = await generateKeyAndCert({ notBefore: "20200101000000Z", notAfter: "20200102000000Z" });
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    /is not currently valid/,
  );
});

test("a not-yet-valid certificate (notBefore in the future) is refused", async () => {
  const notBefore = opensslTimestamp(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000));
  const notAfter = opensslTimestamp(new Date(Date.now() + 366 * 24 * 60 * 60 * 1000));
  const { keyPath, certPath } = await generateKeyAndCert({ notBefore, notAfter });
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    /is not currently valid/,
  );
});

test("a certificate whose SAN doesn't cover any of this deployment's real public hostnames is refused, naming what's missing", async () => {
  const { keyPath, certPath } = await generateKeyAndCert({ san: "DNS:totally-unrelated.example.net" });
  const hostnames = await realPublicHostnames();
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    (error) => {
      assert.match(error.message, /does not cover/);
      for (const hostname of hostnames) assert.ok(error.message.includes(hostname), `expected the missing-hostname list to name ${hostname}`);
      return true;
    },
  );
});

test("a wildcard-only SAN covers every subdomain but not the bare apex domain on its own - real RFC 6125 wildcard scope, not a broader match", async () => {
  const { keyPath, certPath } = await generateKeyAndCert({ san: "DNS:*.example.com" }); // no bare example.com
  await assert.rejects(
    () => readSuppliedTlsMaterial(suppliedManifest({ certificatePath: certPath, privateKeyPath: keyPath }), catalog),
    (error) => {
      // schloss has no catalog hostname of its own, so publicHostnames()
      // includes the bare domains.base ("example.com") for it - a
      // wildcard alone must not be treated as covering that.
      assert.match(error.message, /does not cover example\.com\b/);
      return true;
    },
  );
});
