#!/usr/bin/env node
// examples/release-lock.json's catalogDigest/composeTemplateDigest go
// stale every time catalog/services-v1.yaml or render-topology.mjs
// changes - previously a manual sha256+edit step, repeated (and missed)
// several times. Run this after touching either file.

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sha256(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

const lockPath = path.join(root, "examples/release-lock.json");
const [catalogBytes, templateBytes, lockBytes] = await Promise.all([
  readFile(path.join(root, "catalog/services-v1.yaml")),
  readFile(path.join(root, "scripts/render-topology.mjs")),
  readFile(lockPath),
]);

// Targeted string replacement, not a JSON.parse/stringify round-trip -
// the file's hand-curated formatting (single-line `database: {...}`
// entries) isn't what JSON.stringify would reproduce, and rewriting the
// whole file on every digest bump would bury the real diff in noise.
const catalogDigest = sha256(catalogBytes);
const composeTemplateDigest = sha256(templateBytes);
const text = lockBytes.toString("utf8");
const updated = text
  .replace(/("catalogDigest":\s*")[^"]*(")/, `$1${catalogDigest}$2`)
  .replace(/("composeTemplateDigest":\s*")[^"]*(")/, `$1${composeTemplateDigest}$2`);

await writeFile(lockPath, updated);
console.log(updated === text ? "examples/release-lock.json digests already current" : "examples/release-lock.json digests updated");
