#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, values) => {
  if (index % 2 === 0) pairs.push([value.replace(/^--/, ""), values[index + 1]]);
  return pairs;
}, []));

if (!args.release || !args.lock || !args.out || !args.repository) {
  throw new Error("--release, --lock, --out, and --repository are required");
}

const lockBytes = await readFile(args.lock);
const lock = JSON.parse(lockBytes);
if (lock.release !== args.release) throw new Error("channel release does not match release lock");
const metadata = {
  apiVersion: "hof.dev/channel/v1",
  channel: "stable",
  release: args.release,
  tag: `v${args.release}`,
  releaseLockDigest: "sha256:" + createHash("sha256").update(lockBytes).digest("hex"),
  releaseUrl: `https://github.com/${args.repository}/releases/tag/v${args.release}`,
};
const schema = JSON.parse(await readFile(path.join(root, "schemas/stable-channel-v1.schema.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
if (!validate(metadata)) throw new Error(ajv.errorsText(validate.errors));
await writeFile(args.out, JSON.stringify(metadata, null, 2) + "\n");
