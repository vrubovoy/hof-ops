#!/usr/bin/env node
import path from "node:path";
import process from "node:process";

import { renderFiles } from "./render-topology.mjs";

function usage(message) {
  if (message) console.error(message);
  console.error("usage: hofctl render --services <services.yml> --release-lock <release-lock.json> --catalog <catalog.yaml> --out <directory>");
  process.exitCode = 2;
}

const [command, ...args] = process.argv.slice(2);
if (command !== "render") usage(command ? `unknown command: ${command}` : "a command is required");
else {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || !value) { usage("render options must be --name value pairs"); break; }
    options[flag.slice(2).replaceAll("-", "")] = path.resolve(value);
  }
  const normalized = { services: options.services, releaseLock: options.releaselock, catalog: options.catalog, out: options.out };
  if (!process.exitCode && Object.values(normalized).some((value) => !value)) usage("render requires --services, --release-lock, --catalog, and --out");
  if (!process.exitCode) {
    try {
      const files = await renderFiles(normalized);
      console.log(`rendered ${files.join(", ")} to ${normalized.out}`);
    } catch (error) {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    }
  }
}
