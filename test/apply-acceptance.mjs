#!/usr/bin/env node
// Thin, guard-first entrypoint for `pnpm test:apply-ssh` (Item 10 PR 0
// review, Low finding). The real suite lives in ./apply-acceptance.impl.mjs
// and is loaded ONLY after the privileged opt-in is confirmed here -
// before any of its static imports, its before() hook, or any docker /
// image-build / network call it makes.
//
// ./apply-acceptance.impl.mjs builds and runs a --privileged systemd
// container; it has, once, disrupted a real developer desktop (see that
// module's before() hook note). It is safe only on a disposable,
// single-purpose CI VM. Without HOF_ALLOW_PRIVILEGED_ACCEPTANCE=1 this
// process is a deliberate no-op.
//
// test/apply-acceptance-guard.test.mjs runs this file as a subprocess
// with the flag unset and asserts the impl module never loads.

if (process.env.HOF_ALLOW_PRIVILEGED_ACCEPTANCE !== "1") {
  console.log("# test:apply-ssh skipped - privileged Docker acceptance is opt-in.");
  console.log("# Set HOF_ALLOW_PRIVILEGED_ACCEPTANCE=1 to run it (spins a --privileged systemd container; CI-only).");
  process.exit(0);
}

await import("./apply-acceptance.impl.mjs");
