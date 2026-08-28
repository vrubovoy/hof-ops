import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import YAML from "yaml";

// Lightweight, ansible-core-free structural checks for the pinned
// Execution Environment's baked-in roles (see ansible/README.md). The
// real behavioral verification (a genuine ansible-playbook run against
// every role) was done by hand against a real ansible-core install and
// is covered by the "ansible" CI job (.github/workflows/test.yml) and
// test/apply-acceptance.mjs - node --test's fast suite deliberately
// never assumes ansible-core is on PATH.

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const rolesDir = path.join(repoRoot, "ansible", "roles");

const roles = [
  "host",
  "secret",
  "volume",
  "network",
  "image",
  "config",
  "database",
  "service",
  "readiness",
  "state",
];

// host/secret/volume/network/image/config landed their real
// implementation in item 8's PR #28 - database/service/readiness/state
// are still the PR #26 skeleton (assert + not-yet-implemented), real
// implementation lands in PR #29. The two groups get different checks
// below; this list is the one place that distinction is recorded.
const SKELETON_ROLES = new Set(["database", "service", "readiness", "state"]);

// Every variable a role's tasks/main.yml asserts "is not none" for must
// also be declared (as null) in that same role's defaults/main.yml -
// the assert is only a real contract if every variable it checks has a
// documented default to override. Only ever applied to the skeleton
// roles below - a real role's own assert can express a richer condition
// than a flat "is not none" chain (see image's own hof_image_action
// enum check), which this simple parser deliberately doesn't attempt
// to generalize.
function assertedVariables(tasksYaml) {
  const doc = YAML.parseAllDocuments(tasksYaml)[0].toJSON();
  const assertTask = doc.find(
    (task) => task["ansible.builtin.assert"] !== undefined,
  );
  assert.ok(assertTask, "tasks/main.yml has no ansible.builtin.assert task");
  const that = assertTask["ansible.builtin.assert"].that;
  assert.ok(Array.isArray(that) && that.length > 0);
  return that.map((expr) => {
    const match = /^(\S+) is not none$/.exec(expr);
    assert.ok(match, `unexpected assert expression shape: ${expr}`);
    return match[1];
  });
}

test("ansible/roles contains exactly the 10 plan operation-phase roles, nothing else", () => {
  const entries = readdirSync(rolesDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(entries, [...roles].sort());
});

function loadRoleFiles(role) {
  const roleDir = path.join(rolesDir, role);
  const defaultsPath = path.join(roleDir, "defaults", "main.yml");
  const tasksPath = path.join(roleDir, "tasks", "main.yml");
  assert.ok(existsSync(defaultsPath), `${defaultsPath} missing`);
  assert.ok(existsSync(tasksPath), `${tasksPath} missing`);
  const defaults = YAML.parse(readFileSync(defaultsPath, "utf8"));
  assert.ok(defaults && typeof defaults === "object", "defaults/main.yml must parse to an object");
  assert.ok("hof_operation_id" in defaults, "every role's operation carries hof_operation_id");
  for (const [key, value] of Object.entries(defaults)) {
    assert.equal(value, null, `defaults/main.yml declares ${key} but every default must be null until an operation supplies it`);
  }
  const tasksYaml = readFileSync(tasksPath, "utf8");
  // Every role's tasks/main.yml must at least parse as YAML (a real
  // syntax error here would otherwise only surface via a live
  // ansible-playbook run).
  const tasks = YAML.parseAllDocuments(tasksYaml)[0].toJSON();
  assert.ok(Array.isArray(tasks) && tasks.length > 0, "tasks/main.yml must be a non-empty task list");
  return { defaults, tasksYaml, tasks };
}

for (const role of roles) {
  if (SKELETON_ROLES.has(role)) {
    test(`role ${role} (skeleton): defaults/main.yml and tasks/main.yml parse and agree on the variable contract`, () => {
      const { defaults, tasksYaml } = loadRoleFiles(role);
      const asserted = assertedVariables(tasksYaml);
      assert.deepEqual(
        [...asserted].sort(),
        Object.keys(defaults).sort(),
        "tasks/main.yml's own assert must check exactly the variables defaults/main.yml declares - no more, no fewer",
      );
      // Every skeleton reports itself not-yet-implemented rather than
      // silently succeeding, and does so by name (never a generic
      // "not implemented" that could mask a mis-dispatched role).
      assert.ok(
        tasksYaml.includes(`${role} skeleton reached`) || tasksYaml.includes(`${role}.`),
        `tasks/main.yml for ${role} should identify itself by name in its not-yet-implemented message`,
      );
    });
  } else {
    test(`role ${role} (implemented): defaults/main.yml and tasks/main.yml parse, with a real assert gate`, () => {
      const { tasksYaml } = loadRoleFiles(role);
      assert.match(tasksYaml, /ansible\.builtin\.assert:/, `${role} must still assert its own required variables before doing real work`);
      assert.doesNotMatch(tasksYaml, /not yet implemented|skeleton reached/, `${role} is no longer a skeleton - PR #28 landed its real implementation`);
    });
  }
}

test("host role bootstraps python3 via raw before gathering facts, then installs Docker only when genuinely absent", () => {
  const { tasksYaml } = loadRoleFiles("host");
  assert.match(tasksYaml, /ansible\.builtin\.raw:/, "python3 bootstrap must use raw (no interpreter assumed present yet)");
  assert.match(tasksYaml, /ansible\.builtin\.setup:/);
  assert.match(tasksYaml, /docker-ce/);
  assert.match(tasksYaml, /when: hof_docker_check\.rc != 0/, "Docker install must be skipped when target-inspector.mjs already confirmed it's present");
});

test("secret role never logs secret content and delivers each value via a real SSH-transported copy, not extra-vars", () => {
  const { tasksYaml } = loadRoleFiles("secret");
  assert.match(tasksYaml, /no_log: true/);
  assert.match(tasksYaml, /ansible\.builtin\.copy:/);
  assert.match(tasksYaml, /lookup\('file', hof_secrets_file\)/);
});

test("volume/network roles label resources with the exact same set render-topology.mjs's own resourceOwnershipLabels() produces", () => {
  for (const role of ["volume", "network"]) {
    const { tasksYaml } = loadRoleFiles(role);
    for (const label of ["hof.managed", "hof.installation-id", "hof.generation", "hof.kind", "hof.resource"]) {
      assert.ok(tasksYaml.includes(label), `${role} role is missing label ${label}`);
    }
  }
});

test("image role verifies signed images with cosign delegated to the control node, trusts digest-only by pin alone, and pulls on the real target", () => {
  const { tasksYaml } = loadRoleFiles("image");
  assert.match(tasksYaml, /delegate_to: localhost/);
  assert.match(tasksYaml, /cosign/);
  assert.match(tasksYaml, /hof_image_trust\.policy == "digest-only"/);
  assert.match(tasksYaml, /community\.docker\.docker_image:/);
});

test("config role delivers exactly the fixed generated-artifact filenames, discovered rather than hardcoded", () => {
  const { tasksYaml } = loadRoleFiles("config");
  assert.match(tasksYaml, /ansible\.builtin\.find:/);
  assert.match(tasksYaml, /delegate_to: localhost/);
  assert.match(tasksYaml, /\/etc\/hof\/generated/);
});

test("ansible/requirements.yml pins the exact collections the roles' own README/defaults comments promise", () => {
  const requirements = YAML.parse(
    readFileSync(path.join(repoRoot, "ansible", "requirements.yml"), "utf8"),
  );
  const names = requirements.collections.map((c) => c.name).sort();
  assert.deepEqual(names, [
    "ansible.posix",
    "community.crypto",
    "community.docker",
  ]);
  for (const collection of requirements.collections) {
    assert.match(
      collection.version,
      /^\d+\.\d+\.\d+$/,
      `${collection.name} must pin an exact version, not a range`,
    );
  }
});

test("ansible/ansible.cfg enables host key checking and disables retry files", () => {
  const cfg = readFileSync(path.join(repoRoot, "ansible", "ansible.cfg"), "utf8");
  assert.match(cfg, /host_key_checking\s*=\s*True/i);
  assert.match(cfg, /retry_files_enabled\s*=\s*False/i);
});

test("ansible/Dockerfile pins the base image and cosign by digest/checksum", () => {
  const dockerfile = readFileSync(
    path.join(repoRoot, "ansible", "Dockerfile"),
    "utf8",
  );
  assert.match(
    dockerfile,
    /^FROM python:3\.13-slim-bookworm@sha256:[0-9a-f]{64}/m,
  );
  assert.match(dockerfile, /ADD --checksum=sha256:[0-9a-f]{64}/);
  assert.match(dockerfile, /cosign-linux-amd64/);
});

test("examples/release-selection.yml's ansibleEnvironment tag namespace matches ansible/README.md's own documented convention", () => {
  const selection = YAML.parse(
    readFileSync(
      path.join(repoRoot, "examples", "release-selection.yml"),
      "utf8",
    ),
  );
  const env = selection.ansibleEnvironment;
  assert.ok(env, "release-selection.yml is missing ansibleEnvironment");
  assert.equal(env.repository, "vrubovoy/hof-ops");
  assert.equal(env.image, `ghcr.io/vrubovoy/hof-ops-ee:v${env.version}`);
  assert.ok(
    env.workflowIdentity.endsWith(`refs/tags/ee-v${env.version}`),
    "workflowIdentity must reference the ee-v-prefixed tag, never a plain v-tag",
  );
  assert.deepEqual(env.requiredChecks, ["ansible"]);
});
