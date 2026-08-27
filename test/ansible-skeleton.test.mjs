import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import YAML from "yaml";

// Lightweight, ansible-core-free structural checks for the pinned
// Execution Environment's baked-in roles (see ansible/README.md). The
// real behavioral verification (a genuine ansible-playbook run against
// every role, both a passing and a deliberate assert-failure case) was
// done by hand against a real ansible-core install, not reproduced here
// - node --test's fast suite deliberately never assumes ansible-core is
// on PATH (see the "ansible" CI job in .github/workflows/test.yml for
// that real execution instead).

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

// Every variable a role's tasks/main.yml asserts "is not none" for must
// also be declared (as null) in that same role's defaults/main.yml -
// the assert is only a real contract if every variable it checks has a
// documented default to override.
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

for (const role of roles) {
  test(`role ${role}: defaults/main.yml and tasks/main.yml parse and agree on the variable contract`, () => {
    const roleDir = path.join(rolesDir, role);
    const defaultsPath = path.join(roleDir, "defaults", "main.yml");
    const tasksPath = path.join(roleDir, "tasks", "main.yml");
    assert.ok(existsSync(defaultsPath), `${defaultsPath} missing`);
    assert.ok(existsSync(tasksPath), `${tasksPath} missing`);

    const defaults = YAML.parse(readFileSync(defaultsPath, "utf8"));
    assert.ok(
      defaults && typeof defaults === "object",
      "defaults/main.yml must parse to an object",
    );
    assert.ok(
      "hof_operation_id" in defaults,
      "every role's operation carries hof_operation_id",
    );
    for (const [key, value] of Object.entries(defaults)) {
      assert.equal(
        value,
        null,
        `defaults/main.yml declares ${key} but every default must be null until an operation supplies it`,
      );
    }

    const tasksYaml = readFileSync(tasksPath, "utf8");
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
      tasksYaml.includes(`${role} skeleton reached`) ||
        tasksYaml.includes(`${role}.`),
      `tasks/main.yml for ${role} should identify itself by name in its not-yet-implemented message`,
    );
  });
}

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

test("ansible/Dockerfile pins the base image by digest", () => {
  const dockerfile = readFileSync(
    path.join(repoRoot, "ansible", "Dockerfile"),
    "utf8",
  );
  assert.match(
    dockerfile,
    /^FROM python:3\.13-slim-bookworm@sha256:[0-9a-f]{64}/m,
  );
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
