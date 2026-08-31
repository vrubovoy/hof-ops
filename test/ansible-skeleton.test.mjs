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

// All ten roles landed their real implementation across item 8's
// PR #28 (host/secret/volume/network/image/config) and PR #29
// (database/service/readiness/state) - none are still the PR #26
// skeleton (assert + not-yet-implemented).

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
  test(`role ${role}: defaults/main.yml and tasks/main.yml parse, with a real assert gate`, () => {
    const { tasksYaml } = loadRoleFiles(role);
    assert.match(tasksYaml, /ansible\.builtin\.assert:/, `${role} must still assert its own required variables before doing real work`);
    assert.doesNotMatch(tasksYaml, /not yet implemented|skeleton reached/, `${role} is no longer a skeleton - its real implementation has landed`);
  });
}

test("host role bootstraps python3 via raw before gathering facts, then installs Docker only when genuinely absent", () => {
  const { tasksYaml } = loadRoleFiles("host");
  assert.match(tasksYaml, /ansible\.builtin\.raw:/, "python3 bootstrap must use raw (no interpreter assumed present yet)");
  assert.match(tasksYaml, /ansible\.builtin\.setup:/);
  assert.match(tasksYaml, /docker-ce/);
  assert.match(tasksYaml, /when: hof_docker_check\.rc != 0/, "Docker install must be skipped when target-inspector.mjs already confirmed it's present");
});

test("host role checks and installs the Compose plugin independently of Engine's own presence - a real gap found in a 2026-08-28 review", () => {
  const { tasksYaml } = loadRoleFiles("host");
  assert.match(tasksYaml, /docker compose version/, "must independently probe for the Compose plugin, not just `docker --version`");
  assert.match(tasksYaml, /when: hof_compose_check\.rc != 0/, "the plugin install itself must be gated on hof_compose_check alone");
  // The actual install task (docker-compose-plugin as an apt package
  // name, not just mentioned in a comment) must exist as its own task -
  // never nested only inside the Engine-absent block, which is exactly
  // the real gap a 2026-08-28 review found: an Engine-present-but-
  // Compose-absent target silently never got it installed.
  const tasks = YAML.parseAllDocuments(tasksYaml)[0].toJSON();
  const composeInstallTask = tasks.find((t) => t["ansible.builtin.apt"]?.name === "docker-compose-plugin");
  assert.ok(composeInstallTask, "must have its own dedicated task installing docker-compose-plugin");
  assert.equal(composeInstallTask.when, "hof_compose_check.rc != 0");
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

test("database role runs a migration via `docker compose run`, reusing the service's own already-rendered definition, never a bare docker run", () => {
  const { tasksYaml } = loadRoleFiles("database");
  assert.match(tasksYaml, /docker compose|'docker', 'compose'/);
  assert.match(tasksYaml, /--no-deps/);
  assert.match(tasksYaml, /hof_migrate_argv/);
});

test("service role starts exactly one Compose unit, scoped with --no-deps and never re-pulling", () => {
  const { tasksYaml } = loadRoleFiles("service");
  assert.match(tasksYaml, /--no-deps/);
  assert.match(tasksYaml, /--pull/);
  assert.match(tasksYaml, /hof_service_unit/);
});

// Item 9 (ADR 0005): stop/remove discover their own target container by
// the exact same four labels a real ownership check needs - never just
// project+service (that pair alone can't distinguish two DIFFERENT
// installations' same-named unit on a shared host), zero matches is
// idempotent, more than one is refused as corruption, and neither
// action ever runs `compose down` or touches a volume.
test("service role's stop/remove actions discover by hof.managed + installationId + unit + Compose project, treat zero matches as idempotent, and refuse more than one", () => {
  const { tasksYaml } = loadRoleFiles("service");
  for (const label of ["label=hof.managed=true", "label=hof.installation-id=", "label=hof.unit=", "label=com.docker.compose.project=hof"]) {
    assert.ok(tasksYaml.includes(label), `service role's stop/remove discovery is missing ${label}`);
  }
  assert.match(tasksYaml, /docker\s*\n\s*-\s*stop/, "stop must dispatch a real `docker stop`");
  assert.match(tasksYaml, /docker\s*\n\s*-\s*rm/, "remove must dispatch a real `docker rm`, never `compose down`");
  assert.doesNotMatch(tasksYaml, /compose\s*\n\s*-\s*down/, "service role must never run a project-wide `compose down`");
  assert.doesNotMatch(tasksYaml, /--volumes|docker volume rm/, "service role must never remove a volume");
  assert.match(tasksYaml, /length > 1/, "more than one discovered container must be refused, not guessed at");
});

test("readiness role discovers the container by its own real Compose labels and polls docker inspect's JSON, never a Go-template format string", () => {
  const { tasksYaml } = loadRoleFiles("readiness");
  assert.match(tasksYaml, /com\.docker\.compose\.project=hof/);
  assert.match(tasksYaml, /com\.docker\.compose\.service=/);
  assert.match(tasksYaml, /from_json/);
  assert.match(tasksYaml, /until:/);
});

test("state role writes topology.json before current.json, both via ansible.builtin.copy's own atomic write-then-rename", () => {
  const { tasksYaml } = loadRoleFiles("state");
  const topologyIndex = tasksYaml.indexOf("dest: /var/lib/hof/state/topology.json");
  const currentIndex = tasksYaml.indexOf("dest: /var/lib/hof/state/current.json");
  assert.ok(topologyIndex > 0 && currentIndex > 0, "both files must be written");
  assert.ok(topologyIndex < currentIndex, "topology.json must be written before current.json - see ADR 0004 and state.mjs's own resolveBaseline() corruption check");
  const copyCount = (tasksYaml.match(/ansible\.builtin\.copy:/g) ?? []).length;
  // Item 9 (ADR 0005) added three more copies - the immutable per-
  // generation snapshot (state.json, topology.json, release-lock.json)
  // - on top of the original two pointer-file writes.
  assert.equal(copyCount, 5, "5 copies: 3 immutable generation-snapshot files + 2 pointer files, all via copy's own atomic semantics");
});

// Item 9 (ADR 0005): the immutable per-generation snapshot -
// {state,topology,release-lock}.json under generations/NNNNNN/ - must
// be fully published BEFORE either pointer file is touched, and a
// generation number that already has a snapshot on disk must never be
// silently overwritten with different content.
test("state role publishes the immutable per-generation snapshot before either pointer file, and refuses to overwrite one with different content", () => {
  const { tasksYaml } = loadRoleFiles("state");
  for (const filename of ["state.json", "topology.json", "release-lock.json"]) {
    assert.ok(tasksYaml.includes(`generations/`) && tasksYaml.includes(`/${filename}`), `generation snapshot must include ${filename}`);
  }
  const snapshotStateIndex = tasksYaml.indexOf("hof_state_generation_dir }}/state.json");
  const snapshotTopologyIndex = tasksYaml.indexOf("hof_state_generation_dir }}/topology.json");
  const snapshotReleaseLockIndex = tasksYaml.indexOf("hof_state_generation_dir }}/release-lock.json");
  const pointerTopologyIndex = tasksYaml.indexOf("dest: /var/lib/hof/state/topology.json");
  const pointerCurrentIndex = tasksYaml.indexOf("dest: /var/lib/hof/state/current.json");
  assert.ok(
    snapshotStateIndex > 0 && snapshotTopologyIndex > 0 && snapshotReleaseLockIndex > 0,
    "all three immutable snapshot files must be written",
  );
  assert.ok(
    snapshotStateIndex < pointerTopologyIndex && snapshotTopologyIndex < pointerTopologyIndex && snapshotReleaseLockIndex < pointerTopologyIndex,
    "the immutable generation snapshot must be fully published before either pointer file",
  );
  assert.ok(pointerTopologyIndex < pointerCurrentIndex, "the pointer files themselves keep ADR 0004's own ordering unchanged");
  // Zero-padded, arbitrary positive generation - never a fixed constant.
  assert.match(tasksYaml, /'%06d'\s*\|\s*format\(hof_state_generation\s*\|\s*int\)/, "the snapshot directory name must be zero-padded from the real generation, not hardcoded");
  // Idempotent-if-identical, blocked-if-different, appliedAt excluded.
  assert.match(tasksYaml, /appliedAt/, "the identical-content check must exclude appliedAt - never expected to match across a genuine retry");
  assert.match(tasksYaml, /hof_state_generation_existing == hof_state_generation_incoming/, "an existing snapshot's content must be compared, not assumed");
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

// The CI "ansible" job's own --syntax-check fixture (.github/workflows/
// test.yml) carries ONE shared vars block across all 10 roles - a var a
// role's own defaults/main.yml declares but this shared block never
// mentions would leave that variable None under the fixture's own
// include_role loop, exactly the shape of gap this item 9's own new
// hof_service_action var could have silently reintroduced. Every
// role's own key (other than hof_operation_id, whose single shared
// value already covers every role) must appear in the fixture's vars.
test("the CI workflow's own --syntax-check fixture declares every var every role's defaults/main.yml actually needs", () => {
  const workflow = readFileSync(path.join(repoRoot, ".github", "workflows", "test.yml"), "utf8");
  const fixtureMatch = workflow.match(/cat > \/tmp\/hof-role-syntax-check\.yml << 'PLAYBOOK'\n([\s\S]*?)\n[ \t]*PLAYBOOK/);
  assert.ok(fixtureMatch, "could not locate the embedded --syntax-check fixture playbook in .github/workflows/test.yml");
  // The embedded heredoc carries the workflow YAML's own common leading
  // indentation on every line (it's nested inside a `run: |` block) -
  // stripped here so the extracted text parses as a standalone document.
  const rawLines = fixtureMatch[1].split("\n");
  const commonIndent = Math.min(...rawLines.filter((line) => line.trim().length > 0).map((line) => line.match(/^ */)[0].length));
  const dedented = rawLines.map((line) => line.slice(commonIndent)).join("\n");
  const fixturePlaybook = YAML.parse(dedented);
  const fixtureVars = fixturePlaybook[0].tasks[0].vars;
  assert.ok(fixtureVars && typeof fixtureVars === "object", "fixture playbook's own vars block must parse as an object");

  for (const role of roles) {
    const { defaults } = loadRoleFiles(role);
    for (const key of Object.keys(defaults)) {
      assert.ok(key in fixtureVars, `${role} role's defaults/main.yml declares ${key}, but the CI syntax-check fixture never sets it`);
    }
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
