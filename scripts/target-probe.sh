#!/bin/sh
# HOF-PROBE-V1 - a single, fixed, versioned, read-only probe run on the
# target host (over SSH via `sh -s`, or locally under --target-mode
# local). Never takes arguments, manifest values, or any other
# caller-supplied input - the one thing this script does is describe the
# host it's running on, in a small fixed protocol target-inspector.mjs
# parses. No secrets, no Config.Env, no bind-mount source paths, no
# arbitrary shell.
#
# Protocol: line 1 is the literal version marker. Every following line
# is either "R <name> <base64-payload>" or the final literal "END".
# Record names are a fixed vocabulary (see target-inspector.mjs's own
# RECORD_NAMES) - singletons (os/arch/cpu/memory/disk/clock/sudo/docker/
# state-current/state-topology/generated-artifacts) appear at most once,
# "port"/"container" repeat. Anything else, or EOF before END, is a
# protocol error on the parsing side, deliberately - a truncated or
# malformed transcript must never be interpreted as "everything's fine".
set -eu

b64() {
  printf '%s' "$1" | base64 | tr -d '\n'
}

record() {
  printf 'R %s %s\n' "$1" "$(b64 "$2")"
}

echo 'HOF-PROBE-V1'

# --- os / arch --------------------------------------------------------
if [ -r /etc/os-release ]; then
  os_id=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
  os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-unknown}")
  record os "${os_id}|${os_version}"
fi
record arch "$(uname -m)"

# --- cpu / memory / disk ----------------------------------------------
if command -v nproc >/dev/null 2>&1; then
  record cpu "$(nproc)"
elif command -v getconf >/dev/null 2>&1; then
  record cpu "$(getconf _NPROCESSORS_ONLN)"
fi

mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || true)
if [ -n "${mem_kb:-}" ]; then
  record memory "$((mem_kb * 1024))"
fi

# Free space where Hof actually keeps its state/data - /var/lib, not /,
# since that's the mount that matters for volumes and generated state.
disk_kb=$(df -Pk /var/lib 2>/dev/null | awk 'NR==2 { print $4 }' || true)
if [ -n "${disk_kb:-}" ]; then
  record disk "$((disk_kb * 1024))"
fi

# --- clock / sudo -------------------------------------------------------
if command -v timedatectl >/dev/null 2>&1; then
  synced=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
  case "$synced" in
    yes) record clock yes ;;
    no) record clock no ;;
    *) record clock unknown ;;
  esac
else
  record clock unknown
fi

if sudo -n true >/dev/null 2>&1; then
  record sudo yes
else
  record sudo no
fi

# --- listening ports (state only - "who owns it" is resolved later by
# cross-referencing this same snapshot's own container records, not by
# a privileged process lookup here) --------------------------------
for port in 80 443; do
  if command -v ss >/dev/null 2>&1; then
    listening=$(ss -H -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" { found=1 } END { print found+0 }')
  elif command -v netstat >/dev/null 2>&1; then
    listening=$(netstat -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" { found=1 } END { print found+0 }')
  else
    listening=""
  fi
  if [ "$listening" = "1" ]; then
    record port "${port}|occupied"
  elif [ "$listening" = "0" ]; then
    record port "${port}|free"
  else
    record port "${port}|unknown"
  fi
done

# --- docker -------------------------------------------------------------
docker_engine=""
docker_compose=""
if command -v docker >/dev/null 2>&1; then
  docker_engine=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
  docker_compose=$(docker compose version --short 2>/dev/null || true)
fi
record docker "${docker_engine}|${docker_compose}"

# One inspect call per container, whitelisted fields only, \x1f-joined
# (never a character any of these values can legitimately contain) -
# never Config.Env, command/entrypoint, logs, arbitrary labels, or a
# bind-mount source path.
if command -v docker >/dev/null 2>&1; then
  sep=$(printf '\037')
  fmt="{{.Name}}${sep}{{.Config.Image}}${sep}{{.State.Status}}${sep}{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}${sep}{{index .Config.Labels \"hof.managed\"}}${sep}{{index .Config.Labels \"hof.installation-id\"}}${sep}{{index .Config.Labels \"hof.service\"}}${sep}{{index .Config.Labels \"hof.unit\"}}${sep}{{index .Config.Labels \"hof.artifact\"}}${sep}{{index .Config.Labels \"hof.generation\"}}${sep}{{index .Config.Labels \"com.docker.compose.project\"}}${sep}{{index .Config.Labels \"com.docker.compose.service\"}}${sep}{{range \$n,\$c := .NetworkSettings.Networks}}{{\$n}},{{end}}${sep}{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}},{{end}}{{end}}${sep}{{range \$p,\$b := .NetworkSettings.Ports}}{{range \$b}}{{.HostPort}},{{end}}{{end}}"
  docker ps -aq 2>/dev/null | while IFS= read -r id; do
    line=$(docker inspect --format "$fmt" "$id" 2>/dev/null || true)
    [ -n "$line" ] && record container "$line"
  done
fi

# --- managed state (opaque JSON, never parsed here) ---------------------
if [ -r /var/lib/hof/state/current.json ]; then
  record state-current "$(cat /var/lib/hof/state/current.json)"
else
  record state-current ""
fi
if [ -r /var/lib/hof/state/topology.json ]; then
  record state-topology "$(cat /var/lib/hof/state/topology.json)"
else
  record state-topology ""
fi

# --- generated artifact checksums (fixed filename list, never a
# caller-supplied path) ---------------------------------------------
artifacts_json="{"
first=1
for name in compose.yml Caddyfile service.env runtime-config.json backup-inventory.json; do
  path="/etc/hof/generated/${name}"
  if [ -r "$path" ] && command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$path" | awk '{ print $1 }')
    [ "$first" = 1 ] || artifacts_json="${artifacts_json},"
    artifacts_json="${artifacts_json}\"${name}\":\"sha256:${sum}\""
    first=0
  fi
done
artifacts_json="${artifacts_json}}"
record generated-artifacts "$artifacts_json"

echo 'END'
