#!/bin/sh
# HOF-PROBE-V2 - a single, fixed, versioned, read-only probe run on the
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
# RECORD_NAMES) - every singleton is mandatory, appears exactly once,
# with an explicit "unknown"/status sentinel when the real value
# couldn't be determined (never simply omitted); "port"/"container"
# repeat. Anything else, a missing mandatory record, or EOF before END,
# is a protocol error on the parsing side, deliberately - a truncated or
# malformed transcript must never be interpreted as "everything's fine".
set -eu

b64() {
  printf '%s' "$1" | base64 | tr -d '\n'
}

record() {
  printf 'R %s %s\n' "$1" "$(b64 "$2")"
}

echo 'HOF-PROBE-V2'

# --- os / arch --------------------------------------------------------
if [ -r /etc/os-release ]; then
  os_id=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
  os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-unknown}")
  record os "${os_id}|${os_version}"
else
  record os "unknown|unknown"
fi
record arch "$(uname -m 2>/dev/null || echo unknown)"

# --- cpu / memory / disk - always exactly one record each, "unknown"
# rather than omitted when undeterminable -----------------------------
if command -v nproc >/dev/null 2>&1; then
  record cpu "$(nproc)"
elif command -v getconf >/dev/null 2>&1 && cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null); then
  record cpu "$cores"
else
  record cpu unknown
fi

mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || true)
if [ -n "${mem_kb:-}" ]; then
  record memory "$((mem_kb * 1024))"
else
  record memory unknown
fi

# Free space where Hof actually keeps its state/data - /var/lib, not /,
# since that's the mount that matters for volumes and generated state.
disk_kb=$(df -Pk /var/lib 2>/dev/null | awk 'NR==2 { print $4 }' || true)
if [ -n "${disk_kb:-}" ]; then
  record disk "$((disk_kb * 1024))"
else
  record disk unknown
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
  have_sudo=1
  record sudo yes
else
  have_sudo=0
  record sudo no
fi

# --- listening ports (state only - "who owns it" is resolved later by
# cross-referencing this same snapshot's own container records, not a
# privileged process lookup). The command's own success/failure is
# checked explicitly, never inferred from a pipeline's default output -
# a failed `ss` must report "unknown", not silently read as "free". ---
port_state() {
  target_port="$1"
  if command -v ss >/dev/null 2>&1; then
    if output=$(ss -H -ltn 2>/dev/null); then
      if printf '%s\n' "$output" | awk -v p=":${target_port}" '$4 ~ p"$" { found=1 } END { exit !found }'; then
        echo occupied
      else
        echo free
      fi
      return
    fi
  fi
  if command -v netstat >/dev/null 2>&1; then
    if output=$(netstat -ltn 2>/dev/null); then
      if printf '%s\n' "$output" | awk -v p=":${target_port}" '$4 ~ p"$" { found=1 } END { exit !found }'; then
        echo occupied
      else
        echo free
      fi
      return
    fi
  fi
  echo unknown
}
for port in 80 443; do
  record port "${port}|$(port_state "$port")"
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
# bind-mount source path. docker-resources-status distinguishes "Docker
# is up but genuinely has no containers" from "the container listing
# itself failed" - the two must never be conflated into the same empty
# result.
# Filtered to hof.managed=true only - port free/occupied state itself
# already comes from `ss` above, independent of this listing, so
# scoping container inspection to Hof's own resources doesn't lose any
# real port-conflict detection; it just stops exposing an unrelated
# container's name/image/networks on a shared host that has nothing to
# do with this installation at all.
if command -v docker >/dev/null 2>&1 && container_ids=$(docker ps -aq --filter "label=hof.managed=true" 2>/dev/null); then
  record docker-resources-status available
  sep=$(printf '\037')
  fmt="{{.Name}}${sep}{{.Config.Image}}${sep}{{.State.Status}}${sep}{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}${sep}{{index .Config.Labels \"hof.managed\"}}${sep}{{index .Config.Labels \"hof.installation-id\"}}${sep}{{index .Config.Labels \"hof.service\"}}${sep}{{index .Config.Labels \"hof.unit\"}}${sep}{{index .Config.Labels \"hof.artifact\"}}${sep}{{index .Config.Labels \"hof.generation\"}}${sep}{{index .Config.Labels \"com.docker.compose.project\"}}${sep}{{index .Config.Labels \"com.docker.compose.service\"}}${sep}{{range \$n,\$c := .NetworkSettings.Networks}}{{\$n}},{{end}}${sep}{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}},{{end}}{{end}}${sep}{{range \$p,\$b := .NetworkSettings.Ports}}{{range \$b}}{{.HostPort}},{{end}}{{end}}"
  printf '%s\n' "$container_ids" | while IFS= read -r id; do
    [ -n "$id" ] || continue
    line=$(docker inspect --format "$fmt" "$id" 2>/dev/null || true)
    [ -n "$line" ] && record container "$line"
  done
else
  record docker-resources-status unavailable
fi

# --- managed state - sudo -n is used only for these fixed, whitelisted
# paths, never a caller-supplied one, and only as a fallback when a
# plain read fails. "unreadable" (exists, couldn't read even with sudo,
# or no sudo to escalate with) is always kept distinct from "absent". -
read_fixed_file() {
  file_path="$1"
  name="$2"
  if [ -r "$file_path" ]; then
    record "${name}-status" present
    record "$name" "$(cat "$file_path")"
    return
  fi
  if [ "$have_sudo" = "1" ]; then
    if content=$(sudo -n cat "$file_path" 2>/dev/null); then
      record "${name}-status" present
      record "$name" "$content"
      return
    fi
    if sudo -n test -e "$file_path" 2>/dev/null; then
      record "${name}-status" unreadable
      record "$name" ""
      return
    fi
    record "${name}-status" absent
    record "$name" ""
    return
  fi
  # No sudo to escalate with - can't tell "absent" from "exists but this
  # user can't read it" without root.
  if [ -e "$file_path" ]; then
    record "${name}-status" unreadable
  else
    record "${name}-status" absent
  fi
  record "$name" ""
}
read_fixed_file /var/lib/hof/state/current.json state-current
read_fixed_file /var/lib/hof/state/topology.json state-topology

# --- generated artifact checksums (fixed filename list, never a
# caller-supplied path) - same sudo-aware read as the state files.
# generated-artifacts-status distinguishes "sha256sum genuinely isn't on
# this target at all" (nothing here could ever be trusted) from "it's
# available and each file was individually present/absent/unreadable" -
# a coarser signal than per-file status, but still real: without it, a
# target with no sha256sum at all would look identical to one where
# every generated file simply doesn't exist yet. ---
if command -v sha256sum >/dev/null 2>&1; then
  record generated-artifacts-status available
  artifacts_json="{"
  first=1
  for name in compose.yml Caddyfile service.env runtime-config.json backup-inventory.json topology.json; do
    file_path="/etc/hof/generated/${name}"
    sum=""
    if [ -r "$file_path" ]; then
      sum=$(sha256sum "$file_path" | awk '{ print $1 }')
    elif [ "$have_sudo" = "1" ]; then
      sum=$(sudo -n sha256sum "$file_path" 2>/dev/null | awk '{ print $1 }' || true)
    fi
    if [ -n "$sum" ]; then
      [ "$first" = 1 ] || artifacts_json="${artifacts_json},"
      artifacts_json="${artifacts_json}\"${name}\":\"sha256:${sum}\""
      first=0
    fi
  done
  artifacts_json="${artifacts_json}}"
  record generated-artifacts "$artifacts_json"
else
  record generated-artifacts-status unavailable
  record generated-artifacts "{}"
fi

echo 'END'
