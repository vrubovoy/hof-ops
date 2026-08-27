#!/bin/sh
# HOF-PROBE-V5 - a single, fixed, versioned, read-only probe run on the
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
# couldn't be determined (never simply omitted); "port"/"container"/
# "volume"/"network" repeat. Anything else, a missing mandatory record,
# or EOF before END, is a protocol error on the parsing side,
# deliberately - a truncated or malformed transcript must never be
# interpreted as "everything's fine".
set -eu

b64() {
  printf '%s' "$1" | base64 | tr -d '\n'
}

record() {
  printf 'R %s %s\n' "$1" "$(b64 "$2")"
}

echo 'HOF-PROBE-V5'

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

# sudo -n true succeeding only proves *some* sudo access - a sudoers
# rule scoped to specific commands could still make an escalated file
# read fail for reasons that look identical to "the file doesn't exist".
# Proven once, against a file every Linux host actually has, before this
# script ever treats a sudo-escalated check as authoritative.
sudo_reads=0
if [ "$have_sudo" = "1" ] && sudo -n cat /etc/hostname >/dev/null 2>&1; then
  sudo_reads=1
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

# --- docker: one fixed runner, plain first, sudo -n docker second,
# never a caller-controlled command - every docker_run call below passes
# a hardcoded subcommand literal, nothing derived from external input. -
docker_run() {
  if command -v docker >/dev/null 2>&1; then
    if output=$(docker "$@" 2>/dev/null); then
      printf '%s' "$output"
      return 0
    fi
    if [ "$have_sudo" = "1" ]; then
      if output=$(sudo -n docker "$@" 2>/dev/null); then
        printf '%s' "$output"
        return 0
      fi
    fi
  fi
  return 1
}

# docker-engine-status is a real tri-state, not the old available/
# unavailable boolean: "absent" (the docker binary genuinely isn't on
# PATH at all - a fresh host that never had Docker installed, a
# perfectly legitimate bootstrap candidate) must never be
# indistinguishable from "unavailable" (docker exists but couldn't be
# reached - daemon down, permission denied even via sudo - genuinely
# unsafe to assume either way). Only "unavailable" fails closed;
# "absent" is a real, expected state on a clean host Ansible hasn't
# provisioned yet.
if ! command -v docker >/dev/null 2>&1; then
  docker_engine_status=absent
  docker_engine=""
  docker_compose=""
elif docker_engine=$(docker_run version --format '{{.Server.Version}}'); then
  docker_engine_status=available
  docker_compose=$(docker_run compose version --short) || docker_compose=""
else
  docker_engine_status=unavailable
  docker_engine=""
  docker_compose=""
fi
record docker-engine-status "$docker_engine_status"
record docker "${docker_engine}|${docker_compose}"

sep=$(printf '\037')

# Lists and inspects one class of Hof-managed Docker resource
# (container/volume/network) - narrowly scoped to hof.managed=true OR
# this installation's own Compose project, never the whole Docker host.
# Buffers every matched record until the ENTIRE batch (both list calls,
# every single inspect call) has succeeded, then commits it - if even
# one inspect fails partway through, the whole kind reports
# "unavailable" rather than silently emitting a partial, misleadingly-
# "complete" result (a container that failed to inspect must not simply
# vanish from the snapshot while everything else looks fine).
#
# "absent" (docker itself genuinely isn't on PATH) is reported
# separately from "unavailable" (docker exists but a list/inspect call
# still failed) - a clean host with no Docker at all has trivially
# nothing to be missing or orphaned, and must be a legitimate bootstrap
# candidate rather than indistinguishable from a real inspection
# failure. Mirrors docker-engine-status above; the two are expected to
# always agree, since both gate on the same `command -v docker`.
list_and_inspect() {
  list_subcommand="$1"; inspect_subcommand="$2"; fmt="$3"; record_name="$4"

  if ! command -v docker >/dev/null 2>&1; then
    record "docker-${record_name}s-status" absent
    return
  fi

  ok=1
  buffered=""
  if ids1=$(docker_run $list_subcommand --filter "label=hof.managed=true"); then :; else ok=0; fi
  if [ "$ok" = 1 ]; then
    if ids2=$(docker_run $list_subcommand --filter "label=com.docker.compose.project=hof"); then :; else ok=0; fi
  fi
  if [ "$ok" = 1 ]; then
    ids=$(printf '%s\n%s\n' "${ids1:-}" "${ids2:-}" | sed '/^$/d' | sort -u)
    for id in $ids; do
      if line=$(docker_run $inspect_subcommand --format "$fmt" "$id"); then
        [ -n "$line" ] && buffered="${buffered}${line}
"
      else
        ok=0
        break
      fi
    done
  fi

  if [ "$ok" = 1 ]; then
    record "docker-${record_name}s-status" available
    if [ -n "$buffered" ]; then
      printf '%s' "$buffered" | while IFS= read -r line; do
        [ -n "$line" ] && record "$record_name" "$line"
      done
    fi
  else
    record "docker-${record_name}s-status" unavailable
  fi
}

# Whitelisted container fields only - never Config.Env, command/
# entrypoint, logs, arbitrary labels, or a bind-mount source path.
container_fmt="{{.Name}}${sep}{{.Config.Image}}${sep}{{.State.Status}}${sep}{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}${sep}{{index .Config.Labels \"hof.managed\"}}${sep}{{index .Config.Labels \"hof.installation-id\"}}${sep}{{index .Config.Labels \"hof.service\"}}${sep}{{index .Config.Labels \"hof.unit\"}}${sep}{{index .Config.Labels \"hof.artifact\"}}${sep}{{index .Config.Labels \"hof.generation\"}}${sep}{{index .Config.Labels \"com.docker.compose.project\"}}${sep}{{index .Config.Labels \"com.docker.compose.service\"}}${sep}{{range \$n,\$c := .NetworkSettings.Networks}}{{\$n}},{{end}}${sep}{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}},{{end}}{{end}}${sep}{{range \$p,\$b := .NetworkSettings.Ports}}{{range \$b}}{{.HostPort}},{{end}}{{end}}"
list_and_inspect "ps -aq" inspect "$container_fmt" container

# Volumes/networks have no state/health/mounts of their own - just
# identity and ownership labels, enough to detect an orphaned Hof
# resource with no container currently referencing it.
resource_fmt="{{.Name}}${sep}{{index .Labels \"hof.managed\"}}${sep}{{index .Labels \"hof.installation-id\"}}${sep}{{index .Labels \"hof.generation\"}}${sep}{{index .Labels \"hof.kind\"}}${sep}{{index .Labels \"hof.resource\"}}${sep}{{index .Labels \"com.docker.compose.project\"}}"
list_and_inspect "volume ls -q" "volume inspect" "$resource_fmt" volume
list_and_inspect "network ls -q" "network inspect" "$resource_fmt" network

# --- managed state - sudo -n is used only for these fixed, whitelisted
# paths, never a caller-supplied one. "absent" is reported ONLY when
# positively confirmed (root-level `test -e` says so, or there's simply
# nothing else that could hide it) - "unreadable" covers every case
# where that positive confirmation isn't available, so a permission wall
# this script can't see past is never mistaken for "nothing here". ---
read_fixed_file() {
  file_path="$1"
  name="$2"
  if [ -r "$file_path" ]; then
    record "${name}-status" present
    record "$name" "$(cat "$file_path")"
    return
  fi
  if [ "$sudo_reads" = "1" ]; then
    if content=$(sudo -n cat "$file_path" 2>/dev/null); then
      record "${name}-status" present
      record "$name" "$content"
      return
    fi
    if sudo -n test -e "$file_path" 2>/dev/null; then
      # Root confirms it exists, but even root couldn't read it - a
      # genuinely unusual (broken/special file) case, not "absent".
      record "${name}-status" unreadable
      record "$name" ""
      return
    fi
    # Root positively confirms it does not exist - the only condition
    # this script ever reports "absent" under.
    record "${name}-status" absent
    record "$name" ""
    return
  fi
  # No verified sudo file-read capability - "not directly readable"
  # could mean "doesn't exist" or "exists behind a permission wall this
  # user can't see past", and those are not the same thing. Never guess.
  record "${name}-status" unreadable
  record "$name" ""
}
read_fixed_file /var/lib/hof/state/current.json state-current
read_fixed_file /var/lib/hof/state/topology.json state-topology

# --- generated artifact checksums (fixed filename list, never a
# caller-supplied path) - same sudo-aware, positive-confirmation-only
# read as the state files (see read_fixed_file above), applied per file:
# generated-artifacts-status distinguishes "sha256sum genuinely isn't on
# this target at all" from "it's available and each file gets its own
# present|absent|unreadable status". A file that exists but couldn't be
# hashed even with sudo (a permission wall this script can't see past)
# must never be indistinguishable from one that's genuinely gone - a
# planner that can't tell them apart would treat a merely-unreadable
# file as safe to silently regenerate, exactly like it does a real
# missing one.
if command -v sha256sum >/dev/null 2>&1; then
  record generated-artifacts-status available
  artifacts_json="{"
  first=1
  for name in compose.yml Caddyfile service.env runtime-config.json backup-inventory.json topology.json; do
    file_path="/etc/hof/generated/${name}"
    status=""
    digest="null"
    if [ -r "$file_path" ]; then
      status="present"
      digest="\"sha256:$(sha256sum "$file_path" | awk '{ print $1 }')\""
    elif [ "$sudo_reads" = "1" ]; then
      sum=$(sudo -n sha256sum "$file_path" 2>/dev/null | awk '{ print $1 }' || true)
      if [ -n "$sum" ]; then
        status="present"
        digest="\"sha256:${sum}\""
      elif sudo -n test -e "$file_path" 2>/dev/null; then
        # Root confirms it exists, but even root couldn't hash it.
        status="unreadable"
      else
        # Root positively confirms it does not exist.
        status="absent"
      fi
    else
      # No verified sudo file-read capability - "not directly readable"
      # could mean either absent or permission-walled, and those are not
      # the same thing. Never guess.
      status="unreadable"
    fi
    [ "$first" = 1 ] || artifacts_json="${artifacts_json},"
    artifacts_json="${artifacts_json}\"${name}\":{\"status\":\"${status}\",\"digest\":${digest}}"
    first=0
  done
  artifacts_json="${artifacts_json}}"
  record generated-artifacts "$artifacts_json"
else
  record generated-artifacts-status unavailable
  record generated-artifacts "{}"
fi

echo 'END'
