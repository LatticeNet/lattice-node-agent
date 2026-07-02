#!/bin/sh
# Lattice node-agent installer.
#
# Cross-platform (Linux systemd/openrc, macOS launchd, FreeBSD best-effort).
# Everything lives under /opt/lattice (binary, env file, state); nothing is
# scattered into system paths. Idempotent: a re-run upgrades in place. Supports
# `--uninstall`. The enrollment token is kept OUT of the process argv (it is read
# from the 0600 env file / launchd plist), so it never shows up in `ps`.
set -eu

LATTICE_HOME="${LATTICE_HOME:-/opt/lattice}"
repo="${LATTICE_AGENT_REPO:-LatticeNet/lattice-node-agent}"
version="${LATTICE_AGENT_VERSION:-latest}"
server="${LATTICE_SERVER:-}"
node_id="${LATTICE_NODE_ID:-}"
token="${LATTICE_NODE_TOKEN:-}"
bin_path="${LATTICE_AGENT_BIN:-$LATTICE_HOME/lattice-agent}"
env_path="${LATTICE_AGENT_ENV:-$LATTICE_HOME/lattice-agent.env}"
state_dir="${LATTICE_AGENT_STATE:-$LATTICE_HOME/state}"
service_name="${LATTICE_AGENT_SERVICE:-lattice-agent}"
run_user="${LATTICE_AGENT_RUN_USER:-}"
run_group="${LATTICE_AGENT_RUN_GROUP:-}"
create_run_user="${LATTICE_AGENT_CREATE_USER:-1}"
action="install"
input_node_id="$node_id"

for a in "$@"; do
  case "$a" in
    --uninstall) action="uninstall" ;;
    --help|-h)
      echo "Usage: install.sh [--uninstall]"
      echo "Env: LATTICE_SERVER, LATTICE_NODE_ID, LATTICE_NODE_TOKEN (required for install)"
      echo "     LATTICE_HOME (default /opt/lattice), LATTICE_AGENT_VERSION (default latest)"
      echo "     LATTICE_AGENT_RUN_USER / LATTICE_AGENT_RUN_GROUP for optional non-root systemd service"
      exit 0 ;;
  esac
done
[ "${LATTICE_AGENT_UNINSTALL:-}" = "1" ] && action="uninstall"

log()  { echo "  ▸ $*"; }
ok()   { echo "  ✓ $*"; }
die()  { echo "lattice-agent: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- OS / arch detection (borrows nezha's broad matching) -------------------
case "$(uname -s)" in
  Linux)   os="linux" ;;
  Darwin)  os="darwin" ;;
  FreeBSD) os="freebsd" ;;
  *) die "unsupported OS: $(uname -s) (supported: Linux, Darwin, FreeBSD)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)            arch="amd64" ;;
  aarch64|arm64)           arch="arm64" ;;
  armv7l|armv7|armv6l|arm) arch="arm" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

unit_path="${LATTICE_AGENT_UNIT:-/etc/systemd/system/${service_name}.service}"
openrc_path="/etc/init.d/${service_name}"
plist_label="net.lattice.agent"
plist_path="${LATTICE_AGENT_PLIST:-/Library/LaunchDaemons/${plist_label}.plist}"

# ---- root: friendly check + sudo elevation (re-exec preserving config) ------
if [ "$(id -u)" -ne 0 ]; then
  echo "lattice-agent installer needs root to write $LATTICE_HOME and register a boot service."
  if have sudo; then
    log "re-running with sudo ..."
    exec sudo \
      LATTICE_HOME="$LATTICE_HOME" LATTICE_AGENT_REPO="$repo" LATTICE_AGENT_VERSION="$version" \
      LATTICE_SERVER="$server" LATTICE_NODE_ID="$node_id" LATTICE_NODE_TOKEN="$token" \
      LATTICE_AGENT_BIN="$bin_path" LATTICE_AGENT_ENV="$env_path" LATTICE_AGENT_STATE="$state_dir" \
      LATTICE_AGENT_SERVICE="$service_name" \
      LATTICE_AGENT_RUN_USER="${LATTICE_AGENT_RUN_USER:-}" \
      LATTICE_AGENT_RUN_GROUP="${LATTICE_AGENT_RUN_GROUP:-}" \
      LATTICE_AGENT_CREATE_USER="${LATTICE_AGENT_CREATE_USER:-}" \
      LATTICE_AGENT_ALLOW_EXEC="${LATTICE_AGENT_ALLOW_EXEC:-}" \
      LATTICE_AGENT_ALLOW_ROOT_EXEC="${LATTICE_AGENT_ALLOW_ROOT_EXEC:-}" \
      LATTICE_NO_EXEC="${LATTICE_NO_EXEC:-}" \
      LATTICE_TASK_CGROUP_ROOT="${LATTICE_TASK_CGROUP_ROOT:-}" \
      LATTICE_TASK_CGROUP_MEMORY_MAX="${LATTICE_TASK_CGROUP_MEMORY_MAX:-}" \
      LATTICE_TASK_CGROUP_PIDS_MAX="${LATTICE_TASK_CGROUP_PIDS_MAX:-}" \
      LATTICE_TASK_CGROUP_CPU_MAX="${LATTICE_TASK_CGROUP_CPU_MAX:-}" \
      LATTICE_TASK_WORK_ROOT="${LATTICE_TASK_WORK_ROOT:-}" \
      LATTICE_AGENT_ALLOW_TERMINAL="${LATTICE_AGENT_ALLOW_TERMINAL:-}" \
      LATTICE_TERMINAL_TRANSPORT="${LATTICE_TERMINAL_TRANSPORT:-}" \
      LATTICE_IP_MODE="${LATTICE_IP_MODE:-}" LATTICE_IP_RESOLVERS="${LATTICE_IP_RESOLVERS:-}" \
      LATTICE_IP_SCRIPT="${LATTICE_IP_SCRIPT:-}" LATTICE_PUBLIC_IP="${LATTICE_PUBLIC_IP:-}" \
      LATTICE_PUBLIC_IP6="${LATTICE_PUBLIC_IP6:-}" LATTICE_AGENT_UNINSTALL="${LATTICE_AGENT_UNINSTALL:-}" \
      LATTICE_SSH_ALERTS="${LATTICE_SSH_ALERTS:-}" \
      LATTICE_SINGBOX_DISCOVER="${LATTICE_SINGBOX_DISCOVER:-}" LATTICE_SINGBOX_BIN="${LATTICE_SINGBOX_BIN:-}" \
      LATTICE_PROXY_USAGE_FILE="${LATTICE_PROXY_USAGE_FILE:-}" LATTICE_PROXY_USAGE_URL="${LATTICE_PROXY_USAGE_URL:-}" \
      LATTICE_PROXY_USAGE_XRAY_API="${LATTICE_PROXY_USAGE_XRAY_API:-}" LATTICE_PROXY_USAGE_XRAY_BIN="${LATTICE_PROXY_USAGE_XRAY_BIN:-}" \
      LATTICE_PROXY_USAGE_XRAY_PATTERN="${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}" \
      sh "$0" "$@"
  fi
  die "please re-run as root (e.g. sudo sh $0)"
fi

# ---- existing install adoption ---------------------------------------------
# New installs use:
#   binary:  /opt/lattice/lattice-agent
#   env:     /opt/lattice/lattice-agent.env
#   service: lattice-agent.service
#
# Older beta nodes used:
#   binary:  /opt/lattice/node-agent/lattice-agent
#   env:     /opt/lattice/node-agent/agent.env
#   service: lattice-node-agent.service
#
# Earlier manual docs also showed /etc/lattice/agent.env. Adopt it when present
# so those nodes can migrate into the current /opt/lattice layout without losing
# their token during an installer re-run.
#
# Re-running the installer must upgrade the service that is already installed
# instead of creating a second agent for the same machine. Explicit env values
# (LATTICE_AGENT_BIN, LATTICE_AGENT_ENV, LATTICE_AGENT_SERVICE, etc.) still win.
read_env_value() {
  key="$1"
  file="$2"
  (
    set -a
    # shellcheck disable=SC1090
    . "$file"
    set +a
    eval "printf '%s' \"\${$key:-}\""
  ) 2>/dev/null || true
}

detect_systemd_install() {
  [ "$os" = "linux" ] || return 0
  have systemctl || return 0
  [ -d /run/systemd/system ] || return 0
  [ -z "${LATTICE_AGENT_SERVICE:-}" ] || return 0

  for candidate in lattice-agent lattice-node-agent; do
    unit="/etc/systemd/system/${candidate}.service"
    [ -f "$unit" ] || continue
    detected_bin="$(sed -n 's/^ExecStart=//p' "$unit" | sed -n '1p' | awk '{print $1}')"
    case "$detected_bin" in
      */lattice-agent) ;;
      *) continue ;;
    esac
    service_name="$candidate"
    [ -n "${LATTICE_AGENT_BIN:-}" ] || bin_path="$detected_bin"
    if [ -z "${LATTICE_AGENT_ENV:-}" ]; then
      detected_env="$(sed -n 's/^EnvironmentFile=-\{0,1\}//p' "$unit" | sed -n '1p' | awk '{print $1}')"
      [ -n "$detected_env" ] && env_path="$detected_env"
    fi
    if [ -z "${LATTICE_AGENT_STATE:-}" ] && [ "$env_path" = "/opt/lattice/node-agent/agent.env" ]; then
      state_dir="/opt/lattice/node-agent/state"
    fi
    if [ -z "${LATTICE_AGENT_RUN_USER:-}" ]; then
      detected_user="$(sed -n 's/^User=//p' "$unit" | sed -n '1p')"
      [ -n "$detected_user" ] && run_user="$detected_user"
    fi
    if [ -z "${LATTICE_AGENT_RUN_GROUP:-}" ]; then
      detected_group="$(sed -n 's/^Group=//p' "$unit" | sed -n '1p')"
      [ -n "$detected_group" ] && run_group="$detected_group"
    fi
    log "adopting existing service ${service_name}.service"
    log "effective binary -> $bin_path"
    log "effective env -> $env_path"
    return 0
  done
}

load_existing_config() {
  existing_env=""
  for candidate in "$env_path" "$LATTICE_HOME/lattice-agent.env" "/opt/lattice/node-agent/agent.env" "/etc/lattice/agent.env"; do
    [ -f "$candidate" ] || continue
    existing_env="$candidate"
    break
  done
  [ -n "$existing_env" ] || return 0

  existing_server="$(read_env_value LATTICE_SERVER "$existing_env")"
  existing_node_id="$(read_env_value LATTICE_NODE_ID "$existing_env")"
  existing_token="$(read_env_value LATTICE_NODE_TOKEN "$existing_env")"
  log "loading existing credentials/config -> $existing_env"

  [ -n "$server" ] || server="$existing_server"
  [ -n "$node_id" ] || node_id="$existing_node_id"
  if [ -n "$input_node_id" ] && [ -n "$existing_node_id" ] && [ "$input_node_id" != "$existing_node_id" ] && [ -n "$existing_token" ]; then
    if [ -z "$token" ] || [ "$token" = "$existing_token" ]; then
      die "existing token belongs to node $existing_node_id but this command targets $input_node_id; use the correct node reconfigure command or provide a matching LATTICE_NODE_TOKEN"
    fi
  fi
  if [ -z "$token" ] && [ -n "$existing_token" ]; then
    token="$existing_token"
  fi

  for key in \
    LATTICE_AGENT_RUN_USER LATTICE_AGENT_RUN_GROUP LATTICE_AGENT_CREATE_USER \
    LATTICE_AGENT_ALLOW_EXEC LATTICE_AGENT_ALLOW_ROOT_EXEC LATTICE_NO_EXEC \
    LATTICE_TASK_CGROUP_ROOT LATTICE_TASK_CGROUP_MEMORY_MAX \
    LATTICE_TASK_CGROUP_PIDS_MAX LATTICE_TASK_CGROUP_CPU_MAX \
    LATTICE_TASK_WORK_ROOT \
    LATTICE_AGENT_ALLOW_TERMINAL LATTICE_TERMINAL_TRANSPORT LATTICE_IP_MODE \
    LATTICE_IP_RESOLVERS LATTICE_IP_SCRIPT LATTICE_PUBLIC_IP LATTICE_PUBLIC_IP6 \
    LATTICE_SSH_ALERTS LATTICE_SINGBOX_DISCOVER LATTICE_SINGBOX_BIN \
    LATTICE_PROXY_USAGE_FILE LATTICE_PROXY_USAGE_URL LATTICE_PROXY_USAGE_XRAY_API \
    LATTICE_PROXY_USAGE_XRAY_BIN LATTICE_PROXY_USAGE_XRAY_PATTERN
  do
    eval "current=\${$key:-}"
    [ -z "$current" ] || continue
    existing_value="$(read_env_value "$key" "$existing_env")"
    [ -n "$existing_value" ] || continue
    export "$key=$existing_value"
  done
}

detect_systemd_install
unit_path="${LATTICE_AGENT_UNIT:-/etc/systemd/system/${service_name}.service}"
openrc_path="/etc/init.d/${service_name}"
load_existing_config
run_user="${LATTICE_AGENT_RUN_USER:-$run_user}"
run_group="${LATTICE_AGENT_RUN_GROUP:-$run_group}"
create_run_user="${LATTICE_AGENT_CREATE_USER:-$create_run_user}"

validate_account_name() {
  name="$1"
  label="$2"
  case "$name" in
    ""|-*|*[!A-Za-z0-9_.-]*) die "$label contains unsupported characters: $name" ;;
  esac
}

group_exists() {
  if have getent; then getent group "$1" >/dev/null 2>&1; return $?; fi
  [ -r /etc/group ] || return 1
  while IFS=: read -r name _; do
    [ "$name" = "$1" ] && return 0
  done </etc/group
  return 1
}

create_group_if_needed() {
  group="$1"
  group_exists "$group" && return 0
  [ "$create_run_user" != "0" ] || die "group $group does not exist; create it or unset LATTICE_AGENT_CREATE_USER=0"
  if have groupadd; then
    groupadd --system "$group" 2>/dev/null || groupadd "$group"
  elif have addgroup; then
    addgroup -S "$group" 2>/dev/null || addgroup "$group"
  else
    die "cannot create group $group (missing groupadd/addgroup)"
  fi
}

create_user_if_needed() {
  user="$1"
  group="$2"
  if id -u "$user" >/dev/null 2>&1; then
    return 0
  fi
  [ "$create_run_user" != "0" ] || die "user $user does not exist; create it or unset LATTICE_AGENT_CREATE_USER=0"
  shell="/usr/sbin/nologin"
  [ -x "$shell" ] || shell="/sbin/nologin"
  [ -x "$shell" ] || shell="/bin/false"
  if have useradd; then
    useradd --system --no-create-home --home-dir "$LATTICE_HOME" --shell "$shell" --gid "$group" "$user" 2>/dev/null || \
      useradd -r -M -d "$LATTICE_HOME" -s "$shell" -g "$group" "$user"
  elif have adduser; then
    adduser -S -D -H -h "$LATTICE_HOME" -s "$shell" -G "$group" "$user" 2>/dev/null || \
      adduser --system --no-create-home --home "$LATTICE_HOME" --shell "$shell" --ingroup "$group" "$user"
  else
    die "cannot create user $user (missing useradd/adduser)"
  fi
}

prepare_service_identity() {
  [ -n "$run_user" ] || return 0
  [ "$os" = "linux" ] || die "LATTICE_AGENT_RUN_USER is supported only on Linux systemd installs"
  validate_account_name "$run_user" "LATTICE_AGENT_RUN_USER"
  if id -u "$run_user" >/dev/null 2>&1; then
    if [ -z "$run_group" ]; then
      run_group="$(id -gn "$run_user" 2>/dev/null || true)"
    fi
    [ -n "$run_group" ] || die "cannot resolve primary group for $run_user"
    validate_account_name "$run_group" "LATTICE_AGENT_RUN_GROUP"
    group_exists "$run_group" || die "group $run_group does not exist"
    return 0
  fi
  [ -n "$run_group" ] || run_group="$run_user"
  validate_account_name "$run_group" "LATTICE_AGENT_RUN_GROUP"
  create_group_if_needed "$run_group"
  create_user_if_needed "$run_user" "$run_group"
}

apply_service_identity_permissions() {
  [ -n "$run_user" ] || return 0
  chgrp "$run_group" "$LATTICE_HOME" || die "cannot set $LATTICE_HOME group to $run_group"
  chmod 0750 "$LATTICE_HOME" 2>/dev/null || true
  chown "$run_user:$run_group" "$state_dir" || die "cannot assign $state_dir to $run_user:$run_group"
  chmod 0750 "$state_dir" 2>/dev/null || true
  if [ -n "${LATTICE_TASK_WORK_ROOT:-}" ]; then
    chown "$run_user:$run_group" "$LATTICE_TASK_WORK_ROOT" || die "cannot assign $LATTICE_TASK_WORK_ROOT to $run_user:$run_group"
    chmod 0700 "$LATTICE_TASK_WORK_ROOT" 2>/dev/null || true
  fi
}

prepare_task_work_root() {
  [ -n "${LATTICE_TASK_WORK_ROOT:-}" ] || return 0
  case "$LATTICE_TASK_WORK_ROOT" in
    /*) ;;
    *) die "LATTICE_TASK_WORK_ROOT must be an absolute path" ;;
  esac
  mkdir -p "$LATTICE_TASK_WORK_ROOT" || die "cannot create LATTICE_TASK_WORK_ROOT=$LATTICE_TASK_WORK_ROOT"
  chmod 0700 "$LATTICE_TASK_WORK_ROOT" 2>/dev/null || true
}

# ---- service helpers (systemd / openrc / launchd) --------------------------
svc_kind() {
  if [ "$os" = "darwin" ]; then echo launchd; return; fi
  if have systemctl && [ -d /run/systemd/system ]; then echo systemd; return; fi
  if have rc-service && have rc-update; then echo openrc; return; fi
  echo none
}

svc_stop() {
  case "$(svc_kind)" in
    systemd) systemctl stop "$service_name" 2>/dev/null || true ;;
    openrc)  rc-service "$service_name" stop 2>/dev/null || true ;;
    launchd) launchctl bootout system "$plist_path" 2>/dev/null || launchctl unload "$plist_path" 2>/dev/null || true ;;
  esac
}

# ---- uninstall -------------------------------------------------------------
if [ "$action" = "uninstall" ]; then
  log "stopping service ..."
  svc_stop
  case "$(svc_kind)" in
    systemd) systemctl disable "$service_name" 2>/dev/null || true; rm -f "$unit_path"; systemctl daemon-reload 2>/dev/null || true ;;
    openrc)  rc-update del "$service_name" 2>/dev/null || true; rm -f "$openrc_path" ;;
    launchd) rm -f "$plist_path" ;;
  esac
  rm -f "$bin_path" "$env_path"
  ok "lattice-agent uninstalled. Kept $LATTICE_HOME (incl. backups/state); remove it manually if desired."
  exit 0
fi

# ---- install: validate enrollment inputs -----------------------------------
if [ -z "$server" ] || [ -z "$node_id" ] || [ -z "$token" ]; then
  die "set LATTICE_SERVER, LATTICE_NODE_ID, and LATTICE_NODE_TOKEN (copy the enroll command from the dashboard)"
fi

# download tool (curl preferred, wget fallback)
if have curl; then dl() { curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"; }
elif have wget; then dl() { wget --https-only -qO "$2" "$1"; }
else die "need curl or wget to download the agent"; fi

# checksum tool (sha256sum on Linux, shasum on macOS/BSD, sha256 on FreeBSD)
if have sha256sum; then sumcheck() { grep " $1\$" "$2" | sha256sum -c - ; }
elif have shasum;   then sumcheck() { grep " $1\$" "$2" | shasum -a 256 -c - ; }
elif have sha256;   then sumcheck() {
  expected="$(awk -v name="$1" '$2 == name { print $1; found = 1 } END { if (!found) exit 1 }' "$2")" || return 1
  actual="$(sha256 -q "$1")" || return 1
  [ "$actual" = "$expected" ]
}
else die "need sha256sum, shasum, or sha256 to verify release checksums"; fi

have install || die "missing required command: install"
kind="$(svc_kind)"
if [ -n "$run_user" ] && [ "$kind" != "systemd" ]; then
  die "LATTICE_AGENT_RUN_USER is supported only for systemd installs"
fi
prepare_service_identity

# ---- base dir under /opt/lattice -------------------------------------------
if [ ! -d "$LATTICE_HOME" ]; then
  log "creating $LATTICE_HOME ..."
  mkdir -p "$LATTICE_HOME" || die "cannot create $LATTICE_HOME (insufficient permissions?)"
fi
[ -w "$LATTICE_HOME" ] || die "$LATTICE_HOME is not writable"
mkdir -p "$state_dir"
prepare_task_work_root
chmod 0750 "$LATTICE_HOME" 2>/dev/null || true
apply_service_identity_permissions

# ---- download + verify + install binary ------------------------------------
artifact="lattice-agent-${os}-${arch}"
if [ "$version" = "latest" ]; then
  base="https://github.com/${repo}/releases/latest/download"
else
  base="https://github.com/${repo}/releases/download/${version}"
fi
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
log "downloading $artifact ($version) ..."
dl "$base/$artifact" "$tmp_dir/$artifact" || die "download failed: $base/$artifact"
if dl "$base/SHA256SUMS" "$tmp_dir/SHA256SUMS" 2>/dev/null; then
  ( cd "$tmp_dir" && sumcheck "$artifact" SHA256SUMS ) || die "checksum verification failed"
  ok "checksum verified"
else
  die "SHA256SUMS not available; refusing to install without checksum manifest"
fi

# Upgrade in place: stop a running instance before replacing the binary.
svc_stop
install -m 0755 "$tmp_dir/$artifact" "$bin_path"
ok "installed binary -> $bin_path"

# ---- env file (0600; holds the token, NOT passed on the command line) ------
quote_env() { printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/"; }
xml_escape() {
  printf "%s" "$1" | sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' \
    -e "s/'/\&apos;/g"
}
umask 077
cat >"$env_path" <<EOF
LATTICE_SERVER=$(quote_env "$server")
LATTICE_NODE_ID=$(quote_env "$node_id")
LATTICE_NODE_TOKEN=$(quote_env "$token")
LATTICE_LOG_STATE_DIR=$(quote_env "$state_dir")
LATTICE_AGENT_RUN_USER=$(quote_env "$run_user")
LATTICE_AGENT_RUN_GROUP=$(quote_env "$run_group")
LATTICE_AGENT_CREATE_USER=$(quote_env "$create_run_user")
LATTICE_AGENT_ALLOW_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_EXEC:-0}")
LATTICE_AGENT_ALLOW_ROOT_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")
LATTICE_NO_EXEC=$(quote_env "${LATTICE_NO_EXEC:-0}")
LATTICE_TASK_CGROUP_ROOT=$(quote_env "${LATTICE_TASK_CGROUP_ROOT:-}")
LATTICE_TASK_CGROUP_MEMORY_MAX=$(quote_env "${LATTICE_TASK_CGROUP_MEMORY_MAX:-536870912}")
LATTICE_TASK_CGROUP_PIDS_MAX=$(quote_env "${LATTICE_TASK_CGROUP_PIDS_MAX:-64}")
LATTICE_TASK_CGROUP_CPU_MAX=$(quote_env "${LATTICE_TASK_CGROUP_CPU_MAX:-100000 100000}")
LATTICE_TASK_WORK_ROOT=$(quote_env "${LATTICE_TASK_WORK_ROOT:-}")
LATTICE_AGENT_ALLOW_TERMINAL=$(quote_env "${LATTICE_AGENT_ALLOW_TERMINAL:-0}")
LATTICE_TERMINAL_TRANSPORT=$(quote_env "${LATTICE_TERMINAL_TRANSPORT:-poll}")
LATTICE_IP_MODE=$(quote_env "${LATTICE_IP_MODE:-auto}")
LATTICE_IP_RESOLVERS=$(quote_env "${LATTICE_IP_RESOLVERS:-}")
LATTICE_IP_SCRIPT=$(quote_env "${LATTICE_IP_SCRIPT:-}")
LATTICE_PUBLIC_IP=$(quote_env "${LATTICE_PUBLIC_IP:-}")
LATTICE_PUBLIC_IP6=$(quote_env "${LATTICE_PUBLIC_IP6:-}")
LATTICE_SSH_ALERTS=$(quote_env "${LATTICE_SSH_ALERTS:-0}")
LATTICE_SINGBOX_DISCOVER=$(quote_env "${LATTICE_SINGBOX_DISCOVER:-0}")
LATTICE_SINGBOX_BIN=$(quote_env "${LATTICE_SINGBOX_BIN:-sb}")
LATTICE_PROXY_USAGE_FILE=$(quote_env "${LATTICE_PROXY_USAGE_FILE:-}")
LATTICE_PROXY_USAGE_URL=$(quote_env "${LATTICE_PROXY_USAGE_URL:-}")
LATTICE_PROXY_USAGE_XRAY_API=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_API:-}")
LATTICE_PROXY_USAGE_XRAY_BIN=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_BIN:-}")
LATTICE_PROXY_USAGE_XRAY_PATTERN=$(quote_env "${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}")
EOF
chmod 0600 "$env_path"
ok "wrote env -> $env_path"

# ---- register + start the boot service -------------------------------------
case "$kind" in
  systemd)
    unit_identity=""
    if [ -n "$run_user" ]; then
      unit_identity="User=$run_user
Group=$run_group"
    fi
    cat >"$unit_path" <<EOF
[Unit]
Description=Lattice node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
$unit_identity
EnvironmentFile=$env_path
ExecStart=$bin_path
Delegate=yes
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$service_name"
    ok "systemd service enabled (boot autostart) + started"
    systemctl --no-pager --lines=15 status "$service_name" || true
    ;;
  openrc)
    cat >"$openrc_path" <<EOF
#!/sbin/openrc-run
name="lattice-agent"
command="$bin_path"
command_background=true
pidfile="/run/${service_name}.pid"
output_log="$state_dir/agent.log"
error_log="$state_dir/agent.log"
start_pre() { set -a; . "$env_path"; set +a; }
depend() { need net; }
EOF
    chmod +x "$openrc_path"
    rc-update add "$service_name" default
    rc-service "$service_name" restart
    ok "openrc service added (boot autostart) + started"
    ;;
  launchd)
    # launchd: token lives in EnvironmentVariables (plist is 0600), not argv.
    # Every value is XML-escaped so enrollment commands with URL query
    # delimiters or generated token punctuation cannot corrupt the plist.
    cat >"$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$(xml_escape "$plist_label")</string>
  <key>ProgramArguments</key><array><string>$(xml_escape "$bin_path")</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>LATTICE_SERVER</key><string>$(xml_escape "$server")</string>
    <key>LATTICE_NODE_ID</key><string>$(xml_escape "$node_id")</string>
    <key>LATTICE_NODE_TOKEN</key><string>$(xml_escape "$token")</string>
    <key>LATTICE_LOG_STATE_DIR</key><string>$(xml_escape "$state_dir")</string>
    <key>LATTICE_AGENT_ALLOW_EXEC</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_EXEC:-0}")</string>
    <key>LATTICE_AGENT_ALLOW_ROOT_EXEC</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")</string>
    <key>LATTICE_NO_EXEC</key><string>$(xml_escape "${LATTICE_NO_EXEC:-0}")</string>
    <key>LATTICE_TASK_CGROUP_ROOT</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_ROOT:-}")</string>
    <key>LATTICE_TASK_CGROUP_MEMORY_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_MEMORY_MAX:-536870912}")</string>
    <key>LATTICE_TASK_CGROUP_PIDS_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_PIDS_MAX:-64}")</string>
    <key>LATTICE_TASK_CGROUP_CPU_MAX</key><string>$(xml_escape "${LATTICE_TASK_CGROUP_CPU_MAX:-100000 100000}")</string>
    <key>LATTICE_TASK_WORK_ROOT</key><string>$(xml_escape "${LATTICE_TASK_WORK_ROOT:-}")</string>
    <key>LATTICE_AGENT_ALLOW_TERMINAL</key><string>$(xml_escape "${LATTICE_AGENT_ALLOW_TERMINAL:-0}")</string>
    <key>LATTICE_TERMINAL_TRANSPORT</key><string>$(xml_escape "${LATTICE_TERMINAL_TRANSPORT:-poll}")</string>
    <key>LATTICE_IP_MODE</key><string>$(xml_escape "${LATTICE_IP_MODE:-auto}")</string>
    <key>LATTICE_IP_RESOLVERS</key><string>$(xml_escape "${LATTICE_IP_RESOLVERS:-}")</string>
    <key>LATTICE_IP_SCRIPT</key><string>$(xml_escape "${LATTICE_IP_SCRIPT:-}")</string>
    <key>LATTICE_PUBLIC_IP</key><string>$(xml_escape "${LATTICE_PUBLIC_IP:-}")</string>
    <key>LATTICE_PUBLIC_IP6</key><string>$(xml_escape "${LATTICE_PUBLIC_IP6:-}")</string>
    <key>LATTICE_SSH_ALERTS</key><string>$(xml_escape "${LATTICE_SSH_ALERTS:-0}")</string>
    <key>LATTICE_SINGBOX_DISCOVER</key><string>$(xml_escape "${LATTICE_SINGBOX_DISCOVER:-0}")</string>
    <key>LATTICE_SINGBOX_BIN</key><string>$(xml_escape "${LATTICE_SINGBOX_BIN:-sb}")</string>
    <key>LATTICE_PROXY_USAGE_FILE</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_FILE:-}")</string>
    <key>LATTICE_PROXY_USAGE_URL</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_URL:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_API</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_API:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_BIN</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_BIN:-}")</string>
    <key>LATTICE_PROXY_USAGE_XRAY_PATTERN</key><string>$(xml_escape "${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}")</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$(xml_escape "$state_dir")/agent.log</string>
  <key>StandardErrorPath</key><string>$(xml_escape "$state_dir")/agent.log</string>
</dict>
</plist>
EOF
    chmod 0600 "$plist_path"
    launchctl bootout system "$plist_path" 2>/dev/null || true
    launchctl bootstrap system "$plist_path" 2>/dev/null || launchctl load -w "$plist_path"
    ok "launchd daemon installed (RunAtLoad boot autostart) + started"
    ;;
  none)
    die "no supported service manager found (need systemd, openrc, or launchd). Binary is at $bin_path; run it manually with the env in $env_path."
    ;;
esac

echo
ok "lattice-agent ${version} installed under $LATTICE_HOME for node ${node_id}"
