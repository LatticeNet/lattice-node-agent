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
service_name="lattice-agent"
action="install"

for a in "$@"; do
  case "$a" in
    --uninstall) action="uninstall" ;;
    --help|-h)
      echo "Usage: install.sh [--uninstall]"
      echo "Env: LATTICE_SERVER, LATTICE_NODE_ID, LATTICE_NODE_TOKEN (required for install)"
      echo "     LATTICE_HOME (default /opt/lattice), LATTICE_AGENT_VERSION (default latest)"
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
      LATTICE_AGENT_ALLOW_EXEC="${LATTICE_AGENT_ALLOW_EXEC:-}" \
      LATTICE_AGENT_ALLOW_ROOT_EXEC="${LATTICE_AGENT_ALLOW_ROOT_EXEC:-}" \
      LATTICE_NO_EXEC="${LATTICE_NO_EXEC:-}" \
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
if have curl; then dl() { curl -fsSL "$1" -o "$2"; }
elif have wget; then dl() { wget -qO "$2" "$1"; }
else die "need curl or wget to download the agent"; fi

# checksum tool (sha256sum on Linux, shasum on macOS/BSD)
if have sha256sum; then sumcheck() { grep " $1\$" "$2" | sha256sum -c - ; }
elif have shasum;   then sumcheck() { grep " $1\$" "$2" | shasum -a 256 -c - ; }
else sumcheck() { log "no sha256 tool; skipping checksum verification"; return 0; }; fi

have install || die "missing required command: install"

# ---- base dir under /opt/lattice -------------------------------------------
if [ ! -d "$LATTICE_HOME" ]; then
  log "creating $LATTICE_HOME ..."
  mkdir -p "$LATTICE_HOME" || die "cannot create $LATTICE_HOME (insufficient permissions?)"
fi
[ -w "$LATTICE_HOME" ] || die "$LATTICE_HOME is not writable"
mkdir -p "$state_dir"
chmod 0750 "$LATTICE_HOME" 2>/dev/null || true

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
  log "SHA256SUMS not available; proceeding without checksum"
fi

# Upgrade in place: stop a running instance before replacing the binary.
svc_stop
install -m 0755 "$tmp_dir/$artifact" "$bin_path"
ok "installed binary -> $bin_path"

# ---- env file (0600; holds the token, NOT passed on the command line) ------
quote_env() { printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/"; }
umask 077
cat >"$env_path" <<EOF
LATTICE_SERVER=$(quote_env "$server")
LATTICE_NODE_ID=$(quote_env "$node_id")
LATTICE_NODE_TOKEN=$(quote_env "$token")
LATTICE_LOG_STATE_DIR=$(quote_env "$state_dir")
LATTICE_AGENT_ALLOW_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_EXEC:-0}")
LATTICE_AGENT_ALLOW_ROOT_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")
LATTICE_NO_EXEC=$(quote_env "${LATTICE_NO_EXEC:-0}")
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
kind="$(svc_kind)"
case "$kind" in
  systemd)
    cat >"$unit_path" <<EOF
[Unit]
Description=Lattice node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$env_path
ExecStart=$bin_path
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
    cat >"$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${plist_label}</string>
  <key>ProgramArguments</key><array><string>${bin_path}</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>LATTICE_SERVER</key><string>${server}</string>
    <key>LATTICE_NODE_ID</key><string>${node_id}</string>
    <key>LATTICE_NODE_TOKEN</key><string>${token}</string>
    <key>LATTICE_LOG_STATE_DIR</key><string>${state_dir}</string>
    <key>LATTICE_AGENT_ALLOW_EXEC</key><string>${LATTICE_AGENT_ALLOW_EXEC:-0}</string>
    <key>LATTICE_AGENT_ALLOW_ROOT_EXEC</key><string>${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}</string>
    <key>LATTICE_NO_EXEC</key><string>${LATTICE_NO_EXEC:-0}</string>
    <key>LATTICE_AGENT_ALLOW_TERMINAL</key><string>${LATTICE_AGENT_ALLOW_TERMINAL:-0}</string>
    <key>LATTICE_TERMINAL_TRANSPORT</key><string>${LATTICE_TERMINAL_TRANSPORT:-poll}</string>
    <key>LATTICE_IP_MODE</key><string>${LATTICE_IP_MODE:-auto}</string>
    <key>LATTICE_SSH_ALERTS</key><string>${LATTICE_SSH_ALERTS:-0}</string>
    <key>LATTICE_SINGBOX_DISCOVER</key><string>${LATTICE_SINGBOX_DISCOVER:-0}</string>
    <key>LATTICE_SINGBOX_BIN</key><string>${LATTICE_SINGBOX_BIN:-sb}</string>
    <key>LATTICE_PROXY_USAGE_FILE</key><string>${LATTICE_PROXY_USAGE_FILE:-}</string>
    <key>LATTICE_PROXY_USAGE_URL</key><string>${LATTICE_PROXY_USAGE_URL:-}</string>
    <key>LATTICE_PROXY_USAGE_XRAY_API</key><string>${LATTICE_PROXY_USAGE_XRAY_API:-}</string>
    <key>LATTICE_PROXY_USAGE_XRAY_BIN</key><string>${LATTICE_PROXY_USAGE_XRAY_BIN:-}</string>
    <key>LATTICE_PROXY_USAGE_XRAY_PATTERN</key><string>${LATTICE_PROXY_USAGE_XRAY_PATTERN:-}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${state_dir}/agent.log</string>
  <key>StandardErrorPath</key><string>${state_dir}/agent.log</string>
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
