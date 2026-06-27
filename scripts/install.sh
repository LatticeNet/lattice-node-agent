#!/bin/sh
set -eu

repo="${LATTICE_AGENT_REPO:-LatticeNet/lattice-node-agent}"
version="${LATTICE_AGENT_VERSION:-latest}"
server="${LATTICE_SERVER:-}"
node_id="${LATTICE_NODE_ID:-}"
token="${LATTICE_NODE_TOKEN:-}"
bin_path="${LATTICE_AGENT_BIN:-/usr/local/bin/lattice-agent}"
env_path="${LATTICE_AGENT_ENV:-/etc/lattice-agent.env}"
unit_path="${LATTICE_AGENT_UNIT:-/etc/systemd/system/lattice-agent.service}"

die() {
  echo "lattice-agent install: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

quote_env() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/"
}

if [ -z "$server" ] || [ -z "$node_id" ] || [ -z "$token" ]; then
  die "set LATTICE_SERVER, LATTICE_NODE_ID, and LATTICE_NODE_TOKEN"
fi

case "$(uname -s)" in
  Linux) os="linux" ;;
  *) die "automatic service install currently supports Linux/systemd only" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

need curl
need install
need sha256sum
need systemctl

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo \
      LATTICE_AGENT_REPO="$repo" \
      LATTICE_AGENT_VERSION="$version" \
      LATTICE_SERVER="$server" \
      LATTICE_NODE_ID="$node_id" \
      LATTICE_NODE_TOKEN="$token" \
      LATTICE_AGENT_BIN="$bin_path" \
      LATTICE_AGENT_ENV="$env_path" \
      LATTICE_AGENT_UNIT="$unit_path" \
      LATTICE_AGENT_ALLOW_EXEC="${LATTICE_AGENT_ALLOW_EXEC:-}" \
      LATTICE_AGENT_ALLOW_ROOT_EXEC="${LATTICE_AGENT_ALLOW_ROOT_EXEC:-}" \
      LATTICE_AGENT_ALLOW_TERMINAL="${LATTICE_AGENT_ALLOW_TERMINAL:-}" \
      LATTICE_IP_MODE="${LATTICE_IP_MODE:-}" \
      LATTICE_IP_RESOLVERS="${LATTICE_IP_RESOLVERS:-}" \
      LATTICE_IP_SCRIPT="${LATTICE_IP_SCRIPT:-}" \
      LATTICE_PUBLIC_IP="${LATTICE_PUBLIC_IP:-}" \
      LATTICE_PUBLIC_IP6="${LATTICE_PUBLIC_IP6:-}" \
      sh "$0"
  fi
  die "run as root or install sudo"
fi

artifact="lattice-agent-${os}-${arch}"
if [ "$version" = "latest" ]; then
  url="https://github.com/${repo}/releases/latest/download/${artifact}"
  sums_url="https://github.com/${repo}/releases/latest/download/SHA256SUMS"
else
  url="https://github.com/${repo}/releases/download/${version}/${artifact}"
  sums_url="https://github.com/${repo}/releases/download/${version}/SHA256SUMS"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
tmp="$tmp_dir/$artifact"
sums="$tmp_dir/SHA256SUMS"

echo "Downloading $artifact from $url"
curl -fsSL "$url" -o "$tmp"
curl -fsSL "$sums_url" -o "$sums"
(cd "$tmp_dir" && grep " $artifact\$" SHA256SUMS | sha256sum -c -)
install -m 0755 "$tmp" "$bin_path"

umask 077
cat >"$env_path" <<EOF
LATTICE_SERVER=$(quote_env "$server")
LATTICE_NODE_ID=$(quote_env "$node_id")
LATTICE_NODE_TOKEN=$(quote_env "$token")
LATTICE_AGENT_ALLOW_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_EXEC:-0}")
LATTICE_AGENT_ALLOW_ROOT_EXEC=$(quote_env "${LATTICE_AGENT_ALLOW_ROOT_EXEC:-0}")
LATTICE_AGENT_ALLOW_TERMINAL=$(quote_env "${LATTICE_AGENT_ALLOW_TERMINAL:-0}")
LATTICE_IP_MODE=$(quote_env "${LATTICE_IP_MODE:-auto}")
LATTICE_IP_RESOLVERS=$(quote_env "${LATTICE_IP_RESOLVERS:-}")
LATTICE_IP_SCRIPT=$(quote_env "${LATTICE_IP_SCRIPT:-}")
LATTICE_PUBLIC_IP=$(quote_env "${LATTICE_PUBLIC_IP:-}")
LATTICE_PUBLIC_IP6=$(quote_env "${LATTICE_PUBLIC_IP6:-}")
EOF

cat >"$unit_path" <<EOF
[Unit]
Description=Lattice node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$env_path
ExecStart=$bin_path -server \${LATTICE_SERVER} -node-id \${LATTICE_NODE_ID} -token \${LATTICE_NODE_TOKEN}
Restart=always
RestartSec=10
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now lattice-agent.service
systemctl --no-pager --lines=20 status lattice-agent.service || true

echo "lattice-agent installed and started for node ${node_id}"
