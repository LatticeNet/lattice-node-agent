#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/lattice-install-integrity.$$"
FAKEBIN="$TMP/bin"
HOME_DIR="$TMP/home"
LOG="$TMP/install.log"

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$FAKEBIN" "$HOME_DIR"

cat >"$FAKEBIN/id" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  printf '0\n'
  exit 0
fi
exit 1
SH
chmod +x "$FAKEBIN/id"

cat >"$FAKEBIN/uname" <<'SH'
#!/usr/bin/env sh
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) printf 'Linux\n' ;;
esac
SH
chmod +x "$FAKEBIN/uname"

cat >"$FAKEBIN/curl" <<'SH'
#!/usr/bin/env sh
url=""
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      out="${1:-}"
      ;;
    -*)
      ;;
    *)
      url="$1"
      ;;
  esac
  shift || true
done
[ -n "$url" ] || exit 2
case "$url" in
  */SHA256SUMS)
    exit 22
    ;;
esac
[ -n "$out" ] || exit 2
printf 'fake lattice agent\n' >"$out"
SH
chmod +x "$FAKEBIN/curl"

cat >"$FAKEBIN/install" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "-m" ]; then
  shift 2
fi
cp "$1" "$2"
SH
chmod +x "$FAKEBIN/install"

if PATH="$FAKEBIN:/usr/bin:/bin" \
  LATTICE_HOME="$HOME_DIR" \
  LATTICE_AGENT_BIN="$HOME_DIR/lattice-agent" \
  LATTICE_AGENT_ENV="$HOME_DIR/lattice-agent.env" \
  LATTICE_AGENT_STATE="$HOME_DIR/state" \
  LATTICE_SERVER="https://lattice.example.com" \
  LATTICE_NODE_ID="node-test" \
  LATTICE_NODE_TOKEN="node-token-test" \
  sh "$ROOT/scripts/install.sh" >"$LOG" 2>&1; then
  echo "installer succeeded without SHA256SUMS" >&2
  exit 1
fi

if [ -e "$HOME_DIR/lattice-agent" ]; then
  echo "installer wrote a binary after checksum manifest download failed" >&2
  cat "$LOG" >&2
  exit 1
fi

if ! grep -Fq "SHA256SUMS" "$LOG"; then
  echo "installer failure did not mention SHA256SUMS" >&2
  cat "$LOG" >&2
  exit 1
fi

if ! grep -Fq '"/etc/lattice/agent.env"' "$ROOT/scripts/install.sh"; then
  echo "installer must adopt legacy /etc/lattice/agent.env configs" >&2
  exit 1
fi

if ! grep -Fq "curl -fsSL --proto '=https' --tlsv1.2" "$ROOT/scripts/install.sh"; then
  echo "installer curl downloader must refuse non-HTTPS redirects" >&2
  exit 1
fi

if ! grep -Fq "wget --https-only -qO" "$ROOT/scripts/install.sh"; then
  echo "installer wget downloader must refuse non-HTTPS redirects" >&2
  exit 1
fi

for expected in \
  'LATTICE_AGENT_RUN_USER="${LATTICE_AGENT_RUN_USER:-}"' \
  'LATTICE_AGENT_RUN_USER=$(quote_env "$run_user")' \
  'User=$run_user' \
  'Group=$run_group' \
  'Delegate=yes' \
  'chown "$run_user:$run_group" "$state_dir"'
do
  if ! grep -Fq "$expected" "$ROOT/scripts/install.sh"; then
    echo "installer non-root systemd contract missing: $expected" >&2
    exit 1
  fi
done

DARWIN_TMP="$TMP/darwin"
DARWIN_BIN="$DARWIN_TMP/bin"
DARWIN_HOME="$DARWIN_TMP/home"
DARWIN_LOG="$DARWIN_TMP/install.log"
DARWIN_PLIST="$DARWIN_HOME/lattice-agent.plist"
mkdir -p "$DARWIN_BIN" "$DARWIN_HOME"

cat >"$DARWIN_BIN/id" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  printf '0\n'
  exit 0
fi
exit 1
SH
chmod +x "$DARWIN_BIN/id"

cat >"$DARWIN_BIN/uname" <<'SH'
#!/usr/bin/env sh
case "${1:-}" in
  -s) printf 'Darwin\n' ;;
  -m) printf 'x86_64\n' ;;
  *) printf 'Darwin\n' ;;
esac
SH
chmod +x "$DARWIN_BIN/uname"

cat >"$DARWIN_BIN/curl" <<'SH'
#!/usr/bin/env sh
url=""
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      out="${1:-}"
      ;;
    -*)
      ;;
    *)
      url="$1"
      ;;
  esac
  shift || true
done
[ -n "$url" ] || exit 2
[ -n "$out" ] || exit 2
case "$url" in
  */SHA256SUMS)
    printf 'd59eab46f15b0b8c2b436975504874ec2f103fe5c588af5784f8d5fde28d9fed  lattice-agent-darwin-amd64\n' >"$out"
    ;;
  *)
    printf 'fake lattice agent\n' >"$out"
    ;;
esac
SH
chmod +x "$DARWIN_BIN/curl"

cat >"$DARWIN_BIN/install" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "-m" ]; then
  shift 2
fi
cp "$1" "$2"
SH
chmod +x "$DARWIN_BIN/install"

cat >"$DARWIN_BIN/launchctl" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod +x "$DARWIN_BIN/launchctl"

special_server='https://lattice.example.com/control?x=1&y=<node>'
special_token='tok<&"'"'"'>'

if ! PATH="$DARWIN_BIN:/usr/bin:/bin" \
  LATTICE_HOME="$DARWIN_HOME" \
  LATTICE_AGENT_BIN="$DARWIN_HOME/lattice-agent" \
  LATTICE_AGENT_ENV="$DARWIN_HOME/lattice-agent.env" \
  LATTICE_AGENT_STATE="$DARWIN_HOME/state&logs" \
  LATTICE_AGENT_PLIST="$DARWIN_PLIST" \
  LATTICE_SERVER="$special_server" \
  LATTICE_NODE_ID="node&mac" \
  LATTICE_NODE_TOKEN="$special_token" \
  LATTICE_IP_MODE="script" \
  LATTICE_IP_RESOLVERS="https://api.example.com/ip?format=json&node=<self>" \
  LATTICE_IP_SCRIPT="/usr/local/bin/ip&probe" \
  LATTICE_PUBLIC_IP="203.0.113.7" \
  LATTICE_PUBLIC_IP6="2001:db8::7" \
  sh "$ROOT/scripts/install.sh" >"$DARWIN_LOG" 2>&1; then
  echo "darwin launchd installer scenario failed" >&2
  cat "$DARWIN_LOG" >&2
  exit 1
fi

if ! grep -Fq '<key>LATTICE_SERVER</key><string>https://lattice.example.com/control?x=1&amp;y=&lt;node&gt;</string>' "$DARWIN_PLIST"; then
  echo "launchd plist did not XML-escape LATTICE_SERVER" >&2
  cat "$DARWIN_PLIST" >&2
  exit 1
fi

if ! grep -Fq '<key>LATTICE_NODE_TOKEN</key><string>tok&lt;&amp;&quot;&apos;&gt;</string>' "$DARWIN_PLIST"; then
  echo "launchd plist did not XML-escape LATTICE_NODE_TOKEN" >&2
  cat "$DARWIN_PLIST" >&2
  exit 1
fi

for expected in \
  '<key>LATTICE_IP_MODE</key><string>script</string>' \
  '<key>LATTICE_IP_RESOLVERS</key><string>https://api.example.com/ip?format=json&amp;node=&lt;self&gt;</string>' \
  '<key>LATTICE_IP_SCRIPT</key><string>/usr/local/bin/ip&amp;probe</string>' \
  '<key>LATTICE_PUBLIC_IP</key><string>203.0.113.7</string>' \
  '<key>LATTICE_PUBLIC_IP6</key><string>2001:db8::7</string>'
do
  if ! grep -Fq "$expected" "$DARWIN_PLIST"; then
    echo "launchd plist missing persisted IP config: $expected" >&2
    cat "$DARWIN_PLIST" >&2
    exit 1
  fi
done

printf 'install integrity contract ok\n'
