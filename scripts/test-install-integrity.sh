#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/lattice-install-integrity.$$"
FAKEBIN="$TMP/bin"
HOME_DIR="$TMP/home"
LOG="$TMP/install.log"
# The shell that runs the installer: sh by default. INSTALL_SH=dash holds the
# installer itself, not only this script, to another shell on the same host.
INSTALL_SH="$(command -v "${INSTALL_SH:-sh}")" || { echo "no shell named ${INSTALL_SH:-sh}" >&2; exit 1; }

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
  "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$LOG" 2>&1; then
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

if ! grep -Fq "wget --https-only -q " "$ROOT/scripts/install.sh"; then
  echo "installer wget downloader must refuse non-HTTPS redirects" >&2
  exit 1
fi

for expected in \
  'LATTICE_AGENT_RUN_USER="${LATTICE_AGENT_RUN_USER:-}"' \
  'LATTICE_AGENT_RUN_USER=$(quote_env "$run_user")' \
  'User=$run_user' \
  'Group=$run_group' \
  'Delegate=yes' \
  'chown "$run_user:$run_group" "$state_dir"' \
  'LATTICE_TASK_OUTBOX_DIR="${LATTICE_TASK_OUTBOX_DIR:-}"' \
  'LATTICE_TASK_OUTBOX_DIR=$(quote_env "${LATTICE_TASK_OUTBOX_DIR:-}")' \
  'chown "$run_user:$run_group" "$task_outbox_leaf"' \
  'LATTICE_LINECHAIN_TXN_DIR="$linechain_txn_dir"' \
  'LATTICE_LINECHAIN_TXN_DIR=$(quote_env "$linechain_txn_dir")' \
  'prepare_linechain_txn_dir' \
  'chmod 0700 "$linechain_txn_dir"' \
  'chown "$run_user:$run_group" "$linechain_txn_dir"'
do
  if ! grep -Fq "$expected" "$ROOT/scripts/install.sh"; then
    echo "installer non-root systemd contract missing: $expected" >&2
    exit 1
  fi
done

# Keepalive supervision: the drop-in is written only for a binary that
# advertises sd-notify-v1, it grants a notify socket without turning the unit
# into Type=notify (an older binary installed later must not be killed for
# never sending READY=1), and openrc gets a supervisor that restarts a crash.
for expected in \
  "-compat-json 2>/dev/null | grep -Fq '\"sd-notify-v1\"'" \
  'keepalive_dropin="$keepalive_dropin_dir/10-lattice-keepalive.conf"' \
  'NotifyAccess=main' \
  'RuntimeDirectory=$service_name' \
  'rm -f "$keepalive_dropin"' \
  'supervisor=supervise-daemon' \
  'respawn_max=0'
do
  if ! grep -Fq -- "$expected" "$ROOT/scripts/install.sh"; then
    echo "installer keepalive contract missing: $expected" >&2
    exit 1
  fi
done
for forbidden in 'Type=notify' 'WatchdogSec='; do
  if grep -Fq -- "$forbidden" "$ROOT/scripts/install.sh"; then
    echo "installer must not write $forbidden: an older binary under it is killed at start or by the watchdog" >&2
    exit 1
  fi
done

UNSAFE_LOG="$TMP/unsafe-outbox.log"
if PATH="$FAKEBIN:/usr/bin:/bin" \
  LATTICE_HOME="$HOME_DIR" \
  LATTICE_AGENT_BIN="$HOME_DIR/lattice-agent" \
  LATTICE_AGENT_ENV="$HOME_DIR/lattice-agent.env" \
  LATTICE_AGENT_STATE="$HOME_DIR/state" \
  LATTICE_TASK_OUTBOX_DIR="/" \
  LATTICE_SERVER="https://lattice.example.com" \
  LATTICE_NODE_ID="node-test" \
  LATTICE_NODE_TOKEN="node-token-test" \
  "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$UNSAFE_LOG" 2>&1; then
  echo "installer accepted filesystem root as task outbox" >&2
  exit 1
fi
if ! grep -Fq "must not be a filesystem or system root" "$UNSAFE_LOG"; then
  echo "unsafe outbox rejection was not explicit" >&2
  cat "$UNSAFE_LOG" >&2
  exit 1
fi

SYMLINK_BASE="$TMP/outbox-link"
ln -s "$HOME_DIR" "$SYMLINK_BASE"
if PATH="$FAKEBIN:/usr/bin:/bin" \
  LATTICE_HOME="$HOME_DIR" \
  LATTICE_AGENT_BIN="$HOME_DIR/lattice-agent" \
  LATTICE_AGENT_ENV="$HOME_DIR/lattice-agent.env" \
  LATTICE_AGENT_STATE="$HOME_DIR/state" \
  LATTICE_TASK_OUTBOX_DIR="$SYMLINK_BASE" \
  LATTICE_SERVER="https://lattice.example.com" \
  LATTICE_NODE_ID="node-test" \
  LATTICE_NODE_TOKEN="node-token-test" \
  "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$UNSAFE_LOG" 2>&1; then
  echo "installer accepted symlinked task outbox" >&2
  exit 1
fi
if ! grep -Fq "must not traverse symlinks" "$UNSAFE_LOG"; then
  echo "symlinked outbox rejection was not explicit" >&2
  cat "$UNSAFE_LOG" >&2
  exit 1
fi

NESTED_SYMLINK_PARENT="$TMP/outbox-parent-link"
ln -s "$HOME_DIR" "$NESTED_SYMLINK_PARENT"
if PATH="$FAKEBIN:/usr/bin:/bin" \
  LATTICE_HOME="$HOME_DIR" \
  LATTICE_AGENT_BIN="$HOME_DIR/lattice-agent" \
  LATTICE_AGENT_ENV="$HOME_DIR/lattice-agent.env" \
  LATTICE_AGENT_STATE="$HOME_DIR/state" \
  LATTICE_TASK_OUTBOX_DIR="$NESTED_SYMLINK_PARENT/nested" \
  LATTICE_SERVER="https://lattice.example.com" \
  LATTICE_NODE_ID="node-test" \
  LATTICE_NODE_TOKEN="node-token-test" \
  "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$UNSAFE_LOG" 2>&1; then
  echo "installer accepted non-root-owned parent symlink for task outbox" >&2
  exit 1
fi
if ! grep -Fq "must not traverse a non-root-owned symlink" "$UNSAFE_LOG"; then
  echo "nested symlinked outbox rejection was not explicit" >&2
  cat "$UNSAFE_LOG" >&2
  exit 1
fi
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
  LATTICE_TASK_OUTBOX_DIR="$DARWIN_HOME/outbox&state" \
  LATTICE_AGENT_PLIST="$DARWIN_PLIST" \
  LATTICE_SERVER="$special_server" \
  LATTICE_NODE_ID="node&mac" \
  LATTICE_NODE_TOKEN="$special_token" \
  LATTICE_IP_MODE="script" \
  LATTICE_IP_RESOLVERS="https://api.example.com/ip?format=json&node=<self>" \
  LATTICE_IP_SCRIPT="/usr/local/bin/ip&probe" \
  LATTICE_PUBLIC_IP="203.0.113.7" \
  LATTICE_PUBLIC_IP6="2001:db8::7" \
  "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$DARWIN_LOG" 2>&1; then
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
  '<key>LATTICE_PUBLIC_IP6</key><string>2001:db8::7</string>' \
  '<key>LATTICE_TASK_OUTBOX_DIR</key><string>'"$DARWIN_HOME"'/outbox&amp;state</string>'
do
  if ! grep -Fq "$expected" "$DARWIN_PLIST"; then
    echo "launchd plist missing persisted IP config: $expected" >&2
    cat "$DARWIN_PLIST" >&2
    exit 1
  fi
done

# ---- ordered sources and rendered digests (design 31 S6) -------------------
# A darwin/arm64 install against one fake downloader that serves fixtures by
# host and records each call: the URL, how many bytes the output file held
# when the call began (where a resume starts), and every argument.
#   mirror-evil.example.com          serves wrong bytes in full
#   mirror-cut.example.com           writes 7 wrong bytes, then fails as a cut transfer does
#   mirror-good.example.com          serves the right bytes
#   release.example.com, github.com  serve the right bytes and SHA256SUMS
# The same script is installed as curl and, for the wget run, as wget.
SRC_TMP="$TMP/sources"
SRC_BIN="$SRC_TMP/bin"
FIX="$SRC_TMP/fixtures"
mkdir -p "$SRC_BIN" "$FIX"
GOOD_SHA="d59eab46f15b0b8c2b436975504874ec2f103fe5c588af5784f8d5fde28d9fed"
OTHER_SHA="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
printf 'fake lattice agent\n' >"$FIX/good"
printf 'evil lattice agent, longer than the real one\n' >"$FIX/evil"
printf '%s  lattice-agent-darwin-arm64\n%s  lattice-agent-linux-amd64\n' "$GOOD_SHA" "$OTHER_SHA" >"$FIX/SHA256SUMS"
cp "$DARWIN_BIN/id" "$DARWIN_BIN/install" "$DARWIN_BIN/launchctl" "$SRC_BIN/"
cat >"$SRC_BIN/uname" <<'SH'
#!/usr/bin/env sh
case "${1:-}" in
  -m) printf 'arm64\n' ;;
  *) printf 'Darwin\n' ;;
esac
SH
chmod +x "$SRC_BIN/uname"

cat >"$SRC_BIN/curl" <<'SH'
#!/usr/bin/env sh
case "${0##*/}" in
  wget) out_flag="-O"; resume_flag="-c" ;;
  *) out_flag="-o"; resume_flag="-C -" ;;
esac
out=""
prev=""
for a in "$@"; do
  [ "$prev" != "$out_flag" ] || out="$a"
  prev="$a"
done
url="$prev"
[ -n "$out" ] || exit 2
offset=0
[ ! -f "$out" ] || offset="$(wc -c <"$out" | tr -d ' ')"
printf '%s offset=%s args: %s\n' "$url" "$offset" "$*" >>"$FAKE_CALLS"
skip=0
case " $* " in *" $resume_flag "*) skip="$offset" ;; esac
[ "$skip" -gt 0 ] || : >"$out"
case "$url" in
  https://release-upper.example.com/*/SHA256SUMS)
    awk '{ print toupper($1) "  " $2 }' "$FAKE_DIR/SHA256SUMS" >"$out" ;;
  https://release.example.com/*/SHA256SUMS|https://release-strict.example.com/*/SHA256SUMS|https://github.com/*/SHA256SUMS)
    cat "$FAKE_DIR/SHA256SUMS" >"$out" ;;
  https://mirror-evil.example.com/*)
    tail -c +"$((skip + 1))" "$FAKE_DIR/evil" >>"$out" ;;
  https://mirror-cut.example.com/*)
    tail -c +"$((skip + 1))" "$FAKE_DIR/evil" | head -c 7 >>"$out"
    exit 18 ;;
  https://mirror-long.example.com/*)
    # Wrong bytes past the real end, then a cut transfer.
    tail -c +"$((skip + 1))" "$FAKE_DIR/evil" >>"$out"
    exit 18 ;;
  https://mirror-endless.example.com/*)
    # More than the installer's 64 MiB cap; the cap ends the write.
    head -c "$FAKE_ENDLESS_BYTES" /dev/zero >>"$out" || exit 23 ;;
  https://release-strict.example.com/*)
    # A source that reports a resume at or past its end as an error.
    [ "$skip" -lt "$(wc -c <"$FAKE_DIR/good" | tr -d ' ')" ] || exit 22
    tail -c +"$((skip + 1))" "$FAKE_DIR/good" >>"$out" ;;
  https://mirror-good.example.com/*|https://release.example.com/*|https://release-upper.example.com/*|https://github.com/*)
    tail -c +"$((skip + 1))" "$FAKE_DIR/good" >>"$out" ;;
  *) exit 6 ;;
esac
SH
chmod +x "$SRC_BIN/curl"

# run_src NAME [VAR=value ...]: install with the fixtures; the two new
# variables are empty unless the scenario sets them.
run_src() {
  src_home="$SRC_TMP/$1"
  shift
  mkdir -p "$src_home"
  : >"$src_home.calls"
  env PATH="${SRC_PATH:-$SRC_BIN:/usr/bin:/bin}" FAKE_DIR="$FIX" FAKE_CALLS="$src_home.calls" \
    LATTICE_HOME="$src_home" \
    LATTICE_AGENT_BIN="$src_home/lattice-agent" \
    LATTICE_AGENT_ENV="$src_home/lattice-agent.env" \
    LATTICE_AGENT_STATE="$src_home/state" \
    LATTICE_AGENT_PLIST="$src_home/agent.plist" \
    LATTICE_SERVER="https://lattice.example.com" \
    LATTICE_NODE_ID="node-src" \
    LATTICE_NODE_TOKEN="node-token-src" \
    LATTICE_AGENT_VERSION="v0.3.9" \
    LATTICE_AGENT_SOURCES="" LATTICE_AGENT_SHA256="" \
    "$@" "$INSTALL_SH" "$ROOT/scripts/install.sh" >"$src_home.log" 2>&1 </dev/null
}
src_fail() {
  echo "sources scenario $1: $2" >&2
  cat "$SRC_TMP/$1.log" >&2
  echo "downloads:" >&2
  cat "$SRC_TMP/$1.calls" >&2
  exit 1
}
expect_ok() {
  cmp -s "$SRC_TMP/$1/lattice-agent" "$FIX/good" || src_fail "$1" "the verified binary was not installed"
}
expect_calls() {
  [ "$(wc -l <"$SRC_TMP/$1.calls" | tr -d ' ')" = "$2" ] || src_fail "$1" "expected $2 downloads"
}
# expect_call NAME N URL OFFSET [NEEDLE ...]: download N fetched URL starting
# at byte OFFSET, with every NEEDLE among its arguments.
expect_call() {
  ec_name="$1"
  ec_n="$2"
  ec_line="$(sed -n "${2}p" "$SRC_TMP/$1.calls")"
  case "$ec_line" in
    "$3 offset=$4 args: "*) ;;
    *) src_fail "$ec_name" "download $ec_n was not $3 from byte $4" ;;
  esac
  shift 4
  for ec_needle in "$@"; do
    case "$ec_line" in
      *"$ec_needle"*) ;;
      *) src_fail "$ec_name" "download $ec_n lacks: $ec_needle" ;;
    esac
  done
}
# expect_call_without NAME N NEEDLE ...: download N carries none of NEEDLE.
expect_call_without() {
  ec_name="$1"
  ec_n="$2"
  ec_line="$(sed -n "${2}p" "$SRC_TMP/$1.calls")"
  shift 2
  for ec_needle in "$@"; do
    case "$ec_line" in
      *"$ec_needle"*) src_fail "$ec_name" "download $ec_n must not carry: $ec_needle" ;;
    esac
  done
}
expect_log() {
  grep -Fq -- "$2" "$SRC_TMP/$1.log" || src_fail "$1" "log does not say: $2"
}
expect_no_fetch_of() {
  if grep -Fq -- "$2" "$SRC_TMP/$1.calls"; then src_fail "$1" "must never download $2"; fi
}
# expect_refused NAME NEEDLE VAR=value ...: the installer dies saying NEEDLE,
# before any download and without writing a binary.
expect_refused() {
  ref_name="$1"
  ref_needle="$2"
  shift 2
  if run_src "$ref_name" "$@"; then src_fail "$ref_name" "installer accepted it"; fi
  expect_log "$ref_name" "$ref_needle"
  [ ! -s "$SRC_TMP/$ref_name.calls" ] || src_fail "$ref_name" "installer downloaded before refusing"
  [ ! -e "$SRC_TMP/$ref_name/lattice-agent" ] || src_fail "$ref_name" "installer wrote a binary"
}

TABLE="linux/amd64=$OTHER_SHA linux/arm64=$OTHER_SHA darwin/arm64=$GOOD_SHA"
LINUX_TABLE="linux/amd64=$OTHER_SHA linux/arm64=$OTHER_SHA"
REL="r=https://release.example.com/download/v0.3.9"
REL_URL="https://release.example.com/download/v0.3.9/lattice-agent-darwin-arm64"
GH_BASE="https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.3.9"
MIRROR_PATH="agent/0.3.9/darwin/arm64/$GOOD_SHA"
CURL_LIMITS=" --connect-timeout 20 --speed-limit 1024 --speed-time 60 -C - -o "
CURL_MIRROR="args: -fsS --proto =https --tlsv1.2$CURL_LIMITS"
CURL_RELEASE="args: -fsSL --proto =https --tlsv1.2 --proto-redir =https$CURL_LIMITS"

# A mirror listed first serves wrong bytes; the release serves the right
# ones. The rendered digest decides, SHA256SUMS is never fetched, the mirror
# fetch follows no redirect, and the release fetch follows HTTPS ones.
run_src evil LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-evil.example.com/agent $REL" || src_fail evil "install failed"
expect_ok evil
expect_calls evil 3
expect_call evil 1 "https://mirror-evil.example.com/$MIRROR_PATH" 0 "$CURL_MIRROR"
expect_call evil 2 "https://mirror-evil.example.com/$MIRROR_PATH" 0 "$CURL_MIRROR"
expect_call evil 3 "$REL_URL" 0 "$CURL_RELEASE"
expect_call_without evil 1 " -L " "-fsSL" "--proto-redir" "--max-time"
expect_call_without evil 3 "--max-time"
expect_no_fetch_of evil SHA256SUMS
expect_log evil "wrong digest"
expect_log evil "checksum verified (sha256 $GOOD_SHA)"

# The mirror cuts out after 7 wrong bytes and the release resumes the same
# partial from byte 7 (-C -), so the finished file mismatches. The second
# round fetches each source from byte zero and the release verifies alone.
run_src splice LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-cut.example.com/agent $REL" || src_fail splice "install failed"
expect_ok splice
expect_calls splice 4
expect_call splice 1 "https://mirror-cut.example.com/$MIRROR_PATH" 0 "$CURL_MIRROR"
expect_call splice 2 "$REL_URL" 7 "$CURL_RELEASE"
expect_call splice 3 "https://mirror-cut.example.com/$MIRROR_PATH" 0
expect_call splice 4 "$REL_URL" 0
expect_log splice "second round"

# An honest mirror is enough: the release is never contacted. A trailing
# slash on the base does not double the path separator.
run_src mirror-good LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent/ $REL" || src_fail mirror-good "install failed"
expect_ok mirror-good
expect_calls mirror-good 1
expect_call mirror-good 1 "https://mirror-good.example.com/$MIRROR_PATH" 0 "$CURL_MIRROR"

# A table without this platform (the control plane renders only what it has
# verified) skips every mirror and verifies against SHA256SUMS from the
# first release base, as an install without a table does.
run_src no-platform LATTICE_AGENT_SHA256="$LINUX_TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent $REL" || src_fail no-platform "install failed"
expect_ok no-platform
expect_calls no-platform 2
expect_call no-platform 1 "https://release.example.com/download/v0.3.9/SHA256SUMS" 0
expect_call no-platform 2 "$REL_URL" 0 "$CURL_RELEASE"
expect_no_fetch_of no-platform mirror-good
expect_log no-platform "has no digest for darwin/arm64"

# Without a table a mirror is skipped with a log line.
run_src no-table LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent $REL" || src_fail no-table "install failed"
expect_ok no-table
expect_calls no-table 2
expect_call no-table 1 "https://release.example.com/download/v0.3.9/SHA256SUMS" 0
expect_call no-table 2 "$REL_URL" 0
expect_no_fetch_of no-table mirror-good
expect_log no-table "skipping mirror https://mirror-good.example.com/agent"

# Neither variable: the GitHub release and its SHA256SUMS, as before.
run_src stand-alone || src_fail stand-alone "install failed"
expect_ok stand-alone
expect_calls stand-alone 2
expect_call stand-alone 1 "$GH_BASE/SHA256SUMS" 0
expect_call stand-alone 2 "$GH_BASE/lattice-agent-darwin-arm64" 0 "$CURL_RELEASE"

# A table without sources: the GitHub release, verified against the table.
run_src table-only LATTICE_AGENT_SHA256="$TABLE" || src_fail table-only "install failed"
expect_ok table-only
expect_calls table-only 1
expect_call table-only 1 "$GH_BASE/lattice-agent-darwin-arm64" 0

# A mirror leaves wrong bytes past the real end and fails, and the release
# refuses to resume past its end. Nothing mismatched, but a source continued
# another's partial, so the second round runs and the release verifies alone.
run_src long LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-long.example.com/agent r=https://release-strict.example.com/download/v0.3.9" || src_fail long "install failed"
STRICT_URL="https://release-strict.example.com/download/v0.3.9/lattice-agent-darwin-arm64"
expect_ok long
expect_calls long 4
expect_call long 2 "$STRICT_URL" "$(wc -c <"$FIX/evil" | tr -d ' ')"
expect_call long 4 "$STRICT_URL" 0
expect_log long "second round"

# A mirror that streams without end stops at the installer's file-size cap of
# 131072 blocks, and the release's resume starts exactly there. The block is
# measured with the shell that runs the installer: 512 bytes in dash, busybox
# ash and later bash, 1024 in macOS's bash 3.2.
"$INSTALL_SH" -c "( trap '' XFSZ; ulimit -f 1; head -c 4096 /dev/zero >'$FIX/block' ) 2>/dev/null; :"
CAP_BYTES=$((131072 * $(wc -c <"$FIX/block" | tr -d ' ')))
run_src endless FAKE_ENDLESS_BYTES=$((CAP_BYTES + 1048576)) LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-endless.example.com/agent $REL" || src_fail endless "install failed"
expect_ok endless
expect_call endless 2 "$REL_URL" "$CAP_BYTES"

# Every source serves bytes that miss the rendered digest: nothing is
# installed, and the refusal names what each attempt did.
if run_src all-wrong LATTICE_AGENT_SHA256="darwin/arm64=$OTHER_SHA" \
  LATTICE_AGENT_SOURCES="m=https://mirror-evil.example.com/agent $REL"; then
  src_fail all-wrong "installer accepted bytes that match no digest"
fi
[ ! -e "$SRC_TMP/all-wrong/lattice-agent" ] || src_fail all-wrong "installer wrote a binary"
expect_calls all-wrong 3
expect_log all-wrong "checksum verification failed"
expect_log all-wrong "round 1, https://mirror-evil.example.com/agent/0.3.9/darwin/arm64/$OTHER_SHA: digest mismatch"
expect_log all-wrong "round 2, $REL_URL: digest mismatch (got $GOOD_SHA)"

# Every source fails outright: no partial, so no second round.
if run_src all-down LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-down.example.com/agent r=https://release-down.example.com/x"; then
  src_fail all-down "installer succeeded with no source"
fi
expect_calls all-down 2
expect_log all-down "download failed: no source delivered"
expect_log all-down "round 1, https://release-down.example.com/x/lattice-agent-darwin-arm64: download failed (curl exit 6)"

# latest names no mirror path, so a mirror is skipped with a log line.
run_src latest LATTICE_AGENT_VERSION=latest LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent $REL" || src_fail latest "install failed"
expect_ok latest
expect_calls latest 1
expect_call latest 1 "$REL_URL" 0
expect_log latest "needs an exact LATTICE_AGENT_VERSION"

# SHA256SUMS written in upper case still verifies, as sha256sum -c did.
run_src sums-upper LATTICE_AGENT_SOURCES="r=https://release-upper.example.com/download/v0.3.9" || src_fail sums-upper "install failed"
expect_ok sums-upper

# The sudo re-exec carries both variables. The fake sudo clears the
# environment as sudo's env_reset does, keeping only what this harness needs.
SUDO_BIN="$SRC_TMP/sudo-bin"
mkdir -p "$SUDO_BIN"
cp "$SRC_BIN/install" "$SRC_BIN/launchctl" "$SRC_BIN/uname" "$SRC_BIN/curl" "$SUDO_BIN/"
cat >"$SUDO_BIN/id" <<'SH'
#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  if [ "${FAKE_ROOT:-}" = 1 ]; then printf '0\n'; else printf '1000\n'; fi
  exit 0
fi
exit 1
SH
cat >"$SUDO_BIN/sudo" <<'SH'
#!/usr/bin/env sh
exec env -i PATH="$PATH" FAKE_ROOT=1 FAKE_DIR="$FAKE_DIR" FAKE_CALLS="$FAKE_CALLS" \
  LATTICE_AGENT_PLIST="$LATTICE_AGENT_PLIST" "$@"
SH
chmod +x "$SUDO_BIN/id" "$SUDO_BIN/sudo"
SRC_PATH="$SUDO_BIN:/usr/bin:/bin" run_src sudo LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent $REL" || src_fail sudo "install failed"
SRC_PATH=""
expect_ok sudo
expect_log sudo "re-running with sudo"
expect_calls sudo 1
expect_call sudo 1 "https://mirror-good.example.com/$MIRROR_PATH" 0

# Malformed tables and sources die before any download.
upper_sha="$(printf '%s' "$GOOD_SHA" | tr 'abcdef' 'ABCDEF')"
expect_refused sha-upper "64 lowercase hex" LATTICE_AGENT_SHA256="darwin/arm64=$upper_sha"
expect_refused sha-short "64 lowercase hex" LATTICE_AGENT_SHA256="darwin/arm64=${GOOD_SHA%?}"
expect_refused sha-no-digest "is not os/arch=<sha256>" LATTICE_AGENT_SHA256="darwin/arm64"
expect_refused sha-no-arch "malformed os/arch" LATTICE_AGENT_SHA256="darwin=$GOOD_SHA"
expect_refused sha-deep-key "malformed os/arch" LATTICE_AGENT_SHA256="darwin/arm64/x=$GOOD_SHA"
expect_refused sha-other-entry "64 lowercase hex" LATTICE_AGENT_SHA256="linux/amd64=xyz darwin/arm64=$GOOD_SHA"
expect_refused sha-twice "lists darwin/arm64 twice" LATTICE_AGENT_SHA256="darwin/arm64=$GOOD_SHA darwin/arm64=$GOOD_SHA"
expect_refused sha-newline "64 lowercase hex" LATTICE_AGENT_SHA256="darwin/arm64=$GOOD_SHA
linux/amd64=$OTHER_SHA"
PWNED="$SRC_TMP/pwned"
expect_refused src-quote "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=https://release.example.com/a'b"
expect_refused src-joined "LATTICE_AGENT_SOURCES: a source must be" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="$REL ;touch $PWNED"
expect_refused src-subst "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES='r=https://release.example.com/$(touch '"$PWNED"')'
expect_refused src-backtick "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES='r=https://release.example.com/`touch '"$PWNED"'`'
expect_refused src-http "LATTICE_AGENT_SOURCES: a source must be" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=http://release.example.com/download/v0.3.9"
expect_refused src-mirror-http "LATTICE_AGENT_SOURCES: a source must be" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="m=http://mirror-good.example.com/agent $REL"
expect_refused src-kind "LATTICE_AGENT_SOURCES: a source must be" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="x=https://release.example.com/download/v0.3.9"
expect_refused src-userinfo "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=https://user@release.example.com/x?y=1"
expect_refused src-newline "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="$REL
r=https://release.example.com/other"
expect_refused src-glob "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=https://release.example.com/*"
expect_refused src-percent "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=https://release.example.com/%2e%2e"
expect_refused src-fragment "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES="r=https://release.example.com/x#y"
expect_refused src-backslash "LATTICE_AGENT_SOURCES: a base may hold only" \
  LATTICE_AGENT_SHA256="$TABLE" LATTICE_AGENT_SOURCES='r=https://release.example.com/a\b'
expect_refused src-only-mirror "leaves no source to download from" \
  LATTICE_AGENT_SHA256="$LINUX_TABLE" LATTICE_AGENT_SOURCES="m=https://mirror-good.example.com/agent"
[ ! -e "$PWNED" ] || { echo "a source value was executed" >&2; exit 1; }

# wget, on a PATH without curl: the mirror fetch carries --max-redirect=0,
# the release fetch does not, both are HTTPS-only and continue the partial.
WGET_BIN="$SRC_TMP/wget-bin"
mkdir -p "$WGET_BIN"
cp "$SRC_BIN/id" "$SRC_BIN/install" "$SRC_BIN/launchctl" "$SRC_BIN/uname" "$WGET_BIN/"
cp "$SRC_BIN/curl" "$WGET_BIN/wget"
for tool in sh awk sed grep mktemp rm mkdir chmod cat cp wc tr tail head sha256sum shasum sha256; do
  tool_path="$(command -v "$tool" 2>/dev/null || true)"
  case "$tool_path" in
    /*) ln -s "$tool_path" "$WGET_BIN/$tool" ;;
  esac
done
SRC_PATH="$WGET_BIN" run_src wget LATTICE_AGENT_SHA256="$TABLE" \
  LATTICE_AGENT_SOURCES="m=https://mirror-evil.example.com/agent $REL" || src_fail wget "install failed"
WGET_LIMITS=" --connect-timeout=20 --read-timeout=60 --tries=2 -c -O "
expect_ok wget
expect_calls wget 3
expect_call wget 1 "https://mirror-evil.example.com/$MIRROR_PATH" 0 "args: --https-only -q --max-redirect=0$WGET_LIMITS"
expect_call wget 3 "$REL_URL" 0 "args: --https-only -q$WGET_LIMITS"
expect_call_without wget 3 "--max-redirect"

printf 'install integrity contract ok\n'
