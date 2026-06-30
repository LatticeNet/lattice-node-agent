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

printf 'install integrity contract ok\n'
