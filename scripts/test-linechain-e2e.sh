#!/bin/sh
set -eu

bin="${LATTICE_SINGBOX_E2E_BIN:-}"
[ -n "$bin" ] || { echo "LATTICE_SINGBOX_E2E_BIN is required" >&2; exit 1; }
case "$bin" in /*) ;; *) echo "LATTICE_SINGBOX_E2E_BIN must be absolute" >&2; exit 1;; esac
[ -x "$bin" ] || { echo "LATTICE_SINGBOX_E2E_BIN must be executable" >&2; exit 1; }
version="$($bin version 2>&1)" || { echo "sing-box version failed" >&2; exit 1; }
printf '%s\n' "$version" | grep -Eq '^sing-box version 1\.13\.[0-9]+' || {
  echo "LATTICE_SINGBOX_E2E_BIN must be official sing-box 1.13.x" >&2
  printf '%s\n' "$version" >&2
  exit 1
}

probe="$(mktemp -d "${TMPDIR:-/tmp}/lattice-sing-box-check.XXXXXX")"
e2e_root="$(mktemp -d "${TMPDIR:-/tmp}/lattice-linechain-e2e.XXXXXX")"
cleanup() {
  status=$?
	trap - EXIT HUP INT TERM
  if ps -axo command= | grep -F "$e2e_root" | grep -E 'sing-box|lattice-agent\.test' | grep -v grep >/dev/null; then
    echo "linechain E2E leaked process for $e2e_root" >&2
    ps -axo pid=,ppid=,command= | grep -F "$e2e_root" | grep -E 'sing-box|lattice-agent\.test' | grep -v grep >&2 || true
    ps -axo pid=,command= | grep -F "$e2e_root" | grep -E 'sing-box|lattice-agent\.test' | grep -v grep | while read -r leaked_pid _; do
      kill -TERM "-$leaked_pid" 2>/dev/null || kill -TERM "$leaked_pid" 2>/dev/null || true
      sleep 0.1
      kill -KILL "-$leaked_pid" 2>/dev/null || kill -KILL "$leaked_pid" 2>/dev/null || true
    done
    status=1
  fi
  find "$probe" "$e2e_root" -type f -delete 2>/dev/null || true
  find "$probe" "$e2e_root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

# Prove the root-tagged process detector before relying on it for the real run.
sh -c 'trap : TERM; while :; do sleep 1; done' "$e2e_root" &
detector_pid=$!
ps -axo command= | grep -F "$e2e_root" | grep -F 'while :' >/dev/null || {
  kill "$detector_pid" 2>/dev/null || true
  wait "$detector_pid" 2>/dev/null || true
  echo "linechain E2E leak detector self-test failed" >&2
  exit 1
}
kill -KILL "$detector_pid" 2>/dev/null || true
wait "$detector_pid" 2>/dev/null || true
cat >"$probe/config.json" <<'JSON'
{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
JSON
"$bin" check -C "$probe" >/dev/null 2>&1 || { echo "sing-box 1.13.x config check failed" >&2; exit 1; }
printf '%s\n' "linechain E2E binary: $(printf '%s\n' "$version" | sed -n '1p')"

LATTICE_SINGBOX_E2E_BIN="$bin" LATTICE_LINECHAIN_E2E_ROOT="$e2e_root" go test -tags=linechain_e2e ./cmd/lattice-agent -run '^TestLinechainRealSingBoxE2E$' -count=1 -v
