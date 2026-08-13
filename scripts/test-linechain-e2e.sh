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
trap 'find "$probe" -type f -delete 2>/dev/null || true; rmdir "$probe" 2>/dev/null || true' EXIT HUP INT TERM
cat >"$probe/config.json" <<'JSON'
{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
JSON
"$bin" check -C "$probe" >/dev/null 2>&1 || { echo "sing-box 1.13.x config check failed" >&2; exit 1; }
printf '%s\n' "linechain E2E binary: $(printf '%s\n' "$version" | sed -n '1p')"

LATTICE_SINGBOX_E2E_BIN="$bin" go test -tags=linechain_e2e ./cmd/lattice-agent -run '^TestLinechainRealSingBoxE2E$' -count=1 -v
