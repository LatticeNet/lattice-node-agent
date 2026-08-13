#!/bin/sh
set -eu

bin="${LATTICE_SINGBOX_E2E_BIN:-}"
[ -n "$bin" ] || { echo "LATTICE_SINGBOX_E2E_BIN is required" >&2; exit 1; }
case "$bin" in /*) ;; *) echo "LATTICE_SINGBOX_E2E_BIN must be absolute" >&2; exit 1;; esac
[ -x "$bin" ] || { echo "LATTICE_SINGBOX_E2E_BIN must be executable" >&2; exit 1; }
"$bin" version >/dev/null 2>&1 || { echo "sing-box version failed" >&2; exit 1; }

LATTICE_SINGBOX_E2E_BIN="$bin" go test ./cmd/lattice-agent -run '^TestLinechainRealSingBoxE2E$' -count=1 -v
