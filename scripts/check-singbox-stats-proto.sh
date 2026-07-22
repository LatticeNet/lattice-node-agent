#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
commit=1086ab2563320e0da0c23b3a491d8dfa0939dff4
url="https://raw.githubusercontent.com/SagerNet/sing-box/$commit/experimental/v2rayapi/stats.proto"
tmp=$(mktemp "${TMPDIR:-/tmp}/singbox-stats-proto.XXXXXX")
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$url" |
  sed 's#github.com/sagernet/sing-box/experimental/v2rayapi#github.com/LatticeNet/lattice-node-agent/internal/proxyusage/singboxstats#' >"$tmp"

cmp "$tmp" "$repo_root/internal/proxyusage/singboxstats/stats.proto"
printf 'sing-box stats proto matches upstream commit %s (go_package adjusted)\n' "$commit"
