#!/usr/bin/env sh
set -eu

workflow=".github/workflows/release.yml"

if [ ! -f "$workflow" ]; then
  echo "missing $workflow" >&2
  exit 1
fi

require() {
  pattern="$1"
  description="$2"
  if ! grep -Fq -- "$pattern" "$workflow"; then
    echo "release workflow missing: $description ($pattern)" >&2
    exit 1
  fi
}

require "contents: write" "permission to create or update GitHub Releases"
require "attestations: write" "permission to publish artifact attestations"
require "id-token: write" "OIDC token permission for artifact attestations"
require "lattice-agent-linux-amd64" "linux amd64 release binary"
require "lattice-agent-linux-arm64" "linux arm64 release binary"
require "SHA256SUMS" "combined checksum manifest"
require '-X main.version=$VERSION' "release tag injected into agent -version"
require "gh release" "GitHub Release publication"
