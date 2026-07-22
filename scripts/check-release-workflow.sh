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
require "actions/checkout@v6" "Node 24-compatible checkout action"
require "actions/setup-go@v6" "Node 24-compatible Go setup action"
require "cache: false" "disabled setup-go cache because this repo has no go.sum"
require "actions/attest-build-provenance@v4" "Node 24-compatible provenance action"
require "actions/upload-artifact@v7" "Node 24-compatible artifact upload action"
require "actions/download-artifact@v8" "Node 24-compatible artifact download action"
require "lattice-agent-linux-amd64" "linux amd64 release binary"
require "lattice-agent-linux-arm64" "linux arm64 release binary"
require "lattice-agent-darwin-amd64" "darwin amd64 release binary"
require "lattice-agent-darwin-arm64" "darwin arm64 release binary"
require "SHA256SUMS" "combined checksum manifest"
require '-X main.version=$VERSION' "release tag injected into agent -version"
require '-X main.compatServerMin=$LATTICE_COMPAT_SERVER_MIN' "release compatibility server floor injected"
require '-compat-json' "release binary exposes embedded compatibility metadata"
require 'LATTICE_COMPAT_CHANNEL=stable' "stable release compatibility channel default"
require '*-alpha.*) LATTICE_COMPAT_CHANNEL=alpha' "alpha tag compatibility channel"
require 'vX.Y.Z-alpha.N / beta.N / rc.N' "prerelease tag format guard"
require '--prerelease --latest=false' "prereleases must not become GitHub Latest"
require 'make_latest=$MAKE_LATEST' "existing releases have latest/prerelease metadata corrected"
require "gh release" "GitHub Release publication"

if grep -Fq -- "github.com/LatticeNet/lattice-sdk@v0.2.0" "$workflow"; then
  echo "release workflow must not pin a stale lattice-sdk workspace replace" >&2
  exit 1
fi

if grep -Fq -- "checkout lattice-sdk" "$workflow" || grep -Fq -- "go work init ./lattice-sdk" "$workflow"; then
  echo "release workflow must build the SDK version pinned in go.mod" >&2
  exit 1
fi
