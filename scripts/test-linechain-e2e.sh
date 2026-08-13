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
agent_bin="$e2e_root/lattice-agent"
agent_test_bin="$e2e_root/lattice-agent.test"
server_dir="${LATTICE_SERVER_E2E_DIR:-}"
if [ -z "$server_dir" ]; then
  for candidate in ../../lattice-server/.wt/worker3-task18-server ../../lattice-server; do
    if [ -f "$candidate/go.mod" ] && grep -q 'module github.com/LatticeNet/lattice-server' "$candidate/go.mod"; then
      server_dir="$(cd "$candidate" && pwd -P)"
      break
    fi
  done
fi
[ -n "$server_dir" ] && [ -f "$server_dir/go.mod" ] || { echo "LATTICE_SERVER_E2E_DIR must identify the frozen lattice-server worktree" >&2; exit 1; }
git -C "$server_dir" diff --quiet 67dc25bc6740657449b6c206cf537b22398bc289 HEAD -- . \
  ':(exclude)internal/server/server_linechain_lifecycle_e2e_test.go' || {
  echo "LATTICE_SERVER_E2E_DIR must match the frozen server plus Task21 Reality repair tree" >&2
  exit 1
}
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

go build -trimpath -o "$agent_bin" ./cmd/lattice-agent
go test -c -tags=linechain_e2e -o "$agent_test_bin" ./cmd/lattice-agent
(
  cd "$server_dir"
  LATTICE_AGENT_E2E_BIN="$agent_bin" LATTICE_AGENT_E2E_TEST_BIN="$agent_test_bin" LATTICE_SINGBOX_E2E_BIN="$bin" \
    go test -tags=linechain_lifecycle_e2e ./internal/server -run '^TestLineChainPersistentServerAgentLifecycleE2E$' -count=1 -v
)
