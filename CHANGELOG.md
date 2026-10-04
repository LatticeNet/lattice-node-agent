# Changelog

Release notes for tagged node-agent builds. A version listed as unreleased
is the constant in `cmd/lattice-agent/main.go`, prepared for the next tag but
not yet tagged; the release workflow injects the tag at build time and must
match it.

## 0.3.10-alpha.3 (unreleased)

Prerelease. Changes since v0.3.10-alpha.2.

Control-plane witness:

- `lattice-agent -witness <config>` runs the control-plane witness as its own
  process (`lattice-witness.service`, written by an approved server plan). It
  polls the control plane's public `/readyz` every interval; after the hold
  window of failures with the node's own network up (any HTTP answer from a
  reference URL) it pushes one message through the bark-server on the node's
  loopback interface, and one recovery once the control plane has answered
  without a break for the recovery window. The push is titled "not ready"
  when the control plane answered with something other than 200 and
  "unreachable" when nothing answered. When the control plane and every
  reference fail together it pushes nothing, and the first failed check after
  the node's own network returns only confirms. Its state survives restarts,
  so a restart in the middle of an outage neither pushes twice nor drops the
  recovery. Standard library only; no node token, no fleet data. It has no
  mute: a control plane stop longer than the hold pages.
- The hold and the recovery window are measured on the monotonic clock while
  the witness runs, so a step of the node's wall clock neither pages early nor
  holds a page back. A saved last check later than the node's clock after a
  restart, or a wall clock that moved ahead by more than the gap while the
  monotonic clock stood still (a suspend), starts the count again. The push
  leads with how long the outage has lasted; the node's clock comes second
  and is labelled as such. A check or push cut short by the witness stopping
  is not recorded.
- The Bark device key is read from a root-only file the config names; a file
  readable by group or others, owned by another user, or not shaped like a
  Bark key is refused at start. The config must belong to the witness's user
  and must not be writable by group or others. Both are checked on the opened
  file, not the path, and a FIFO at either path is refused without blocking.
  `-witness-check` validates config and key and prints a summary without the
  key.
- The heartbeat relays the witness status file
  (`/var/lib/lattice-witness/status.json`) as `witness`, with `relayed_at`
  (this node's clock when the agent read it), so the console can show the
  last check and the last push, and the server can tell a witness whose
  service stopped from one that is watching. Older servers ignore the field.
- Hello capabilities and `-compat-json` features list
  `control-plane-witness-v1`, on every beat whether or not linechain recovery
  is ready.

Compatibility: no new server or dashboard floor. The witness plan needs a
server that knows the `controlplane-witness` plan kind
(lattice-server `feat/witness-plan-and-fallback-channel`).

## 0.3.10-alpha.2 (2026-10-03)

Prerelease. Changes since v0.3.10-alpha.1.

- With `-singbox-discover`, the agent asks the node's `sb` script what it can
  do (`sb --json caps`) at startup and at most every 10 minutes, with a 5 s
  timeout, and reports each capability as `sb:<cap>` in the hello and the
  heartbeat. Only the names script v1.24.3-alpha.8 lists pass
  (`user-del-by-name`, `user-park`, `user-parked-list`,
  `user-open-proxy-guard`, `user-match-counts`, `user-socks-add`,
  `user-lock`). An older script, a failure, a timeout or unexpected output
  reports none and leaves the heartbeat unchanged. lattice-server uses
  `sb:user-del-by-name` to remove a deleted VPN user from an adopted line by
  name.
- A timed-out `sb` call no longer waits for a child process that still holds
  its output: the runner gives up one second after the deadline. This also
  covers `sb --json list`.

## 0.3.10-alpha.1 (2026-10-02)

Prerelease. Changes since v0.3.9, the current stable release.

Keepalive:

- The heartbeat (`POST /api/agent/metrics`) runs on its own goroutine every
  interval with a 10 s deadline, so a slow control plane or a stuck report no
  longer flips a healthy node offline. Each beat carries `loop_health`
  (per-step progress, the step in progress, task batch age, monitor queue,
  watchdog state, and a blocked linechain recovery with its reason). A blocked
  recovery keeps the node visible and withholds `durable-task-result-v1`
  until it clears. Older servers ignore the new field.
- When the unit grants a notify socket (`NotifyAccess=main`), the agent sends
  `READY=1`, arms a 120 s systemd watchdog for itself with `WATCHDOG_USEC=`
  once startup recovery has finished, and pets it only while its own loops
  make local progress. An unreachable control plane never stops the
  keepalive; a wedged step does, and systemd restarts the agent. A long
  startup recovery is not a stall.
- After its first successful hello the agent writes its version to
  `$RUNTIME_DIRECTORY/healthy`, which a server-managed update's guard reads
  before it keeps a new binary.
- `-compat-json` lists `features`: `sd-notify-v1` and `health-marker-v1`.
- The installer writes the keepalive drop-in
  (`10-lattice-keepalive.conf`: `NotifyAccess=main`, a runtime directory) for
  a binary that advertises `sd-notify-v1`, and removes it otherwise. The unit
  stays `Type=simple` without `WatchdogSec`, so an older binary under the
  drop-in is unaffected.
- On openrc the installer runs the agent under `supervise-daemon` with a 10 s
  respawn delay where OpenRC provides it.

Monitors:

- Probe results are queued (up to 2000 through an outage) and sent in batches
  of up to 200 on `POST /api/agent/monitor-results`. A server without the
  route answers 404 and the agent posts one result per request, retrying the
  batch route every 30 minutes. The queue is in memory: a clean stop sends it
  once more, a crash loses it. Every result the server never stored is logged
  and counted in `loop_health.monitor_results_dropped`.

Fixes carried from `main` (merged into integration after v0.3.9):

- A task timeout above the 10 minute maximum clamps to the maximum instead of
  falling back to the 30 s default, so the 600 s agent update budget is
  honoured (the v0.3.9 binary still turns a 900 s deadline into 30 s).
- grpc moves to v1.83.1 so the sing-box stats client is off GO-2026-6348.

Compatibility: no new server or dashboard floor (`server_min` stays
`v0.2.2-alpha.19`). Every new field is optional and the batch route falls
back on 404.

Rollout notes:

- The update guard is server-side (lattice-server
  `feat/agent-update-keepalive-guard`): only an approval planned by a server
  with that change writes the drop-in and arms the guard. Updating with an
  older server installs the binary as before; the watchdog then stays off
  until the installer or a guarded update writes the drop-in.
- Roll one canary node first, then the fleet in batches, as alpha.8 was
  rolled.
