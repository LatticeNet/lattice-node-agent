# Changelog

Release notes for tagged node-agent builds. A version listed as unreleased
is the constant in `cmd/lattice-agent/main.go`, prepared for the next tag but
not yet tagged; the release workflow injects the tag at build time and must
match it.

## 0.3.10-alpha.1 (unreleased)

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
  `READY=1`, arms a 120 s systemd watchdog for itself with `WATCHDOG_USEC=` and
  pets it only while its own loops make local progress. An unreachable
  control plane never stops the keepalive; a wedged step does, and systemd
  restarts the agent.
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
  batch route every 30 minutes.

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
