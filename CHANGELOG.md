# Changelog

Release notes for tagged node-agent builds. A version listed as unreleased
is the constant in `cmd/lattice-agent/main.go`, prepared for the next tag but
not yet tagged; the release workflow injects the tag at build time and must
match it.

## Unreleased

Design 29, slice M2b (monitoring paths), the agent half of the measurement
beacon: the responder of D3 and the client, against the wire contract in
design 29 D12. Pins lattice-sdk v0.2.24-0.20261016144248-9807b34bfd82, whose
package `beacon` holds the wire format and the responder's decision core; the
agent re-implements none of it. No compatibility floor moves: an older server
sends no `beacon` in the config pull, which the agent reads as "responder
off, no keys", and ignores the new `beacon` facts.

Responder:

- Off until a config pull carries `beacon.responder`; a pull without it closes
  the socket. The agent binds exactly `bind:port` over UDP. The bind address
  must be an IPv4 literal of a class `beacon.ParseIPv4` allows (never
  `0.0.0.0`, loopback, link-local, multicast or reserved) and the port 1024 to
  65535; anything else is refused without a bind. A bound address is never
  the wildcard, so replies leave from the address requests arrived on.
- Reads into a 128-byte buffer. Before authentication a CPU guard counts
  every datagram read, 20000 a second in all, and lets at most 1000 a second
  of one bucket (a fixed array of 1024, keyed by a seeded hash of the
  sender) reach the decision; past the global budget the loop stops reading
  until the next second, so the kernel drops the excess. The guard counts on
  the monotonic clock from the socket's start. No reply goes to a sender of
  a class `beacon.AddressRefused` names (broadcast, multicast, loopback and
  the rest) or to port zero, since Go enables `SO_BROADCAST` on every UDP
  socket. Anything not exactly 96 bytes is dropped, then
  `beacon.Responder.Handle` decides in the contract's order. A reply is never
  longer than its request. The drop path allocates nothing.
- A panic while deciding a datagram drops that datagram and is counted; the
  loop and the agent go on.
- Circuit breaker: when at least 54 of the last 60 seconds each dropped 5000
  datagrams or more after the guard (a quarter of its global budget) or spent
  that budget, the oldest of them included, the socket closes for 5 minutes
  and the facts read `circuit_open`. Datagrams the guard refused for their
  bucket do not count, so one host cannot close the socket below the global
  budget. A trip that lands while a pull moves the socket closes the new one
  too. The next pull after the cooldown binds again.
- A bind failure reads `bind_failed` with a short error (at most 200 bytes)
  and is retried once a minute on the same address and port only, never on
  another port.
- `-no-beacon` (`LATTICE_NO_BEACON=1`, kept by the installer like
  `LATTICE_NO_EXEC`) is fixed at startup and checked before anything else:
  the responder never binds, whatever the server sends, and reports
  `refusal: "refused_by_node"`, state `refused`. The variable fails closed:
  any value but empty, `0`, `false`, `no` or `off` sets the veto.
- A pull that lands after the agent began to stop binds nothing.
- Path keys from the pull are held in memory only, and the decoded copies are
  wiped once taken. No log line, debug line, fact, error or result carries a
  key, and the package writes no file; tests pin both.

Facts:

- Hello and every heartbeat carry the top-level `beacon` key: `responder`
  (always true), `refusal`, `state` (`off`, `listening`, `bind_failed`,
  `circuit_open`, `refused`), `bind`, `port`, `epoch` (newest in the applied
  table), `sources` (source ids in it), `last_auth_at` and `error`. A state
  change sends a heartbeat at once.
- `probe_methods` lists `beacon` on every agent, `-no-beacon` included: the
  client only sends.
- `-compat-json` lists the feature `beacon-v1`.

Client (monitor kind `beacon`):

- A check must name `target_node`; its `target` must be an endpoint
  `beacon.ParseEndpoint` accepts, or the run reports `destination_refused`
  with nothing sent. Without a path key for the target the run reports
  `beacon_no_key` with `sent` zero.
- One connected UDP socket per run, `packets` requests (zero reads as 5, at
  most 10) 200 ms apart, each with a fresh random nonce and waiting
  `timeout_sec`. RTTs come from the monotonic clock. A reply counts only if it
  verifies under the path key and carries the nonce and sequence of a request
  still waiting.
- Results carry `sent`, `lost` and `rtts_ms` (the ok replies) like icmp. A run
  with no ok reply carries `beacon_not_listening` when the socket met
  `ECONNREFUSED` for more than one request (or for the only one), else
  `beacon_stale`, `beacon_unknown_epoch` or `beacon_rate_limited` from a
  signed reply; plain loss carries no reason. A refusal does not end the run,
  so one forged or stray port-unreachable cannot cut short a run whose
  authentic replies are on their way.

## 0.3.10-alpha.5 (2026-10-16)

Design 29, slice M2a (monitoring paths), the agent half of the wire
contract in design 29 D11. Pins lattice-sdk
v0.2.24-0.20261016120438-f2689021eb38. No compatibility floor moves: the
server decodes agent bodies without rejecting unknown fields, so an older
server ignores the new facts and results fields.

Probe methods and facts:

- Hello and every heartbeat carry `probe_methods` (`http`, `tcp`, and `icmp`
  when the host allows it) and `probe_refusals` (`{"icmp":
  "icmp_not_permitted"}` when the kernel refuses unprivileged echo sockets,
  which on Linux means `net.ipv4.ping_group_range` excludes every group of
  the agent, root included). The agent asks the kernel at startup, again
  every ten minutes, and at once when a run is refused.
- `-compat-json` lists the feature `probe-methods-v1`.
- A check of a kind this agent does not run (`beacon`, `tls`, anything
  unknown) reports reason `agent_too_old` instead of a failure.

icmp:

- Unprivileged `udp4` echo sockets, no `CAP_NET_RAW`. `packets` echoes
  (zero reads as 5, at most 10) 200 ms apart, each waiting `timeout_sec`.
  Every echo carries a 32-byte payload, a fixed marker and 16 fresh random
  bytes; a reply counts only if it is an echo reply from the target address
  carrying an outstanding echo's whole payload, inside that echo's wait.
- Results carry `sent`, `lost` and `rtts_ms` (replied echoes in send order);
  `latency_ms` is their median and `success` means at least one reply. A
  refused socket reports `icmp_not_permitted` with `sent` zero.
- An echo the kernel will not send (no route, a local firewall) never left:
  sending stops there, it is neither sent nor lost, and the run waits only
  for the echoes already out. One read error is tolerated; three in a row
  end the run with the error.

Destinations, for tcp, http and icmp:

- The target is resolved once and every address is judged with
  `model.MonitorDestinationRefused` (loopback, link-local, metadata,
  multicast, private, carrier-grade NAT, reserved, benchmarking, the 6to4
  relay anycast range, IPv6 discard-only, unspecified, broadcast, and the
  IPv6 transition forms below). One
  refused address refuses the run with reason `destination_refused` and
  nothing is dialed. A tcp or icmp check with `target_node` set skips the
  rule; http never takes `target_node`, so an http check carrying one is
  judged like any other. The probe dials only the judged addresses, in
  resolver order, with no second lookup and no proxy from the environment.
- Under that rule NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and
  IPv4-translated (`::ffff:0:0:0/96`) addresses are judged by the IPv4
  address they carry, and local-use NAT64 (`64:ff9b:1::/48`),
  IPv4-compatible (`::/96`), site-local (`fec0::/10`) and Teredo
  (`2001::/32`) are refused outright. A zone never changes the verdict.

http:

- GET only; redirects are never followed and a 3xx is judged against
  `expect_status` (default `200-399`). Latency is the time to the response
  headers; the body is closed unread.
- An internationalized host is looked up and dialed in punycode, as
  net/http sends it.
- Request headers from the check are sent. Secret headers are sent only over
  https to exactly `secrets_origin`; otherwise the run reports
  `destination_refused` and sends nothing. Headers the agent's stack owns
  (`Host`, `Proxy-*` and the rest of the contract's list) are refused.
- Error text drops the URL's user info, query and fragment and every header
  value.

Other:

- A monitor restarts when `target_node`, `packets`, `expect_status`,
  `headers` or `secrets_origin` change, not only its kind, target, interval
  or timeout.
- A run's deadline covers its echo spacing, and a monitor without a timeout
  now gets the five seconds the prober always used instead of being cut at
  two.

## 0.3.10-alpha.4 (unreleased)

Prerelease. Changes since v0.3.10-alpha.3. Design 26, slice R1: the trace
collector says whether it is really collecting, raw lines have their own
switch, and the budget sheds whole connections instead of cutting lines.

Clash API discovery and collector status:

- When the trace policy names no Clash API address, the collector reads
  `experimental.clash_api.external_controller` from
  `/etc/sing-box/config.json` on every poll and uses it only if it passes the
  same loopback rule the Clash API client enforces (`localhost` or a loopback
  literal, `host:port`, no URL). A policy address still wins. `sb api on` on
  the node is picked up at the next poll without restarting the agent.
- Only a config that was read and has no usable controller stops a running
  pipeline. A config that cannot be read or parsed while the collector is
  recording from it (caught mid-rewrite, say) keeps the pipeline and its open
  connections; after three such polls in a row the state is `no_clash_api`,
  saying the stream keeps running, and the next good read is `ready` again.
- The sing-box config and every Clash API secret file are opened with
  `O_NOFOLLOW|O_NONBLOCK` and checked on the open descriptor: a regular file,
  owned by root or the agent's uid, writable by nobody else (a secret file
  also readable by nobody else), at most 1 MiB. A symlink, FIFO, device,
  oversized or loosely permitted file is refused with a detail naming the
  path and the reason, and never blocks the work loop. A config that is not
  JSON is reported as "<path> cannot be parsed as JSON", never with the
  decoder's message, which quotes bytes of the file.
- A rotated secret is picked up without a restart: each poll re-reads it, and
  when it has changed while the `/logs` stream is down, the client takes it
  and resubscribes at once. An open stream keeps the secret it is using.
- A `/logs` subscription that gets no answer within 10 s is ended and retried,
  so a hung request cannot leave `ready` standing.
- The metrics beat carries `trace_collector` (lattice-sdk
  `model.CollectorStatus`): `state` is `off`, `ready`, `no_clash_api`,
  `secret_unreadable` or `stream_failing`, with `since`, the address in use
  and where it came from (`policy` or `config`), a detail line of at most 256
  bytes saying why it is not ready (it never carries the secret), whether raw
  lines are flowing, lines arriving per second over the last 10 s (counted
  before the pre-parse ceiling, so the rate is not capped by it), the budget
  in force, and the cumulative shed connections and unparsed lines. The key
  is left out until the collector has applied a policy. A state change beats
  at once (at most one nudged beat per second) instead of waiting for the
  next interval.
- `ready` means the `/logs` subscription was accepted and `/connections`
  answers. A subscription refused before it ever opened is `stream_failing`
  at once; one that drops after it was up stays `ready` for 15 s (a sing-box
  restart is back well inside that), and three consecutive `/connections`
  failures are `stream_failing` too.

Raw lines:

- Raw sing-box lines go to the `singbox://<node>` source only when the
  server names `raw_source_id` and the policy's `raw.enabled` is not false.
  A policy without `raw` (every server up to alpha-0.2.2a117) keeps the
  previous behaviour. Turning raw off discards the raw lines still queued, so
  none ships on a later flush.

Connection shedding:

- The budget is now a CPU guard in parsed lines per second, default 5,000
  (a policy budget of 0 means this default). Over it, a connection first seen
  in that second is shed whole: none of its lines reach the assembler, and
  connections already being assembled keep every line, so the budget never
  produces a partial record. A shed connection is counted once, as
  `shed_connections` on the trace batch and also inside `dropped`, so an
  older server still audits the gap. Up to 65,536 shed ids are remembered; a
  sing-box restart forgets them. Lines without a connection id over budget
  are dropped and counted as before.
- A hard ceiling of four times the budget per second still drops entries
  before they are parsed, counted into `dropped`.

Compatibility: no new server or dashboard floor. Against alpha-0.2.2a117 the
new beat key and batch field are ignored by its lenient decoders, raw lines
follow `raw_source_id` as before, and a117's explicit budget of 500 is applied
as a parsed-line budget. lattice-sdk pinned at
`v0.2.24-0.20261005113750-cae46247ddb6`.

## 0.3.10-alpha.3 (2026-10-04)

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
