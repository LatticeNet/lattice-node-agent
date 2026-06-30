# lattice-node-agent

Outbound node daemon for Lattice.

The agent has no inbound listener. It authenticates with a per-node token,
reports metrics and slow-changing HostFacts inventory telemetry, polls for
queued tasks, executes bounded tasks only when explicitly enabled, and posts
results back to the server. It can also report proxy-core traffic counters from
a bounded local JSON snapshot file or a loopback-only HTTP JSON source for the
server-owned usage rollup. Interactive browser terminal sessions are supported
only when explicitly enabled; they are outbound, agent-side PTY sessions, not an
inbound SSH service.
Node tokens are sent in the `Authorization: Bearer` header, not in JSON bodies.
For rollback-protected firewall apply tasks, the binary also supports
`--selfcheck-controlplane`, a one-shot unauthenticated `/api/health` reachability
check used after nft commit; this mode does not require or send the node token.

HostFacts are best-effort advisory facts (OS, arch, CPU cores/model,
memory/swap, platform, kernel, hostname, boot time, virtualization hint). They
are collected with stdlib and local platform files such as `/proc` and
`/etc/os-release`; missing fields are left empty and never block the agent.

## Run

```sh
go run ./cmd/lattice-agent \
  -server http://127.0.0.1:8088 \
  -node-id demo-node \
  -token '<enrollment-token>' \
  -allow-exec=false
```

`-allow-exec=false` is the safe default. Use `-allow-exec=true` only on nodes
where remote script execution is acceptable.

The node token is sent in the `Authorization: Bearer` header on every request.
The loopback `http://127.0.0.1:8088` URL above is safe because the token never
leaves the host. For a **remote** server the agent refuses to start on a
cleartext `http://` URL (it would leak the token) — use `https://` instead. The
`-allow-insecure-http` flag exists only as a deliberate escape hatch and is off
by default.

Debug diagnostics:

```sh
go run ./cmd/lattice-agent \
  -server https://lattice.example.com \
  -node-id demo-node \
  -token '<enrollment-token>' \
  -debug
```

`LATTICE_AGENT_DEBUG=1` enables the same mode for systemd environments. Debug
logs include poll progress, request paths, payload key names, metrics summaries,
monitor counts, task IDs, and task exit status. They do not print the node token,
task script body, proxy usage secret, or client secret values.

The server can also enable debug mode per node for `lattice-agent 0.2.1+`
through `/api/nodes/debug` or the dashboard node detail panel.
Server-controlled debug writes to the node's normal service logs and, by
default, also uploads the same debug lines to the server Logs store under
`agent-debug://<node_id>`. Set `collect=false` on the server policy to keep debug
enabled on the node while preventing central collection.

Current topology is hub-and-spoke: every agent points directly at the primary
`lattice-server`. `role` and `tags` are metadata for filtering/planning; there is
no production group-leader or relay-agent mode yet.

Interactive terminal sessions:

```sh
go run ./cmd/lattice-agent \
  -server https://lattice.example.com \
  -node-id demo-node \
  -token '<enrollment-token>' \
  -allow-terminal=true
```

`LATTICE_AGENT_ALLOW_TERMINAL=1` enables the same mode for systemd
environments. Terminal mode is off by default and is separate from reviewed
batch tasks: it opens a short-lived PTY on the node, polls the server for input,
and posts output back to the dashboard. The agent still has no inbound listener,
does not accept SSH connections, and does not store SSH credentials. Dashboard
access requires the operator scope `terminal:open`.

If the agent process runs as root, terminal mode is refused unless
`-allow-root-exec=true` is also set. Prefer running the agent as a dedicated
least-privilege service user when browser terminal access is needed.

Firewall apply selfcheck:

```sh
lattice-agent --selfcheck-controlplane -server https://203.0.113.99
```

The selfcheck exits 0 only when `GET /api/health` returns HTTP 200. It reuses
the same transport safety guard as normal startup, so remote cleartext `http://`
is refused unless deliberately allowed.

Firewall apply domain-set update:

```sh
lattice-agent --update-nft-domain-set \
  -host lattice.example.com \
  -family inet \
  -table lattice_policy \
  -set lattice_control4 \
  -set6 lattice_control6
```

This mode resolves the hostname with Go's resolver, splits answers into IPv4
and IPv6 sets, sorts/deduplicates each family, then updates the existing nft
named sets using direct `nft` argv calls. `-set` may be used alone for the
legacy IPv4-only path; `-set` + `-set6` updates both control-plane sets and
requires at least one A or AAAA answer. It does not require or send the node
token. It is intended for server-rendered, rollback-protected apply scripts;
empty resolution or invalid nft identifiers exit non-zero so the task can roll
back.

Proxy usage reporting bridge (file source):

```sh
lattice-agent \
  -server https://lattice.example.com \
  -node-id gmami-jp1 \
  -token '<node-token>' \
  -proxy-usage-file /run/lattice/proxy-usage.json
```

The file is read once per agent loop and posted to `/api/agent/proxy-usage`.
The agent overrides any `node_id` in the file with its configured node id,
defaults `at` when omitted, rejects empty user ids, rejects negative counters,
and refuses files over 1 MiB. The server performs monotonic diffing,
per-profile user eligibility filtering, quota status updates, and audit.

Minimal file shape:

```json
{
  "core_uptime_sec": 12345,
  "user_bytes": {
    "alice": 1048576,
    "bob": 2097152
  }
}
```

This is an interim stable contract for sidecar collectors and future direct
sing-box/xray collectors; it is not a general log or metrics ingestion channel.

Proxy usage reporting bridge (loopback HTTP JSON source):

```sh
lattice-agent \
  -server https://lattice.example.com \
  -node-id gmami-jp1 \
  -token '<node-token>' \
  -proxy-usage-url http://127.0.0.1:19090/stats \
  -proxy-usage-secret-file /etc/lattice/proxy-usage.secret
```

`-proxy-usage-url` is mutually exclusive with `-proxy-usage-file`. The URL must
use `http://` or `https://` and a loopback host (`127.0.0.0/8`, `::1`, or
`localhost`); remote hosts and URL userinfo are refused before any request is
sent. The optional local bearer secret is sent as `Authorization: Bearer` to
that local source only. For persistent services, prefer
`-proxy-usage-secret-file` / `LATTICE_PROXY_USAGE_SECRET_FILE` over
`-proxy-usage-secret` so the secret is not exposed in process arguments or shell
history. Responses are capped at 1 MiB and fetched with `-proxy-usage-timeout`
(default `3s`).

The HTTP source accepts the same Lattice snapshot shape as the file source, an
envelope `{"snapshot": ...}`, or V2Ray-style stats output:

```json
{
  "stat": [
    {"name": "user>>>alice>>>traffic>>>uplink", "value": 1048576},
    {"name": "user>>>alice>>>traffic>>>downlink", "value": 2097152}
  ]
}
```

The agent sums uplink/downlink per user and posts the normalized
`ProxyUsageSnapshot` to `/api/agent/proxy-usage`. This keeps the server's
monotonic diffing, eligibility filtering, quota state, and audit as the
authoritative layer. Direct sing-box/xray gRPC adapters can reuse this parser
later without changing the server ingest contract.

## On-box sing-box discovery

`-singbox-discover` / `LATTICE_SINGBOX_DISCOVER=1` reports existing sing-box
inbounds to `/api/agent/singbox-inventory` without enabling generic task
execution. This is the read-only adoption path for machines that already run VPN
configs outside Lattice.

Discovery order:

1. Try the 233boy management interface, `sb --json list`, plus best-effort
   `sb --json provision` for version metadata.
2. If that interface is missing or returns non-JSON, fall back to parsing the
   running standard sing-box config set. The agent discovers `sing-box run`
   arguments from `/proc/*/cmdline`, honors `-c/--config` and
   `-C/--config-directory`, then falls back to `/etc/sing-box/config.json` and
   `/etc/sing-box/conf/*.json`.

The runtime-config fallback emits only safe inbound metadata: tag/name, protocol,
network, public address, port, SNI, and listen host. It does not emit private
keys or invent credential-bearing share URLs from raw config files. Nodes that
run with `-allow-exec=false` should use this discovery path instead of dashboard
manual probe tasks.

Dashboard manual probe is different from continuous discovery: it queues a
bounded task and asks the on-box `sb --json list/provision` interface first,
then falls back to parsing the running sing-box config set. Older management
scripts may print human error text before fallback JSON (for example when
`--addr` is unsupported); the server parser extracts the first JSON object from
each probe section and records a bounded error summary plus the task id when the
probe still fails. Full stdout/stderr stay in Task History so operators can
debug incompatible local sing-box layouts without losing the last good
continuous-discovery inventory.

## Installer-persisted launch profile

The dashboard's enroll and reconfigure commands set lattice-agent startup
behavior through environment variables. `scripts/install.sh` persists these into
`/opt/lattice/lattice-agent.env` (or the platform equivalent) so the service
keeps the same behavior after restart:

The installer downloads release artifacts only when it can also download
`SHA256SUMS` and verify the selected binary with `sha256sum`, `shasum`, or
FreeBSD `sha256`. Missing checksum tooling or a missing checksum manifest aborts
the install before the binary is written.

- `LATTICE_AGENT_ALLOW_EXEC=1` enables bounded task execution.
- `LATTICE_AGENT_ALLOW_ROOT_EXEC=1` permits task execution while the agent runs
  as root.
- `LATTICE_NO_EXEC=1` is the hard kill switch and overrides execution/terminal
  enablement.
- `LATTICE_AGENT_ALLOW_TERMINAL=1` enables audited browser terminal sessions.
- `LATTICE_TERMINAL_TRANSPORT=poll|stream` selects the terminal transport.
- `LATTICE_SSH_ALERTS=1` reports accepted sshd logins.
- `LATTICE_SINGBOX_DISCOVER=1` and `LATTICE_SINGBOX_BIN=sb` enable sing-box
  discovery.
- `LATTICE_PROXY_USAGE_FILE`, `LATTICE_PROXY_USAGE_URL`, and
  `LATTICE_PROXY_USAGE_XRAY_API` configure proxy usage reporting sources.

If a task-backed dashboard action reports `agent task execution disabled`, rerun
the node detail page's generated reconfigure command with `allow_exec=true`
instead of enrolling the same machine as a second node.

Agent 0.2.7+ reports a non-secret `agent_runtime` object with every metrics
heartbeat. The dashboard uses it as runtime proof for exec/root/terminal
transport/ssh-alert/sing-box-discovery state, while `agent_launch` remains only
the saved desired installer profile. A node can therefore show three distinct
states: runtime now, saved desired, and unsaved local draft.

Terminal transport modes:

- `poll` is the legacy HTTP store-and-forward path. It is slower but works with
  older agents and avoids a long-lived browser-to-agent stream.
- `stream` attaches the browser WebSocket to an agent-dialed WebSocket bridge.
  It is lower latency and better for interactive shells. The agent keeps the PTY
  alive across short WebSocket drops, redials the server, and replays recent
  output from a bounded ring using the browser's rendered byte offset.
  Browser paste is handled through a single xterm paste path so native paste
  events and Cmd/Ctrl+Shift+V do not duplicate input; bracketed paste is still
  honored. Explicit dashboard close sends a stream close control frame so the
  node-side PTY is torn down immediately instead of waiting for detach cleanup.

Default Linux install layout:

- Binary: `/opt/lattice/lattice-agent`
- Environment file: `/opt/lattice/lattice-agent.env`
- State directory: `/opt/lattice/state`
- systemd unit: `lattice-agent.service`

Legacy beta nodes may still use `/opt/lattice/node-agent/lattice-agent`,
`/opt/lattice/node-agent/agent.env`, and `lattice-node-agent.service`. The
installer adopts that existing service and env file when rerun, preserving the
node token and upgrading the binary that systemd actually starts. This avoids
creating a duplicate agent under the canonical path. If a reconfigure command
targets a different node id than the token stored in the existing env file, the
installer refuses to run rather than cross-wiring one node's token to another
node id.

## Execution Limits

- Interpreter allowlist: `sh`, `bash`, `python3`, `node`.
- Default timeout: 30 seconds.
- Maximum timeout: 10 minutes.
- Output cap: up to 256 KiB.
- Server-side task creation enforces the same interpreter, timeout, output, and
  script-size limits before a task can be leased.
- Server-side result ingestion also rejects stdout, stderr, or error text that
  exceeds the task's output cap.
- Temporary working directory and minimal environment.
- Leased tasks carry a server-issued `lease_id`; the agent returns it with the
  result and exposes it to the task as `LATTICE_TASK_LEASE_ID` for traceability.
- Leased task payloads contain only execution fields; control-plane actor/token
  metadata is not sent to agents.

## Development

```sh
go test ./...
go build ./cmd/lattice-agent
```

## Releases

Push a `v*` tag to publish Linux binaries:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The release workflow builds:

```txt
lattice-agent-linux-amd64
lattice-agent-linux-arm64
SHA256SUMS
```

The tag version is injected into the binary with `-X main.version=...`, so:

```sh
lattice-agent -version
```

must match the server update policy target version. Use the matching artifact
URL and SHA-256 digest from `SHA256SUMS` when configuring server-controlled
agent updates.
