# lattice-node-agent

Outbound node daemon for Lattice.

The agent has no inbound listener. It authenticates with a per-node token,
reports metrics and slow-changing HostFacts inventory telemetry, polls for
queued tasks, executes bounded tasks only when explicitly enabled, and posts
results back to the server. It can also report proxy-core traffic counters from
a bounded local JSON snapshot file or a loopback-only HTTP JSON source for the
server-owned usage rollup.
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
