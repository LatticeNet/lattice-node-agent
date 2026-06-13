# lattice-node-agent

Outbound node daemon for Lattice.

The agent has no inbound listener. It authenticates with a per-node token,
reports metrics and slow-changing HostFacts inventory telemetry, polls for
queued tasks, executes bounded tasks only when explicitly enabled, and posts
results back to the server.
Node tokens are sent in the `Authorization: Bearer` header, not in JSON bodies.

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
