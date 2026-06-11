# lattice-node-agent

Outbound node daemon for Lattice.

The agent has no inbound listener. It authenticates with a per-node token,
reports metrics, polls for queued tasks, executes bounded tasks only when
explicitly enabled, and posts results back to the server.

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

## Execution Limits

- Interpreter allowlist: `sh`, `bash`, `python3`, `node`.
- Default timeout: 30 seconds.
- Maximum timeout: 10 minutes.
- Output cap: up to 256 KiB.
- Temporary working directory and minimal environment.

## Development

```sh
go test ./...
go build ./cmd/lattice-agent
```

