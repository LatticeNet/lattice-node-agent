# Vendored sing-box stats proto (ADR-004)

`stats.proto` is the sing-box upstream definition
(`experimental/v2rayapi/stats.proto`) with ONLY the `go_package` option
adjusted to this module. Service and message wire shapes are byte-identical to
upstream; do not renumber fields.

The pinned upstream is sing-box `v1.13.12`, commit
`1086ab2563320e0da0c23b3a491d8dfa0939dff4`. The adjusted local proto has
SHA-256 `681150ae39d29d4c5036e2e77b753f73a86d0b64a576a73516774d21560890df`.
Run `scripts/check-singbox-stats-proto.sh` to compare it against that exact
upstream revision before updating either pin.

Regenerate after an upstream sync (development-time only, never at build):

```sh
export PATH="$HOME/go/bin:$PATH"   # protoc-gen-go, protoc-gen-go-grpc
protoc --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  -I internal/proxyusage/singboxstats internal/proxyusage/singboxstats/stats.proto
mv stats.pb.go stats_grpc.pb.go internal/proxyusage/singboxstats/
```
