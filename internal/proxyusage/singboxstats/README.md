# Vendored sing-box stats proto (ADR-004)

`stats.proto` is the sing-box upstream definition
(`experimental/v2rayapi/stats.proto`) with ONLY the `go_package` option
adjusted to this module. Service and message wire shapes are byte-identical to
upstream; do not renumber fields.

Regenerate after an upstream sync (development-time only, never at build):

```sh
export PATH="$HOME/go/bin:$PATH"   # protoc-gen-go, protoc-gen-go-grpc
protoc --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  -I internal/proxyusage/singboxstats internal/proxyusage/singboxstats/stats.proto
mv stats.pb.go stats_grpc.pb.go internal/proxyusage/singboxstats/
```
