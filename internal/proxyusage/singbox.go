package proxyusage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/proxyusage/singboxstats"
	"github.com/LatticeNet/lattice-sdk/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultSingBoxStatsPattern = "user>>>"
	defaultSingBoxStatsTimeout = 5 * time.Second
	// sing-box rewrites its generated StatsService descriptor at runtime to
	// the V2Ray-compatible service name. The protobuf messages keep the local
	// experimental.v2rayapi package, but clients must invoke this aliased path.
	singBoxStatsQueryMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"
)

// SingBoxStatsSource collects per-user usage from sing-box's experimental
// V2Ray Stats API over loopback gRPC (ADR-004). sing-box has no CLI stats
// subcommand, so — unlike the xray path (ADR-003) — the gRPC call happens in
// the agent itself, using the vendored proto in singboxstats (byte-identical
// service/messages with upstream, only go_package adjusted).
//
// Queries are read-only (never reset): counters stay monotonic and the server
// keeps ownership of successive-snapshot diffing, eligibility, and audit. The
// API address must be loopback, mirroring the HTTP source's loopback rule —
// a node must not be configured into dialing arbitrary networks.
type SingBoxStatsSource struct {
	APIAddr string        // loopback host:port of the sing-box experimental API
	Pattern string        // optional substring stat-name filter; default "user>>>"
	Timeout time.Duration // per-invocation timeout; default 5s
	Now     func() time.Time

	// query is a test seam; production uses grpcQueryStats.
	query func(ctx context.Context, addr, pattern string) ([]nameValue, error)
}

type nameValue struct {
	name  string
	value int64
}

// ValidateSingBoxStatsSource checks the loopback API address and pattern
// without dialing, so the agent can fail fast at startup.
func ValidateSingBoxStatsSource(source SingBoxStatsSource) error {
	if _, err := validateLoopbackHostPort(source.APIAddr); err != nil {
		return err
	}
	if pattern := strings.TrimSpace(source.Pattern); pattern != "" {
		if err := validateXrayStatsPattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

// LoadSingBoxStats runs one read-only QueryStats call and normalizes the
// counters into a server-ingestible snapshot. An empty counter set (a freshly
// started core with no traffic yet) is a valid empty snapshot, not an error.
// Counter names keep their on-box users[].name (design-15 §5 u_<hash>) — the
// server reverses them into (user, line) pairs.
func LoadSingBoxStats(ctx context.Context, source SingBoxStatsSource, nodeID string) (model.ProxyUsageSnapshot, error) {
	addr, err := validateLoopbackHostPort(source.APIAddr)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	pattern := strings.TrimSpace(source.Pattern)
	if pattern == "" {
		pattern = defaultSingBoxStatsPattern
	}
	if err := validateXrayStatsPattern(pattern); err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultSingBoxStatsTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	query := source.query
	if query == nil {
		query = grpcQueryStats
	}
	stats, err := query(ctx, addr, pattern)
	if err != nil {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("sing-box stats query: %w", err)
	}
	snapshot := model.ProxyUsageSnapshot{UserBytes: map[string]int64{}}
	for _, stat := range stats {
		if stat.value < 0 {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("sing-box stats counter %q cannot be negative", stat.name)
		}
		user, ok := v2rayUserFromStatName(stat.name)
		if !ok {
			continue
		}
		snapshot.UserBytes[user] += stat.value
	}
	return NormalizeSnapshot(snapshot, nodeID, now(source.Now))
}

// statsConn is the minimal connection surface the stats client needs.
type statsConn interface {
	grpc.ClientConnInterface
	Close() error
}

// statsNewClientConn dials the loopback API; it is a test seam (bufconn) and
// otherwise grpc.NewClient with the caller's options.
var statsNewClientConn = func(addr string, opts ...grpc.DialOption) (statsConn, error) {
	return grpc.NewClient(addr, opts...)
}

// grpcQueryStats dials the loopback experimental API (plaintext: loopback
// only, exactly like xray's own statsquery) and issues a substring QueryStats.
func grpcQueryStats(ctx context.Context, addr, pattern string) ([]nameValue, error) {
	conn, err := statsNewClientConn(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	request := &singboxstats.QueryStatsRequest{
		Patterns: []string{pattern},
	}
	resp := new(singboxstats.QueryStatsResponse)
	err = conn.Invoke(ctx, singBoxStatsQueryMethod, request, resp)
	if err != nil {
		return nil, err
	}
	out := make([]nameValue, 0, len(resp.GetStat()))
	for _, stat := range resp.GetStat() {
		out = append(out, nameValue{name: stat.GetName(), value: stat.GetValue()})
	}
	return out, nil
}
