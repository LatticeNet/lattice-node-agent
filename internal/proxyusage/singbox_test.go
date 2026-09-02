package proxyusage

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/proxyusage/singboxstats"
	"github.com/LatticeNet/lattice-sdk/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestValidateSingBoxStatsSource(t *testing.T) {
	if err := ValidateSingBoxStatsSource(SingBoxStatsSource{APIAddr: "127.0.0.1:8080"}); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	if err := ValidateSingBoxStatsSource(SingBoxStatsSource{APIAddr: "10.0.0.5:8080"}); err == nil {
		t.Fatal("non-loopback must be rejected")
	}
	if err := ValidateSingBoxStatsSource(SingBoxStatsSource{APIAddr: "127.0.0.1:8080", Pattern: "user>>>\x00bad"}); err == nil {
		t.Fatal("control characters must be rejected")
	}
}

func TestLoadSingBoxStatsAggregatesAndSplits(t *testing.T) {
	source := SingBoxStatsSource{
		APIAddr: "127.0.0.1:8080",
		query: func(_ context.Context, addr, pattern string) ([]nameValue, error) {
			// The default query asks for every counter: inbound counters are
			// the only usage signal for legacy inbounds without named users.
			if addr != "127.0.0.1:8080" || pattern != "" {
				t.Fatalf("query args: %q %q", addr, pattern)
			}
			return []nameValue{
				{name: "user>>>u_0123abcd>>>traffic>>>uplink", value: 100},
				{name: "user>>>u_0123abcd>>>traffic>>>downlink", value: 250},
				{name: "user>>>u_ef89>>>traffic>>>uplink", value: 7},
				{name: "inbound>>>vless>>>traffic>>>uplink", value: 999},
				{name: "inbound>>>vless>>>traffic>>>downlink", value: 1},
				{name: "outbound>>>direct>>>traffic>>>uplink", value: 5},
				{name: "user>>>u_ef89>>>requests>>>total", value: 3}, // not traffic
			}, nil
		},
	}
	snapshot, err := LoadSingBoxStats(context.Background(), source, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int64{"u_0123abcd": 350, "u_ef89": 7}; !reflect.DeepEqual(snapshot.UserBytes, want) {
		t.Fatalf("user_bytes stays the per-user sum: %+v", snapshot.UserBytes)
	}
	if want := map[string]model.ProxyTrafficCounter{
		"u_0123abcd": {Uplink: 100, Downlink: 250},
		"u_ef89":     {Uplink: 7},
	}; !reflect.DeepEqual(snapshot.UserTraffic, want) {
		t.Fatalf("user_traffic: %+v", snapshot.UserTraffic)
	}
	if want := map[string]model.ProxyTrafficCounter{"vless": {Uplink: 999, Downlink: 1}}; !reflect.DeepEqual(snapshot.InboundTraffic, want) {
		t.Fatalf("inbound_traffic: %+v", snapshot.InboundTraffic)
	}
	if want := map[string]model.ProxyTrafficCounter{"direct": {Uplink: 5}}; !reflect.DeepEqual(snapshot.OutboundTraffic, want) {
		t.Fatalf("outbound_traffic: %+v", snapshot.OutboundTraffic)
	}
	if snapshot.NodeID != "node-a" || snapshot.At.IsZero() || snapshot.IgnoredCounters != 0 {
		t.Fatalf("normalization: %+v", snapshot)
	}
}

func TestLoadSingBoxStatsHonorsExplicitPattern(t *testing.T) {
	source := SingBoxStatsSource{
		APIAddr: "127.0.0.1:8080",
		Pattern: " user>>> ",
		query: func(_ context.Context, _, pattern string) ([]nameValue, error) {
			if pattern != "user>>>" {
				t.Fatalf("pattern: %q", pattern)
			}
			return nil, nil
		},
	}
	if _, err := LoadSingBoxStats(context.Background(), source, "node-a"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSingBoxStatsEmptyAndErrorPaths(t *testing.T) {
	// Empty counter set is a valid empty snapshot.
	source := SingBoxStatsSource{
		APIAddr: "127.0.0.1:8080",
		query:   func(context.Context, string, string) ([]nameValue, error) { return nil, nil },
	}
	snapshot, err := LoadSingBoxStats(context.Background(), source, "node-a")
	if err != nil || len(snapshot.UserBytes) != 0 {
		t.Fatalf("empty: %+v err=%v", snapshot, err)
	}
	// Query failure surfaces, wrapped.
	source.query = func(context.Context, string, string) ([]nameValue, error) {
		return nil, errors.New("connection refused")
	}
	if _, err := LoadSingBoxStats(context.Background(), source, "node-a"); err == nil ||
		!strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("query error: %v", err)
	}
	// Negative counters are rejected, whichever kind they belong to.
	for _, name := range []string{"user>>>u_x>>>traffic>>>uplink", "inbound>>>vless>>>traffic>>>downlink"} {
		source.query = func(context.Context, string, string) ([]nameValue, error) {
			return []nameValue{{name: name, value: -1}}, nil
		}
		if _, err := LoadSingBoxStats(context.Background(), source, "node-a"); err == nil {
			t.Fatalf("%s: negative counter: want error", name)
		}
	}
}

// fakeStatsServer serves canned counters over an in-memory gRPC channel.
type fakeStatsServer struct {
	singboxstats.UnimplementedStatsServiceServer
	stats       []*singboxstats.Stat
	gotPatterns []string
	gotReset    bool
}

func (f *fakeStatsServer) QueryStats(_ context.Context, req *singboxstats.QueryStatsRequest) (*singboxstats.QueryStatsResponse, error) {
	f.gotPatterns = req.GetPatterns()
	f.gotReset = req.GetReset_()
	return &singboxstats.QueryStatsResponse{Stat: f.stats}, nil
}

func TestGRPCQueryStatsEndToEnd(t *testing.T) {
	fake := &fakeStatsServer{stats: []*singboxstats.Stat{
		{Name: "user>>>u_0123abcd>>>traffic>>>uplink", Value: 100},
		{Name: "user>>>u_0123abcd>>>traffic>>>downlink", Value: 250},
	}}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	// sing-box aliases the generated service name for V2Ray client
	// compatibility. Register the fake under that runtime name so this test
	// catches clients that only work against the unaliased generated package.
	desc := singboxstats.StatsService_ServiceDesc
	desc.ServiceName = "v2ray.core.app.stats.command.StatsService"
	server.RegisterService(&desc, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	original := statsNewClientConn
	statsNewClientConn = func(addr string, opts ...grpc.DialOption) (statsConn, error) {
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
		return grpc.NewClient("passthrough:///bufnet", opts...)
	}
	t.Cleanup(func() { statsNewClientConn = original })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stats, err := grpcQueryStats(ctx, "127.0.0.1:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("stats: %+v", stats)
	}
	// The empty pattern is sent as one empty string: a substring the server
	// finds in every counter name, rather than a missing list whose meaning
	// depends on the server.
	if len(fake.gotPatterns) != 1 || fake.gotPatterns[0] != "" {
		t.Fatalf("patterns: %v", fake.gotPatterns)
	}
	if fake.gotReset {
		t.Fatal("queries must never reset counters")
	}
}
