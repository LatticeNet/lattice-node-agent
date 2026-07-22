package proxyusage

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/proxyusage/singboxstats"
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

func TestLoadSingBoxStatsAggregatesAndFilters(t *testing.T) {
	source := SingBoxStatsSource{
		APIAddr: "127.0.0.1:8080",
		query: func(_ context.Context, addr, pattern string) ([]nameValue, error) {
			if addr != "127.0.0.1:8080" || pattern != "user>>>" {
				t.Fatalf("query args: %q %q", addr, pattern)
			}
			return []nameValue{
				{name: "user>>>u_0123abcd>>>traffic>>>uplink", value: 100},
				{name: "user>>>u_0123abcd>>>traffic>>>downlink", value: 250},
				{name: "user>>>u_ef89>>>traffic>>>uplink", value: 7},
				{name: "inbound>>>vless>>>traffic>>>uplink", value: 999}, // not a user counter
				{name: "outbound>>>direct>>>traffic>>>uplink", value: 5},
			}, nil
		},
	}
	snapshot, err := LoadSingBoxStats(context.Background(), source, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UserBytes["u_0123abcd"] != 350 {
		t.Fatalf("aggregate: %+v", snapshot.UserBytes)
	}
	if snapshot.UserBytes["u_ef89"] != 7 {
		t.Fatalf("second user: %+v", snapshot.UserBytes)
	}
	if len(snapshot.UserBytes) != 2 {
		t.Fatalf("non-user counters must be filtered: %+v", snapshot.UserBytes)
	}
	if snapshot.NodeID != "node-a" || snapshot.At.IsZero() {
		t.Fatalf("normalization: %+v", snapshot)
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
	// Negative counters are rejected.
	source.query = func(context.Context, string, string) ([]nameValue, error) {
		return []nameValue{{name: "user>>>u_x>>>traffic>>>uplink", value: -1}}, nil
	}
	if _, err := LoadSingBoxStats(context.Background(), source, "node-a"); err == nil {
		t.Fatal("negative counter: want error")
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
	singboxstats.RegisterStatsServiceServer(server, fake)
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
	stats, err := grpcQueryStats(ctx, "127.0.0.1:8080", "user>>>")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(fake.gotPatterns) != 1 || fake.gotPatterns[0] != "user>>>" {
		t.Fatalf("patterns: %v", fake.gotPatterns)
	}
	if fake.gotReset {
		t.Fatal("queries must never reset counters")
	}
}
