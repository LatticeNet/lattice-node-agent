package proxyusage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadXrayCLIParsesStatsQuery(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	var gotName string
	var gotArgs []string
	src := XrayCLISource{
		APIAddr: "127.0.0.1:10085",
		Now:     func() time.Time { return fixed },
		runner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName = name
			gotArgs = args
			return []byte(`{"stat":[
				{"name":"user>>>alice>>>traffic>>>uplink","value":"100"},
				{"name":"user>>>alice>>>traffic>>>downlink","value":50},
				{"name":"user>>>bob>>>traffic>>>uplink","value":7},
				{"name":"inbound>>>api>>>traffic>>>uplink","value":999}
			]}`), nil
		},
	}
	snapshot, err := LoadXrayCLI(context.Background(), src, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if gotName != "xray" {
		t.Fatalf("expected default binary xray, got %q", gotName)
	}
	wantArgs := []string{"api", "statsquery", "--server=127.0.0.1:10085", "-pattern", "user>>>", "-reset=false"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("unexpected args %v", gotArgs)
	}
	want := map[string]int64{"alice": 150, "bob": 7}
	if snapshot.NodeID != "node-a" || !snapshot.At.Equal(fixed) || !reflect.DeepEqual(snapshot.UserBytes, want) {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestLoadXrayCLIEmptyStatsIsValid(t *testing.T) {
	cases := []string{`{}`, `{"stat":[]}`, `{"stat":null}`, "", "   "}
	for _, body := range cases {
		src := XrayCLISource{
			APIAddr: "[::1]:10085",
			runner:  func(context.Context, string, ...string) ([]byte, error) { return []byte(body), nil },
		}
		snapshot, err := LoadXrayCLI(context.Background(), src, "node-a")
		if err != nil {
			t.Fatalf("body %q: unexpected error %v", body, err)
		}
		if snapshot.NodeID != "node-a" || len(snapshot.UserBytes) != 0 {
			t.Fatalf("body %q: expected empty snapshot, got %+v", body, snapshot)
		}
	}
}

func TestLoadXrayCLIRejectsBadInputs(t *testing.T) {
	ok := func(context.Context, string, ...string) ([]byte, error) { return []byte(`{"stat":[]}`), nil }
	cases := []XrayCLISource{
		{APIAddr: "", runner: ok},
		{APIAddr: "10.0.0.1:10085", runner: ok},                            // not loopback
		{APIAddr: "127.0.0.1", runner: ok},                                 // missing port
		{APIAddr: "127.0.0.1:0", runner: ok},                               // invalid port
		{APIAddr: "127.0.0.1:10085", Binary: "xray; rm -rf /", runner: ok}, // unsafe binary
		{APIAddr: "127.0.0.1:10085", Pattern: "user\x00", runner: ok},      // control char in pattern
	}
	for i, src := range cases {
		if _, err := LoadXrayCLI(context.Background(), src, "node-a"); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestLoadXrayCLISurfacesRunnerError(t *testing.T) {
	src := XrayCLISource{
		APIAddr: "127.0.0.1:10085",
		runner: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("dial tcp 127.0.0.1:10085: connection refused")
		},
	}
	_, err := LoadXrayCLI(context.Background(), src, "node-a")
	if err == nil || !strings.Contains(err.Error(), "statsquery") {
		t.Fatalf("expected wrapped statsquery error, got %v", err)
	}
}

func TestLoadXrayCLIRejectsNegativeCounters(t *testing.T) {
	src := XrayCLISource{
		APIAddr: "127.0.0.1:10085",
		runner: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(`{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":-1}]}`), nil
		},
	}
	if _, err := LoadXrayCLI(context.Background(), src, "node-a"); err == nil {
		t.Fatal("expected negative-counter rejection")
	}
}

func TestCappedBufferFlagsOverflow(t *testing.T) {
	c := &cappedBuffer{limit: 8}
	n, err := c.Write([]byte("1234"))
	if err != nil || n != 4 || c.overflow {
		t.Fatalf("first write: n=%d err=%v overflow=%v", n, err, c.overflow)
	}
	// This write crosses the limit: the buffer keeps exactly `limit` bytes,
	// reports a full write (so the child is not killed), and flags overflow.
	n, err = c.Write([]byte("567890"))
	if err != nil || n != 6 || !c.overflow {
		t.Fatalf("overflow write: n=%d err=%v overflow=%v", n, err, c.overflow)
	}
	if c.buf.String() != "12345678" {
		t.Fatalf("unexpected buffered content %q", c.buf.String())
	}
	// Further writes are silently discarded.
	if n, err := c.Write([]byte("more")); err != nil || n != 4 || c.buf.Len() != 8 {
		t.Fatalf("post-overflow write: n=%d err=%v len=%d", n, err, c.buf.Len())
	}
}
