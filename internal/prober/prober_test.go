package prober

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestProbeTCPSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable in this environment: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	res := Probe(context.Background(), model.Monitor{ID: "m1", Type: model.MonitorTypeTCP, Target: ln.Addr().String(), TimeoutSec: 2})
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Error)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("latency should be non-negative: %v", res.LatencyMs)
	}
	if res.MonitorID != "m1" {
		t.Fatalf("monitor id not propagated: %q", res.MonitorID)
	}
}

func TestProbeTCPFailure(t *testing.T) {
	// 127.0.0.1:1 is almost certainly closed.
	res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeTCP, Target: "127.0.0.1:1", TimeoutSec: 1})
	if res.Success {
		t.Fatal("expected failure to closed port")
	}
	if res.Error == "" {
		t.Fatal("expected error message")
	}
}

func TestProbeHTTP(t *testing.T) {
	ok := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	bad := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()

	if res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: ok.URL, TimeoutSec: 2}); !res.Success {
		t.Fatalf("expected http success, got %q", res.Error)
	}
	res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: bad.URL, TimeoutSec: 2})
	if res.Success || !strings.Contains(res.Error, "503") {
		t.Fatalf("expected http 503 failure, got success=%v err=%q", res.Success, res.Error)
	}
}

func newLocalHTTPTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable in this environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	return srv
}

func TestProbeUnsupportedType(t *testing.T) {
	res := Probe(context.Background(), model.Monitor{Type: "icmp", Target: "x"})
	if res.Success || !strings.Contains(res.Error, "unsupported") {
		t.Fatalf("expected unsupported error, got %+v", res)
	}
}
