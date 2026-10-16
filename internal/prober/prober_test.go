package prober

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Loopback servers stand in for targets throughout these tests. The
// destination rules refuse loopback unless the control plane resolved the
// target from a node, so tests that need a live peer set TargetNode.
const testNode = "node-under-test"

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
	res := Probe(context.Background(), model.Monitor{ID: "m1", Type: model.MonitorTypeTCP, Target: ln.Addr().String(), TargetNode: testNode, TimeoutSec: 2})
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Error)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("latency should be non-negative: %v", res.LatencyMs)
	}
	if res.MonitorID != "m1" {
		t.Fatalf("monitor id not propagated: %q", res.MonitorID)
	}
	if res.Sent != 0 || res.Lost != 0 || res.RTTsMs != nil || res.Reason != "" {
		t.Fatalf("a single-probe run carries no packet fields or reason: %+v", res)
	}
	wire, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cert_not_after", "sent", "lost", "rtts_ms", "reason"} {
		if strings.Contains(string(wire), `"`+key+`"`) {
			t.Fatalf("a tcp result carries %s on the wire: %s", key, wire)
		}
	}
}

func TestProbeTCPFailure(t *testing.T) {
	// 127.0.0.1:1 is almost certainly closed.
	res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeTCP, Target: "127.0.0.1:1", TargetNode: testNode, TimeoutSec: 1})
	if res.Success {
		t.Fatal("expected failure to closed port")
	}
	if res.Error == "" || res.Reason != "" {
		t.Fatalf("a refused connection is a failure, not a reason: %+v", res)
	}
}

func TestProbeHTTP(t *testing.T) {
	ok := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	bad := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	pOK, okURL := servedAsPublic(t, ok)
	pBad, badURL := servedAsPublic(t, bad)

	if res := pOK.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: okURL, TimeoutSec: 2}); !res.Success {
		t.Fatalf("expected http success, got %q", res.Error)
	}
	res := pBad.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: badURL, TimeoutSec: 2})
	if res.Success || !strings.Contains(res.Error, "503") || res.Reason != "" {
		t.Fatalf("expected http 503 failure, got %+v", res)
	}
	res = pBad.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: badURL, TimeoutSec: 2, ExpectStatus: "500-599"})
	if !res.Success {
		t.Fatalf("503 is inside expect_status 500-599: %+v", res)
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
	t.Cleanup(srv.Close)
	return srv
}

// An M2a agent handed a kind it does not run reports agent_too_old, which
// the control plane reads as unknown, never as a failure.
func TestProbeUnknownKindReportsAgentTooOld(t *testing.T) {
	for _, kind := range []string{model.MonitorTypeBeacon, model.MonitorTypeTLS, "smtp", ""} {
		res := Probe(context.Background(), model.Monitor{ID: "m", Type: kind, Target: "203.0.113.9"})
		if res.Success || res.Reason != model.PathReasonAgentTooOld {
			t.Fatalf("kind %q: want reason %s, got %+v", kind, model.PathReasonAgentTooOld, res)
		}
		if res.Sent != 0 || res.LatencyMs != 0 {
			t.Fatalf("kind %q: nothing was measured: %+v", kind, res)
		}
	}
}

// Every reason the agent reports fits the contract's code shape.
func TestReasonCodesFitContract(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	for _, reason := range []string{model.PathReasonAgentTooOld, model.PathReasonICMPNotPermitted, model.PathReasonDestinationRefused} {
		if !shape.MatchString(reason) {
			t.Fatalf("reason %q does not match %s", reason, shape)
		}
	}
}

func TestRunBudgetCoversEchoSpacing(t *testing.T) {
	cases := []struct {
		m    model.Monitor
		want string
	}{
		{model.Monitor{Type: model.MonitorTypeTCP, TimeoutSec: 3}, "3s"},
		{model.Monitor{Type: model.MonitorTypeHTTP}, "5s"},
		{model.Monitor{Type: model.MonitorTypeICMP, TimeoutSec: 2}, "2.8s"},
		{model.Monitor{Type: model.MonitorTypeICMP, TimeoutSec: 1, Packets: 10}, "2.8s"},
		{model.Monitor{Type: model.MonitorTypeICMP, TimeoutSec: 1, Packets: 1}, "1s"},
		{model.Monitor{Type: model.MonitorTypeICMP, TimeoutSec: 1, Packets: 50}, "2.8s"},
	}
	for _, c := range cases {
		if got := RunBudget(c.m).String(); got != c.want {
			t.Fatalf("RunBudget(%+v) = %s, want %s", c.m, got, c.want)
		}
	}
}
