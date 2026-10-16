package prober

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A 3xx is the answer: it is judged against expect_status and its
// Location is never requested.
func TestHTTPRedirectIsNotFollowed(t *testing.T) {
	var landed atomic.Int32
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			landed.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/landed", http.StatusFound)
	}))
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: srv.URL + "/start", TargetNode: testNode, TimeoutSec: 2}
	if res := Probe(context.Background(), m); !res.Success {
		t.Fatalf("302 is inside the default 200-399: %+v", res)
	}
	m.ExpectStatus = "200"
	res := Probe(context.Background(), m)
	if res.Success || !strings.Contains(res.Error, "302") {
		t.Fatalf("302 is outside expect_status 200: %+v", res)
	}
	if n := landed.Load(); n != 0 {
		t.Fatalf("the redirect target was requested %d times", n)
	}
}

// Latency is the time to the response headers: a body that never ends
// does not hold the probe, and it is closed unread.
func TestHTTPLatencyStopsAtHeaders(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	start := time.Now()
	res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: srv.URL, TargetNode: testNode, TimeoutSec: 5})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("probe waited %s for a body it should not read", took)
	}
}

// secretServer is an https origin that records the X-Api-Key it saw.
func secretServer(t *testing.T) (*httptest.Server, *prober, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p := newProber()
	p.rootCAs = pool
	return srv, p, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func secretMonitor(target, origin string) model.Monitor {
	return model.Monitor{
		Type: model.MonitorTypeHTTP, Target: target, TargetNode: testNode, TimeoutSec: 2,
		Headers:       []model.MonitorHeader{{Name: "x-api-key", Value: "s3cret-token-value", Secret: true}},
		SecretsOrigin: origin,
	}
}

func TestHTTPSecretHeadersGoOnlyToTheirHTTPSOrigin(t *testing.T) {
	srv, p, seen := secretServer(t)
	origin, err := model.MonitorOrigin(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := p.probe(context.Background(), secretMonitor(srv.URL+"/health", origin))
	if !res.Success {
		t.Fatalf("matching origin over https: want success, got %+v", res)
	}
	if got := seen(); len(got) != 1 || got[0] != "s3cret-token-value" {
		t.Fatalf("server saw %q, want the secret once", got)
	}

	for _, other := range []string{"", "https://127.0.0.1:1", "https://example.com:443", strings.Replace(origin, "https://", "http://", 1)} {
		res := p.probe(context.Background(), secretMonitor(srv.URL, other))
		if res.Reason != model.PathReasonDestinationRefused {
			t.Fatalf("secrets_origin %q: want %s, got %+v", other, model.PathReasonDestinationRefused, res)
		}
	}
	if got := seen(); len(got) != 1 {
		t.Fatalf("a refused run reached the server: %q", got)
	}
}

// Over plain http a secret header is never sent, even when the origin
// matches; the run is refused before anything leaves.
func TestHTTPSecretHeadersNeverGoOverHTTP(t *testing.T) {
	var hits atomic.Int32
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	origin, err := model.MonitorOrigin(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := Probe(context.Background(), secretMonitor(srv.URL, origin))
	if res.Reason != model.PathReasonDestinationRefused || res.Success {
		t.Fatalf("want %s, got %+v", model.PathReasonDestinationRefused, res)
	}
	if strings.Contains(res.Error, "s3cret-token-value") {
		t.Fatalf("error carries the secret: %q", res.Error)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server was reached %d times", n)
	}
}

func TestHTTPPlainHeadersAreSent(t *testing.T) {
	got := make(chan string, 1)
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Probe")
	}))
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: srv.URL, TargetNode: testNode, TimeoutSec: 2,
		Headers: []model.MonitorHeader{{Name: "x-probe", Value: "lattice"}}}
	if res := Probe(context.Background(), m); !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if v := <-got; v != "lattice" {
		t.Fatalf("server saw X-Probe %q", v)
	}
}

// A header the agent's stack owns is refused even if the control plane
// sent one, and the error names it without its value.
func TestHTTPForbiddenHeaderIsNotSent(t *testing.T) {
	var hits atomic.Int32
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: srv.URL, TargetNode: testNode, TimeoutSec: 2,
		Headers: []model.MonitorHeader{{Name: "Host", Value: "evil.example"}}}
	res := Probe(context.Background(), m)
	if res.Success || hits.Load() != 0 || strings.Contains(res.Error, "evil.example") {
		t.Fatalf("a Host header was not refused cleanly: %+v hits=%d", res, hits.Load())
	}
}

// Error text keeps the scheme, host and path of the URL and nothing of its
// user info, query or fragment.
func TestHTTPErrorIsRedacted(t *testing.T) {
	m := model.Monitor{
		Type:       model.MonitorTypeHTTP,
		Target:     "http://probe-user:hunter2-pass@127.0.0.1:1/status?token=q-secret-value&x=1#frag-secret",
		TargetNode: testNode,
		TimeoutSec: 1,
		Headers:    []model.MonitorHeader{{Name: "Authorization", Value: "Bearer header-secret"}},
	}
	res := Probe(context.Background(), m)
	if res.Success || res.Error == "" {
		t.Fatalf("expected a connection failure, got %+v", res)
	}
	for _, leak := range []string{"probe-user", "hunter2-pass", "q-secret-value", "token=", "frag-secret", "header-secret"} {
		if strings.Contains(res.Error, leak) {
			t.Fatalf("error %q carries %q", res.Error, leak)
		}
	}
	if !strings.Contains(res.Error, "127.0.0.1:1/status") {
		t.Fatalf("error %q lost the host and path", res.Error)
	}
}

func TestRedactHTTPErrorScrubsWhateverFormTheErrorTook(t *testing.T) {
	m := model.Monitor{
		Target:  "https://alice:pw-12345@api.example/v1?key=abc%2Fdef",
		Headers: []model.MonitorHeader{{Name: "X-Api-Key", Value: "value-9876", Secret: true}},
	}
	wrapped := &url.Error{Op: "Get", URL: m.Target, Err: errors.New("remote said value-9876 and key=abc/def")}
	got := redactHTTPError(wrapped, m)
	for _, leak := range []string{"alice", "pw-12345", "abc%2Fdef", "abc/def", "value-9876"} {
		if strings.Contains(got, leak) {
			t.Fatalf("redacted error %q carries %q", got, leak)
		}
	}
	if !strings.Contains(got, `"https://api.example/v1"`) {
		t.Fatalf("redacted error %q lost the URL's origin and path", got)
	}
}

// The transport never takes a proxy from the environment, so a probe's
// request goes to the judged address and nowhere else.
func TestHTTPTransportIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	tr := newProber().httpTransport("example.com", nil)
	if tr.Proxy != nil {
		t.Fatal("transport carries a proxy function")
	}
	if !tr.DisableKeepAlives {
		t.Fatal("transport keeps connections between probes")
	}
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if res := Probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: srv.URL, TargetNode: testNode, TimeoutSec: 2}); !res.Success {
		t.Fatalf("probe went through the environment proxy: %+v", res)
	}
}
