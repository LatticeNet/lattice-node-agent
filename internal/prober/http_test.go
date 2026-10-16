package prober

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// testPublicAddr is what the test resolver answers for testHost; the test
// dialer carries connections to it to a local server.
const (
	testHost       = "example.com"
	testPublicAddr = "203.0.113.80"
)

// servedAsPublic returns a prober that resolves testHost to a public
// address and dials that address on the loopback listener of srv, so the
// destination rules run as they do on a node, and srv's URL rewritten to
// testHost. httptest certificates name example.com, so https verifies.
func servedAsPublic(t *testing.T, srv *httptest.Server) (*prober, string) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	real := &net.Dialer{}
	p := newProber()
	p.resolver = &fakeResolver{answers: map[string][]string{testHost: {testPublicAddr}}}
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != testPublicAddr {
			return nil, fmt.Errorf("test dialer: unexpected address %s", address)
		}
		return real.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	if srv.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		p.rootCAs = pool
	}
	return p, u.Scheme + "://" + net.JoinHostPort(testHost, u.Port())
}

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
	p, base := servedAsPublic(t, srv)
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: base + "/start", TimeoutSec: 2}
	if res := p.probe(context.Background(), m); !res.Success {
		t.Fatalf("302 is inside the default 200-399: %+v", res)
	}
	m.ExpectStatus = "200"
	res := p.probe(context.Background(), m)
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
	p, base := servedAsPublic(t, srv)
	start := time.Now()
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: base, TimeoutSec: 5})
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("probe waited %s for a body it should not read", took)
	}
}

// secretServer is an https origin that records the X-Api-Key it saw.
func secretServer(t *testing.T) (string, *prober, func() []string) {
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
	p, base := servedAsPublic(t, srv)
	return base, p, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func secretMonitor(target, origin string) model.Monitor {
	return model.Monitor{
		Type: model.MonitorTypeHTTP, Target: target, TimeoutSec: 2,
		Headers:       []model.MonitorHeader{{Name: "x-api-key", Value: "s3cret-token-value", Secret: true}},
		SecretsOrigin: origin,
	}
}

func TestHTTPSecretHeadersGoOnlyToTheirHTTPSOrigin(t *testing.T) {
	base, p, seen := secretServer(t)
	origin, err := model.MonitorOrigin(base)
	if err != nil {
		t.Fatal(err)
	}
	res := p.probe(context.Background(), secretMonitor(base+"/health", origin))
	if !res.Success {
		t.Fatalf("matching origin over https: want success, got %+v", res)
	}
	if got := seen(); len(got) != 1 || got[0] != "s3cret-token-value" {
		t.Fatalf("server saw %q, want the secret once", got)
	}

	for _, other := range []string{"", "https://example.com:1", "https://127.0.0.1:443", strings.Replace(origin, "https://", "http://", 1), strings.ToUpper(origin)} {
		res := p.probe(context.Background(), secretMonitor(base, other))
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
	p, base := servedAsPublic(t, srv)
	origin, err := model.MonitorOrigin(base)
	if err != nil {
		t.Fatal(err)
	}
	res := p.probe(context.Background(), secretMonitor(base, origin))
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
	p, base := servedAsPublic(t, srv)
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: base, TimeoutSec: 2,
		Headers: []model.MonitorHeader{{Name: "x-probe", Value: "lattice"}}}
	if res := p.probe(context.Background(), m); !res.Success {
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
	p, base := servedAsPublic(t, srv)
	m := model.Monitor{Type: model.MonitorTypeHTTP, Target: base, TimeoutSec: 2,
		Headers: []model.MonitorHeader{{Name: "Host", Value: "evil.example"}}}
	res := p.probe(context.Background(), m)
	if res.Success || hits.Load() != 0 || strings.Contains(res.Error, "evil.example") {
		t.Fatalf("a Host header was not refused cleanly: %+v hits=%d", res, hits.Load())
	}
}

// Error text keeps the scheme, host and path of the URL and nothing of its
// user info, query or fragment.
func TestHTTPErrorIsRedacted(t *testing.T) {
	p, _, _ := fakeNetProber(map[string][]string{testHost: {testPublicAddr}})
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connect: connection refused")
	}
	m := model.Monitor{
		Type:       model.MonitorTypeHTTP,
		Target:     "http://probe-user:hunter2-pass@" + testHost + ":1/status?token=q-secret-value&x=1#frag-secret",
		TimeoutSec: 1,
		Headers:    []model.MonitorHeader{{Name: "Authorization", Value: "Bearer header-secret"}},
	}
	res := p.probe(context.Background(), m)
	if res.Success || res.Error == "" {
		t.Fatalf("expected a connection failure, got %+v", res)
	}
	for _, leak := range []string{"probe-user", "hunter2-pass", "q-secret-value", "token=", "frag-secret", "header-secret"} {
		if strings.Contains(res.Error, leak) {
			t.Fatalf("error %q carries %q", res.Error, leak)
		}
	}
	if !strings.Contains(res.Error, testHost+":1/status") {
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
	p, base := servedAsPublic(t, srv)
	if res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: base, TimeoutSec: 2}); !res.Success {
		t.Fatalf("probe went through the environment proxy: %+v", res)
	}
}

// http never takes target_node (design 29 D11): a check that carries one
// is judged like any other, so a stale or forged node reference cannot
// open the metadata service or a private range to an http check.
func TestHTTPIgnoresTargetNode(t *testing.T) {
	for _, target := range []string{"http://169.254.169.254/latest/meta-data/", "http://10.0.0.5:8080/", "http://inside.example/"} {
		p, _, d := fakeNetProber(map[string][]string{"inside.example": {"192.168.7.7"}})
		res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: target, TargetNode: testNode, TimeoutSec: 1})
		if res.Reason != model.PathReasonDestinationRefused {
			t.Fatalf("%s with target_node: want %s, got %+v", target, model.PathReasonDestinationRefused, res)
		}
		if got := d.addresses(); len(got) != 0 {
			t.Fatalf("%s with target_node: dialed %v", target, got)
		}
	}
}

// The transport dials only the target's host; a dial for any other host is
// refused and the run reports destination_refused, not a failure.
func TestHTTPTransportRefusesAnotherHost(t *testing.T) {
	p, _, d := fakeNetProber(nil)
	tr := p.httpTransport(testHost, []netip.Addr{netip.MustParseAddr(testPublicAddr)})
	_, err := tr.DialContext(context.Background(), "tcp", "other.example:443")
	var refused *destinationError
	if !errors.As(err, &refused) {
		t.Fatalf("want a destination refusal, got %v", err)
	}
	if got := d.addresses(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

// An internationalized host is looked up and dialed in punycode, as
// net/http sends it, and is not mistaken for another host.
func TestHTTPInternationalizedHost(t *testing.T) {
	srv := newLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	p, base := servedAsPublic(t, srv)
	r := &fakeResolver{answers: map[string][]string{"xn--bcher-kva.example": {testPublicAddr}}}
	p.resolver = r
	target := strings.Replace(base, testHost, "b\u00fccher.example", 1)
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeHTTP, Target: target, TimeoutSec: 2})
	if !res.Success {
		t.Fatalf("want success, got %+v", res)
	}
	if len(r.lookups) != 1 || r.lookups[0] != "xn--bcher-kva.example" {
		t.Fatalf("lookups %v, want the punycode name once", r.lookups)
	}
}
