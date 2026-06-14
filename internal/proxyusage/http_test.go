package proxyusage

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestValidateLocalHTTPURL(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:9090/proxy-usage",
		"http://127.9.8.7:9090/",
		"http://[::1]:9090/stats",
		"https://localhost/stats",
	}
	for _, raw := range valid {
		if _, err := ValidateLocalHTTPURL(raw); err != nil {
			t.Fatalf("ValidateLocalHTTPURL(%q) unexpected error: %v", raw, err)
		}
	}
	invalid := []string{
		"",
		"ftp://127.0.0.1/stats",
		"http://user:pass@127.0.0.1/stats",
		"http://10.0.0.1/stats",
		"http://example.com/stats",
		"http://0.0.0.0:9090/stats",
	}
	for _, raw := range invalid {
		if _, err := ValidateLocalHTTPURL(raw); err == nil {
			t.Fatalf("ValidateLocalHTTPURL(%q) expected error", raw)
		}
	}
}

func TestDecodeUsageSnapshotDirectAndEnvelope(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	direct, err := DecodeUsageSnapshot([]byte(`{"core_uptime_sec":99,"user_bytes":{" alice ":10,"alice":2}}`), "node-a", fixed)
	if err != nil {
		t.Fatal(err)
	}
	if direct.NodeID != "node-a" || !direct.At.Equal(fixed) || direct.CoreUptimeSec != 99 || direct.UserBytes["alice"] != 12 {
		t.Fatalf("unexpected direct snapshot: %+v", direct)
	}
	envelope, err := DecodeUsageSnapshot([]byte(`{"snapshot":{"user_bytes":{"bob":7}}}`), "node-b", fixed)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.NodeID != "node-b" || envelope.UserBytes["bob"] != 7 {
		t.Fatalf("unexpected envelope snapshot: %+v", envelope)
	}
}

func TestDecodeUsageSnapshotV2RayStats(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	body := []byte(`{
	  "stat": [
	    {"name":"user>>>alice>>>traffic>>>uplink","value":100},
	    {"name":"user>>>alice>>>traffic>>>downlink","value":"50"},
	    {"name":"user>>>bob>>>traffic>>>uplink","value":7},
	    {"name":"inbound>>>proxy-in>>>traffic>>>uplink","value":999},
	    {"name":"user>>>carol>>>requests>>>total","value":123}
	  ]
	}`)
	snapshot, err := DecodeUsageSnapshot(body, "node-a", fixed)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"alice": 150, "bob": 7}
	if snapshot.NodeID != "node-a" || !snapshot.At.Equal(fixed) || !reflect.DeepEqual(snapshot.UserBytes, want) {
		t.Fatalf("unexpected v2ray snapshot: %+v", snapshot)
	}
}

func TestDecodeUsageSnapshotRejectsMalformedCounters(t *testing.T) {
	cases := []string{
		`{"user_bytes":{"alice":-1}}`,
		`{"user_bytes":{"":1}}`,
		`{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":-1}]}`,
		`{"hello":"world"}`,
	}
	for _, body := range cases {
		if _, err := DecodeUsageSnapshot([]byte(body), "node-a", time.Now()); err == nil {
			t.Fatalf("DecodeUsageSnapshot(%s) expected error", body)
		}
	}
}

func TestLoadHTTPUsesBearerAndBoundsResponse(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.String() != "http://127.0.0.1:9090/stats" {
			t.Fatalf("bad request: %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer local-secret" {
			t.Fatalf("missing bearer secret: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing accept header: %q", r.Header.Get("Accept"))
		}
		return response(http.StatusOK, `{"user_bytes":{"alice":42}}`), nil
	})}
	snapshot, err := LoadHTTP(context.Background(), HTTPSource{
		URL:    "http://127.0.0.1:9090/stats",
		Secret: " local-secret ",
		Client: client,
		Now:    func() time.Time { return time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC) },
	}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || snapshot.UserBytes["alice"] != 42 || snapshot.NodeID != "node-a" {
		t.Fatalf("unexpected load result calls=%d snapshot=%+v", calls, snapshot)
	}
}

func TestLoadHTTPRejectsRemoteBeforeCallingTransport(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("transport must not be called for remote usage URL")
		return nil, nil
	})}
	_, err := LoadHTTP(context.Background(), HTTPSource{URL: "http://example.com/stats", Client: client}, "node-a")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback validation error, got %v", err)
	}
}

func TestLoadHTTPRejectsOversizedBody(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(make([]byte, maxUsageFileBytes+1))),
		}, nil
	})}
	if _, err := LoadHTTP(context.Background(), HTTPSource{URL: "http://127.0.0.1/stats", Client: client}, "node-a"); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
