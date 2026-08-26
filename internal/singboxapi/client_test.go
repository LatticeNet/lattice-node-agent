package singboxapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// addrOf turns an httptest server URL into the host:port form Config wants.
func addrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "http://")
}

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	client, err := New(Config{Addr: addrOf(t, srv), Secret: "s3cret", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestNewRejectsNonLoopbackAddresses(t *testing.T) {
	// This is a security boundary. The Clash API secret is a bearer token sent
	// over plain HTTP, so a non-loopback address would put full control of the
	// local core on the wire.
	rejected := []struct {
		name string
		addr string
	}{
		{"unspecified v4", "0.0.0.0:9090"},
		{"unspecified v6", "[::]:9090"},
		{"public ip", "8.8.8.8:9090"},
		{"private lan ip", "192.168.1.10:9090"},
		{"non localhost hostname", "example.com:9090"},
		{"hostname that merely contains localhost", "localhost.evil.com:9090"},
		{"url form", "http://127.0.0.1:9090"},
		{"userinfo", "user@127.0.0.1:9090"},
		{"missing port", "127.0.0.1"},
		{"zero port", "127.0.0.1:0"},
		{"out of range port", "127.0.0.1:99999"},
		{"non numeric port", "127.0.0.1:clash"},
		{"empty", ""},
		{"whitespace", "   "},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Config{Addr: tc.addr})
			if err == nil {
				t.Fatalf("New(%q) accepted a non-loopback or malformed address", tc.addr)
			}
			if client != nil {
				t.Fatalf("New(%q) returned a client alongside an error", tc.addr)
			}
		})
	}
}

func TestNewAcceptsLoopbackAddresses(t *testing.T) {
	accepted := []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 loopback", "127.0.0.1:9090", "http://127.0.0.1:9090"},
		{"ipv4 loopback range", "127.0.0.2:9090", "http://127.0.0.2:9090"},
		{"ipv6 loopback", "[::1]:9090", "http://[::1]:9090"},
		{"localhost", "localhost:9090", "http://localhost:9090"},
		{"padded", "  127.0.0.1:9090  ", "http://127.0.0.1:9090"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Config{Addr: tc.addr})
			if err != nil {
				t.Fatalf("New(%q): %v", tc.addr, err)
			}
			if client.baseURL != tc.want {
				t.Fatalf("baseURL = %q, want %q", client.baseURL, tc.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Errorf("path = %q, want /version", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want Bearer s3cret", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":true,"premium":false,"version":"1.13.14"}`))
	}))
	defer srv.Close()

	version, err := newTestClient(t, srv).Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !version.Meta || version.Premium || version.Version != "1.13.14" {
		t.Fatalf("Version = %+v", version)
	}
}

func TestNoAuthorizationHeaderWhenSecretIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("Authorization header sent with an empty secret")
		}
		_, _ = w.Write([]byte(`{"meta":true,"version":"1.13.14"}`))
	}))
	defer srv.Close()

	client, err := New(Config{Addr: addrOf(t, srv), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Version(context.Background()); err != nil {
		t.Fatalf("Version: %v", err)
	}
}

func TestUnaryCallRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv).Connections(context.Background()); err == nil {
		t.Fatal("Connections accepted a 401 response")
	}
}

// TestConnectionsLiveFixture pins the top level shape against the real capture
// from a running sing-box v1.13.14. That capture has an empty connections
// array, so it can only guard the envelope; the per connection fields are
// covered by TestConnectionFieldsDecode below.
func TestConnectionsLiveFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/connections_live.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			t.Errorf("path = %q, want /connections", r.URL.Path)
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	before := time.Now().UTC()
	snapshot, err := newTestClient(t, srv).Connections(context.Background())
	if err != nil {
		t.Fatalf("Connections: %v", err)
	}
	if len(snapshot.Connections) != 0 {
		t.Fatalf("Connections = %d, want 0; the live fixture captured an idle core", len(snapshot.Connections))
	}
	if snapshot.DownloadTotal != 6224 {
		t.Errorf("DownloadTotal = %d, want 6224", snapshot.DownloadTotal)
	}
	if snapshot.UploadTotal != 748 {
		t.Errorf("UploadTotal = %d, want 748", snapshot.UploadTotal)
	}
	if snapshot.Memory != 3686400 {
		t.Errorf("Memory = %d, want 3686400", snapshot.Memory)
	}
	if snapshot.At.Before(before) || snapshot.At.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("At = %v, want a receipt time inside the call", snapshot.At)
	}
	if snapshot.At.Location() != time.UTC {
		t.Errorf("At location = %v, want UTC", snapshot.At.Location())
	}
}

// populatedConnections is hand built, NOT a live capture. The checked in
// fixture caught an idle core with zero connections, so the per connection
// field assertions need a body with connections in it. The field names and
// their types follow SINGBOX-TRACE-DESIGN.md section 3.3, which records what
// the real binary sends. It is kept inline rather than in testdata/ so nobody
// later mistakes it for captured evidence.
const populatedConnections = `{
  "connections": [
    {
      "id": "8f0f7a9c-1a3e-4b2d-9f11-2c6d5e4a7b30",
      "upload": 4096,
      "download": 1048576,
      "start": "2026-08-26T00:02:38.512345678+08:00",
      "chains": ["vless-exit", "direct-out"],
      "rule": "rule_set",
      "rulePayload": "geosite-cn",
      "metadata": {
        "network": "tcp",
        "type": "vless/vless-exit",
        "host": "example.com",
        "sourceIP": "10.24.0.7",
        "sourcePort": "51514",
        "destinationIP": "93.184.216.34",
        "destinationPort": "443",
        "dnsMode": "normal",
        "processPath": "/usr/bin/curl"
      }
    },
    {
      "id": "b1c2d3e4-0000-4000-8000-000000000001",
      "upload": 0,
      "download": 0,
      "start": "2026-08-26T00:02:39Z",
      "chains": null,
      "rule": "",
      "rulePayload": "",
      "metadata": {
        "network": "udp",
        "type": "tun",
        "host": "",
        "sourceIP": "10.24.0.9",
        "sourcePort": "not-a-port",
        "destinationIP": "1.1.1.1",
        "destinationPort": "53",
        "dnsMode": "normal",
        "processPath": ""
      }
    }
  ],
  "downloadTotal": 1048576,
  "uploadTotal": 4096,
  "memory": 3686400
}`

func TestConnectionFieldsDecode(t *testing.T) {
	var snapshot ConnectionsSnapshot
	if err := json.Unmarshal([]byte(populatedConnections), &snapshot); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snapshot.Connections) != 2 {
		t.Fatalf("Connections = %d, want 2", len(snapshot.Connections))
	}

	first := snapshot.Connections[0]
	if first.ID != "8f0f7a9c-1a3e-4b2d-9f11-2c6d5e4a7b30" {
		t.Errorf("ID = %q", first.ID)
	}
	if first.Upload != 4096 {
		t.Errorf("Upload = %d, want 4096", first.Upload)
	}
	if first.Download != 1048576 {
		t.Errorf("Download = %d, want 1048576", first.Download)
	}
	wantStart := time.Date(2026, 8, 26, 0, 2, 38, 512345678, time.FixedZone("", 8*3600))
	if !first.Start.Equal(wantStart) {
		t.Errorf("Start = %v, want %v", first.Start, wantStart)
	}
	if first.Rule != "rule_set" || first.RulePayload != "geosite-cn" {
		t.Errorf("Rule/RulePayload = %q/%q", first.Rule, first.RulePayload)
	}
	if len(first.Chains) != 2 || first.Chains[0] != "vless-exit" || first.Chains[1] != "direct-out" {
		t.Errorf("Chains = %v", first.Chains)
	}

	meta := first.Metadata
	if meta.Network != "tcp" || meta.Host != "example.com" {
		t.Errorf("Network/Host = %q/%q", meta.Network, meta.Host)
	}
	if meta.SourceIP != "10.24.0.7" || meta.DestinationIP != "93.184.216.34" {
		t.Errorf("SourceIP/DestinationIP = %q/%q", meta.SourceIP, meta.DestinationIP)
	}
	if meta.DNSMode != "normal" || meta.ProcessPath != "/usr/bin/curl" {
		t.Errorf("DNSMode/ProcessPath = %q/%q", meta.DNSMode, meta.ProcessPath)
	}

	inboundType, inboundTag := meta.InboundTypeAndTag()
	if inboundType != "vless" || inboundTag != "vless-exit" {
		t.Errorf("InboundTypeAndTag = %q/%q, want vless/vless-exit", inboundType, inboundTag)
	}

	// Ports arrive as JSON strings and have to survive the round trip to int.
	srcPort, err := meta.SourcePortInt()
	if err != nil {
		t.Fatalf("SourcePortInt: %v", err)
	}
	if srcPort != 51514 {
		t.Errorf("SourcePortInt = %d, want 51514", srcPort)
	}
	dstPort, err := meta.DestinationPortInt()
	if err != nil {
		t.Fatalf("DestinationPortInt: %v", err)
	}
	if dstPort != 443 {
		t.Errorf("DestinationPortInt = %d, want 443", dstPort)
	}

	second := snapshot.Connections[1]
	// A null chains array must decode to an empty slice, not blow up, because
	// a connection handled by the default outbound has no chain at all.
	if len(second.Chains) != 0 {
		t.Errorf("Chains = %v, want empty for a null value", second.Chains)
	}
	// A type with no separator is a type with no tag, not a tag with no type.
	if gotType, gotTag := second.Metadata.InboundTypeAndTag(); gotType != "tun" || gotTag != "" {
		t.Errorf("InboundTypeAndTag = %q/%q, want tun/\"\"", gotType, gotTag)
	}
	// An unparseable port must report failure. Returning 0 would silently
	// corrupt the SourceIP:SourcePort key used to join against log lines.
	if _, err := second.Metadata.SourcePortInt(); err == nil {
		t.Error("SourcePortInt accepted \"not-a-port\"")
	}
}

func TestInboundTypeAndTagEdgeCases(t *testing.T) {
	cases := []struct {
		raw      string
		wantType string
		wantTag  string
	}{
		{"vless/vless-exit", "vless", "vless-exit"},
		{"mixed/mixed-entry", "mixed", "mixed-entry"},
		{"", "", ""},
		{"tun", "tun", ""},
		// An inbound tag is free text and may contain a slash; an inbound type
		// never does, so only the first separator splits.
		{"http/tag/with/slash", "http", "tag/with/slash"},
		{"vless/", "vless", ""},
	}
	for _, tc := range cases {
		gotType, gotTag := ConnMetadata{Type: tc.raw}.InboundTypeAndTag()
		if gotType != tc.wantType || gotTag != tc.wantTag {
			t.Errorf("InboundTypeAndTag(%q) = %q/%q, want %q/%q", tc.raw, gotType, gotTag, tc.wantType, tc.wantTag)
		}
	}
}

func TestParsePortRejectsBadValues(t *testing.T) {
	for _, raw := range []string{"", "   ", "abc", "-1", "65536", "443.0", "0x1bb"} {
		if _, err := parsePort("sourcePort", raw); err == nil {
			t.Errorf("parsePort(%q) accepted an invalid port", raw)
		}
	}
	for _, tc := range []struct {
		raw  string
		want int
	}{{"0", 0}, {"443", 443}, {"65535", 65535}, {" 51514 ", 51514}} {
		got, err := parsePort("sourcePort", tc.raw)
		if err != nil {
			t.Errorf("parsePort(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parsePort(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}
