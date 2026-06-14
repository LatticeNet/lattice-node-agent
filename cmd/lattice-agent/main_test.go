package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestReportMetricsUsesBearerAuthAndOmitsBodyToken(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["node_id"] != "node-a" {
			return testResponse(http.StatusBadRequest, "missing node_id"), nil
		}
		if _, ok := body["token"]; ok {
			return testResponse(http.StatusBadRequest, "body token leaked"), nil
		}
		if _, ok := body["host_facts"].(map[string]any); !ok {
			return testResponse(http.StatusBadRequest, "missing host_facts"), nil
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}

	err := reportMetrics(agentConfig{
		Server:   "http://lattice.test",
		NodeID:   "node-a",
		Token:    "node-secret",
		Interval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCheckServerTransport pins the cleartext-token guard (C19): https is always
// allowed, loopback http is allowed, but non-loopback http must be refused unless
// the operator explicitly opts in with -allow-insecure-http.
func TestCheckServerTransport(t *testing.T) {
	cases := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
	}{
		{"loopback ipv4 http ok", "http://127.0.0.1:8088", false, false},
		{"loopback ipv4 subnet http ok", "http://127.5.6.7:8088", false, false},
		{"loopback ipv6 http ok", "http://[::1]:8088", false, false},
		{"localhost http ok", "http://localhost:8088", false, false},
		{"https remote ok", "https://lattice.example.com", false, false},
		{"https loopback ok", "https://127.0.0.1:8443", false, false},
		{"remote http refused", "http://lattice.example.com:8088", false, true},
		{"remote ip http refused", "http://203.0.113.5:8088", false, true},
		{"remote http allowed with override", "http://lattice.example.com:8088", true, false},
		{"unsupported scheme refused", "ftp://lattice.example.com", false, true},
		{"unsupported scheme not saved by override", "ftp://lattice.example.com", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkServerTransport(c.url, c.allowInsecure)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkServerTransport(%q, allowInsecure=%v) err=%v, wantErr=%v", c.url, c.allowInsecure, err, c.wantErr)
			}
		})
	}
}

func TestSelfcheckControlPlaneUsesHealthWithoutBearer(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/health" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "" {
			return testResponse(http.StatusBadRequest, "unexpected auth"), nil
		}
		return testResponse(http.StatusOK, `{"status":"ok"}`), nil
	})}
	if err := selfcheckControlPlaneWithClient("https://lattice.test/", client); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected one health request, got %d", calls)
	}
}

func TestSelfcheckControlPlaneRejectsNonOK(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(http.StatusServiceUnavailable, "down"), nil
	})}
	if err := selfcheckControlPlaneWithClient("https://lattice.test", client); err == nil {
		t.Fatal("expected non-200 selfcheck to fail")
	}
}

func TestNFTDomainSetUpdateBuildsDeterministicArgv(t *testing.T) {
	var commands [][]string
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "LATTICE.Example.COM.", Family: "inet", Table: "lattice_policy", Set: "lattice_control4",
	}, func(ctx context.Context, host string) ([]string, error) {
		if host != "lattice.example.com" {
			t.Fatalf("host not normalized before resolution: %q", host)
		}
		return []string{"203.0.113.10", "2001:db8::1", "198.51.100.2", "203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"flush", "set", "inet", "lattice_policy", "lattice_control4"},
		{"add", "element", "inet", "lattice_policy", "lattice_control4", "{ 198.51.100.2, 203.0.113.10 }"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected nft argv:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestNFTDomainSetUpdateRejectsNoIPv4(t *testing.T) {
	called := false
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"2001:db8::1"}, nil
	}, func(ctx context.Context, args ...string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("expected no-IPv4 failure before nft commands, err=%v called=%v", err, called)
	}
}

func TestNFTDomainSetUpdateRejectsUnsafeIdentifiers(t *testing.T) {
	cases := []nftDomainSetConfig{
		{Host: "bad host", Family: "inet", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet;reboot", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice-policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice/control4"},
	}
	for _, cfg := range cases {
		err := updateNFTDomainSet(context.Background(), cfg, func(ctx context.Context, host string) ([]string, error) {
			t.Fatalf("resolver should not run for invalid config: %+v", cfg)
			return nil, nil
		}, func(ctx context.Context, args ...string) error {
			t.Fatalf("nft should not run for invalid config: %+v", cfg)
			return nil
		})
		if err == nil {
			t.Fatalf("expected invalid config to fail: %+v", cfg)
		}
	}
}

func TestNFTDomainSetUpdateStopsOnFlushFailure(t *testing.T) {
	errBoom := errors.New("boom")
	calls := 0
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		calls++
		if calls == 1 {
			return errBoom
		}
		return nil
	})
	if !errors.Is(err, errBoom) || calls != 1 {
		t.Fatalf("expected flush failure to stop before add, err=%v calls=%d", err, calls)
	}
}

// TestIsLoopbackHost covers the pure helper directly for the loopback decision.
func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"localhost", "127.0.0.1", "127.0.0.53", "::1"}
	remote := []string{"lattice.example.com", "203.0.113.5", "10.0.0.1", "0.0.0.0", "2001:db8::1", ""}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range remote {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}
