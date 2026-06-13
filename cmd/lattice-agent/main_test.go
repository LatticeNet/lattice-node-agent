package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
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
