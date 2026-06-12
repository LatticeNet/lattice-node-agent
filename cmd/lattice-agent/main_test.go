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

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}
