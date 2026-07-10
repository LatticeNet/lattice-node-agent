package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestVersionMatchesCurrentRelease(t *testing.T) {
	if version != "0.2.9" {
		t.Fatalf("version = %q, want 0.2.9", version)
	}
}

func TestCompatibilityPayloadIsEmbedded(t *testing.T) {
	got := compatibilityPayload()
	if got.ServerMin == "" || got.DashboardMin == "" || got.Channel == "" {
		t.Fatalf("compatibility metadata must be embedded: %+v", got)
	}
	if got.Channel != "stable" {
		t.Fatalf("compatibility channel = %q, want stable", got.Channel)
	}
	if got.ServerMin != "v0.2.1" || got.DashboardMin != "v0.2.1" {
		t.Fatalf("compatibility floor = %+v, want coordinated v0.2.1", got)
	}
}

func TestApplyAgentConfigControlsDebugCollection(t *testing.T) {
	sink := newDebugSink(10)
	cfg := agentConfig{DebugSink: sink}
	applyAgentConfig(&cfg, model.AgentConfig{Debug: model.AgentDebugConfig{
		Enabled:       true,
		Collect:       true,
		MaxLineBytes:  12,
		MaxBatchLines: 2,
	}})
	if !cfg.Debug || !cfg.ServerDebug || !cfg.DebugCollect {
		t.Fatalf("expected server debug with collection enabled: %+v", cfg)
	}
	if cfg.DebugMaxLineBytes != 12 || cfg.DebugMaxBatchLines != 2 {
		t.Fatalf("debug caps not applied: line=%d batch=%d", cfg.DebugMaxLineBytes, cfg.DebugMaxBatchLines)
	}
	debugf(cfg, "diagnostic %s", "message")
	lines := sink.drain(10)
	if len(lines) != 1 || lines[0] != "diagnostic m...truncated" {
		t.Fatalf("debug line not collected/truncated as expected: %q", lines)
	}

	applyAgentConfig(&cfg, model.AgentConfig{Debug: model.AgentDebugConfig{
		Enabled: true,
		Collect: false,
	}})
	if !cfg.Debug || cfg.DebugCollect {
		t.Fatalf("expected local debug without collection: %+v", cfg)
	}
	debugf(cfg, "local only")
	if got := sink.drain(10); len(got) != 0 {
		t.Fatalf("collect=false should not retain debug lines, got %q", got)
	}
}

func TestFlushDebugEventsPostsBufferedLines(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	sink := newDebugSink(10)
	cfg := agentConfig{
		Server:             "http://lattice.test",
		NodeID:             "node-a",
		Token:              "node-secret",
		Debug:              true,
		DebugCollect:       true,
		DebugMaxLineBytes:  defaultDebugMaxLineBytes,
		DebugMaxBatchLines: defaultDebugMaxBatchLines,
		DebugSink:          sink,
	}
	debugf(cfg, "poll cycle complete")
	debugf(cfg, "agent post ok: path=/api/agent/metrics")

	var body struct {
		NodeID string                `json:"node_id"`
		Batch  model.AgentDebugBatch `json:"batch"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/debug-events" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true,"accepted":2}`), nil
	})}
	if err := flushDebugEvents(cfg); err != nil {
		t.Fatal(err)
	}
	if body.NodeID != "node-a" || body.Batch.NodeID != "node-a" {
		t.Fatalf("node id not pinned in debug batch: %+v", body)
	}
	if len(body.Batch.Lines) != 2 || body.Batch.Lines[0] != "poll cycle complete" {
		t.Fatalf("unexpected debug batch: %+v", body.Batch.Lines)
	}
	if got := sink.drain(10); len(got) != 0 {
		t.Fatalf("flush should drain sent lines, got %q", got)
	}
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

func TestAgentHTTPErrorIncludesStructuredServerDiagnostics(t *testing.T) {
	resp := testResponse(http.StatusForbidden, `{"error":{"code":"agent_update_policy_stale","message":"re-plan before approving","request_id":"req-body"}}`)
	resp.Header.Set(latticeRequestIDHeader, "req-header")

	err := agentHTTPError(resp, "fetch tasks")

	requireErrorContains(t, err, "fetch tasks")
	requireErrorContains(t, err, "403 Forbidden")
	requireErrorContains(t, err, "agent_update_policy_stale")
	requireErrorContains(t, err, "re-plan before approving")
	requireErrorContains(t, err, "request_id=req-body")
}

func TestAgentHTTPErrorUsesHeaderRequestIDForTextClientError(t *testing.T) {
	resp := testResponse(http.StatusTooManyRequests, "retry later")
	resp.Header.Set(latticeRequestIDHeader, "req-header")
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")

	err := agentHTTPError(resp, "post /api/agent/logs")

	requireErrorContains(t, err, "429 Too Many Requests")
	requireErrorContains(t, err, "retry later")
	requireErrorContains(t, err, "request_id=req-header")
}

func TestAgentHTTPErrorHidesUnstructuredServerBody(t *testing.T) {
	resp := testResponse(http.StatusInternalServerError, "database password leaked")
	resp.Header.Set("Content-Type", "text/plain")

	err := agentHTTPError(resp, "fetch monitors")

	requireErrorContains(t, err, "fetch monitors")
	requireErrorContains(t, err, "500 Internal Server Error")
	requireErrorNotContains(t, err, "database password leaked")
}

func TestPostJSONReturnsStructuredServerDiagnostics(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/task-result" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		resp := testResponse(http.StatusConflict, `{"error":{"code":"task_result_conflict","message":"task already finished","request_id":"req-task"}}`)
		resp.Header.Set(latticeRequestIDHeader, "req-header")
		return resp, nil
	})}

	err := postJSON("http://lattice.test/api/agent/task-result", "node-secret", map[string]any{"ok": true}, nil)

	requireErrorContains(t, err, "post /api/agent/task-result")
	requireErrorContains(t, err, "409 Conflict")
	requireErrorContains(t, err, "task_result_conflict")
	requireErrorContains(t, err, "task already finished")
	requireErrorContains(t, err, "request_id=req-task")
}

func TestShipLogBatchReturnsStatusAndStructuredDiagnostics(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/logs" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		resp := testResponse(http.StatusTooManyRequests, `{"error":{"code":"rate_limited","message":"slow down","request_id":"req-log"}}`)
		resp.Header.Set(latticeRequestIDHeader, "req-header")
		return resp, nil
	})}

	status, err := shipLogBatch(agentConfig{
		Server: "http://lattice.test",
		NodeID: "node-a",
		Token:  "node-secret",
	}, model.LogBatch{SourceID: "src-a", Lines: []string{"hello"}})

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
	requireErrorContains(t, err, "ship log batch")
	requireErrorContains(t, err, "429 Too Many Requests")
	requireErrorContains(t, err, "rate_limited")
	requireErrorContains(t, err, "slow down")
	requireErrorContains(t, err, "request_id=req-log")
}

func TestReportProxyUsageIncludesCollectorHealthOnSuccess(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	dir := t.TempDir()
	usageFile := filepath.Join(dir, "usage.json")
	if err := os.WriteFile(usageFile, []byte(`{"core_uptime_sec":10,"user_bytes":{"alice":123}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var body struct {
		NodeID   string                   `json:"node_id"`
		Snapshot model.ProxyUsageSnapshot `json:"snapshot"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/proxy-usage" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	if err := reportProxyUsage(agentConfig{
		Server:         "http://lattice.test",
		NodeID:         "node-a",
		Token:          "node-secret",
		ProxyUsageFile: usageFile,
	}); err != nil {
		t.Fatal(err)
	}
	if body.NodeID != "node-a" || body.Snapshot.NodeID != "node-a" {
		t.Fatalf("node id not pinned in body: %+v", body)
	}
	if body.Snapshot.CollectorSource != "file" || body.Snapshot.CollectorStatus != model.ProxyUsageCollectorStatusOK {
		t.Fatalf("collector health missing from success snapshot: %+v", body.Snapshot)
	}
	if body.Snapshot.CollectorError != "" || body.Snapshot.CollectorCheckedAt.IsZero() {
		t.Fatalf("unexpected success collector fields: %+v", body.Snapshot)
	}
}

func TestReportProxyUsageReportsCollectorError(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	calls := 0
	var body struct {
		NodeID   string                   `json:"node_id"`
		Snapshot model.ProxyUsageSnapshot `json:"snapshot"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/api/agent/proxy-usage" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	err := reportProxyUsage(agentConfig{
		Server:         "http://lattice.test",
		NodeID:         "node-a",
		Token:          "node-secret",
		ProxyUsageFile: filepath.Join(t.TempDir(), "missing.json"),
	})
	if err == nil {
		t.Fatal("expected local collector error to remain visible")
	}
	if calls != 1 {
		t.Fatalf("expected one collector health report, got %d", calls)
	}
	if body.Snapshot.CollectorSource != "file" || body.Snapshot.CollectorStatus != model.ProxyUsageCollectorStatusError {
		t.Fatalf("collector error health missing: %+v", body.Snapshot)
	}
	if body.Snapshot.CollectorError == "" || body.Snapshot.CollectorCheckedAt.IsZero() {
		t.Fatalf("collector error details missing: %+v", body.Snapshot)
	}
	if len(body.Snapshot.UserBytes) != 0 {
		t.Fatalf("error health report must not include usage counters: %+v", body.Snapshot.UserBytes)
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

func TestValidateProxyUsageConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     agentConfig
		wantErr bool
	}{
		{
			name:    "none ok",
			cfg:     agentConfig{},
			wantErr: false,
		},
		{
			name:    "file ok",
			cfg:     agentConfig{ProxyUsageFile: "/run/lattice/proxy-usage.json"},
			wantErr: false,
		},
		{
			name:    "loopback url ok",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: false,
		},
		{
			name:    "file and url conflict",
			cfg:     agentConfig{ProxyUsageFile: "/run/lattice/proxy-usage.json", ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: true,
		},
		{
			name:    "remote url refused",
			cfg:     agentConfig{ProxyUsageURL: "http://example.com/stats"},
			wantErr: true,
		},
		{
			name:    "secret without url refused",
			cfg:     agentConfig{ProxyUsageSecret: "local-secret"},
			wantErr: true,
		},
		{
			name:    "secret file without url refused",
			cfg:     agentConfig{ProxyUsageSecretFile: "/run/lattice/proxy-usage.secret"},
			wantErr: true,
		},
		{
			name:    "secret and secret file conflict",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats", ProxyUsageSecret: "local-secret", ProxyUsageSecretFile: "/run/lattice/proxy-usage.secret"},
			wantErr: true,
		},
		{
			name:    "negative timeout refused",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats", ProxyUsageTimeout: -time.Second},
			wantErr: true,
		},
		{
			name:    "xray api loopback ok",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085"},
			wantErr: false,
		},
		{
			name:    "xray api remote refused",
			cfg:     agentConfig{ProxyUsageXrayAPI: "10.0.0.1:10085"},
			wantErr: true,
		},
		{
			name:    "xray and url conflict",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085", ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: true,
		},
		{
			name:    "xray bin without api refused",
			cfg:     agentConfig{ProxyUsageXrayBin: "/usr/local/bin/xray"},
			wantErr: true,
		},
		{
			name:    "xray unsafe binary refused",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085", ProxyUsageXrayBin: "xray; reboot"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateProxyUsageConfig(c.cfg)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateProxyUsageConfig() err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestResolveProxyUsageSecret(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "proxy-usage.secret")
	if err := os.WriteFile(secretFile, []byte(" local-secret \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := agentConfig{ProxyUsageSecretFile: secretFile}
	if err := resolveProxyUsageSecret(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyUsageSecret != "local-secret" {
		t.Fatalf("unexpected secret %q", cfg.ProxyUsageSecret)
	}
	if cfg.ProxyUsageSecretFile != "" {
		t.Fatalf("resolved secret file path must be cleared before validation, got %q", cfg.ProxyUsageSecretFile)
	}
	cfg.ProxyUsageURL = "http://127.0.0.1:9090/stats"
	if err := validateProxyUsageConfig(cfg); err != nil {
		t.Fatalf("resolved secret-file config should validate: %v", err)
	}
}

func TestResolveProxyUsageSecretRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(emptyFile, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	largeFile := filepath.Join(dir, "large.secret")
	if err := os.WriteFile(largeFile, bytes.Repeat([]byte("x"), 4097), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []agentConfig{
		{ProxyUsageSecret: "already-set", ProxyUsageSecretFile: emptyFile},
		{ProxyUsageSecretFile: emptyFile},
		{ProxyUsageSecretFile: largeFile},
		{ProxyUsageSecretFile: filepath.Join(dir, "missing.secret")},
	}
	for _, cfg := range cases {
		if err := resolveProxyUsageSecret(&cfg); err == nil {
			t.Fatalf("resolveProxyUsageSecret(%+v) expected error", cfg)
		}
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
		Host: "LATTICE.Example.COM.", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		if host != "lattice.example.com" {
			t.Fatalf("host not normalized before resolution: %q", host)
		}
		return []string{"203.0.113.10", "2001:db8::1", "198.51.100.2", "2001:db8::2", "203.0.113.10"}, nil
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
		{"flush", "set", "inet", "lattice_policy", "lattice_control6"},
		{"add", "element", "inet", "lattice_policy", "lattice_control6", "{ 2001:db8::1, 2001:db8::2 }"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected nft argv:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestNFTDomainSetUpdateAllowsMissingIPv6WhenIPv4Exists(t *testing.T) {
	var commands [][]string
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"flush", "set", "inet", "lattice_policy", "lattice_control4"},
		{"add", "element", "inet", "lattice_policy", "lattice_control4", "{ 203.0.113.10 }"},
		{"flush", "set", "inet", "lattice_policy", "lattice_control6"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected nft argv:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestNFTDomainSetUpdateRejectsNoIPv4ForLegacySetOnly(t *testing.T) {
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

func TestNFTDomainSetUpdateRejectsNoRequestedRecords(t *testing.T) {
	called := false
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"not-an-ip"}, nil
	}, func(ctx context.Context, args ...string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("expected no-record failure before nft commands, err=%v called=%v", err, called)
	}
}

func TestNFTDomainSetUpdateRejectsUnsafeIdentifiers(t *testing.T) {
	cases := []nftDomainSetConfig{
		{Host: "bad host", Family: "inet", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet;reboot", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice-policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice/control4"},
		{Host: "lattice.example.com", Family: "ip", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6"},
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

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %q", want, err.Error())
	}
}

func requireErrorNotContains(t *testing.T, err error, unwanted string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if strings.Contains(err.Error(), unwanted) {
		t.Fatalf("expected error not to contain %q, got %q", unwanted, err.Error())
	}
}
