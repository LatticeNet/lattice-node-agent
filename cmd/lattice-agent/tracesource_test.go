package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// fakeClashAPI stands in for sing-box's loopback control endpoint. httptest
// binds 127.0.0.1, which is what the client's loopback check requires.
func fakeClashAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": true, "version": "test"})
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": []any{}, "uploadTotal": 0, "downloadTotal": 0})
	})
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		// Hold the stream open the way sing-box does, until the client leaves.
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func traceTestCollector(t *testing.T, api *httptest.Server) (*traceCollector, model.TraceAgentConfig) {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "clash.secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newTraceCollector(agentConfig{
		Server: "http://127.0.0.1:1",
		NodeID: "node-a",
		Token:  "tok",
	})
	cfg := model.TraceAgentConfig{
		Policy: model.TracePolicy{
			NodeID:            "node-a",
			Enabled:           true,
			Level:             model.TraceLevelInfo,
			BudgetLinesPerSec: 100,
			ClashAPIAddr:      api.Listener.Addr().String(),
			SecretPath:        secret,
		},
		ServerTime: time.Now().UTC(),
	}
	return c, cfg
}

// Repeated level changes must not leak goroutines.
//
// Every level change tears the subscription down and builds a new one, because
// a Clash API log subscription fixes its level when it opens. That happens
// whenever an operator starts or stops a capture, so a leak here would grow for
// as long as the agent runs.
func TestSubscriptionCyclesDoNotLeakGoroutines(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		c.stop()
	}()

	levels := []model.TraceLevel{model.TraceLevelInfo, model.TraceLevelDebug, model.TraceLevelTrace}

	// Warm up so one-off machinery is not counted as a leak.
	for i := 0; i < 3; i++ {
		cfg.Policy.Level = levels[i%len(levels)]
		c.applyConfig(ctx, cfg)
	}
	time.Sleep(150 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 12; i++ {
		cfg.Policy.Level = levels[i%len(levels)]
		c.applyConfig(ctx, cfg)
		time.Sleep(20 * time.Millisecond)
	}
	c.stop()
	time.Sleep(300 * time.Millisecond)

	after := runtime.NumGoroutine()
	// One subscription is four goroutines. Twelve cycles that leaked would add
	// dozens; allow generous slack for the runtime and the test server.
	if after > baseline+8 {
		t.Fatalf("goroutines grew from %d to %d across 12 subscription cycles; a cycle is leaking", baseline, after)
	}
}

// Concurrent applyConfig calls must produce exactly one subscription.
//
// applyConfig checks whether a subscription is running, releases the lock, and
// only then stops and starts one. Without serialisation two callers racing
// through that window both see nothing running, both start, and the second
// overwrites the first's cancel func, stranding its goroutines for good.
func TestConcurrentApplyConfigStartsOneSubscription(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		c.stop()
	}()

	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.applyConfig(ctx, cfg)
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	if after > baseline+8 {
		t.Fatalf("goroutines grew from %d to %d after 8 concurrent applyConfig calls; more than one subscription started", baseline, after)
	}

	c.mu.Lock()
	haveCancel := c.cancel != nil
	c.mu.Unlock()
	if !haveCancel {
		t.Fatal("no subscription is recorded after applyConfig")
	}

	// And stopping once must take everything down.
	c.stop()
	time.Sleep(250 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > baseline+4 {
		t.Fatalf("goroutines still %d after stop (baseline %d); stop did not take the subscription down", n, baseline)
	}
}

func TestApplyConfigDisabledPolicyStopsEverything(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.applyConfig(ctx, cfg)
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	running := c.cancel != nil
	c.mu.Unlock()
	if !running {
		t.Fatal("expected a running subscription")
	}

	cfg.Policy.Enabled = false
	c.applyConfig(ctx, cfg)

	c.mu.Lock()
	stillRunning := c.cancel != nil
	c.mu.Unlock()
	if stillRunning {
		t.Fatal("a disabled policy must stop collection, not leave it running")
	}
	_ = fmt.Sprint()
}
