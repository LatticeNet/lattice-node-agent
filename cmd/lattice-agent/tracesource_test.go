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

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
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
	haveCancel := c.runCancel != nil
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
	running := c.runCancel != nil
	c.mu.Unlock()
	if !running {
		t.Fatal("expected a running subscription")
	}

	cfg.Policy.Enabled = false
	c.applyConfig(ctx, cfg)

	c.mu.Lock()
	stillRunning := c.runCancel != nil
	c.mu.Unlock()
	if stillRunning {
		t.Fatal("a disabled policy must stop collection, not leave it running")
	}
	_ = fmt.Sprint()
}

// A verbosity change must not destroy the pipeline's state.
//
// The assembler holds open connections and the shipper holds queued delivery.
// Rebuilding them on every level change loses pending records with no Dropped
// count and strands open connections, whose later close lines then arrive
// without an opening identity and are suppressed as partial. Starting a capture
// would erase the connection being investigated, which is the opposite of the
// point.
func TestLevelChangeKeepsThePipelineAndItsOpenConnections(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	cfg.Policy.Level = model.TraceLevelInfo
	c.applyConfig(ctx, cfg)
	time.Sleep(120 * time.Millisecond)

	c.mu.Lock()
	asmBefore := c.asm
	shipperBefore := c.shipper
	c.mu.Unlock()
	if asmBefore == nil || shipperBefore == nil {
		t.Fatal("pipeline did not come up")
	}

	// An open connection lives in the assembler.
	asmBefore.Line(singboxlog.Line{
		At: time.Now().UTC(), Level: "info", HasLogID: true, LogID: 4242,
		TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "in",
		Event: singboxlog.EventInboundFrom, SrcIP: "10.0.0.5", SrcPort: 1234,
	})
	if got := asmBefore.Stats().Open; got != 1 {
		t.Fatalf("expected 1 open connection before the level change, got %d", got)
	}

	// Raise the level, which reopens the subscription.
	cfg.Policy.Level = model.TraceLevelTrace
	c.applyConfig(ctx, cfg)
	time.Sleep(120 * time.Millisecond)

	c.mu.Lock()
	asmAfter := c.asm
	shipperAfter := c.shipper
	level := c.haveLevel
	c.mu.Unlock()

	if level != model.TraceLevelTrace {
		t.Fatalf("subscription level = %q, want trace", level)
	}
	if asmAfter != asmBefore {
		t.Fatal("the assembler was replaced by a level change; every open connection went with it")
	}
	if shipperAfter != shipperBefore {
		t.Fatal("the shipper was replaced by a level change; everything queued for delivery went with it")
	}
	if got := asmAfter.Stats().Open; got != 1 {
		t.Fatalf("the open connection did not survive the level change: %d open", got)
	}
}

// A budget-only policy change must reach the running stream.
func TestBudgetChangeTakesEffectWithoutRebuildingTheStream(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	cfg.Policy.BudgetLinesPerSec = 100
	c.applyConfig(ctx, cfg)
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	first := c.budget
	c.mu.Unlock()
	if first != 100 {
		t.Fatalf("budget = %d, want 100", first)
	}

	cfg.Policy.BudgetLinesPerSec = 7
	c.applyConfig(ctx, cfg)
	c.mu.Lock()
	second := c.budget
	c.mu.Unlock()
	if second != 7 {
		t.Fatalf("budget stayed %d after a budget-only policy change; the control is inert", second)
	}
}
