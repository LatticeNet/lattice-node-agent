package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/sessionasm"
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
	// Never the machine's own sing-box config or secret.
	c.configPath = filepath.Join(t.TempDir(), "absent-config.json")
	c.fallbackSecretPath = filepath.Join(t.TempDir(), "absent.secret")
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

// A budget-only policy change must reach the running stream's guard, which is
// what applies the parsed-line budget per line, without replacing the guard
// (its shed marks have to outlive the change). A budget of 0 is what a server
// sends for "the agent default", which is 5,000 parsed lines a second.
func TestBudgetChangeTakesEffectWithoutRebuildingTheStream(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	cfg.Policy.BudgetLinesPerSec = 100
	c.applyConfig(ctx, cfg)
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	first, guard := c.budget, c.guard
	c.mu.Unlock()
	if first != 100 || guard == nil || guard.Budget() != 100 {
		t.Fatalf("budget = %d, guard %v, want 100 on both", first, guard)
	}

	cfg.Policy.BudgetLinesPerSec = 7
	c.applyConfig(ctx, cfg)
	c.mu.Lock()
	second, sameGuard := c.budget, c.guard == guard
	c.mu.Unlock()
	if second != 7 || guard.Budget() != 7 {
		t.Fatalf("budget stayed %d (guard %d) after a budget-only policy change; the control is inert", second, guard.Budget())
	}
	if !sameGuard {
		t.Fatal("a budget change replaced the guard and forgot its shed marks")
	}

	cfg.Policy.BudgetLinesPerSec = 0
	c.applyConfig(ctx, cfg)
	if got := guard.Budget(); got != defaultTraceBudgetLines || defaultTraceBudgetLines != 5000 {
		t.Fatalf("budget 0 applied as %d, want the agent default of 5000", got)
	}
}

// A transport gap is not a restart, and a restart is caught even if the stream
// never noticed it.
//
// Reachability was the old signal: a two second API stall closed every healthy
// connection as core_restart, and a restart that came back before the probe ran
// was missed entirely. Cumulative totals are monotonic within one sing-box
// process, so a decrease is a different process answering. That is the identity
// evidence the close-reason contract needs.
func TestRestartIsDetectedFromProcessIdentityNotReachability(t *testing.T) {
	c := newTraceCollector(agentConfig{Server: "http://127.0.0.1:1", NodeID: "n1", Token: "t"})
	asm := sessionasm.New(sessionasm.Options{NodeID: "n1", CoreGeneration: 1})

	// Totals climbing: same process, no restart.
	for _, tot := range []struct{ up, down int64 }{{10, 20}, {30, 60}, {31, 61}} {
		c.mu.Lock()
		regressed := c.sawTotals && (tot.up < c.lastUpload || tot.down < c.lastDownload)
		c.lastUpload, c.lastDownload, c.sawTotals = tot.up, tot.down, true
		c.mu.Unlock()
		if regressed {
			t.Fatalf("climbing totals reported a restart at %+v", tot)
		}
	}

	// An observation gap alone must not sweep anything.
	c.mu.Lock()
	c.observationGaps++
	gen := c.generation
	c.mu.Unlock()
	if gen != 1 {
		t.Fatalf("an observation gap changed the generation to %d", gen)
	}

	// Totals reset: a new process is answering.
	c.mu.Lock()
	regressed := c.sawTotals && (int64(5) < c.lastUpload || int64(5) < c.lastDownload)
	c.lastUpload, c.lastDownload = 5, 5
	c.mu.Unlock()
	if !regressed {
		t.Fatal("a totals reset was not recognised as a new process")
	}
	c.noteCoreRestart(asm, nil)
	c.mu.Lock()
	after := c.generation
	c.mu.Unlock()
	if after != 2 {
		t.Fatalf("generation = %d after a real restart, want 2", after)
	}
}

// A session expires on the agent even when the control plane is gone.
//
// The agent-side TTL is the whole point of the deadline: a capture must stop
// even if the server disappears mid-capture, which is exactly when the privacy
// boundary matters. Rebuilding the set only on a successful config fetch left
// an expired session running and tagging indefinitely during an outage.
func TestSessionExpiresLocallyWithoutTheServer(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	now := time.Now().UTC()
	cfg.Policy.Level = model.TraceLevelInfo
	cfg.ServerTime = now
	cfg.Sessions = []model.TraceAgentSession{{
		ID:        "sess-expiring",
		Level:     model.TraceLevelTrace,
		ExpiresAt: now.Add(2 * time.Second),
	}}
	c.applyConfig(ctx, cfg)
	time.Sleep(120 * time.Millisecond)

	c.mu.Lock()
	during := c.policy.SubscribeLevel()
	c.mu.Unlock()
	if during != model.TraceLevelTrace {
		t.Fatalf("subscription level during the session = %q, want trace", during)
	}

	// No further config fetch will succeed: the server is gone. The agent must
	// still let the session lapse.
	c.expireSessionsLocally(now.Add(5 * time.Second))

	c.mu.Lock()
	after := c.policy.SubscribeLevel()
	active := len(c.policy.ActiveSessions())
	c.mu.Unlock()
	if active != 0 {
		t.Fatalf("%d sessions still active past their deadline with the server unreachable", active)
	}
	if after != model.TraceLevelInfo {
		t.Fatalf("subscription stayed at %q after expiry; it must fall back to the node floor", after)
	}
}

// --- Design 26 R1: discovery, collector status, the raw switch, shedding ---

// countingClashAPI is a fake Clash API that counts every request it gets and,
// when secret is non-empty, answers 401 to any other bearer token. /logs
// writes lines once and then holds the stream open, as sing-box does.
type countingClashAPI struct {
	srv      *httptest.Server
	requests atomic.Int64
}

func newCountingClashAPI(t *testing.T, secret string, lines []string) *countingClashAPI {
	t.Helper()
	api := &countingClashAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": []any{}, "uploadTotal": 0, "downloadTotal": 0})
	})
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		for _, l := range lines {
			_, _ = fmt.Fprintln(w, l)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.requests.Add(1)
		if secret != "" && r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(api.srv.Close)
	return api
}

func (a *countingClashAPI) addr() string { return a.srv.Listener.Addr().String() }

// writeSingBoxConfig writes a sing-box config with the given clash_api object,
// or none when clashAPI is nil, and returns its path.
func writeSingBoxConfig(t *testing.T, clashAPI map[string]any) string {
	t.Helper()
	cfg := map[string]any{"log": map[string]any{"level": "info"}}
	if clashAPI != nil {
		cfg["experimental"] = map[string]any{"clash_api": clashAPI}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// discoveryCollector is a collector reading the given config, with a policy
// that is on and names no Clash API address and no secret path.
func discoveryCollector(t *testing.T, configPath string) (*traceCollector, model.TraceAgentConfig) {
	t.Helper()
	c := newTraceCollector(agentConfig{Server: "http://127.0.0.1:1", NodeID: "node-a", Token: "tok"})
	c.configPath = configPath
	c.fallbackSecretPath = filepath.Join(t.TempDir(), "absent.secret")
	return c, model.TraceAgentConfig{
		Policy:     model.TracePolicy{NodeID: "node-a", Enabled: true, Level: model.TraceLevelInfo},
		ServerTime: time.Now().UTC(),
	}
}

func collectorState(c *traceCollector) model.CollectorState {
	if st := c.Status(); st != nil {
		return st.State
	}
	return ""
}

func waitForState(t *testing.T, c *traceCollector, want model.CollectorState) *model.CollectorStatus {
	t.Helper()
	waitFor(t, "collector state "+string(want), func() bool { return collectorState(c) == want })
	return c.Status()
}

// Acceptance 1, agent side: a node switched on with no Clash API anywhere says
// so, names where it looked, and starts nothing.
func TestEnabledWithoutAnyClashAPIReportsNoClashAPI(t *testing.T) {
	path := writeSingBoxConfig(t, nil)
	c, cfg := discoveryCollector(t, path)
	if st := c.Status(); st != nil {
		t.Fatalf("status before any policy = %+v, want none", st)
	}
	c.applyConfig(context.Background(), cfg)
	defer c.stop()

	st := c.Status()
	if st == nil || st.State != model.CollectorNoClashAPI {
		t.Fatalf("status = %+v, want no_clash_api", st)
	}
	// A pipeline whose stream has not answered yet has decided nothing either.
	pending := newTraceCollector(agentConfig{Server: "http://127.0.0.1:1", NodeID: "node-a", Token: "tok"})
	pending.mu.Lock()
	pending.runCancel = func() {}
	pending.mu.Unlock()
	pending.evaluateStream()
	if got := pending.Status(); got != nil {
		t.Fatalf("status before the stream answered = %+v, want none", got)
	}
	if !strings.Contains(st.Detail, path) || !strings.Contains(st.Detail, "no experimental.clash_api") {
		t.Fatalf("detail %q does not say what is missing and where", st.Detail)
	}
	if st.ClashAPIAddr != "" || st.AddrSource != "" || st.RawLines || st.Since.IsZero() {
		t.Fatalf("status = %+v, want no address, no raw lines, a since", st)
	}
	if st.BudgetLinesPerSec != defaultTraceBudgetLines || st.CountersSince.IsZero() {
		t.Fatalf("status = %+v, want the default budget and counters_since", st)
	}
	c.mu.Lock()
	running := c.runCancel != nil || c.asm != nil || c.client != nil
	c.mu.Unlock()
	if running {
		t.Fatal("a pipeline was started with no Clash API to read")
	}
}

// With no address in the policy, the controller in the node's sing-box config
// is used, with the secret from the same config.
func TestDiscoveryUsesTheConfigControllerWhenThePolicyHasNone(t *testing.T) {
	api := newCountingClashAPI(t, "cfg-secret", nil)
	path := writeSingBoxConfig(t, map[string]any{"external_controller": api.addr(), "secret": "cfg-secret"})
	c, cfg := discoveryCollector(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorReady)
	if st.AddrSource != model.ClashAddrFromConfig || st.ClashAPIAddr != api.addr() {
		t.Fatalf("status = %+v, want %s from the config", st, api.addr())
	}
	if st.Level != model.TraceLevelInfo || st.Detail != "" {
		t.Fatalf("ready status = %+v, want level info and no detail", st)
	}
}

// Discovery refuses a controller that is not loopback by the client's own
// rule, and never dials it.
func TestDiscoveryRefusesANonLoopbackController(t *testing.T) {
	api := newCountingClashAPI(t, "", nil)
	_, port, err := net.SplitHostPort(api.addr())
	if err != nil {
		t.Fatal(err)
	}
	for _, ctrl := range []string{"0.0.0.0:" + port, ":" + port, "http://127.0.0.1:" + port} {
		path := writeSingBoxConfig(t, map[string]any{"external_controller": ctrl})
		c, cfg := discoveryCollector(t, path)
		c.applyConfig(context.Background(), cfg)
		st := c.Status()
		c.stop()
		if st.State != model.CollectorNoClashAPI || !strings.Contains(st.Detail, "not a loopback") {
			t.Fatalf("controller %q: status = %+v, want no_clash_api naming the loopback rule", ctrl, st)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := api.requests.Load(); n != 0 {
		t.Fatalf("the fake Clash API saw %d requests; a refused controller was dialled", n)
	}
}

// An explicit policy address wins over whatever the config says.
func TestPolicyAddressWinsOverTheConfig(t *testing.T) {
	inPolicy := newCountingClashAPI(t, "", nil)
	inConfig := newCountingClashAPI(t, "", nil)
	path := writeSingBoxConfig(t, map[string]any{"external_controller": inConfig.addr()})
	c, cfg := discoveryCollector(t, path)
	cfg.Policy.ClashAPIAddr = inPolicy.addr()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorReady)
	if st.AddrSource != model.ClashAddrFromPolicy || st.ClashAPIAddr != inPolicy.addr() {
		t.Fatalf("status = %+v, want the policy address", st)
	}
	if n := inConfig.requests.Load(); n != 0 {
		t.Fatalf("the config's controller saw %d requests although the policy named another", n)
	}
}

// `sb api on` writes the controller into the config. The next poll notices it
// without the agent restarting.
func TestDiscoveryNoticesApiOnWithoutARestart(t *testing.T) {
	api := newCountingClashAPI(t, "", nil)
	path := writeSingBoxConfig(t, nil)
	c, cfg := discoveryCollector(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	if got := collectorState(c); got != model.CollectorNoClashAPI {
		t.Fatalf("state = %q before api on, want no_clash_api", got)
	}
	data, _ := json.Marshal(map[string]any{"experimental": map[string]any{"clash_api": map[string]any{"external_controller": api.addr()}}})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorReady)
	if st.AddrSource != model.ClashAddrFromConfig {
		t.Fatalf("status = %+v, want the discovered address", st)
	}
}

// An address exists but the bearer secret cannot be read.
func TestUnreadableSecretReportsSecretUnreadable(t *testing.T) {
	api := newCountingClashAPI(t, "", nil)
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	cfg.Policy.ClashAPIAddr = api.addr()
	cfg.Policy.SecretPath = t.TempDir() // a directory: present, and unreadable as a file
	c.applyConfig(context.Background(), cfg)
	defer c.stop()

	st := c.Status()
	if st.State != model.CollectorSecretUnreadable || st.ClashAPIAddr != api.addr() || st.AddrSource != model.ClashAddrFromPolicy {
		t.Fatalf("status = %+v, want secret_unreadable for the policy address", st)
	}
	if !strings.Contains(st.Detail, "secret") {
		t.Fatalf("detail %q does not say the secret is the problem", st.Detail)
	}
}

// A Clash API that refuses the subscription from the start is a fault, and is
// reported at once rather than after the grace.
func TestStreamThatNeverOpensReportsStreamFailing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": []any{}})
	})
	api := httptest.NewServer(mux)
	defer api.Close()
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorStreamFailing)
	if !strings.Contains(st.Detail, "503") || st.Level != "" {
		t.Fatalf("status = %+v, want the 503 in the detail and no level", st)
	}
}

// A stream that drops after it was up (a sing-box restart) stays ready inside
// the grace and turns stream_failing once the grace has passed. The clock is
// injected, so no test sleeps fifteen seconds.
func TestBriefStreamDropStaysReadyInsideTheGrace(t *testing.T) {
	clock := newFakeClock()
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	c.now = clock.now
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	c.mu.Lock()
	epoch := c.streamEpoch
	c.mu.Unlock()

	c.noteStreamError(epoch, errors.New("singboxapi: log stream closed by peer"))
	clock.advance(traceStreamGrace - time.Second)
	c.evaluateStream()
	if got := collectorState(c); got != model.CollectorReady {
		t.Fatalf("state = %q inside the grace, want ready", got)
	}
	// Back before the grace ran out: still ready, and the clock restarts.
	c.noteStreamOpen(epoch)
	c.noteStreamError(epoch, errors.New("singboxapi: log stream closed by peer"))
	clock.advance(traceStreamGrace - time.Second)
	c.evaluateStream()
	if got := collectorState(c); got != model.CollectorReady {
		t.Fatalf("state = %q, want ready: the grace restarts after the stream came back", got)
	}
	clock.advance(time.Second)
	c.evaluateStream()
	st := c.Status()
	if st.State != model.CollectorStreamFailing || !strings.Contains(st.Detail, "closed by peer") {
		t.Fatalf("status = %+v past the grace, want stream_failing with the cause", st)
	}
	if !st.Since.Equal(clock.now()) {
		t.Fatalf("since = %s, want the moment the state changed (%s)", st.Since, clock.now())
	}
	// A hook of a replaced subscription moves nothing.
	c.noteStreamOpen(epoch + 100)
	if got := collectorState(c); got != model.CollectorStreamFailing {
		t.Fatalf("a stale subscription's Open moved the state to %q", got)
	}
}

// The beat is nudged once per state change, not once per poll.
func TestStateChangeCallsOnStateChangeOncePerChange(t *testing.T) {
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	var calls atomic.Int32
	c.setOnStateChange(func() { calls.Add(1) })
	for i := 0; i < 10; i++ {
		c.applyConfig(context.Background(), cfg)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("ten polls in no_clash_api called onStateChange %d times, want 1", n)
	}
	before := c.Status().Since
	cfg.Policy.Enabled = false
	c.applyConfig(context.Background(), cfg)
	c.applyConfig(context.Background(), cfg)
	if n := calls.Load(); n != 2 {
		t.Fatalf("turning off called onStateChange %d times in total, want 2", n)
	}
	if st := c.Status(); st.State != model.CollectorOff || st.Detail != "" || st.Since.Before(before) {
		t.Fatalf("status = %+v, want off with no detail", st)
	}
}

// A wrong secret is refused with 401. The detail says so and never carries
// the secret, here or anywhere in the status.
func TestStatusDetailNeverCarriesTheSecret(t *testing.T) {
	const wrong = "wrong-s3cret-9f8e7d6c"
	api := newCountingClashAPI(t, "the-right-one", nil)
	secretPath := filepath.Join(t.TempDir(), "clash.secret")
	if err := os.WriteFile(secretPath, []byte(wrong+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	cfg.Policy.ClashAPIAddr = api.addr()
	cfg.Policy.SecretPath = secretPath
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorStreamFailing)
	if !strings.Contains(st.Detail, "401") {
		t.Fatalf("detail %q does not name the 401", st.Detail)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), wrong) || strings.Contains(string(data), "the-right-one") {
		t.Fatalf("the status carries a secret: %s", data)
	}
	if len(st.Detail) > model.CollectorDetailMaxBytes || strings.ContainsAny(st.Detail, "\r\n") {
		t.Fatalf("detail is not one bounded line: %q", st.Detail)
	}
}

// fakeControlPlane counts what the collector ships: trace batches (and the
// records in them) and raw log batches.
type fakeControlPlane struct {
	srv         *httptest.Server
	traceBodies atomic.Int64
	records     atomic.Int64
	logBodies   atomic.Int64
	mu          sync.Mutex
	logSources  []string
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	t.Helper()
	cp := &fakeControlPlane{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/trace", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Batch model.TraceBatch `json:"batch"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		cp.traceBodies.Add(1)
		cp.records.Add(int64(len(body.Batch.Records)))
	})
	mux.HandleFunc("/api/agent/logs", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Batch model.LogBatch `json:"batch"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		cp.logBodies.Add(1)
		cp.mu.Lock()
		cp.logSources = append(cp.logSources, body.Batch.SourceID)
		cp.mu.Unlock()
	})
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

// oneConnection is a complete connection as sing-box 1.13 prints it
// (internal/singboxlog/testdata/v1.13.14/entry_nosniff.jsonl).
var oneConnection = []string{
	`{"type":"info","payload":"[2064424212 0ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62010"}`,
	`{"type":"info","payload":"[2064424212 3ms] inbound/mixed[mixed-entry]: inbound connection to 127.0.0.1:18081"}`,
	`{"type":"debug","payload":"[2064424212 4ms] router: match[0] inbound=mixed-entry => route(chain-to-exit)"}`,
	`{"type":"info","payload":"[2064424212 5ms] outbound/vless[chain-to-exit]: outbound connection to 127.0.0.1:18081"}`,
	`{"type":"debug","payload":"[2064424212 11ms] connection: connection download finished"}`,
	`{"type":"trace","payload":"[2064424212 11ms] connection: connection upload closed"}`,
	`{"type":"debug","payload":"[2064424212 11ms] inbound/mixed[mixed-entry]: connection closed: read http request: EOF"}`,
}

// rawSwitchRun runs a collector with records on against a fake Clash API that
// prints one whole connection, and returns the control plane once a record has
// arrived and flushCycles more assembler ticks have passed.
func rawSwitchRun(t *testing.T, raw *model.RawLinePolicy, flushCycles int) *fakeControlPlane {
	t.Helper()
	api := newCountingClashAPI(t, "", oneConnection)
	cp := newFakeControlPlane(t)
	c := newTraceCollector(agentConfig{Server: cp.srv.URL, NodeID: "node-a", Token: "tok"})
	c.configPath = writeSingBoxConfig(t, map[string]any{"external_controller": api.addr()})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, model.TraceAgentConfig{
		Policy:      model.TracePolicy{NodeID: "node-a", Enabled: true, Level: model.TraceLevelTrace, Raw: raw},
		RawSourceID: "src-singbox-node-a",
		ServerTime:  time.Now().UTC(),
	})
	waitFor(t, "a record to reach the control plane", func() bool { return cp.records.Load() > 0 })
	time.Sleep(time.Duration(flushCycles)*traceAssemblerTick + 200*time.Millisecond)
	return cp
}

// Acceptance 2, agent side: records on and raw off ships records and zero raw
// lines, even though the server named a raw source (an a117 server does
// whenever records are on).
func TestRecordsOnRawOffShipsZeroRawLines(t *testing.T) {
	cp := rawSwitchRun(t, &model.RawLinePolicy{Enabled: false}, 3)
	if n := cp.logBodies.Load(); n != 0 {
		t.Fatalf("%d /api/agent/logs requests with raw off, want 0", n)
	}
	if cp.records.Load() == 0 {
		t.Fatal("no records shipped; records must flow while raw is off")
	}
}

// A policy written before the switch (nil Raw) keeps today's behaviour: raw
// lines follow RawSourceID.
func TestRawFollowsRawSourceIDWhenThePolicyPredatesTheSwitch(t *testing.T) {
	cp := rawSwitchRun(t, nil, 1)
	waitFor(t, "raw lines to ship", func() bool { return cp.logBodies.Load() > 0 })
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.logSources[0] != "src-singbox-node-a" {
		t.Fatalf("raw lines went to %q, want the named source", cp.logSources[0])
	}
}

// Raw lines queued while raw was on are discarded when it turns off, so none
// of them ships on a later flush.
func TestRawOffDiscardsTheQueuedRawLines(t *testing.T) {
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	cfg.RawSourceID = "src-singbox-node-a"
	c.applyConfig(context.Background(), cfg)
	c.mu.Lock()
	if c.rawSourceID != "src-singbox-node-a" {
		c.mu.Unlock()
		t.Fatalf("raw source = %q with a nil switch, want the named source", c.rawSourceID)
	}
	c.rawQueue = []string{"line one", "line two"}
	c.rawDropped = 3
	c.mu.Unlock()

	cfg.Policy.Raw = &model.RawLinePolicy{Enabled: false}
	c.applyConfig(context.Background(), cfg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rawSourceID != "" || len(c.rawQueue) != 0 || c.rawDropped != 0 {
		t.Fatalf("after raw off: source %q, %d queued, %d dropped; want all empty", c.rawSourceID, len(c.rawQueue), c.rawDropped)
	}
}

// Local session expiry rebuilds the policy set from Enabled and Level only. The
// raw switch lives on the collector, so expiry cannot turn raw lines back on.
func TestRawSwitchSurvivesLocalSessionExpiry(t *testing.T) {
	api := fakeClashAPI(t)
	c, cfg := traceTestCollector(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	now := time.Now().UTC()
	cfg.ServerTime = now
	cfg.RawSourceID = "src-singbox-node-a"
	cfg.Policy.Raw = &model.RawLinePolicy{Enabled: false}
	cfg.Sessions = []model.TraceAgentSession{{ID: "sess-1", Level: model.TraceLevelTrace, ExpiresAt: now.Add(time.Second)}}
	c.applyConfig(ctx, cfg)
	c.expireSessionsLocally(now.Add(5 * time.Second))

	c.mu.Lock()
	src, active := c.rawSourceID, len(c.policy.ActiveSessions())
	c.mu.Unlock()
	if active != 0 {
		t.Fatalf("%d sessions still active after expiry", active)
	}
	if src != "" {
		t.Fatalf("raw source %q after local expiry; the raw switch was lost", src)
	}
	if st := waitForState(t, c, model.CollectorReady); st.RawLines {
		t.Fatal("status reports raw lines after local expiry with raw off")
	}
}

// --- Review of design 26 R1: transient discovery, hardened reads, rotation ---

// switchableClashAPI is a fake Clash API whose secret can rotate and whose
// /logs can hang before answering. rotate also drops every open /logs
// stream, the way a sing-box restart does.
type switchableClashAPI struct {
	srv    *httptest.Server
	secret atomic.Pointer[string]
	hang   atomic.Bool
	mu     sync.Mutex
	kick   chan struct{}
}

func newSwitchableClashAPI(t *testing.T, secret string) *switchableClashAPI {
	t.Helper()
	a := &switchableClashAPI{kick: make(chan struct{})}
	a.secret.Store(&secret)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := *a.secret.Load(); want != "" && r.Header.Get("Authorization") != "Bearer "+want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{"connections": []any{}, "uploadTotal": 0, "downloadTotal": 0})
		case "/logs":
			if a.hang.Load() {
				<-r.Context().Done() // accepted, never answered
				return
			}
			a.mu.Lock()
			kick := a.kick
			a.mu.Unlock()
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-kick:
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *switchableClashAPI) addr() string { return a.srv.Listener.Addr().String() }

func (a *switchableClashAPI) rotate(secret string) {
	a.secret.Store(&secret)
	a.mu.Lock()
	close(a.kick)
	a.kick = make(chan struct{})
	a.mu.Unlock()
}

func pipelineParts(c *traceCollector) (*sessionasm.Assembler, bool, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asm, c.runCancel != nil, c.streamEpoch
}

// A config that is momentarily empty or half written while the collector is
// recording is not an answer. The pipeline and the connection it is
// assembling stay; three failed reads in a row say no_clash_api while the
// stream keeps running; a good read is ready again; and only a config that
// was read and has no Clash API stops the pipeline.
func TestTransientConfigFailureKeepsThePipelineAndItsOpenConnections(t *testing.T) {
	api := newCountingClashAPI(t, "", nil)
	path := writeSingBoxConfig(t, map[string]any{"external_controller": api.addr()})
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, cfg := discoveryCollector(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	asm, _, _ := pipelineParts(c)
	asm.Line(singboxlog.Line{
		At: time.Now().UTC(), Level: "info", HasLogID: true, LogID: 4242,
		TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "in",
		Event: singboxlog.EventInboundFrom, SrcIP: "10.0.0.5", SrcPort: 1234,
	})

	for i, content := range []string{"", `{"experimental":{"clash_api":{"external_contr`} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c.applyConfig(ctx, cfg)
		gotAsm, up, _ := pipelineParts(c)
		if !up || gotAsm != asm {
			t.Fatalf("read %d of a partial config tore the pipeline down", i+1)
		}
		if got := asm.Stats().Open; got != 1 {
			t.Fatalf("read %d of a partial config lost the open connection: %d open", i+1, got)
		}
		if got := collectorState(c); got != model.CollectorReady {
			t.Fatalf("read %d of a partial config moved the state to %q, want ready inside the limit", i+1, got)
		}
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	st := c.Status()
	if st.State != model.CollectorNoClashAPI || !strings.Contains(st.Detail, "cannot be parsed as JSON") || !strings.Contains(st.Detail, "keeps running") {
		t.Fatalf("status after %d failed reads = %+v, want no_clash_api saying the stream keeps running", traceDiscoveryFailLimit, st)
	}
	if gotAsm, up, _ := pipelineParts(c); !up || gotAsm != asm || asm.Stats().Open != 1 {
		t.Fatal("the pipeline or its open connection did not survive the failure limit")
	}

	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	if got := collectorState(c); got != model.CollectorReady {
		t.Fatalf("state after a good read = %q, want ready", got)
	}
	if gotAsm, _, _ := pipelineParts(c); gotAsm != asm {
		t.Fatal("a good read rebuilt the pipeline")
	}

	// A config that was read and has no Clash API is an answer.
	if err := os.WriteFile(path, []byte(`{"log":{"level":"info"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	if _, up, _ := pipelineParts(c); up {
		t.Fatal("the pipeline survived `sb api off`")
	}
	if st := c.Status(); st.State != model.CollectorNoClashAPI || !strings.Contains(st.Detail, "no experimental.clash_api") {
		t.Fatalf("status after api off = %+v", st)
	}
}

// readNodeFile refuses every file that should not gate a bearer token, with a
// detail that names the path and the reason, and never blocks.
func TestNodeFileReadRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	good := write("good", []byte("s3cret\n"), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		path   string
		secret bool
		want   string // empty means accepted
	}{
		{"regular 0600 secret", good, true, ""},
		{"fifo", fifo, true, "is not a regular file"},
		{"directory", dir, false, "is not a regular file"},
		{"symlink", link, true, "is a symlink"},
		{"oversized", write("big", make([]byte, nodeFileMaxBytes+1), 0o600), false, "is larger than 1 MiB"},
		{"exactly the cap", write("cap", make([]byte, nodeFileMaxBytes), 0o600), false, ""},
		{"group-writable secret", write("gw", []byte("s"), 0o620), true, "is writable by group or others"},
		{"world-writable config", write("ww", []byte("{}"), 0o602), false, "is writable by group or others"},
		{"group-readable secret", write("gr", []byte("s"), 0o640), true, "is readable by group or others"},
		{"group-readable config", write("grc", []byte("{}"), 0o644), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type result struct {
				err error
			}
			done := make(chan result, 1)
			go func() {
				_, err := readNodeFile(tc.path, tc.secret)
				done <- result{err}
			}()
			var res result
			select {
			case res = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("readNodeFile blocked")
			}
			if tc.want == "" {
				if res.err != nil {
					t.Fatalf("refused: %v", res.err)
				}
				return
			}
			if res.err == nil || !strings.Contains(res.err.Error(), tc.want) || !strings.Contains(res.err.Error(), tc.path) {
				t.Fatalf("err = %v, want %q naming %s", res.err, tc.want, tc.path)
			}
		})
	}
}

// Through the collector: an unsafe secret or config is reported in the
// status, and applyConfig, which runs on the work loop, returns at once.
func TestUnsafeSecretOrConfigIsRefusedWithoutBlockingTheWorkLoop(t *testing.T) {
	api := newCountingClashAPI(t, "", nil)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	gw := filepath.Join(dir, "gw.secret")
	if err := os.WriteFile(gw, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gw, 0o660); err != nil {
		t.Fatal(err)
	}
	cfgLink := filepath.Join(dir, "config-link.json")
	if err := os.Symlink(writeSingBoxConfig(t, map[string]any{"external_controller": api.addr()}), cfgLink); err != nil {
		t.Fatal(err)
	}

	apply := func(c *traceCollector, cfg model.TraceAgentConfig) *model.CollectorStatus {
		t.Helper()
		done := make(chan struct{})
		go func() { c.applyConfig(context.Background(), cfg); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("applyConfig blocked on a node file")
		}
		return c.Status()
	}
	for _, tc := range []struct {
		name       string
		secretPath string
		configPath string
		want       model.CollectorState
		detail     string
	}{
		{"fifo secret", fifo, "", model.CollectorSecretUnreadable, "is not a regular file"},
		{"group-writable secret", gw, "", model.CollectorSecretUnreadable, "is writable by group or others"},
		{"fifo config", "", fifo, model.CollectorNoClashAPI, "is not a regular file"},
		{"symlinked config", "", cfgLink, model.CollectorNoClashAPI, "is a symlink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := tc.configPath
			if configPath == "" {
				configPath = writeSingBoxConfig(t, nil)
			}
			c, cfg := discoveryCollector(t, configPath)
			defer c.stop()
			if tc.secretPath != "" {
				cfg.Policy.ClashAPIAddr = api.addr()
				cfg.Policy.SecretPath = tc.secretPath
			}
			st := apply(c, cfg)
			if st.State != tc.want || !strings.Contains(st.Detail, tc.detail) {
				t.Fatalf("status = %+v, want %s with %q", st, tc.want, tc.detail)
			}
			if _, up, _ := pipelineParts(c); up {
				t.Fatal("a pipeline started on a refused file")
			}
		})
	}
}

// A rotated secret: the core restarts with a new one, the stream drops and
// every resubscribe gets 401, and past the grace the node is stream_failing.
// Once the secret file holds the new secret, the next poll hands it to the
// client and resubscribes. The node is ready again with the same assembler:
// no agent restart, no pipeline rebuild.
func TestRotatedSecretRecoversFromStreamFailingWithoutARestart(t *testing.T) {
	clock := newFakeClock()
	api := newSwitchableClashAPI(t, "old-secret")
	secretPath := filepath.Join(t.TempDir(), "clash.secret")
	if err := os.WriteFile(secretPath, []byte("old-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	c.now = clock.now
	cfg.Policy.ClashAPIAddr = api.addr()
	cfg.Policy.SecretPath = secretPath
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	asm, _, _ := pipelineParts(c)

	api.rotate("new-secret")
	waitFor(t, "the stream to drop", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return !c.streamOpen && !c.streamDownSince.IsZero()
	})
	clock.advance(traceStreamGrace)
	c.evaluateStream()
	if got := collectorState(c); got != model.CollectorStreamFailing {
		t.Fatalf("state past the grace with the old secret = %q, want stream_failing", got)
	}
	// A poll before the file changes leaves it failing.
	c.applyConfig(ctx, cfg)
	if got := collectorState(c); got != model.CollectorStreamFailing {
		t.Fatalf("state = %q with the secret unchanged on disk", got)
	}

	if err := os.WriteFile(secretPath, []byte("new-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	if gotAsm, up, _ := pipelineParts(c); !up || gotAsm != asm {
		t.Fatal("recovering from a rotated secret rebuilt the pipeline")
	}
}

// A secret file that changes while the stream is open is left alone: the
// running core still holds the secret in use, so swapping now would break a
// working stream. The subscription is not touched.
func TestChangedSecretLeavesAnOpenStreamAlone(t *testing.T) {
	api := newSwitchableClashAPI(t, "old-secret")
	secretPath := filepath.Join(t.TempDir(), "clash.secret")
	if err := os.WriteFile(secretPath, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	cfg.Policy.ClashAPIAddr = api.addr()
	cfg.Policy.SecretPath = secretPath
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	_, _, epoch := pipelineParts(c)
	if err := os.WriteFile(secretPath, []byte("written-before-the-core-restarts"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.applyConfig(ctx, cfg)
	if _, _, got := pipelineParts(c); got != epoch {
		t.Fatal("a secret change resubscribed an open stream")
	}
	if got := collectorState(c); got != model.CollectorReady {
		t.Fatalf("state = %q, want ready", got)
	}
}

// A config that is not JSON is named, never quoted: the decoder's message
// carries bytes of the file, and the file carries the secret. Checked in the
// discovery detail, the secret_unreadable detail and the log line.
func TestConfigParseErrorNeverQuotesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"experimental":{"clash_api":{"secret":"s"}}} Zq-leak-7731`), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	var logMu sync.Mutex
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}))
	defer log.SetOutput(os.Stderr)

	c, cfg := discoveryCollector(t, path)
	c.applyConfig(context.Background(), cfg)
	want := path + " cannot be parsed as JSON"
	if st := c.Status(); st.State != model.CollectorNoClashAPI || st.Detail != want {
		t.Fatalf("discovery status = %+v, want detail %q", st, want)
	}

	api := newCountingClashAPI(t, "", nil)
	cfg.Policy.ClashAPIAddr = api.addr() // the secret now falls back to the config
	c.applyConfig(context.Background(), cfg)
	defer c.stop()
	st := c.Status()
	if st.State != model.CollectorSecretUnreadable || !strings.HasSuffix(st.Detail, want) {
		t.Fatalf("secret status = %+v, want a detail ending %q", st, want)
	}
	logMu.Lock()
	logged := logs.String()
	logMu.Unlock()
	if !strings.Contains(logged, want) {
		t.Fatalf("log does not name the file: %q", logged)
	}
	for _, s := range []string{st.Detail, logged} {
		if strings.Contains(s, "invalid character") || strings.Contains(s, "'Z'") || strings.Contains(s, "Zq-leak") {
			t.Fatalf("a parse error quoted the file: %q", s)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A resubscribe that the Clash API accepts and never answers must not leave
// ready standing: the first-answer deadline turns it into stream_failing.
func TestHungResubscribeTurnsStreamFailing(t *testing.T) {
	api := newSwitchableClashAPI(t, "")
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	c.streamOpenTimeout = 100 * time.Millisecond
	cfg.Policy.ClashAPIAddr = api.addr()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitForState(t, c, model.CollectorReady)
	api.hang.Store(true)
	cfg.Policy.Level = model.TraceLevelTrace // a level change resubscribes
	c.applyConfig(ctx, cfg)
	st := waitForState(t, c, model.CollectorStreamFailing)
	if !strings.Contains(st.Detail, "no answer within") {
		t.Fatalf("detail = %q, want the first-answer deadline", st.Detail)
	}
}

// LinesPerSec is what sing-box sends, counted before the pre-parse ceiling,
// so a rate measurement is not capped at four times the budget.
func TestLinesPerSecCountsLinesOverTheCeiling(t *testing.T) {
	const n = 200
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf(`{"type":"info","payload":"line %d"}`, i)
	}
	api := newCountingClashAPI(t, "", lines)
	c, cfg := discoveryCollector(t, writeSingBoxConfig(t, nil))
	cfg.Policy.ClashAPIAddr = api.addr()
	cfg.Policy.BudgetLinesPerSec = 1 // a ceiling of 4 lines a second
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.stop() }()

	c.applyConfig(ctx, cfg)
	waitFor(t, "every line in the rate window", func() bool {
		st := c.Status()
		return st != nil && st.LinesPerSec*traceLinesWindow >= n
	})
	if got := c.Status().LinesPerSec * traceLinesWindow; got != n {
		t.Fatalf("lines counted = %v, want %d", got, n)
	}
}
