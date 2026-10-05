package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// The production failure this guards: the heartbeat was the metrics POST
// inside the serial work loop, so a control plane that answered /api/agent/
// config slowly (four 30 s timeouts already exceed the 90 s offline flip)
// made healthy nodes read offline. Here the config fetch hangs, and beats
// keep landing every interval on their own goroutine.
func TestHeartbeatKeepsBeatingWhileConfigFetchHangs(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	release := make(chan struct{})
	var beats atomic.Int32
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/agent/config":
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return testResponse(http.StatusOK, `{}`), nil
		case "/api/agent/metrics":
			beats.Add(1)
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		}
		return testResponse(http.StatusNotFound, "no"), nil
	})}
	cfg := agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret", Interval: 20 * time.Millisecond}
	configDone := make(chan error, 1)
	go func() {
		_, err := fetchAgentConfig(cfg)
		configDone <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newHeartbeat(cfg, newLoopHealth(nil)).start(ctx)
	waitFor(t, "three beats while the config fetch hangs", func() bool { return beats.Load() >= 3 })
	select {
	case err := <-configDone:
		t.Fatalf("config fetch returned while it should hang: %v", err)
	default:
	}
	close(release)
	if err := <-configDone; err != nil {
		t.Fatalf("config fetch after release: %v", err)
	}
}

func TestHeartbeatCarriesLoopHealthAndWithholdsDurableCapabilityWhileRecoveryBlocks(t *testing.T) {
	health := newLoopHealth(nil)
	var got []map[string]any
	beat := newHeartbeat(agentConfig{NodeID: "node-a", Interval: time.Second, LinechainReady: true}, health)
	beat.monitorStats = func() (int, uint64) { return 7, 2 }
	beat.post = func(ctx context.Context, cfg agentConfig, payload map[string]any) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("beat posted without a deadline")
		}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		got = append(got, decoded)
		return nil
	}

	health.setLinechainBlocked(errors.New("journal txn-1 awaits\nauthority"))
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	health.clearLinechainBlocked()
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}

	caps := func(body map[string]any) []string {
		var out []string
		for _, c := range body["capabilities"].([]any) {
			out = append(out, c.(string))
		}
		return out
	}
	if c := caps(got[0]); strings.Contains(strings.Join(c, ","), durableTaskResultCapability) {
		t.Fatalf("blocked beat advertised %s: %v", durableTaskResultCapability, c)
	}
	if c := caps(got[1]); !strings.Contains(strings.Join(c, ","), durableTaskResultCapability) {
		t.Fatalf("recovered beat did not advertise %s: %v", durableTaskResultCapability, c)
	}
	lh, ok := got[0]["loop_health"].(map[string]any)
	if !ok {
		t.Fatalf("beat has no loop_health: %v", got[0])
	}
	if lh["linechain_blocked"] != "journal txn-1 awaits authority" {
		t.Fatalf("linechain_blocked = %q", lh["linechain_blocked"])
	}
	if lh["linechain_blocked_since"] == nil || lh["started_at"] == nil {
		t.Fatalf("loop_health missing timestamps: %v", lh)
	}
	if lh["monitor_results_queued"] != float64(7) || lh["monitor_results_dropped"] != float64(2) {
		t.Fatalf("monitor queue stats = %v / %v", lh["monitor_results_queued"], lh["monitor_results_dropped"])
	}
	if _, ok := got[1]["loop_health"].(map[string]any)["linechain_blocked"]; ok {
		t.Fatalf("cleared recovery still reported: %v", got[1]["loop_health"])
	}
	if got[0]["metrics"] == nil || got[0]["agent_runtime"] == nil || got[0]["version"] != version {
		t.Fatalf("beat lost the metrics body: %v", got[0])
	}
}

func TestLoopHealthRecordsStepOutcomes(t *testing.T) {
	clock := newFakeClock()
	h := newLoopHealth(clock.now)
	h.cycleStart()
	clock.advance(time.Second)
	_ = h.run(stepConfig, func() error { return nil })
	for i := 0; i < 3; i++ {
		clock.advance(time.Second)
		_ = h.run(stepUsage, func() error {
			return errors.New(strings.Repeat("x", 300) + "\x1b[31m")
		})
	}
	clock.advance(2 * time.Second)
	h.cycleEnd()

	snap := h.snapshot()
	if !snap.Steps[stepConfig].LastOKAt.Equal(clock.t.Add(-5*time.Second)) || snap.Steps[stepConfig].ConsecutiveErrors != 0 {
		t.Fatalf("config step = %+v", snap.Steps[stepConfig])
	}
	usage := snap.Steps[stepUsage]
	if usage.ConsecutiveErrors != 3 || !usage.LastOKAt.IsZero() {
		t.Fatalf("usage step = %+v", usage)
	}
	if n := len([]rune(usage.LastError)); n != loopErrorMaxRunes+3 || strings.ContainsRune(usage.LastError, 0x1b) {
		t.Fatalf("usage error not bounded or not cleaned: %d runes %q", n, usage.LastError)
	}
	if snap.CycleDurationMs != 6000 {
		t.Fatalf("cycle duration = %d ms, want 6000", snap.CycleDurationMs)
	}
	_ = h.run(stepUsage, func() error { return nil })
	if st := h.snapshot().Steps[stepUsage]; st.ConsecutiveErrors != 0 || st.LastError != "" || st.LastErrorAt.IsZero() {
		t.Fatalf("usage after recovery = %+v", st)
	}
}

// decodeBeat turns a beat payload into what the server would decode.
func decodeBeat(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestBeatCarriesTraceCollectorStatus(t *testing.T) {
	var got map[string]any
	beat := newHeartbeat(agentConfig{NodeID: "node-a", Interval: time.Second}, newLoopHealth(nil))
	beat.witnessStatus = nil
	beat.post = func(ctx context.Context, cfg agentConfig, payload map[string]any) error {
		got = decodeBeat(t, payload)
		return nil
	}
	since := time.Date(2026, 10, 5, 9, 59, 51, 0, time.UTC)
	beat.setTraceStatus(func() *model.CollectorStatus {
		return &model.CollectorStatus{
			State:             model.CollectorNoClashAPI,
			Since:             since,
			Detail:            "no experimental.clash_api in /etc/sing-box/config.json",
			BudgetLinesPerSec: 5000,
			CountersSince:     since.Add(-time.Hour),
		}
	})
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	tc, ok := got["trace_collector"].(map[string]any)
	if !ok {
		t.Fatalf("beat has no trace_collector: %v", got)
	}
	if tc["state"] != "no_clash_api" || tc["since"] != "2026-10-05T09:59:51Z" || tc["budget_lines_per_sec"] != float64(5000) {
		t.Fatalf("trace_collector = %v", tc)
	}
	if _, ok := tc["raw_lines"]; ok {
		t.Fatalf("raw_lines false should be omitted: %v", tc)
	}
	if got["loop_health"] == nil || got["metrics"] == nil {
		t.Fatalf("the status replaced the rest of the beat: %v", got)
	}
}

// Before the collector exists (the recovery-blocked start beats first), and
// before it has applied a policy, the key is left out rather than sent as a
// placeholder "off" the server would believe.
func TestBeatOmitsTraceCollectorBeforeTheCollectorExists(t *testing.T) {
	var got []map[string]any
	beat := newHeartbeat(agentConfig{NodeID: "node-a", Interval: time.Second}, newLoopHealth(nil))
	beat.witnessStatus = nil
	beat.post = func(ctx context.Context, cfg agentConfig, payload map[string]any) error {
		got = append(got, decodeBeat(t, payload))
		return nil
	}
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := newTraceCollector(agentConfig{NodeID: "node-a"})
	beat.setTraceStatus(c.Status)
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, body := range got {
		if _, ok := body["trace_collector"]; ok {
			t.Fatalf("beat %d carried trace_collector before the collector decided a state: %v", i, body["trace_collector"])
		}
	}
}

// A nudge beats promptly, and a burst of nudges never beats more often than
// the minimum gap.
func TestNudgeBeatsPromptlyAndAtMostOncePerSecond(t *testing.T) {
	if heartbeatNudgeMinGap != time.Second {
		t.Fatalf("the production nudge gap is %s, want one second", heartbeatNudgeMinGap)
	}
	var (
		mu    sync.Mutex
		beats []time.Time
	)
	beat := newHeartbeat(agentConfig{NodeID: "node-a", Interval: time.Hour}, newLoopHealth(nil))
	beat.witnessStatus = nil
	beat.nudgeMinGap = 200 * time.Millisecond
	beat.post = func(ctx context.Context, cfg agentConfig, payload map[string]any) error {
		mu.Lock()
		beats = append(beats, time.Now())
		mu.Unlock()
		return nil
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(beats)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beat.start(ctx)
	waitFor(t, "the first beat", func() bool { return count() == 1 })

	nudged := time.Now()
	for i := 0; i < 20; i++ {
		beat.nudgeNow()
	}
	waitFor(t, "a nudged beat", func() bool { return count() >= 2 })
	if d := time.Since(nudged); d > time.Second {
		t.Fatalf("the nudged beat took %s with an interval of an hour", d)
	}
	time.Sleep(600 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	// Twenty nudges: the one taken plus at most one held in the channel.
	if len(beats) > 3 {
		t.Fatalf("%d beats for one burst of nudges, want at most 3", len(beats))
	}
	for i := 1; i < len(beats); i++ {
		if gap := beats[i].Sub(beats[i-1]); gap < 190*time.Millisecond {
			t.Fatalf("beats %d and %d were %s apart, under the %s minimum", i-1, i, gap, beat.nudgeMinGap)
		}
	}
}

// Acceptance 1, agent side, end to end: one work-loop poll against a control
// plane whose policy is on with no address, on a node with no Clash API, and
// the nudged beat carries no_clash_api well inside one interval.
func TestNoClashAPIReachesTheBeatWithinOnePoll(t *testing.T) {
	const interval = 10 * time.Second
	beats := make(chan map[string]any, 16)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/trace-config":
			_ = json.NewEncoder(w).Encode(model.TraceAgentConfig{
				Policy:     model.TracePolicy{NodeID: "node-a", Enabled: true, Level: model.TraceLevelDebug},
				ServerTime: time.Now().UTC(),
			})
		case "/api/agent/metrics":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			beats <- body
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer cp.Close()

	cfg := agentConfig{Server: cp.URL, NodeID: "node-a", Token: "tok", Interval: interval}
	beat := newHeartbeat(cfg, newLoopHealth(nil))
	beat.witnessStatus = nil
	collector := newTraceCollector(cfg)
	collector.configPath = writeSingBoxConfig(t, nil)
	collector.setOnStateChange(beat.nudgeNow)
	beat.setTraceStatus(collector.Status)
	defer collector.stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beat.start(ctx)
	select {
	case first := <-beats:
		if _, ok := first["trace_collector"]; ok {
			t.Fatalf("the beat before any poll carried trace_collector: %v", first["trace_collector"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no first beat")
	}

	polled := time.Now()
	collector.reconcile(context.Background(), cfg)
	select {
	case body := <-beats:
		elapsed := time.Since(polled)
		tc, _ := body["trace_collector"].(map[string]any)
		if tc["state"] != "no_clash_api" {
			t.Fatalf("beat after the poll has trace_collector %v, want state no_clash_api", tc)
		}
		if elapsed >= interval {
			t.Fatalf("no_clash_api reached the beat after %s, not within one poll (%s)", elapsed, interval)
		}
		t.Logf("no_clash_api reached the beat %s after the poll", elapsed.Round(time.Millisecond))
	case <-time.After(interval):
		t.Fatal("no beat within one interval of the poll")
	}
}
