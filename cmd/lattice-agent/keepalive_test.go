package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
