package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// alpha8ScriptCaps is the caps list lr00rl/sing-box v1.24.3-alpha.8 prints on
// a node with flock.
var alpha8ScriptCaps = []string{"user-del-by-name", "user-park", "user-parked-list", "user-open-proxy-guard", "user-match-counts", "user-socks-add", "user-lock"}

type fakeCapsScript struct {
	names    []string
	err      error
	calls    int
	binaries []string
}

func (f *fakeCapsScript) probe(_ context.Context, binary string) ([]string, error) {
	f.calls++
	f.binaries = append(f.binaries, binary)
	return f.names, f.err
}

func newTestCapsProbe(script *fakeCapsScript, clock *fakeClock) *singBoxCapsProbe {
	return &singBoxCapsProbe{probe: script.probe, now: clock.now}
}

// captureSingBoxLog returns the log lines about the sb script written while fn
// runs. Other lines (a leftover goroutine from another test) are ignored.
func captureSingBoxLog(t *testing.T, fn func()) []string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	var lines []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "sing-box script") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestAllowedSingBoxCapsKeepsOnlyKnownNames(t *testing.T) {
	got := allowedSingBoxCaps([]string{
		"user-lock", "user-del-by-name", "user-lock",
		"sb:user-lock", "durable-task-result-v1", "netguard-managed-sha-v1",
		"user-del-by-name ", "USER-LOCK", "user-del-by-name,user-lock", "",
	})
	want := []string{"sb:user-del-by-name", "sb:user-lock"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowed = %v, want %v", got, want)
	}
	all := allowedSingBoxCaps(alpha8ScriptCaps)
	if len(all) != len(alpha8ScriptCaps) {
		t.Fatalf("alpha.8 caps allowed = %v, want all %d", all, len(alpha8ScriptCaps))
	}
	for _, c := range all {
		if !strings.HasPrefix(c, singBoxCapPrefix) {
			t.Fatalf("cap %q lacks the %q prefix", c, singBoxCapPrefix)
		}
	}
	if got := allowedSingBoxCaps(nil); got != nil {
		t.Fatalf("no names allowed %v", got)
	}
}

// The server gates name-only removal on exactly this string; if the two ever
// drift, adopted-line deletes silently stay on the old path.
func TestServerReadsTheUserDelByNameCap(t *testing.T) {
	if !slices.Contains(allowedSingBoxCaps(alpha8ScriptCaps), "sb:user-del-by-name") {
		t.Fatal("alpha.8 caps do not yield sb:user-del-by-name")
	}
}

func TestSingBoxCapsProbeRunsAtStartupThenAtMostEveryTenMinutes(t *testing.T) {
	clock := newFakeClock()
	script := &fakeCapsScript{names: alpha8ScriptCaps}
	p := newTestCapsProbe(script, clock)
	cfg := agentConfig{SingBoxDiscover: true, SingBoxBin: "/usr/local/bin/sb"}

	p.refresh(&cfg)
	if script.calls != 1 || script.binaries[0] != "/usr/local/bin/sb" {
		t.Fatalf("startup probe calls = %d binaries = %v", script.calls, script.binaries)
	}
	if !slices.Contains(cfg.SingBoxScriptCaps, "sb:user-del-by-name") {
		t.Fatalf("caps = %v", cfg.SingBoxScriptCaps)
	}
	for i := 0; i < 59; i++ {
		clock.advance(10 * time.Second)
		next := agentConfig{SingBoxDiscover: true, SingBoxBin: "/usr/local/bin/sb"}
		p.refresh(&next)
		if !reflect.DeepEqual(next.SingBoxScriptCaps, cfg.SingBoxScriptCaps) {
			t.Fatalf("cached caps = %v, want %v", next.SingBoxScriptCaps, cfg.SingBoxScriptCaps)
		}
	}
	if script.calls != 1 {
		t.Fatalf("probe ran %d times inside ten minutes", script.calls)
	}
	clock.advance(10 * time.Second)
	script.names = alpha8ScriptCaps[:6] // flock went away
	p.refresh(&cfg)
	if script.calls != 2 {
		t.Fatalf("probe calls after ten minutes = %d, want 2", script.calls)
	}
	if slices.Contains(cfg.SingBoxScriptCaps, "sb:user-lock") {
		t.Fatalf("caps after flock went away = %v", cfg.SingBoxScriptCaps)
	}
}

func TestSingBoxCapsProbeTreatsAlpha7AsNoCapsQuietly(t *testing.T) {
	clock := newFakeClock()
	script := &fakeCapsScript{err: errors.New(`exit status 1: {"ok":false,"error":"error"}`)}
	p := newTestCapsProbe(script, clock)
	cfg := agentConfig{SingBoxDiscover: true, SingBoxBin: "sb"}

	lines := captureSingBoxLog(t, func() { p.refresh(&cfg) })
	if cfg.SingBoxScriptCaps != nil {
		t.Fatalf("caps = %v, want none", cfg.SingBoxScriptCaps)
	}
	if len(lines) != 0 {
		t.Fatalf("alpha.7 logged without debug: %q", lines)
	}

	cfg.Debug = true
	clock.advance(singBoxCapsInterval)
	lines = captureSingBoxLog(t, func() { p.refresh(&cfg) })
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "debug: sing-box script reports no caps") {
		t.Fatalf("debug lines = %q, want one", lines)
	}
	if got := payloadCapabilities(cfg); !reflect.DeepEqual(got, capabilitiesFor(false)) {
		t.Fatalf("capabilities = %v, want the agent's own only", got)
	}
}

func TestSingBoxCapsProbeLogsOnlyWhenTheReportedSetChanges(t *testing.T) {
	clock := newFakeClock()
	script := &fakeCapsScript{names: alpha8ScriptCaps}
	p := newTestCapsProbe(script, clock)
	cfg := agentConfig{SingBoxDiscover: true, SingBoxBin: "sb"}

	lines := captureSingBoxLog(t, func() {
		p.refresh(&cfg)
		clock.advance(singBoxCapsInterval)
		p.refresh(&cfg)
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "sb:user-del-by-name") {
		t.Fatalf("lines = %q, want one naming the caps", lines)
	}
	script.names, script.err = nil, errors.New("timeout")
	clock.advance(singBoxCapsInterval)
	lines = captureSingBoxLog(t, func() { p.refresh(&cfg) })
	if len(lines) != 1 || !strings.Contains(lines[0], "no longer reports caps") {
		t.Fatalf("lines = %q, want one saying the caps went away", lines)
	}
}

func TestSingBoxCapsProbeNeedsSingBoxDiscover(t *testing.T) {
	clock := newFakeClock()
	script := &fakeCapsScript{names: alpha8ScriptCaps}
	p := newTestCapsProbe(script, clock)

	off := agentConfig{SingBoxBin: "sb"}
	p.refresh(&off)
	if script.calls != 0 || off.SingBoxScriptCaps != nil {
		t.Fatalf("probe ran without -singbox-discover: calls=%d caps=%v", script.calls, off.SingBoxScriptCaps)
	}
	on := agentConfig{SingBoxDiscover: true, SingBoxBin: "sb"}
	p.refresh(&on)
	if script.calls != 1 || len(on.SingBoxScriptCaps) == 0 {
		t.Fatalf("calls=%d caps=%v", script.calls, on.SingBoxScriptCaps)
	}
	on.SingBoxDiscover = false
	p.refresh(&on)
	if on.SingBoxScriptCaps != nil {
		t.Fatalf("caps kept after discovery turned off: %v", on.SingBoxScriptCaps)
	}
}

func TestHeartbeatCarriesPrefixedSingBoxScriptCaps(t *testing.T) {
	clock := newFakeClock()
	script := &fakeCapsScript{names: append([]string{"rm -rf /", "durable-task-result-v1"}, alpha8ScriptCaps...)}
	p := newTestCapsProbe(script, clock)
	cfg := agentConfig{NodeID: "node-a", Interval: time.Second, LinechainReady: true, SingBoxDiscover: true, SingBoxBin: "sb"}
	p.refresh(&cfg)

	health := newLoopHealth(nil)
	beat := newHeartbeat(cfg, health)
	var body map[string]any
	beat.post = func(_ context.Context, _ agentConfig, payload map[string]any) error {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return json.Unmarshal(data, &body)
	}
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range body["capabilities"].([]any) {
		got = append(got, c.(string))
	}
	want := append(capabilitiesFor(true), allowedSingBoxCaps(alpha8ScriptCaps)...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("heartbeat capabilities = %v, want %v", got, want)
	}
	for _, c := range got {
		if c == "rm -rf /" || c == "sb:durable-task-result-v1" {
			t.Fatalf("heartbeat carried a name outside the allowlist: %v", got)
		}
	}
	// A blocked durable recovery still withholds the durable capability and
	// leaves the script's caps alone.
	health.setLinechainBlocked(errors.New("blocked"))
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = got[:0]
	for _, c := range body["capabilities"].([]any) {
		got = append(got, c.(string))
	}
	if slices.Contains(got, durableTaskResultCapability) || !slices.Contains(got, "sb:user-del-by-name") {
		t.Fatalf("blocked heartbeat capabilities = %v", got)
	}
}
