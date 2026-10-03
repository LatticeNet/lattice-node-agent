package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoopHealthStalledJudgesLocalProgressOnly(t *testing.T) {
	clock := newFakeClock()
	h := newLoopHealth(clock.now)
	bound := loopStallBound(10 * time.Second)
	if bound != loopStallFloor {
		t.Fatalf("bound for 10 s interval = %s, want %s", bound, loopStallFloor)
	}
	if got := loopStallBound(10 * time.Minute); got != 30*time.Minute {
		t.Fatalf("bound for 10 min interval = %s", got)
	}

	// Failing requests are progress: each returns within its timeout.
	for i := 0; i < 20; i++ {
		clock.advance(30 * time.Second)
		_ = h.run(stepConfig, func() error { return errors.New("control plane unreachable") })
		h.beat()
	}
	if stalled, why := h.stalled(bound); stalled {
		t.Fatalf("failing but moving loops judged stalled: %s", why)
	}

	// A step that never returns is a stall, and names itself.
	entered := make(chan struct{})
	block := make(chan struct{})
	go func() {
		_ = h.run(stepInventory, func() error {
			close(entered)
			<-block
			return nil
		})
	}()
	<-entered
	clock.advance(bound + time.Second)
	h.beat()
	stalled, why := h.stalled(bound)
	if !stalled || !strings.Contains(why, "in step inventory") {
		t.Fatalf("wedged step: stalled=%v why=%q", stalled, why)
	}
	close(block)
	waitFor(t, "step to finish", func() bool { s, _ := h.stalled(bound); return !s })

	// A heartbeat that stops moving is a stall too.
	clock.advance(bound + time.Second)
	h.waiting()
	if stalled, why := h.stalled(bound); !stalled || !strings.Contains(why, "heartbeat") {
		t.Fatalf("stalled heartbeat: stalled=%v why=%q", stalled, why)
	}
}

// A durable recovery that outlasts the stall bound is healthy work, not a
// wedge. The watchdog is armed only after it, and the heartbeat, which has
// not started yet, is not judged; from its start on it is.
func TestLongStartupRecoveryDoesNotTripTheWatchdog(t *testing.T) {
	clock := newFakeClock()
	h := newLoopHealth(clock.now)
	var beats atomic.Int32
	beat := newHeartbeat(agentConfig{Interval: time.Hour}, h)
	beat.post = func(context.Context, agentConfig, map[string]any) error {
		beats.Add(1)
		return nil
	}
	recovered, armed := false, false
	recoverThenSupervise(h, beat, func() error {
		if armed {
			t.Error("watchdog armed while recovery was still running")
		}
		clock.advance(2 * loopStallFloor)
		recovered = true
		return nil
	}, func() {
		t.Fatal("recovery succeeded, so there is nothing to wait for")
	}, func() {
		armed = true
		if !recovered {
			t.Error("watchdog armed before recovery finished")
		}
		if stalled, why := h.stalled(loopStallFloor); stalled {
			t.Errorf("a recovery that took %s reads as a stall at arming: %s", 2*loopStallFloor, why)
		}
	})
	if !armed {
		t.Fatal("watchdog never armed")
	}
	if beats.Load() != 0 {
		t.Fatalf("heartbeat started before hello on an unblocked recovery: %d beats", beats.Load())
	}

	// Hello and setup take seconds, then the heartbeat starts.
	clock.advance(30 * time.Second)
	_ = h.run(stepHello, func() error { return nil })
	if stalled, why := h.stalled(loopStallFloor); stalled {
		t.Fatalf("stalled before the heartbeat started: %s", why)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beat.start(ctx)
	waitFor(t, "first beat", func() bool { return beats.Load() >= 1 })
	clock.advance(loopStallFloor + time.Second)
	h.waiting()
	if stalled, why := h.stalled(loopStallFloor); !stalled || !strings.Contains(why, "heartbeat") {
		t.Fatalf("a started heartbeat that stops must read as a stall: stalled=%v why=%q", stalled, why)
	}
}

// A blocked recovery starts the heartbeat at once, so the node reads online
// with the reason, and arms the watchdog only after recovery clears.
func TestBlockedStartupRecoveryBeatsBeforeTheWatchdogArms(t *testing.T) {
	clock := newFakeClock()
	h := newLoopHealth(clock.now)
	var beats atomic.Int32
	beat := newHeartbeat(agentConfig{Interval: time.Hour}, h)
	beat.post = func(context.Context, agentConfig, map[string]any) error {
		beats.Add(1)
		return nil
	}
	failures, waits, arms := 2, 0, 0
	recoverThenSupervise(h, beat, func() error {
		if arms > 0 {
			t.Error("watchdog armed while recovery was blocked")
		}
		if failures > 0 {
			failures--
			return errors.New("linechain recovery journal is outside captured authority")
		}
		return nil
	}, func() {
		waits++
		if !h.linechainIsBlocked() {
			t.Error("waiting on a blocked recovery that loop health does not record")
		}
		clock.advance(10 * time.Second)
	}, func() {
		arms++
	})
	if waits != 2 || arms != 1 {
		t.Fatalf("waits=%d arms=%d, want 2 and 1", waits, arms)
	}
	if h.linechainIsBlocked() {
		t.Fatal("recovery cleared but loop health still says blocked")
	}
	waitFor(t, "heartbeat started by the blocked recovery", func() bool { return beats.Load() >= 1 })
}

func TestRunWatchdogPetsOnlyWhileLoopsMove(t *testing.T) {
	clock := newFakeClock()
	h := newLoopHealth(clock.now)
	var mu sync.Mutex
	var sent []string
	notify := func(state string) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, state)
		return nil
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(sent)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runWatchdog(ctx, h, 10*time.Millisecond, time.Minute, notify)
	waitFor(t, "first keepalive", func() bool { return count() >= 2 })
	if !h.snapshot().Watchdog {
		t.Fatal("loop health does not say the watchdog is armed")
	}

	clock.advance(2 * time.Minute)
	time.Sleep(20 * time.Millisecond)
	before := count()
	time.Sleep(60 * time.Millisecond)
	if after := count(); after != before {
		t.Fatalf("watchdog petted while stalled: %d -> %d", before, after)
	}

	h.waiting()
	h.beat()
	waitFor(t, "keepalive to resume", func() bool { return count() > before })
	mu.Lock()
	defer mu.Unlock()
	for _, s := range sent {
		if s != "WATCHDOG=1" {
			t.Fatalf("watchdog sent %q", s)
		}
	}
}

func TestSDNotifyWritesStateToSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify("READY=1"); !errors.Is(err, errNoNotifySocket) {
		t.Fatalf("without NOTIFY_SOCKET: %v", err)
	}
	// Unix socket paths are short on darwin; t.TempDir is too long there.
	dir, err := os.MkdirTemp("/tmp", "sdn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := sdNotify("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("socket got %q", got)
	}
}

func TestWatchdogIntervalHonoursSystemdEnvironment(t *testing.T) {
	t.Setenv("WATCHDOG_PID", "")
	t.Setenv("WATCHDOG_USEC", "")
	if got := watchdogInterval(); got != 0 {
		t.Fatalf("unset = %s", got)
	}
	t.Setenv("WATCHDOG_USEC", "120000000")
	if got := watchdogInterval(); got != 2*time.Minute {
		t.Fatalf("120000000 usec = %s", got)
	}
	t.Setenv("WATCHDOG_PID", "1")
	if got := watchdogInterval(); got != 0 {
		t.Fatalf("watchdog for another pid = %s", got)
	}
	t.Setenv("WATCHDOG_PID", "")
	t.Setenv("WATCHDOG_USEC", "nope")
	if got := watchdogInterval(); got != 0 {
		t.Fatalf("invalid usec = %s", got)
	}
}

func TestArmWatchdogNeedsANotifySocketAndPrefersTheUnitTimeout(t *testing.T) {
	var sent []string
	notify := func(s string) error { sent = append(sent, s); return nil }
	t.Setenv("WATCHDOG_PID", "")
	t.Setenv("WATCHDOG_USEC", "")
	t.Setenv("NOTIFY_SOCKET", "")
	if got := armWatchdog(notify); got != 0 || len(sent) != 0 {
		t.Fatalf("no socket: %s, sent %v", got, sent)
	}
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	if got := armWatchdog(notify); got != agentWatchdogTimeout || len(sent) != 1 || sent[0] != "WATCHDOG_USEC=120000000" {
		t.Fatalf("socket, no unit watchdog: %s, sent %v", got, sent)
	}
	t.Setenv("WATCHDOG_USEC", "30000000")
	if got := armWatchdog(notify); got != 30*time.Second || len(sent) != 1 {
		t.Fatalf("unit WatchdogSec should win without a message: %s, sent %v", got, sent)
	}
	t.Setenv("WATCHDOG_USEC", "")
	if got := armWatchdog(func(string) error { return errors.New("refused") }); got != 0 {
		t.Fatalf("failed arm returned %s", got)
	}
}

func TestWriteHealthMarkerInRuntimeDirectory(t *testing.T) {
	t.Setenv("RUNTIME_DIRECTORY", "")
	if err := writeHealthMarker("0.3.10-alpha.1"); err != nil {
		t.Fatalf("without a runtime directory: %v", err)
	}
	dir := t.TempDir()
	t.Setenv("RUNTIME_DIRECTORY", dir+":/run/other")
	if err := writeHealthMarker("0.3.10-alpha.1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, healthMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "0.3.10-alpha.1\n" {
		t.Fatalf("marker = %q", data)
	}
	info, err := os.Stat(filepath.Join(dir, healthMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("marker mode = %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	t.Setenv("RUNTIME_DIRECTORY", "relative/dir")
	if err := writeHealthMarker("x"); err == nil {
		t.Fatal("relative runtime directory accepted")
	}
}

// Installers and agent updates grep -compat-json for these names before they
// write a Type=notify drop-in or arm a dead-man timer, and the release
// workflow greps the same output for its server floor and channel.
func TestCompatJSONAdvertisesSupervisionFeatures(t *testing.T) {
	data, err := json.Marshal(compatibilityPayload())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"` + sdNotifyCapability + `"`, `"` + healthMarkerCapability + `"`, `"server_min":"` + compatServerMin + `"`, `"channel":"` + compatChannel + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("-compat-json %s lacks %s", data, want)
		}
	}
}
