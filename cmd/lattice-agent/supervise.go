package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Supervision: the agent keeps itself alive with systemd's help when its unit
// grants it a notify socket. It arms a watchdog for itself and pets it only
// while its own loops make local progress, so systemd restarts a wedged agent
// and never one that merely cannot reach the control plane. After its first
// hello it writes a health marker, which an agent update's dead-man timer
// reads before it keeps a new binary.

const (
	// loopStallFloor is the shortest time the work loop or the heartbeat may
	// go without progress before the watchdog stops being petted. Every step
	// in the work loop is bounded by its own timeout (30 s at most for one
	// request), so only a wedged step gets near it.
	loopStallFloor = 5 * time.Minute

	// sdNotifyCapability means the binary, when its unit grants it a notify
	// socket (NotifyAccess=main), sends READY=1 once its local state is open,
	// arms its own watchdog with WATCHDOG_USEC= and sends WATCHDOG=1 only
	// while its loops make progress. The unit stays Type=simple with no
	// WatchdogSec, so the same drop-in is inert under an older binary that
	// never notifies: installing one later (a rollback, an older installer,
	// a move from an alpha to the stable release) cannot get it killed.
	sdNotifyCapability = "sd-notify-v1"
	// agentWatchdogTimeout is the watchdog the agent arms for itself.
	agentWatchdogTimeout = 2 * time.Minute
	// healthMarkerCapability means the binary writes its version to
	// $RUNTIME_DIRECTORY/healthy after its first successful hello, which is
	// what an update's dead-man timer checks before it keeps the new binary.
	healthMarkerCapability = "health-marker-v1"
	healthMarkerName       = "healthy"
)

func (h *loopHealth) setWatchdog(on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.watchdog = on
}

// stalled reports which loop, if any, has gone longer than bound without
// progress. Only a wedged step or a wedged heartbeat can trip it; a heartbeat
// that has not started yet is not judged.
func (h *loopHealth) stalled(bound time.Duration) (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.clock()
	if d := t.Sub(h.workProgress); d > bound {
		where := "between steps"
		if h.step != "" {
			where = "in step " + h.step
		}
		return true, fmt.Sprintf("work loop has not moved for %s (%s)", d.Truncate(time.Second), where)
	}
	if h.beatProgress.IsZero() {
		return false, ""
	}
	if d := t.Sub(h.beatProgress); d > bound {
		return true, fmt.Sprintf("heartbeat has not moved for %s", d.Truncate(time.Second))
	}
	return false, ""
}

// loopStallBound scales the stall bound with the configured interval, so a
// node running a long interval is not judged against the 10 s default.
func loopStallBound(interval time.Duration) time.Duration {
	if b := 3 * interval; b > loopStallFloor {
		return b
	}
	return loopStallFloor
}

// recoverThenSupervise runs durable linechain recovery until it succeeds and
// only then calls arm, which arms the watchdog. Recovery restarts sing-box
// once per interrupted journal and has no deadline of its own, so on a node
// with several journals or a slow sing-box restart a healthy recovery can
// outlast the stall bound. Armed before it, the watchdog would read that as a
// wedged step and systemd would kill the agent mid-recovery, on every start.
// While recovery is blocked the heartbeat starts early, so the node reads
// "online, recovery blocked" with the reason rather than "offline".
//
// The recovery at the top of each work loop cycle stays under the watchdog:
// it runs only while no task is in flight and each task poll recovers first,
// so it meets at most the journal of the task that just ended.
func recoverThenSupervise(health *loopHealth, beat *heartbeat, recover func() error, wait func(), arm func()) {
	for {
		err := health.run(stepLinechainRecovery, recover)
		if err == nil {
			health.clearLinechainBlocked()
			break
		}
		health.setLinechainBlocked(err)
		beat.start(context.Background())
		log.Printf("linechain recovery blocked readiness: %v", err)
		health.waiting()
		wait()
	}
	arm()
}

var errNoNotifySocket = errors.New("NOTIFY_SOCKET not set")

// sdNotify sends one state line to systemd's notification socket. It returns
// errNoNotifySocket when the unit grants no socket, which is every unit
// written before sd-notify-v1.
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return errNoNotifySocket
	}
	// A leading '@' names an abstract socket; the net package maps it.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// watchdogInterval returns systemd's watchdog timeout for this process, or 0
// when no watchdog is armed for it.
func watchdogInterval() time.Duration {
	usec := strings.TrimSpace(os.Getenv("WATCHDOG_USEC"))
	if usec == "" {
		return 0
	}
	if pid := strings.TrimSpace(os.Getenv("WATCHDOG_PID")); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Microsecond
}

// armWatchdog returns the watchdog timeout this process must keep. A unit
// that sets WatchdogSec decides it. Otherwise, when systemd handed over a
// notify socket, the agent arms agentWatchdogTimeout itself with
// WATCHDOG_USEC=, which systemd honours without WatchdogSec in the unit. No
// socket means no supervision contract, and 0.
func armWatchdog(notify func(string) error) time.Duration {
	if wd := watchdogInterval(); wd > 0 {
		return wd
	}
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return 0
	}
	if err := notify("WATCHDOG_USEC=" + strconv.FormatInt(agentWatchdogTimeout.Microseconds(), 10)); err != nil {
		log.Printf("watchdog: could not arm: %v", err)
		return 0
	}
	return agentWatchdogTimeout
}

// runWatchdog pets systemd's watchdog at half its timeout while both loops
// make local progress, and withholds it while either is stalled, so systemd
// restarts a wedged agent. An unreachable control plane is not a stall: every
// request has a timeout, and the loops keep moving through failures.
func runWatchdog(ctx context.Context, health *loopHealth, timeout, bound time.Duration, notify func(string) error) {
	if timeout <= 0 {
		return
	}
	health.setWatchdog(true)
	t := time.NewTicker(timeout / 2)
	defer t.Stop()
	withholding := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if stalled, why := health.stalled(bound); stalled {
			if !withholding {
				log.Printf("watchdog: withholding keepalive, systemd will restart the agent: %s", why)
				withholding = true
			}
			continue
		}
		if withholding {
			log.Printf("watchdog: loops moving again, keepalive resumed")
			withholding = false
		}
		if err := notify("WATCHDOG=1"); err != nil {
			log.Printf("watchdog: notify failed: %v", err)
		}
	}
}

// writeHealthMarker records that this binary completed its first hello, in
// the runtime directory systemd creates for the unit (RuntimeDirectory=). An
// update's dead-man timer reads it and restores the previous binary when the
// new one never gets here. Without a runtime directory there is nothing to
// write and nobody reading.
func writeHealthMarker(agentVersion string) error {
	dir, _, _ := strings.Cut(os.Getenv("RUNTIME_DIRECTORY"), ":")
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("RUNTIME_DIRECTORY %q is not absolute", dir)
	}
	tmp, err := os.CreateTemp(dir, ".healthy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(agentVersion + "\n"); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, healthMarkerName)); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
