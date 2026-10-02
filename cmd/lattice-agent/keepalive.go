package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// Keepalive: the heartbeat runs on its own goroutine and carries the work
// loop's own account of its progress (loop health).
//
// Before this, the heartbeat was the metrics POST inside the serial work
// loop. Four 30 s timeouts ahead of it already exceeded the server's 90 s
// offline threshold, so a half-hung control plane flipped healthy nodes
// offline, and a blocked linechain recovery skipped the heartbeat entirely, so
// the node read "offline" while the reason sat only in its journal.

const (
	// heartbeatTimeout bounds one beat. A beat that cannot finish in this time
	// is lost, and the next tick sends a fresh one.
	heartbeatTimeout = 10 * time.Second
	// loopErrorMaxRunes bounds the error text one step reports.
	loopErrorMaxRunes = 200
)

// Work loop steps as they appear in loop health. The names are a contract
// with the server, which may derive "beating but stalled" from them.
const (
	stepLinechainRecovery = "linechain_recovery"
	stepHello             = "hello"
	stepConfig            = "config"
	stepIPRefresh         = "ip_refresh"
	stepUsage             = "usage"
	stepInventory         = "inventory"
	stepTasks             = "tasks"
	stepMonitors          = "monitors"
	stepLogSources        = "log_sources"
	stepTrace             = "trace"
	stepDebug             = "debug"
	stepGuardReality      = "guard_reality"
)

type loopStepState struct {
	LastOKAt          time.Time `json:"last_ok_at,omitzero"`
	LastErrorAt       time.Time `json:"last_error_at,omitzero"`
	LastError         string    `json:"last_error,omitempty"`
	ConsecutiveErrors int       `json:"consecutive_errors,omitempty"`
}

// loopHealthPayload rides on every heartbeat as "loop_health". Older servers
// decode agent bodies leniently and ignore it.
type loopHealthPayload struct {
	StartedAt             time.Time                `json:"started_at"`
	CycleStartedAt        time.Time                `json:"cycle_started_at,omitzero"`
	CycleCompletedAt      time.Time                `json:"cycle_completed_at,omitzero"`
	CycleDurationMs       int64                    `json:"cycle_duration_ms,omitempty"`
	Step                  string                   `json:"step,omitempty"`
	StepSince             time.Time                `json:"step_since,omitzero"`
	LinechainBlocked      string                   `json:"linechain_blocked,omitempty"`
	LinechainBlockedSince time.Time                `json:"linechain_blocked_since,omitzero"`
	Steps                 map[string]loopStepState `json:"steps,omitempty"`
	TaskBusySince         time.Time                `json:"task_busy_since,omitzero"`
	MonitorResultsQueued  int                      `json:"monitor_results_queued,omitempty"`
	MonitorResultsDropped uint64                   `json:"monitor_results_dropped,omitempty"`
}

// loopHealth is the agent's own record of whether its loops are moving. Only
// local events update it; nothing here depends on the control plane
// answering.
type loopHealth struct {
	mu  sync.Mutex
	now func() time.Time

	startedAt             time.Time
	workProgress          time.Time
	beatProgress          time.Time
	cycleStarted          time.Time
	cycleCompleted        time.Time
	cycleDuration         time.Duration
	step                  string
	stepSince             time.Time
	steps                 map[string]*loopStepState
	linechainBlocked      string
	linechainBlockedSince time.Time
	taskBusySince         time.Time
}

func newLoopHealth(now func() time.Time) *loopHealth {
	if now == nil {
		now = time.Now
	}
	t := now().UTC()
	return &loopHealth{now: now, startedAt: t, workProgress: t, beatProgress: t, steps: map[string]*loopStepState{}}
}

func (h *loopHealth) clock() time.Time { return h.now().UTC() }

// cycleStart marks the top of one work loop cycle.
func (h *loopHealth) cycleStart() {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.clock()
	h.cycleStarted = t
	h.workProgress = t
}

// cycleEnd marks a cycle that ran every step, whatever each step's outcome.
func (h *loopHealth) cycleEnd() {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.clock()
	h.cycleCompleted = t
	if !h.cycleStarted.IsZero() {
		h.cycleDuration = t.Sub(h.cycleStarted)
	}
	h.workProgress = t
}

// waiting marks the work loop as idle until its next tick. Waiting is
// progress: the loop is where it means to be.
func (h *loopHealth) waiting() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.step = ""
	h.stepSince = time.Time{}
	h.workProgress = h.clock()
}

// run executes one named step and records its outcome.
func (h *loopHealth) run(step string, fn func() error) error {
	h.mu.Lock()
	t := h.clock()
	h.step = step
	h.stepSince = t
	h.workProgress = t
	h.mu.Unlock()

	err := fn()

	h.mu.Lock()
	defer h.mu.Unlock()
	t = h.clock()
	h.workProgress = t
	h.step = ""
	h.stepSince = time.Time{}
	st := h.steps[step]
	if st == nil {
		st = &loopStepState{}
		h.steps[step] = st
	}
	if err == nil {
		st.LastOKAt = t
		st.ConsecutiveErrors = 0
		st.LastError = ""
	} else {
		st.LastErrorAt = t
		st.LastError = boundedLoopError(err)
		st.ConsecutiveErrors++
	}
	return err
}

// setLinechainBlocked records why durable task recovery refuses to proceed.
// While it is set the heartbeat withholds the durable task capability.
func (h *loopHealth) setLinechainBlocked(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.linechainBlocked == "" {
		h.linechainBlockedSince = h.clock()
	}
	h.linechainBlocked = boundedLoopError(err)
	if h.linechainBlocked == "" {
		h.linechainBlocked = "blocked"
	}
}

func (h *loopHealth) clearLinechainBlocked() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.linechainBlocked = ""
	h.linechainBlockedSince = time.Time{}
}

func (h *loopHealth) linechainIsBlocked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.linechainBlocked != ""
}

func (h *loopHealth) setTaskBusy(busy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case busy && h.taskBusySince.IsZero():
		h.taskBusySince = h.clock()
	case !busy:
		h.taskBusySince = time.Time{}
	}
}

func (h *loopHealth) beat() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beatProgress = h.clock()
}

func (h *loopHealth) snapshot() loopHealthPayload {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := loopHealthPayload{
		StartedAt:             h.startedAt,
		CycleStartedAt:        h.cycleStarted,
		CycleCompletedAt:      h.cycleCompleted,
		CycleDurationMs:       h.cycleDuration.Milliseconds(),
		Step:                  h.step,
		StepSince:             h.stepSince,
		LinechainBlocked:      h.linechainBlocked,
		LinechainBlockedSince: h.linechainBlockedSince,
		TaskBusySince:         h.taskBusySince,
	}
	if len(h.steps) > 0 {
		out.Steps = make(map[string]loopStepState, len(h.steps))
		for name, st := range h.steps {
			out.Steps[name] = *st
		}
	}
	return out
}

// boundedLoopError keeps one line of an error, without control characters,
// short enough to ride on every heartbeat. Agent errors carry request paths
// and server diagnostics, never the node token (that travels only in the
// Authorization header).
func boundedLoopError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, strings.TrimSpace(err.Error()))
	runes := []rune(msg)
	if len(runes) > loopErrorMaxRunes {
		return string(runes[:loopErrorMaxRunes]) + "..."
	}
	return msg
}

// heartbeat sends the metrics beat on its own goroutine, every interval,
// whatever the work loop is doing.
type heartbeat struct {
	mu     sync.Mutex
	cfg    agentConfig
	health *loopHealth
	// monitorStats reports the monitor result queue for loop health; nil
	// leaves the fields out.
	monitorStats func() (queued int, dropped uint64)
	timeout      time.Duration
	post         func(ctx context.Context, cfg agentConfig, payload map[string]any) error
	startOnce    sync.Once
}

func newHeartbeat(cfg agentConfig, health *loopHealth) *heartbeat {
	return &heartbeat{
		cfg:     cfg,
		health:  health,
		timeout: heartbeatTimeout,
		post: func(ctx context.Context, cfg agentConfig, payload map[string]any) error {
			return postAgentJSONContext(ctx, cfg, "/api/agent/metrics", payload, nil)
		},
	}
}

// setConfig hands the heartbeat the work loop's latest config (pushed debug
// policy, discovered IPs, runtime flags).
func (b *heartbeat) setConfig(cfg agentConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg
}

func (b *heartbeat) config() agentConfig {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg
}

// once sends one beat under its own deadline.
func (b *heartbeat) once(ctx context.Context) error {
	defer b.health.beat()
	cfg := b.config()
	// A node whose durable recovery is blocked cannot run linechain tasks,
	// so it does not advertise that it can until recovery clears.
	cfg.LinechainReady = cfg.LinechainReady && !b.health.linechainIsBlocked()
	payload := metricsPayload(cfg)
	lh := b.health.snapshot()
	if b.monitorStats != nil {
		lh.MonitorResultsQueued, lh.MonitorResultsDropped = b.monitorStats()
	}
	payload["loop_health"] = lh
	beatCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	return b.post(beatCtx, cfg, payload)
}

// start runs the heartbeat goroutine once; later calls do nothing.
func (b *heartbeat) start(ctx context.Context) {
	b.startOnce.Do(func() { go b.run(ctx) })
}

// run beats at once and then every interval until ctx ends.
func (b *heartbeat) run(ctx context.Context) {
	interval := b.config().Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := b.once(ctx); err != nil && ctx.Err() == nil {
			log.Printf("metrics error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
