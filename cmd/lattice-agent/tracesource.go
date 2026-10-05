package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/sessionasm"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxapi"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-node-agent/internal/tracepolicy"
	"github.com/LatticeNet/lattice-node-agent/internal/traceshed"
	"github.com/LatticeNet/lattice-node-agent/internal/traceship"
	"github.com/LatticeNet/lattice-sdk/model"
)

// The sing-box trace collector.
//
// It subscribes to the node's loopback Clash API log stream, parses each line,
// assembles connections, and ships records to the control plane. The verbosity
// it subscribes at is the maximum of the node policy and every active trace
// session, which is the whole reason this reads the API instead of tailing a
// file: sing-box delivers to Clash API subscribers WITHOUT applying log.level,
// so verbosity changes without editing the node's config and without a restart.
// A restart would drop every live connection, which is precisely the outage
// this subsystem exists to make visible.

const (
	traceConnectionsPoll = 5 * time.Second
	traceAssemblerTick   = time.Second
	// traceCoreProbeTimeout bounds the liveness probe used to tell a sing-box
	// restart apart from a transport blip.
	traceCoreProbeTimeout = 2 * time.Second
	// traceFinalFlushTimeout bounds the last delivery attempt on shutdown.
	traceFinalFlushTimeout = 5 * time.Second
	// defaultTraceBudgetLines is the per-second parsed-line budget when a
	// policy sets none (or sets 0, which a server sends to mean "the agent
	// default"). Over it the collector sheds new connections whole; see
	// internal/traceshed.
	defaultTraceBudgetLines = 5000
	// traceStreamGrace is how long the /logs stream may stay down after it
	// was open before the collector reports stream_failing. A sing-box
	// restart is back well inside it, and flashing a failure on every restart
	// would teach the operator to ignore the state.
	traceStreamGrace = 15 * time.Second
	// traceConnPollFailLimit consecutive /connections failures (15 s at the
	// poll interval) report stream_failing even while /logs is open.
	traceConnPollFailLimit = 3
	// traceDiscoveryFailLimit consecutive polls that could not read or parse
	// the sing-box config, while a pipeline built from it is running, report
	// no_clash_api. The pipeline keeps running: a config caught mid-rewrite
	// is not a reason to drop the connections being assembled.
	traceDiscoveryFailLimit = traceConnPollFailLimit
	// traceLinesWindow is the window, in whole seconds, that LinesPerSec
	// averages over.
	traceLinesWindow = 10
	// defaultSingBoxConfigPath is where the sb script and the managed profile
	// both put the node's sing-box config. Discovery reads the Clash API
	// address from it and the secret fallback reads the secret.
	defaultSingBoxConfigPath = "/etc/sing-box/config.json"
	// defaultClashSecretPath is where `sb api on` writes the Clash API secret
	// (root:root 0600) when the policy names no secret path.
	defaultClashSecretPath = "/etc/sing-box/lattice-clash-api.secret"
	// nodeFileMaxBytes caps a config or secret read. A sing-box config is a
	// few kilobytes; anything past this is not one.
	nodeFileMaxBytes = 1 << 20
)

type traceCollector struct {
	// applyMu serialises applyConfig end to end. mu alone is not enough:
	// applyConfig reads whether a subscription is running, releases the lock,
	// and only then stops and starts one. Two callers racing through that
	// window would both see nothing running, both start, and the second would
	// overwrite the first's cancel func, leaking its four goroutines for the
	// life of the process. There is one caller today, but the whole point of
	// splitting applyConfig out of reconcile is that a control-stream push can
	// call it too.
	applyMu sync.Mutex

	mu     sync.Mutex
	cfg    agentConfig
	policy tracepolicy.Set
	// generation increments on every observed core restart. It scopes the
	// sing-box log id, which is rand.Uint32 and therefore meaningless on its own.
	generation uint64
	coreStart  time.Time

	asm     *sessionasm.Assembler
	shipper *traceship.Shipper

	client *singboxapi.Client

	// haveLevel is what the open stream is actually delivering. A difference
	// from the merged policy is what triggers a resubscribe.
	haveLevel model.TraceLevel

	// The pipeline and the subscription have different lifetimes on purpose.
	//
	// runCancel stops the assembler, the shipper and the connection poll. Those
	// hold the open connections and everything queued for delivery, so they
	// must survive a verbosity change: tearing them down mid-flight loses
	// pending records with no Dropped count and strands open connections, whose
	// later close lines then arrive without an opening identity and are dropped
	// as partial. Starting a capture would erase the connection being
	// investigated.
	//
	// streamCancel stops only the /logs subscription, which is the one thing
	// that genuinely has to be reopened, because a Clash API log stream fixes
	// its level when it opens.
	runCancel    context.CancelFunc
	streamCancel context.CancelFunc
	// addr is the endpoint the live pipeline was built against. A change means
	// a different core, so the pipeline is rebuilt rather than re-pointed.
	addr string

	// lastUpload and lastDownload are the newest cumulative totals seen from
	// /connections. They are monotonic within one sing-box process, so a drop
	// is process identity changing, which is the only honest restart signal
	// available through this API.
	lastUpload   int64
	lastDownload int64
	sawTotals    bool
	// observationGaps counts stream interruptions that were NOT shown to be
	// restarts. They are reported so a flapping endpoint is visible without
	// being mislabelled as connections being killed.
	observationGaps uint64
	// lastAsmDropped and lastAsmPartial are the assembler counters already
	// forwarded, so only deltas travel.
	lastAsmDropped uint64
	lastAsmPartial uint64
	// serverSkew is serverTime minus agent time at the last successful config
	// fetch. The deadline is the server's, so its clock is what the agent
	// compares against when enforcing expiry on its own.
	serverSkew time.Duration

	// budget is live, so a policy that changes only the budget takes effect
	// without waiting for a level change to rebuild the stream. guard applies
	// it per line; it lives as long as the assembler, because a shed mark has
	// to outlive a resubscribe or the shed connection's later lines would
	// reach the assembler mid-connection.
	budget int
	guard  *traceshed.Guard

	// configPath is the node's sing-box config, read for the Clash API
	// address when the policy names none and for the secret fallback. A field
	// so tests can point it at a temporary file.
	configPath string
	// now is the clock for the status, a field so the grace can be tested
	// without sleeping.
	now func() time.Time

	// configured turns true the first time a state is decided. Until then
	// the collector has not heard its policy, or has started a pipeline whose
	// stream has not answered yet, and reports no status rather than an
	// "off" it has not decided.
	configured bool
	// status holds State, Since, ClashAPIAddr, AddrSource and Detail; Status
	// fills in the rest when it is read.
	status        model.CollectorStatus
	onStateChange func()
	// streamEpoch identifies the current /logs subscription, so hooks of a
	// subscription that was replaced cannot move the state. streamOpen is
	// whether that subscription is up now; streamOpened whether it ever came
	// up; streamDownSince when it went down after being up (or first failed).
	streamEpoch     uint64
	streamOpen      bool
	streamOpened    bool
	streamDownSince time.Time
	streamErr       string
	// connPollFailures counts consecutive /connections failures.
	connPollFailures int
	connErr          string
	// discoveryFailures counts consecutive polls whose config read or parse
	// failed while a pipeline was running without a policy address, and
	// discoveryErr is the last such detail.
	discoveryFailures int
	discoveryErr      string
	// secretHash is the SHA-256 of the bearer secret the client holds, so a
	// rotated secret is noticed without keeping a second copy of it.
	secretHash [sha256.Size]byte
	// fallbackSecretPath and streamOpenTimeout are fields so tests can point
	// them at a temporary file and shorten the wait.
	fallbackSecretPath string
	streamOpenTimeout  time.Duration
	// lineSecs and lineCounts are a ring of lines arriving per wall second,
	// counted before the pre-parse ceiling, for LinesPerSec. One slot more
	// than the window, so the second in progress never overwrites the oldest
	// second the window still counts.
	lineSecs   [traceLinesWindow + 1]int64
	lineCounts [traceLinesWindow + 1]uint32
	// The cumulative counters the status reports, since countersSince.
	unparsedTotal uint64
	shedTotal     uint64
	countersSince time.Time

	// pending holds the opening lines of connections whose identity is not
	// known yet. A session filtered by user cannot match "inbound connection
	// from" because the user only appears on the NEXT line, so without this the
	// captured chain would always start one line late and lose the source
	// address. Bounded on both axes: a few lines per connection, a few hundred
	// connections, oldest evicted first.
	pending      map[uint32][]model.TraceLine
	pendingOrder []uint32
	// tagged marks connections already claimed by a session, so their later
	// lines go straight out instead of buffering again.
	tagged map[uint32][]string

	// rawSourceID is the virtual log source that takes the node's ordinary
	// lines, and rawQueue is what is waiting to go there. These are the lines
	// no capture session asked for: they belong in the existing bounded log
	// store, so the Logs view keeps working on a traced node and there is
	// parser evidence to look at after the fact rather than only records.
	rawSourceID string
	rawQueue    []string
	rawDropped  uint64
	// rawEpoch moves when the queue is discarded, so a flush that was in
	// flight at that moment does not trim a queue that is no longer its own.
	rawEpoch uint64

	// unparsed is owed to the shipper; unparsedTotal above is cumulative.
	unparsed uint64
}

const (
	// tracePendingPerConn and tracePendingConns bound the pre-identity buffer.
	// Eight lines is more than a connection emits before its user is known;
	// the connection cap is what stops a flood of half-open connections from
	// growing it without limit.
	tracePendingPerConn = 8
	tracePendingConns   = 512
)

func newTraceCollector(cfg agentConfig) *traceCollector {
	start := time.Now().UTC()
	return &traceCollector{
		cfg:                cfg,
		generation:         1,
		pending:            map[uint32][]model.TraceLine{},
		tagged:             map[uint32][]string{},
		configPath:         defaultSingBoxConfigPath,
		fallbackSecretPath: defaultClashSecretPath,
		now:                time.Now,
		status:             model.CollectorStatus{State: model.CollectorOff, Since: start},
		countersSince:      start,
	}
}

func (c *traceCollector) clock() time.Time { return c.now().UTC() }

// setOnStateChange registers what to call when the collector's state changes,
// which is how a change reaches the server within a second instead of a beat.
func (c *traceCollector) setOnStateChange(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = fn
}

// setStatusLocked records a state and its detail. Since moves only when the
// state changes, and the return value says whether it did. The caller holds
// c.mu and calls notifyStateChange after releasing it.
func (c *traceCollector) setStatusLocked(state model.CollectorState, detail string) bool {
	c.configured = true
	c.status.Detail = model.BoundCollectorDetail(detail)
	if c.status.State == state {
		return false
	}
	c.status.State = state
	c.status.Since = c.clock()
	return true
}

// setStatus records a state, with the Clash API address it concerns (empty
// when none was found), and nudges the beat if the state changed.
func (c *traceCollector) setStatus(state model.CollectorState, detail, addr, source string) {
	c.mu.Lock()
	c.status.ClashAPIAddr, c.status.AddrSource = addr, source
	changed := c.setStatusLocked(state, detail)
	notify := c.onStateChange
	c.mu.Unlock()
	if changed && notify != nil {
		notify()
	}
}

// evaluateStream decides ready and stream_failing for a running pipeline,
// from what the stream hooks and the connection poll recorded. It runs on
// every hook, every poll and every assembler tick, the last being what lets
// the grace expire. Before the first answer after a (re)subscribe the state
// stands: on loopback that answer takes milliseconds.
func (c *traceCollector) evaluateStream() {
	now := c.clock()
	c.mu.Lock()
	if c.runCancel == nil {
		// No pipeline: applyConfig owns the state.
		c.mu.Unlock()
		return
	}
	var (
		state  model.CollectorState
		detail string
	)
	switch {
	case c.connPollFailures >= traceConnPollFailLimit:
		state, detail = model.CollectorStreamFailing, "connections: "+c.connErr
	case c.discoveryFailures >= traceDiscoveryFailLimit:
		state, detail = model.CollectorNoClashAPI, c.discoveryErr+"; the stream to "+c.addr+" keeps running"
	case c.streamOpen:
		state = model.CollectorReady
	case !c.streamDownSince.IsZero() && now.Sub(c.streamDownSince) >= traceStreamGrace:
		state, detail = model.CollectorStreamFailing, "log stream: "+c.streamErr
	case !c.streamOpened && c.streamErr != "":
		// Refused before it ever opened. On loopback that is a real fault
		// (nothing listening, a wrong secret), not a restart in progress.
		state, detail = model.CollectorStreamFailing, "log stream: "+c.streamErr
	default:
		c.mu.Unlock()
		return
	}
	changed := c.setStatusLocked(state, detail)
	notify := c.onStateChange
	c.mu.Unlock()
	if changed && notify != nil {
		notify()
	}
}

// Status is the collector's account of itself for the metrics beat, or nil
// before it has applied a policy.
func (c *traceCollector) Status() *model.CollectorStatus {
	now := c.clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.configured {
		return nil
	}
	st := c.status
	if st.State == model.CollectorReady {
		st.Level = c.haveLevel
	}
	// Raw lines flow only through a running pipeline.
	st.RawLines = c.rawSourceID != "" && c.runCancel != nil
	st.LinesPerSec = c.linesPerSecLocked(now)
	st.BudgetLinesPerSec = c.budget
	if st.BudgetLinesPerSec <= 0 {
		st.BudgetLinesPerSec = defaultTraceBudgetLines
	}
	st.ShedConnections = c.shedTotal
	st.Unparsed = c.unparsedTotal
	st.CountersSince = c.countersSince
	return &st
}

// countLineLocked adds one arriving line to the per-second ring.
func (c *traceCollector) countLineLocked(now time.Time) {
	sec := now.Unix()
	i := int(sec % int64(len(c.lineSecs)))
	if c.lineSecs[i] != sec {
		c.lineSecs[i], c.lineCounts[i] = sec, 0
	}
	c.lineCounts[i]++
}

// linesPerSecLocked averages the last traceLinesWindow whole seconds, leaving
// out the second still in progress.
func (c *traceCollector) linesPerSecLocked(now time.Time) float64 {
	cur := now.Unix()
	var sum uint64
	for i, sec := range c.lineSecs {
		if sec >= cur-traceLinesWindow && sec < cur {
			sum += uint64(c.lineCounts[i])
		}
	}
	return float64(sum) / traceLinesWindow
}

// bufferPending remembers a line whose connection has not been claimed yet.
func (c *traceCollector) bufferPending(logID uint32, l model.TraceLine) {
	if _, done := c.tagged[logID]; done {
		return
	}
	if _, ok := c.pending[logID]; !ok {
		if len(c.pendingOrder) >= tracePendingConns {
			oldest := c.pendingOrder[0]
			c.pendingOrder = c.pendingOrder[1:]
			delete(c.pending, oldest)
		}
		c.pendingOrder = append(c.pendingOrder, logID)
	}
	q := c.pending[logID]
	if len(q) >= tracePendingPerConn {
		return
	}
	c.pending[logID] = append(q, l)
}

// claimPending marks a connection captured and returns the opening lines that
// were waiting for it, stamped with the sessions that claimed it.
func (c *traceCollector) claimPending(logID uint32, sessionIDs []string) []model.TraceLine {
	if _, done := c.tagged[logID]; done {
		return nil
	}
	c.tagged[logID] = sessionIDs
	q := c.pending[logID]
	delete(c.pending, logID)
	for i, id := range c.pendingOrder {
		if id == logID {
			c.pendingOrder = append(c.pendingOrder[:i], c.pendingOrder[i+1:]...)
			break
		}
	}
	out := make([]model.TraceLine, 0, len(q)*len(sessionIDs))
	for _, sessionID := range sessionIDs {
		for _, l := range q {
			l.SessionID = sessionID
			out = append(out, l)
		}
	}
	return out
}

// forgetConn drops per-connection bookkeeping once its record has been emitted.
func (c *traceCollector) forgetConn(logID uint32) {
	delete(c.tagged, logID)
	if _, ok := c.pending[logID]; ok {
		delete(c.pending, logID)
		for i, id := range c.pendingOrder {
			if id == logID {
				c.pendingOrder = append(c.pendingOrder[:i], c.pendingOrder[i+1:]...)
				break
			}
		}
	}
}

// reconcile is called once per agent poll cycle. It fetches the node's trace
// config, rebuilds the merged policy, and starts, stops, or re-levels the log
// subscription to match. It never blocks the poll loop on network work.
func (c *traceCollector) reconcile(ctx context.Context, cfg agentConfig) {
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()

	agentCfg, err := fetchTraceConfig(cfg)
	if err != nil {
		debugf(cfg, "trace config fetch failed: %v", err)
		return
	}
	c.applyConfig(ctx, agentCfg)
}

// applyConfig is separated from reconcile so a pushed trace.config message on
// the control stream can drive the same path without a poll.
func (c *traceCollector) applyConfig(ctx context.Context, agentCfg model.TraceAgentConfig) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	now := time.Now().UTC()
	set := tracepolicy.Build(agentCfg, now)

	c.mu.Lock()
	if !agentCfg.ServerTime.IsZero() {
		c.serverSkew = agentCfg.ServerTime.Sub(now)
	}
	c.policy = set
	c.setRawSourceLocked(effectiveRawSourceID(agentCfg))
	enabled := set.Enabled()
	secretPath := strings.TrimSpace(agentCfg.Policy.SecretPath)
	cfg := c.cfg
	pipelineUp := c.runCancel != nil
	running := c.addr
	runningSource := c.status.AddrSource
	have := c.haveLevel
	c.mu.Unlock()

	// The budget is recorded whatever happens next, so the status reports
	// the ceiling the policy asks for even before a pipeline exists.
	c.setBudget(agentCfg.Policy.BudgetLinesPerSec)
	if !enabled {
		c.stop()
		c.setStatus(model.CollectorOff, "", "", "")
		return
	}
	// Discovery runs on every poll and every pushed config, so `sb api on`
	// on the node is noticed without restarting the agent.
	addr, source, detail, transient := c.resolveAddr(agentCfg.Policy)
	switch {
	case addr == "" && transient && pipelineUp:
		// The config could not be read or parsed this time (a rewrite in
		// progress, a permission slip). Only a config that was read and has
		// no usable controller is an answer; this is not one, so the running
		// pipeline and the connections it holds stay. noteDiscovery turns the
		// state after traceDiscoveryFailLimit polls in a row.
		addr, source = running, runningSource
		c.noteDiscovery(detail)
	case addr == "":
		c.stop()
		c.setStatus(model.CollectorNoClashAPI, detail, "", "")
		return
	default:
		c.noteDiscovery("")
	}
	if pipelineUp && running != addr {
		// A different Clash API means a different core. Nothing in flight
		// belongs to it, so take the whole pipeline down, flushing what is
		// already assembled rather than dropping it.
		c.stop()
		pipelineUp = false
	}
	resubscribe := false
	if !pipelineUp {
		if !c.startPipeline(ctx, cfg, addr, source, secretPath) {
			return
		}
		have = ""
	} else {
		// Same endpoint, but the policy may now name the address discovery
		// found, or the other way round.
		c.mu.Lock()
		c.status.ClashAPIAddr, c.status.AddrSource = addr, source
		c.mu.Unlock()
		// A rotated secret, picked up while the stream is down, resubscribes
		// at once instead of waiting out the retry backoff with the old one.
		resubscribe = c.refreshSecret(secretPath)
	}
	if have == set.SubscribeLevel() && !resubscribe {
		return
	}
	c.restartStream(cfg, set.SubscribeLevel(), len(set.ActiveSessions()))
}

// effectiveRawSourceID is the raw log source the collector feeds, after the
// policy's raw switch. A nil switch is a policy written before the switch
// existed (an alpha-0.2.2a117 server or older): raw lines then follow
// RawSourceID, which such a server sends whenever records are on.
func effectiveRawSourceID(agentCfg model.TraceAgentConfig) string {
	if raw := agentCfg.Policy.Raw; raw != nil && !raw.Enabled {
		return ""
	}
	return strings.TrimSpace(agentCfg.RawSourceID)
}

// setRawSourceLocked switches the raw source. Turning it off discards what is
// queued: those lines belong to a stream the operator stopped, and shipping
// them on a later flush would break "records on, raw off ships zero raw
// lines". The switch lives here and never on tracepolicy.Set, which drops
// every policy field but Enabled and Level when it is rebuilt locally.
func (c *traceCollector) setRawSourceLocked(id string) {
	if id == "" && (len(c.rawQueue) > 0 || c.rawDropped > 0) {
		c.rawQueue = nil
		c.rawDropped = 0
		c.rawEpoch++
	}
	c.rawSourceID = id
}

// setBudget makes the per-second line budget live, so a policy that changes
// only the budget takes effect without waiting for a level change to rebuild
// the stream. 0 means the agent default.
func (c *traceCollector) setBudget(budget int) {
	if budget <= 0 {
		budget = defaultTraceBudgetLines
	}
	c.mu.Lock()
	c.budget = budget
	guard := c.guard
	c.mu.Unlock()
	if guard != nil {
		guard.SetBudget(budget)
	}
}

// startPipeline brings up the parts that must outlive any one subscription:
// the assembler holding open connections, the shipper holding queued delivery,
// the budget guard, and the connection poll. Returns false if the endpoint
// cannot be used at all, in which case nothing is left half-built and the
// status says why.
func (c *traceCollector) startPipeline(ctx context.Context, cfg agentConfig, addr, source, secretPath string) bool {
	secret, err := resolveClashSecret(secretPath, c.fallbackSecretPath, c.configPath)
	if err != nil {
		log.Printf("trace: cannot read the Clash API secret: %v", err)
		c.setStatus(model.CollectorSecretUnreadable, "cannot read the Clash API secret: "+err.Error(), addr, source)
		return false
	}
	client, err := singboxapi.New(singboxapi.Config{Addr: addr, Secret: secret, StreamOpenTimeout: c.streamOpenTimeout})
	if err != nil {
		// Only a policy address can get here: discovery refuses a
		// non-loopback controller by the same rule before it is used.
		log.Printf("trace: Clash API client: %v", err)
		c.setStatus(model.CollectorNoClashAPI, err.Error(), addr, source)
		return false
	}

	c.mu.Lock()
	// The assembler starts on the generation the collector is counting from, or
	// the connections swept by the first restart carry a generation the server
	// never sees again and the marker reports generation zero.
	asm := sessionasm.New(sessionasm.Options{NodeID: cfg.NodeID, CoreGeneration: c.generation})
	shipper := traceship.New(traceship.Config{
		Server: cfg.Server,
		NodeID: cfg.NodeID,
		Token:  cfg.Token,
	})
	budget := c.budget
	if budget <= 0 {
		budget = defaultTraceBudgetLines
	}
	guard := traceshed.New(budget, traceshed.DefaultRingCapacity)
	runCtx, runCancel := context.WithCancel(ctx)
	c.client = client
	c.asm = asm
	c.shipper = shipper
	c.guard = guard
	c.runCancel = runCancel
	c.addr = addr
	c.status.ClashAPIAddr, c.status.AddrSource = addr, source
	c.connPollFailures, c.connErr = 0, ""
	c.secretHash = sha256.Sum256([]byte(strings.TrimSpace(secret)))
	generation, coreStart := c.generation, c.coreStart
	c.mu.Unlock()

	shipper.SetCore(generation, coreStart)

	go shipper.Run(runCtx)
	go c.pollConnections(runCtx, client, asm, guard)
	go c.driveAssembler(runCtx, asm, shipper, guard)
	debugf(cfg, "trace: pipeline up for %s (%s) generation=%d", addr, source, generation)
	return true
}

// resolveAddr finds the Clash API address. The policy's address wins.
// Otherwise the node's sing-box config is read, and its external_controller
// is used only if it passes the same loopback rule the client enforces. With
// no usable address, detail says why in one line that names the file and
// never quotes it. transient reports a failure to read or parse the config,
// as opposed to a config that was read and has no usable controller: a file
// caught mid-rewrite is the first kind, `sb api off` the second.
func (c *traceCollector) resolveAddr(pol model.TracePolicy) (addr, source, detail string, transient bool) {
	if a := strings.TrimSpace(pol.ClashAPIAddr); a != "" {
		return a, model.ClashAddrFromPolicy, "", false
	}
	path := c.configPath
	api, err := readClashAPIConfig(path)
	switch {
	case err != nil:
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			return "", "", fmt.Sprintf("cannot read %s: %v", path, pathErr.Err), true
		}
		return "", "", err.Error(), true
	case !api.Present:
		return "", "", fmt.Sprintf("no experimental.clash_api in %s", path), false
	case api.Controller == "":
		return "", "", fmt.Sprintf("experimental.clash_api in %s has no external_controller", path), false
	}
	normalized, err := singboxapi.ValidateLoopbackAddr(api.Controller)
	if err != nil {
		return "", "", fmt.Sprintf("external_controller %q in %s is not a loopback host:port", api.Controller, path), false
	}
	return normalized, model.ClashAddrFromConfig, "", false
}

// noteDiscovery records the outcome of one config read for a running
// pipeline: failed with detail, or succeeded when detail is empty. The
// pipeline stays up either way; evaluateStream turns the state to
// no_clash_api once traceDiscoveryFailLimit reads in a row have failed.
func (c *traceCollector) noteDiscovery(detail string) {
	c.mu.Lock()
	if detail == "" {
		c.discoveryFailures, c.discoveryErr = 0, ""
	} else {
		c.discoveryFailures++
		c.discoveryErr = detail
	}
	c.mu.Unlock()
	c.evaluateStream()
}

// refreshSecret re-reads the Clash API secret for a running pipeline and
// reports whether the caller should resubscribe. A changed secret is handed
// to the client only while the subscription is not open: an open one proves
// the core still holds the secret in use, and a core reads its secret only
// when it starts, so the new one is wanted once the stream has dropped. A
// read failure changes nothing; the next poll reads again.
func (c *traceCollector) refreshSecret(secretPath string) bool {
	secret, err := resolveClashSecret(secretPath, c.fallbackSecretPath, c.configPath)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if sum == c.secretHash || c.client == nil || c.streamOpen {
		return false
	}
	c.client.SetSecret(secret)
	c.secretHash = sum
	return true
}

// restartStream reopens the /logs subscription at a new level, leaving the
// assembler, the shipper and everything they hold untouched.
func (c *traceCollector) restartStream(cfg agentConfig, level model.TraceLevel, sessionCount int) {
	c.mu.Lock()
	if c.streamCancel != nil {
		c.streamCancel()
	}
	client, asm, guard := c.client, c.asm, c.guard
	budget := c.budget
	addr := c.addr
	runCancelSet := c.runCancel != nil
	c.mu.Unlock()
	if client == nil || asm == nil || guard == nil || !runCancelSet {
		return
	}

	streamCtx, streamCancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.streamCancel = streamCancel
	c.haveLevel = level
	// A new subscription starts with no answer yet. The state stands until
	// its first Open or Error.
	c.streamEpoch++
	epoch := c.streamEpoch
	c.streamOpen, c.streamOpened = false, false
	c.streamDownSince, c.streamErr = time.Time{}, ""
	c.mu.Unlock()

	debugf(cfg, "trace: subscribed to %s at level=%s budget=%d lines/s sessions=%d",
		addr, level, budget, sessionCount)
	go c.streamLogs(streamCtx, client, asm, guard, string(level), epoch)
}

// stop takes the whole collector down and does NOT discard what is in flight:
// the assembler is drained one last time and the shipper is given a bounded,
// independent context to deliver it. Cancelling and walking away is how pending
// evidence disappears without ever being counted as dropped.
func (c *traceCollector) stop() {
	c.mu.Lock()
	streamCancel, runCancel := c.streamCancel, c.runCancel
	asm, shipper, guard := c.asm, c.shipper, c.guard
	c.streamCancel, c.runCancel = nil, nil
	c.asm, c.shipper, c.client, c.guard = nil, nil, nil, nil
	c.haveLevel = ""
	c.addr = ""
	// Hooks of the subscription being stopped must not move the state.
	c.streamEpoch++
	c.streamOpen, c.streamOpened = false, false
	c.streamDownSince, c.streamErr = time.Time{}, ""
	c.connPollFailures, c.connErr = 0, ""
	c.discoveryFailures, c.discoveryErr = 0, ""
	c.secretHash = [sha256.Size]byte{}
	c.mu.Unlock()

	if streamCancel != nil {
		streamCancel()
	}
	if runCancel != nil {
		runCancel()
	}
	if asm != nil && shipper != nil {
		if records := asm.Drain(); len(records) > 0 {
			shipper.AddRecords(records)
		}
		// The guard's counts since the last tick are owed too, or a node
		// switched off mid-overload would under-report what it shed.
		if guard != nil {
			shed, dropped := guard.Take()
			c.mu.Lock()
			c.shedTotal += shed
			c.mu.Unlock()
			shipper.AddShed(shed)
			shipper.AddDropped(dropped)
		}
		// An independent context: the one that just got cancelled cannot carry
		// a final delivery.
		flushCtx, cancel := context.WithTimeout(context.Background(), traceFinalFlushTimeout)
		if err := shipper.Flush(flushCtx); err != nil {
			log.Printf("trace: final flush left data undelivered: %v", err)
		}
		cancel()
	}
}

// streamLogs is the hot path. Every line under the hard ceiling is parsed; the
// budget guard then decides whether its connection is observed, and a kept
// line is offered to the assembler and (when a session asked for it) shipped
// verbatim.
func (c *traceCollector) streamLogs(ctx context.Context, client *singboxapi.Client, asm *sessionasm.Assembler, guard *traceshed.Guard, level string, epoch uint64) {
	// nodeID and cfg are captured once: reading c.cfg from inside the hot
	// path would race with the poll loop that reassigns it every cycle.
	c.mu.Lock()
	cfg := c.cfg
	nodeID := cfg.NodeID
	c.mu.Unlock()

	onEntry := func(entry []byte) {
		now := time.Now().UTC()

		// The pre-parse ceiling is the CPU brake. Over it a line is dropped
		// unparsed and counted, and the tick loop hands the count to the
		// shipper, so a silently discarded line never reads as a quiet
		// network. The budget behind it is live, so a policy that changes
		// only the budget takes effect on the running stream.
		//
		// The rate is counted first, so LinesPerSec is what sing-box sends,
		// not what the ceiling lets through; the lines over the ceiling are
		// in dropped.
		c.mu.Lock()
		c.countLineLocked(now)
		c.mu.Unlock()
		if !guard.Ceiling(now) {
			return
		}
		line, err := singboxlog.ParseEntry(entry, now)
		if err != nil || !line.Parsed() {
			// Every unrecognised line counts, with or without a connection id.
			// A newer sing-box can reword a message while keeping the
			// "[id elapsed] tag: message" shape, and only counting the
			// id-less ones would let that drift read as quiet traffic. It is
			// counted before the guard decides, so the parser signal does not
			// depend on the budget.
			c.mu.Lock()
			c.unparsed++
			c.unparsedTotal++
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
		// Over budget, a connection the assembler does not already hold is
		// shed whole; one it holds keeps every line, so no record is ever cut
		// in the middle.
		if !guard.Admit(now, line, line.HasLogID && asm.Tracked(line.LogID)) {
			return
		}

		asm.Line(line)

		c.mu.Lock()
		set := c.policy
		sh := c.shipper
		c.mu.Unlock()
		if sh == nil {
			return
		}
		// Match against the CONNECTION, not the line.
		//
		// A session filtered by user or destination can only ever match the one
		// authenticated inbound line that carries them. The rule, sniff,
		// outbound and close lines for the same connection carry neither, so
		// matching per line would keep the predicate's echo and throw away the
		// evidence chain the operator actually asked for. The assembler knows
		// what the connection is; ask it.
		user, dstHost := line.User, line.DstHost
		if line.HasLogID {
			if ctxInfo := asm.Context(line.LogID); ctxInfo.Known {
				if ctxInfo.User != "" {
					user = ctxInfo.User
				}
				if ctxInfo.DstHost != "" {
					dstHost = ctxInfo.DstHost
				}
			}
		}
		decision := set.Match(line, user, dstHost)

		base := model.TraceLine{
			NodeID:  nodeID,
			At:      now,
			Level:   line.Level,
			LogID:   line.LogID,
			Tag:     line.Tag,
			Message: line.Message,
			Raw:     line.Raw,
		}

		c.mu.Lock()
		// Every line the node floor keeps goes to the raw log source, whether
		// or not a session wanted it. That is the always-on path: records are
		// a summary, and a summary is not evidence.
		if decision.Keep && c.rawSourceID != "" {
			if len(c.rawQueue) < traceRawQueueMax {
				c.rawQueue = append(c.rawQueue, line.Raw)
			} else {
				c.rawDropped++
			}
		}
		claimed, alreadyTagged := c.tagged[line.LogID]
		if line.HasLogID && !alreadyTagged && len(decision.SessionIDs) == 0 {
			// Identity is not resolved yet. Hold the line so the chain can
			// still start at the beginning if a session claims the connection
			// on the very next line.
			c.bufferPending(line.LogID, base)
			c.mu.Unlock()
			return
		}
		sessions := decision.SessionIDs
		var backlog []model.TraceLine
		if line.HasLogID {
			if alreadyTagged {
				// Membership is the connection's, so every later line rides on
				// it even when the line itself carries no matchable field.
				sessions = claimed
			} else if len(sessions) > 0 {
				backlog = c.claimPending(line.LogID, sessions)
			}
		}
		c.mu.Unlock()

		if line.HasLogID && len(sessions) > 0 && !alreadyTagged {
			asm.Tag(line.LogID, sessions)
		}
		if len(backlog) > 0 {
			sh.AddLines(backlog)
		}
		if !decision.Keep && !alreadyTagged {
			return
		}
		if len(sessions) == 0 {
			return
		}
		out := make([]model.TraceLine, 0, len(sessions))
		for _, sessionID := range sessions {
			l := base
			l.SessionID = sessionID
			out = append(out, l)
		}
		sh.AddLines(out)
	}

	onError := func(err error) {
		// A dropped stream is an OBSERVATION GAP, not evidence that sing-box
		// restarted. Asserting a restart from reachability closed healthy
		// connections as core_restart whenever the API stalled for a couple of
		// seconds, and missed a real restart that came back before the probe
		// ran. Process identity is what settles it, and the connection totals
		// carry it: they are cumulative within one process, so they only go
		// backwards when a new process is answering. That check lives in the
		// connection poll, which sees every reset whether or not the stream
		// noticed a gap.
		debugf(cfg, "trace: log stream ended, treating as an observation gap: %v", err)
		c.noteStreamError(epoch, err)
	}

	if err := client.StreamLogsWithHooks(ctx, level, singboxapi.StreamHooks{
		Entry: onEntry,
		Open:  func() { c.noteStreamOpen(epoch) },
		Error: onError,
	}); err != nil && ctx.Err() == nil {
		log.Printf("trace: log stream stopped: %v", err)
	}
}

// noteStreamOpen records that subscription epoch was accepted. A hook of a
// subscription that has since been replaced changes nothing.
func (c *traceCollector) noteStreamOpen(epoch uint64) {
	c.mu.Lock()
	if c.streamEpoch != epoch {
		c.mu.Unlock()
		return
	}
	c.streamOpen, c.streamOpened = true, true
	c.streamDownSince, c.streamErr = time.Time{}, ""
	c.mu.Unlock()
	c.evaluateStream()
}

// noteStreamError records a disconnect or a refusal of subscription epoch.
// The grace runs from the first failure after the stream was last up.
func (c *traceCollector) noteStreamError(epoch uint64, err error) {
	now := c.clock()
	c.mu.Lock()
	c.observationGaps++
	if c.streamEpoch != epoch {
		c.mu.Unlock()
		return
	}
	c.streamOpen = false
	if c.streamDownSince.IsZero() {
		c.streamDownSince = now
	}
	c.streamErr = err.Error()
	c.mu.Unlock()
	c.evaluateStream()
}

// noteCoreRestart moves the generation on. guard may be nil in tests; when
// set, its shed marks are forgotten, because the new process draws its log
// ids afresh.
func (c *traceCollector) noteCoreRestart(asm *sessionasm.Assembler, guard *traceshed.Guard) {
	c.mu.Lock()
	c.generation++
	generation := c.generation
	c.coreStart = time.Now().UTC()
	coreStart := c.coreStart
	sh := c.shipper
	c.mu.Unlock()
	asm.CoreRestart(generation, time.Now().UTC())
	if guard != nil {
		guard.Reset()
	}
	if sh != nil {
		sh.SetCore(generation, coreStart)
	}
}

func (c *traceCollector) pollConnections(ctx context.Context, client *singboxapi.Client, asm *sessionasm.Assembler, guard *traceshed.Guard) {
	ticker := time.NewTicker(traceConnectionsPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		snap, err := client.Connections(ctx)
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		if c.client != client {
			// This poll belongs to a pipeline that was replaced.
			c.mu.Unlock()
			return
		}
		if err != nil {
			c.connPollFailures++
			c.connErr = err.Error()
			c.mu.Unlock()
			c.evaluateStream()
			continue
		}
		c.connPollFailures, c.connErr = 0, ""
		// Cumulative totals are monotonic within one sing-box process, so a
		// decrease is a new process answering. This is the restart signal:
		// it fires on a fast restart the stream never noticed, and does not
		// fire on a stall that merely interrupted observation.
		regressed := c.sawTotals && (snap.UploadTotal < c.lastUpload || snap.DownloadTotal < c.lastDownload)
		c.lastUpload, c.lastDownload, c.sawTotals = snap.UploadTotal, snap.DownloadTotal, true
		c.mu.Unlock()
		c.evaluateStream()
		if regressed {
			c.noteCoreRestart(asm, guard)
		}
		items := make([]sessionasm.SnapshotItem, 0, len(snap.Connections))
		for _, conn := range snap.Connections {
			inboundType, inboundTag := conn.Metadata.InboundTypeAndTag()
			items = append(items, sessionasm.SnapshotItem{
				SrcIP:       conn.Metadata.SourceIP,
				SrcPort:     conn.Metadata.SourcePort,
				DstHost:     conn.Metadata.Host,
				DstPort:     conn.Metadata.DestinationPort,
				InboundType: inboundType,
				InboundTag:  inboundTag,
				Network:     conn.Metadata.Network,
				Upload:      conn.Upload,
				Download:    conn.Download,
				Rule:        conn.Rule,
				Chains:      conn.Chains,
				Start:       conn.Start,
			})
		}
		asm.Snapshot(sessionasm.Snapshot{At: snap.At, Items: items})
	}
}

func (c *traceCollector) driveAssembler(ctx context.Context, asm *sessionasm.Assembler, sh *traceship.Shipper, guard *traceshed.Guard) {
	ticker := time.NewTicker(traceAssemblerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Drain once on the way out so a level change does not discard the
			// connections assembled just before it.
			if records := asm.Drain(); len(records) > 0 {
				sh.AddRecords(records)
			}
			return
		case now := <-ticker.C:
			c.expireSessionsLocally(now.UTC())
			asm.Tick(now.UTC())
			if records := asm.Drain(); len(records) > 0 {
				// A finished connection will send no more lines, so its
				// buffering state can go. Open snapshots are not final and keep
				// theirs.
				c.mu.Lock()
				for _, r := range records {
					if !r.Open {
						c.forgetConn(r.LogID)
					}
				}
				c.mu.Unlock()
				sh.AddRecords(records)
			}
			c.flushRaw()
			// The assembler keeps its own loss counters and nothing was
			// reading them, so bounded eviction and suppressed partial records
			// were invisible: the server's gap audit could report zero loss
			// while connections had been discarded. Forward the deltas, with
			// the guard's: lines over the hard ceiling or id-less over budget
			// go to dropped, shed connections to AddShed (which also counts
			// them as dropped for a server that predates the field).
			asmStats := asm.Stats()
			shed, dropped := guard.Take()
			c.mu.Lock()
			unparsed := c.unparsed
			c.unparsed = 0
			c.shedTotal += shed
			if d := asmStats.Dropped - c.lastAsmDropped; d > 0 {
				dropped += d
				c.lastAsmDropped = asmStats.Dropped
			}
			if d := asmStats.Partial - c.lastAsmPartial; d > 0 {
				// A partial observation is not a clean result. It is folded
				// into the same counter an operator already watches rather
				// than kept as a local statistic nobody sees.
				dropped += d
				c.lastAsmPartial = asmStats.Partial
			}
			c.mu.Unlock()
			sh.AddUnparsed(unparsed)
			sh.AddDropped(dropped)
			sh.AddShed(shed)
			// The grace for a dropped stream expires on this tick.
			c.evaluateStream()
		}
	}
}

// resolveClashSecret reads the Clash API bearer token from the node. The server
// never sends it: for an adopted node the management script writes a 0600 file,
// and for a managed node the token lives in the rendered sing-box config, which
// is already handled as a node-scoped secret-bearing artifact.
//
// The policy's secret path is tried first, then fallbackPath, then the config.
// A missing file falls through to the next; so does a fallback file the agent
// may not open (a non-root agent beside a root-only secret), as before. A file
// that is there and fails readNodeFile's checks is refused, never skipped
// silently, so a secret anyone can rewrite is never used.
func resolveClashSecret(secretPath, fallbackPath, configPath string) (string, error) {
	if secretPath != "" {
		b, err := readNodeFile(secretPath, true)
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	if fallbackPath != "" {
		b, err := readNodeFile(fallbackPath, true)
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !os.IsNotExist(err) && !errors.Is(err, fs.ErrPermission) {
			return "", err
		}
	}
	api, err := readClashAPIConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("no Clash API secret found in %s or the sing-box config: %w", secretPath, err)
	}
	return api.Secret, nil
}

// nodeFileError refuses a config or secret file for what it is rather than
// for whether it can be opened. Its text is fixed and names the path; it never
// carries a byte of the file.
type nodeFileError struct {
	path   string
	reason string
}

func (e *nodeFileError) Error() string { return e.path + " " + e.reason }

// readNodeFile reads a sing-box config or Clash API secret the way a file that
// gates a bearer token should be read. O_NOFOLLOW refuses a symlink at the
// last component and O_NONBLOCK keeps a FIFO from blocking the open; the
// checks then run on the open descriptor, so the file cannot be swapped
// between check and read. It must be a regular file owned by root or the
// agent's own uid, writable by nobody else, and, for a secret, readable by
// nobody else either. At most nodeFileMaxBytes are read. A missing file
// returns the *fs.PathError from open, so os.IsNotExist still works.
func readNodeFile(path string, secret bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, &nodeFileError{path, "is a symlink"}
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, &nodeFileError{path, "is not a regular file"}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, &nodeFileError{path, "has no owner the agent can check"}
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return nil, &nodeFileError{path, fmt.Sprintf("is owned by uid %d, not root or the agent", st.Uid)}
	}
	perm := fi.Mode().Perm()
	if perm&0o022 != 0 {
		return nil, &nodeFileError{path, "is writable by group or others"}
	}
	if secret && perm&0o044 != 0 {
		return nil, &nodeFileError{path, "is readable by group or others"}
	}
	b, err := io.ReadAll(io.LimitReader(f, nodeFileMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > nodeFileMaxBytes {
		return nil, &nodeFileError{path, "is larger than 1 MiB"}
	}
	return b, nil
}

// clashAPIConfig is experimental.clash_api as the node's sing-box config has it.
type clashAPIConfig struct {
	// Present is whether the config has an experimental.clash_api object.
	Present    bool
	Controller string
	Secret     string
}

// readClashAPIConfig reads experimental.clash_api.{external_controller,secret}
// in one parse. Discovery uses the controller and the secret fallback the
// secret. A parse failure is reported as a fixed sentence with the path: the
// decoder's own message quotes bytes of the file, and the file holds the
// secret.
func readClashAPIConfig(path string) (clashAPIConfig, error) {
	b, err := readNodeFile(path, false)
	if err != nil {
		return clashAPIConfig{}, err
	}
	var parsed struct {
		Experimental struct {
			ClashAPI *struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return clashAPIConfig{}, &nodeFileError{path, "cannot be parsed as JSON"}
	}
	api := parsed.Experimental.ClashAPI
	if api == nil {
		return clashAPIConfig{}, nil
	}
	return clashAPIConfig{
		Present:    true,
		Controller: strings.TrimSpace(api.ExternalController),
		Secret:     strings.TrimSpace(api.Secret),
	}, nil
}

func fetchTraceConfig(cfg agentConfig) (model.TraceAgentConfig, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/trace-config?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return model.TraceAgentConfig{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return model.TraceAgentConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return model.TraceAgentConfig{}, fmt.Errorf("trace config: unexpected status %d", resp.StatusCode)
	}
	var out model.TraceAgentConfig
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return model.TraceAgentConfig{}, err
	}
	return out, nil
}

// traceRawQueueMax bounds the raw line queue between flushes. Over it, lines
// are dropped and counted rather than growing memory without limit.
const traceRawQueueMax = 5000

// flushRaw ships the ordinary lines to the virtual log source. A failure holds
// position: the queue is only cleared once the server has taken it, so a
// server outage delays raw lines rather than silently discarding them, up to
// the queue bound.
func (c *traceCollector) flushRaw() {
	c.mu.Lock()
	sourceID := c.rawSourceID
	if sourceID == "" || len(c.rawQueue) == 0 {
		c.mu.Unlock()
		return
	}
	lines := c.rawQueue
	dropped := c.rawDropped
	epoch := c.rawEpoch
	cfg := c.cfg
	c.mu.Unlock()

	status, err := shipLogBatch(cfg, model.LogBatch{
		SourceID:   sourceID,
		Path:       singBoxRawPathFor(cfg.NodeID),
		Lines:      lines,
		Dropped:    dropped,
		CapturedAt: time.Now().UTC(),
	})
	if err != nil || status != http.StatusOK {
		return
	}
	c.mu.Lock()
	// A raw switch turned off while this was on the wire discarded the
	// queue; what is there now is not what was shipped.
	if c.rawEpoch == epoch {
		c.rawQueue = c.rawQueue[len(lines):]
		c.rawDropped = 0
	}
	c.mu.Unlock()
}

// singBoxRawPathFor mirrors the server's virtual path so the cross-check on
// ingest passes. It is not a file and nothing ever opens it.
func singBoxRawPathFor(nodeID string) string { return "singbox://" + nodeID }

// expireSessionsLocally drops sessions whose deadline has passed, without
// waiting to hear it from the server.
//
// The agent-side TTL is the whole point of the deadline: a capture must stop
// even if the control plane disappears mid-capture, which is exactly when the
// privacy boundary matters most. Previously the set was only rebuilt when a
// config fetch succeeded, so a server outage at 12:14 left a session that
// expired at 12:15 running and tagging indefinitely.
//
// The server's clock governs the deadline, so its skew relative to this agent
// is applied before comparing. A server ahead of the agent must not let a
// session outlive its deadline, and a server behind must not cut one short.
func (c *traceCollector) expireSessionsLocally(now time.Time) {
	c.mu.Lock()
	set := c.policy
	skew := c.serverSkew
	c.mu.Unlock()

	next := set.ExpiresNext()
	if next.IsZero() || now.Add(skew).Before(next) {
		return
	}
	rebuilt := tracepolicy.Build(model.TraceAgentConfig{
		Policy:   set.Policy(),
		Sessions: set.ActiveSessions(),
	}, now.Add(skew))

	c.mu.Lock()
	c.policy = rebuilt
	want := rebuilt.SubscribeLevel()
	have := c.haveLevel
	cfg := c.cfg
	c.mu.Unlock()

	if want != have {
		// Expiry can lower the subscription, and leaving it high would keep
		// collecting at a verbosity nobody is authorised for any more.
		debugf(cfg, "trace: a session expired locally; dropping the subscription from %s to %s", have, want)
		c.restartStream(cfg, want, len(rebuilt.ActiveSessions()))
	}
}
