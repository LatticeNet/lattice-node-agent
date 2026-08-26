package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/sessionasm"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxapi"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-node-agent/internal/tracepolicy"
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
	// defaultTraceBudgetLines is the per-second ceiling when a policy sets none.
	defaultTraceBudgetLines = 500
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

	// coreDown latches while sing-box is unreachable so a flapping stream
	// cannot bump the generation more than once per real restart.
	coreDown bool

	// budget is live, so a policy that changes only the budget takes effect
	// without waiting for a level change to rebuild the stream.
	budget int

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

	unparsed uint64
	dropped  uint64
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
	return &traceCollector{
		cfg:        cfg,
		generation: 1,
		pending:    map[uint32][]model.TraceLine{},
		tagged:     map[uint32][]string{},
	}
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
	c.policy = set
	enabled := set.Enabled()
	addr := strings.TrimSpace(agentCfg.Policy.ClashAPIAddr)
	secretPath := strings.TrimSpace(agentCfg.Policy.SecretPath)
	cfg := c.cfg
	pipelineUp := c.runCancel != nil
	sameEndpoint := c.addr == addr
	have := c.haveLevel
	c.mu.Unlock()

	if !enabled || addr == "" {
		c.stop()
		return
	}
	if pipelineUp && !sameEndpoint {
		// A different Clash API means a different core. Nothing in flight
		// belongs to it, so take the whole pipeline down, flushing what is
		// already assembled rather than dropping it.
		c.stop()
		pipelineUp = false
	}
	if !pipelineUp {
		if !c.startPipeline(ctx, cfg, addr, secretPath, agentCfg.Policy) {
			return
		}
		have = ""
	}
	c.setBudget(agentCfg.Policy.BudgetLinesPerSec)
	if have == set.SubscribeLevel() {
		return
	}
	c.restartStream(cfg, set.SubscribeLevel(), len(set.ActiveSessions()))
}

// setBudget makes the per-second line budget live, so a policy that changes
// only the budget takes effect without waiting for a level change to rebuild
// the stream.
func (c *traceCollector) setBudget(budget int) {
	if budget <= 0 {
		budget = defaultTraceBudgetLines
	}
	c.mu.Lock()
	c.budget = budget
	c.mu.Unlock()
}

// startPipeline brings up the parts that must outlive any one subscription:
// the assembler holding open connections, the shipper holding queued delivery,
// and the connection poll. Returns false if the endpoint cannot be reached at
// all, in which case nothing is left half-built.
func (c *traceCollector) startPipeline(ctx context.Context, cfg agentConfig, addr, secretPath string, pol model.TracePolicy) bool {
	secret, err := resolveClashSecret(secretPath, cfg)
	if err != nil {
		log.Printf("trace: cannot read the Clash API secret: %v", err)
		return false
	}
	client, err := singboxapi.New(singboxapi.Config{Addr: addr, Secret: secret})
	if err != nil {
		log.Printf("trace: Clash API client: %v", err)
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
	runCtx, runCancel := context.WithCancel(ctx)
	c.client = client
	c.asm = asm
	c.shipper = shipper
	c.runCancel = runCancel
	c.addr = addr
	generation, coreStart := c.generation, c.coreStart
	c.mu.Unlock()

	shipper.SetCore(generation, coreStart)

	go shipper.Run(runCtx)
	go c.pollConnections(runCtx, client, asm)
	go c.driveAssembler(runCtx, asm, shipper)
	debugf(cfg, "trace: pipeline up for %s generation=%d", addr, generation)
	return true
}

// restartStream reopens the /logs subscription at a new level, leaving the
// assembler, the shipper and everything they hold untouched.
func (c *traceCollector) restartStream(cfg agentConfig, level model.TraceLevel, sessionCount int) {
	c.mu.Lock()
	if c.streamCancel != nil {
		c.streamCancel()
	}
	client, asm := c.client, c.asm
	budget := c.budget
	runCancelSet := c.runCancel != nil
	c.mu.Unlock()
	if client == nil || asm == nil || !runCancelSet {
		return
	}

	streamCtx, streamCancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.streamCancel = streamCancel
	c.haveLevel = level
	c.mu.Unlock()

	debugf(cfg, "trace: subscribed to %s at level=%s budget=%d lines/s sessions=%d",
		c.addr, level, budget, sessionCount)
	go c.streamLogs(streamCtx, client, asm, string(level))
}

// stop takes the whole collector down and does NOT discard what is in flight:
// the assembler is drained one last time and the shipper is given a bounded,
// independent context to deliver it. Cancelling and walking away is how pending
// evidence disappears without ever being counted as dropped.
func (c *traceCollector) stop() {
	c.mu.Lock()
	streamCancel, runCancel := c.streamCancel, c.runCancel
	asm, shipper := c.asm, c.shipper
	c.streamCancel, c.runCancel = nil, nil
	c.asm, c.shipper, c.client = nil, nil, nil
	c.haveLevel = ""
	c.addr = ""
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
		// An independent context: the one that just got cancelled cannot carry
		// a final delivery.
		flushCtx, cancel := context.WithTimeout(context.Background(), traceFinalFlushTimeout)
		if err := shipper.Flush(flushCtx); err != nil {
			log.Printf("trace: final flush left data undelivered: %v", err)
		}
		cancel()
	}
}

// streamLogs is the hot path. Every kept line is parsed, offered to the
// assembler, and (when a session asked for it) shipped verbatim.
func (c *traceCollector) streamLogs(ctx context.Context, client *singboxapi.Client, asm *sessionasm.Assembler, level string) {
	// nodeID is captured once: reading c.cfg from inside the hot path would race
	// with the poll loop that reassigns it every cycle.
	c.mu.Lock()
	nodeID := c.cfg.NodeID
	c.mu.Unlock()

	var (
		windowStart = time.Now()
		inWindow    int
	)
	onEntry := func(entry []byte) {
		now := time.Now().UTC()

		// The first line after an outage is the proof that sing-box came back.
		// Recovery cannot be detected in onError, which only runs when a stream
		// ENDS: the down to up transition happens on a successful reconnect,
		// where nothing else would notice it. Sweeping here is what turns a
		// restart into a marker carrying the number of connections it killed.
		c.mu.Lock()
		recovered := c.coreDown
		c.coreDown = false
		c.mu.Unlock()
		if recovered {
			c.noteCoreRestart(asm)
		}

		if now.Sub(windowStart) >= time.Second {
			windowStart = now
			inWindow = 0
		}
		inWindow++
		// The budget is read live rather than captured, so a policy that
		// changes only the budget takes effect on the running stream instead
		// of waiting for a level change to rebuild it.
		c.mu.Lock()
		budgetPerSec := c.budget
		c.mu.Unlock()
		if budgetPerSec <= 0 {
			budgetPerSec = defaultTraceBudgetLines
		}
		if inWindow > budgetPerSec {
			// Over budget: drop and count. A silently discarded line reads later
			// as a quiet network, so the count rides along in the next batch.
			// The tick loop hands it to the shipper, so no drop waits on a
			// threshold before it becomes visible.
			c.mu.Lock()
			c.dropped++
			c.mu.Unlock()
			return
		}

		line, err := singboxlog.ParseEntry(entry, now)
		if err != nil {
			c.mu.Lock()
			c.unparsed++
			c.mu.Unlock()
			return
		}
		if line.Event == singboxlog.EventOther && !line.HasLogID {
			c.mu.Lock()
			c.unparsed++
			c.mu.Unlock()
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
		// A dropped stream MIGHT mean sing-box restarted, taking every live
		// connection with it, or it might be a transport blip. Treating every
		// disconnect as a restart would invent restart markers and mislabel
		// healthy connections as core_restart, so probe before believing it:
		// if the API still answers, the core is alive and only the stream fell
		// over.
		probeCtx, cancel := context.WithTimeout(ctx, traceCoreProbeTimeout)
		_, probeErr := client.Version(probeCtx)
		cancel()

		c.mu.Lock()
		wasDown := c.coreDown
		c.coreDown = probeErr != nil
		c.mu.Unlock()

		if probeErr != nil {
			debugf(c.cfg, "trace: sing-box unreachable after stream end: %v", probeErr)
			return
		}
		if wasDown {
			// It was unreachable and is now answering again: that is a restart,
			// and the connections still open in the assembler did not survive it.
			c.noteCoreRestart(asm)
		}
		debugf(c.cfg, "trace: log stream ended: %v", err)
	}

	if err := client.StreamLogsWithRetry(ctx, level, onEntry, onError); err != nil && ctx.Err() == nil {
		log.Printf("trace: log stream stopped: %v", err)
	}
}

func (c *traceCollector) noteCoreRestart(asm *sessionasm.Assembler) {
	c.mu.Lock()
	c.generation++
	generation := c.generation
	c.coreStart = time.Now().UTC()
	sh := c.shipper
	c.mu.Unlock()
	asm.CoreRestart(generation, time.Now().UTC())
	if sh != nil {
		sh.SetCore(generation, c.coreStart)
	}
}

func (c *traceCollector) pollConnections(ctx context.Context, client *singboxapi.Client, asm *sessionasm.Assembler) {
	ticker := time.NewTicker(traceConnectionsPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		snap, err := client.Connections(ctx)
		if err != nil {
			continue
		}
		// Recovery must not depend on traffic. A restart on a quiet node ends
		// the log stream and then nothing else happens, so waiting for the next
		// log line would leave the swept connections and the restart marker
		// pending indefinitely. This poll runs either way, so whichever of the
		// two observes the core answering again wins; the check and clear is
		// under the lock, so only one of them sweeps.
		c.mu.Lock()
		recovered := c.coreDown
		c.coreDown = false
		c.mu.Unlock()
		if recovered {
			c.noteCoreRestart(asm)
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

func (c *traceCollector) driveAssembler(ctx context.Context, asm *sessionasm.Assembler, sh *traceship.Shipper) {
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
			c.mu.Lock()
			unparsed, dropped := c.unparsed, c.dropped
			c.unparsed, c.dropped = 0, 0
			c.mu.Unlock()
			if unparsed > 0 {
				sh.AddUnparsed(unparsed)
			}
			if dropped > 0 {
				sh.AddDropped(dropped)
			}
		}
	}
}

// resolveClashSecret reads the Clash API bearer token from the node. The server
// never sends it: for an adopted node the management script writes a 0600 file,
// and for a managed node the token lives in the rendered sing-box config, which
// is already handled as a node-scoped secret-bearing artifact.
func resolveClashSecret(secretPath string, cfg agentConfig) (string, error) {
	if secretPath != "" {
		b, err := os.ReadFile(secretPath)
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	for _, path := range []string{"/etc/sing-box/lattice-clash-api.secret"} {
		if b, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	secret, err := clashSecretFromConfig("/etc/sing-box/config.json")
	if err != nil {
		return "", fmt.Errorf("no Clash API secret found in %s or the sing-box config: %w", secretPath, err)
	}
	return secret, nil
}

func clashSecretFromConfig(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Experimental struct {
			ClashAPI struct {
				Secret string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return "", err
	}
	return strings.TrimSpace(parsed.Experimental.ClashAPI.Secret), nil
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
