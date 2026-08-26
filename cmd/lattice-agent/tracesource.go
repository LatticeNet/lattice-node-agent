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
)

type traceCollector struct {
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
	cancel    context.CancelFunc

	// coreDown latches while sing-box is unreachable so a flapping stream
	// cannot bump the generation more than once per real restart.
	coreDown bool

	unparsed uint64
	dropped  uint64
}

func newTraceCollector(cfg agentConfig) *traceCollector {
	return &traceCollector{cfg: cfg, generation: 1}
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
	now := time.Now().UTC()
	set := tracepolicy.Build(agentCfg, now)

	c.mu.Lock()
	c.policy = set
	enabled := set.Enabled()
	addr := strings.TrimSpace(agentCfg.Policy.ClashAPIAddr)
	secretPath := strings.TrimSpace(agentCfg.Policy.SecretPath)
	cfg := c.cfg
	running := c.cancel != nil
	have := c.haveLevel
	c.mu.Unlock()

	if !enabled || addr == "" {
		c.stop()
		return
	}
	if running && have == set.SubscribeLevel() {
		return
	}
	// Either nothing is running, or the level moved. Both mean a fresh stream,
	// because a Clash API log subscription fixes its level at open time.
	c.stop()
	c.start(ctx, cfg, addr, secretPath, set.SubscribeLevel(), agentCfg.Policy, len(set.ActiveSessions()))
}

func (c *traceCollector) start(ctx context.Context, cfg agentConfig, addr, secretPath string, level model.TraceLevel, pol model.TracePolicy, sessionCount int) {
	secret, err := resolveClashSecret(secretPath, cfg)
	if err != nil {
		log.Printf("trace: cannot read the Clash API secret: %v", err)
		return
	}
	client, err := singboxapi.New(singboxapi.Config{Addr: addr, Secret: secret})
	if err != nil {
		log.Printf("trace: Clash API client: %v", err)
		return
	}

	budget := pol.BudgetLinesPerSec
	if budget <= 0 {
		budget = 500
	}
	// The assembler must start on the SAME generation the collector is counting
	// from, or the records swept by the first restart carry a generation the
	// server never sees again, and the restart marker reports generation zero.
	c.mu.Lock()
	startGeneration := c.generation
	c.mu.Unlock()
	asm := sessionasm.New(sessionasm.Options{NodeID: cfg.NodeID, CoreGeneration: startGeneration})
	shipper := traceship.New(traceship.Config{
		Server: cfg.Server,
		NodeID: cfg.NodeID,
		Token:  cfg.Token,
	})

	streamCtx, cancel := context.WithCancel(ctx)

	c.mu.Lock()
	c.client = client
	c.asm = asm
	c.shipper = shipper
	c.haveLevel = level
	c.cancel = cancel
	generation := c.generation
	coreStart := c.coreStart
	c.mu.Unlock()

	shipper.SetCore(generation, coreStart)

	// Say what changed. An operator raising a node to trace needs to see that
	// the subscription actually moved, and this is the only place that knows
	// the level, the budget and how many sessions are riding on it.
	debugf(cfg, "trace: subscribed to %s at level=%s budget=%d lines/s sessions=%d generation=%d",
		addr, level, budget, sessionCount, generation)

	go shipper.Run(streamCtx)
	go c.pollConnections(streamCtx, client, asm)
	go c.driveAssembler(streamCtx, asm, shipper)
	go c.streamLogs(streamCtx, client, asm, string(level), budget)
}

func (c *traceCollector) stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.haveLevel = ""
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// streamLogs is the hot path. Every kept line is parsed, offered to the
// assembler, and (when a session asked for it) shipped verbatim.
func (c *traceCollector) streamLogs(ctx context.Context, client *singboxapi.Client, asm *sessionasm.Assembler, level string, budgetPerSec int) {
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
		decision := set.Match(line, line.User, line.DstHost)
		if !decision.Keep || len(decision.SessionIDs) == 0 {
			return
		}
		for _, sessionID := range decision.SessionIDs {
			sh.AddLines([]model.TraceLine{{
				SessionID: sessionID,
				NodeID:    nodeID,
				At:        now,
				Level:     line.Level,
				LogID:     line.LogID,
				Tag:       line.Tag,
				Message:   line.Message,
				Raw:       line.Raw,
			}})
		}
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
