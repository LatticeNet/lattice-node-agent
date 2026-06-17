package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/logtail"
	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	logTailFlushInterval = time.Second
	logTailMaxPending    = 50000 // bounded in-memory buffer; overflow drops oldest (counted)
)

// logTailManager keeps one goroutine per assigned log source, each tailing its
// file and shipping line deltas. reconcile is called every poll to start new
// sources, stop removed ones, and restart any whose path/caps changed —
// structurally identical to monitorManager.
type logTailManager struct {
	cfg    agentConfig
	mu     sync.Mutex
	active map[string]*logTailEntry
}

type logTailEntry struct {
	cancel context.CancelFunc
	spec   model.LogSource
}

func newLogTailManager(cfg agentConfig) *logTailManager {
	return &logTailManager{cfg: cfg, active: map[string]*logTailEntry{}}
}

func (m *logTailManager) setConfig(cfg agentConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

func (m *logTailManager) snapshotConfig() agentConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

func (m *logTailManager) reconcile(sources []model.LogSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := make(map[string]model.LogSource, len(sources))
	for _, s := range sources {
		desired[s.ID] = s
	}
	for id, entry := range m.active {
		if d, ok := desired[id]; !ok || logSourceChanged(entry.spec, d) {
			entry.cancel()
			delete(m.active, id)
		}
	}
	for id, s := range desired {
		if _, ok := m.active[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.active[id] = &logTailEntry{cancel: cancel, spec: s}
		go m.run(ctx, s)
	}
}

func logSourceChanged(a, b model.LogSource) bool {
	return a.Path != b.Path || a.MaxLineBytes != b.MaxLineBytes || a.MaxBatchLines != b.MaxBatchLines
}

func (m *logTailManager) run(ctx context.Context, src model.LogSource) {
	tailer := logtail.New(src.Path, src.MaxLineBytes)
	defer tailer.Close()
	ckptPath := m.checkpointPath(src.ID)
	if off, inc, ok := loadLogCheckpoint(ckptPath); ok {
		tailer.Resume(off, inc)
	}
	batchLines := src.MaxBatchLines
	if batchLines <= 0 {
		batchLines = 500
	}
	pending := []string{}
	var dropped uint64
	loggedErr := false

	flush := time.NewTicker(logTailFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
		}
		lines, err := tailer.Poll()
		if err != nil {
			if !loggedErr {
				log.Printf("logtail %s (%s): %v", src.ID, src.Path, err)
				loggedErr = true
			}
			continue
		}
		loggedErr = false
		if len(lines) > 0 {
			pending = append(pending, lines...)
			if len(pending) > logTailMaxPending {
				over := len(pending) - logTailMaxPending
				pending = pending[over:]
				dropped += uint64(over)
			}
		}
		if len(pending) == 0 {
			continue
		}
		for len(pending) > 0 {
			n := len(pending)
			if n > batchLines {
				n = batchLines
			}
			batch := model.LogBatch{
				SourceID:   src.ID,
				Path:       src.Path,
				RotID:      tailer.RotID(),
				LastOff:    tailer.Offset(),
				Dropped:    dropped,
				Lines:      pending[:n],
				CapturedAt: time.Now().UTC(),
			}
			status, err := shipLogBatch(m.snapshotConfig(), batch)
			if err != nil || status != http.StatusOK {
				// Hold position; retry on the next tick. The checkpoint is not
				// advanced, so a restart re-reads from the last shipped offset.
				break
			}
			dropped = 0
			pending = pending[n:]
		}
		if len(pending) == 0 {
			saveLogCheckpoint(ckptPath, tailer.Offset(), tailer.Incarnation())
		}
	}
}

func (m *logTailManager) checkpointPath(sourceID string) string {
	dir := strings.TrimSpace(m.cfg.LogStateDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sourceID+".ckpt")
}

func loadLogCheckpoint(path string) (uint64, int, bool) {
	if path == "" {
		return 0, 0, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	return logtail.ParseCheckpoint(strings.TrimSpace(string(b)))
}

func saveLogCheckpoint(path string, offset uint64, incarnation int) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(logtail.CheckpointString(offset, incarnation)), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func fetchLogSources(cfg agentConfig) ([]model.LogSource, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/log-sources?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log-sources status %d", resp.StatusCode)
	}
	var out struct {
		Sources []model.LogSource `json:"sources"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Sources, nil
}

// shipLogBatch posts one batch and returns the HTTP status so the caller can
// distinguish 429 (hold + retry) from success.
func shipLogBatch(cfg agentConfig, batch model.LogBatch) (int, error) {
	body, err := json.Marshal(map[string]any{"node_id": cfg.NodeID, "batch": batch})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.Server+"/api/agent/logs", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}
