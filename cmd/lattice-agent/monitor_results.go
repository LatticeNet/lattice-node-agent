package main

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Monitor results are queued and sent in batches on POST
// /api/agent/monitor-results ({"node_id", "results": [...]}, 1 to 500
// entries). A batch answer is final for every result in it: accepted,
// duplicate (the pair already holds that instant, so a resend after a lost
// response is safe) or dropped with a reason. A 5xx stores nothing, so the
// batch is sent again. A server without the batch route answers 404, and the
// agent falls back to one result per request on the single route, retrying
// the batch route now and then in case the server was upgraded.
//
// The queue is the outage buffer: while the control plane is unreachable
// probe results keep accumulating, oldest first, up to monitorResultQueueMax.
// Past that the oldest are dropped and counted; the server refuses results
// stamped more than 24 hours before they arrive in any case.
const (
	monitorResultQueueMax     = 2000
	monitorResultBatchMax     = 200
	monitorResultFlushBatches = 5
	monitorResultFlushTimeout = 20 * time.Second
	monitorBatchReprobe       = 30 * time.Minute
	monitorResultsBatchPath   = "/api/agent/monitor-results"
	monitorResultSinglePath   = "/api/agent/monitor-result"
)

type queuedMonitorResult struct {
	seq    uint64
	result model.MonitorResult
}

type monitorResultsAnswer struct {
	OK         bool `json:"ok"`
	Accepted   int  `json:"accepted"`
	Duplicates int  `json:"duplicates"`
	Dropped    []struct {
		Index     int    `json:"index"`
		MonitorID string `json:"monitor_id"`
		Reason    string `json:"reason"`
	} `json:"dropped"`
}

type monitorResultQueue struct {
	mu      sync.Mutex
	now     func() time.Time
	items   []queuedMonitorResult
	nextSeq uint64
	dropped uint64
	// batchOffUntil is when the batch route is tried again after a 404.
	batchOffUntil time.Time
	// flushMu keeps one flush in flight, so two cannot send the same head.
	flushMu sync.Mutex
	post    func(ctx context.Context, cfg agentConfig, path string, payload map[string]any, out any) error
}

func newMonitorResultQueue() *monitorResultQueue {
	return &monitorResultQueue{now: time.Now, post: postAgentJSONContext}
}

func (q *monitorResultQueue) push(r model.MonitorResult) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nextSeq++
	q.items = append(q.items, queuedMonitorResult{seq: q.nextSeq, result: r})
	if over := len(q.items) - monitorResultQueueMax; over > 0 {
		q.items = append(q.items[:0:0], q.items[over:]...)
		q.dropped += uint64(over)
	}
}

func (q *monitorResultQueue) stats() (queued int, dropped uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items), q.dropped
}

// head copies up to n of the oldest results.
func (q *monitorResultQueue) head(n int) []queuedMonitorResult {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n > len(q.items) {
		n = len(q.items)
	}
	return append([]queuedMonitorResult(nil), q.items[:n]...)
}

// settle removes every result up to and including seq. Sequence numbers keep
// this correct when overflow dropped part of the head while a send was in
// flight.
func (q *monitorResultQueue) settle(seq uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := 0
	for i < len(q.items) && q.items[i].seq <= seq {
		i++
	}
	if i > 0 {
		q.items = append(q.items[:0:0], q.items[i:]...)
	}
}

func (q *monitorResultQueue) batchAllowed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.now().Before(q.batchOffUntil)
}

func (q *monitorResultQueue) disableBatch() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.batchOffUntil = q.now().Add(monitorBatchReprobe)
}

// flush sends queued results, oldest first, until the queue is empty, a send
// fails, or monitorResultFlushBatches batches went out in this call.
func (q *monitorResultQueue) flush(ctx context.Context, cfg agentConfig) error {
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	for i := 0; i < monitorResultFlushBatches; i++ {
		batch := q.head(monitorResultBatchMax)
		if len(batch) == 0 {
			return nil
		}
		if q.batchAllowed() {
			err := q.sendBatch(ctx, cfg, batch)
			if err == nil {
				continue
			}
			if code, ok := agentHTTPStatusCode(err); !ok || code != http.StatusNotFound {
				return err
			}
			q.disableBatch()
			debugf(cfg, "monitor result batch route missing (404); posting one result per request for %s", monitorBatchReprobe)
		}
		if err := q.sendSingles(ctx, cfg, batch); err != nil {
			return err
		}
	}
	return nil
}

func (q *monitorResultQueue) sendBatch(ctx context.Context, cfg agentConfig, batch []queuedMonitorResult) error {
	results := make([]model.MonitorResult, len(batch))
	for i, item := range batch {
		results[i] = item.result
	}
	var answer monitorResultsAnswer
	err := q.post(ctx, cfg, monitorResultsBatchPath, map[string]any{"results": results}, &answer)
	if err != nil {
		if code, ok := agentHTTPStatusCode(err); ok && code == http.StatusBadRequest {
			// The server refused the batch as a whole and stored nothing.
			// Sending the same bytes again cannot succeed, so it is dropped
			// rather than left to block every later result.
			q.settle(batch[len(batch)-1].seq)
			log.Printf("monitor results: server refused a batch of %d, dropped: %v", len(batch), err)
			return nil
		}
		return err
	}
	q.settle(batch[len(batch)-1].seq)
	for _, d := range answer.Dropped {
		debugf(cfg, "monitor result dropped by server: index=%d monitor=%s reason=%s", d.Index, d.MonitorID, d.Reason)
	}
	debugf(cfg, "monitor results sent: batch=%d accepted=%d duplicates=%d dropped=%d", len(batch), answer.Accepted, answer.Duplicates, len(answer.Dropped))
	return nil
}

// sendSingles posts one result per request, the only shape older servers
// accept. A 4xx on one result is final for it; anything else stops the
// flush and keeps the rest queued.
func (q *monitorResultQueue) sendSingles(ctx context.Context, cfg agentConfig, batch []queuedMonitorResult) error {
	for _, item := range batch {
		err := q.post(ctx, cfg, monitorResultSinglePath, map[string]any{"result": item.result}, nil)
		if err != nil {
			code, ok := agentHTTPStatusCode(err)
			if !ok || code >= 500 || code == http.StatusUnauthorized || code == http.StatusTooManyRequests {
				return err
			}
			log.Printf("monitor %s report refused, dropped: %v", item.result.MonitorID, err)
		}
		q.settle(item.seq)
	}
	return nil
}

// flushLoop sends queued results every agent interval until ctx ends.
func (mm *monitorManager) flushLoop(ctx context.Context) {
	interval := mm.snapshotConfig().Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg := mm.snapshotConfig()
		flushCtx, cancel := context.WithTimeout(ctx, monitorResultFlushTimeout)
		if err := mm.results.flush(flushCtx, cfg); err != nil {
			queued, _ := mm.results.stats()
			log.Printf("monitor results report error (%d queued): %v", queued, err)
		}
		cancel()
	}
}
