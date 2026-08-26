// Package traceship batches connection records and trace lines and ships them
// to the server.
//
// It follows the shape of the agent's log tailer on purpose: one flush ticker,
// a bounded in-memory queue that sheds the oldest under pressure and counts
// what it shed, and a failed ship that holds position instead of discarding.
// The counts ride along in the next batch, so a node that lost data says so.
// Silent loss is the specific failure this feature cannot afford, because a
// trace that quietly dropped half its lines reads exactly like a quiet
// network, which is the thing the operator was trying to rule out.
package traceship

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	defaultMaxBatchRecords = 200
	defaultMaxBatchLines   = 500
	defaultMaxPending      = 5000
	defaultFlushInterval   = time.Second
	defaultHTTPTimeout     = 30 * time.Second
	// maxBackoff bounds the wait after a 429 without a Retry-After header. A
	// node that backs off further than this stops being useful for tailing.
	maxBackoff = time.Minute
	// errBodyLimit keeps a rejection's own words in the log without letting a
	// misbehaving server write the agent's log for it.
	errBodyLimit = 512
)

// Config is the shipper's wiring. The zero value of every tunable falls back
// to the constant above it, so a caller only sets what it means to change.
type Config struct {
	Server string
	NodeID string
	Token  string

	HTTPClient *http.Client
	// MaxBatchRecords and MaxBatchLines split an oversized queue across several
	// requests rather than sending one body the server has to refuse whole.
	MaxBatchRecords int
	MaxBatchLines   int
	// MaxPending bounds records plus lines together. Over it, the oldest are
	// dropped and counted.
	MaxPending    int
	FlushInterval time.Duration
	// Now is the clock, injectable so backoff can be tested without sleeping.
	Now func() time.Time
}

// Stats is a snapshot for the caller's own reporting. Dropped and Unparsed are
// the counts still owed to the server; the Total fields are what this process
// has seen since it started.
type Stats struct {
	Pending        int
	PendingRecords int
	PendingLines   int

	ShippedRecords uint64
	ShippedLines   uint64
	ShippedBatches uint64

	Dropped       uint64
	DroppedTotal  uint64
	Unparsed      uint64
	UnparsedTotal uint64

	LastError   string
	LastSuccess time.Time
}

// Shipper is safe for concurrent use: the assembler goroutine calls the Add
// methods while the flush loop ships.
type Shipper struct {
	server          string
	nodeID          string
	token           string
	client          *http.Client
	maxBatchRecords int
	maxBatchLines   int
	maxPending      int
	flushInterval   time.Duration
	now             func() time.Time

	// shipMu serialises whole flush cycles, so two callers cannot ship the same
	// pending items twice. It is never held while mu is taken for a queue edit.
	shipMu sync.Mutex

	mu      sync.Mutex
	records []model.ConnRecord
	lines   []model.TraceLine
	// recordsBase and linesBase are the absolute index of the queue head. A
	// request runs without the lock held, so items can be dropped from the
	// front while it is in flight; the absolute positions are what let the
	// commit remove exactly the shipped items and nothing else.
	recordsBase uint64
	linesBase   uint64

	coreGeneration uint64
	coreStartedAt  time.Time

	dropped       uint64
	droppedTotal  uint64
	unparsed      uint64
	unparsedTotal uint64

	shippedRecords uint64
	shippedLines   uint64
	shippedBatches uint64

	lastError   string
	lastSuccess time.Time
	// loggedShipErr keeps a broken control plane from filling the node's log
	// with one line per second. The first failure is logged and the rest stay
	// quiet until it recovers.
	loggedShipErr   bool
	retryUntil      time.Time
	backoffFailures int
}

// pendingBatch is one request together with where its items sat in the queue.
type pendingBatch struct {
	batch     model.TraceBatch
	recordEnd uint64
	lineEnd   uint64
}

// New builds a shipper. It does not start anything; call Run for the flush
// loop or Flush to ship once.
func New(cfg Config) *Shipper {
	s := &Shipper{
		server:          strings.TrimRight(strings.TrimSpace(cfg.Server), "/"),
		nodeID:          strings.TrimSpace(cfg.NodeID),
		token:           cfg.Token,
		client:          cfg.HTTPClient,
		maxBatchRecords: cfg.MaxBatchRecords,
		maxBatchLines:   cfg.MaxBatchLines,
		maxPending:      cfg.MaxPending,
		flushInterval:   cfg.FlushInterval,
		now:             cfg.Now,
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if s.maxBatchRecords <= 0 {
		s.maxBatchRecords = defaultMaxBatchRecords
	}
	if s.maxBatchLines <= 0 {
		s.maxBatchLines = defaultMaxBatchLines
	}
	if s.maxPending <= 0 {
		s.maxPending = defaultMaxPending
	}
	if s.flushInterval <= 0 {
		s.flushInterval = defaultFlushInterval
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// AddRecords queues assembled connection records.
func (s *Shipper) AddRecords(rs []model.ConnRecord) {
	if len(rs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rs...)
	s.trimLocked()
}

// AddLines queues raw lines a session asked to keep.
func (s *Shipper) AddLines(ls []model.TraceLine) {
	if len(ls) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, ls...)
	s.trimLocked()
}

// SetCore records which sing-box generation the queued data came from. The
// server needs it to detect a restart even when it missed the records that the
// restart swept.
func (s *Shipper) SetCore(generation uint64, startedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.coreGeneration = generation
	s.coreStartedAt = startedAt
}

// AddUnparsed counts lines the parser could not read. A rising number means
// sing-box changed its format, which is the failure most easily mistaken for
// nothing happening, so it travels with the data rather than staying local.
func (s *Shipper) AddUnparsed(n uint64) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unparsed += n
	s.unparsedTotal += n
}

// AddDropped counts lines discarded BEFORE they reached this shipper, which is
// what the collector does when a node exceeds its per-second ingest budget. It
// is the same kind of loss as an over-capacity drop here and belongs in the same
// counter: the operator needs one number for "lines this node did not keep",
// not two that have to be added up correctly to notice a gap.
func (s *Shipper) AddDropped(n uint64) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropped += n
	s.droppedTotal += n
}

// Flush ships what is pending, splitting it across as many requests as the
// batch caps require, and stops at the first failure with everything still
// queued. It is a no-op while a 429 backoff is in effect.
func (s *Shipper) Flush(ctx context.Context) error {
	s.shipMu.Lock()
	defer s.shipMu.Unlock()
	for {
		pb, ok := s.nextBatch()
		if !ok {
			return nil
		}
		status, retryAfter, err := s.post(ctx, pb.batch)
		if err != nil {
			s.recordFailure(status, retryAfter, err)
			return err
		}
		s.commit(pb)
	}
}

// Run flushes on a ticker until ctx is done. A failed flush is not an error
// here: the items stay queued and the next tick retries them.
func (s *Shipper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = s.Flush(ctx)
	}
}

// Stats returns a snapshot of the queue and the counters.
func (s *Shipper) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Pending:        len(s.records) + len(s.lines),
		PendingRecords: len(s.records),
		PendingLines:   len(s.lines),
		ShippedRecords: s.shippedRecords,
		ShippedLines:   s.shippedLines,
		ShippedBatches: s.shippedBatches,
		Dropped:        s.dropped,
		DroppedTotal:   s.droppedTotal,
		Unparsed:       s.unparsed,
		UnparsedTotal:  s.unparsedTotal,
		LastError:      s.lastError,
		LastSuccess:    s.lastSuccess,
	}
}

// trimLocked enforces MaxPending by dropping the oldest. Lines go first when
// both queues are equally long: a raw line is evidence for a record, but a
// dropped record is a row the operator can never rebuild.
func (s *Shipper) trimLocked() {
	over := len(s.records) + len(s.lines) - s.maxPending
	if over <= 0 {
		return
	}
	dropRecords, dropLines := 0, 0
	for over > 0 {
		remainingRecords := len(s.records) - dropRecords
		remainingLines := len(s.lines) - dropLines
		if remainingRecords == 0 && remainingLines == 0 {
			break
		}
		if remainingLines >= remainingRecords {
			dropLines++
		} else {
			dropRecords++
		}
		over--
	}
	if dropRecords > 0 {
		s.records = s.records[dropRecords:]
		s.recordsBase += uint64(dropRecords)
	}
	if dropLines > 0 {
		s.lines = s.lines[dropLines:]
		s.linesBase += uint64(dropLines)
	}
	n := uint64(dropRecords + dropLines)
	s.dropped += n
	s.droppedTotal += n
}

// nextBatch takes the head of each queue without removing it, so a failed ship
// holds position. It reports false when there is nothing to say.
func (s *Shipper) nextBatch() (pendingBatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.retryUntil.IsZero() && now.Before(s.retryUntil) {
		return pendingBatch{}, false
	}
	recordN := min(len(s.records), s.maxBatchRecords)
	lineN := min(len(s.lines), s.maxBatchLines)
	// An empty batch is still worth sending when counters are owed: drops that
	// stopped the flow entirely would otherwise never be reported.
	if recordN == 0 && lineN == 0 && s.dropped == 0 && s.unparsed == 0 {
		return pendingBatch{}, false
	}
	pb := pendingBatch{
		batch: model.TraceBatch{
			NodeID:         s.nodeID,
			CoreGeneration: s.coreGeneration,
			CoreStartedAt:  s.coreStartedAt,
			Dropped:        s.dropped,
			Unparsed:       s.unparsed,
			CapturedAt:     now.UTC(),
		},
		recordEnd: s.recordsBase + uint64(recordN),
		lineEnd:   s.linesBase + uint64(lineN),
	}
	if recordN > 0 {
		pb.batch.Records = append([]model.ConnRecord(nil), s.records[:recordN]...)
	}
	if lineN > 0 {
		pb.batch.Lines = append([]model.TraceLine(nil), s.lines[:lineN]...)
	}
	return pb, true
}

// commit removes what the server accepted. It subtracts the counters the batch
// carried rather than zeroing them, because a drop that happened while the
// request was in flight is still owed to the next batch.
func (s *Shipper) commit(pb pendingBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pb.recordEnd > s.recordsBase {
		n := min(int(pb.recordEnd-s.recordsBase), len(s.records))
		s.records = s.records[n:]
		s.recordsBase += uint64(n)
	}
	if pb.lineEnd > s.linesBase {
		n := min(int(pb.lineEnd-s.linesBase), len(s.lines))
		s.lines = s.lines[n:]
		s.linesBase += uint64(n)
	}
	s.dropped = saturatingSub(s.dropped, pb.batch.Dropped)
	s.unparsed = saturatingSub(s.unparsed, pb.batch.Unparsed)
	s.shippedRecords += uint64(len(pb.batch.Records))
	s.shippedLines += uint64(len(pb.batch.Lines))
	s.shippedBatches++
	s.lastSuccess = s.now().UTC()
	s.lastError = ""
	s.loggedShipErr = false
	s.retryUntil = time.Time{}
	s.backoffFailures = 0
}

func (s *Shipper) recordFailure(status int, retryAfter time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = err.Error()
	if status == http.StatusTooManyRequests {
		s.backoffFailures++
		wait := retryAfter
		if wait <= 0 {
			wait = backoffFor(s.backoffFailures, s.flushInterval)
		}
		s.retryUntil = s.now().Add(wait)
	}
	if !s.loggedShipErr {
		log.Printf("traceship %s: ship failed: %v", s.nodeID, err)
		s.loggedShipErr = true
	}
}

// post sends one batch and returns the status so the caller can tell a 429
// apart from every other refusal.
func (s *Shipper) post(ctx context.Context, batch model.TraceBatch) (int, time.Duration, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return 0, 0, fmt.Errorf("encode trace batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server+"/api/agent/trace", bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("ship trace batch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), s.now())
		return resp.StatusCode, retryAfter, fmt.Errorf("ship trace batch: %s%s", resp.Status, errorSnippet(resp.Body))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, 0, nil
}

// parseRetryAfter reads the header in either of its two legal forms. A value
// that is neither is ignored, and the caller backs off on its own schedule.
func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// backoffFor doubles per consecutive refusal, from the flush interval up to
// maxBackoff.
func backoffFor(failures int, base time.Duration) time.Duration {
	if base <= 0 {
		base = defaultFlushInterval
	}
	wait := base
	for i := 1; i < failures && wait < maxBackoff; i++ {
		wait *= 2
	}
	if wait > maxBackoff {
		wait = maxBackoff
	}
	return wait
}

// errorSnippet keeps the server's own explanation of a rejection, collapsed to
// one line and bounded.
func errorSnippet(r io.Reader) string {
	body, _ := io.ReadAll(io.LimitReader(r, errBodyLimit))
	text := strings.Join(strings.Fields(string(body)), " ")
	if text == "" {
		return ""
	}
	return ": " + text
}

func saturatingSub(a, b uint64) uint64 {
	if a <= b {
		return 0
	}
	return a - b
}
