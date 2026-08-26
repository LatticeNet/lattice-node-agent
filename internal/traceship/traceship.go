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
	// dropped and counted. The batch currently on the wire sits outside this
	// bound, so the real ceiling is MaxPending plus one batch: an item being
	// delivered must not be discardable, or it would be counted twice.
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
	// inflightRecords and inflightLines hold the items of the batch currently
	// on the wire. They leave the queues for the duration of the request, so
	// neither an Add nor the capacity trim can reach them. That is what keeps
	// every item counted exactly once: an item discarded under pressure while
	// it was also being delivered would land in both the dropped and the
	// shipped counter, and the operator's total would then correspond to
	// nothing. On failure they go back on the front of the queues. Only a
	// flush cycle touches them, and shipMu allows one cycle at a time, so at
	// most one batch is ever in flight.
	inflightRecords []model.ConnRecord
	inflightLines   []model.TraceLine

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
		batch, ok := s.takeBatch()
		if !ok {
			return nil
		}
		status, retryAfter, err := s.post(ctx, batch)
		if err != nil {
			s.restore()
			s.recordFailure(status, retryAfter, err)
			return err
		}
		s.commit(batch)
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
	pendingRecords := len(s.records) + len(s.inflightRecords)
	pendingLines := len(s.lines) + len(s.inflightLines)
	return Stats{
		Pending:        pendingRecords + pendingLines,
		PendingRecords: pendingRecords,
		PendingLines:   pendingLines,
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
	}
	if dropLines > 0 {
		s.lines = s.lines[dropLines:]
	}
	n := uint64(dropRecords + dropLines)
	s.dropped += n
	s.droppedTotal += n
}

// takeBatch moves the head of each queue into the in-flight slices and builds
// the request from them. Taking the items out of the queue, rather than
// peeking at them, is what makes the delivery window immune to the capacity
// trim that may run while the request is on the wire. It reports false when
// there is nothing to say.
func (s *Shipper) takeBatch() (model.TraceBatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.retryUntil.IsZero() && now.Before(s.retryUntil) {
		return model.TraceBatch{}, false
	}
	recordN := min(len(s.records), s.maxBatchRecords)
	lineN := min(len(s.lines), s.maxBatchLines)
	// Also bound the batch by SIZE, not only by count.
	//
	// Individual lines can be large, so a handful of them can exceed the
	// server's body cap. That produces a permanent 413, and because a failure
	// holds position the same oversized head is retried forever and every item
	// behind it never ships. Trimming to a byte budget keeps the queue moving;
	// a single item that cannot fit on its own is still sent alone, so the
	// server rejects one item rather than the queue wedging on it.
	recordN, lineN = s.trimToByteBudget(recordN, lineN)
	// An empty batch is still worth sending when counters are owed: drops that
	// stopped the flow entirely would otherwise never be reported.
	if recordN == 0 && lineN == 0 && s.dropped == 0 && s.unparsed == 0 {
		return model.TraceBatch{}, false
	}
	batch := model.TraceBatch{
		NodeID:         s.nodeID,
		CoreGeneration: s.coreGeneration,
		CoreStartedAt:  s.coreStartedAt,
		Dropped:        s.dropped,
		Unparsed:       s.unparsed,
		CapturedAt:     now.UTC(),
	}
	if recordN > 0 {
		s.inflightRecords = append([]model.ConnRecord(nil), s.records[:recordN]...)
		s.records = s.records[recordN:]
		batch.Records = s.inflightRecords
	}
	if lineN > 0 {
		s.inflightLines = append([]model.TraceLine(nil), s.lines[:lineN]...)
		s.lines = s.lines[lineN:]
		batch.Lines = s.inflightLines
	}
	return batch, true
}

// restore puts an unacknowledged batch back on the front of the queues, in the
// order it was taken. Holding position is the point: the next tick resends
// exactly these items. Whatever the restore pushes past MaxPending is dropped
// here and counted once, as a drop and only as a drop.
func (s *Shipper) restore() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inflightRecords) > 0 {
		s.records = prepend(s.inflightRecords, s.records)
		s.inflightRecords = nil
	}
	if len(s.inflightLines) > 0 {
		s.lines = prepend(s.inflightLines, s.lines)
		s.inflightLines = nil
	}
	s.trimLocked()
}

// commit releases what the server accepted. It subtracts the counters the
// batch carried rather than zeroing them, because a drop that happened while
// the request was in flight is still owed to the next batch.
func (s *Shipper) commit(batch model.TraceBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shippedRecords += uint64(len(s.inflightRecords))
	s.shippedLines += uint64(len(s.inflightLines))
	s.inflightRecords = nil
	s.inflightLines = nil
	s.dropped = saturatingSub(s.dropped, batch.Dropped)
	s.unparsed = saturatingSub(s.unparsed, batch.Unparsed)
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
	// The wire shape is {node_id, batch}, matching every other agent endpoint
	// (see the server's handleAgentLogs). Sending a bare batch would still
	// authenticate, because TraceBatch carries its own node_id, and the server
	// would then accept an empty batch with 200 OK. That silent success is
	// exactly the failure this subsystem exists to remove, so the envelope is
	// explicit here rather than implied.
	body, err := json.Marshal(struct {
		NodeID string           `json:"node_id"`
		Batch  model.TraceBatch `json:"batch"`
	}{NodeID: s.nodeID, Batch: batch})
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

// prepend returns head followed by tail in a slice of its own, so that putting
// a batch back cannot write into the array the request read from.
func prepend[T any](head, tail []T) []T {
	out := make([]T, 0, len(head)+len(tail))
	out = append(out, head...)
	return append(out, tail...)
}

func saturatingSub(a, b uint64) uint64 {
	if a <= b {
		return 0
	}
	return a - b
}

// maxBatchBytes is the encoded-size budget for one request. It sits well under
// the server's body cap so that JSON overhead cannot push a legal batch over.
const maxBatchBytes = 4 << 20

// trimToByteBudget reduces the head counts until their approximate encoded size
// fits the budget, always leaving at least one item so the queue can drain even
// when a single item is oversized on its own.
func (s *Shipper) trimToByteBudget(recordN, lineN int) (int, int) {
	size := 0
	keptRecords := 0
	for i := 0; i < recordN; i++ {
		r := s.records[i]
		n := len(r.DstHost) + len(r.CloseError) + len(r.RuleText) + len(r.UserName) + 256
		if size+n > maxBatchBytes && keptRecords > 0 {
			break
		}
		size += n
		keptRecords++
	}
	keptLines := 0
	for i := 0; i < lineN; i++ {
		l := s.lines[i]
		n := len(l.Message) + len(l.Raw) + len(l.Tag) + 128
		if size+n > maxBatchBytes && keptRecords+keptLines > 0 {
			break
		}
		size += n
		keptLines++
	}
	return keptRecords, keptLines
}
