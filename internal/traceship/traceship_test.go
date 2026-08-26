package traceship

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type recordedRequest struct {
	path        string
	auth        string
	contentType string
	batch       model.TraceBatch
}

type recorder struct {
	mu       sync.Mutex
	requests []recordedRequest
	// respond decides the reply for the nth request (1 based). A nil respond,
	// or one that writes nothing, means 200.
	respond func(n int, w http.ResponseWriter) bool
}

func (r *recorder) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, req *http.Request) {
		// Decode the same envelope the server does. Decoding a bare TraceBatch
		// here would still "work" and would hide a shape mismatch, which is how
		// this went unnoticed the first time: the server accepted the wrong
		// shape with 200 OK and zero records.
		var envelope struct {
			NodeID string           `json:"node_id"`
			Batch  model.TraceBatch `json:"batch"`
		}
		if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
			t.Errorf("decode batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if envelope.NodeID == "" {
			t.Error("envelope node_id is empty; the server authenticates on it")
		}
		batch := envelope.Batch
		r.mu.Lock()
		r.requests = append(r.requests, recordedRequest{
			path:        req.URL.Path,
			auth:        req.Header.Get("Authorization"),
			contentType: req.Header.Get("Content-Type"),
			batch:       batch,
		})
		n := len(r.requests)
		respond := r.respond
		r.mu.Unlock()
		if respond != nil && respond(n, w) {
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

func (r *recorder) at(t *testing.T, i int) recordedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.requests) {
		t.Fatalf("request %d not made; only %d so far", i, len(r.requests))
	}
	return r.requests[i]
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newShipper(t *testing.T, rec *recorder, mutate func(*Config)) *Shipper {
	t.Helper()
	srv := httptest.NewServer(rec.handler(t))
	t.Cleanup(srv.Close)
	cfg := Config{
		Server:        srv.URL,
		NodeID:        "node-a",
		Token:         "tok",
		FlushInterval: 5 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

func records(logIDs ...uint32) []model.ConnRecord {
	out := make([]model.ConnRecord, 0, len(logIDs))
	for _, id := range logIDs {
		out = append(out, model.ConnRecord{NodeID: "node-a", LogID: id})
	}
	return out
}

func lines(seqs ...uint64) []model.TraceLine {
	out := make([]model.TraceLine, 0, len(seqs))
	for _, seq := range seqs {
		out = append(out, model.TraceLine{SessionID: "s1", NodeID: "node-a", Seq: seq, Message: fmt.Sprintf("line %d", seq)})
	}
	return out
}

func recordIDs(rs []model.ConnRecord) []uint32 {
	out := make([]uint32, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.LogID)
	}
	return out
}

func lineSeqs(ls []model.TraceLine) []uint64 {
	out := make([]uint64, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Seq)
	}
	return out
}

func equalUint32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalUint64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFlushSuccessShipsAndClearsPending(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, nil)
	coreStart := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	s.SetCore(7, coreStart)
	s.AddRecords(records(1, 2))
	s.AddLines(lines(1, 2, 3))
	s.AddUnparsed(4)

	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("requests = %d, want 1", rec.count())
	}
	req := rec.at(t, 0)
	if req.path != "/api/agent/trace" {
		t.Fatalf("path = %q", req.path)
	}
	if req.auth != "Bearer tok" {
		t.Fatalf("authorization = %q", req.auth)
	}
	if req.contentType != "application/json" {
		t.Fatalf("content type = %q", req.contentType)
	}
	if req.batch.NodeID != "node-a" || req.batch.CoreGeneration != 7 || !req.batch.CoreStartedAt.Equal(coreStart) {
		t.Fatalf("batch identity wrong: %+v", req.batch)
	}
	if req.batch.Unparsed != 4 || req.batch.Dropped != 0 {
		t.Fatalf("counters = unparsed %d dropped %d", req.batch.Unparsed, req.batch.Dropped)
	}
	if req.batch.CapturedAt.IsZero() {
		t.Fatal("captured at is zero")
	}
	if !equalUint32(recordIDs(req.batch.Records), []uint32{1, 2}) || !equalUint64(lineSeqs(req.batch.Lines), []uint64{1, 2, 3}) {
		t.Fatalf("batch payload wrong: %+v", req.batch)
	}

	st := s.Stats()
	if st.Pending != 0 || st.PendingRecords != 0 || st.PendingLines != 0 {
		t.Fatalf("pending after success: %+v", st)
	}
	if st.ShippedRecords != 2 || st.ShippedLines != 3 || st.ShippedBatches != 1 {
		t.Fatalf("shipped counters: %+v", st)
	}
	if st.Unparsed != 0 || st.UnparsedTotal != 4 {
		t.Fatalf("unparsed counters: %+v", st)
	}
	if st.LastError != "" || st.LastSuccess.IsZero() {
		t.Fatalf("status fields: %+v", st)
	}

	// Nothing pending and nothing owed: no request at all.
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("requests = %d, want no second request", rec.count())
	}
}

func TestFlushHoldsPositionAndResendsTheSameItems(t *testing.T) {
	rec := &recorder{respond: func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("store unavailable"))
			return true
		}
		return false
	}}
	s := newShipper(t, rec, nil)
	s.AddRecords(records(11, 12))
	s.AddLines(lines(21))

	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected an error from the 500")
	}
	st := s.Stats()
	if st.PendingRecords != 2 || st.PendingLines != 1 {
		t.Fatalf("failed ship must hold position: %+v", st)
	}
	if st.ShippedBatches != 0 || st.ShippedRecords != 0 || st.ShippedLines != 0 {
		t.Fatalf("failed ship advanced a counter: %+v", st)
	}
	if st.LastError == "" || !st.LastSuccess.IsZero() {
		t.Fatalf("status fields after failure: %+v", st)
	}

	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("requests = %d, want 2", rec.count())
	}
	first, second := rec.at(t, 0), rec.at(t, 1)
	if !equalUint32(recordIDs(first.batch.Records), []uint32{11, 12}) {
		t.Fatalf("first attempt payload: %v", recordIDs(first.batch.Records))
	}
	if !equalUint32(recordIDs(second.batch.Records), recordIDs(first.batch.Records)) {
		t.Fatalf("retry sent %v, want the same %v", recordIDs(second.batch.Records), recordIDs(first.batch.Records))
	}
	if !equalUint64(lineSeqs(second.batch.Lines), lineSeqs(first.batch.Lines)) {
		t.Fatalf("retry sent lines %v, want %v", lineSeqs(second.batch.Lines), lineSeqs(first.batch.Lines))
	}
	st = s.Stats()
	if st.Pending != 0 || st.ShippedRecords != 2 || st.ShippedLines != 1 || st.LastError != "" {
		t.Fatalf("stats after recovery: %+v", st)
	}
}

func TestFlushHonoursRetryAfterOn429(t *testing.T) {
	rec := &recorder{respond: func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		}
		return false
	}}
	clock := &fakeClock{t: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)}
	s := newShipper(t, rec, func(cfg *Config) {
		cfg.Now = clock.now
		cfg.FlushInterval = time.Second
	})
	s.AddRecords(records(1, 2))

	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected an error from the 429")
	}
	if st := s.Stats(); st.PendingRecords != 2 {
		t.Fatalf("429 must hold position: %+v", st)
	}

	// Inside the window the shipper stays off the wire entirely.
	clock.advance(59 * time.Second)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush during backoff: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("requests = %d, want no request during the Retry-After window", rec.count())
	}

	clock.advance(2 * time.Second)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush after backoff: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("requests = %d, want 2 after the window", rec.count())
	}
	if !equalUint32(recordIDs(rec.at(t, 1).batch.Records), []uint32{1, 2}) {
		t.Fatalf("resent payload: %v", recordIDs(rec.at(t, 1).batch.Records))
	}
	if st := s.Stats(); st.Pending != 0 || st.ShippedRecords != 2 {
		t.Fatalf("stats after recovery: %+v", st)
	}
}

func TestFlush429WithoutRetryAfterBacksOff(t *testing.T) {
	rec := &recorder{respond: func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		}
		return false
	}}
	clock := &fakeClock{t: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)}
	s := newShipper(t, rec, func(cfg *Config) {
		cfg.Now = clock.now
		cfg.FlushInterval = 2 * time.Second
	})
	s.AddLines(lines(1))

	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("expected an error from the 429")
	}
	clock.advance(time.Second)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush during backoff: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("requests = %d, want the default backoff to hold", rec.count())
	}
	clock.advance(2 * time.Second)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush after backoff: %v", err)
	}
	if rec.count() != 2 {
		t.Fatalf("requests = %d, want 2 after the backoff", rec.count())
	}
}

func TestOverCapacityDropsOldestAndReportsIt(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, func(cfg *Config) { cfg.MaxPending = 4 })
	s.AddRecords(records(1, 2, 3))
	s.AddLines(lines(1, 2, 3))

	st := s.Stats()
	if st.Pending != 4 || st.Dropped != 2 || st.DroppedTotal != 2 {
		t.Fatalf("capacity trim: %+v", st)
	}

	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	batch := rec.at(t, 0).batch
	if batch.Dropped != 2 {
		t.Fatalf("dropped = %d, want 2 riding along in the batch", batch.Dropped)
	}
	// The oldest of each queue went, so the survivors are the newest.
	if !equalUint32(recordIDs(batch.Records), []uint32{2, 3}) {
		t.Fatalf("records = %v, want the newest two", recordIDs(batch.Records))
	}
	if !equalUint64(lineSeqs(batch.Lines), []uint64{2, 3}) {
		t.Fatalf("lines = %v, want the newest two", lineSeqs(batch.Lines))
	}

	st = s.Stats()
	if st.Dropped != 0 || st.DroppedTotal != 2 {
		t.Fatalf("dropped must reset only after the batch carrying it succeeded: %+v", st)
	}

	s.AddRecords(records(4))
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if got := rec.at(t, 1).batch.Dropped; got != 0 {
		t.Fatalf("second batch dropped = %d, want 0", got)
	}
}

func TestDropsAreReportedEvenWithNothingPending(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, nil)
	s.AddUnparsed(9)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	batch := rec.at(t, 0).batch
	if len(batch.Records) != 0 || len(batch.Lines) != 0 {
		t.Fatalf("expected an empty payload: %+v", batch)
	}
	if batch.Unparsed != 9 {
		t.Fatalf("unparsed = %d, want 9", batch.Unparsed)
	}
	if st := s.Stats(); st.Unparsed != 0 || st.UnparsedTotal != 9 {
		t.Fatalf("unparsed counters: %+v", st)
	}
}

func TestFlushSplitsOversizedPayload(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, func(cfg *Config) {
		cfg.MaxBatchRecords = 2
		cfg.MaxBatchLines = 3
	})
	s.AddRecords(records(1, 2, 3, 4, 5))
	s.AddLines(lines(1, 2, 3, 4, 5, 6, 7))

	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec.count() != 3 {
		t.Fatalf("requests = %d, want 3", rec.count())
	}
	wantRecords := [][]uint32{{1, 2}, {3, 4}, {5}}
	wantLines := [][]uint64{{1, 2, 3}, {4, 5, 6}, {7}}
	for i := range 3 {
		batch := rec.at(t, i).batch
		if !equalUint32(recordIDs(batch.Records), wantRecords[i]) {
			t.Fatalf("batch %d records = %v, want %v", i, recordIDs(batch.Records), wantRecords[i])
		}
		if !equalUint64(lineSeqs(batch.Lines), wantLines[i]) {
			t.Fatalf("batch %d lines = %v, want %v", i, lineSeqs(batch.Lines), wantLines[i])
		}
	}
	if st := s.Stats(); st.Pending != 0 || st.ShippedRecords != 5 || st.ShippedLines != 7 || st.ShippedBatches != 3 {
		t.Fatalf("stats after split: %+v", st)
	}
}

func TestRunFlushesAndStopsOnContextCancel(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, nil)
	s.AddRecords(records(1))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	deadline := time.After(2 * time.Second)
	for s.Stats().ShippedBatches == 0 {
		select {
		case <-deadline:
			t.Fatal("Run never shipped the pending record")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return promptly after cancel")
	}
}

func TestConcurrentAddsAndFlushes(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, func(cfg *Config) { cfg.MaxPending = 64 })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()

	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func(base uint32) {
			defer wg.Done()
			for i := range uint32(50) {
				s.AddRecords(records(base*100 + i))
				s.AddLines(lines(uint64(base*100 + i)))
				s.AddUnparsed(1)
				s.SetCore(uint64(base), time.Unix(int64(base), 0).UTC())
				_ = s.Stats()
			}
		}(uint32(w))
	}
	wg.Wait()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("final flush: %v", err)
	}
	cancel()
	<-done

	st := s.Stats()
	// Every record either shipped or was counted as dropped; nothing vanishes
	// without being counted somewhere.
	if total := st.ShippedRecords + st.ShippedLines + st.DroppedTotal; total != 400 {
		t.Fatalf("shipped %d records, %d lines, dropped %d; want 400 accounted for", st.ShippedRecords, st.ShippedLines, st.DroppedTotal)
	}
	if st.Pending != 0 {
		t.Fatalf("pending after the final flush: %+v", st)
	}
}

func TestAddIgnoresEmptyInput(t *testing.T) {
	rec := &recorder{}
	s := newShipper(t, rec, nil)
	s.AddRecords(nil)
	s.AddLines(nil)
	s.AddUnparsed(0)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("requests = %d, want none", rec.count())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"30", 30 * time.Second},
		{" 30 ", 30 * time.Second},
		{"0", 0},
		{"-5", 0},
		{"not a number", 0},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			if got := parseRetryAfter(tc.header, now); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestBackoffForDoublesAndCaps(t *testing.T) {
	cases := []struct {
		failures int
		base     time.Duration
		want     time.Duration
	}{
		{1, time.Second, time.Second},
		{2, time.Second, 2 * time.Second},
		{4, time.Second, 8 * time.Second},
		{20, time.Second, maxBackoff},
		{1, 0, defaultFlushInterval},
	}
	for _, tc := range cases {
		if got := backoffFor(tc.failures, tc.base); got != tc.want {
			t.Fatalf("backoffFor(%d, %v) = %v, want %v", tc.failures, tc.base, got, tc.want)
		}
	}
}

func TestDropPressureDuringInFlightShipCountsEachItemOnce(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	rec := &recorder{respond: func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			close(started)
			<-release
		}
		return false
	}}
	s := newShipper(t, rec, func(cfg *Config) {
		cfg.MaxPending = 4
		cfg.MaxBatchRecords = 4
	})
	s.AddRecords(records(1, 2, 3, 4))

	errc := make(chan error, 1)
	go func() { errc <- s.Flush(context.Background()) }()
	<-started
	// Eight more arrive while the first four are on the wire. Four of them do
	// not fit and are dropped; the four being delivered must not be touched,
	// because an item counted as dropped while it is also being shipped lands
	// in both counters and the operator's total then means nothing.
	s.AddRecords(records(5, 6, 7, 8, 9, 10, 11, 12))
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("flush: %v", err)
	}

	if rec.count() != 2 {
		t.Fatalf("requests = %d, want 2", rec.count())
	}
	first, second := rec.at(t, 0).batch, rec.at(t, 1).batch
	if got := recordIDs(first.Records); !equalUint32(got, []uint32{1, 2, 3, 4}) {
		t.Fatalf("first batch = %v, want the four that were in flight", got)
	}
	if first.Dropped != 0 {
		t.Fatalf("first batch dropped = %d, want 0: the drop happened after it was built", first.Dropped)
	}
	if got := recordIDs(second.Records); !equalUint32(got, []uint32{9, 10, 11, 12}) {
		t.Fatalf("second batch = %v, want the newest four", got)
	}
	if second.Dropped != 4 {
		t.Fatalf("second batch dropped = %d, want 4", second.Dropped)
	}

	st := s.Stats()
	if st.ShippedRecords != 8 || st.DroppedTotal != 4 {
		t.Fatalf("shipped %d, dropped %d; want 8 and 4", st.ShippedRecords, st.DroppedTotal)
	}
	if total := st.ShippedRecords + st.DroppedTotal + uint64(st.Pending); total != 12 {
		t.Fatalf("accounted for %d of the 12 items added", total)
	}
	if st.Pending != 0 || st.Dropped != 0 {
		t.Fatalf("final stats: %+v", st)
	}
}

func TestDropPressureDuringFailedShipRestoresAndCountsOnce(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	rec := &recorder{respond: func(n int, w http.ResponseWriter) bool {
		if n == 1 {
			close(started)
			<-release
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		return false
	}}
	s := newShipper(t, rec, func(cfg *Config) {
		cfg.MaxPending = 4
		cfg.MaxBatchRecords = 4
	})
	s.AddRecords(records(1, 2, 3, 4))

	errc := make(chan error, 1)
	go func() { errc <- s.Flush(context.Background()) }()
	<-started
	s.AddRecords(records(5, 6, 7, 8, 9, 10, 11, 12))
	close(release)
	if err := <-errc; err == nil {
		t.Fatal("expected an error from the 500")
	}

	// The failed batch went back on the front of the queue, which put the
	// queue over capacity, so the oldest four went as a drop and only as a
	// drop. Nothing shipped, nothing is owed twice.
	st := s.Stats()
	if st.ShippedRecords != 0 || st.ShippedBatches != 0 {
		t.Fatalf("failed ship advanced a shipped counter: %+v", st)
	}
	if st.DroppedTotal != 8 || st.PendingRecords != 4 {
		t.Fatalf("dropped %d, pending %d; want 8 and 4", st.DroppedTotal, st.PendingRecords)
	}
	if total := st.ShippedRecords + st.DroppedTotal + uint64(st.Pending); total != 12 {
		t.Fatalf("accounted for %d of the 12 items added", total)
	}

	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	batch := rec.at(t, 1).batch
	if got := recordIDs(batch.Records); !equalUint32(got, []uint32{9, 10, 11, 12}) {
		t.Fatalf("retry batch = %v, want the survivors", got)
	}
	if batch.Dropped != 8 {
		t.Fatalf("retry batch dropped = %d, want 8", batch.Dropped)
	}
	st = s.Stats()
	if st.ShippedRecords != 4 || st.DroppedTotal != 8 || st.Pending != 0 || st.Dropped != 0 {
		t.Fatalf("final stats: %+v", st)
	}
}
