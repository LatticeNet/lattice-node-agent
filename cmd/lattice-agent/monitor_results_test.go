package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type monitorPost struct {
	path    string
	results []model.MonitorResult
}

// fakeMonitorServer answers the agent's monitor result posts by path.
type fakeMonitorServer struct {
	posts  []monitorPost
	answer func(path string, n int) error
}

func (f *fakeMonitorServer) post(_ context.Context, _ agentConfig, path string, payload map[string]any, out any) error {
	p := monitorPost{path: path}
	switch path {
	case monitorResultsBatchPath:
		p.results = payload["results"].([]model.MonitorResult)
	case monitorResultSinglePath:
		p.results = []model.MonitorResult{payload["result"].(model.MonitorResult)}
	}
	f.posts = append(f.posts, p)
	if f.answer != nil {
		if err := f.answer(path, len(p.results)); err != nil {
			return err
		}
	}
	if a, ok := out.(*monitorResultsAnswer); ok {
		a.OK = true
		a.Accepted = len(p.results)
	}
	return nil
}

func statusErr(code int) error {
	return &agentHTTPStatusError{statusCode: code, err: fmt.Errorf("post: %d %s", code, http.StatusText(code))}
}

func queueWith(n int) (*monitorResultQueue, *fakeMonitorServer) {
	q := newMonitorResultQueue()
	srv := &fakeMonitorServer{}
	q.post = srv.post
	for i := 0; i < n; i++ {
		q.push(model.MonitorResult{MonitorID: fmt.Sprintf("m-%d", i), Success: true})
	}
	return q, srv
}

func TestMonitorResultsGoOutInOrderedBatches(t *testing.T) {
	q, srv := queueWith(450)
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 3 {
		t.Fatalf("posts = %d, want 3 batches", len(srv.posts))
	}
	sizes := []int{200, 200, 50}
	next := 0
	for i, p := range srv.posts {
		if p.path != monitorResultsBatchPath || len(p.results) != sizes[i] {
			t.Fatalf("post %d = %s with %d results", i, p.path, len(p.results))
		}
		for _, r := range p.results {
			if r.MonitorID != fmt.Sprintf("m-%d", next) {
				t.Fatalf("result order broken at %d: %s", next, r.MonitorID)
			}
			next++
		}
	}
	if queued, _ := q.stats(); queued != 0 {
		t.Fatalf("queued after flush = %d", queued)
	}
}

func TestMonitorResultsKeepQueueOnServerErrorAndResendLater(t *testing.T) {
	q, srv := queueWith(3)
	srv.answer = func(string, int) error { return statusErr(http.StatusServiceUnavailable) }
	if err := q.flush(context.Background(), agentConfig{}); err == nil {
		t.Fatal("flush hid a 503")
	}
	if queued, _ := q.stats(); queued != 3 {
		t.Fatalf("queued after 503 = %d, want 3", queued)
	}
	srv.answer = func(string, int) error { return errors.New("dial tcp: connection refused") }
	if err := q.flush(context.Background(), agentConfig{}); err == nil {
		t.Fatal("flush hid a network error")
	}
	srv.answer = nil
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	last := srv.posts[len(srv.posts)-1]
	if last.path != monitorResultsBatchPath || len(last.results) != 3 || last.results[0].MonitorID != "m-0" {
		t.Fatalf("resend = %s %d results", last.path, len(last.results))
	}
	if queued, _ := q.stats(); queued != 0 {
		t.Fatalf("queued after resend = %d", queued)
	}
}

// Servers older than the batch route answer 404 there; the agent posts one
// result per request instead and tries the batch route again later.
func TestMonitorResultsFallBackToSinglePostsOnOldServer(t *testing.T) {
	clock := newFakeClock()
	q, srv := queueWith(3)
	q.now = clock.now
	srv.answer = func(path string, _ int) error {
		if path == monitorResultsBatchPath {
			return statusErr(http.StatusNotFound)
		}
		return nil
	}
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 4 || srv.posts[0].path != monitorResultsBatchPath {
		t.Fatalf("posts = %+v, want one batch then three singles", srv.posts)
	}
	for i, p := range srv.posts[1:] {
		if p.path != monitorResultSinglePath || p.results[0].MonitorID != fmt.Sprintf("m-%d", i) {
			t.Fatalf("single %d = %s %s", i, p.path, p.results[0].MonitorID)
		}
	}
	if queued, _ := q.stats(); queued != 0 {
		t.Fatalf("queued = %d", queued)
	}

	q.push(model.MonitorResult{MonitorID: "m-3"})
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if p := srv.posts[len(srv.posts)-1]; p.path != monitorResultSinglePath || len(srv.posts) != 5 {
		t.Fatalf("within the reprobe window the batch route was tried again: %+v", srv.posts[4:])
	}

	clock.advance(monitorBatchReprobe + time.Second)
	srv.answer = nil
	q.push(model.MonitorResult{MonitorID: "m-4"})
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if p := srv.posts[len(srv.posts)-1]; p.path != monitorResultsBatchPath {
		t.Fatalf("after the reprobe window the batch route was not retried: %s", p.path)
	}
}

func TestMonitorResultsDropWhatTheServerRefusesAsFinal(t *testing.T) {
	q, srv := queueWith(2)
	srv.answer = func(path string, _ int) error { return statusErr(http.StatusBadRequest) }
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if queued, _ := q.stats(); queued != 0 {
		t.Fatalf("a refused batch stayed queued: %d", queued)
	}

	// On the single route a refusal drops that one result, a 401 or 5xx
	// stops the flush and keeps the rest.
	q, srv = queueWith(3)
	q.disableBatch()
	calls := 0
	srv.answer = func(string, int) error {
		calls++
		switch calls {
		case 1:
			return statusErr(http.StatusUnprocessableEntity)
		case 2:
			return statusErr(http.StatusUnauthorized)
		}
		return nil
	}
	if err := q.flush(context.Background(), agentConfig{}); err == nil {
		t.Fatal("flush hid a 401")
	}
	if queued, _ := q.stats(); queued != 2 {
		t.Fatalf("queued after 422 then 401 = %d, want 2", queued)
	}
	if head := q.head(1); head[0].result.MonitorID != "m-1" {
		t.Fatalf("head after 401 = %s, want m-1", head[0].result.MonitorID)
	}
}

func TestMonitorResultQueueBoundsTheOutageBuffer(t *testing.T) {
	q, _ := queueWith(monitorResultQueueMax + 5)
	queued, dropped := q.stats()
	if queued != monitorResultQueueMax || dropped != 5 {
		t.Fatalf("queued=%d dropped=%d", queued, dropped)
	}
	if head := q.head(1); head[0].result.MonitorID != "m-5" {
		t.Fatalf("oldest kept = %s, want m-5", head[0].result.MonitorID)
	}
	// Overflow while a batch is in flight must not make settle remove
	// results that were never sent.
	batch := q.head(10)
	for i := 0; i < 20; i++ {
		q.push(model.MonitorResult{MonitorID: fmt.Sprintf("late-%d", i)})
	}
	q.settle(batch[len(batch)-1].seq)
	if head := q.head(1); head[0].result.MonitorID != "m-25" {
		t.Fatalf("head after settle = %s, want m-25", head[0].result.MonitorID)
	}
}

// The batch request on the wire: bearer token in the header, node id and the
// results array in the body, no token in the body.
func TestMonitorResultsBatchRequestShape(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	var body map[string]json.RawMessage
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != monitorResultsBatchPath || r.Method != http.MethodPost {
			return testResponse(http.StatusNotFound, "no"), nil
		}
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusUnauthorized, "no"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true,"accepted":1,"duplicates":1,"dropped":[{"index":2,"monitor_id":"gone","reason":"unknown_monitor"}]}`), nil
	})}
	q := newMonitorResultQueue()
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"a", "b", "gone"} {
		q.push(model.MonitorResult{MonitorID: id, At: at, Success: true, LatencyMs: 12.5})
	}
	cfg := agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "node-secret"}
	if err := q.flush(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if string(body["node_id"]) != `"node-a"` {
		t.Fatalf("node_id = %s", body["node_id"])
	}
	if _, ok := body["token"]; ok {
		t.Fatal("token leaked into the body")
	}
	var results []model.MonitorResult
	if err := json.Unmarshal(body["results"], &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || results[0].MonitorID != "a" || !results[0].At.Equal(at) {
		t.Fatalf("results = %+v", results)
	}
	if queued, _ := q.stats(); queued != 0 {
		t.Fatalf("accepted, duplicate and dropped results must all settle; queued = %d", queued)
	}
}

// Every result the server never stores is counted, whatever the reason, so
// the count on the heartbeat is the whole loss and not only overflow.
func TestMonitorResultsCountEveryResultTheServerNeverStored(t *testing.T) {
	q, srv := queueWith(2)
	srv.answer = func(string, int) error { return statusErr(http.StatusBadRequest) }
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, dropped := q.stats(); dropped != 2 {
		t.Fatalf("dropped after a refused batch of 2 = %d", dropped)
	}

	q, srv = queueWith(3)
	q.disableBatch()
	calls := 0
	srv.answer = func(string, int) error {
		calls++
		if calls == 2 {
			return statusErr(http.StatusUnprocessableEntity)
		}
		return nil
	}
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, dropped := q.stats(); dropped != 1 {
		t.Fatalf("dropped after one refused single = %d", dropped)
	}

	q, _ = queueWith(4)
	q.post = func(_ context.Context, _ agentConfig, _ string, _ map[string]any, out any) error {
		a := out.(*monitorResultsAnswer)
		a.OK, a.Accepted = true, 2
		a.Dropped = []monitorResultDrop{
			{Index: 1, MonitorID: "m-1", Reason: "monitor_not_assigned"},
			{Index: 3, MonitorID: "m-3", Reason: "too_old"},
		}
		return nil
	}
	if err := q.flush(context.Background(), agentConfig{}); err != nil {
		t.Fatal(err)
	}
	queued, dropped := q.stats()
	if queued != 0 || dropped != 2 {
		t.Fatalf("after a batch answer listing two drops: queued=%d dropped=%d", queued, dropped)
	}
	if fresh, total := q.droppedSinceLog(); fresh != 2 || total != 2 {
		t.Fatalf("first drop report = %d of %d", fresh, total)
	}
	if fresh, _ := q.droppedSinceLog(); fresh != 0 {
		t.Fatalf("drops reported twice: %d", fresh)
	}
}

// A clean stop sends what is still queued, and gives up within its grace
// when the control plane does not answer.
func TestMonitorDrainSendsTheQueueOnStop(t *testing.T) {
	mm := newMonitorManager(agentConfig{Interval: time.Hour})
	srv := &fakeMonitorServer{}
	mm.results.post = srv.post
	for i := 0; i < 3; i++ {
		mm.results.push(model.MonitorResult{MonitorID: fmt.Sprintf("m-%d", i), Success: true})
	}
	mm.drain(time.Second)
	if queued, _ := mm.results.stats(); queued != 0 || len(srv.posts) != 1 || len(srv.posts[0].results) != 3 {
		t.Fatalf("drain left %d queued after %d posts", queued, len(srv.posts))
	}

	mm.results.push(model.MonitorResult{MonitorID: "late", Success: true})
	mm.results.post = func(ctx context.Context, _ agentConfig, _ string, _ map[string]any, _ any) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	mm.drain(50 * time.Millisecond)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("drain against a silent control plane took %s", took)
	}
	if queued, _ := mm.results.stats(); queued != 1 {
		t.Fatalf("an unsent result must stay counted as queued: %d", queued)
	}
}

// Stopping the flush loop cuts the flush in flight short, so drain does not
// wait out its 20 s timeout behind it.
func TestMonitorFlushLoopStopsItsFlushInFlight(t *testing.T) {
	mm := newMonitorManager(agentConfig{Interval: 5 * time.Millisecond})
	entered := make(chan struct{}, 1)
	mm.results.post = func(ctx context.Context, _ agentConfig, _ string, _ map[string]any, _ any) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	mm.results.push(model.MonitorResult{MonitorID: "m-0", Success: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mm.flushLoop(ctx)
		close(done)
	}()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("flush loop kept its flush in flight after stop")
	}
}
