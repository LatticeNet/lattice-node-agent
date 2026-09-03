package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/taskoutbox"
	"github.com/LatticeNet/lattice-sdk/model"
)

// blockingTaskRunner holds every task until the test releases it (or, through
// RunContext, until the run context is cancelled) and records what ran, in
// which order, and how many tasks were running at once.
type blockingTaskRunner struct {
	mu          sync.Mutex
	started     chan string
	release     chan struct{}
	order       []string
	running     int
	maxRunning  int
	interrupted int
}

func newBlockingTaskRunner() *blockingTaskRunner {
	return &blockingTaskRunner{started: make(chan string, 8), release: make(chan struct{}, 8)}
}

func (r *blockingTaskRunner) Run(task model.Task) model.TaskResult {
	return r.RunContext(context.Background(), task)
}

func (r *blockingTaskRunner) RunContext(ctx context.Context, task model.Task) model.TaskResult {
	r.mu.Lock()
	r.running++
	if r.running > r.maxRunning {
		r.maxRunning = r.running
	}
	r.order = append(r.order, task.ID)
	r.mu.Unlock()
	r.started <- task.ID
	result := model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, StartedAt: time.Now().UTC()}
	select {
	case <-r.release:
	case <-ctx.Done():
		result.ExitCode = -1
		result.Error = "task interrupted before completion: " + ctx.Err().Error()
		r.mu.Lock()
		r.interrupted++
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.running--
	r.mu.Unlock()
	result.FinishedAt = time.Now().UTC()
	return result
}

func (r *blockingTaskRunner) snapshot() (order []string, running, maxRunning, interrupted int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...), r.running, r.maxRunning, r.interrupted
}

// fakeTaskServer answers the three agent endpoints a task cycle and a metrics
// report touch. Each lease request pops the next prepared batch; after that
// it returns an empty lease.
type fakeTaskServer struct {
	mu      sync.Mutex
	batches [][]leasedAgentTask
	fetches int
	metrics int
	results []model.TaskResult
}

func (s *fakeTaskServer) roundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/api/agent/tasks":
		s.fetches++
		if len(s.batches) == 0 {
			return testResponse(http.StatusOK, `[]`), nil
		}
		batch := s.batches[0]
		s.batches = s.batches[1:]
		data, err := json.Marshal(batch)
		if err != nil {
			return nil, err
		}
		return testResponse(http.StatusOK, string(data)), nil
	case "/api/agent/task-result":
		var body struct {
			Result model.TaskResult `json:"result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		s.results = append(s.results, body.Result)
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	case "/api/agent/metrics":
		s.metrics++
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	default:
		return testResponse(http.StatusNotFound, ""), nil
	}
}

func (s *fakeTaskServer) counts() (fetches, metrics int, results []model.TaskResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches, s.metrics, append([]model.TaskResult(nil), s.results...)
}

func durableTask(id string) leasedAgentTask {
	return leasedAgentTask{
		Task:          model.Task{ID: id, LeaseID: "lease-" + id, Interpreter: "sh", Script: "echo " + id, TimeoutSec: 600, OutputLimit: 1024},
		DurableResult: true, DurableProtocol: "netguard-v1",
	}
}

// startWorker wires a worker to the fake server over a real outbox. It returns
// the only way a test may stop the worker: shutdown closes channels, so calling
// it twice would panic, and it can return while the worker is still running
// (its reportGrace path), which makes "is done closed yet" the wrong way to ask
// whether it has already been called. The cleanup releases whatever the runner
// still holds and stops the worker, so a failing assertion cannot leave a
// goroutine blocked past the test.
func startWorker(t *testing.T, server *fakeTaskServer, runner *blockingTaskRunner) (*taskWorker, agentConfig, func(grace, reportGrace time.Duration)) {
	t.Helper()
	oldClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(server.roundTrip)}
	t.Cleanup(func() { httpClient = oldClient })
	outbox, err := taskoutbox.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outbox.Close() })
	worker := newTaskWorker(runner, outbox, nil)
	var once sync.Once
	stopWorker := func(grace, reportGrace time.Duration) {
		once.Do(func() { worker.shutdown(grace, reportGrace) })
	}
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(runner.release) })
		stopWorker(0, 2*time.Second)
	})
	return worker, agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret", LinechainReady: true}, stopWorker
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func awaitStart(t *testing.T, runner *blockingTaskRunner, want string) {
	t.Helper()
	select {
	case got := <-runner.started:
		if got != want {
			t.Fatalf("task %q started, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("task %q did not start", want)
	}
}

// The production failure: a task whose script hangs for its whole timeout used
// to hold the poll loop, so the node stopped reporting and showed offline for
// as long as the task ran. With the worker, three report cycles complete while
// the task is still blocked, and its result still arrives once it finishes.
func TestTaskWorkerKeepsReportingWhileTaskBlocks(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{durableTask("task-a")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, _ := startWorker(t, server, runner)

	const interval = 20 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	started := time.Now()
	for cycle := 0; cycle < 3; cycle++ {
		if err := reportMetrics(cfg); err != nil {
			t.Fatal(err)
		}
		if err := worker.poll(cfg); err != nil {
			t.Fatal(err)
		}
		<-ticker.C
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("three cycles took %s; the poll blocked on the task", elapsed)
	}
	awaitStart(t, runner, "task-a")
	_, running, _, _ := runner.snapshot()
	fetches, metrics, results := server.counts()
	if running != 1 || len(results) != 0 {
		t.Fatalf("task should still be running with no result yet: running=%d results=%d", running, len(results))
	}
	if metrics != 3 {
		t.Fatalf("metrics reports while task blocked = %d, want 3", metrics)
	}
	if fetches != 1 {
		t.Fatalf("lease requests while task blocked = %d, want 1", fetches)
	}

	runner.release <- struct{}{}
	waitFor(t, "worker to go idle", worker.idle)
	_, _, results = server.counts()
	if len(results) != 1 || results[0].TaskID != "task-a" || results[0].NodeID != "node-a" {
		t.Fatalf("results after release = %+v, want exactly task-a", results)
	}
}

// One lease response can carry several tasks. They run strictly one at a time
// and in lease order, and their results are uploaded in that order.
func TestTaskWorkerRunsOneTaskAtATimeInLeaseOrder(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{durableTask("task-a"), durableTask("task-b"), durableTask("task-c")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, _ := startWorker(t, server, runner)

	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"task-a", "task-b", "task-c"} {
		awaitStart(t, runner, id)
		if _, running, _, _ := runner.snapshot(); running != 1 {
			t.Fatalf("running while %s executes = %d, want 1", id, running)
		}
		runner.release <- struct{}{}
	}
	waitFor(t, "worker to go idle", worker.idle)

	order, _, maxRunning, _ := runner.snapshot()
	if maxRunning != 1 {
		t.Fatalf("max concurrent tasks = %d, want 1", maxRunning)
	}
	if len(order) != 3 || order[0] != "task-a" || order[1] != "task-b" || order[2] != "task-c" {
		t.Fatalf("execution order = %v", order)
	}
	_, _, results := server.counts()
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	for i, id := range []string{"task-a", "task-b", "task-c"} {
		if results[i].TaskID != id {
			t.Fatalf("result %d is for %q, want %q", i, results[i].TaskID, id)
		}
	}
}

// A lease held in memory behind a running task would expire unused, so the
// poll asks the server for nothing while the worker is busy and leases again
// as soon as it is idle.
func TestTaskWorkerDoesNotLeaseWhileBusy(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{durableTask("task-a")}, {durableTask("task-b")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, _ := startWorker(t, server, runner)

	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	awaitStart(t, runner, "task-a")
	for i := 0; i < 3; i++ {
		if err := worker.poll(cfg); err != nil {
			t.Fatal(err)
		}
	}
	if fetches, _, _ := server.counts(); fetches != 1 {
		t.Fatalf("lease requests while busy = %d, want 1", fetches)
	}
	if _, _, maxRunning, _ := runner.snapshot(); maxRunning != 1 {
		t.Fatalf("max concurrent tasks = %d, want 1", maxRunning)
	}

	runner.release <- struct{}{}
	waitFor(t, "worker to go idle", worker.idle)
	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	awaitStart(t, runner, "task-b")
	if fetches, _, _ := server.counts(); fetches != 2 {
		t.Fatalf("lease requests after idle = %d, want 2", fetches)
	}
	runner.release <- struct{}{}
	waitFor(t, "worker to go idle", worker.idle)
}

// A slow task's result goes through the outbox and is posted exactly once; the
// idle polls that follow flush nothing extra and leave the outbox empty.
func TestTaskWorkerPostsResultOnceAfterSlowTask(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{durableTask("task-a")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, _ := startWorker(t, server, runner)

	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	awaitStart(t, runner, "task-a")
	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	runner.release <- struct{}{}
	waitFor(t, "worker to go idle", worker.idle)
	for i := 0; i < 2; i++ {
		if err := worker.poll(cfg); err != nil {
			t.Fatal(err)
		}
	}

	_, _, results := server.counts()
	if len(results) != 1 {
		t.Fatalf("result posts = %d, want exactly 1: %+v", len(results), results)
	}
	if results[0].TaskID != "task-a" || results[0].LeaseID != "lease-task-a" || results[0].NodeID != "node-a" {
		t.Fatalf("posted result = %+v", results[0])
	}
	if pending, err := worker.outbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after upload = %+v, err=%v", pending, err)
	}
}

// Shutdown with a task in flight: the task gets its grace, is then killed
// through the run context, its failed result is still journaled and uploaded,
// and the rest of the batch is left to expire instead of being started.
func TestTaskWorkerShutdownKillsRunningTaskAndReports(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{durableTask("task-a"), durableTask("task-b")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, stopWorker := startWorker(t, server, runner)

	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	awaitStart(t, runner, "task-a")

	started := time.Now()
	stopWorker(30*time.Millisecond, 5*time.Second)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("worker goroutine still running after shutdown")
	}

	order, running, _, interrupted := runner.snapshot()
	if running != 0 || interrupted != 1 {
		t.Fatalf("running=%d interrupted=%d after shutdown, want 0 and 1", running, interrupted)
	}
	if len(order) != 1 || order[0] != "task-a" {
		t.Fatalf("tasks started = %v, want only task-a", order)
	}
	_, _, results := server.counts()
	if len(results) != 1 || results[0].TaskID != "task-a" || results[0].ExitCode != -1 || results[0].Error == "" {
		t.Fatalf("results after shutdown = %+v, want one failed task-a", results)
	}
	if pending, err := worker.outbox.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after shutdown upload = %+v, err=%v", pending, err)
	}
}

// Shutdown with nothing running returns at once.
func TestTaskWorkerShutdownIdleReturnsImmediately(t *testing.T) {
	server := &fakeTaskServer{}
	runner := newBlockingTaskRunner()
	worker, cfg, stopWorker := startWorker(t, server, runner)
	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	stopWorker(time.Minute, time.Minute)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("idle shutdown took %s", elapsed)
	}
}
