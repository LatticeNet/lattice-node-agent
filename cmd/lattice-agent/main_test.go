package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/taskoutbox"
	"github.com/LatticeNet/lattice-sdk/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type countingTaskRunner struct {
	calls  int
	result model.TaskResult
}

func (r *countingTaskRunner) Run(task model.Task) model.TaskResult {
	r.calls++
	result := r.result
	result.TaskID = task.ID
	result.LeaseID = task.LeaseID
	return result
}

func TestVersionMatchesCurrentRelease(t *testing.T) {
	if version != "0.3.3" {
		t.Fatalf("version = %q, want 0.3.3", version)
	}
}

func TestCompatibilityPayloadIsEmbedded(t *testing.T) {
	got := compatibilityPayload()
	if got.ServerMin == "" || got.DashboardMin == "" || got.Channel == "" {
		t.Fatalf("compatibility metadata must be embedded: %+v", got)
	}
	if got.Channel != "stable" {
		t.Fatalf("compatibility channel = %q, want stable", got.Channel)
	}
	// The floors stay on design-15 prerelease coordinates on purpose: no stable
	// server or dashboard satisfies this agent yet (stable server is still v0.2.1),
	// so naming a stable floor here would be a claim the ecosystem cannot back.
	if got.ServerMin != "v0.2.2-alpha.2" || got.DashboardMin != "v0.2.2-alpha.7" {
		t.Fatalf("compatibility floor = %+v, want coordinated design-15 alpha", got)
	}
}

func TestApplyAgentConfigControlsDebugCollection(t *testing.T) {
	sink := newDebugSink(10)
	cfg := agentConfig{DebugSink: sink}
	applyAgentConfig(&cfg, model.AgentConfig{Debug: model.AgentDebugConfig{
		Enabled:       true,
		Collect:       true,
		MaxLineBytes:  12,
		MaxBatchLines: 2,
	}})
	if !cfg.Debug || !cfg.ServerDebug || !cfg.DebugCollect {
		t.Fatalf("expected server debug with collection enabled: %+v", cfg)
	}
	if cfg.DebugMaxLineBytes != 12 || cfg.DebugMaxBatchLines != 2 {
		t.Fatalf("debug caps not applied: line=%d batch=%d", cfg.DebugMaxLineBytes, cfg.DebugMaxBatchLines)
	}
	debugf(cfg, "diagnostic %s", "message")
	lines := sink.drain(10)
	if len(lines) != 1 || lines[0] != "diagnostic m...truncated" {
		t.Fatalf("debug line not collected/truncated as expected: %q", lines)
	}

	applyAgentConfig(&cfg, model.AgentConfig{Debug: model.AgentDebugConfig{
		Enabled: true,
		Collect: false,
	}})
	if !cfg.Debug || cfg.DebugCollect {
		t.Fatalf("expected local debug without collection: %+v", cfg)
	}
	debugf(cfg, "local only")
	if got := sink.drain(10); len(got) != 0 {
		t.Fatalf("collect=false should not retain debug lines, got %q", got)
	}
}

func TestFlushDebugEventsPostsBufferedLines(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	sink := newDebugSink(10)
	cfg := agentConfig{
		Server:             "http://lattice.test",
		NodeID:             "node-a",
		Token:              "node-secret",
		Debug:              true,
		DebugCollect:       true,
		DebugMaxLineBytes:  defaultDebugMaxLineBytes,
		DebugMaxBatchLines: defaultDebugMaxBatchLines,
		DebugSink:          sink,
	}
	debugf(cfg, "poll cycle complete")
	debugf(cfg, "agent post ok: path=/api/agent/metrics")

	var body struct {
		NodeID string                `json:"node_id"`
		Batch  model.AgentDebugBatch `json:"batch"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/debug-events" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true,"accepted":2}`), nil
	})}
	if err := flushDebugEvents(cfg); err != nil {
		t.Fatal(err)
	}
	if body.NodeID != "node-a" || body.Batch.NodeID != "node-a" {
		t.Fatalf("node id not pinned in debug batch: %+v", body)
	}
	if len(body.Batch.Lines) != 2 || body.Batch.Lines[0] != "poll cycle complete" {
		t.Fatalf("unexpected debug batch: %+v", body.Batch.Lines)
	}
	if got := sink.drain(10); len(got) != 0 {
		t.Fatalf("flush should drain sent lines, got %q", got)
	}
}

func TestReportMetricsUsesBearerAuthAndOmitsBodyToken(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["node_id"] != "node-a" {
			return testResponse(http.StatusBadRequest, "missing node_id"), nil
		}
		if _, ok := body["token"]; ok {
			return testResponse(http.StatusBadRequest, "body token leaked"), nil
		}
		if _, ok := body["host_facts"].(map[string]any); !ok {
			return testResponse(http.StatusBadRequest, "missing host_facts"), nil
		}
		runtime, ok := body["agent_runtime"].(map[string]any)
		if !ok || runtime["singbox_stats_api"] != "127.0.0.1:8080" {
			return testResponse(http.StatusBadRequest, "missing singbox_stats_api"), nil
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}

	err := reportMetrics(agentConfig{
		Server:          "http://lattice.test",
		NodeID:          "node-a",
		Token:           "node-secret",
		Interval:        time.Second,
		SingBoxStatsAPI: "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAgentHTTPErrorIncludesStructuredServerDiagnostics(t *testing.T) {
	resp := testResponse(http.StatusForbidden, `{"error":{"code":"agent_update_policy_stale","message":"re-plan before approving","request_id":"req-body"}}`)
	resp.Header.Set(latticeRequestIDHeader, "req-header")

	err := agentHTTPError(resp, "fetch tasks")

	requireErrorContains(t, err, "fetch tasks")
	requireErrorContains(t, err, "403 Forbidden")
	requireErrorContains(t, err, "agent_update_policy_stale")
	requireErrorContains(t, err, "re-plan before approving")
	requireErrorContains(t, err, "request_id=req-body")
}

func TestAgentHTTPErrorUsesHeaderRequestIDForTextClientError(t *testing.T) {
	resp := testResponse(http.StatusTooManyRequests, "retry later")
	resp.Header.Set(latticeRequestIDHeader, "req-header")
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")

	err := agentHTTPError(resp, "post /api/agent/logs")

	requireErrorContains(t, err, "429 Too Many Requests")
	requireErrorContains(t, err, "retry later")
	requireErrorContains(t, err, "request_id=req-header")
}

func TestAgentHTTPErrorHidesUnstructuredServerBody(t *testing.T) {
	resp := testResponse(http.StatusInternalServerError, "database password leaked")
	resp.Header.Set("Content-Type", "text/plain")

	err := agentHTTPError(resp, "fetch monitors")

	requireErrorContains(t, err, "fetch monitors")
	requireErrorContains(t, err, "500 Internal Server Error")
	requireErrorNotContains(t, err, "database password leaked")
}

func TestPostJSONReturnsStructuredServerDiagnostics(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/task-result" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		resp := testResponse(http.StatusConflict, `{"error":{"code":"task_result_conflict","message":"task already finished","request_id":"req-task"}}`)
		resp.Header.Set(latticeRequestIDHeader, "req-header")
		return resp, nil
	})}

	err := postJSON("http://lattice.test/api/agent/task-result", "node-secret", map[string]any{"ok": true}, nil)

	requireErrorContains(t, err, "post /api/agent/task-result")
	requireErrorContains(t, err, "409 Conflict")
	requireErrorContains(t, err, "task_result_conflict")
	requireErrorContains(t, err, "task already finished")
	requireErrorContains(t, err, "request_id=req-task")
}

func TestRunTasksRetainsResultAcrossTransientServerFailure(t *testing.T) {
	for _, firstStatus := range []int{http.StatusInternalServerError, http.StatusConflict} {
		t.Run(http.StatusText(firstStatus), func(t *testing.T) {
			oldClient := httpClient
			defer func() { httpClient = oldClient }()

			store, err := taskoutbox.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo ok", TimeoutSec: 10, OutputLimit: 1024}
			runner := &countingTaskRunner{result: model.TaskResult{ExitCode: 0, Stdout: "ok", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}}
			postCalls := 0
			fetchCalls := 0
			var posted []model.TaskResult
			httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/api/agent/tasks":
					if r.Header.Get(agentCapabilitiesHeader) != guardManagedSHACapability {
						return testResponse(http.StatusBadRequest, "missing lease-time capability"), nil
					}
					fetchCalls++
					if fetchCalls == 1 {
						data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
						return testResponse(http.StatusOK, string(data)), nil
					}
					return testResponse(http.StatusOK, `[]`), nil
				case "/api/agent/task-result":
					postCalls++
					var body struct {
						Result model.TaskResult `json:"result"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					posted = append(posted, body.Result)
					if postCalls == 1 {
						return testResponse(firstStatus, `{"error":{"code":"retry","message":"retry same lease"}}`), nil
					}
					return testResponse(http.StatusOK, `{"ok":true}`), nil
				default:
					return testResponse(http.StatusNotFound, ""), nil
				}
			})}
			cfg := agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}

			if err := runTasks(cfg, runner, store); err == nil {
				t.Fatal("first result upload should fail")
			}
			if pending, err := store.Pending(); err != nil || len(pending) != 1 {
				t.Fatalf("pending after failed upload = %+v, err=%v", pending, err)
			}
			if err := runTasks(cfg, runner, store); err != nil {
				t.Fatal(err)
			}
			if runner.calls != 1 {
				t.Fatalf("runner calls = %d, want 1", runner.calls)
			}
			if postCalls != 2 || len(posted) != 2 || !reflect.DeepEqual(posted[0], posted[1]) {
				t.Fatalf("result retry changed: calls=%d posted=%+v", postCalls, posted)
			}
			if pending, err := store.Pending(); err != nil || len(pending) != 0 {
				t.Fatalf("pending after acknowledgement = %+v, err=%v", pending, err)
			}
		})
	}
}

func TestRunTasksRestartFlushesCompletedResultBeforeFetch(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	dir := t.TempDir()
	store, err := taskoutbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo ok"}
	if _, err := store.Begin(task); err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, NodeID: "node-a", ExitCode: 0, Stdout: "persisted"}
	if _, err := store.Complete(result); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := taskoutbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	runner := &countingTaskRunner{}
	var order []string
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		order = append(order, r.URL.Path)
		if r.URL.Path == "/api/agent/task-result" {
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		}
		return testResponse(http.StatusOK, `[]`), nil
	})}
	if err := runTasks(agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}, runner, restarted); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("completed task was re-executed: calls=%d", runner.calls)
	}
	wantOrder := []string{"/api/agent/task-result", "/api/agent/tasks"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("request order = %v, want %v", order, wantOrder)
	}
}

func TestRunTasksRestartConvertsInterruptedLeaseToUnknownOutcome(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	dir := t.TempDir()
	store, err := taskoutbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Begin(model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "mutate host"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := taskoutbox.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	runner := &countingTaskRunner{}
	var posted model.TaskResult
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/agent/task-result" {
			var body struct {
				Result model.TaskResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			posted = body.Result
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		}
		return testResponse(http.StatusOK, `[]`), nil
	})}
	if err := runTasks(agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}, runner, restarted); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("interrupted task was re-executed: calls=%d", runner.calls)
	}
	if posted.ExitCode != -1 || !strings.Contains(posted.Error, "outcome is unknown") || !strings.Contains(posted.Error, "not re-executed") {
		t.Fatalf("interrupted result is not honest: %+v", posted)
	}
}

type beginFailingOutbox struct {
	committed bool
	err       error
}

func (o beginFailingOutbox) Begin(model.Task) (bool, error)          { return o.committed, o.err }
func (o beginFailingOutbox) Complete(model.TaskResult) (bool, error) { return true, nil }
func (o beginFailingOutbox) ConfirmDurability() error                { return nil }
func (o beginFailingOutbox) RecoverInterrupted(string) error         { return nil }
func (o beginFailingOutbox) Pending() ([]taskoutbox.Entry, error)    { return nil, nil }
func (o beginFailingOutbox) Remove(taskoutbox.Entry) error           { return nil }

func TestRunTasksJournalFailurePreventsExecution(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "must not run"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
	var reported model.TaskResult
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/agent/tasks" {
			return testResponse(http.StatusOK, string(data)), nil
		}
		var body struct {
			Result model.TaskResult `json:"result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		reported = body.Result
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	runner := &countingTaskRunner{}
	err := runTasks(
		agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"},
		runner,
		beginFailingOutbox{err: errors.New("disk full")},
	)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("runTasks error = %v, want disk failure", err)
	}
	if runner.calls != 0 {
		t.Fatalf("task ran despite journal failure: calls=%d", runner.calls)
	}
	if reported.TaskID != task.ID || reported.LeaseID != task.LeaseID || reported.ExitCode != -1 ||
		!strings.Contains(reported.Error, "not executed") {
		t.Fatalf("journal failure did not report an honest terminal result: %+v", reported)
	}
}

func TestRunTasksPublishedJournalFailureDoesNotPostConflictingDirectResult(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "must not run"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
	postCalls := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/agent/tasks" {
			return testResponse(http.StatusOK, string(data)), nil
		}
		postCalls++
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	runner := &countingTaskRunner{}
	err := runTasks(
		agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"},
		runner,
		beginFailingOutbox{committed: true, err: errors.New("directory sync failed")},
	)
	if err == nil || !strings.Contains(err.Error(), "directory sync failed") {
		t.Fatalf("runTasks error = %v, want directory sync failure", err)
	}
	if runner.calls != 0 || postCalls != 0 {
		t.Fatalf("published journal ambiguity ran or directly reported task: runner=%d posts=%d", runner.calls, postCalls)
	}
}

func TestRunTasksExactRedeliveryDoesNotExecuteExistingJournal(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "must run once"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/tasks" {
			t.Fatalf("unexpected request for already-journaled lease: %s", r.URL.Path)
		}
		return testResponse(http.StatusOK, string(data)), nil
	})}
	runner := &countingTaskRunner{}
	if err := runTasks(
		agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"},
		runner,
		beginFailingOutbox{committed: false},
	); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatalf("exact redelivery executed an existing journal: calls=%d", runner.calls)
	}
}

func TestRunTasksKeepsGenericTasksOutsideDurableNetGuardProtocol(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-generic", LeaseID: "lease-generic", Interpreter: "sh", Script: "echo generic"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task}})
	posts := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/agent/tasks":
			return testResponse(http.StatusOK, string(data)), nil
		case "/api/agent/task-result":
			posts++
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		default:
			return testResponse(http.StatusNotFound, ""), nil
		}
	})}
	runner := &countingTaskRunner{result: model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID}}
	if err := runTasks(
		agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"},
		runner,
		beginFailingOutbox{err: errors.New("generic task must not journal")},
	); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 || posts != 1 {
		t.Fatalf("generic task delivery = runner %d posts %d, want one direct execution/result", runner.calls, posts)
	}
}

type completePublishingOutbox struct {
	task       model.Task
	result     *model.TaskResult
	confirmErr error
	confirmed  int
	removed    int
}

func (o *completePublishingOutbox) Begin(task model.Task) (bool, error) {
	o.task = task
	return true, nil
}

func (o *completePublishingOutbox) Complete(result model.TaskResult) (bool, error) {
	o.result = &result
	return true, errors.New("directory sync failed")
}

func (o *completePublishingOutbox) ConfirmDurability() error {
	o.confirmed++
	return o.confirmErr
}

func (o *completePublishingOutbox) RecoverInterrupted(string) error { return nil }

func (o *completePublishingOutbox) Pending() ([]taskoutbox.Entry, error) {
	if o.result == nil {
		return nil, nil
	}
	return []taskoutbox.Entry{{Task: o.task, Result: o.result}}, nil
}

func (o *completePublishingOutbox) Remove(taskoutbox.Entry) error {
	o.removed++
	o.result = nil
	return nil
}

func TestRunTasksConfirmsAndUploadsResultPublishedBeforeDirectorySyncFailure(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo once"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
	posts := 0
	var posted model.TaskResult
	outbox := &completePublishingOutbox{}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/agent/tasks":
			return testResponse(http.StatusOK, string(data)), nil
		case "/api/agent/task-result":
			if outbox.confirmed != 1 {
				t.Fatalf("result posted before local durability confirmation: confirms=%d", outbox.confirmed)
			}
			posts++
			var body struct {
				Result model.TaskResult `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			posted = body.Result
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		default:
			return testResponse(http.StatusNotFound, ""), nil
		}
	})}
	runner := &countingTaskRunner{result: model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, ExitCode: 0, Stdout: "exact"}}
	err := runTasks(agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}, runner, outbox)
	if err == nil || !strings.Contains(err.Error(), "directory sync failed") {
		t.Fatalf("runTasks error = %v, want published-result sync warning", err)
	}
	if runner.calls != 1 || posts != 1 || outbox.confirmed != 1 || outbox.removed != 1 {
		t.Fatalf("published result was not confirmed and uploaded exactly once: runner=%d confirms=%d posts=%d removed=%d", runner.calls, outbox.confirmed, posts, outbox.removed)
	}
	if posted.TaskID != task.ID || posted.LeaseID != task.LeaseID || posted.NodeID != "node-a" || posted.Stdout != "exact" {
		t.Fatalf("immediate upload changed result: %+v", posted)
	}
}

func TestRunTasksDoesNotUploadUnconfirmedPublishedResult(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()
	task := model.Task{ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo once"}
	data, _ := json.Marshal([]leasedAgentTask{{Task: task, DurableResult: true}})
	posts := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/agent/tasks":
			return testResponse(http.StatusOK, string(data)), nil
		case "/api/agent/task-result":
			posts++
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		default:
			return testResponse(http.StatusNotFound, ""), nil
		}
	})}
	runner := &countingTaskRunner{result: model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, ExitCode: 0}}
	outbox := &completePublishingOutbox{confirmErr: errors.New("directory still unavailable")}
	err := runTasks(agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}, runner, outbox)
	if err == nil || !strings.Contains(err.Error(), "confirm published task result") {
		t.Fatalf("runTasks error = %v, want durability confirmation error", err)
	}
	if runner.calls != 1 || outbox.confirmed != 1 || posts != 0 || outbox.removed != 0 {
		t.Fatalf("unconfirmed result escaped locally: runner=%d confirms=%d posts=%d removed=%d", runner.calls, outbox.confirmed, posts, outbox.removed)
	}
}

func TestTaskResultOutboxDirPrefersConfiguredStateAndIsolatedIdentity(t *testing.T) {
	base := t.TempDir()
	one, err := taskResultOutboxDir(agentConfig{
		Server:      "https://one.example",
		NodeID:      "node-a",
		LogStateDir: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	two, err := taskResultOutboxDir(agentConfig{
		Server:        "https://two.example",
		NodeID:        "node-a",
		LogStateDir:   base,
		TaskOutboxDir: filepath.Join(base, "override"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(one, filepath.Join(base, "task-outbox")+string(os.PathSeparator)) {
		t.Fatalf("LogStateDir was not used: %s", one)
	}
	if !strings.HasPrefix(two, filepath.Join(base, "override", "task-outbox")+string(os.PathSeparator)) {
		t.Fatalf("TaskOutboxDir override was not used: %s", two)
	}
	if one == two || filepath.Base(one) == filepath.Base(two) {
		t.Fatalf("server/node identities were not isolated: one=%s two=%s", one, two)
	}
}

func TestShipLogBatchReturnsStatusAndStructuredDiagnostics(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/logs" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			return testResponse(http.StatusBadRequest, "missing bearer"), nil
		}
		resp := testResponse(http.StatusTooManyRequests, `{"error":{"code":"rate_limited","message":"slow down","request_id":"req-log"}}`)
		resp.Header.Set(latticeRequestIDHeader, "req-header")
		return resp, nil
	})}

	status, err := shipLogBatch(agentConfig{
		Server: "http://lattice.test",
		NodeID: "node-a",
		Token:  "node-secret",
	}, model.LogBatch{SourceID: "src-a", Lines: []string{"hello"}})

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
	requireErrorContains(t, err, "ship log batch")
	requireErrorContains(t, err, "429 Too Many Requests")
	requireErrorContains(t, err, "rate_limited")
	requireErrorContains(t, err, "slow down")
	requireErrorContains(t, err, "request_id=req-log")
}

func TestReportProxyUsageIncludesCollectorHealthOnSuccess(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	dir := t.TempDir()
	usageFile := filepath.Join(dir, "usage.json")
	if err := os.WriteFile(usageFile, []byte(`{"core_uptime_sec":10,"user_bytes":{"alice":123}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var body struct {
		NodeID   string                   `json:"node_id"`
		Snapshot model.ProxyUsageSnapshot `json:"snapshot"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/agent/proxy-usage" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	if err := reportProxyUsage(agentConfig{
		Server:         "http://lattice.test",
		NodeID:         "node-a",
		Token:          "node-secret",
		ProxyUsageFile: usageFile,
	}); err != nil {
		t.Fatal(err)
	}
	if body.NodeID != "node-a" || body.Snapshot.NodeID != "node-a" {
		t.Fatalf("node id not pinned in body: %+v", body)
	}
	if body.Snapshot.CollectorSource != "file" || body.Snapshot.CollectorStatus != model.ProxyUsageCollectorStatusOK {
		t.Fatalf("collector health missing from success snapshot: %+v", body.Snapshot)
	}
	if body.Snapshot.CollectorError != "" || body.Snapshot.CollectorCheckedAt.IsZero() {
		t.Fatalf("unexpected success collector fields: %+v", body.Snapshot)
	}
}

func TestReportProxyUsageReportsCollectorError(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	calls := 0
	var body struct {
		NodeID   string                   `json:"node_id"`
		Snapshot model.ProxyUsageSnapshot `json:"snapshot"`
	}
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/api/agent/proxy-usage" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return testResponse(http.StatusOK, `{"ok":true}`), nil
	})}
	err := reportProxyUsage(agentConfig{
		Server:         "http://lattice.test",
		NodeID:         "node-a",
		Token:          "node-secret",
		ProxyUsageFile: filepath.Join(t.TempDir(), "missing.json"),
	})
	if err == nil {
		t.Fatal("expected local collector error to remain visible")
	}
	if calls != 1 {
		t.Fatalf("expected one collector health report, got %d", calls)
	}
	if body.Snapshot.CollectorSource != "file" || body.Snapshot.CollectorStatus != model.ProxyUsageCollectorStatusError {
		t.Fatalf("collector error health missing: %+v", body.Snapshot)
	}
	if body.Snapshot.CollectorError == "" || body.Snapshot.CollectorCheckedAt.IsZero() {
		t.Fatalf("collector error details missing: %+v", body.Snapshot)
	}
	if len(body.Snapshot.UserBytes) != 0 {
		t.Fatalf("error health report must not include usage counters: %+v", body.Snapshot.UserBytes)
	}
}

// TestCheckServerTransport pins the cleartext-token guard (C19): https is always
// allowed, loopback http is allowed, but non-loopback http must be refused unless
// the operator explicitly opts in with -allow-insecure-http.
func TestCheckServerTransport(t *testing.T) {
	cases := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
	}{
		{"loopback ipv4 http ok", "http://127.0.0.1:8088", false, false},
		{"loopback ipv4 subnet http ok", "http://127.5.6.7:8088", false, false},
		{"loopback ipv6 http ok", "http://[::1]:8088", false, false},
		{"localhost http ok", "http://localhost:8088", false, false},
		{"https remote ok", "https://lattice.example.com", false, false},
		{"https loopback ok", "https://127.0.0.1:8443", false, false},
		{"remote http refused", "http://lattice.example.com:8088", false, true},
		{"remote ip http refused", "http://203.0.113.5:8088", false, true},
		{"remote http allowed with override", "http://lattice.example.com:8088", true, false},
		{"unsupported scheme refused", "ftp://lattice.example.com", false, true},
		{"unsupported scheme not saved by override", "ftp://lattice.example.com", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkServerTransport(c.url, c.allowInsecure)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkServerTransport(%q, allowInsecure=%v) err=%v, wantErr=%v", c.url, c.allowInsecure, err, c.wantErr)
			}
		})
	}
}

func TestValidateProxyUsageConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     agentConfig
		wantErr bool
	}{
		{
			name:    "none ok",
			cfg:     agentConfig{},
			wantErr: false,
		},
		{
			name:    "file ok",
			cfg:     agentConfig{ProxyUsageFile: "/run/lattice/proxy-usage.json"},
			wantErr: false,
		},
		{
			name:    "loopback url ok",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: false,
		},
		{
			name:    "file and url conflict",
			cfg:     agentConfig{ProxyUsageFile: "/run/lattice/proxy-usage.json", ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: true,
		},
		{
			name:    "remote url refused",
			cfg:     agentConfig{ProxyUsageURL: "http://example.com/stats"},
			wantErr: true,
		},
		{
			name:    "secret without url refused",
			cfg:     agentConfig{ProxyUsageSecret: "local-secret"},
			wantErr: true,
		},
		{
			name:    "secret file without url refused",
			cfg:     agentConfig{ProxyUsageSecretFile: "/run/lattice/proxy-usage.secret"},
			wantErr: true,
		},
		{
			name:    "secret and secret file conflict",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats", ProxyUsageSecret: "local-secret", ProxyUsageSecretFile: "/run/lattice/proxy-usage.secret"},
			wantErr: true,
		},
		{
			name:    "negative timeout refused",
			cfg:     agentConfig{ProxyUsageURL: "http://127.0.0.1:9090/stats", ProxyUsageTimeout: -time.Second},
			wantErr: true,
		},
		{
			name:    "xray api loopback ok",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085"},
			wantErr: false,
		},
		{
			name:    "xray api remote refused",
			cfg:     agentConfig{ProxyUsageXrayAPI: "10.0.0.1:10085"},
			wantErr: true,
		},
		{
			name:    "xray and url conflict",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085", ProxyUsageURL: "http://127.0.0.1:9090/stats"},
			wantErr: true,
		},
		{
			name:    "xray bin without api refused",
			cfg:     agentConfig{ProxyUsageXrayBin: "/usr/local/bin/xray"},
			wantErr: true,
		},
		{
			name:    "xray unsafe binary refused",
			cfg:     agentConfig{ProxyUsageXrayAPI: "127.0.0.1:10085", ProxyUsageXrayBin: "xray; reboot"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateProxyUsageConfig(c.cfg)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateProxyUsageConfig() err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestResolveProxyUsageSecret(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "proxy-usage.secret")
	if err := os.WriteFile(secretFile, []byte(" local-secret \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := agentConfig{ProxyUsageSecretFile: secretFile}
	if err := resolveProxyUsageSecret(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyUsageSecret != "local-secret" {
		t.Fatalf("unexpected secret %q", cfg.ProxyUsageSecret)
	}
	if cfg.ProxyUsageSecretFile != "" {
		t.Fatalf("resolved secret file path must be cleared before validation, got %q", cfg.ProxyUsageSecretFile)
	}
	cfg.ProxyUsageURL = "http://127.0.0.1:9090/stats"
	if err := validateProxyUsageConfig(cfg); err != nil {
		t.Fatalf("resolved secret-file config should validate: %v", err)
	}
}

func TestResolveProxyUsageSecretRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(emptyFile, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	largeFile := filepath.Join(dir, "large.secret")
	if err := os.WriteFile(largeFile, bytes.Repeat([]byte("x"), 4097), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []agentConfig{
		{ProxyUsageSecret: "already-set", ProxyUsageSecretFile: emptyFile},
		{ProxyUsageSecretFile: emptyFile},
		{ProxyUsageSecretFile: largeFile},
		{ProxyUsageSecretFile: filepath.Join(dir, "missing.secret")},
	}
	for _, cfg := range cases {
		if err := resolveProxyUsageSecret(&cfg); err == nil {
			t.Fatalf("resolveProxyUsageSecret(%+v) expected error", cfg)
		}
	}
}

func TestSelfcheckControlPlaneUsesHealthWithoutBearer(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/health" {
			return testResponse(http.StatusBadRequest, "bad path"), nil
		}
		if r.Header.Get("Authorization") != "" {
			return testResponse(http.StatusBadRequest, "unexpected auth"), nil
		}
		return testResponse(http.StatusOK, `{"status":"ok"}`), nil
	})}
	if err := selfcheckControlPlaneWithClient("https://lattice.test/", client); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected one health request, got %d", calls)
	}
}

func TestSelfcheckControlPlaneRejectsNonOK(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(http.StatusServiceUnavailable, "down"), nil
	})}
	if err := selfcheckControlPlaneWithClient("https://lattice.test", client); err == nil {
		t.Fatal("expected non-200 selfcheck to fail")
	}
}

func TestNFTDomainSetUpdateBuildsDeterministicArgv(t *testing.T) {
	var commands [][]string
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "LATTICE.Example.COM.", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		if host != "lattice.example.com" {
			t.Fatalf("host not normalized before resolution: %q", host)
		}
		return []string{"203.0.113.10", "2001:db8::1", "198.51.100.2", "2001:db8::2", "203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"flush", "set", "inet", "lattice_policy", "lattice_control4"},
		{"add", "element", "inet", "lattice_policy", "lattice_control4", "{ 198.51.100.2, 203.0.113.10 }"},
		{"flush", "set", "inet", "lattice_policy", "lattice_control6"},
		{"add", "element", "inet", "lattice_policy", "lattice_control6", "{ 2001:db8::1, 2001:db8::2 }"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected nft argv:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestNFTDomainSetUpdateAllowsMissingIPv6WhenIPv4Exists(t *testing.T) {
	var commands [][]string
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"flush", "set", "inet", "lattice_policy", "lattice_control4"},
		{"add", "element", "inet", "lattice_policy", "lattice_control4", "{ 203.0.113.10 }"},
		{"flush", "set", "inet", "lattice_policy", "lattice_control6"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected nft argv:\n got: %#v\nwant: %#v", commands, want)
	}
}

func TestNFTDomainSetUpdateRejectsNoIPv4ForLegacySetOnly(t *testing.T) {
	called := false
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"2001:db8::1"}, nil
	}, func(ctx context.Context, args ...string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("expected no-IPv4 failure before nft commands, err=%v called=%v", err, called)
	}
}

func TestNFTDomainSetUpdateRejectsNoRequestedRecords(t *testing.T) {
	called := false
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"not-an-ip"}, nil
	}, func(ctx context.Context, args ...string) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("expected no-record failure before nft commands, err=%v called=%v", err, called)
	}
}

func TestNFTDomainSetUpdateRejectsUnsafeIdentifiers(t *testing.T) {
	cases := []nftDomainSetConfig{
		{Host: "bad host", Family: "inet", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet;reboot", Table: "lattice_policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice-policy", Set: "lattice_control4"},
		{Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice/control4"},
		{Host: "lattice.example.com", Family: "ip", Table: "lattice_policy", Set: "lattice_control4", Set6: "lattice_control6"},
	}
	for _, cfg := range cases {
		err := updateNFTDomainSet(context.Background(), cfg, func(ctx context.Context, host string) ([]string, error) {
			t.Fatalf("resolver should not run for invalid config: %+v", cfg)
			return nil, nil
		}, func(ctx context.Context, args ...string) error {
			t.Fatalf("nft should not run for invalid config: %+v", cfg)
			return nil
		})
		if err == nil {
			t.Fatalf("expected invalid config to fail: %+v", cfg)
		}
	}
}

func TestNFTDomainSetUpdateStopsOnFlushFailure(t *testing.T) {
	errBoom := errors.New("boom")
	calls := 0
	err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
		Host: "lattice.example.com", Family: "inet", Table: "lattice_policy", Set: "lattice_control4",
	}, func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.10"}, nil
	}, func(ctx context.Context, args ...string) error {
		calls++
		if calls == 1 {
			return errBoom
		}
		return nil
	})
	if !errors.Is(err, errBoom) || calls != 1 {
		t.Fatalf("expected flush failure to stop before add, err=%v calls=%d", err, calls)
	}
}

// TestIsLoopbackHost covers the pure helper directly for the loopback decision.
func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"localhost", "127.0.0.1", "127.0.0.53", "::1"}
	remote := []string{"lattice.example.com", "203.0.113.5", "10.0.0.1", "0.0.0.0", "2001:db8::1", ""}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range remote {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %q", want, err.Error())
	}
}

func requireErrorNotContains(t *testing.T, err error, unwanted string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if strings.Contains(err.Error(), unwanted) {
		t.Fatalf("expected error not to contain %q, got %q", unwanted, err.Error())
	}
}
