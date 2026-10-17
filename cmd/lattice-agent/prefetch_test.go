package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-node-agent/internal/prefetch"
)

// recordingHolder stands in for the prefetcher and records, in one log with
// the runner, when the worker held and released it.
type recordingHolder struct {
	mu  sync.Mutex
	log []string
}

func (h *recordingHolder) Hold() {
	h.mu.Lock()
	h.log = append(h.log, "hold")
	h.mu.Unlock()
}

func (h *recordingHolder) Release() {
	h.mu.Lock()
	h.log = append(h.log, "release")
	h.mu.Unlock()
}

func (h *recordingHolder) events() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.log...)
}

// The hand-off: the worker holds the prefetcher before the first task of a
// batch starts and releases it only after the last one finished, so an
// update task is the only writer of the file it continues.
func TestTaskWorkerHoldsPrefetchWhileTasksRun(t *testing.T) {
	server := &fakeTaskServer{batches: [][]leasedAgentTask{{genericTask("task-a"), genericTask("task-b")}}}
	runner := newBlockingTaskRunner()
	worker, cfg, _ := startWorker(t, server, runner)
	holder := &recordingHolder{}
	worker.prefetch = holder

	if err := worker.poll(cfg); err != nil {
		t.Fatal(err)
	}
	awaitStart(t, runner, "task-a")
	if got := holder.events(); len(got) != 1 || got[0] != "hold" {
		t.Fatalf("prefetch must be held before the first task starts: %v", got)
	}
	runner.release <- struct{}{}
	awaitStart(t, runner, "task-b")
	if got := holder.events(); len(got) != 1 {
		t.Fatalf("prefetch must stay held between the tasks of a batch: %v", got)
	}
	runner.release <- struct{}{}
	waitFor(t, "worker to go idle", worker.idle)
	if got := holder.events(); len(got) != 2 || got[1] != "release" {
		t.Fatalf("prefetch must be released after the batch: %v", got)
	}
}

// The config pull keeps the SDK's fields and reads the prefetch block beside
// them; a server that predates prefetch sends none, which is nil.
func TestAgentConfigCarriesThePrefetchBlock(t *testing.T) {
	oldClient := httpClient
	t.Cleanup(func() { httpClient = oldClient })
	body := ""
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, body), nil
	})}
	cfg := agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "secret"}

	body = `{"debug":{"enabled":true},"lattice_identity_uuid":"u-1"}`
	got, err := fetchAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentUpdate != nil || !got.Debug.Enabled || got.LatticeIdentityUUID != "u-1" {
		t.Fatalf("an older server's config: %+v", got)
	}

	digest := strings.Repeat("a", 64)
	body = `{"debug":{},"agent_update":{"prefetch":{"approval_id":"ap-1","version":"0.3.10-alpha.7","os":"linux","arch":"amd64","sha256":"` + digest +
		`","size":10,"binary_size":10,"install_path":"/opt/lattice/node-agent/lattice-agent"},"keep":["` + digest + `"]}}`
	got, err = fetchAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := prefetch.Target{ApprovalID: "ap-1", Version: "0.3.10-alpha.7", OS: "linux", Arch: "amd64", SHA256: digest, Size: 10, BinarySize: 10, InstallPath: "/opt/lattice/node-agent/lattice-agent"}
	if got.AgentUpdate == nil || got.AgentUpdate.Prefetch == nil || *got.AgentUpdate.Prefetch != want || len(got.AgentUpdate.Keep) != 1 {
		t.Fatalf("prefetch block: %+v", got.AgentUpdate)
	}
}

// The heartbeat carries the prefetch report only while the server names a
// file.
func TestMetricsPayloadCarriesThePrefetchReport(t *testing.T) {
	cfg := agentConfig{NodeID: "node-a"}
	cfg.Prefetch = prefetch.New(prefetch.Options{Server: "https://lattice.test", NodeID: "node-a", Token: "secret", Veto: true})
	defer cfg.Prefetch.Close()
	if _, ok := metricsPayload(cfg)["prefetch"]; ok {
		t.Fatal("no report before the server names a file")
	}
	digest := strings.Repeat("b", 64)
	cfg.Prefetch.Update(&prefetch.Config{Prefetch: &prefetch.Target{
		ApprovalID: "ap-1", Version: "0.3.10-alpha.7", OS: "linux", Arch: "amd64", SHA256: digest,
		Size: 10, BinarySize: 10, InstallPath: "/opt/lattice/node-agent/lattice-agent",
	}, Keep: []string{digest}})
	raw, err := json.Marshal(metricsPayload(cfg)["prefetch"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"state":"refused"`) || !strings.Contains(string(raw), `"approval_id":"ap-1"`) {
		t.Fatalf("report %s", raw)
	}
}
