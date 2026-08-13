package taskoutbox

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestCompletedResultSurvivesReopenUntilAcknowledged(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := testTask()
	if _, err := store.Begin(task); err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{
		TaskID: task.ID, LeaseID: task.LeaseID, NodeID: "node-a", ExitCode: 0,
		Stdout: "done", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
	}
	if _, err := store.Complete(result); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil || pending[0].Result.Stdout != "done" {
		t.Fatalf("unexpected durable result: %+v", pending)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var journals []os.DirEntry
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			journals = append(journals, file)
		}
	}
	if len(journals) != 1 {
		t.Fatalf("journal files = %d, want 1 (all files: %d)", len(journals), len(files))
	}
	info, err := journals[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %o, want 600", info.Mode().Perm())
	}
	if err := reopened.Remove(pending[0]); err != nil {
		t.Fatal(err)
	}
	if pending, err := reopened.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after acknowledgement = %+v, err=%v", pending, err)
	}
}

func TestRecoverInterruptedCreatesUnknownOutcomeWithoutTaskOutput(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Begin(testTask()); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverInterrupted("node-a"); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil {
		t.Fatalf("unexpected recovered entries: %+v", pending)
	}
	result := pending[0].Result
	if result.NodeID != "node-a" || result.ExitCode != -1 || result.Stdout != "" || result.Stderr != "" {
		t.Fatalf("unexpected recovered result: %+v", result)
	}
	if !strings.Contains(result.Error, "outcome is unknown") || !strings.Contains(result.Error, "not re-executed") {
		t.Fatalf("recovery error is not honest enough: %q", result.Error)
	}
}

func TestBeginReportsJournalPublishedWhenDirectorySyncFails(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	committed, err := store.Begin(testTask())
	if !committed || err == nil || !strings.Contains(err.Error(), "directory sync failure") {
		t.Fatalf("Begin() = committed %v, err %v; want published journal plus sync error", committed, err)
	}
	store.syncDir = syncDir
	if err := store.RecoverInterrupted("node-a"); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil || pending[0].Result.ExitCode != -1 {
		t.Fatalf("published lease was not recoverable: %+v", pending)
	}
}

func TestCompleteReportsResultPublishedWhenDirectorySyncFails(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := testTask()
	if _, err := store.Begin(task); err != nil {
		t.Fatal(err)
	}
	store.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	result := model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, NodeID: "node-a", ExitCode: 0, Stdout: "exact"}
	committed, err := store.Complete(result)
	if !committed || err == nil || !strings.Contains(err.Error(), "directory sync failure") {
		t.Fatalf("Complete() = committed %v, err %v; want published result plus sync error", committed, err)
	}
	store.syncDir = syncDir
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil || pending[0].Result.Stdout != "exact" {
		t.Fatalf("published result was not retained exactly: %+v", pending)
	}
}

func TestOpenRefusesConcurrentOwnerWithoutChangingJournal(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Begin(testTask()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("concurrent Open() error = %v, want exclusive-owner rejection", err)
	}
	entry, err := first.read(entryKey(testTask().ID, testTask().LeaseID))
	if err != nil {
		t.Fatal(err)
	}
	if entry.State != stateLeased || entry.Result != nil {
		t.Fatalf("concurrent open modified active journal: %+v", entry)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() after release: %v", err)
	}
	defer second.Close()
}

func testTask() model.Task {
	return model.Task{
		ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo done",
		TimeoutSec: 10, OutputLimit: 1024,
	}
}
