package taskoutbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestOpenDurablyCreatesEveryMissingDirectoryComponent(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "task-outbox", "node-hash")
	var synced []string
	store, err := openWithSync(target, func(dir string) error {
		synced = append(synced, dir)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	want := []string{filepath.Dir(base), base, filepath.Join(base, "task-outbox")}
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("directory sync order = %q, want %q", synced, want)
	}
	for _, dir := range []string{filepath.Join(base, "task-outbox"), target} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode = %o, want 700", dir, info.Mode().Perm())
		}
	}
}

func TestOpenReconfirmsVisibleDirectoryAfterPriorSyncFailure(t *testing.T) {
	base := t.TempDir()
	taskRoot := filepath.Join(base, "task-outbox")
	target := filepath.Join(taskRoot, "node-hash")
	calls := 0
	_, err := openWithSync(target, func(string) error {
		calls++
		if calls == 3 {
			return errors.New("injected directory sync failure")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "directory sync failure") {
		t.Fatalf("Open() error = %v, want parent sync failure", err)
	}
	if _, statErr := os.Lstat(target); statErr != nil {
		t.Fatalf("published but unconfirmed node directory is not visible: %v", statErr)
	}
	var retrySynced []string
	store, err := openWithSync(target, func(dir string) error {
		retrySynced = append(retrySynced, dir)
		return nil
	})
	if err != nil {
		t.Fatalf("retry Open() did not confirm visible directory: %v", err)
	}
	defer store.Close()
	if len(retrySynced) == 0 || retrySynced[0] != taskRoot {
		t.Fatalf("retry sync order = %q, want first confirmation of %q", retrySynced, taskRoot)
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

func TestRecoverInterruptedReconfirmsPublishedResultBeforeLaterUpload(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Begin(testTask()); err != nil {
		t.Fatal(err)
	}

	syncCalls := 0
	store.syncDir = func(string) error {
		syncCalls++
		// The cycle-start confirmation succeeds, then both the recovery write's
		// directory sync and its immediate confirmation fail.
		if syncCalls >= 2 {
			return errors.New("injected recovery directory sync failure")
		}
		return nil
	}
	if err := store.RecoverInterrupted("node-a"); err == nil || !strings.Contains(err.Error(), "confirm published recovery") {
		t.Fatalf("first RecoverInterrupted() error = %v, want unconfirmed published recovery", err)
	}
	if pending, err := store.Pending(); err == nil || pending != nil || !strings.Contains(err.Error(), "durability is unconfirmed") {
		t.Fatalf("Pending() after unconfirmed recovery = %+v, %v; want upload blocked", pending, err)
	}
	entries, err := store.readAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].State != stateDone || entries[0].Result == nil {
		t.Fatalf("published recovery was not retained: %+v", entries)
	}
	finishedAt := entries[0].Result.FinishedAt

	// A second runTasks cycle enters RecoverInterrupted before Pending. If
	// confirmation still fails, the cycle must stop and cannot upload.
	if err := store.RecoverInterrupted("node-a"); err == nil || !strings.Contains(err.Error(), "before recovery") {
		t.Fatalf("second RecoverInterrupted() error = %v, want pre-upload confirmation failure", err)
	}

	store.syncDir = syncDir
	if err := store.RecoverInterrupted("node-a"); err != nil {
		t.Fatalf("RecoverInterrupted() after durability recovery: %v", err)
	}
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil || !pending[0].Result.FinishedAt.Equal(finishedAt) {
		t.Fatalf("recovery result changed across durability retry: %+v", pending)
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

func TestBeginTreatsExactLeaseRedeliveryAsNoOpAndRejectsChangedScript(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := testTask()
	if created, err := store.Begin(task); err != nil || !created {
		t.Fatalf("first Begin() = created %v, err %v", created, err)
	}
	if created, err := store.Begin(task); err != nil || created {
		t.Fatalf("exact redelivery Begin() = created %v, err %v; want no-op", created, err)
	}
	changed := task
	changed.Script = "echo changed"
	if created, err := store.Begin(changed); err == nil || created || !strings.Contains(err.Error(), "different lease or content") {
		t.Fatalf("changed redelivery Begin() = created %v, err %v", created, err)
	}
	changedLease := task
	changedLease.LeaseID = "lease-b"
	if created, err := store.Begin(changedLease); err == nil || created || !strings.Contains(err.Error(), "different lease or content") {
		t.Fatalf("new-lease redelivery Begin() = created %v, err %v", created, err)
	}
	changedControlPlaneField := task
	changedControlPlaneField.ActorID = "actor-changed"
	changedControlPlaneField.Targets = []string{"node-other"}
	if created, err := store.Begin(changedControlPlaneField); err == nil || created || !strings.Contains(err.Error(), "different lease or content") {
		t.Fatalf("full-task redelivery Begin() = created %v, err %v", created, err)
	}
	entry, err := store.read(entryKey(task.ID, task.LeaseID))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Task.Script != task.Script || entry.State != stateLeased {
		t.Fatalf("redelivery changed durable journal: %+v", entry)
	}
}

func TestBeginExactCompletedRedeliveryPreservesResult(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := testTask()
	if _, err := store.Begin(task); err != nil {
		t.Fatal(err)
	}
	result := model.TaskResult{TaskID: task.ID, LeaseID: task.LeaseID, NodeID: "node-a", ExitCode: 0, Stdout: "exact"}
	if _, err := store.Complete(result); err != nil {
		t.Fatal(err)
	}
	if created, err := store.Begin(task); err != nil || created {
		t.Fatalf("completed redelivery Begin() = created %v, err %v", created, err)
	}
	pending, err := store.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Result == nil || !reflect.DeepEqual(*pending[0].Result, result) {
		t.Fatalf("completed redelivery changed exact result: %+v", pending)
	}
}

func TestBeginExactRedeliveryBypassesCapacity(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	task := testTask()
	if _, err := store.Begin(task); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxEntries; i++ {
		other := model.Task{ID: fmt.Sprintf("task-%04d", i), LeaseID: fmt.Sprintf("lease-%04d", i)}
		entry := Entry{Version: entryVersion, State: stateLeased, Task: other, UpdatedAt: time.Now().UTC()}
		raw, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.path(entryKey(other.ID, other.LeaseID)), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if created, err := store.Begin(task); err != nil || created {
		t.Fatalf("exact full-capacity redelivery = created %v, err %v", created, err)
	}
	if created, err := store.Begin(model.Task{ID: "task-overflow", LeaseID: "lease-overflow"}); !errors.Is(err, ErrCapacity) || created {
		t.Fatalf("new full-capacity task = created %v, err %v; want ErrCapacity", created, err)
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
	if err := store.ConfirmDurability(); err == nil || !strings.Contains(err.Error(), "directory sync failure") {
		t.Fatalf("ConfirmDurability() error = %v, want persistent sync failure", err)
	}
	store.syncDir = syncDir
	if err := store.ConfirmDurability(); err != nil {
		t.Fatalf("ConfirmDurability() after recovery: %v", err)
	}
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

func TestOpenRejectsPersistedLegacyLinechainProtocol(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := testTask()
	if _, err := store.BeginWithProtocol(task, "linechain-e3-v1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "unsupported persisted linechain durable protocol") {
		t.Fatalf("legacy linechain outbox error = %v", err)
	}
}

func testTask() model.Task {
	return model.Task{
		ID: "task-a", LeaseID: "lease-a", Interpreter: "sh", Script: "echo done",
		TimeoutSec: 10, OutputLimit: 1024,
	}
}
