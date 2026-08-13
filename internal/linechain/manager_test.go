package linechain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApplyCreateResolveAndCleanup(t *testing.T) {
	m, dir := testManager(t)
	configDir := filepath.Join(dir, "conf")
	fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	mustMkdir(t, filepath.Dir(fragmentPath))
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	fragment := `{"outbounds":[{"type":"direct","tag":"chain"}]}`
	sidecar := `{"schema":"lattice.singbox-metadata.v2","inbounds":[]}`
	doc := Document{Version: 2, Operation: "create", FragmentBasename: filepath.Base(fragmentPath), Fragment: &fragment, Sidecar: &sidecar}
	applyDoc(t, m, doc, "task-a", "lease-a")
	result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "task-a", LeaseID: "lease-a"}, model.TaskResult{TaskID: "task-a", LeaseID: "lease-a", ExitCode: 0, FinishedAt: time.Now().UTC()})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("resolve: result=%+v err=%v", result, err)
	}
	journalBytes, err := os.ReadFile(m.journalPath("task-a", "lease-a"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journalBytes), fragment) {
		t.Fatal("journal contains credential-bearing desired bytes")
	}
	if err := m.Cleanup("task-a", "lease-a"); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRejectsUnexpectedExistingAndSymlink(t *testing.T) {
	m, dir := testManager(t)
	mustMkdir(t, filepath.Join(dir, "conf"))
	configDir := filepath.Join(dir, "conf")
	fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fragmentPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	desired := "new"
	desiredSidecar := "{}"
	doc := Document{Version: 2, Operation: "create", FragmentBasename: filepath.Base(fragmentPath), Fragment: &desired, Sidecar: &desiredSidecar}
	if err := applyDocErr(m, doc, "task-a", "lease-a"); err == nil || !strings.Contains(err.Error(), "unexpected existing") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := os.Remove(fragmentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), fragmentPath); err != nil {
		t.Fatal(err)
	}
	if err := applyDocErr(m, doc, "task-b", "lease-b"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckFailureRestoresExactOldPair(t *testing.T) {
	m, dir := testManager(t)
	mustMkdir(t, filepath.Join(dir, "conf"))
	configDir := filepath.Join(dir, "conf")
	fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("false", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	oldFragment, oldSidecar := "old-fragment", "old-sidecar"
	for path, data := range map[string]string{fragmentPath: oldFragment, sidecarPath: oldSidecar} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newFragment, newSidecar := "new-fragment", "new-sidecar"
	doc := Document{Version: 2, Operation: "replace", FragmentBasename: filepath.Base(fragmentPath), PreviousFragmentSHA256: digest([]byte(oldFragment)), Fragment: &newFragment, Sidecar: &newSidecar}
	if err := applyDocErr(m, doc, "task-a", "lease-a"); err == nil || !strings.Contains(err.Error(), "check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFile(t, fragmentPath, oldFragment)
	assertFile(t, sidecarPath, oldSidecar)
}

func TestRecoveryProducesStableFailureAndCleansAfterCompletion(t *testing.T) {
	m, dir := testManager(t)
	mustMkdir(t, filepath.Join(dir, "conf"))
	fragmentPath := filepath.Join(dir, "conf", "lattice-linechain-0123456789abcdef0123.json")
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	if err := m.ConfigureLayout(filepath.Join(dir, "conf"), sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	j := journal{Version: 1, TaskID: "task-a", LeaseID: "lease-a", FragmentPath: fragmentPath, SidecarPath: sidecarPath, Phase: "prepared"}
	path := m.journalPath(j.TaskID, j.LeaseID)
	if err := writeJSON(path, j); err != nil {
		t.Fatal(err)
	}
	var got model.TaskResult
	if err := m.RequireRecovered(context.Background(), func(r model.TaskResult) error { got = r; return nil }, "node-a"); err != nil {
		t.Fatal(err)
	}
	if got.ExitCode == 0 || got.TaskID != j.TaskID || got.LeaseID != j.LeaseID || got.FinishedAt.IsZero() {
		t.Fatalf("bad recovered result: %+v", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal not cleaned: %v", err)
	}
}

func TestOpenIsExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "txn")
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := Open(dir); err == nil {
		t.Fatal("second manager unexpectedly acquired lock")
	}
	if helper, err := OpenHelper(dir); err != nil {
		t.Fatal(err)
	} else {
		_ = helper.Close()
	}
}

func TestOpenRecoversStaleLockFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "txn")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Open(dir)
	if err != nil {
		t.Fatalf("stale lock file blocked advisory lock: %v", err)
	}
	defer m.Close()
}

func TestValidateDocumentBindsOwnedPaths(t *testing.T) {
	m, _ := testManager(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "conf")
	mustMkdir(t, configDir)
	fragment := "{}"
	sidecar := "{}"
	if err := m.ConfigureLayout(configDir, filepath.Join(root, "lattice-metadata.json")); err != nil {
		t.Fatal(err)
	}
	basename := "lattice-linechain-0123456789abcdef0123.json"
	valid := BindDocument(Document{Version: 2, Operation: "create", ConfigDir: configDir, FragmentBasename: basename, FragmentPath: filepath.Join(configDir, basename), SidecarPath: filepath.Join(root, "lattice-metadata.json"), Fragment: &fragment, Sidecar: &sidecar})
	if err := m.validateDocument(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.FragmentPath = filepath.Join(root, "outside.json")
	if err := m.validateDocument(invalid); err == nil {
		t.Fatal("outside fragment accepted")
	}
	invalid = valid
	invalid.SidecarPath = filepath.Join(root, "other.json")
	if err := m.validateDocument(invalid); err == nil {
		t.Fatal("unowned sidecar accepted")
	}
}

func TestResolvePreflightFailureWithoutJournal(t *testing.T) {
	m, _ := testManager(t)
	finished := time.Now().UTC()
	input := model.TaskResult{TaskID: "task-a", LeaseID: "lease-a", ExitCode: -1, Error: "document rejected before host mutation", FinishedAt: finished}
	got, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "task-a", LeaseID: "lease-a"}, input)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("preflight result changed: %+v", got)
	}
}

func testManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "txn")
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, dir
}
func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}
func applyDoc(t *testing.T, m *Manager, d Document, task, lease string) {
	t.Helper()
	if err := applyDocErr(m, d, task, lease); err != nil {
		t.Fatal(err)
	}
}
func applyDocErr(m *Manager, d Document, task, lease string) error {
	d = BindDocument(d)
	b, _ := json.Marshal(wireDocumentV2{
		Version: d.Version, Operation: d.Operation, FragmentBasename: d.FragmentBasename,
		PreviousFragmentSHA256: d.PreviousFragmentSHA256, Fragment: d.Fragment, Sidecar: d.Sidecar,
		FragmentSHA256: d.FragmentSHA256, SidecarSHA256: d.SidecarSHA256, CombinedSHA256: d.CombinedSHA256,
	})
	return m.Apply(context.Background(), strings.NewReader(string(b)), task, lease)
}
func assertFile(t *testing.T, p, want string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil || string(b) != want {
		t.Fatalf("file %s = %q err=%v", p, b, err)
	}
}
