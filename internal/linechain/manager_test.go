package linechain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
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
	if err := os.WriteFile(sidecarPath, []byte(testCurrentSidecar(nil, map[string]any{"credential": "sidecar-secret"})), 0o600); err != nil {
		t.Fatal(err)
	}
	fragment := `{"outbounds":[{"type":"direct","tag":"chain"}]}`
	doc := Document{Version: 2, Operation: "create", FragmentBasename: filepath.Base(fragmentPath), Fragment: &fragment, SidecarPatch: testSidecarPatch("create")}
	applyDoc(t, m, doc, "task-a", "lease-a")
	result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "task-a", LeaseID: "lease-a"}, model.TaskResult{TaskID: "task-a", LeaseID: "lease-a", ExitCode: 0, FinishedAt: time.Now().UTC()})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("resolve: result=%+v err=%v", result, err)
	}
	journalBytes, err := os.ReadFile(m.journalPath("task-a", "lease-a"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journalBytes), fragment) || strings.Contains(string(journalBytes), "sidecar-secret") {
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
	doc := Document{Version: 2, Operation: "create", FragmentBasename: filepath.Base(fragmentPath), Fragment: &desired, SidecarPatch: testSidecarPatch("create")}
	if err := applyDocErr(m, doc, "task-a", "lease-a"); err == nil || !strings.Contains(err.Error(), "unexpected existing") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := os.Remove(fragmentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "target"), fragmentPath); err != nil {
		t.Fatal(err)
	}
	if err := applyDocErr(m, doc, "task-b", "lease-b"); err == nil {
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
	oldFragment, oldSidecar := "old-fragment", testCurrentSidecar(stringPtr(newUUID), map[string]any{"ordinary": "old"})
	for path, data := range map[string]string{fragmentPath: oldFragment, sidecarPath: oldSidecar} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newFragment := "new-fragment"
	doc := Document{Version: 2, Operation: "replace", FragmentBasename: filepath.Base(fragmentPath), PreviousFragmentSHA256: stringPtr(digest([]byte(oldFragment))), Fragment: &newFragment, SidecarPatch: testSidecarPatch("replace")}
	if err := applyDocErr(m, doc, "task-a", "lease-a"); err == nil || !strings.Contains(err.Error(), "check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFile(t, fragmentPath, oldFragment)
	assertFile(t, sidecarPath, oldSidecar)
}

func TestRecoveryProducesStableFailureAndCleansAfterCompletion(t *testing.T) {
	m, dir := testManager(t)
	mustMkdir(t, filepath.Join(dir, "conf"))
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	if err := m.ConfigureLayout(filepath.Join(dir, "conf"), sidecarPath); err != nil {
		t.Fatal(err)
	}
	fragmentPath := filepath.Join(m.configDir, "lattice-linechain-0123456789abcdef0123.json")
	sidecarPath = m.sidecarPath
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	j := journal{
		Version: journalVersion, TaskID: "task-a", LeaseID: "lease-a", FragmentPath: fragmentPath, SidecarPath: sidecarPath,
		FragmentOutputSHA256: digest([]byte("new-fragment")), SidecarOutputSHA256: digest([]byte("new-sidecar")), ArtifactSHA256: digest([]byte("combined")), SidecarPatchSHA256: digest([]byte("patch")), TaskScriptSHA: digest(nil), Phase: "prepared",
	}
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
	if err := m.ConfigureLayout(configDir, filepath.Join(root, "lattice-metadata.json")); err != nil {
		t.Fatal(err)
	}
	basename := "lattice-linechain-0123456789abcdef0123.json"
	valid := BindDocument(Document{Version: 2, Operation: "create", ConfigDir: m.configDir, FragmentBasename: basename, FragmentPath: filepath.Join(m.configDir, basename), SidecarPath: m.sidecarPath, Fragment: &fragment, SidecarPatch: testSidecarPatch("create")})
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
	invalid = valid
	invalid.FragmentBasename = "lattice-linechain-not-hex.json"
	invalid.FragmentPath = filepath.Join(configDir, invalid.FragmentBasename)
	if err := m.validateDocument(invalid); err == nil {
		t.Fatal("malformed fragment basename accepted by internal validation")
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

func TestApplyRejectsTrailingAndLegacyWireFields(t *testing.T) {
	m, dir := testManager(t)
	configDir := filepath.Join(dir, "conf")
	mustMkdir(t, configDir)
	if err := m.ConfigureLayout(configDir, filepath.Join(dir, "lattice-metadata.json")); err != nil {
		t.Fatal(err)
	}
	fragment := `{}`
	d := BindDocument(Document{Version: 2, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json", Fragment: &fragment, SidecarPatch: testSidecarPatch("create")})
	base, _ := json.Marshal(wireDocumentV2{Version: d.Version, DurableProtocol: d.DurableProtocol, Operation: d.Operation, FragmentBasename: d.FragmentBasename,
		Fragment: d.Fragment, SidecarPatch: d.SidecarPatch, PreviousFragmentSHA256: d.PreviousFragmentSHA256,
		FragmentSHA256: d.FragmentSHA256, SidecarPatchSHA256: d.SidecarPatchSHA256, ArtifactSHA256: d.ArtifactSHA256})
	for name, raw := range map[string]string{
		"trailing":                       string(base) + ` {}`,
		"duplicate known field":          strings.Replace(string(base), `"version":2`, `"version":2,"version":2`, 1),
		"legacy config path":             strings.TrimSuffix(string(base), "}") + `,"config_dir":""}`,
		"legacy fragment path":           strings.TrimSuffix(string(base), "}") + `,"fragment_path":""}`,
		"legacy sidecar path":            strings.TrimSuffix(string(base), "}") + `,"sidecar_path":""}`,
		"legacy previous sidecar digest": strings.TrimSuffix(string(base), "}") + `,"previous_sidecar_sha256":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.Apply(context.Background(), strings.NewReader(raw), "task-"+name, "lease", digest([]byte("script"))); err == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
	t.Run("oversized whitespace", func(t *testing.T) {
		raw := string(base) + strings.Repeat(" ", maxDocumentSize-len(base)+1)
		if err := m.Apply(context.Background(), strings.NewReader(raw), "task-oversized", "lease", digest([]byte("script"))); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized wire error = %v", err)
		}
	})
}

func TestApplyRequiresStrictTaskScriptBinding(t *testing.T) {
	m, _ := testManager(t)
	for name, binding := range map[string]string{
		"missing": "", "short": "abcd", "uppercase": strings.Repeat("A", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.Apply(context.Background(), strings.NewReader(`{}`), "task", "lease", binding); err == nil || !strings.Contains(err.Error(), "script binding") {
				t.Fatalf("binding error=%v", err)
			}
		})
	}
}

func TestSemanticSidecarOverlayPreservesOrdinaryFields(t *testing.T) {
	m, dir := testManager(t)
	configDir := filepath.Join(dir, "conf")
	mustMkdir(t, configDir)
	sidecarPath := filepath.Join(dir, "lattice-metadata.json")
	if err := os.WriteFile(sidecarPath, []byte(testCurrentSidecar(nil, map[string]any{"ordinary": map[string]any{"owner": "sb"}})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	fragment := `{}`
	d := Document{Version: 2, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json", Fragment: &fragment, SidecarPatch: testSidecarPatch("create")}
	applyDoc(t, m, d, "task-overlay", "lease-overlay")
	b, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["ordinary"] == nil || got["schema"] != "lattice.singbox-metadata.v2" {
		t.Fatalf("overlay lost fields: %s", b)
	}
}

func TestConfigureLayoutAcceptsTrustedAliasAndRejectsHostileTarget(t *testing.T) {
	m, dir := testManager(t)
	realDir := filepath.Join(dir, "real")
	mustMkdir(t, realDir)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	metaReal := filepath.Join(dir, "meta-real")
	mustMkdir(t, metaReal)
	metaAlias := filepath.Join(dir, "meta-alias")
	if err := os.Symlink(metaReal, metaAlias); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureLayout(link, filepath.Join(metaAlias, "meta.json")); err != nil {
		t.Fatalf("trusted config alias rejected: %v", err)
	}
	wantConfig, _ := filepath.EvalSymlinks(realDir)
	wantMeta, _ := filepath.EvalSymlinks(metaReal)
	if m.configDir != wantConfig || m.sidecarPath != filepath.Join(wantMeta, "meta.json") {
		t.Fatalf("trusted aliases not canonicalized: config=%s sidecar=%s", m.configDir, m.sidecarPath)
	}
	badTarget := filepath.Join(dir, "bad-target")
	mustMkdir(t, badTarget)
	if err := os.Chmod(badTarget, 0o777); err != nil {
		t.Fatal(err)
	}
	badAlias := filepath.Join(dir, "bad-alias")
	if err := os.Symlink(badTarget, badAlias); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureLayout(badAlias, filepath.Join(dir, "meta.json")); err == nil {
		t.Fatal("alias to writable config root accepted")
	}
}

func TestApplyRejectsSymlinkAndInvalidCurrentSidecar(t *testing.T) {
	for name, setup := range map[string]func(string) error{
		"symlink": func(path string) error {
			target := path + ".target"
			if err := os.WriteFile(target, []byte(`{"schema":"lattice.singbox-metadata.v2","inbounds":[]}`), 0o600); err != nil {
				return err
			}
			return os.Symlink(target, path)
		},
		"null":         func(path string) error { return os.WriteFile(path, []byte(`null`), 0o600) },
		"wrong schema": func(path string) error { return os.WriteFile(path, []byte(`{"schema":"v1","inbounds":[]}`), 0o600) },
		"wrong inbounds": func(path string) error {
			return os.WriteFile(path, []byte(`{"schema":"lattice.singbox-metadata.v2","inbounds":{}}`), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, dir := testManager(t)
			configDir := filepath.Join(dir, "conf")
			mustMkdir(t, configDir)
			sidecarPath := filepath.Join(dir, "lattice-metadata.json")
			if err := setup(sidecarPath); err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
				t.Fatal(err)
			}
			fragment := `{}`
			d := Document{Version: 2, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json", Fragment: &fragment, SidecarPatch: testSidecarPatch("create")}
			if err := applyDocErr(m, d, "task-"+name, "lease"); err == nil {
				t.Fatal("invalid current sidecar accepted")
			}
		})
	}
}

func TestSnapshotRejectsRenamedAndDuplicateJournalIdentity(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "renamed", true: "duplicate"}[duplicate], func(t *testing.T) {
			m, _ := testManager(t)
			j := journal{Version: journalVersion, TaskID: "task-a", LeaseID: "lease-a", Phase: "prepared"}
			canonical := m.journalPath(j.TaskID, j.LeaseID)
			if duplicate {
				if err := writeJSON(canonical, j); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeJSON(filepath.Join(m.dir, "zz-renamed.json"), j); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Snapshot(); err == nil {
				t.Fatal("corrupt journal namespace accepted")
			}
		})
	}
}

func TestSnapshotRejectsSymlinkFIFOOwnerAndMode(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		m, _ := testManager(t)
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte(`{"version":1,"task_id":"secret","lease_id":"secret"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(m.dir, "symlink.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Snapshot(); err == nil {
			t.Fatal("journal symlink accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		m, _ := testManager(t)
		fifo := filepath.Join(m.dir, "fifo.json")
		if err := exec.Command("mkfifo", fifo).Run(); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		if _, err := m.Snapshot(); err == nil {
			t.Fatal("journal FIFO accepted")
		}
	})
	t.Run("mode", func(t *testing.T) {
		m, _ := testManager(t)
		j := journal{Version: journalVersion, TaskID: "task-mode", LeaseID: "lease"}
		path := m.journalPath(j.TaskID, j.LeaseID)
		if err := writeJSON(path, j); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Snapshot(); err == nil {
			t.Fatal("non-private journal mode accepted")
		}
	})
	if os.Geteuid() == 0 {
		t.Run("owner", func(t *testing.T) {
			m, _ := testManager(t)
			j := journal{Version: journalVersion, TaskID: "task-owner", LeaseID: "lease"}
			path := m.journalPath(j.TaskID, j.LeaseID)
			if err := writeJSON(path, j); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Snapshot(); err == nil {
				t.Fatal("wrong-owner journal accepted")
			}
		})
	}
}

func TestRecoveryPhasesRestoreOrCommitExactPair(t *testing.T) {
	for _, tc := range []struct {
		phase       string
		wantSuccess bool
	}{
		{phase: "prepared"},
		{phase: "fragment_published"},
		{phase: "pair_published"},
		{phase: "desired_verified", wantSuccess: true},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			m, _ := testManager(t)
			artifactRoot := t.TempDir()
			configDir := filepath.Join(artifactRoot, "conf")
			mustMkdir(t, configDir)
			fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
			sidecarPath := filepath.Join(artifactRoot, "lattice-metadata.json")
			if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
				t.Fatal(err)
			}
			fragmentPath = filepath.Join(m.configDir, filepath.Base(fragmentPath))
			sidecarPath = m.sidecarPath
			if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
				t.Fatal(err)
			}
			oldFragment := []byte("old-fragment")
			oldSidecar := []byte(testCurrentSidecar(stringPtr(newUUID), map[string]any{"ordinary": true}))
			newFragment := []byte("new-fragment")
			newSidecar := []byte(`{"inbounds":[],"schema":"lattice.singbox-metadata.v2"}` + "\n")
			currentFragment, currentSidecar := newFragment, newSidecar
			if tc.phase == "prepared" {
				currentFragment, currentSidecar = oldFragment, oldSidecar
			} else if tc.phase == "fragment_published" {
				currentSidecar = oldSidecar
			}
			if err := os.WriteFile(fragmentPath, currentFragment, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sidecarPath, currentSidecar, 0o600); err != nil {
				t.Fatal(err)
			}
			j := journal{
				Version: journalVersion, TaskID: "task-" + tc.phase, LeaseID: "lease", FragmentPath: fragmentPath, SidecarPath: sidecarPath,
				FragmentOld: digest(oldFragment), SidecarOld: digest(oldSidecar), FragmentOutputSHA256: digest(newFragment), SidecarOutputSHA256: digest(newSidecar),
				ArtifactSHA256: digest(append(append(append([]byte{}, newFragment...), 0), newSidecar...)), SidecarPatchSHA256: digest([]byte("patch")), TaskScriptSHA: digest(nil),
				FragmentHadOld: true, SidecarHadOld: true, Phase: tc.phase,
			}
			path := m.journalPath(j.TaskID, j.LeaseID)
			if err := m.writeBackup(path+".fragment.old", oldFragment, true); err != nil {
				t.Fatal(err)
			}
			if err := m.writeBackup(path+".sidecar.old", oldSidecar, true); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(path, j); err != nil {
				t.Fatal(err)
			}
			var got model.TaskResult
			if err := m.RequireRecovered(context.Background(), func(result model.TaskResult) error { got = result; return nil }, "node-a"); err != nil {
				t.Fatal(err)
			}
			if (got.ExitCode == 0) != tc.wantSuccess {
				t.Fatalf("result=%+v", got)
			}
			if tc.wantSuccess {
				assertFile(t, fragmentPath, string(newFragment))
				assertFile(t, sidecarPath, string(newSidecar))
			} else {
				assertFile(t, fragmentPath, string(oldFragment))
				assertFile(t, sidecarPath, string(oldSidecar))
			}
		})
	}
}

func TestJournalAuthorityRejectsCorruptSemanticsAndUnconfiguredRecovery(t *testing.T) {
	t.Run("unconfigured empty allowed", func(t *testing.T) {
		m, _ := testManager(t)
		if refs, err := m.Snapshot(); err != nil || len(refs) != 0 {
			t.Fatalf("empty unconfigured snapshot = %+v, %v", refs, err)
		}
	})
	t.Run("unconfigured journal blocked", func(t *testing.T) {
		m, _ := testManager(t)
		j := journal{Version: journalVersion, TaskID: "task-a", LeaseID: "lease-a", Phase: "prepared"}
		if err := writeJSON(m.journalPath(j.TaskID, j.LeaseID), j); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Snapshot(); err == nil || !strings.Contains(err.Error(), "before runtime layout") {
			t.Fatalf("error=%v", err)
		}
	})
	for name, mutate := range map[string]func(*journal){
		"phase":  func(j *journal) { j.Phase = "invented" },
		"path":   func(j *journal) { j.FragmentPath = filepath.Join(t.TempDir(), filepath.Base(j.FragmentPath)) },
		"digest": func(j *journal) { j.SidecarOutputSHA256 = "bad" },
		"result": func(j *journal) {
			j.Phase = "terminal_desired"
			j.Result = &model.TaskResult{TaskID: "wrong", LeaseID: j.LeaseID, FinishedAt: time.Now().UTC()}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, path := appliedJournal(t, "task-"+name, "lease")
			j, err := readJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&j)
			if err := writeJSON(path, j); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Snapshot(); err == nil {
				t.Fatal("corrupt journal semantics accepted")
			}
		})
	}
	t.Run("unknown field", func(t *testing.T) {
		m, path := appliedJournal(t, "task-unknown-field", "lease")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"unexpected":true}`)...)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Snapshot(); err == nil {
			t.Fatal("unknown journal field accepted")
		}
	})
}

func TestAuthorizedRecoveryRejectsJournalSwapAfterSnapshot(t *testing.T) {
	m, path := appliedJournal(t, "task-swap", "lease")
	refs, err := m.Snapshot()
	if err != nil || len(refs) != 1 {
		t.Fatalf("snapshot=%+v err=%v", refs, err)
	}
	ref := refs[0]
	authority := map[string]RecoveryAuthority{
		ref.TaskID + "\x00" + ref.LeaseID: {TaskScriptSHA: ref.TaskScriptSHA, ArtifactSHA256: ref.ArtifactSHA256, Phase: ref.Phase, ResultSHA256: resultSHA(ref.Result), JournalSHA256: ref.JournalSHA256},
	}
	j, err := readJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	j.ArtifactSHA256 = digest([]byte("swapped-artifact"))
	if err := writeJSON(path, j); err != nil {
		t.Fatal(err)
	}
	beforeFragment, _, err := readCurrent(j.FragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := m.RequireRecoveredAuthorized(context.Background(), func(model.TaskResult) error { called = true; return nil }, "node-a", authority); err == nil || !strings.Contains(err.Error(), "changed after authority capture") {
		t.Fatalf("error=%v", err)
	}
	afterFragment, _, err := readCurrent(j.FragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if called || !bytes.Equal(beforeFragment, afterFragment) {
		t.Fatal("journal swap mutated result or artifact")
	}
}

func TestRecoveryRejectsOversizeArtifactAndBackupSymlink(t *testing.T) {
	t.Run("oversize current", func(t *testing.T) {
		m, dir := testManager(t)
		configDir := filepath.Join(dir, "conf")
		mustMkdir(t, configDir)
		if err := m.ConfigureLayout(configDir, filepath.Join(dir, "meta.json")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(m.configDir, "lattice-linechain-0123456789abcdef0123.json")
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxArtifactSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readCurrent(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("backup symlink", func(t *testing.T) {
		m, path := appliedJournal(t, "task-backup", "lease")
		j, err := readJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		old := []byte("old")
		j.FragmentHadOld = true
		j.FragmentOld = digest(old)
		if err := writeJSON(path, j); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(target, old, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+".fragment.old"); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(j.FragmentPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.RequireRecovered(context.Background(), func(model.TaskResult) error { return nil }, "node-a"); err == nil {
			t.Fatal("symlink backup accepted")
		}
		after, err := os.ReadFile(j.FragmentPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("destination changed after rejected backup")
		}
	})
}

func TestApplyExactRetryReplaceAndRemove(t *testing.T) {
	m, _ := testManager(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "conf")
	mustMkdir(t, configDir)
	sidecarPath := filepath.Join(root, "meta.json")
	if err := os.WriteFile(sidecarPath, []byte(testCurrentSidecar(nil, map[string]any{"ordinary": "keep"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("check", []string{"restart"}, []string{"active"}); err != nil {
		t.Fatal(err)
	}
	runs := 0
	m.run = func(context.Context, string, ...string) ([]byte, error) { runs++; return nil, nil }
	basename := "lattice-linechain-0123456789abcdef0123.json"
	fragment1 := "one"
	create := Document{Version: 2, Operation: "create", FragmentBasename: basename, Fragment: &fragment1, SidecarPatch: testSidecarPatch("create")}
	applyDoc(t, m, create, "create", "lease")
	if err := m.Apply(context.Background(), bytes.NewReader(marshalDocument(t, create)), "create", "lease", digest([]byte("different-script"))); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched retry binding error=%v", err)
	}
	applyDoc(t, m, create, "create", "lease")
	if runs != 6 {
		t.Fatalf("exact retry reran host commands: %d", runs)
	}
	first, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "create", LeaseID: "lease"}, model.TaskResult{TaskID: "create", LeaseID: "lease", FinishedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "create", LeaseID: "lease"}, model.TaskResult{TaskID: "create", LeaseID: "lease", FinishedAt: time.Now().UTC().Add(time.Hour)})
	if err != nil || !second.FinishedAt.Equal(first.FinishedAt) {
		t.Fatalf("exact retry result drift: first=%+v second=%+v err=%v", first, second, err)
	}
	if err := m.Cleanup("create", "lease"); err != nil {
		t.Fatal(err)
	}

	fragment2 := "two"
	replace := Document{Version: 2, Operation: "replace", FragmentBasename: basename, PreviousFragmentSHA256: stringPtr(digest([]byte(fragment1))), Fragment: &fragment2, SidecarPatch: testSidecarPatch("replace")}
	applyDoc(t, m, replace, "replace", "lease")
	resolveSuccess(t, m, "replace", "lease")
	remove := Document{Version: 2, Operation: "remove", FragmentBasename: basename, PreviousFragmentSHA256: stringPtr(digest([]byte(fragment2))), SidecarPatch: testSidecarPatch("remove")}
	applyDoc(t, m, remove, "remove", "lease")
	resolveSuccess(t, m, "remove", "lease")
	if _, err := os.Stat(filepath.Join(m.configDir, basename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fragment remains: %v", err)
	}
	b, err := os.ReadFile(m.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"ordinary":"keep"`) {
		t.Fatalf("ordinary sidecar field lost: %s", b)
	}
}

func TestCommandAndRollbackFailureMatrix(t *testing.T) {
	for _, failAt := range []string{"check", "restart", "active"} {
		t.Run(failAt, func(t *testing.T) {
			m, _ := testManager(t)
			root := t.TempDir()
			configDir := filepath.Join(root, "conf")
			mustMkdir(t, configDir)
			sidecarPath := filepath.Join(root, "meta.json")
			oldFragment := "old"
			oldSidecar := testCurrentSidecar(stringPtr(newUUID), map[string]any{"ordinary": "secret-not-logged"})
			fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
			if err := os.WriteFile(fragmentPath, []byte(oldFragment), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sidecarPath, []byte(oldSidecar), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureCommands("check", []string{"restart"}, []string{"active"}); err != nil {
				t.Fatal(err)
			}
			m.run = func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name == failAt {
					return []byte("old new secret-not-logged private-key-canary"), errors.New("failed")
				}
				return nil, nil
			}
			newFragment := "new"
			d := Document{Version: 2, Operation: "replace", FragmentBasename: filepath.Base(fragmentPath), PreviousFragmentSHA256: stringPtr(digest([]byte(oldFragment))), Fragment: &newFragment, SidecarPatch: testSidecarPatch("replace")}
			err := applyDocErr(m, d, "task-"+failAt, "lease")
			if err == nil || strings.Contains(err.Error(), "secret-not-logged") || strings.Contains(err.Error(), "private-key-canary") {
				t.Fatalf("failure=%v", err)
			}
			journalBytes, readErr := os.ReadFile(m.journalPath("task-"+failAt, "lease"))
			if readErr == nil && (bytes.Contains(journalBytes, []byte("secret-not-logged")) || bytes.Contains(journalBytes, []byte("private-key-canary"))) {
				t.Fatalf("journal leaked command output: %s", journalBytes)
			}
			assertFile(t, fragmentPath, oldFragment)
			assertFile(t, sidecarPath, oldSidecar)
		})
	}

	t.Run("rollback backup failure is loud", func(t *testing.T) {
		m, path := appliedJournal(t, "task-rollback", "lease")
		j, err := readJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		j.Phase = "pair_published"
		j.FragmentHadOld = true
		j.FragmentOld = digest([]byte("old"))
		if err := writeJSON(path, j); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), path+".fragment.old"); err != nil {
			t.Fatal(err)
		}
		if err := m.RequireRecovered(context.Background(), func(model.TaskResult) error { return nil }, "node-a"); err == nil {
			t.Fatal("rollback failure was hidden")
		}
	})
}

func TestJournalAndPublishFailureMatrix(t *testing.T) {
	for _, failAt := range []string{"journal", "fragment publish", "sidecar publish"} {
		t.Run(failAt, func(t *testing.T) {
			m, _ := testManager(t)
			root := t.TempDir()
			configDir := filepath.Join(root, "conf")
			mustMkdir(t, configDir)
			fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
			sidecarPath := filepath.Join(root, "meta.json")
			oldFragment := "old"
			oldSidecar := testCurrentSidecar(stringPtr(newUUID), map[string]any{"ordinary": true})
			if err := os.WriteFile(fragmentPath, []byte(oldFragment), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sidecarPath, []byte(oldSidecar), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
				t.Fatal(err)
			}
			failed := false
			m.ConfigureMutationForTest(func(path string, content *string) error {
				shouldFail := (failAt == "fragment publish" && path == m.configDir+string(filepath.Separator)+filepath.Base(fragmentPath)) ||
					(failAt == "sidecar publish" && path == m.sidecarPath)
				if shouldFail && !failed {
					failed = true
					return errors.New("injected publish failure")
				}
				return publish(path, content)
			}, func(path string, value any) error {
				if failAt == "journal" && !failed {
					failed = true
					return errors.New("injected temp journal failure")
				}
				return writeJSON(path, value)
			})
			newFragment := "new"
			d := Document{Version: 2, Operation: "replace", FragmentBasename: filepath.Base(fragmentPath), PreviousFragmentSHA256: stringPtr(digest([]byte(oldFragment))), Fragment: &newFragment, SidecarPatch: testSidecarPatch("replace")}
			err := applyDocErr(m, d, "task-"+failAt, "lease")
			if err == nil || !failed {
				t.Fatalf("injected failure not surfaced: %v", err)
			}
			assertFile(t, fragmentPath, oldFragment)
			assertFile(t, sidecarPath, oldSidecar)
		})
	}
}

func TestPostRunAndRecoveryRuntimeVerificationFailures(t *testing.T) {
	newAppliedReplace := func(t *testing.T) (*Manager, string, string, string) {
		t.Helper()
		m, _ := testManager(t)
		root := t.TempDir()
		configDir := filepath.Join(root, "conf")
		mustMkdir(t, configDir)
		fragmentPath := filepath.Join(configDir, "lattice-linechain-0123456789abcdef0123.json")
		sidecarPath := filepath.Join(root, "meta.json")
		oldFragment := "old"
		oldSidecar := testCurrentSidecar(stringPtr(newUUID), map[string]any{"ordinary": true})
		if err := os.WriteFile(fragmentPath, []byte(oldFragment), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sidecarPath, []byte(oldSidecar), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
			t.Fatal(err)
		}
		if err := m.ConfigureCommands("check", []string{"restart"}, []string{"active"}); err != nil {
			t.Fatal(err)
		}
		m.run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
		newFragment := "new"
		d := Document{Version: 2, Operation: "replace", FragmentBasename: filepath.Base(fragmentPath), PreviousFragmentSHA256: stringPtr(digest([]byte(oldFragment))), Fragment: &newFragment, SidecarPatch: testSidecarPatch("replace")}
		applyDoc(t, m, d, "task-post-run", "lease")
		return m, fragmentPath, sidecarPath, oldSidecar
	}

	for _, boundary := range []string{"resolve desired", "recover desired"} {
		t.Run(boundary, func(t *testing.T) {
			m, fragmentPath, sidecarPath, oldSidecar := newAppliedReplace(t)
			failed := false
			m.run = func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name == "active" && !failed {
					failed = true
					return nil, errors.New("inactive")
				}
				return nil, nil
			}
			if boundary == "resolve desired" {
				result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: "task-post-run", LeaseID: "lease"}, model.TaskResult{TaskID: "task-post-run", LeaseID: "lease", FinishedAt: time.Now().UTC()})
				if err != nil || result.ExitCode == 0 || !strings.Contains(result.Error, "exact old pair restored") {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			} else {
				var result model.TaskResult
				if err := m.RequireRecovered(context.Background(), func(got model.TaskResult) error { result = got; return nil }, "node-a"); err != nil {
					t.Fatal(err)
				}
				if result.ExitCode == 0 || !strings.Contains(result.Error, "exact old pair restored") {
					t.Fatalf("result=%+v", result)
				}
			}
			assertFile(t, fragmentPath, "old")
			assertFile(t, sidecarPath, oldSidecar)
		})
	}

	t.Run("runner failure with inactive restored runtime remains nonterminal", func(t *testing.T) {
		m, fragmentPath, sidecarPath, oldSidecar := newAppliedReplace(t)
		m.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("inactive") }
		result := model.TaskResult{TaskID: "task-post-run", LeaseID: "lease", ExitCode: -1, Error: "helper killed", FinishedAt: time.Now().UTC()}
		if _, err := m.ResolveAfterRun(context.Background(), model.Task{ID: result.TaskID, LeaseID: result.LeaseID}, result); err == nil {
			t.Fatal("inactive restored runtime was recorded terminal")
		}
		assertFile(t, fragmentPath, "old")
		assertFile(t, sidecarPath, oldSidecar)
		j, err := readJournal(m.journalPath(result.TaskID, result.LeaseID))
		if err != nil {
			t.Fatal(err)
		}
		if journalTerminal(j.Phase) || j.Result != nil {
			t.Fatalf("failure became terminal: %+v", j)
		}
	})
}

func resolveSuccess(t *testing.T, m *Manager, taskID, leaseID string) {
	t.Helper()
	result := model.TaskResult{TaskID: taskID, LeaseID: leaseID, FinishedAt: time.Now().UTC()}
	result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: taskID, LeaseID: leaseID}, result)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("resolve result=%+v err=%v", result, err)
	}
	if err := m.Cleanup(taskID, leaseID); err != nil {
		t.Fatal(err)
	}
}

func appliedJournal(t *testing.T, taskID, leaseID string) (*Manager, string) {
	t.Helper()
	m, _ := testManager(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "conf")
	mustMkdir(t, configDir)
	if err := m.ConfigureLayout(configDir, filepath.Join(root, "meta.json")); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	fragment := `{}`
	applyDoc(t, m, Document{Version: 2, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json", Fragment: &fragment, SidecarPatch: testSidecarPatch("create")}, taskID, leaseID)
	return m, m.journalPath(taskID, leaseID)
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
	if m.sidecarPath != "" {
		if _, err := os.Lstat(m.sidecarPath); errors.Is(err, os.ErrNotExist) {
			inbound := map[string]any{"tag": d.SidecarPatch.SourceInboundTag, "line_uuid": d.SidecarPatch.SourceLineUUID}
			if d.SidecarPatch.ExpectedDownstreamLineUUID != nil {
				inbound["chain"] = map[string]any{"downstream_line_uuid": *d.SidecarPatch.ExpectedDownstreamLineUUID}
			}
			base, _ := json.Marshal(map[string]any{"schema": semanticSidecarMetadataSchema, "inbounds": []any{inbound}})
			if err := os.WriteFile(m.sidecarPath, base, 0o600); err != nil {
				return err
			}
		}
	}
	b := marshalDocument(nil, d)
	return m.Apply(context.Background(), strings.NewReader(string(b)), task, lease, digest([]byte(task)))
}

func testSidecarPatch(operation string) SidecarPatchV2 {
	patch := SidecarPatchV2{Schema: semanticSidecarPatchSchema, SourceLineUUID: sourceUUID, SourceInboundTag: "source", DesiredDownstreamLineUUID: stringPtr(newUUID)}
	if operation != "create" {
		patch.ExpectedDownstreamLineUUID = stringPtr(newUUID)
	}
	if operation == "remove" {
		patch.DesiredDownstreamLineUUID = nil
	}
	return patch
}

func marshalDocument(t *testing.T, d Document) []byte {
	d = BindDocument(d)
	b, err := json.Marshal(wireDocumentV2{
		Version: d.Version, DurableProtocol: d.DurableProtocol, Operation: d.Operation, FragmentBasename: d.FragmentBasename,
		Fragment: d.Fragment, SidecarPatch: d.SidecarPatch, PreviousFragmentSHA256: d.PreviousFragmentSHA256,
		FragmentSHA256: d.FragmentSHA256, SidecarPatchSHA256: d.SidecarPatchSHA256, ArtifactSHA256: d.ArtifactSHA256,
	})
	if err != nil && t != nil {
		t.Fatal(err)
	}
	return b
}

func TestConsumeProductionServerFixture(t *testing.T) {
	fixturePath := os.Getenv("LATTICE_LINECHAIN_SERVER_FIXTURE")
	if fixturePath == "" {
		t.Skip("LATTICE_LINECHAIN_SERVER_FIXTURE is not set")
	}
	type fixture struct {
		Schema                 string          `json:"schema"`
		ApprovalArtifactSHA256 string          `json:"approval_artifact_sha256"`
		RequestSHA256          string          `json:"request_sha256"`
		TaskScriptSHA256       string          `json:"task_script_sha256"`
		TaskID                 string          `json:"task_id"`
		LeaseID                string          `json:"lease_id"`
		Document               json.RawMessage `json:"document"`
	}
	rawFixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	dec := json.NewDecoder(bytes.NewReader(rawFixture))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("fixture has trailing data: %v", err)
	}
	if f.Schema != "lattice.linechain.cross-contract-fixture.v2" || !validSHA(f.ApprovalArtifactSHA256) || !validSHA(f.RequestSHA256) || !validSHA(f.TaskScriptSHA256) || f.TaskID == "" || f.LeaseID == "" {
		t.Fatalf("invalid production fixture wrapper: %+v", f)
	}
	var document wireDocumentV2
	if err := json.Unmarshal(f.Document, &document); err != nil {
		t.Fatal(err)
	}
	if document.ArtifactSHA256 != f.ApprovalArtifactSHA256 {
		t.Fatalf("approval/document artifact mismatch: %s != %s", f.ApprovalArtifactSHA256, document.ArtifactSHA256)
	}

	root := t.TempDir()
	m, err := Open(filepath.Join(root, "txn"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	configDir := filepath.Join(root, "conf")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(root, "lattice-metadata.json")
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureCommands("true", []string{"true"}, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	current := []byte("{\n  \"unknown_root\": {\"preserve\": true},\n  \"schema\": \"lattice.singbox-metadata.v2\",\n  \"inbounds\": [\n" +
		"    {\"tag\":\"before\",\"line_uuid\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"keep\":1},\n" +
		"    {\"tag\":\"source-b\",\"line_uuid\":\"22222222-2222-4222-8222-222222222222\",\"ordinary\":\"keep\"},\n" +
		"    {\"tag\":\"after\",\"line_uuid\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"keep\":2}\n  ]\n}\n")
	if err := os.WriteFile(sidecarPath, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), bytes.NewReader(f.Document), f.TaskID, f.LeaseID, f.TaskScriptSHA256); err != nil {
		t.Fatal(err)
	}

	j, err := readJournal(m.journalPath(f.TaskID, f.LeaseID))
	if err != nil {
		t.Fatal(err)
	}
	fragmentBytes, err := os.ReadFile(filepath.Join(configDir, document.FragmentBasename))
	if err != nil {
		t.Fatal(err)
	}
	sidecarBytes, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if j.ArtifactSHA256 != f.ApprovalArtifactSHA256 || j.TaskScriptSHA != f.TaskScriptSHA256 || j.FragmentOutputSHA256 != digest(fragmentBytes) || j.SidecarOutputSHA256 != digest(sidecarBytes) {
		t.Fatalf("fixture journal authority/output mismatch: %+v", j)
	}
	var output struct {
		UnknownRoot map[string]bool `json:"unknown_root"`
		Inbounds    []struct {
			Tag      string         `json:"tag"`
			Ordinary string         `json:"ordinary"`
			Keep     int            `json:"keep"`
			Chain    map[string]any `json:"chain"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(sidecarBytes, &output); err != nil {
		t.Fatal(err)
	}
	wantDownstream := ""
	if document.SidecarPatch.DesiredDownstreamLineUUID != nil {
		wantDownstream = *document.SidecarPatch.DesiredDownstreamLineUUID
	}
	if !output.UnknownRoot["preserve"] || len(output.Inbounds) != 3 || output.Inbounds[0].Tag != "before" || output.Inbounds[0].Keep != 1 || output.Inbounds[1].Tag != "source-b" || output.Inbounds[1].Ordinary != "keep" || output.Inbounds[2].Tag != "after" || output.Inbounds[2].Keep != 2 || output.Inbounds[1].Chain["downstream_line_uuid"] != wantDownstream {
		t.Fatalf("fixture merge did not preserve scoped host state: %s", sidecarBytes)
	}

	m.publishFile = func(string, *string) error { return errors.New("replay attempted to republish output") }
	if err := m.Apply(context.Background(), bytes.NewReader(f.Document), f.TaskID, f.LeaseID, f.TaskScriptSHA256); err != nil {
		t.Fatal(err)
	}
	replayed, err := readJournal(m.journalPath(f.TaskID, f.LeaseID))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Phase != "terminal_desired" || replayed.FragmentOutputSHA256 != j.FragmentOutputSHA256 || replayed.SidecarOutputSHA256 != j.SidecarOutputSHA256 {
		t.Fatalf("fixture replay did not use journaled output authority: %+v", replayed)
	}
}

func testCurrentSidecar(expected *string, extras map[string]any) string {
	inbound := map[string]any{"tag": "source", "line_uuid": sourceUUID}
	if expected != nil {
		inbound["chain"] = map[string]any{"downstream_line_uuid": *expected}
	}
	top := map[string]any{"schema": semanticSidecarMetadataSchema, "inbounds": []any{inbound}}
	for key, value := range extras {
		top[key] = value
	}
	raw, err := json.Marshal(top)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func assertFile(t *testing.T, p, want string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil || string(b) != want {
		t.Fatalf("file %s = %q err=%v", p, b, err)
	}
}
