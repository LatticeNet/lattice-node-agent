// Package linechain applies the two host-local artifacts that define a
// sing-box line chain as one crash-recoverable transaction.
package linechain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	journalVersion  = 1
	maxDocumentSize = 4 << 20
	maxDiagnostic   = 4096
)

var linechainBasenameRE = regexp.MustCompile(`^lattice-linechain-[0-9a-f]{20}\.json$`)

// Document is the bounded server-rendered input consumed by -linechain-apply.
// Desired content is never copied into the journal; only its digest is stored.
type Document struct {
	Version                int     `json:"version"`
	Operation              string  `json:"operation"`
	ConfigDir              string  `json:"config_dir"`
	FragmentBasename       string  `json:"fragment_basename,omitempty"`
	FragmentPath           string  `json:"fragment_path"`
	SidecarPath            string  `json:"sidecar_path"`
	PreviousFragmentSHA256 string  `json:"previous_fragment_sha256,omitempty"`
	PreviousSidecarSHA256  string  `json:"previous_sidecar_sha256,omitempty"`
	Fragment               *string `json:"fragment,omitempty"`
	Sidecar                *string `json:"sidecar,omitempty"`
	FragmentSHA256         string  `json:"fragment_sha256,omitempty"`
	SidecarSHA256          string  `json:"sidecar_sha256,omitempty"`
	CombinedSHA256         string  `json:"combined_sha256"`
}

// BindDocument computes the deterministic desired artifact binding.
func BindDocument(d Document) Document {
	d.FragmentSHA256 = digestPtr(d.Fragment)
	d.SidecarSHA256 = digestPtr(d.Sidecar)
	var pair []byte
	if d.Fragment != nil {
		pair = append(pair, []byte(*d.Fragment)...)
	}
	pair = append(pair, 0)
	if d.Sidecar != nil {
		pair = append(pair, []byte(*d.Sidecar)...)
	}
	d.CombinedSHA256 = digest(pair)
	return d
}

type journal struct {
	Version        int               `json:"version"`
	TaskID         string            `json:"task_id"`
	LeaseID        string            `json:"lease_id"`
	FragmentPath   string            `json:"fragment_path"`
	SidecarPath    string            `json:"sidecar_path"`
	FragmentOld    string            `json:"fragment_old_sha256,omitempty"`
	SidecarOld     string            `json:"sidecar_old_sha256,omitempty"`
	FragmentNew    string            `json:"fragment_desired_sha256,omitempty"`
	SidecarNew     string            `json:"sidecar_desired_sha256,omitempty"`
	FragmentHadOld bool              `json:"fragment_had_old"`
	SidecarHadOld  bool              `json:"sidecar_had_old"`
	Phase          string            `json:"phase"`
	Result         *model.TaskResult `json:"result,omitempty"`
}

type Manager struct {
	dir            string
	lock           *os.File
	run            func(context.Context, string, ...string) ([]byte, error)
	configDir      string
	sidecarPath    string
	remove         func(string) error
	syncDirectory  func(string) error
	singBoxBinary  string
	restartCommand []string
	verifyCommand  []string
}

func (m *Manager) ConfigureLayout(configDir, sidecarPath string) error {
	configDir = filepath.Clean(strings.TrimSpace(configDir))
	sidecarPath = filepath.Clean(strings.TrimSpace(sidecarPath))
	if !filepath.IsAbs(configDir) || !filepath.IsAbs(sidecarPath) {
		return fmt.Errorf("linechain layout paths must be absolute")
	}
	if err := validateParents(filepath.Join(configDir, "placeholder")); err != nil {
		return err
	}
	if err := validateParents(sidecarPath); err != nil {
		return err
	}
	m.configDir = configDir
	m.sidecarPath = sidecarPath
	return nil
}
func (m *Manager) Configured() bool { return m != nil && m.configDir != "" && m.sidecarPath != "" }

// ConfigureCommands is an integration-test seam. Production uses fixed local
// command vectors; task documents cannot select executables or arguments.
func (m *Manager) ConfigureCommands(binary string, restart, verify []string) error {
	if strings.TrimSpace(binary) == "" || len(restart) == 0 || len(verify) == 0 {
		return fmt.Errorf("linechain command vectors must be non-empty")
	}
	m.singBoxBinary = binary
	m.restartCommand = append([]string(nil), restart...)
	m.verifyCommand = append([]string(nil), verify...)
	return nil
}

// ConfigureCleanupForTest injects cleanup fault seams for crash-boundary tests.
func (m *Manager) ConfigureCleanupForTest(remove func(string) error, syncDirectory func(string) error) {
	if remove == nil {
		remove = os.Remove
	}
	if syncDirectory == nil {
		syncDirectory = syncDir
	}
	m.remove = remove
	m.syncDirectory = syncDirectory
}

// Open takes exclusive ownership of a private absolute transaction directory.
func Open(dir string) (*Manager, error) {
	m, err := open(dir)
	if err != nil {
		return nil, err
	}
	lock, err := lockManager(filepath.Join(m.dir, ".lock"))
	if err != nil {
		return nil, fmt.Errorf("linechain transaction manager already open: %w", err)
	}
	m.lock = lock
	if err := syncDir(m.dir); err != nil {
		_ = unlockManager(lock)
		m.lock = nil
		return nil, err
	}
	return m, nil
}

// OpenHelper opens the transaction directory without taking the manager lock.
// It is used only by a child helper spawned by the lock-owning agent.
func OpenHelper(dir string) (*Manager, error) { return open(dir) }

func open(dir string) (*Manager, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || !filepath.IsAbs(dir) || dir == string(filepath.Separator) {
		return nil, fmt.Errorf("linechain transaction directory must be absolute and non-root")
	}
	if err := makeDurablePrivateDir(dir, syncDir); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("linechain transaction path must be a real directory")
	}
	if !ownedPath(info) || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("linechain transaction directory must be agent-owned with exact mode 0700")
	}
	m := &Manager{dir: dir}
	m.remove = os.Remove
	m.syncDirectory = syncDir
	m.singBoxBinary = "sing-box"
	m.restartCommand = []string{"systemctl", "restart", "sing-box"}
	m.verifyCommand = []string{"systemctl", "is-active", "--quiet", "sing-box"}
	m.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	return m, nil
}

func makeDurablePrivateDir(dir string, syncDirectory func(string) error) error {
	dir = filepath.Clean(dir)
	missing := []string{}
	current := dir
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("path component must be a real directory: %s", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for linechain transaction directory")
		}
		current = parent
	}
	if parent := filepath.Dir(current); parent != current {
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("confirm existing directory %s: %w", current, err)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		path := missing[i]
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync parent after creating %s: %w", path, err)
		}
	}
	return nil
}

func (m *Manager) Close() error {
	if m == nil || m.lock == nil {
		return nil
	}
	err := unlockManager(m.lock)
	m.lock = nil
	return err
}

func (m *Manager) journalPath(taskID, leaseID string) string {
	s := sha256.Sum256([]byte(taskID + "\x00" + leaseID))
	return filepath.Join(m.dir, hex.EncodeToString(s[:])+".json")
}

// Apply reads and applies one document. It is intended for the early-exit
// helper mode and obtains task identity from the runner's minimal environment.
func (m *Manager) Apply(ctx context.Context, r io.Reader, taskID, leaseID string) error {
	if strings.TrimSpace(taskID) == "" || strings.TrimSpace(leaseID) == "" {
		return fmt.Errorf("task and lease identity are required")
	}
	dec := json.NewDecoder(io.LimitReader(r, maxDocumentSize+1))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("decode linechain document: %w", err)
	}
	if d.Version == 2 && (d.ConfigDir != "" || d.FragmentPath != "" || d.SidecarPath != "") {
		return fmt.Errorf("v2 documents must not contain server-supplied paths")
	}
	// Artifact locations are agent-owned. The server may provide only the
	// deterministic basename; full paths are derived from the locally resolved
	// sing-box layout and cannot redirect writes.
	if d.FragmentBasename != "" {
		if filepath.Base(d.FragmentBasename) != d.FragmentBasename || !linechainBasenameRE.MatchString(d.FragmentBasename) {
			return fmt.Errorf("fragment_basename is invalid")
		}
		if d.FragmentPath != "" && filepath.Clean(d.FragmentPath) != filepath.Join(m.configDir, d.FragmentBasename) {
			return fmt.Errorf("fragment_path is not agent-owned")
		}
		d.FragmentPath = filepath.Join(m.configDir, d.FragmentBasename)
		if d.SidecarPath != "" && filepath.Clean(d.SidecarPath) != filepath.Clean(m.sidecarPath) {
			return fmt.Errorf("sidecar_path is not agent-owned")
		}
		d.SidecarPath = m.sidecarPath
	}
	if err := m.validateDocument(d); err != nil {
		return err
	}
	path := m.journalPath(taskID, leaseID)
	if _, err := os.Lstat(path); err == nil {
		return m.recoverOne(ctx, path, nil, "")
	}

	fragmentOld, fragmentHad, err := readCurrent(d.FragmentPath)
	if err != nil {
		return err
	}
	sidecarOld, sidecarHad, err := readCurrent(d.SidecarPath)
	if err != nil {
		return err
	}
	if err := requirePrevious("fragment", fragmentOld, fragmentHad, d.PreviousFragmentSHA256); err != nil {
		return err
	}
	if err := requirePrevious("sidecar", sidecarOld, sidecarHad, d.PreviousSidecarSHA256); err != nil {
		return err
	}
	j := journal{Version: journalVersion, TaskID: taskID, LeaseID: leaseID, FragmentPath: d.FragmentPath, SidecarPath: d.SidecarPath,
		FragmentOld: digest(fragmentOld), SidecarOld: digest(sidecarOld), FragmentHadOld: fragmentHad, SidecarHadOld: sidecarHad,
		FragmentNew: digestPtr(d.Fragment), SidecarNew: digestPtr(d.Sidecar), Phase: "prepared"}
	if err := m.writeBackup(path+".fragment.old", fragmentOld, fragmentHad); err != nil {
		return err
	}
	if err := m.writeBackup(path+".sidecar.old", sidecarOld, sidecarHad); err != nil {
		return err
	}
	if err := writeJSON(path, j); err != nil {
		return err
	}
	if err := publish(d.FragmentPath, d.Fragment); err != nil {
		return m.rollback(ctx, path, &j, d, fmt.Errorf("publish fragment: %w", err))
	}
	j.Phase = "fragment_published"
	if err := writeJSON(path, j); err != nil {
		return err
	}
	if err := publish(d.SidecarPath, d.Sidecar); err != nil {
		return m.rollback(ctx, path, &j, d, fmt.Errorf("publish sidecar: %w", err))
	}
	j.Phase = "pair_published"
	if err := writeJSON(path, j); err != nil {
		return err
	}
	if err := m.checkRestartVerify(ctx, d); err != nil {
		return m.rollback(ctx, path, &j, d, err)
	}
	j.Phase = "desired_verified"
	return writeJSON(path, j)
}

func (m *Manager) validateDocument(d Document) error {
	if d.Version != journalVersion && d.Version != 2 {
		return fmt.Errorf("unsupported linechain document version %d", d.Version)
	}
	if d.Version == 2 && d.FragmentBasename == "" {
		return fmt.Errorf("v2 fragment_basename is required")
	}
	switch d.Operation {
	case "create":
		if d.PreviousFragmentSHA256 != "" || d.PreviousSidecarSHA256 != "" || d.Fragment == nil || d.Sidecar == nil {
			return fmt.Errorf("create document has inconsistent old/desired shape")
		}
	case "replace":
		if d.PreviousFragmentSHA256 == "" || d.PreviousSidecarSHA256 == "" || d.Fragment == nil || d.Sidecar == nil {
			return fmt.Errorf("replace document has inconsistent old/desired shape")
		}
	case "remove":
		if d.PreviousFragmentSHA256 == "" || d.PreviousSidecarSHA256 == "" || d.Fragment != nil || d.Sidecar == nil {
			return fmt.Errorf("remove document has inconsistent old/desired shape")
		}
	default:
		return fmt.Errorf("unsupported linechain operation %q", d.Operation)
	}
	bound := BindDocument(d)
	if d.FragmentSHA256 != bound.FragmentSHA256 || d.SidecarSHA256 != bound.SidecarSHA256 || d.CombinedSHA256 != bound.CombinedSHA256 {
		return fmt.Errorf("linechain desired artifact digest binding mismatch")
	}
	configDir := filepath.Clean(d.ConfigDir)
	if !m.Configured() {
		return fmt.Errorf("linechain runtime layout is unresolved")
	}
	if configDir != m.configDir {
		return fmt.Errorf("config_dir does not match the locally resolved sing-box directory")
	}
	if !filepath.IsAbs(configDir) || configDir == string(filepath.Separator) {
		return fmt.Errorf("config_dir must be absolute and non-root")
	}
	for _, p := range []string{d.FragmentPath, d.SidecarPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) == string(filepath.Separator) {
			return fmt.Errorf("artifact path must be absolute and non-root")
		}
		if strings.Contains(filepath.Clean(p), "..") {
			return fmt.Errorf("artifact path escapes its directory")
		}
	}
	if filepath.Clean(d.FragmentPath) == filepath.Clean(d.SidecarPath) {
		return fmt.Errorf("fragment and sidecar paths must differ")
	}
	fragmentName := filepath.Base(d.FragmentPath)
	if filepath.Dir(filepath.Clean(d.FragmentPath)) != configDir || !strings.HasPrefix(fragmentName, "lattice-linechain-") || filepath.Ext(fragmentName) != ".json" {
		return fmt.Errorf("fragment path is outside the server-owned linechain config namespace")
	}
	wantSidecar := m.sidecarPath
	if filepath.Clean(d.SidecarPath) != wantSidecar {
		return fmt.Errorf("sidecar path must match locally resolved %s", wantSidecar)
	}
	if err := validateParents(d.FragmentPath); err != nil {
		return err
	}
	if err := validateParents(d.SidecarPath); err != nil {
		return err
	}
	for _, want := range []string{d.PreviousFragmentSHA256, d.PreviousSidecarSHA256} {
		if want != "" && !validSHA(want) {
			return fmt.Errorf("previous artifact digest is invalid")
		}
	}
	return nil
}

func (m *Manager) checkRestartVerify(ctx context.Context, d Document) error {
	if out, err := m.run(ctx, m.singBoxBinary, "check", "-C", m.configDir); err != nil {
		return fmt.Errorf("sing-box check failed: %s", bounded(out))
	}
	restart := m.restartCommand
	if out, err := m.run(ctx, restart[0], restart[1:]...); err != nil {
		return fmt.Errorf("sing-box restart failed: %s", bounded(out))
	}
	verify := m.verifyCommand
	if out, err := m.run(ctx, verify[0], verify[1:]...); err != nil {
		return fmt.Errorf("sing-box active verification failed: %s", bounded(out))
	}
	return nil
}

// ResolveAfterRun converts the host transaction into one stable terminal result.
func (m *Manager) ResolveAfterRun(ctx context.Context, task model.Task, result model.TaskResult) (model.TaskResult, error) {
	path := m.journalPath(task.ID, task.LeaseID)
	j, err := readJournal(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && (result.ExitCode != 0 || result.Error != "") {
			if result.FinishedAt.IsZero() {
				result.FinishedAt = time.Now().UTC()
			}
			return result, nil
		}
		return result, err
	}
	if j.Result != nil {
		return *j.Result, nil
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	if result.ExitCode == 0 && result.Error == "" && j.Phase == "desired_verified" {
		if !pairMatches(j, true) {
			return result, fmt.Errorf("desired linechain pair is not exact")
		}
		j.Phase = "terminal_desired"
	} else {
		if err := m.restoreOld(path, &j); err != nil {
			return result, err
		}
		if result.ExitCode == 0 {
			result.ExitCode = -1
		}
		if result.Error == "" {
			result.Error = "linechain helper did not leave a verified desired pair; exact old pair restored"
		}
		j.Phase = "terminal_old"
	}
	j.Result = &result
	if err := writeJSON(path, j); err != nil {
		return result, err
	}
	return result, nil
}

// RequireRecovered resolves all non-terminal journals before network activity.
// complete is called only with a stable exact result; cleanup follows its
// confirmed durable completion.
func (m *Manager) RequireRecovered(ctx context.Context, complete func(model.TaskResult) error, nodeID string) error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if err := m.recoverOne(ctx, filepath.Join(m.dir, entry.Name()), complete, nodeID); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) recoverOne(ctx context.Context, path string, complete func(model.TaskResult) error, nodeID string) error {
	j, err := readJournal(path)
	if err != nil {
		return err
	}
	if j.Result == nil {
		result := model.TaskResult{TaskID: j.TaskID, LeaseID: j.LeaseID, NodeID: nodeID, ExitCode: -1, Error: "linechain transaction interrupted; exact old pair restored", FinishedAt: time.Now().UTC()}
		if j.Phase == "desired_verified" && pairMatches(j, true) {
			result.ExitCode = 0
			result.Error = ""
			j.Phase = "terminal_desired"
		} else {
			if err := m.restoreOld(path, &j); err != nil {
				return err
			}
			if err := m.checkRestartVerify(ctx, Document{}); err != nil {
				return fmt.Errorf("recover old linechain pair service state: %w", err)
			}
			j.Phase = "terminal_old"
		}
		j.Result = &result
		if err := writeJSON(path, j); err != nil {
			return err
		}
	}
	if complete != nil {
		if err := complete(*j.Result); err != nil {
			return err
		}
		return m.Cleanup(j.TaskID, j.LeaseID)
	}
	return nil
}

func (m *Manager) Cleanup(taskID, leaseID string) error {
	path := m.journalPath(taskID, leaseID)
	for _, p := range []string{path + ".fragment.old", path + ".sidecar.old", path} {
		if err := m.remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return m.syncDirectory(m.dir)
}

func (m *Manager) rollback(ctx context.Context, path string, j *journal, d Document, cause error) error {
	if err := m.restoreOld(path, j); err != nil {
		return fmt.Errorf("%v; rollback failed: %w", cause, err)
	}
	if err := m.checkRestartVerify(ctx, d); err != nil {
		return fmt.Errorf("%v; exact old pair restored but service recovery failed: %s", cause, bounded([]byte(err.Error())))
	}
	return cause
}

func (m *Manager) restoreOld(path string, j *journal) error {
	for _, a := range []struct {
		dst, backup string
		had         bool
		want        string
	}{{j.FragmentPath, path + ".fragment.old", j.FragmentHadOld, j.FragmentOld}, {j.SidecarPath, path + ".sidecar.old", j.SidecarHadOld, j.SidecarOld}} {
		if a.had {
			data, err := os.ReadFile(a.backup)
			if err != nil {
				return err
			}
			if digest(data) != a.want {
				return fmt.Errorf("backup digest mismatch")
			}
			s := string(data)
			if err := publish(a.dst, &s); err != nil {
				return err
			}
		} else if err := publish(a.dst, nil); err != nil {
			return err
		}
	}
	if !pairMatches(*j, false) {
		return fmt.Errorf("restored pair digest mismatch")
	}
	j.Phase = "old_restored"
	return writeJSON(path, *j)
}

func pairMatches(j journal, desired bool) bool {
	a, ah, e1 := readCurrent(j.FragmentPath)
	b, bh, e2 := readCurrent(j.SidecarPath)
	if e1 != nil || e2 != nil {
		return false
	}
	if desired {
		return digestMaybe(a, ah) == j.FragmentNew && digestMaybe(b, bh) == j.SidecarNew
	}
	return ah == j.FragmentHadOld && bh == j.SidecarHadOld && digestMaybe(a, ah) == j.FragmentOld && digestMaybe(b, bh) == j.SidecarOld
}

func readCurrent(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ownedPath(info) {
		return nil, false, fmt.Errorf("artifact is not a regular file: %s", path)
	}
	b, err := os.ReadFile(path)
	return b, true, err
}
func requirePrevious(name string, data []byte, exists bool, want string) error {
	if want == "" {
		if exists {
			return fmt.Errorf("unexpected existing %s artifact", name)
		}
		return nil
	}
	if !exists || digest(data) != strings.ToLower(want) {
		return fmt.Errorf("%s artifact does not match previous digest", name)
	}
	return nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func digestPtr(s *string) string {
	if s == nil {
		return ""
	}
	return digest([]byte(*s))
}
func digestMaybe(b []byte, exists bool) string {
	if !exists {
		return ""
	}
	return digest(b)
}
func validSHA(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}
func bounded(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > maxDiagnostic {
		b = b[:maxDiagnostic]
	}
	return string(b)
}
func (m *Manager) writeBackup(path string, data []byte, exists bool) error {
	if !exists {
		return nil
	}
	return writeFile(path, data)
}
func publish(path string, content *string) error {
	if err := validateParents(path); err != nil {
		return err
	}
	if content == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(path))
	}
	return writeFile(path, []byte(*content))
}
func validateParents(path string) error {
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if (!info.IsDir() && info.Mode()&os.ModeSymlink == 0) || (dir == filepath.Dir(path) && info.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("artifact parent must be a real directory")
		}
		if dir == filepath.Dir(path) && !ownedPath(info) {
			return fmt.Errorf("artifact parent must be owned by the agent user")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".lattice-linechain-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err == nil {
		err = f.Sync()
		_ = f.Close()
	}
	if err != nil {
		return err
	}
	return syncDir(dir)
}
func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}
func readJournal(path string) (journal, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return journal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return journal{}, fmt.Errorf("invalid linechain journal")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return journal{}, err
	}
	var j journal
	if err = json.Unmarshal(b, &j); err != nil {
		return j, err
	}
	if j.Version != journalVersion || j.TaskID == "" || j.LeaseID == "" {
		return j, fmt.Errorf("invalid linechain journal identity")
	}
	return j, nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
