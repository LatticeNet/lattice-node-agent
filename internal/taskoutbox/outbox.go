// Package taskoutbox persists leased tasks and their results so an agent
// restart or transient control-plane failure cannot cause silent re-execution
// or result loss.
package taskoutbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	entryVersion = 1
	stateLeased  = "leased"
	stateDone    = "completed"
	maxEntries   = 1024
	maxEntrySize = 4 << 20 // 4 MiB: bounds scripts plus capped task output.
)

var ErrCapacity = errors.New("task result outbox capacity exceeded")

// Entry is a durable task execution journal record.
type Entry struct {
	Version            int               `json:"version"`
	State              string            `json:"state"`
	Task               model.Task        `json:"task"`
	DurableProtocol    string            `json:"durable_protocol,omitempty"`
	Result             *model.TaskResult `json:"result,omitempty"`
	ExecutionStartedAt time.Time         `json:"execution_started_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	key                string
}

// Store is a bounded, file-backed task result outbox.
type Store struct {
	dir                   string
	syncDir               func(string) error
	lock                  *os.File
	durabilityUnconfirmed bool
}

// Open creates or validates a private outbox directory.
func Open(dir string) (*Store, error) {
	return openWithSync(dir, syncDir)
}

func openWithSync(dir string, syncDirectory func(string) error) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("task result outbox directory is empty")
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("task result outbox directory must be absolute: %q", dir)
	}
	if syncDirectory == nil {
		syncDirectory = syncDir
	}
	if err := makeDurablePrivateDir(dir, syncDirectory); err != nil {
		return nil, fmt.Errorf("create task result outbox: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect task result outbox: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("task result outbox must be a real directory: %s", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure task result outbox: %w", err)
	}
	lock, err := lockOutbox(filepath.Join(dir, ".lock"))
	if err != nil {
		return nil, err
	}
	store := &Store{dir: dir, syncDir: syncDirectory, lock: lock}
	if err := store.cleanupTemps(); err != nil {
		_ = store.Close()
		return nil, err
	}
	if _, err := store.readAll(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// makeDurablePrivateDir creates every missing path component with private
// permissions and fsyncs its parent immediately after publication. It also
// re-confirms the deepest visible component so a retry cannot mistake a prior
// sync-failed mkdir for a crash-durable directory entry.
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
			return fmt.Errorf("inspect directory %s: %w", current, err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent for task result outbox: %s", dir)
		}
		current = parent
	}

	// Confirm the deepest existing component before extending it. A prior Open
	// may have created exactly this component and then failed its parent fsync;
	// creation proceeds only one confirmed component at a time, so this retry
	// closes that ambiguity without trusting mere directory visibility.
	if parent := filepath.Dir(current); parent != current {
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("confirm existing directory %s: %w", current, err)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		path := missing[i]
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create private directory %s: %w", path, err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync parent after creating %s: %w", path, err)
		}
	}
	return nil
}

// Close releases this process's exclusive ownership of the outbox.
func (s *Store) Close() error {
	if s == nil || s.lock == nil {
		return nil
	}
	err := unlockOutbox(s.lock)
	s.lock = nil
	return err
}

// Begin durably records a task lease before any task code is executed. A false,
// nil result means the exact executable task and lease are already journaled and
// must not be executed again. A true result means this call published the new
// lease journal, even if a subsequent directory sync reported an error.
func (s *Store) Begin(task model.Task) (committed bool, err error) {
	return s.begin(task, "")
}

// BeginWithProtocol records the leased delivery discriminator for recovery.
func (s *Store) BeginWithProtocol(task model.Task, protocol string) (bool, error) {
	return s.begin(task, protocol)
}

func (s *Store) begin(task model.Task, protocol string) (committed bool, err error) {
	if strings.TrimSpace(task.ID) == "" || strings.TrimSpace(task.LeaseID) == "" {
		return false, fmt.Errorf("task id and lease id are required for durable execution")
	}
	entries, err := s.readAll()
	if err != nil {
		return false, err
	}
	key := entryKey(task.ID, task.LeaseID)
	for _, entry := range entries {
		if entry.Task.ID == task.ID {
			if entry.key == key && reflect.DeepEqual(entry.Task, task) && entry.DurableProtocol == protocol {
				return false, nil
			}
			return false, fmt.Errorf("task %s was redelivered with a different lease or content", task.ID)
		}
	}
	if len(entries) >= maxEntries {
		return false, ErrCapacity
	}
	now := time.Now().UTC()
	return s.writeNew(key, Entry{
		Version:            entryVersion,
		State:              stateLeased,
		Task:               task,
		DurableProtocol:    protocol,
		ExecutionStartedAt: now,
		UpdatedAt:          now,
	})
}

// Complete replaces the lease journal with the full result before upload. The
// committed return value has the same publication semantics as Begin.
func (s *Store) Complete(result model.TaskResult) (committed bool, err error) {
	key := entryKey(result.TaskID, result.LeaseID)
	entry, err := s.read(key)
	if err != nil {
		return false, err
	}
	if entry.State == stateDone && entry.Result != nil && reflect.DeepEqual(*entry.Result, result) {
		return false, nil
	}
	if entry.State != stateLeased {
		return false, fmt.Errorf("task lease %s is not awaiting completion", result.TaskID)
	}
	if entry.Task.ID != result.TaskID || entry.Task.LeaseID != result.LeaseID {
		return false, fmt.Errorf("task result does not match durable lease")
	}
	entry.State = stateDone
	entry.Result = &result
	entry.UpdatedAt = time.Now().UTC()
	return s.write(key, entry)
}

// ConfirmDurability retries the directory sync that makes a published journal
// transition crash-durable. A completed result must not be exposed to the
// server after Complete reports committed=true with an error until this call
// succeeds.
func (s *Store) ConfirmDurability() error {
	if err := s.syncDir(s.dir); err != nil {
		return fmt.Errorf("confirm task result outbox durability: %w", err)
	}
	s.durabilityUnconfirmed = false
	return nil
}

// RecoverInterrupted turns every pre-execution/unknown-outcome lease journal
// into an honest synthetic result. It never re-runs the task.
func (s *Store) RecoverInterrupted(nodeID string) error {
	// runTasks always calls recovery before Pending. Re-confirm the journal
	// directory on every cycle so a completed entry that was published by a
	// prior recovery attempt but whose directory fsync failed can never be
	// uploaded merely because it is visible after the failed call.
	if err := s.ConfirmDurability(); err != nil {
		return fmt.Errorf("confirm task result outbox before recovery: %w", err)
	}
	entries, err := s.readAll()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.State != stateLeased {
			continue
		}
		if entry.DurableProtocol == "linechain-e3-v1" {
			return fmt.Errorf("leased E3 task %s requires linechain journal recovery before generic outbox recovery", entry.Task.ID)
		}
		now := time.Now().UTC()
		result := model.TaskResult{
			TaskID:     entry.Task.ID,
			LeaseID:    entry.Task.LeaseID,
			NodeID:     nodeID,
			ExitCode:   -1,
			Error:      "agent restarted or lost durable result after task launch; execution outcome is unknown and the task was not re-executed",
			StartedAt:  entry.ExecutionStartedAt,
			FinishedAt: now,
		}
		entry.State = stateDone
		entry.Result = &result
		entry.UpdatedAt = now
		committed, writeErr := s.write(entry.key, entry)
		if writeErr == nil {
			continue
		}
		if !committed {
			return fmt.Errorf("recover interrupted task %s: %w", entry.Task.ID, writeErr)
		}
		// The unknown-outcome result is visible after rename, but it must not
		// escape through Pending until its directory entry is crash-durable.
		// Try immediately; if this also fails, the next recovery cycle's leading
		// confirmation blocks upload and preserves the exact published result.
		if confirmErr := s.ConfirmDurability(); confirmErr != nil {
			return fmt.Errorf("recover interrupted task %s: %v; confirm published recovery: %w", entry.Task.ID, writeErr, confirmErr)
		}
	}
	return nil
}

// Pending returns completed results in deterministic oldest-first order.
func (s *Store) Pending() ([]Entry, error) {
	if s.durabilityUnconfirmed {
		return nil, fmt.Errorf("task result outbox durability is unconfirmed")
	}
	entries, err := s.readAll()
	if err != nil {
		return nil, err
	}
	pending := entries[:0]
	for _, entry := range entries {
		if entry.State == stateDone && entry.Result != nil {
			pending = append(pending, entry)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].UpdatedAt.Equal(pending[j].UpdatedAt) {
			return pending[i].key < pending[j].key
		}
		return pending[i].UpdatedAt.Before(pending[j].UpdatedAt)
	})
	return pending, nil
}

// Snapshot returns a bounded copy of every leased and completed entry.
func (s *Store) Snapshot() ([]Entry, error) {
	entries, err := s.readAll()
	if err != nil {
		return nil, err
	}
	return append([]Entry(nil), entries...), nil
}

// Remove atomically unlinks an acknowledged outbox entry and syncs the
// directory so the acknowledgement survives a crash.
func (s *Store) Remove(entry Entry) error {
	if entry.key == "" {
		entry.key = entryKey(entry.Task.ID, entry.Task.LeaseID)
	}
	if err := os.Remove(s.path(entry.key)); err != nil {
		return fmt.Errorf("remove acknowledged task result: %w", err)
	}
	if err := s.syncDir(s.dir); err != nil {
		s.durabilityUnconfirmed = true
		return err
	}
	return nil
}

func (s *Store) readAll() ([]Entry, error) {
	dirEntries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read task result outbox: %w", err)
	}
	entries := make([]Entry, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() || !strings.HasSuffix(dirEntry.Name(), ".json") {
			continue
		}
		if len(entries) >= maxEntries {
			return nil, ErrCapacity
		}
		key := strings.TrimSuffix(dirEntry.Name(), ".json")
		entry, err := s.read(key)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *Store) read(key string) (Entry, error) {
	path := s.path(key)
	info, err := os.Lstat(path)
	if err != nil {
		return Entry{}, fmt.Errorf("inspect task result journal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Entry{}, fmt.Errorf("task result journal is not a regular file: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Entry{}, fmt.Errorf("task result journal permissions are not private: %s", path)
	}
	if info.Size() > maxEntrySize {
		return Entry{}, fmt.Errorf("task result journal exceeds %d bytes: %s", maxEntrySize, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, fmt.Errorf("open task result journal: %w", err)
	}
	defer f.Close()
	var entry Entry
	dec := json.NewDecoder(io.LimitReader(f, maxEntrySize+1))
	if err := dec.Decode(&entry); err != nil {
		return Entry{}, fmt.Errorf("decode task result journal: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Entry{}, fmt.Errorf("decode task result journal: unexpected trailing data")
	} else if !errors.Is(err, io.EOF) {
		return Entry{}, fmt.Errorf("decode task result journal trailing data: %w", err)
	}
	if entry.Version != entryVersion || entry.Task.ID == "" || entry.Task.LeaseID == "" {
		return Entry{}, fmt.Errorf("invalid task result journal: %s", path)
	}
	if key != entryKey(entry.Task.ID, entry.Task.LeaseID) {
		return Entry{}, fmt.Errorf("task result journal key mismatch: %s", path)
	}
	if entry.State != stateLeased && entry.State != stateDone {
		return Entry{}, fmt.Errorf("invalid task result journal state %q", entry.State)
	}
	if entry.State == stateLeased && entry.Result != nil {
		return Entry{}, fmt.Errorf("leased task result journal unexpectedly contains a result")
	}
	if entry.State == stateDone {
		if entry.Result == nil || entry.Result.TaskID != entry.Task.ID || entry.Result.LeaseID != entry.Task.LeaseID {
			return Entry{}, fmt.Errorf("completed task result journal does not match its lease")
		}
	}
	entry.key = key
	return entry, nil
}

func (s *Store) cleanupTemps() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read task result outbox: %w", err)
	}
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".task-result-") || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect stale task result journal: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("stale task result journal is not a regular file: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale task result journal: %w", err)
		}
		removed = true
	}
	if removed {
		return s.syncDir(s.dir)
	}
	return nil
}

func (s *Store) write(key string, entry Entry) (bool, error) {
	return s.writeEntry(key, entry, false)
}

func (s *Store) writeNew(key string, entry Entry) (bool, error) {
	return s.writeEntry(key, entry, true)
}

func (s *Store) writeEntry(key string, entry Entry, createOnly bool) (bool, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return false, fmt.Errorf("encode task result journal: %w", err)
	}
	if len(data) > maxEntrySize {
		return false, fmt.Errorf("task result journal exceeds %d bytes", maxEntrySize)
	}
	tmp, err := os.CreateTemp(s.dir, ".task-result-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create task result journal: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return false, fmt.Errorf("secure task result journal: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return false, fmt.Errorf("write task result journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return false, fmt.Errorf("sync task result journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("close task result journal: %w", err)
	}
	finalPath := s.path(key)
	if createOnly {
		// Linking a fully written same-directory temp file publishes the initial
		// lease without overwriting another agent process's journal.
		if err := os.Link(tmpPath, finalPath); err != nil {
			_ = os.Remove(tmpPath)
			return false, fmt.Errorf("publish new task result journal: %w", err)
		}
		if err := os.Remove(tmpPath); err != nil {
			s.durabilityUnconfirmed = true
			return true, fmt.Errorf("remove published task result temp file: %w", err)
		}
	} else if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("publish task result journal: %w", err)
	}
	if err := s.syncDir(s.dir); err != nil {
		s.durabilityUnconfirmed = true
		return true, fmt.Errorf("sync task result outbox: %w", err)
	}
	s.durabilityUnconfirmed = false
	return true, nil
}

func (s *Store) path(key string) string {
	return filepath.Join(s.dir, key+".json")
}

func entryKey(taskID, leaseID string) string {
	sum := sha256.Sum256([]byte(taskID + "\x00" + leaseID))
	return hex.EncodeToString(sum[:])
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
