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
	Result             *model.TaskResult `json:"result,omitempty"`
	ExecutionStartedAt time.Time         `json:"execution_started_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	key                string
}

// Store is a bounded, file-backed task result outbox.
type Store struct {
	dir     string
	syncDir func(string) error
	lock    *os.File
}

// Open creates or validates a private outbox directory.
func Open(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("task result outbox directory is empty")
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("task result outbox directory must be absolute: %q", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	store := &Store{dir: dir, syncDir: syncDir, lock: lock}
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

// Close releases this process's exclusive ownership of the outbox.
func (s *Store) Close() error {
	if s == nil || s.lock == nil {
		return nil
	}
	err := unlockOutbox(s.lock)
	s.lock = nil
	return err
}

// Begin durably records a task lease before any task code is executed. The
// committed return value reports whether the final journal path was published,
// even if a subsequent directory sync reported an error.
func (s *Store) Begin(task model.Task) (committed bool, err error) {
	if strings.TrimSpace(task.ID) == "" || strings.TrimSpace(task.LeaseID) == "" {
		return false, fmt.Errorf("task id and lease id are required for durable execution")
	}
	entries, err := s.readAll()
	if err != nil {
		return false, err
	}
	if len(entries) >= maxEntries {
		return false, ErrCapacity
	}
	key := entryKey(task.ID, task.LeaseID)
	for _, entry := range entries {
		if entry.key == key {
			return false, fmt.Errorf("task lease is already journaled: %s", task.ID)
		}
	}
	now := time.Now().UTC()
	return s.writeNew(key, Entry{
		Version:            entryVersion,
		State:              stateLeased,
		Task:               task,
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

// RecoverInterrupted turns every pre-execution/unknown-outcome lease journal
// into an honest synthetic result. It never re-runs the task.
func (s *Store) RecoverInterrupted(nodeID string) error {
	entries, err := s.readAll()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.State != stateLeased {
			continue
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
		if _, err := s.write(entry.key, entry); err != nil {
			return fmt.Errorf("recover interrupted task %s: %w", entry.Task.ID, err)
		}
	}
	return nil
}

// Pending returns completed results in deterministic oldest-first order.
func (s *Store) Pending() ([]Entry, error) {
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

// Remove atomically unlinks an acknowledged outbox entry and syncs the
// directory so the acknowledgement survives a crash.
func (s *Store) Remove(entry Entry) error {
	if entry.key == "" {
		entry.key = entryKey(entry.Task.ID, entry.Task.LeaseID)
	}
	if err := os.Remove(s.path(entry.key)); err != nil {
		return fmt.Errorf("remove acknowledged task result: %w", err)
	}
	return s.syncDir(s.dir)
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
			return true, fmt.Errorf("remove published task result temp file: %w", err)
		}
	} else if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("publish task result journal: %w", err)
	}
	if err := s.syncDir(s.dir); err != nil {
		return true, fmt.Errorf("sync task result outbox: %w", err)
	}
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
