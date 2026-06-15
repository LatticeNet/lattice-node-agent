// Package logtail follows an appended log file read-only, yielding new complete
// lines in batches with byte-offset checkpoints and rotation/truncation
// handling. It is the agent-side core of log ingestion: pure Go, no CGo, no
// fsnotify (a polling agent re-reads on its own tick). It never writes to or
// rotates the file it observes.
package logtail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	defaultMaxLineBytes = 16384
	defaultMaxReadBytes = 1 << 20 // 1 MiB per poll, bounds memory on a chatty file
)

// Tailer follows one file. It is not safe for concurrent use; the agent runs one
// per source in its own goroutine.
type Tailer struct {
	path         string
	maxLineBytes int
	maxReadBytes int64

	file        *os.File
	info        os.FileInfo
	offset      int64
	incarnation int
	started     bool // first ensureOpen seeks to end unless a checkpoint was set
	resumed     bool
}

// New builds a Tailer for path. maxLineBytes<=0 uses the default.
func New(path string, maxLineBytes int) *Tailer {
	if maxLineBytes <= 0 {
		maxLineBytes = defaultMaxLineBytes
	}
	return &Tailer{path: path, maxLineBytes: maxLineBytes, maxReadBytes: defaultMaxReadBytes}
}

// Resume restores a checkpoint so a restart continues without re-shipping or
// losing position. Call before the first Poll.
func (t *Tailer) Resume(offset uint64, incarnation int) {
	t.offset = int64(offset)
	t.incarnation = incarnation
	t.resumed = true
	t.started = true
}

// Offset is the byte offset after the last consumed line (the checkpoint).
func (t *Tailer) Offset() uint64 { return uint64(t.offset) }

// RotID is an opaque per-incarnation id that changes on rotation/truncation, so
// the server can tell the offset namespace reset.
func (t *Tailer) RotID() string { return strconv.Itoa(t.incarnation) }

// Incarnation is the rotation counter (persisted in the checkpoint).
func (t *Tailer) Incarnation() int { return t.incarnation }

// Close releases the file handle.
func (t *Tailer) Close() error {
	if t.file != nil {
		err := t.file.Close()
		t.file = nil
		return err
	}
	return nil
}

func (t *Tailer) ensureOpen() error {
	if t.file != nil {
		return nil
	}
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !t.started {
		// First ever start with no checkpoint: collect only new lines.
		t.offset = info.Size()
		t.started = true
	}
	if t.offset > info.Size() {
		t.offset = 0 // checkpoint points past EOF (file was replaced/truncated)
	}
	if _, err := f.Seek(t.offset, 0); err != nil {
		f.Close()
		return err
	}
	t.file = f
	t.info = info
	return nil
}

// Poll reads any appended complete lines since the last checkpoint and returns
// them (truncated to maxLineBytes, without the trailing newline). It detects
// truncation (copytruncate) on the open handle and inode rotation on the path;
// on either, it resets to the new incarnation. A missing file is returned as an
// error so the caller backs off without crashing.
func (t *Tailer) Poll() ([]string, error) {
	if err := t.ensureOpen(); err != nil {
		return nil, err
	}
	info, err := t.file.Stat()
	if err != nil {
		return nil, err
	}
	// Same-inode truncation (logrotate copytruncate zeroes the file).
	if info.Size() < t.offset {
		t.offset = 0
		t.incarnation++
		if _, err := t.file.Seek(0, 0); err != nil {
			return nil, err
		}
	}

	lines, err := t.readLines(info.Size())
	if err != nil {
		return nil, err
	}

	// Cross-inode rotation: the live path now points at a different file.
	if pathInfo, statErr := os.Stat(t.path); statErr == nil && !os.SameFile(t.info, pathInfo) {
		// Drained what we could from the old handle this pass; reopen the new
		// file from its start on the next Poll. (The brief tail written to the
		// old inode after this read may be missed — documented MVP limitation.)
		_ = t.file.Close()
		t.file = nil
		t.offset = 0
		t.incarnation++
	}
	return lines, nil
}

// readLines reads from the current offset up to maxReadBytes, returns complete
// lines, and advances the offset to the last newline boundary. A line longer
// than maxReadBytes with no newline is force-emitted (truncated) so a pathological
// unterminated line can never wedge progress.
func (t *Tailer) readLines(size int64) ([]string, error) {
	avail := size - t.offset
	if avail <= 0 {
		return nil, nil
	}
	if avail > t.maxReadBytes {
		avail = t.maxReadBytes
	}
	buf := make([]byte, avail)
	n, err := t.file.ReadAt(buf, t.offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	buf = buf[:n]

	lastNL := bytes.LastIndexByte(buf, '\n')
	if lastNL < 0 {
		if int64(n) >= t.maxReadBytes {
			// Unterminated over-long line: force a break so we make progress.
			t.offset += int64(n)
			return []string{t.truncate(buf)}, nil
		}
		return nil, nil // wait for the newline
	}
	consumed := buf[:lastNL+1]
	t.offset += int64(len(consumed))
	raw := bytes.Split(consumed[:len(consumed)-1], []byte{'\n'})
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		out = append(out, t.truncate(bytes.TrimSuffix(line, []byte{'\r'})))
	}
	return out, nil
}

func (t *Tailer) truncate(b []byte) string {
	if len(b) > t.maxLineBytes {
		b = b[:t.maxLineBytes]
	}
	return string(b)
}

// CheckpointString / ParseCheckpoint are tiny helpers for the agent's on-disk
// checkpoint file (offset + incarnation).
func CheckpointString(offset uint64, incarnation int) string {
	return fmt.Sprintf("%d:%d", offset, incarnation)
}

func ParseCheckpoint(s string) (offset uint64, incarnation int, ok bool) {
	var off uint64
	var inc int
	if _, err := fmt.Sscanf(s, "%d:%d", &off, &inc); err != nil {
		return 0, 0, false
	}
	return off, inc, true
}
