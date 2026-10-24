package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The server names a log source, and the agent, running as root, turns that
// name into a checkpoint file. A name that is not a plain file name must not
// reach outside the state directory: it gets no checkpoint at all, and the
// source still tails from the end, as it does with no state directory.
func TestLogCheckpointPathStaysInStateDir(t *testing.T) {
	dir := t.TempDir()
	m := newLogTailManager(agentConfig{LogStateDir: dir})
	for _, id := range []string{"logsrc_abcdefghijklmnop", "agent-debug-0123456789abcdef", "singbox-0123456789abcdef"} {
		if got, want := m.checkpointPath(id), filepath.Join(dir, id+".ckpt"); got != want {
			t.Errorf("checkpointPath(%q) = %q, want %q", id, got, want)
		}
	}
	for _, id := range []string{"", "../escape", "../../etc/cron.d/x", "a/b", "/abs", ".", "..", ".hidden", "a\x00b"} {
		if got := m.checkpointPath(id); got != "" {
			t.Errorf("checkpointPath(%q) = %q, want no checkpoint", id, got)
		}
	}
}

// A checkpoint belongs to the file it measured. When a source's path changes
// under the same id, the old offset says nothing about the new file, so the
// source starts like a new one, from the end, instead of resuming: a smaller
// new file used to restart at 0 and ship whole.
func TestLogCheckpointIsBoundToItsPath(t *testing.T) {
	ckpt := filepath.Join(t.TempDir(), "logsrc_a.ckpt")
	saveLogCheckpoint(ckpt, "/var/log/syslog", 1<<20, 3)
	if off, inc, ok := loadLogCheckpoint(ckpt, "/var/log/syslog"); !ok || off != 1<<20 || inc != 3 {
		t.Fatalf("same path: offset %d, incarnation %d, ok %t", off, inc, ok)
	}
	if _, _, ok := loadLogCheckpoint(ckpt, "/var/log/other.log"); ok {
		t.Fatal("a checkpoint resumed a different file")
	}
	// A checkpoint an older agent wrote names no file, so nothing says it
	// measured this one: the source starts at the end, as a new one does.
	if err := os.WriteFile(ckpt, []byte("42:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := loadLogCheckpoint(ckpt, "/var/log/syslog"); ok {
		t.Fatal("an unbound checkpoint resumed a source")
	}
}
