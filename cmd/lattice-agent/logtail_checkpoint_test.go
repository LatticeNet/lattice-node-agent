package main

import (
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
