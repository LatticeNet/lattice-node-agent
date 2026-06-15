package logtail

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func poll(t *testing.T, tl *Tailer) []string {
	t.Helper()
	lines, err := tl.Poll()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	return lines
}

func TestTailFromEndThenAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "old1\nold2\n")
	tl := New(path, 0)
	defer tl.Close()
	// First poll seeks to end: history is not shipped.
	if lines := poll(t, tl); len(lines) != 0 {
		t.Fatalf("expected no history lines, got %v", lines)
	}
	appendFile(t, path, "a\nb\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"a", "b"}) {
		t.Fatalf("got %v", lines)
	}
	// A partial line (no newline) is not shipped until terminated.
	appendFile(t, path, "partial")
	if lines := poll(t, tl); len(lines) != 0 {
		t.Fatalf("partial line must wait, got %v", lines)
	}
	appendFile(t, path, " done\nnext\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"partial done", "next"}) {
		t.Fatalf("got %v", lines)
	}
}

func TestResumeFromCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "x\ny\nz\n")
	tl := New(path, 0)
	tl.Resume(0, 0) // read from the start instead of the end
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"x", "y", "z"}) {
		t.Fatalf("got %v", lines)
	}
	off, inc := tl.Offset(), tl.Incarnation()
	tl.Close()

	appendFile(t, path, "w\n")
	tl2 := New(path, 0)
	tl2.Resume(off, inc)
	defer tl2.Close()
	if lines := poll(t, tl2); !reflect.DeepEqual(lines, []string{"w"}) {
		t.Fatalf("resume continued wrong: %v", lines)
	}
}

func TestRotationRenameRecreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "a\n")
	tl := New(path, 0)
	defer tl.Close()
	poll(t, tl) // seek to end
	appendFile(t, path, "b\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"b"}) {
		t.Fatalf("got %v", lines)
	}
	// logrotate move-and-recreate.
	if err := os.Rename(path, filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "c\n")
	// First poll after rotation drains the old handle and detects the new inode.
	poll(t, tl)
	// Next poll opens the new file from the start.
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"c"}) {
		t.Fatalf("post-rotation got %v", lines)
	}
	if tl.Incarnation() == 0 {
		t.Fatal("rotation should have advanced the incarnation")
	}
}

func TestCopytruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "a\n")
	tl := New(path, 0)
	defer tl.Close()
	poll(t, tl) // seek to end
	appendFile(t, path, "bb\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"bb"}) {
		t.Fatalf("got %v", lines)
	}
	// logrotate copytruncate: same inode, file zeroed then rewritten.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "new\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"new"}) {
		t.Fatalf("post-truncate got %v", lines)
	}
	if tl.Incarnation() == 0 {
		t.Fatal("truncation should have advanced the incarnation")
	}
}

func TestLineTruncatedToMax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	tl := New(path, 4)
	defer tl.Close()
	poll(t, tl)
	appendFile(t, path, "abcdefgh\nij\n")
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"abcd", "ij"}) {
		t.Fatalf("got %v", lines)
	}
}

func TestUnterminatedOverlongLineForceEmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	tl := New(path, 4)
	tl.maxReadBytes = 8 // force-emit once an unterminated line exceeds this
	defer tl.Close()
	poll(t, tl)
	appendFile(t, path, "abcdefghij") // 10 bytes, no newline
	if lines := poll(t, tl); !reflect.DeepEqual(lines, []string{"abcd"}) {
		t.Fatalf("force-emit got %v", lines)
	}
}

func TestMissingFileReturnsError(t *testing.T) {
	tl := New(filepath.Join(t.TempDir(), "does-not-exist.log"), 0)
	if _, err := tl.Poll(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	s := CheckpointString(42, 3)
	off, inc, ok := ParseCheckpoint(s)
	if !ok || off != 42 || inc != 3 {
		t.Fatalf("roundtrip failed: %q -> %d,%d,%v", s, off, inc, ok)
	}
	if _, _, ok := ParseCheckpoint("garbage"); ok {
		t.Fatal("garbage should not parse")
	}
}
