//go:build linux || darwin || freebsd

package taskoutbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRefusesSymlinkLockWithoutChangingTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	const contents = "do not touch"
	if err := os.WriteFile(victim, []byte(contents), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".lock")); err != nil {
		t.Fatal(err)
	}

	if store, err := Open(dir); err == nil {
		_ = store.Close()
		t.Fatal("Open() succeeded with a symlink lock, want rejection")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != contents {
		t.Fatalf("victim content = %q, want %q", got, contents)
	}
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("victim mode = %o, want 640", info.Mode().Perm())
	}
}

func TestOpenRefusesInsecurePreexistingLockPermissions(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".lock")
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}

	if store, err := Open(dir); err == nil {
		_ = store.Close()
		t.Fatal("Open() succeeded with an insecure preexisting lock, want rejection")
	}
	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("lock mode = %o, want unchanged 644", info.Mode().Perm())
	}
}
