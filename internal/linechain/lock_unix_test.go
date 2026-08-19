//go:build linux || darwin || freebsd

package linechain

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenRefusesSymlinkLockWithoutChangingTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "txn")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".lock")); err != nil {
		t.Fatal(err)
	}
	if m, err := Open(dir); err == nil {
		_ = m.Close()
		t.Fatal("symlink lock accepted")
	}
	b, err := os.ReadFile(victim)
	if err != nil || string(b) != "unchanged" {
		t.Fatalf("victim changed: %q %v", b, err)
	}
}

func TestOpenRefusesFIFOAndInsecureLockMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(string) error
	}{
		{"fifo", func(path string) error { return syscall.Mkfifo(path, 0o600) }},
		{"mode", func(path string) error { return os.WriteFile(path, nil, 0o644) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "txn")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".lock")
			if err := tc.make(path); err != nil {
				t.Fatal(err)
			}
			if tc.name == "mode" {
				_ = os.Chmod(path, 0o644)
			}
			if m, err := Open(dir); err == nil {
				_ = m.Close()
				t.Fatal("hostile lock accepted")
			}
		})
	}
}

type lockInfoWithStat struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i lockInfoWithStat) Sys() any { return &i.stat }

func TestLockValidationRefusesWrongOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := *(info.Sys().(*syscall.Stat_t))
	stat.Uid = uint32(os.Geteuid() + 1)
	if err := validateLockInfo(lockInfoWithStat{FileInfo: info, stat: stat}, os.Geteuid()); err == nil {
		t.Fatal("wrong-owner lock accepted")
	}
}
