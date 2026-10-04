//go:build unix

package witness

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO left where the key file should be is refused at once rather than
// blocking the witness, or the apply script's -witness-check, until a writer
// appears.
func TestReadDeviceKeyRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadDeviceKey(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO key file: err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadDeviceKey blocked on a FIFO")
	}
}

type foreignFile struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (f foreignFile) Sys() any { return f.st }

// A file another user owns is one that user can rewrite.
func TestCheckOwnerRefusesAnotherUsersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "witness.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOwner("witness config", info); err != nil {
		t.Fatalf("own file refused: %v", err)
	}
	st := *info.Sys().(*syscall.Stat_t)
	st.Uid++
	if err := checkOwner("witness config", foreignFile{info, &st}); err == nil || !strings.Contains(err.Error(), "witness config belongs to uid") {
		t.Fatalf("another user's file: err = %v", err)
	}
}

// LoadConfig applies the owner check to the file it opens (ReadDeviceKey goes
// through the same helper). A system file owned by root and not writable by
// others stands in for a config someone else owns; the test cannot be root.
func TestLoadConfigRefusesAFileAnotherUserOwns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root owns every file under test")
	}
	for _, path := range []string{"/etc/hosts", "/etc/passwd"} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) == os.Geteuid() {
			continue
		}
		if _, _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "witness config belongs to uid") {
			t.Fatalf("LoadConfig(%s) err = %v", path, err)
		}
		return
	}
	t.Skip("no regular file owned by another user and closed to writes by others")
}
