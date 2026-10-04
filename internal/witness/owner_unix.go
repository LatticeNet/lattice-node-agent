//go:build unix

package witness

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openForCheck opens a file whose opened descriptor is checked before it is
// read. O_NONBLOCK keeps a FIFO left at the path from blocking the open until
// a writer appears, so the regular-file check can refuse it; it changes
// nothing for a regular file.
func openForCheck(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// checkOwner refuses a file that belongs to another user: a file someone
// else owns is one someone else can rewrite.
func checkOwner(what string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("%s belongs to uid %d, not to the witness (uid %d)", what, st.Uid, uid)
	}
	return nil
}
