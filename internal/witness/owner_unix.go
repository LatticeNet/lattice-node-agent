//go:build unix

package witness

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a key file that belongs to another user: a file someone
// else owns is one someone else can rewrite.
func checkOwner(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("device key file belongs to uid %d, not to the witness (uid %d)", st.Uid, uid)
	}
	return nil
}
