//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package linechain

import (
	"fmt"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	visible, err := os.Lstat(path)
	if err != nil || visible.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, visible) {
		_ = f.Close()
		return nil, fmt.Errorf("path changed or is a symbolic link")
	}
	return f, nil
}
