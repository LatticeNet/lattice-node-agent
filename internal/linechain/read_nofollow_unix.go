//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package linechain

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open without following links: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
