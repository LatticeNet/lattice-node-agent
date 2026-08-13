//go:build unix

package linechain

import (
	"fmt"
	"os"
	"syscall"
)

func lockManager(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("linechain transaction manager already open: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func unlockManager(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func ownedPath(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
