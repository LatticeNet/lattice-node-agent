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
	if f == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open linechain manager lock: invalid file descriptor")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("inspect linechain manager lock: %w", err)
	}
	if err := validateLockInfo(info, os.Geteuid()); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("linechain transaction manager already open: %w", err)
	}
	return f, nil
}

func validateLockInfo(info os.FileInfo, effectiveUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect linechain manager lock ownership: unsupported stat data")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("linechain manager lock must be a regular file")
	}
	if stat.Uid != uint32(effectiveUID) {
		return fmt.Errorf("linechain manager lock must be owned by effective user %d", effectiveUID)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("linechain manager lock permissions are %o, want 600", info.Mode().Perm())
	}
	return nil
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
