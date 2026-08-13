//go:build linux || darwin || freebsd

package taskoutbox

import (
	"fmt"
	"os"
	"syscall"
)

func lockOutbox(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open task result outbox lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open task result outbox lock: invalid file descriptor")
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("inspect task result outbox lock: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		f.Close()
		return nil, fmt.Errorf("inspect task result outbox lock ownership: unsupported stat data")
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("task result outbox lock must be a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, fmt.Errorf("task result outbox lock must be owned by effective user %d", os.Geteuid())
	}
	if info.Mode().Perm() != 0o600 {
		f.Close()
		return nil, fmt.Errorf("task result outbox lock permissions are %o, want 600", info.Mode().Perm())
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("task result outbox is already owned by another agent process: %w", err)
	}
	return f, nil
}

func unlockOutbox(f *os.File) error {
	unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock task result outbox: %w", unlockErr)
	}
	return closeErr
}
