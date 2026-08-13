//go:build linux || darwin || freebsd

package taskoutbox

import (
	"fmt"
	"os"
	"syscall"
)

func lockOutbox(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open task result outbox lock: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("secure task result outbox lock: %w", err)
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
