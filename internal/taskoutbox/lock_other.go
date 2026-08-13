//go:build !linux && !darwin && !freebsd

package taskoutbox

import (
	"fmt"
	"os"
)

func lockOutbox(string) (*os.File, error) {
	return nil, fmt.Errorf("durable task outbox locking is unsupported on this operating system")
}

func unlockOutbox(f *os.File) error { return f.Close() }
