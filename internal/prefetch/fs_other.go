//go:build !unix

package prefetch

import (
	"errors"
	"os"
)

// Agent updates run only on Linux; elsewhere prefetch refuses.
var errUnsupported = errors.New("prefetch runs only on unix nodes")

func openPartial(string) (*os.File, int64, error) { return nil, 0, errUnsupported }

func secureDir(string) error { return errUnsupported }

func freeSpace(string) (uint64, error) { return 0, errUnsupported }
