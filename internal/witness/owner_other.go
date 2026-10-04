//go:build !unix

package witness

import (
	"os"
	"path/filepath"
)

// openForCheck opens a file whose opened descriptor is checked before it is
// read.
func openForCheck(path string) (*os.File, error) { return os.Open(filepath.Clean(path)) }

// checkOwner has no portable owner to compare on this platform; the mode
// check still applies.
func checkOwner(string, os.FileInfo) error { return nil }
