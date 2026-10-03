//go:build !unix

package witness

import "os"

// checkOwner has no portable owner to compare on this platform; the mode
// check still applies.
func checkOwner(os.FileInfo) error { return nil }
