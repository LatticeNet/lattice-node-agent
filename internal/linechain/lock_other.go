//go:build !unix

package linechain

import "os"

func lockManager(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}
func unlockManager(f *os.File) error {
	name := f.Name()
	err := f.Close()
	if removeErr := os.Remove(name); err == nil {
		err = removeErr
	}
	return err
}
func ownedPath(os.FileInfo) bool { return true }
