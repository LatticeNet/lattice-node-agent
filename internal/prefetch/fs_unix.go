//go:build unix

package prefetch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPartial opens the download for appending without ever following a
// symlink at its name, and returns it with its size. The file the update
// script continues must be a regular file owned by the user it runs as,
// with no other name: anything else at that name (a symlink, a file with a
// second name, another user's file) is removed as a name and a new file is
// created in its place, exclusively.
func openPartial(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err == nil {
		if size, ok := ownedRegular(f); ok {
			if err := f.Chmod(0o600); err != nil {
				f.Close()
				return nil, 0, err
			}
			return f, size, nil
		}
		f.Close()
	} else if !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.EISDIR) && !errors.Is(err, syscall.ENXIO) {
		return nil, 0, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, 0, fmt.Errorf("remove what stands at the download's name: %w", err)
	}
	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, 0, err
	}
	if _, ok := ownedRegular(f); !ok {
		f.Close()
		return nil, 0, errors.New("the new download is not a regular file of this user")
	}
	return f, 0, nil
}

func ownedRegular(f *os.File) (int64, bool) {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || uint64(st.Nlink) != 1 {
		return 0, false
	}
	return fi.Size(), true
}

// secureDir accepts a directory only when no user but root, or the agent's
// own user, can change it or any directory above it. The update script
// trusts its download as far as that directory, which holds the binary root
// runs; prefetch writes there before any approval, so it also refuses a
// directory another user could swap a name in.
func secureDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("the install directory %q is not absolute", dir)
	}
	euid := os.Geteuid()
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("cannot inspect %s: %w", p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("%s is not a plain directory", p)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read the owner of %s", p)
		}
		if (st.Uid != 0 && int(st.Uid) != euid) || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s can be changed by a user other than root, so the agent does not write there", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// freeSpace is what an unprivileged writer may still use on dir's
// filesystem.
func freeSpace(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
