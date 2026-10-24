package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// The log tail veto. The server names the files a node tails and checks the
// path itself (validateLogPath), but a node does not take the control plane's
// word for what its own user, usually root, may read and ship: it tails only
// regular files under its own allowlist, /var/log/ unless -log-path-allow
// (LATTICE_LOG_PATH_ALLOW in the agent's env file) widens it, and nothing the
// server sends can widen it. The path is judged after symlinks and ".." are
// resolved, and again on every open, rotations included.

// defaultLogPathAllow is the prefix a node tails without configuration, the
// server's own default.
const defaultLogPathAllow = "/var/log/"

// errLogPathRefused marks a source the node refuses to tail.
var errLogPathRefused = errors.New("refused by the node")

type logPathRefusal struct{ reason string }

func (e *logPathRefusal) Error() string { return "refused by the node: " + e.reason }
func (e *logPathRefusal) Unwrap() error { return errLogPathRefused }

func refuseLogPath(reason string) error { return &logPathRefusal{reason: reason} }

const (
	logRefusedOutside    = "outside its log allowlist"
	logRefusedNotRegular = "not a regular file"
)

// logPathPolicy is the node's allowlist: absolute directory prefixes, each
// ending in "/". A prefix that is itself reached through a symlink is listed
// as written and as resolved, so /var/log/ still matches where /var is a link.
type logPathPolicy struct {
	allow []string
}

func newLogPathPolicy(extra string) logPathPolicy {
	var p logPathPolicy
	add := func(prefix string) {
		prefix = strings.TrimSpace(prefix)
		if !filepath.IsAbs(prefix) {
			return
		}
		prefix = filepath.Clean(prefix)
		forms := []string{prefix}
		if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
			forms = append(forms, resolved)
		}
		for _, form := range forms {
			if !strings.HasSuffix(form, "/") {
				form += "/"
			}
			if !slices.Contains(p.allow, form) {
				p.allow = append(p.allow, form)
			}
		}
	}
	add(defaultLogPathAllow)
	for _, prefix := range strings.Split(extra, ",") {
		add(prefix)
	}
	return p
}

func (p logPathPolicy) allowed(path string) bool {
	for _, prefix := range p.allow {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// resolve is path with symlinks and ".." resolved the way the kernel will
// open it, or "" when nothing is there yet, so a log that appears later is
// judged when it does. A path that is not an absolute file path, which takes
// in every scheme a server mints for virtual sources (singbox://,
// agent-debug://) and any it may invent, is refused like one outside the
// allowlist.
func (p logPathPolicy) resolve(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", refuseLogPath(logRefusedOutside)
	}
	if !p.allowed(filepath.Clean(path)) {
		return "", refuseLogPath(logRefusedOutside)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !p.allowed(resolved) {
		return "", refuseLogPath(logRefusedOutside)
	}
	return resolved, nil
}

// check is the node's verdict on a source path before it starts tailing: a
// refusal, nil for a path it may tail (or that does not exist yet), or another
// error the next look may not repeat.
func (p logPathPolicy) check(path string) error {
	resolved, err := p.resolve(path)
	if err != nil || resolved == "" {
		return err
	}
	info, err := os.Stat(resolved)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return refuseLogPath(logRefusedNotRegular)
	}
	return nil
}

// open is the tailer's open: it resolves and judges the path again, opens the
// resolved file without following a symlink at its last component or blocking
// on a FIFO, and judges the descriptor it got. Where /proc names what was
// opened, that name is judged too, so a directory swapped between resolving
// and opening cannot carry the open outside the allowlist.
func (p logPathPolicy) open(path string) (*os.File, error) {
	resolved, err := p.resolve(path)
	if err != nil {
		return nil, err
	}
	if resolved == "" {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- resolved and judged against the node's own allowlist just above
	if errors.Is(err, syscall.ELOOP) {
		return nil, refuseLogPath(logRefusedOutside)
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, refuseLogPath(logRefusedNotRegular)
	}
	if opened, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)); err == nil && !p.allowed(opened) {
		_ = f.Close()
		return nil, refuseLogPath(logRefusedOutside)
	}
	return f, nil
}
