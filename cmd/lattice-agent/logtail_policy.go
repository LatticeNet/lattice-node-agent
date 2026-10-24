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
// server sends can widen it. The built-in /var/log/ leaves out the files that
// hold credentials or audit trails (defaultLogPathDeny); a node opts in to
// one by listing that file, or a directory inside /var/log/ holding it, and
// gets exactly that. Listing /var/log/ itself or a parent of it restates the
// default and keeps the denylist. The path is judged as written, after
// symlinks and ".." are resolved, and again on every open, rotations
// included.

// defaultLogPathAllow is the prefix a node tails without configuration, the
// server's own default.
const defaultLogPathAllow = "/var/log/"

// defaultLogPathDeny is what the built-in /var/log/ leaves out: logins and
// failed logins, audit and sudo session logs, and the installer and
// cloud-init logs that can echo a password or user-data. An entry ending in
// "*" is a file name prefix directly under /var/log/, one ending in "/" a
// whole directory under it, and any other a file name there. Entries are
// lowercase and matched without case, since a filesystem that folds case
// opens auth.log as AUTH.log.
var defaultLogPathDeny = []string{
	"auth.log*", "secure*", "btmp*", "wtmp*", "lastlog", "faillog", "tallylog", "sudo.log*",
	"cloud-init*", "audit/", "sudo-io/", "installer/", "anaconda/", "private/",
}

// errLogPathRefused marks a source the node refuses to tail.
var errLogPathRefused = errors.New("refused by the node")

type logPathRefusal struct{ reason string }

func (e *logPathRefusal) Error() string { return "refused by the node: " + e.reason }
func (e *logPathRefusal) Unwrap() error { return errLogPathRefused }

func refuseLogPath(reason string) error { return &logPathRefusal{reason: reason} }

// The reasons an operator reads on the node's loop health, each saying what
// would let the source through.
const (
	logRefusedOutside    = "outside this node's log allowlist; widen it with LATTICE_LOG_PATH_ALLOW on the node"
	logRefusedSensitive  = "a credential or audit log this node's default leaves out; allow it by listing the file in LATTICE_LOG_PATH_ALLOW on the node"
	logRefusedNotRegular = "not a regular file"
	logRefusedOff        = "log tailing is turned off on this node (LATTICE_NO_LOG_TAIL)"
)

// logPathPolicy is the node's allowlist: absolute directory prefixes, each
// ending in "/". base is the built-in /var/log/, which leaves out
// defaultLogPathDeny; allow is what the node lists, each entry taken whole and
// also naming the file of that name, so /var/log/auth.log lists one file. A
// prefix that is itself reached through a symlink is listed as written and as
// resolved, so /var/log/ still matches where /var is a link.
type logPathPolicy struct {
	allow []string
	base  []string
}

func newLogPathPolicy(extra string) logPathPolicy {
	return newLogPathPolicyFrom(defaultLogPathAllow, extra)
}

func newLogPathPolicyFrom(base, extra string) logPathPolicy {
	p := logPathPolicy{base: appendLogPrefix(nil, base)}
	for _, prefix := range strings.Split(extra, ",") {
		p.allow = appendLogPrefix(p.allow, prefix)
	}
	return p
}

func appendLogPrefix(list []string, prefix string) []string {
	prefix = strings.TrimSpace(prefix)
	if !filepath.IsAbs(prefix) {
		return list
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
		if !slices.Contains(list, form) {
			list = append(list, form)
		}
	}
	return list
}

// judge is why the node refuses path, or "" when it may tail it.
func (p logPathPolicy) judge(path string) string {
	for _, base := range p.base {
		if rel, ok := strings.CutPrefix(path, base); ok {
			if deniedByDefault(rel) && !p.listed(path, base) {
				return logRefusedSensitive
			}
			return ""
		}
	}
	if p.listed(path, "") {
		return ""
	}
	return logRefusedOutside
}

// listed reports whether an entry the node lists strictly inside within names
// path or a directory that holds it.
func (p logPathPolicy) listed(path, within string) bool {
	for _, entry := range p.allow {
		if entry == within || !strings.HasPrefix(entry, within) {
			continue
		}
		if strings.HasPrefix(path, entry) || path == strings.TrimSuffix(entry, "/") {
			return true
		}
	}
	return false
}

func deniedByDefault(rel string) bool {
	rel = strings.ToLower(rel)
	for _, entry := range defaultLogPathDeny {
		switch {
		case strings.HasSuffix(entry, "/"):
			if strings.HasPrefix(rel, entry) {
				return true
			}
		case strings.HasSuffix(entry, "*"):
			if !strings.Contains(rel, "/") && strings.HasPrefix(rel, strings.TrimSuffix(entry, "*")) {
				return true
			}
		case rel == entry:
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
	if reason := p.judge(filepath.Clean(path)); reason != "" {
		return "", refuseLogPath(reason)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if reason := p.judge(resolved); reason != "" {
		return "", refuseLogPath(reason)
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
	if opened, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)); err == nil {
		if reason := p.judge(opened); reason != "" {
			_ = f.Close()
			return nil, refuseLogPath(reason)
		}
	}
	return f, nil
}
