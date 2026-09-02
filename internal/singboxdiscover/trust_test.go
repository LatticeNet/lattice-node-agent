package singboxdiscover

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The selector trusts a sing-box process by the integrity of the path behind
// /proc/<pid>/exe, not by which directory it sits in. Each case builds a real
// tree under the fixture, points a fake /proc entry at it, and pins the one
// refusal the selector must name, or acceptance. The fleet layout
// (/etc/sing-box/bin/sing-box, root-owned, run by systemd as root) is the
// acceptance case; it was refused by the old directory list.
func TestProcessExecutableAncestryRules(t *testing.T) {
	type built struct {
		proc string
		want string
	}
	cases := []struct {
		name  string
		build func(t *testing.T, f *procFixture) built
	}{
		{"root-owned chain outside the old directory list is accepted", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run", "-c", "/etc/sing-box/config.json"}, exe)
			f.ownedByRoot(proc, exe)
			return built{proc, ""}
		}},
		{"file owned by the manager uid", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc)
			f.ownedBy(1001, exe)
			return built{proc, "owned by uid 1001, not root"}
		}},
		{"file group or world writable", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o777)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, exe)
			return built{proc, "group or world writable (mode 0777)"}
		}},
		{"ancestor owned by the manager uid", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, exe)
			f.ownedBy(1001, bin)
			return built{proc, "directory " + bin + " owned by uid 1001, not root"}
		}},
		{"outermost weak ancestor is the one named", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, exe)
			f.ownedBy(1001, filepath.Dir(bin), bin)
			return built{proc, "directory " + filepath.Dir(bin) + " owned by uid 1001, not root"}
		}},
		{"ancestor group writable", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			if err := os.Chmod(bin, 0o775); err != nil {
				t.Fatal(err)
			}
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, exe)
			return built{proc, "directory " + bin + " is group or world writable (mode 0775)"}
		}},
		{"ancestor is a symlink", func(t *testing.T, f *procFixture) built {
			target := f.dir(t, "opt", "sing-box")
			exe := f.binary(t, f.dir(t, "opt", "sing-box", "bin"), "sing-box", 0o755)
			link := filepath.Join(f.dir(t, "etc"), "sing-box")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			viaLink := filepath.Join(link, "bin", "sing-box")
			proc := f.process(t, "3917185", []string{viaLink, "run"}, viaLink)
			f.ownedByRoot(proc, exe, viaLink)
			return built{proc, "directory " + link + " is a symlink"}
		}},
		{"not a regular file", func(t *testing.T, f *procFixture) built {
			exe := f.dir(t, "etc", "sing-box", "bin", "sing-box")
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc)
			return built{proc, "not a regular file"}
		}},
		{"path is a different file from the running inode", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			real := f.binary(t, bin, ".sing-box.real", 0o755)
			exe := filepath.Join(bin, "sing-box")
			if err := os.Symlink(real, exe); err != nil {
				t.Fatal(err)
			}
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, real, exe)
			return built{proc, "path and /proc/3917185/exe are different files"}
		}},
		{"binary replaced in place under the running process", func(t *testing.T, f *procFixture) built {
			// The kernel reports "<path> (deleted)" for an unlinked exe; the
			// path now holds the upgrade while the process still runs the old
			// inode. Rule 4 says so.
			bin := f.dir(t, "etc", "sing-box", "bin")
			old := f.binary(t, bin, "sing-box (deleted)", 0o755)
			current := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{current, "run"}, old)
			f.ownedByRoot(proc, old, current)
			return built{proc, "path and /proc/3917185/exe are different files"}
		}},
		{"running inode cannot be stat'd", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := filepath.Join(bin, "sing-box")
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc)
			return built{proc, "cannot stat /proc/3917185/exe: no such file or directory"}
		}},
		{"ancestor cannot be stat'd", func(t *testing.T, f *procFixture) built {
			bin := f.dir(t, "etc", "sing-box", "bin")
			exe := f.binary(t, bin, "sing-box", 0o755)
			proc := f.process(t, "3917185", []string{exe, "run"}, exe)
			f.ownedByRoot(proc, exe)
			f.unstatable(filepath.Dir(bin), syscall.EACCES)
			return built{proc, "cannot stat " + filepath.Dir(bin) + ": permission denied"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProcFixture(t)
			b := tc.build(t, f)
			exe, err := os.Readlink(filepath.Join(b.proc, "exe"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, got := explainProcessExecutable(b.proc, exe); got != b.want {
				t.Fatalf("reason = %q, want %q", got, b.want)
			}
			trusted, refused := TrustedProcesses(), RefusedProcesses()
			if b.want == "" {
				if len(trusted) != 1 || trusted[0].PID != 3917185 || len(refused) != 0 {
					t.Fatalf("accepted process not listed as trusted: trusted=%+v refused=%+v", trusted, refused)
				}
				return
			}
			if len(trusted) != 0 {
				t.Fatalf("refused process listed as trusted: %+v", trusted)
			}
			if len(refused) != 1 || refused[0].PID != 3917185 || refused[0].Reason != b.want {
				t.Fatalf("refusal listing = %+v, want one entry with reason %q", refused, b.want)
			}
		})
	}
}

func TestTrustedProcessesReportTheExecutableDigestOnce(t *testing.T) {
	f := newProcFixture(t)
	exe := f.binary(t, f.bin, "sing-box", 0o755)
	proc := f.process(t, "1234", []string{exe, "run"}, exe)
	f.ownedByRoot(proc, exe)
	digest := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}

	procs := TrustedProcesses()
	if len(procs) != 1 || procs[0].ExeSHA256 != digest("#!/bin/true\n") {
		t.Fatalf("digest of the running binary wrong: %+v", procs)
	}

	// Same inode, same mtime, different bytes: the cache answers, which is
	// the "once per identity" contract (a 30 MB binary is not re-read every
	// probe cycle).
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(exe, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if got := TrustedProcesses()[0].ExeSHA256; got != digest("#!/bin/true\n") {
		t.Fatalf("digest recomputed for an unchanged identity: %q", got)
	}

	// A new mtime is a new identity: the replacement is hashed.
	later := info.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(exe, later, later); err != nil {
		t.Fatal(err)
	}
	if got := TrustedProcesses()[0].ExeSHA256; got != digest("#!/bin/false\n") {
		t.Fatalf("digest not refreshed after the binary changed: %q", got)
	}
}

// Merged-usr hosts alias /bin and /sbin to /usr/bin and /usr/sbin through
// symlinks. The resolver judges the canonical path, so sshd found through the
// alias is accepted on its real ancestry, and a link that leads to some other
// trusted binary is refused by name.
func TestResolveTrustedExecutableJudgesTheCanonicalPath(t *testing.T) {
	f := newProcFixture(t)
	usrSbin := f.dir(t, "usr", "sbin")
	sshd := f.binary(t, usrSbin, "sshd", 0o755)
	f.ownedByRoot(sshd)
	alias := filepath.Join(f.base, "merged-sbin")
	if err := os.Symlink(usrSbin, alias); err != nil {
		t.Fatal(err)
	}
	trustedExecutableSearchDirs = []string{alias, usrSbin}
	if path, reason := ResolveTrustedExecutable("sshd"); path != sshd || reason != "" {
		t.Fatalf("merged-usr alias: path=%q reason=%q", path, reason)
	}

	python := f.binary(t, usrSbin, "python3", 0o755)
	f.ownedByRoot(python)
	local := f.dir(t, "usr", "local", "sbin")
	if err := os.Symlink(python, filepath.Join(local, "sshd")); err != nil {
		t.Fatal(err)
	}
	trustedExecutableSearchDirs = []string{local}
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || reason != python+": executable is not named sshd" {
		t.Fatalf("link to another binary: path=%q reason=%q", path, reason)
	}
}
