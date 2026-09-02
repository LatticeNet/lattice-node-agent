package singboxdiscover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AUDIT (audit/agentsec): cover the privileged half of the sing-box process
// selector.
//
// singBoxProcessArgs decides which local processes may name host paths for the
// root agent. Its load-bearing checks read /proc: the process must be owned by
// uid 0, its executable is taken from /proc/<pid>/exe rather than the
// self-reported argv[0], and that executable must sit in a root-owned,
// non-writable ancestry. Those checks previously had nothing exercising them,
// so removing one left the package green. These tests fabricate a process
// tree and pin every refusal.
//
// Two facts are fabricated, because a test process that is not root cannot
// create a root-owned file: the uid of paths inside the fixture, and the
// identity of the host directories above it (the temp directory tree, where
// /tmp is world writable and /var is a symlink on macOS), which stand in for
// the root-owned system tree. Modes, symlinks, inodes and the /proc layout
// are real on disk.

type procFixture struct {
	// root is the fake /proc.
	root string
	// base is the canonical per-test temp directory; every fixture path sits
	// below it and everything below it is real on disk.
	base string
	// bin is a root-owned executable directory under base; the fixture points
	// the resolver's search order at it.
	bin    string
	owner  map[string]uint32
	broken map[string]error
}

func newProcFixture(t *testing.T) *procFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(filepath.Dir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	f := &procFixture{base: base, owner: map[string]uint32{}, broken: map[string]error{}}
	f.ownedByRoot(base)
	f.root = f.dir(t, "proc")
	f.bin = f.dir(t, "sbin")

	realLstat, realStat := lstatIdentity, statIdentity
	realRoot := procRoot
	realDirs := trustedExecutableSearchDirs
	procRoot = f.root
	trustedExecutableSearchDirs = []string{f.bin}
	lstatIdentity = f.identity(realLstat, false)
	statIdentity = f.identity(realStat, true)
	t.Cleanup(func() {
		lstatIdentity = realLstat
		statIdentity = realStat
		procRoot = realRoot
		trustedExecutableSearchDirs = realDirs
	})
	return f
}

// identity wraps a real stat function with the fixture's fabrications: an
// injected error, a substituted uid for paths inside the fixture, and a
// root-owned 0755 directory for every host directory above it. Everything
// else (mode, symlink, inode, mtime) comes from disk. A following stat keys
// the uid by the link's target, as the kernel would own it.
func (f *procFixture) identity(real func(string) (fileIdentity, error), follow bool) func(string) (fileIdentity, error) {
	return func(path string) (fileIdentity, error) {
		clean := filepath.Clean(path)
		if err, ok := f.broken[clean]; ok {
			return fileIdentity{}, err
		}
		if clean != f.base && !strings.HasPrefix(clean, f.base+"/") {
			if clean == "/" || strings.HasPrefix(f.base, clean+"/") {
				return fileIdentity{mode: os.ModeDir | 0o755}, nil
			}
			return real(path)
		}
		id, err := real(path)
		if err != nil {
			return id, err
		}
		key := clean
		if follow {
			if target, err := filepath.EvalSymlinks(clean); err == nil {
				key = target
			}
		}
		if uid, ok := f.owner[key]; ok {
			id.uid = uid
		}
		return id, nil
	}
}

// ownedByRoot marks paths as uid 0 for the duration of the test.
func (f *procFixture) ownedByRoot(paths ...string) {
	for _, p := range paths {
		f.owner[filepath.Clean(p)] = 0
	}
}

// ownedBy marks paths as an arbitrary uid.
func (f *procFixture) ownedBy(uid uint32, paths ...string) {
	for _, p := range paths {
		f.owner[filepath.Clean(p)] = uid
	}
}

// unstatable makes every stat of exactly this path fail with err.
func (f *procFixture) unstatable(path string, err error) {
	f.broken[filepath.Clean(path)] = err
}

// dir creates a directory chain under base with mode 0755 and marks every
// component root-owned, so the result models a system directory.
func (f *procFixture) dir(t *testing.T, elems ...string) string {
	t.Helper()
	path := f.base
	for _, elem := range elems {
		path = filepath.Join(path, elem)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
		f.ownedByRoot(path)
	}
	return path
}

// binary writes an executable file into a directory and returns its path.
// Ownership is not marked: the test says who owns it.
func (f *procFixture) binary(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/true\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// process writes a fake /proc/<pid> whose cmdline holds argv and whose exe link
// points at exeTarget (skipped when empty, modelling a link that cannot be
// read).
func (f *procFixture) process(t *testing.T, pid string, argv []string, exeTarget string) string {
	t.Helper()
	dir := filepath.Join(f.root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if exeTarget != "" {
		if err := os.Symlink(exeTarget, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSingBoxProcessArgsAcceptsRootProcessWithRealBinary(t *testing.T) {
	f := newProcFixture(t)
	exe := f.binary(t, f.bin, "sing-box", 0o755)
	cfg := t.TempDir()
	// argv[0] is the bare name a PATH-launched process reports. Acceptance here
	// therefore also proves the kernel's exe path replaces the process's claim,
	// since a bare argv[0] does not satisfy the executable rules on its own.
	proc := f.process(t, "1234", []string{"sing-box", "run", "-C", cfg}, exe)
	f.ownedByRoot(proc, exe)

	got := singBoxProcessArgs()
	if len(got) != 1 {
		t.Fatalf("expected the legitimate sing-box process, got %d vectors: %v", len(got), got)
	}
	if got[0][0] != exe {
		t.Fatalf("argv[0] = %q, want the resolved exe %q", got[0][0], exe)
	}
	if got[0][len(got[0])-1] != cfg {
		t.Fatalf("argv tail = %q, want the config dir %q", got[0][len(got[0])-1], cfg)
	}
}

func TestSingBoxProcessArgsRefusesUnprivilegedAndSpoofedProcesses(t *testing.T) {
	cfg := t.TempDir()

	t.Run("process not owned by root", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "sing-box", 0o755)
		proc := f.process(t, "1234", []string{"sing-box", "run", "-C", cfg}, exe)
		f.ownedBy(1000, proc) // an unprivileged user's decoy
		f.ownedByRoot(exe)
		requireNoProcesses(t)
	})

	t.Run("exe resolves into a user-owned directory while argv0 lies", func(t *testing.T) {
		f := newProcFixture(t)
		elsewhere := f.dir(t, "home", "mallory")
		f.ownedBy(1000, elsewhere)
		exe := f.binary(t, elsewhere, "sing-box", 0o755)
		// The process claims the trusted path in argv[0]; only /proc/<pid>/exe
		// tells the truth.
		proc := f.process(t, "1234", []string{filepath.Join(f.bin, "sing-box"), "run", "-C", cfg}, exe)
		f.ownedByRoot(proc, exe)
		requireNoProcesses(t)
	})

	t.Run("exe not owned by root", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "sing-box", 0o755)
		proc := f.process(t, "1234", []string{"sing-box", "run", "-C", cfg}, exe)
		f.ownedByRoot(proc)
		f.ownedBy(1000, exe)
		requireNoProcesses(t)
	})

	t.Run("exe is group or world writable", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "sing-box", 0o757)
		proc := f.process(t, "1234", []string{"sing-box", "run", "-C", cfg}, exe)
		f.ownedByRoot(proc, exe)
		requireNoProcesses(t)
	})

	t.Run("exe basename is not sing-box", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "my-sing-box-shim", 0o755)
		proc := f.process(t, "1234", []string{"sing-box", "run", "-C", cfg}, exe)
		f.ownedByRoot(proc, exe)
		requireNoProcesses(t)
	})

	t.Run("no run subcommand", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "sing-box", 0o755)
		proc := f.process(t, "1234", []string{"sing-box", "check", "-C", cfg}, exe)
		f.ownedByRoot(proc, exe)
		requireNoProcesses(t)
	})
}

// A root agent can always read /proc/<pid>/exe, so a link that cannot be
// read is a process that cannot be identified, and argv[0] is never consulted
// in its place: a trusted-looking argv[0] behind an unreadable link is refused.
func TestSingBoxProcessArgsRefusesUnreadableExeLink(t *testing.T) {
	f := newProcFixture(t)
	exe := f.binary(t, f.bin, "sing-box", 0o755)
	proc := f.process(t, "1234", []string{exe, "run", "-C", t.TempDir()}, "")
	f.ownedByRoot(proc, exe)
	requireNoProcesses(t)
}

// A decoy must not displace the legitimate process, which is the denial half of
// the finding: two -C directories make the layout ambiguous and disable durable
// linechain tasks.
func TestSingBoxProcessArgsIgnoresDecoyBesideRealProcess(t *testing.T) {
	f := newProcFixture(t)
	realExe := f.binary(t, f.bin, "sing-box", 0o755)
	realCfg := t.TempDir()
	realProc := f.process(t, "1000", []string{"sing-box", "run", "-C", realCfg}, realExe)
	f.ownedByRoot(realProc, realExe)

	decoyDir := f.dir(t, "home", "mallory")
	decoyExe := f.binary(t, decoyDir, "sing-box", 0o755)
	decoyProc := f.process(t, "2000", []string{"sing-box", "run", "-C", decoyDir}, decoyExe)
	f.ownedBy(1000, decoyDir, decoyProc, decoyExe)

	got := singBoxProcessArgs()
	if len(got) != 1 {
		t.Fatalf("expected only the legitimate process, got %d vectors: %v", len(got), got)
	}
	config, _, err := resolveRuntimeLayout(got, "/etc/sing-box/lattice-metadata.json")
	if err != nil {
		t.Fatalf("decoy displaced the real sing-box authority: %v", err)
	}
	if config != realCfg {
		t.Fatalf("config dir = %q, want %q", config, realCfg)
	}
}

func requireNoProcesses(t *testing.T) {
	t.Helper()
	if got := singBoxProcessArgs(); len(got) != 0 {
		t.Fatalf("untrusted process accepted as local authority: %v", got)
	}
}
