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
// uid 0, and its executable is taken from /proc/<pid>/exe rather than the
// self-reported argv[0]. Those checks previously had nothing exercising them,
// so removing either one left the package green. These tests fabricate a
// process tree and pin every refusal.
//
// Only one fact is fabricated: file ownership, because a test process that is
// not root cannot create a root-owned file. Modes, symlinks, and the /proc
// layout are real on disk.

type procFixture struct {
	root  string
	bin   string
	owner map[string]uint32
}

func newProcFixture(t *testing.T) *procFixture {
	t.Helper()
	base := t.TempDir()
	f := &procFixture{
		root:  filepath.Join(base, "proc"),
		bin:   filepath.Join(base, "sbin"),
		owner: map[string]uint32{},
	}
	if err := os.MkdirAll(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}

	realStat := statIdentity
	realRoot := procRoot
	realDirs := trustedSingBoxExecutableDirs
	procRoot = f.root
	trustedSingBoxExecutableDirs = []string{f.bin}
	// Keep the real mode from disk and substitute only the uid, so the mode,
	// permission and regular-file rules are still exercised against real files.
	statIdentity = func(path string) (fileIdentity, error) {
		id, err := realStat(path)
		if err != nil {
			return id, err
		}
		if uid, ok := f.owner[filepath.Clean(path)]; ok {
			id.uid = uid
		}
		return id, nil
	}
	t.Cleanup(func() {
		statIdentity = realStat
		procRoot = realRoot
		trustedSingBoxExecutableDirs = realDirs
	})
	return f
}

// ownedByRoot marks a path as uid 0 for the duration of the test.
func (f *procFixture) ownedByRoot(paths ...string) {
	for _, p := range paths {
		f.owner[filepath.Clean(p)] = 0
	}
}

// ownedBy marks a path as an arbitrary uid.
func (f *procFixture) ownedBy(uid uint32, paths ...string) {
	for _, p := range paths {
		f.owner[filepath.Clean(p)] = uid
	}
}

// binary writes an executable file into a directory and returns its path.
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
// points at exeTarget (skipped when empty, modelling a link the agent may not
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

	t.Run("exe resolves outside a trusted location while argv0 lies", func(t *testing.T) {
		f := newProcFixture(t)
		elsewhere := t.TempDir()
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

// When /proc/<pid>/exe cannot be read (a non-root agent has no ptrace permission
// over a root process) the selector falls back to the self-reported argv[0].
// That is only sound because the uid-0 check already passed, so the fallback
// must still apply the full executable rules.
func TestSingBoxProcessArgsUnreadableExeFallsBackToArgv0Rules(t *testing.T) {
	cfg := t.TempDir()

	t.Run("trusted argv0 is accepted", func(t *testing.T) {
		f := newProcFixture(t)
		exe := f.binary(t, f.bin, "sing-box", 0o755)
		proc := f.process(t, "1234", []string{exe, "run", "-C", cfg}, "")
		f.ownedByRoot(proc, exe)
		got := singBoxProcessArgs()
		if len(got) != 1 || got[0][0] != exe {
			t.Fatalf("root process with a trusted argv[0] was not accepted: %v", got)
		}
	})

	t.Run("untrusted argv0 is refused", func(t *testing.T) {
		f := newProcFixture(t)
		elsewhere := t.TempDir()
		exe := f.binary(t, elsewhere, "sing-box", 0o755)
		proc := f.process(t, "1234", []string{exe, "run", "-C", cfg}, "")
		f.ownedByRoot(proc, exe)
		requireNoProcesses(t)
	})
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

	decoyDir := t.TempDir()
	decoyExe := f.binary(t, decoyDir, "sing-box", 0o755)
	decoyProc := f.process(t, "2000", []string{"sing-box", "run", "-C", decoyDir}, decoyExe)
	f.ownedBy(1000, decoyProc, decoyExe)

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
