package singboxdiscover

import (
	"path/filepath"
	"testing"
)

// AUDIT (audit/agentsec): an unprivileged local user must not be able to
// nominate the sing-box config directory the root agent trusts.
//
// The selector (singBoxProcessArgs) used to accept every process whose argv[0]
// basename merely contained "sing-box" and whose argv contained "run", with no
// check on the process credentials or on the real executable. So
//
//	cp /bin/sleep /tmp/sing-box && /tmp/sing-box run -C /tmp/mine 3600
//
// made any local user the local authority: resolveRuntimeLayout handed that
// directory to linechain.ConfigureLayout as the E3 config root (main.go:376) and
// singBoxRuntimeConfigFiles read *.json out of it and reported the contents to
// the control plane as this node's inventory.
//
// The load-bearing fix is the uid-0 and /proc/<pid>/exe check in
// singBoxProcessArgs, pinned in audit_proc_authority_test.go. These tests pin
// the second layer: a process may only name host paths if its argument vector
// starts with a sing-box binary whose file and whole ancestry are root-owned
// and writable by nobody else.
func TestResolveRuntimeLayoutRefusesUnprivilegedDirectory(t *testing.T) {
	f := newProcFixture(t)
	attacker := f.dir(t, "home", "mallory")
	f.ownedBy(1000, attacker)
	decoy := f.binary(t, attacker, "sing-box", 0o755)
	f.ownedByRoot(decoy) // even a root-owned file is refused under a user-owned directory
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")

	for _, vector := range [][]string{
		{decoy, "run", "-C", attacker},
		{"/tmp/sing-box", "run", "-C", attacker},
		{"sing-box", "run", "-C", attacker},                  // bare, resolved through PATH
		{"/usr/bin/my-sing-box-shim", "run", "-C", attacker}, // basename merely contains sing-box
	} {
		config, _, err := resolveRuntimeLayout([][]string{vector}, meta)
		if err == nil {
			t.Fatalf("decoy %q nominated the layout authority: config dir = %q", vector[0], config)
		}
	}
}

// A decoy must not be able to knock the real sing-box out of authority either,
// which is what an unfiltered second -C directory did (len(dirs) != 1 disables
// durable linechain tasks for as long as the decoy runs).
func TestResolveRuntimeLayoutIgnoresDecoyBesideRealProcess(t *testing.T) {
	f := newProcFixture(t)
	exe := f.binary(t, f.bin, "sing-box", 0o755)
	f.ownedByRoot(exe)
	attacker := f.dir(t, "home", "mallory")
	f.ownedBy(1000, attacker)
	decoy := f.binary(t, attacker, "sing-box", 0o755)
	real := t.TempDir()
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")

	config, _, err := resolveRuntimeLayout([][]string{
		{exe, "run", "-C", real},
		{decoy, "run", "-C", attacker},
	}, meta)
	if err != nil {
		t.Fatalf("decoy displaced the real sing-box authority: %v", err)
	}
	if config != real {
		t.Fatalf("config dir = %q, want %q", config, real)
	}
}

func TestTrustedSingBoxExecutable(t *testing.T) {
	f := newProcFixture(t)
	systemBin := f.binary(t, f.bin, "sing-box", 0o755)
	managerBin := f.binary(t, f.dir(t, "etc", "sing-box", "bin"), "sing-box", 0o755)
	f.ownedByRoot(systemBin, managerBin)
	for _, exe := range []string{systemBin, managerBin} {
		if !trustedSingBoxExecutable(exe) {
			t.Fatalf("legitimate sing-box path refused: %s (%s)", exe, explainSingBoxExecutable(exe))
		}
	}
	refuse := []string{
		"",
		"sing-box",
		"./sing-box",
		"/tmp/sing-box",
		"/home/user/bin/sing-box",
		"/opt/evil/sing-box",
		"/usr/bin/sing-box-fake",
		"/usr/bin/my-sing-box",
		"/usr/bin/sing-box/../../tmp/sing-box",
		"/usr/bin/subdir/sing-box",
		filepath.Join(f.bin, "sing-box", "..", "..", "sing-box"),
	}
	for _, exe := range refuse {
		if trustedSingBoxExecutable(exe) {
			t.Fatalf("untrusted executable path accepted: %q", exe)
		}
	}
}
