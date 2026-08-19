package singboxdiscover

import (
	"os"
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
// singBoxProcessArgs, which needs a live /proc and so is not exercised here.
// These tests pin the second layer, which is pure and portable: a process may
// only name host paths if it is running a sing-box binary out of a system
// executable directory.
func TestResolveRuntimeLayoutRefusesUnprivilegedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test models an unprivileged decoy against a root agent")
	}
	attacker := t.TempDir() // owned by the caller, not by root
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")

	for _, decoy := range [][]string{
		{"/tmp/sing-box", "run", "-C", attacker},
		{filepath.Join(attacker, "sing-box"), "run", "-C", attacker},
		{"sing-box", "run", "-C", attacker},                  // bare, resolved through PATH
		{"/usr/bin/my-sing-box-shim", "run", "-C", attacker}, // basename merely contains sing-box
	} {
		config, _, err := resolveRuntimeLayout([][]string{decoy}, meta)
		if err == nil {
			t.Fatalf("decoy %q nominated the layout authority: config dir = %q", decoy[0], config)
		}
	}
}

// A decoy must not be able to knock the real sing-box out of authority either,
// which is what an unfiltered second -C directory did (len(dirs) != 1 disables
// durable linechain tasks for as long as the decoy runs).
func TestResolveRuntimeLayoutIgnoresDecoyBesideRealProcess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test models an unprivileged decoy against a root agent")
	}
	real := t.TempDir()
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")

	config, _, err := resolveRuntimeLayout([][]string{
		{"/usr/bin/sing-box", "run", "-C", real},
		{"/tmp/sing-box", "run", "-C", t.TempDir()},
	}, meta)
	if err != nil {
		t.Fatalf("decoy displaced the real sing-box authority: %v", err)
	}
	if config != real {
		t.Fatalf("config dir = %q, want %q", config, real)
	}
}

func TestTrustedSingBoxExecutable(t *testing.T) {
	accept := []string{
		"/usr/bin/sing-box",
		"/usr/local/bin/sing-box",
		"/usr/sbin/sing-box",
		"/bin/sing-box",
	}
	for _, exe := range accept {
		if !trustedSingBoxExecutable(exe) {
			t.Fatalf("legitimate sing-box path refused: %s", exe)
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
	}
	for _, exe := range refuse {
		if trustedSingBoxExecutable(exe) {
			t.Fatalf("untrusted executable path accepted: %q", exe)
		}
	}
}
