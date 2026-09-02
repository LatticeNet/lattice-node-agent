package singboxdiscover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fleet this agent runs on installs sing-box under /etc/sing-box/bin. The
// binary itself is root-owned now; the directory still belongs to the
// manager's uid on some nodes. The selector refuses that, correctly, and the
// refusal listing is what the probe reports instead of a bare unknown.
func TestRefusedProcessesNamesTheRuleAndTheOwner(t *testing.T) {
	f := newProcFixture(t)
	managerDir := f.dir(t, "etc", "sing-box", "bin")
	f.ownedBy(1001, managerDir)
	exe := f.binary(t, managerDir, "sing-box", 0o755)
	proc := f.process(t, "3917185", []string{exe, "run", "-c", "/etc/sing-box/config.json"}, exe)
	f.ownedByRoot(proc, exe)

	trusted := f.binary(t, f.bin, "sing-box", 0o755)
	good := f.process(t, "42", []string{"sing-box", "run"}, trusted)
	f.ownedByRoot(good, trusted)

	unprivileged := f.process(t, "77", []string{exe, "run"}, exe)
	f.ownedBy(1001, unprivileged)

	other := f.process(t, "99", []string{"/usr/bin/nginx", "run"}, "/usr/bin/nginx")
	f.ownedByRoot(other)

	got := RefusedProcesses()
	if len(got) != 2 {
		t.Fatalf("expected the manager-owned and the unprivileged candidates, got %+v", got)
	}
	if got[0].PID != 77 || got[0].Reason != "process does not run as root" {
		t.Fatalf("unprivileged candidate wrong: %+v", got[0])
	}
	if got[1].PID != 3917185 || got[1].Exe != exe {
		t.Fatalf("manager candidate wrong: %+v", got[1])
	}
	if want := "directory " + managerDir + " owned by uid 1001, not root"; got[1].Reason != want {
		t.Fatalf("reason = %q, want %q", got[1].Reason, want)
	}
	if len(TrustedProcesses()) != 1 {
		t.Fatalf("the trusted process must still be accepted on its own")
	}
}

func TestExplainSingBoxExecutableOrdersTheRules(t *testing.T) {
	f := newProcFixture(t)
	if got := explainSingBoxExecutable("sing-box"); got != "executable path is not absolute" {
		t.Fatalf("relative: %q", got)
	}
	if got := explainSingBoxExecutable(filepath.Join(f.bin, "xray")); got != "executable is not named sing-box" {
		t.Fatalf("name: %q", got)
	}
	missing := filepath.Join(f.bin, "missing", "sing-box")
	if got := explainSingBoxExecutable(missing); got != "cannot stat "+missing+": no such file or directory" {
		t.Fatalf("missing: %q", got)
	}
	loose := f.binary(t, f.bin, "sing-box", 0o777)
	f.ownedBy(1001, loose)
	if got := explainSingBoxExecutable(loose); got != "owned by uid 1001, not root" {
		t.Fatalf("owner must come before mode: %q", got)
	}
	f.ownedByRoot(loose)
	if got := explainSingBoxExecutable(loose); got != "group or world writable (mode 0777)" {
		t.Fatalf("writable: %q", got)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := explainSingBoxExecutable(loose); got != "" {
		t.Fatalf("trusted binary must pass: %q", got)
	}
	f.ownedBy(1001, f.bin)
	if got := explainSingBoxExecutable(loose); got != "directory "+f.bin+" owned by uid 1001, not root" {
		t.Fatalf("ancestry: %q", got)
	}
}

// The sshd facts probe runs a root-only command from whatever
// ResolveTrustedExecutable hands it, so the resolver has to apply the
// selector's file and ancestry rules and name the rule it failed.
func TestResolveTrustedExecutableSharesTheSelectorRules(t *testing.T) {
	f := newProcFixture(t)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || !strings.Contains(reason, "sshd not found in the executable search directories") || !strings.Contains(reason, f.bin) {
		t.Fatalf("missing: path=%q reason=%q", path, reason)
	}
	if path, reason := ResolveTrustedExecutable("../sshd"); path != "" || reason != "executable name must be a bare file name" {
		t.Fatalf("relative name: path=%q reason=%q", path, reason)
	}
	loose := f.binary(t, f.bin, "sshd", 0o777)
	f.ownedByRoot(loose)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || reason != loose+": group or world writable (mode 0777)" {
		t.Fatalf("writable: path=%q reason=%q", path, reason)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	f.ownedBy(1001, loose)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || reason != loose+": owned by uid 1001, not root" {
		t.Fatalf("owner: path=%q reason=%q", path, reason)
	}
	f.ownedByRoot(loose)
	f.ownedBy(1001, f.bin)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || reason != loose+": directory "+f.bin+" owned by uid 1001, not root" {
		t.Fatalf("ancestry: path=%q reason=%q", path, reason)
	}
	f.ownedByRoot(f.bin)
	if path, reason := ResolveTrustedExecutable("sshd"); path != loose || reason != "" {
		t.Fatalf("trusted: path=%q reason=%q", path, reason)
	}
}
