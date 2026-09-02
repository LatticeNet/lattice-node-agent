package singboxdiscover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fleet this agent runs on installs sing-box under /etc/sing-box/bin with
// the manager's own uid. The selector refuses it, correctly, and until now
// said nothing. The refusal listing is what the probe reports instead.
func TestRefusedProcessesNamesTheRuleAndTheOwner(t *testing.T) {
	f := newProcFixture(t)
	managerDir := filepath.Join(t.TempDir(), "etc", "sing-box", "bin")
	if err := os.MkdirAll(managerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := f.binary(t, managerDir, "sing-box", 0o755)
	proc := f.process(t, "3917185", []string{exe, "run", "-c", "/etc/sing-box/config.json"}, exe)
	f.ownedByRoot(proc)
	f.ownedBy(1001, exe)

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
	if !strings.Contains(got[1].Reason, "outside the trusted executable directories") || !strings.Contains(got[1].Reason, "owned by uid 1001") {
		t.Fatalf("reason must name the directory rule and the owner: %q", got[1].Reason)
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
	loose := f.binary(t, f.bin, "sing-box", 0o777)
	f.ownedByRoot(loose)
	if got := explainSingBoxExecutable(loose); got != "group or world writable" {
		t.Fatalf("writable: %q", got)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	f.ownedBy(1001, loose)
	if got := explainSingBoxExecutable(loose); got != "owned by uid 1001, not root" {
		t.Fatalf("owner: %q", got)
	}
	f.ownedByRoot(loose)
	if got := explainSingBoxExecutable(loose); got != "" {
		t.Fatalf("trusted binary must pass: %q", got)
	}
	if got := explainSingBoxExecutable(filepath.Join(f.root, "missing", "sing-box")); !strings.HasPrefix(got, "outside the trusted executable directories") {
		t.Fatalf("directory rule must apply without a stat: %q", got)
	}
}

// The sshd facts probe runs a root-only command from whatever
// ResolveTrustedExecutable hands it, so the resolver has to apply the
// selector's rules in the selector's order and name the rule it failed.
func TestResolveTrustedExecutableSharesTheSelectorRules(t *testing.T) {
	f := newProcFixture(t)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || !strings.Contains(reason, "sshd not found in the trusted executable directories") || !strings.Contains(reason, f.bin) {
		t.Fatalf("missing: path=%q reason=%q", path, reason)
	}
	if path, reason := ResolveTrustedExecutable("../sshd"); path != "" || reason != "executable name must be a bare file name" {
		t.Fatalf("relative name: path=%q reason=%q", path, reason)
	}
	loose := f.binary(t, f.bin, "sshd", 0o777)
	f.ownedByRoot(loose)
	if path, reason := ResolveTrustedExecutable("sshd"); path != "" || reason != loose+": group or world writable" {
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
	if path, reason := ResolveTrustedExecutable("sshd"); path != loose || reason != "" {
		t.Fatalf("trusted: path=%q reason=%q", path, reason)
	}
}
