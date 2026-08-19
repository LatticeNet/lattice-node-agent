package singboxdiscover

import (
	"os"
	"path/filepath"
	"testing"
)

// AUDIT (audit/agentsec): any local user can nominate the sing-box config
// directory the root agent trusts.
//
// singBoxProcessArgs (discover.go:681-705) walks /proc/[0-9]*/cmdline and accepts
// EVERY process whose argv[0] basename merely contains "sing-box" and whose argv
// contains "run". There is no check that the process runs as root, that its
// executable is a root-owned system path, or that it is the service the agent
// manages. An unprivileged local user therefore only has to run
//
//	cp /bin/sleep /tmp/sing-box && /tmp/sing-box run -C /tmp/mine 3600
//
// to be counted as the local authority. resolveRuntimeLayout then hands that
// directory to linechain.ConfigureLayout (main.go:376) as the E3 config root, and
// singBoxRuntimeConfigFiles (discover.go:646-675) reads *.json out of it and
// reports the contents to the control plane as this node's inventory.
//
// This test asserts the property that is missing at this layer: a config
// directory that the agent user does not own must not become the layout
// authority. It fails today.
//
// Not asserted here (the fix belongs in the selector, not in this function): a
// decoy running alongside the real sing-box makes len(dirs) == 2, which
// permanently disables durable linechain tasks on that node.
func TestResolveRuntimeLayoutRefusesUnprivilegedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test models an unprivileged decoy against a root agent")
	}
	attacker := t.TempDir() // owned by the caller, not by root
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")

	config, _, err := resolveRuntimeLayout([][]string{{"/tmp/sing-box", "run", "-C", attacker}}, meta)
	if err == nil {
		t.Fatalf("decoy process nominated the layout authority: config dir = %q", config)
	}
}
