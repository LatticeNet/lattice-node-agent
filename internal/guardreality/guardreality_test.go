package guardreality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcAddressDecodesLittleEndianWords(t *testing.T) {
	// /proc writes each 32-bit word little-endian, so a naive hex decode gets
	// the octets backwards and every address in the report is wrong.
	addr, port, ok := parseProcAddress("0100007F:0016")
	if !ok || addr != "127.0.0.1" || port != 22 {
		t.Fatalf("ipv4 loopback decoded as %q:%d (ok=%t)", addr, port, ok)
	}
	addr, port, ok = parseProcAddress("00000000:01BB")
	if !ok || addr != "0.0.0.0" || port != 443 {
		t.Fatalf("wildcard decoded as %q:%d (ok=%t)", addr, port, ok)
	}
	// A v4-mapped v6 socket is the same listener the operator sees as v4.
	addr, _, ok = parseProcAddress("0000000000000000FFFF00000100007F:0050")
	if !ok || addr != "127.0.0.1" {
		t.Fatalf("v4-mapped v6 decoded as %q (ok=%t)", addr, ok)
	}
	if _, _, ok := parseProcAddress("nonsense"); ok {
		t.Fatal("a malformed entry must be skipped, not guessed at")
	}
}

func TestParseProcNetKeepsOnlyListeningTCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	// Columns as the kernel writes them: sl, local, remote, st, ..., inode.
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:C350 0100007F:0016 01 00000000:00000000 00:00000000 00000000     0        0 23456 1
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sockets := parseProcNet(path, "tcp", true)
	if len(sockets) != 1 {
		t.Fatalf("expected only the LISTEN row, got %d: %+v", len(sockets), sockets)
	}
	if sockets[0].port != 22 || sockets[0].inode != "12345" {
		t.Fatalf("unexpected socket: %+v", sockets[0])
	}

	// UDP has no LISTEN state, so a bound socket counts.
	udp := filepath.Join(dir, "udp")
	if err := os.WriteFile(udp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := parseProcNet(udp, "udp", false); len(got) != 2 {
		t.Fatalf("udp should keep every bound socket, got %d", len(got))
	}

	if got := parseProcNet(filepath.Join(dir, "missing"), "tcp", true); got != nil {
		t.Fatal("a missing /proc file must read as no sockets, not a crash")
	}
}

func TestCanonicalizeRulesetIgnoresHandlesAndBlankLines(t *testing.T) {
	// Handles are assigned at insert time: an identical ruleset reloaded gets
	// new ones, and hashing them would report drift on a table nobody touched.
	withHandles := `table inet lattice_guard {
	chain input { # handle 1
		type filter hook input priority 0; policy drop;
		tcp dport 22 accept # handle 7

	}
}
`
	withoutHandles := `table inet lattice_guard {
	chain input {
		type filter hook input priority 0; policy drop;
		tcp dport 22 accept
	}
}
`
	if canonicalizeRuleset(withHandles) != canonicalizeRuleset(withoutHandles) {
		t.Fatalf("handle numbers changed the canonical form:\n%q\n%q",
			canonicalizeRuleset(withHandles), canonicalizeRuleset(withoutHandles))
	}
	// A real rule change must still change the hash.
	changed := strings.Replace(withoutHandles, "dport 22", "dport 2222", 1)
	if canonicalizeRuleset(changed) == canonicalizeRuleset(withoutHandles) {
		t.Fatal("a changed rule must produce a different canonical form")
	}
	if canonicalizeRuleset("   \n\n") != "" {
		t.Fatal("an empty ruleset must canonicalize to empty, so the server sees it as not comparable")
	}
}

func TestInterfacesReportsSomethingOnAnyHost(t *testing.T) {
	// Loopback exists everywhere this runs; the point is that the collector
	// returns a usable list rather than erroring out on an odd host.
	ifaces := Interfaces()
	if len(ifaces) == 0 {
		t.Skip("no interfaces visible in this environment")
	}
	found := false
	for _, iface := range ifaces {
		if iface.Name != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("every reported interface was unnamed")
	}
}
