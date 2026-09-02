package guardreality

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestCollectBuildsRealityFromInjectedCommands(t *testing.T) {
	fixed := time.Date(2026, 7, 31, 12, 30, 0, 0, time.UTC)
	calls := []string{}
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "ss -tulpnH":
			return []byte(ssFixture), nil
		case "ip -j addr":
			return []byte(ipFixture), nil
		case "nft -j list ruleset":
			return []byte(nftFixture("11", "22")), nil
		case "nft --version":
			return []byte("nftables v1.0.9 (Old Doc Yak)\n"), nil
		default:
			t.Fatalf("unexpected live command shape: %s", call)
			return nil, nil
		}
	}

	got, err := Collect(context.Background(), Source{Runner: runner, Now: func() time.Time { return fixed }}, " node-a ")
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "node-a" || !got.CollectedAt.Equal(fixed) {
		t.Fatalf("identity/time not normalized: %+v", got)
	}
	wantCalls := []string{"ss -tulpnH", "ip -j addr", "nft -j list ruleset", "nft --version"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("unexpected commands:\n got %#v\nwant %#v", calls, wantCalls)
	}
	wantListeners := []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"},
		{Protocol: "tcp", Port: 443, Address: "::", Process: "nginx"},
		{Protocol: "udp", Port: 41641, Address: "0.0.0.0", Process: "tailscaled"},
	}
	if !reflect.DeepEqual(got.Listeners, wantListeners) {
		t.Fatalf("listeners:\n got %#v\nwant %#v", got.Listeners, wantListeners)
	}
	wantIfaces := []model.GuardInterface{
		{Name: "eth0", Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, Up: true},
		{Name: "tailscale0", Addresses: []string{"100.64.0.2/32"}, Up: true},
	}
	if !reflect.DeepEqual(got.Interfaces, wantIfaces) {
		t.Fatalf("interfaces:\n got %#v\nwant %#v", got.Interfaces, wantIfaces)
	}
	if got.ManagedSHA == "" {
		t.Fatal("managed table hash must be set")
	}
	if !reflect.DeepEqual(got.ForeignTables, []string{"inet ts-input", "ip filter"}) {
		t.Fatalf("foreign tables = %#v", got.ForeignTables)
	}
	if got.NFTVersion != "nftables v1.0.9 (Old Doc Yak)" {
		t.Fatalf("nft version = %q", got.NFTVersion)
	}
}

func TestCollectPropagatesCommandFailure(t *testing.T) {
	boom := errors.New("missing ip")
	_, err := Collect(context.Background(), Source{Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ss" {
			return []byte(ssFixture), nil
		}
		return nil, boom
	}}, "node-a")
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "ip -j addr") {
		t.Fatalf("expected ip failure with command context, got %v", err)
	}
}

func TestCollectManagedTableSHA(t *testing.T) {
	collect := func(ruleset string, runnerErr error) (string, []string, error) {
		calls := []string{}
		got, err := CollectManagedTableSHA(context.Background(), Source{
			NFTBinary: "custom-nft",
			Runner: func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if runnerErr != nil {
					return nil, runnerErr
				}
				return []byte(ruleset), nil
			},
		})
		return got, calls, err
	}

	first, calls, err := collect(nftFixture("11", "22"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"custom-nft -j list ruleset"}) {
		t.Fatalf("commands = %#v, want one bounded ruleset read", calls)
	}
	second, _, err := collect(nftFixture("99", "100"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("managed hash should be stable across handle churn: %q vs %q", first, second)
	}
	changed, _, err := collect(strings.ReplaceAll(nftFixture("11", "22"), `"right": 22`, `"right": 2222`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("managed hash must change when a managed rule changes")
	}

	missing, _, err := collect(`{"nftables":[{"table":{"family":"ip","name":"filter"}}]}`, nil)
	if err == nil || missing != "" || !strings.Contains(err.Error(), "managed nft table inet lattice_guard not found") {
		t.Fatalf("missing table = %q, %v; want fail-closed error", missing, err)
	}
	empty, _, err := collect(`{"nftables":[{"table":{"family":"inet","name":"lattice_guard"}}]}`, nil)
	if err == nil || empty != "" || !strings.Contains(err.Error(), "managed nft table inet lattice_guard is empty") {
		t.Fatalf("empty managed table = %q, %v; want fail-closed error", empty, err)
	}
	malformed, _, err := collect(`{"nftables":`, nil)
	if err == nil || malformed != "" || !strings.Contains(err.Error(), "parse nft ruleset") {
		t.Fatalf("malformed ruleset = %q, %v; want fail-closed parse error", malformed, err)
	}
	boom := errors.New("nft unavailable")
	failed, _, err := collect("", boom)
	if !errors.Is(err, boom) || failed != "" || !strings.Contains(err.Error(), "custom-nft -j list ruleset") {
		t.Fatalf("runner failure = %q, %v; want contextual fail-closed error", failed, err)
	}
}

func TestParseSSListenersSkipsNonNumericPortsAndSorts(t *testing.T) {
	got, err := ParseSSListeners([]byte(strings.Join([]string{
		`udp UNCONN 0 0 *:51820 *:* users:(("wg",pid=9,fd=3))`,
		`tcp LISTEN 0 4096 127.0.0.1:http 0.0.0.0:* users:(("web",pid=1,fd=3))`,
		`tcp LISTEN 0 4096 [fe80::1%eth0]:22 [::]:* users:(("sshd",pid=2,fd=3))`,
		`tcp LISTEN 0 4096 [fe80::1%eth0]:22 [::]:* users:(("sshd",pid=2,fd=3))`,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	want := []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "fe80::1", Process: "sshd"},
		{Protocol: "udp", Port: 51820, Address: "*", Process: "wg"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseIPAddrNormalizesInterfaces(t *testing.T) {
	got, err := ParseIPAddr([]byte(`[
	  {"ifname":"tailscale0","flags":["POINTOPOINT","UP"],"addr_info":[{"local":"100.64.0.2","prefixlen":32}]},
	  {"ifname":"down0","operstate":"DOWN","addr_info":[{"local":"not-an-ip","prefixlen":24}]},
	  {"ifname":"eth0","operstate":"UP","addr_info":[{"local":"2001:db8::10","prefixlen":64},{"local":"192.0.2.10","prefixlen":24},{"local":"192.0.2.10","prefixlen":24},{"local":"198.51.100.9","prefixlen":128}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []model.GuardInterface{
		{Name: "down0"},
		{Name: "eth0", Addresses: []string{"192.0.2.10/24", "198.51.100.9", "2001:db8::10/64"}, Up: true},
		{Name: "tailscale0", Addresses: []string{"100.64.0.2/32"}, Up: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interfaces:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseNFTRulesetIgnoresHandlesWhenHashingManagedTable(t *testing.T) {
	a, foreignA, err := ParseNFTRuleset([]byte(nftFixture("11", "22")))
	if err != nil {
		t.Fatal(err)
	}
	b, foreignB, err := ParseNFTRuleset([]byte(nftFixture("99", "100")))
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a != b {
		t.Fatalf("managed hash should be stable across handle churn: %q vs %q", a, b)
	}
	wantForeign := []string{"inet ts-input", "ip filter"}
	if !reflect.DeepEqual(foreignA, wantForeign) || !reflect.DeepEqual(foreignB, wantForeign) {
		t.Fatalf("foreign tables = %#v / %#v", foreignA, foreignB)
	}
	changed, _, err := ParseNFTRuleset([]byte(strings.ReplaceAll(nftFixture("11", "22"), `"right": 22`, `"right": 2222`)))
	if err != nil {
		t.Fatal(err)
	}
	if changed == a {
		t.Fatal("managed hash must change when a managed rule changes")
	}
}

func TestParseNFTRulesetWithoutManagedTableReturnsOnlyForeign(t *testing.T) {
	hash, foreign, err := ParseNFTRuleset([]byte(`{"nftables":[{"table":{"family":"ip","name":"filter"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if hash != "" {
		t.Fatalf("managed hash = %q, want empty", hash)
	}
	if !reflect.DeepEqual(foreign, []string{"ip filter"}) {
		t.Fatalf("foreign tables = %#v", foreign)
	}
}

func TestLimitedBufferReportsTruncation(t *testing.T) {
	var buf limitedBuffer
	chunk := strings.Repeat("x", maxOutputBytes+1)
	n, err := buf.Write([]byte(chunk))
	if err != nil || n != len(chunk) {
		t.Fatalf("write = %d, %v; want full write count and nil error", n, err)
	}
	if !buf.Truncated() || len(buf.Bytes()) != maxOutputBytes {
		t.Fatalf("truncation not reported correctly: truncated=%v len=%d", buf.Truncated(), len(buf.Bytes()))
	}
}

const ssFixture = `
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))
udp UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* users:(("tailscaled",pid=234,fd=13))
tcp LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=1,fd=6))
tcp LISTEN 0 4096 127.0.0.1:http 0.0.0.0:* users:(("named-port",pid=2,fd=3))
`

const ipFixture = `[
  {"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP"],"addr_info":[{"local":"192.0.2.10","prefixlen":24},{"local":"2001:db8::10","prefixlen":64}]},
  {"ifname":"tailscale0","flags":["POINTOPOINT","UP"],"addr_info":[{"local":"100.64.0.2","prefixlen":32}]}
]`

func nftFixture(tableHandle, ruleHandle string) string {
	return `{
  "nftables": [
    {"metainfo": {"json_schema_version": 1}},
    {"table": {"family": "inet", "name": "lattice_guard", "handle": ` + tableHandle + `}},
    {"chain": {"family": "inet", "table": "lattice_guard", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop", "handle": 20}},
    {"rule": {"family": "inet", "table": "lattice_guard", "chain": "input", "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 22}}, {"accept": null}], "handle": ` + ruleHandle + `}},
    {"table": {"family": "ip", "name": "filter", "handle": 3}},
    {"table": {"family": "inet", "name": "ts-input", "handle": 4}}
  ]
}`
}

func TestCollectAttachesSSHDFactsOrNote(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch name + " " + strings.Join(args, " ") {
		case "ss -tulpnH":
			return []byte(ssFixture), nil
		case "ip -j addr":
			return []byte(ipFixture), nil
		case "nft -j list ruleset":
			return []byte(nftFixture("11", "22")), nil
		case "nft --version":
			return []byte("nftables v1.0.9\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	got, err := Collect(context.Background(), Source{Runner: runner}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHD != nil || got.SSHDNote != "sshd facts collector not configured" {
		t.Fatalf("unwired sshd step must say so: sshd=%+v note=%q", got.SSHD, got.SSHDNote)
	}

	facts := &model.GuardSSHDFacts{
		PubkeyAuthentication: true,
		PermitRootLogin:      "no",
		Ports:                []int{58394},
		ObservedAt:           time.Date(2026, 9, 2, 7, 0, 0, 0, time.UTC),
	}
	got, err = Collect(context.Background(), Source{Runner: runner, SSHD: func(context.Context) (*model.GuardSSHDFacts, string) {
		return facts, ""
	}}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.SSHD, facts) || got.SSHDNote != "" {
		t.Fatalf("facts not attached: sshd=%+v note=%q", got.SSHD, got.SSHDNote)
	}

	got, err = Collect(context.Background(), Source{Runner: runner, SSHD: func(context.Context) (*model.GuardSSHDFacts, string) {
		return nil, "sshd -T needs root to read the effective configuration; agent runs as uid 1000"
	}}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHD != nil || !strings.Contains(got.SSHDNote, "needs root") || len(got.Listeners) == 0 {
		t.Fatalf("a refused sshd step must keep the rest of the snapshot: %+v", got)
	}
}
