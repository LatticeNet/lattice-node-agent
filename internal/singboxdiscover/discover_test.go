package singboxdiscover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestDiscoverParsesListAndVersion(t *testing.T) {
	src := Source{
		Addr: "203.0.113.7",
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			last := args[len(args)-1]
			// --addr must be threaded so the script stays non-interactive.
			if !contains(args, "--addr") || !contains(args, "203.0.113.7") || !contains(args, "--json") {
				t.Fatalf("expected --addr/--json in args, got %v", args)
			}
			switch last {
			case "list":
				return []byte(`{"ok":true,"count":2,"nodes":[
					{"name":"VLESS-REALITY-17891.json","protocol":"vless","network":"reality","port":"17891","sni":"www.x.com","share_url":"vless://a@h:17891"},
					{"name":"Hysteria2-17892.json","protocol":"hysteria2","port":"17892","share_url":"hysteria2://b@h:17892"}
				]}`), nil
			case "provision":
				return []byte(`{"ok":true,"installed":true,"version":"1.12.12","service_active":true}`), nil
			}
			return nil, errors.New("unexpected command")
		},
	}
	inv, err := Discover(context.Background(), src, "node-x")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if inv.NodeID != "node-x" || inv.Status != "ok" {
		t.Fatalf("unexpected inv meta: %+v", inv)
	}
	if inv.CoreVersion != "1.12.12" {
		t.Fatalf("version not captured: %q", inv.CoreVersion)
	}
	if len(inv.Nodes) != 2 || inv.Nodes[0].Network != "reality" || inv.Nodes[1].Protocol != "hysteria2" {
		t.Fatalf("nodes parse wrong: %+v", inv.Nodes)
	}
}

func TestResolveRuntimeLayoutUsesLocalProcessAuthority(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(t.TempDir(), "lattice-metadata.json")
	config, sidecar, err := resolveRuntimeLayout([][]string{{"/usr/bin/sing-box", "run", "-C", dir}}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if config != dir || sidecar != meta {
		t.Fatalf("layout = %q %q", config, sidecar)
	}
	// Ambiguity must still be refused. Both vectors carry a trusted executable
	// path so this asserts the ambiguity rule itself rather than being satisfied
	// by the executable-identity check added for the decoy-process finding.
	if _, _, err := resolveRuntimeLayout([][]string{{"/usr/bin/sing-box", "run", "-C", dir}, {"/usr/local/bin/sing-box", "run", "-C", t.TempDir()}}, meta); err == nil {
		t.Fatal("ambiguous config directories accepted")
	}
}

func TestDiscoverListFailureReportsErrorStatus(t *testing.T) {
	src := Source{
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "list" {
				return nil, errors.New("sb: command not found")
			}
			return []byte(`{}`), nil
		},
		runtimeFiles: func() []string { return nil },
	}
	inv, err := Discover(context.Background(), src, "node-y")
	if err == nil {
		t.Fatalf("expected error")
	}
	if inv.Status != "error" || inv.Error == "" || inv.Nodes == nil {
		t.Fatalf("expected error-status inventory with empty node list, got %+v", inv)
	}
	if !strings.Contains(inv.Error, "command not found") {
		t.Fatalf("error not surfaced: %q", inv.Error)
	}
}

func TestDiscoverFallsBackToRuntimeConfigDirectory(t *testing.T) {
	files := map[string]string{
		"/etc/sing-box/config.json": `{"log":{},"outbounds":[]}`,
		"/etc/sing-box/conf/routes.json": `{
			"route":{"rules":[{"inbound":["VLESS-REALITY-31001.json"],"action":"route","outbound":"[openjobs]-qqpw-vds1-vless"}]}
		}`,
		"/etc/sing-box/conf/VLESS-REALITY-31001.json": `{
			"inbounds":[{
				"tag":"VLESS-REALITY-31001.json",
				"type":"vless",
				"listen":"::",
				"listen_port":31001,
				"users":[{"uuid":"redacted"}],
				"_lattice":{"owner":"ops","line_id":"line-uuid-a","node_uuid":"node-uuid-a","labels":{"tier":"edge"}},
				"tls":{
					"enabled":true,
					"server_name":"www.cloudflare.com",
					"reality":{"enabled":true,"handshake":{"server":"www.cloudflare.com","server_port":443}}
				}
			}]
		}`,
	}
	src := Source{
		Addr: "64.186.227.5",
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "list" {
				return nil, errors.New("sing-box: unknown flag --json")
			}
			return []byte(`{}`), nil
		},
		runtimeFiles: func() []string {
			return []string{"/etc/sing-box/config.json", "/etc/sing-box/conf/routes.json", "/etc/sing-box/conf/VLESS-REALITY-31001.json"}
		},
		readFile: func(path string) ([]byte, error) {
			return []byte(files[path]), nil
		},
	}
	inv, err := Discover(context.Background(), src, "node-runtime")
	if err != nil {
		t.Fatalf("Discover fallback: %v", err)
	}
	if inv.Status != "ok" || len(inv.Nodes) != 1 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
	n := inv.Nodes[0]
	if n.Name != "VLESS-REALITY-31001.json" || n.Protocol != "vless" || n.Network != "reality" || n.Port != "31001" || n.Address != "64.186.227.5" || n.SNI != "www.cloudflare.com" {
		t.Fatalf("runtime node parse wrong: %+v", n)
	}
	if n.ListenHost != "::" || n.OutboundRef != "[openjobs]-qqpw-vds1-vless" || !n.UserKnown || n.UserCount != 1 {
		t.Fatalf("runtime enrichment wrong: %+v", n)
	}
	if n.LineID != "line-uuid-a" || n.NodeIdentityUUID != "node-uuid-a" {
		t.Fatalf("runtime lattice identity wrong: %+v", n)
	}
	if n.Metadata["owner"] != "ops" || n.Metadata["label.tier"] != "edge" {
		t.Fatalf("runtime metadata wrong: %+v", n.Metadata)
	}
	if n.ShareURL != "" || n.PublicKey != "" {
		t.Fatalf("runtime fallback must not invent credential-bearing fields: %+v", n)
	}
}

func TestDiscoverProvisionFailureStillReturnsNodes(t *testing.T) {
	src := Source{
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "list" {
				return []byte(`{"ok":true,"count":0,"nodes":[]}`), nil
			}
			return nil, errors.New("provision boom") // must not fail discovery
		},
	}
	inv, err := Discover(context.Background(), src, "node-z")
	if err != nil {
		t.Fatalf("provision failure must not fail discovery: %v", err)
	}
	if inv.Status != "ok" || inv.CoreVersion != "" {
		t.Fatalf("unexpected: %+v", inv)
	}
}

func TestDiscoverRuntimeConfigResolvesOutboundDestination(t *testing.T) {
	files := map[string]string{
		"/etc/sing-box/config.json": `{
			"inbounds":[
				{"tag":"in-relay","type":"vless","listen":"::","listen_port":20001,"users":[{"uuid":"u1"}]},
				{"tag":"in-direct","type":"vless","listen":"::","listen_port":20002,"users":[{"uuid":"u2"}]}
			],
			"outbounds":[
				{"tag":"exit-b","type":"vless","server":"198.51.100.9","server_port":443},
				{"tag":"direct","type":"direct"}
			],
			"route":{"rules":[
				{"inbound":["in-relay"],"action":"route","outbound":"exit-b"},
				{"inbound":["in-direct"],"action":"route","outbound":"direct"}
			]}
		}`,
	}
	src := Source{
		Addr: "203.0.113.1",
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[len(args)-1] == "list" {
				return nil, errors.New("sing-box: unknown flag --json")
			}
			return []byte(`{}`), nil
		},
		runtimeFiles: func() []string { return []string{"/etc/sing-box/config.json"} },
		readFile:     func(path string) ([]byte, error) { return []byte(files[path]), nil },
	}
	inv, err := Discover(context.Background(), src, "node-relay")
	if err != nil {
		t.Fatalf("Discover fallback: %v", err)
	}
	if inv.Status != "ok" || len(inv.Nodes) != 2 {
		t.Fatalf("want 2 nodes ok, got status=%q nodes=%+v", inv.Status, inv.Nodes)
	}
	var relay, direct *model.SingBoxNode
	for i := range inv.Nodes {
		switch inv.Nodes[i].Name {
		case "in-relay":
			relay = &inv.Nodes[i]
		case "in-direct":
			direct = &inv.Nodes[i]
		}
	}
	if relay == nil || direct == nil {
		t.Fatalf("expected both inbounds present: %+v", inv.Nodes)
	}
	// The relayed inbound must resolve its outbound tag to the downstream exit.
	if relay.OutboundRef != "exit-b" || relay.OutboundServer != "198.51.100.9" ||
		relay.OutboundPort != "443" || relay.OutboundType != "vless" {
		t.Fatalf("relay outbound resolution wrong: %+v", relay)
	}
	// The direct inbound carries no downstream server/port.
	if direct.OutboundRef != "direct" || direct.OutboundServer != "" || direct.OutboundPort != "" {
		t.Fatalf("direct outbound must leave server/port empty: %+v", direct)
	}
}

func TestPrimaryPathEnrichesFromConfig(t *testing.T) {
	// `sb --json list` output carries only per-inbound fields. Trojan-41003 also
	// arrives with an sb-provided line_id, which enrichment must not clobber.
	listJSON := `{"ok":true,"count":3,"nodes":[
		{"name":"Trojan-41001.json","protocol":"trojan","port":"41001"},
		{"name":"VLESS-41002.json","protocol":"vless","port":"41002"},
		{"name":"Trojan-41003.json","protocol":"trojan","port":"41003","line_id":"sb-provided-line"}
	]}`
	files := map[string]string{
		"/etc/sing-box/config.json": `{
			"inbounds":[
				{"tag":"Trojan-41001.json","type":"trojan","listen":"::","listen_port":41001,"_lattice":{"line_id":"line-uuid-a","node_uuid":"node-uuid-a"}},
				{"tag":"VLESS-41002.json","type":"vless","listen":"::","listen_port":41002,"_lattice":{"line_id":"line-uuid-b","node_uuid":"node-uuid-b"}},
				{"tag":"Trojan-41003.json","type":"trojan","listen":"::","listen_port":41003,"_lattice":{"line_id":"config-line-c"}}
			],
			"outbounds":[
				{"tag":"exit-hk","type":"trojan","server":"198.51.100.9","server_port":8443},
				{"tag":"direct","type":"direct"}
			],
			"route":{"rules":[
				{"inbound":["Trojan-41001.json"],"action":"route","outbound":"exit-hk"},
				{"inbound":["VLESS-41002.json"],"action":"route","outbound":"direct"},
				{"inbound":["Trojan-41003.json"],"action":"route","outbound":"exit-hk"}
			]}
		}`,
	}
	src := Source{
		Addr: "203.0.113.42",
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch args[len(args)-1] {
			case "list":
				return []byte(listJSON), nil
			case "provision":
				return []byte(`{"ok":true,"version":"1.12.0"}`), nil
			}
			return nil, errors.New("unexpected command")
		},
		runtimeFiles: func() []string { return []string{"/etc/sing-box/config.json"} },
		readFile:     func(path string) ([]byte, error) { return []byte(files[path]), nil },
	}
	inv, err := Discover(context.Background(), src, "node-primary")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if inv.Status != "ok" || len(inv.Nodes) != 3 {
		t.Fatalf("unexpected inventory: status=%q nodes=%+v", inv.Status, inv.Nodes)
	}
	byName := map[string]model.SingBoxNode{}
	for _, n := range inv.Nodes {
		byName[n.Name] = n
	}
	// Relayed inbound: outbound tag + downstream server:port + line/identity all
	// recovered from the config that sb omitted.
	relay := byName["Trojan-41001.json"]
	if relay.OutboundRef != "exit-hk" || relay.OutboundServer != "198.51.100.9" ||
		relay.OutboundPort != "8443" || relay.OutboundType != "trojan" {
		t.Fatalf("relay outbound enrichment wrong: %+v", relay)
	}
	if relay.LineID != "line-uuid-a" || relay.NodeIdentityUUID != "node-uuid-a" {
		t.Fatalf("relay lattice identity enrichment wrong: %+v", relay)
	}
	// Direct-routed inbound: outbound tag recorded but no downstream server/port.
	direct := byName["VLESS-41002.json"]
	if direct.OutboundRef != "direct" || direct.OutboundServer != "" || direct.OutboundPort != "" {
		t.Fatalf("direct-routed inbound must leave OutboundServer/Port empty: %+v", direct)
	}
	if direct.LineID != "line-uuid-b" {
		t.Fatalf("direct inbound line enrichment wrong: %+v", direct)
	}
	// sb-provided value must survive: config line_id ("config-line-c") must NOT
	// overwrite the sb-provided one.
	kept := byName["Trojan-41003.json"]
	if kept.LineID != "sb-provided-line" {
		t.Fatalf("sb-provided LineID must not be overwritten, got %q", kept.LineID)
	}
	if kept.OutboundRef != "exit-hk" || kept.OutboundServer != "198.51.100.9" {
		t.Fatalf("outbound enrichment should still apply to sb node: %+v", kept)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// --- design-15: per-line inspect enrichment + sidecar (lattice.singbox-metadata.v2) ---
//
// testdata/{v2-valid-full,v2-valid-minimal,v1-legacy-upgrade}.json are verbatim
// copies of lattice/docs/contracts/fixtures/ (design-15 S0); the schema there is
// the arbiter.

// sidecarTestList is a list row the way a NEWER sb emits it (outbound_ref,
// line_id, user_known already set), so discovery skips the per-line inspect
// call and the test isolates the sidecar join.
const sidecarTestList = `{"ok":true,"count":1,"nodes":[
	{"name":"vless-31001","protocol":"vless","port":"31001","line_id":"l","outbound_ref":"direct","user_known":true}
]}`

// listOnlyRunner answers list/provision and fails the test on anything else,
// which also proves no inspect call is spent on already-enriched rows.
func listOnlyRunner(t *testing.T, listJSON string) func(context.Context, string, ...string) ([]byte, error) {
	t.Helper()
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[len(args)-1] {
		case "list":
			return []byte(listJSON), nil
		case "provision":
			return []byte(`{}`), nil
		}
		t.Fatalf("unexpected command: %v", args)
		return nil, nil
	}
}

func TestDiscoverAppliesSidecarV2(t *testing.T) {
	listJSON := `{"ok":true,"count":3,"nodes":[
		{"name":"vless-31001","protocol":"vless","port":"31001","line_id":"l1","outbound_ref":"direct","user_known":true},
		{"name":"vless-8468","protocol":"vless","port":"8468","line_id":"l2","outbound_ref":"direct","user_known":true},
		{"name":"trojan-9999","protocol":"trojan","port":"9999","line_id":"l3","outbound_ref":"direct","user_known":true}
	]}`
	src := Source{
		MetaPath:     "testdata/v2-valid-full.json",
		runner:       listOnlyRunner(t, listJSON),
		runtimeFiles: func() []string { return nil },
	}
	inv, err := Discover(context.Background(), src, "node-hk")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	byName := map[string]model.SingBoxNode{}
	for _, n := range inv.Nodes {
		byName[n.Name] = n
	}
	// Tag hit with a declared chain edge: both identities join.
	relay := byName["vless-31001"]
	if relay.LineUUID != "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d" ||
		relay.DownstreamLineUUID != "1eec4b5a-9c2f-4a1b-8d3e-5f6a7b8c9d0e" {
		t.Fatalf("declared chain join wrong: %+v", relay)
	}
	// Tag hit with chain.downstream_line_uuid null: single-exit, stays empty.
	single := byName["vless-8468"]
	if single.LineUUID != "2af49c3e-1d5b-4e7a-8c9d-0e1f2a3b4c5d" || single.DownstreamLineUUID != "" {
		t.Fatalf("null downstream_line_uuid must stay empty: %+v", single)
	}
	// Tag miss: the sidecar must not invent annotations.
	if n := byName["trojan-9999"]; n.LineUUID != "" || n.DownstreamLineUUID != "" {
		t.Fatalf("unlisted tag must stay unannotated: %+v", n)
	}
}

func TestDiscoverAppliesSidecarV2Minimal(t *testing.T) {
	listJSON := `{"ok":true,"count":1,"nodes":[
		{"name":"trojan-41001","protocol":"trojan","port":"41001","line_id":"l","outbound_ref":"direct","user_known":true}
	]}`
	src := Source{
		MetaPath:     "testdata/v2-valid-minimal.json",
		runner:       listOnlyRunner(t, listJSON),
		runtimeFiles: func() []string { return nil },
	}
	inv, err := Discover(context.Background(), src, "node-aaitr")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	n := inv.Nodes[0]
	if n.LineUUID != "7c3d8e2f-5a4b-4c6d-9e0f-1a2b3c4d5e6f" || n.DownstreamLineUUID != "" {
		t.Fatalf("minimal sidecar (no chain block) join wrong: %+v", n)
	}
}

func TestDiscoverSidecarMissingIsSilent(t *testing.T) {
	var logs []string
	src := Source{
		MetaPath:     "/nonexistent/lattice-metadata.json",
		runner:       listOnlyRunner(t, sidecarTestList),
		runtimeFiles: func() []string { return nil },
		Logf:         func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	}
	inv, err := Discover(context.Background(), src, "node-nometa")
	if err != nil {
		t.Fatalf("missing sidecar must not fail discovery: %v", err)
	}
	if inv.Nodes[0].LineUUID != "" || inv.Nodes[0].DownstreamLineUUID != "" {
		t.Fatalf("missing sidecar must omit the fields: %+v", inv.Nodes[0])
	}
	if len(logs) != 0 {
		t.Fatalf("missing sidecar must stay silent, got %v", logs)
	}
}

func TestDiscoverSidecarCorruptLogsAndContinues(t *testing.T) {
	var logs []string
	src := Source{
		MetaPath:     "/etc/sing-box/lattice-metadata.json",
		runner:       listOnlyRunner(t, sidecarTestList),
		runtimeFiles: func() []string { return nil },
		readFile: func(path string) ([]byte, error) {
			if path == "/etc/sing-box/lattice-metadata.json" {
				return []byte(`{"schema":"lattice.singbox-metadata.v2","inbounds":[broken`), nil
			}
			// The endpoints file is read from the same seam. Most nodes do not
			// have one, and this case is about the sidecar.
			return nil, os.ErrNotExist
		},
		Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	}
	inv, err := Discover(context.Background(), src, "node-corrupt")
	if err != nil {
		t.Fatalf("corrupt sidecar must not fail discovery: %v", err)
	}
	if inv.Status != "ok" || inv.Nodes[0].LineUUID != "" {
		t.Fatalf("corrupt sidecar must report the base inventory: %+v", inv)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "sidecar") {
		t.Fatalf("corrupt sidecar must be logged once, got %v", logs)
	}
}

func TestDiscoverSidecarReadPermissionErrorLogsAndContinues(t *testing.T) {
	var logs []string
	src := Source{
		MetaPath:     "/etc/sing-box/lattice-metadata.json",
		runner:       listOnlyRunner(t, sidecarTestList),
		runtimeFiles: func() []string { return nil },
		// Only the sidecar is unreadable here. Answering permission-denied for
		// every path would also trip the endpoints reader and make this assert
		// on two warnings for one fault.
		readFile: func(path string) ([]byte, error) {
			if strings.Contains(path, "lattice-metadata.json") {
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		},
		Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	}
	inv, err := Discover(context.Background(), src, "node-permission")
	if err != nil || inv.Nodes[0].LineUUID != "" {
		t.Fatalf("unreadable sidecar must return only base inventory: inv=%+v err=%v", inv, err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "permission") {
		t.Fatalf("permission error must be surfaced once, got %v", logs)
	}
}

func TestDiscoverSidecarInvalidV2IsRejectedAtomically(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"wrong schema", `{"schema":"lattice.singbox-metadata.v3","inbounds":[]}`},
		{"bad uuid", `{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"vless-31001","line_uuid":"not-a-uuid"}]}`},
		{"duplicate tag", `{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"vless-31001","line_uuid":"11111111-1111-4111-8111-111111111111"},{"tag":"vless-31001","line_uuid":"22222222-2222-4222-8222-222222222222"}]}`},
		{"self chain", `{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"vless-31001","line_uuid":"11111111-1111-4111-8111-111111111111","chain":{"downstream_line_uuid":"11111111-1111-4111-8111-111111111111"}}]}`},
		{"local cycle", `{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"a","line_uuid":"11111111-1111-4111-8111-111111111111","chain":{"downstream_line_uuid":"22222222-2222-4222-8222-222222222222"}},{"tag":"b","line_uuid":"22222222-2222-4222-8222-222222222222","chain":{"downstream_line_uuid":"11111111-1111-4111-8111-111111111111"}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs []string
			src := Source{
				MetaPath:     "/meta.json",
				runner:       listOnlyRunner(t, sidecarTestList),
				runtimeFiles: func() []string { return nil },
				// Answer per path: this case is about the sidecar, and most
				// nodes have no endpoints file at all.
				readFile: func(path string) ([]byte, error) {
					if path == "/meta.json" {
						return []byte(tc.raw), nil
					}
					return nil, os.ErrNotExist
				},
				Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
			}
			inv, err := Discover(context.Background(), src, "node-invalid")
			if err != nil || inv.Nodes[0].LineUUID != "" || inv.Nodes[0].DownstreamLineUUID != "" {
				t.Fatalf("invalid v2 must be rejected as a whole: inv=%+v err=%v", inv, err)
			}
			if len(logs) != 1 || !strings.Contains(logs[0], "invalid") {
				t.Fatalf("invalid v2 must be surfaced once, got %v", logs)
			}
		})
	}
}

func TestDiscoverSidecarV1Ignored(t *testing.T) {
	var logs []string
	src := Source{
		MetaPath:     "testdata/v1-legacy-upgrade.json",
		runner:       listOnlyRunner(t, sidecarTestList),
		runtimeFiles: func() []string { return nil },
		Logf:         func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	}
	inv, err := Discover(context.Background(), src, "node-v1")
	if err != nil {
		t.Fatalf("v1 sidecar must not fail discovery: %v", err)
	}
	// v1 is a flat per-node shape with no inbounds array: nothing to join.
	if inv.Nodes[0].LineUUID != "" || inv.Nodes[0].DownstreamLineUUID != "" {
		t.Fatalf("v1 sidecar carries no per-line data: %+v", inv.Nodes[0])
	}
	if len(logs) != 0 {
		t.Fatalf("v1 sidecar is an accepted legacy shape, not an error: %v", logs)
	}
}

func TestPrimaryPathEnrichesFromInspect(t *testing.T) {
	var inspectNames []string
	files := map[string]string{
		// inspect reports only the outbound tag/protocol; the config join below
		// resolves the tag to the downstream server:port.
		"/etc/sing-box/config.json": `{
			"inbounds":[],
			"outbounds":[{"tag":"[openjobs]-qqpw-vds1-vless","type":"vless","server":"198.51.100.9","server_port":443}]
		}`,
	}
	src := Source{
		Addr: "203.0.113.5",
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			last := args[len(args)-1]
			switch last {
			case "list":
				return []byte(`{"ok":true,"count":1,"nodes":[{"name":"VLESS-31001.json","protocol":"vless","port":"31001"}]}`), nil
			case "provision":
				return []byte(`{}`), nil
			}
			if len(args) >= 2 && args[len(args)-2] == "inspect" {
				inspectNames = append(inspectNames, last)
				// Shape per core.sh line_json_obj.
				return []byte(`{"ok":true,"line":{
					"core":"sing-box",
					"tag":"VLESS-31001.json",
					"type":"vless",
					"listen_host":"::",
					"listen_port":31001,
					"users":[{"name":"u_0123456789abcdef","uuid":"redacted"},{"name":"u_fedcba9876543210","uuid":"redacted"}],
					"outbound":{"tag":"[openjobs]-qqpw-vds1-vless","protocol":"vless"},
					"metadata":{"line_id":"line-uuid-a","node_uuid":"node-uuid-a"}
				}}`), nil
			}
			return nil, errors.New("unexpected command: " + strings.Join(args, " "))
		},
		runtimeFiles: func() []string { return []string{"/etc/sing-box/config.json"} },
		readFile:     func(path string) ([]byte, error) { return []byte(files[path]), nil },
	}
	inv, err := Discover(context.Background(), src, "node-inspect")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(inv.Nodes) != 1 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
	n := inv.Nodes[0]
	if n.OutboundRef != "[openjobs]-qqpw-vds1-vless" || n.OutboundType != "vless" {
		t.Fatalf("inspect outbound enrichment wrong: %+v", n)
	}
	if n.OutboundServer != "198.51.100.9" || n.OutboundPort != "443" {
		t.Fatalf("config join must resolve the server/port inspect omits: %+v", n)
	}
	if n.LineID != "line-uuid-a" || n.NodeIdentityUUID != "node-uuid-a" {
		t.Fatalf("inspect identity enrichment wrong: %+v", n)
	}
	if n.ListenHost != "::" || !n.UserKnown || n.UserCount != 2 {
		t.Fatalf("inspect listen/user enrichment wrong: %+v", n)
	}
	if len(inspectNames) != 1 || inspectNames[0] != "VLESS-31001.json" {
		t.Fatalf("inspect must be called once per bare line by name, got %v", inspectNames)
	}
}

func TestInspectUnavailableFallsBackToConfig(t *testing.T) {
	var logs []string
	var inspectCalls atomic.Int32
	files := map[string]string{
		"/etc/sing-box/config.json": `{
			"inbounds":[{"tag":"Trojan-41001.json","type":"trojan","listen":"::","listen_port":41001,"_lattice":{"line_id":"line-uuid-a"}}],
			"outbounds":[{"tag":"exit-hk","type":"trojan","server":"198.51.100.9","server_port":8443}],
			"route":{"rules":[{"inbound":["Trojan-41001.json"],"action":"route","outbound":"exit-hk"}]}
		}`,
	}
	src := Source{
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch args[len(args)-1] {
			case "list":
				return []byte(`{"ok":true,"count":1,"nodes":[{"name":"Trojan-41001.json","protocol":"trojan","port":"41001"}]}`), nil
			case "provision":
				return []byte(`{}`), nil
			}
			inspectCalls.Add(1)
			return nil, errors.New("sb: unknown command inspect") // old sb build
		},
		runtimeFiles: func() []string { return []string{"/etc/sing-box/config.json"} },
		readFile:     func(path string) ([]byte, error) { return []byte(files[path]), nil },
		Logf:         func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	}
	inv, err := Discover(context.Background(), src, "node-oldsb")
	if err != nil {
		t.Fatalf("old sb without inspect must not fail discovery: %v", err)
	}
	n := inv.Nodes[0]
	if n.OutboundRef != "exit-hk" || n.OutboundServer != "198.51.100.9" || n.LineID != "line-uuid-a" {
		t.Fatalf("config join must still enrich when inspect is unavailable: %+v", n)
	}
	if inspectCalls.Load() != 1 {
		t.Fatalf("first inspect failure must stop further inspect calls, got %d", inspectCalls.Load())
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "inspect unavailable") {
		t.Fatalf("inspect degradation must be logged once, got %v", logs)
	}
}

func TestInspectBudgetTruncates(t *testing.T) {
	names := []string{"n1.json", "n2.json", "n3.json", "n4.json", "n5.json"}
	var rows []string
	for _, name := range names {
		rows = append(rows, fmt.Sprintf(`{"name":%q,"protocol":"vless","port":"31001"}`, name))
	}
	listJSON := `{"ok":true,"count":5,"nodes":[` + strings.Join(rows, ",") + `]}`
	var inspectCalls atomic.Int32
	src := Source{
		MaxInspect: 3,
		runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			last := args[len(args)-1]
			switch last {
			case "list":
				return []byte(listJSON), nil
			case "provision":
				return []byte(`{}`), nil
			}
			inspectCalls.Add(1)
			return []byte(`{"ok":true,"line":{"tag":"` + last + `","outbound":{"tag":"direct","protocol":"direct"}}}`), nil
		},
		runtimeFiles: func() []string { return nil },
	}
	inv, err := Discover(context.Background(), src, "node-fleet")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if inspectCalls.Load() != 3 {
		t.Fatalf("inspect calls must be bounded by MaxInspect=3, got %d", inspectCalls.Load())
	}
	for i, n := range inv.Nodes {
		enriched := n.OutboundRef == "direct"
		if (i < 3) != enriched {
			t.Fatalf("only the first 3 lines may be inspect-enriched: node %d %+v", i, n)
		}
	}
}

func TestInspectUsesAggregateDeadlineAndBoundedConcurrency(t *testing.T) {
	var rows []string
	for i := 0; i < 17; i++ {
		rows = append(rows, fmt.Sprintf(`{"name":"n%d.json","protocol":"vless","port":"31001"}`, i))
	}
	listJSON := `{"ok":true,"count":17,"nodes":[` + strings.Join(rows, ",") + `]}`
	var mu sync.Mutex
	active, peak := 0, 0
	src := Source{
		Timeout:    120 * time.Millisecond,
		MaxInspect: 17,
		runner: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			last := args[len(args)-1]
			switch last {
			case "list":
				return []byte(listJSON), nil
			case "provision":
				return []byte(`{}`), nil
			}
			mu.Lock()
			active++
			if active > peak {
				peak = active
			}
			mu.Unlock()
			defer func() {
				mu.Lock()
				active--
				mu.Unlock()
			}()
			select {
			case <-time.After(40 * time.Millisecond):
				return []byte(`{"ok":true,"line":{"outbound":{"tag":"direct"}}}`), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		runtimeFiles: func() []string { return nil },
	}
	started := time.Now()
	_, err := Discover(context.Background(), src, "node-deadline")
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if elapsed > 280*time.Millisecond {
		t.Fatalf("inspect aggregate deadline exceeded: %v", elapsed)
	}
	if peak < 2 || peak > maxInspectWorkers {
		t.Fatalf("inspect concurrency peak = %d, want 2..%d", peak, maxInspectWorkers)
	}
}

// TestApplyNodeEndpoints covers the node-owned endpoint declaration.
//
// A NAT node listens on one port while the world dials another, and nothing in
// its sing-box config says so: the mapping lives in the provider's router.
// Without this the inventory reports the listen port as though it were
// reachable, and a chain built on it dials a closed door.
func TestApplyNodeEndpoints(t *testing.T) {
	const doc = `{
	  "schema": "lattice.node-endpoints.v1",
	  "network": "nat",
	  "public_host": "jp.nat.example.org",
	  "inbounds": [
	    {"tag": "VLESS-REALITY-488.json", "listen_port": 488, "public_port": 50100},
	    {"tag": "Hysteria2-7890.json", "listen_port": 7890, "public_port": 50101,
	     "public_host": "alt.example.org"}
	  ]
	}`
	src := Source{
		EndpointsPath: "/etc/sing-box/lattice-endpoints.json",
		readFile:      func(string) ([]byte, error) { return []byte(doc), nil },
	}
	inv := model.SingBoxInventory{Nodes: []model.SingBoxNode{
		{Name: "VLESS-REALITY-488.json", Address: "203.0.113.1", Port: "488"},
		{Name: "Hysteria2-7890.json", Address: "203.0.113.1", Port: "7890"},
		{Name: "Unlisted.json", Address: "203.0.113.1", Port: "9000"},
	}}
	applyNodeEndpoints(src, &inv)

	if inv.Network != "nat" {
		t.Fatalf("network = %q, want nat", inv.Network)
	}
	if got := inv.Nodes[0].PublicPort; got != "50100" {
		t.Fatalf("public port = %q, want 50100", got)
	}
	if got := inv.Nodes[0].Address; got != "jp.nat.example.org" {
		t.Fatalf("address should fall back to the document host, got %q", got)
	}
	if got := inv.Nodes[1].Address; got != "alt.example.org" {
		t.Fatalf("a per-inbound host must win over the document host, got %q", got)
	}
	// An inbound the file does not mention keeps its listen port as public: most
	// nodes are reached where they listen, and silence is the right answer.
	if got := inv.Nodes[2].PublicPort; got != "" {
		t.Fatalf("unlisted inbound got a public port: %q", got)
	}
	if got := inv.Nodes[2].Address; got != "jp.nat.example.org" {
		t.Fatalf("unlisted inbound should still take the node-wide host, got %q", got)
	}
}

// TestApplyNodeEndpointsIgnoresJunk pins the failure modes: a node without the
// file is the common case and must not be treated as an error, and a document
// this agent does not understand must not be half-applied.
func TestApplyNodeEndpointsIgnoresJunk(t *testing.T) {
	base := func() model.SingBoxInventory {
		return model.SingBoxInventory{Nodes: []model.SingBoxNode{
			{Name: "a.json", Address: "203.0.113.1", Port: "80"},
		}}
	}
	for _, tc := range []struct{ name, body string }{
		{"wrong schema", `{"schema":"something.else.v9","network":"nat","public_host":"x.example.org"}`},
		{"not json", `{`},
		{"empty", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := base()
			applyNodeEndpoints(Source{
				readFile: func(string) ([]byte, error) { return []byte(tc.body), nil },
				Logf:     func(string, ...any) {},
			}, &inv)
			if inv.Network != "" || inv.Nodes[0].Address != "203.0.113.1" || inv.Nodes[0].PublicPort != "" {
				t.Fatalf("junk was applied: network=%q addr=%q port=%q",
					inv.Network, inv.Nodes[0].Address, inv.Nodes[0].PublicPort)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		inv := base()
		applyNodeEndpoints(Source{EndpointsPath: "/nonexistent/lattice-endpoints.json"}, &inv)
		if inv.Nodes[0].Address != "203.0.113.1" {
			t.Fatalf("a missing file changed the inventory: %q", inv.Nodes[0].Address)
		}
	})
	t.Run("out of range port", func(t *testing.T) {
		inv := base()
		applyNodeEndpoints(Source{
			readFile: func(string) ([]byte, error) {
				return []byte(`{"schema":"lattice.node-endpoints.v1","inbounds":[{"tag":"a.json","public_port":70000}]}`), nil
			},
		}, &inv)
		if inv.Nodes[0].PublicPort != "" {
			t.Fatalf("an impossible port was accepted: %q", inv.Nodes[0].PublicPort)
		}
	})
}

// TestDiscoverAppliesNodeEndpoints proves the reader is actually wired into
// Discover, not merely present. A correct function nobody calls is the failure
// this pins: the inventory would keep reporting listen ports as public and
// nothing would look wrong until a chain failed to connect.
func TestDiscoverAppliesNodeEndpoints(t *testing.T) {
	const endpoints = `{"schema":"lattice.node-endpoints.v1","network":"nat",
	  "public_host":"nat.example.org",
	  "inbounds":[{"tag":"vless-31001","listen_port":31001,"public_port":40001}]}`
	src := Source{
		MetaPath:      "/meta.json",
		EndpointsPath: "/endpoints.json",
		runner:        listOnlyRunner(t, sidecarTestList),
		runtimeFiles:  func() []string { return nil },
		readFile: func(path string) ([]byte, error) {
			if path == "/endpoints.json" {
				return []byte(endpoints), nil
			}
			return nil, os.ErrNotExist
		},
		Logf: func(string, ...any) {},
	}
	inv, err := Discover(context.Background(), src, "node-endpoints")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Network != "nat" {
		t.Fatalf("Discover did not apply the network type: %q", inv.Network)
	}
	var found bool
	for _, n := range inv.Nodes {
		if n.Name == "vless-31001" {
			found = true
			if n.PublicPort != "40001" {
				t.Fatalf("Discover did not apply the public port: %q", n.PublicPort)
			}
			if n.Address != "nat.example.org" {
				t.Fatalf("Discover did not apply the public host: %q", n.Address)
			}
		}
	}
	if !found {
		t.Fatal("test fixture no longer contains vless-31001")
	}
}
