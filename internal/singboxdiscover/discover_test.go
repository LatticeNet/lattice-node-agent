package singboxdiscover

import (
	"context"
	"errors"
	"strings"
	"testing"

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
