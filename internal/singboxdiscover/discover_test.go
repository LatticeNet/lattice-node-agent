package singboxdiscover

import (
	"context"
	"errors"
	"strings"
	"testing"
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

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
