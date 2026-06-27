package main

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestApplyIPConfigOverride verifies a server-pushed NodeIPConfig overrides the
// startup IP flags and that clearing it (nil or empty mode) reverts cleanly.
func TestApplyIPConfigOverride(t *testing.T) {
	newCfg := func() *agentConfig {
		return &agentConfig{
			IPMode:             "auto",
			IPResolvers:        "https://startup.example",
			ipScript:           "echo 8.8.4.4",
			startupIPMode:      "auto",
			startupIPResolvers: "https://startup.example",
			startupStaticPubV4: "",
			startupStaticPubV6: "",
			startupIPScript:    "echo 8.8.4.4",
		}
	}

	cfg := newCfg()
	applyIPConfigOverride(cfg, &model.NodeIPConfig{
		Mode:       "static",
		StaticIPv4: "203.0.113.9",
		Resolvers:  []string{"https://a", "https://b"},
	})
	if cfg.IPMode != "static" || cfg.staticPublicIP != "203.0.113.9" {
		t.Fatalf("static override not applied: %+v", cfg)
	}
	if cfg.IPResolvers != "https://a,https://b" {
		t.Fatalf("resolvers not joined: %q", cfg.IPResolvers)
	}

	applyIPConfigOverride(cfg, &model.NodeIPConfig{
		Mode:   "script",
		Script: "#!/usr/bin/env bash\necho 8.8.8.8",
	})
	if cfg.IPMode != "script" || cfg.ipScript == "" {
		t.Fatalf("script override not applied: %+v", cfg)
	}
	if got := ipDiscoveryInterpreter(cfg.ipScript); got != "bash" {
		t.Fatalf("script interpreter = %q, want bash", got)
	}

	// nil clears the override -> revert to startup flags.
	applyIPConfigOverride(cfg, nil)
	if cfg.IPMode != "auto" || cfg.staticPublicIP != "" || cfg.IPResolvers != "https://startup.example" || cfg.ipScript != "echo 8.8.4.4" {
		t.Fatalf("nil did not revert to startup: %+v", cfg)
	}

	// An empty mode is also a clear.
	cfg2 := newCfg()
	applyIPConfigOverride(cfg2, &model.NodeIPConfig{Mode: ""})
	if cfg2.IPMode != "auto" {
		t.Fatalf("empty mode should revert, got %q", cfg2.IPMode)
	}
}

func TestParseIPDiscoveryOutput(t *testing.T) {
	v4, v6 := parseIPDiscoveryOutput("10.0.0.5\n8.8.8.8\n2606:4700:4700::1111\n")
	if v4 != "8.8.8.8" {
		t.Fatalf("v4 = %q, want 8.8.8.8", v4)
	}
	if v6 != "2606:4700:4700::1111" {
		t.Fatalf("v6 = %q, want 2606:4700:4700::1111", v6)
	}

	v4, v6 = parseIPDiscoveryOutput("127.0.0.1 192.168.1.2 fd00::1")
	if v4 != "" || v6 != "" {
		t.Fatalf("private/loopback output should be rejected, got v4=%q v6=%q", v4, v6)
	}

	v4, v6 = parseIPDiscoveryOutput("203.0.113.8 2001:db8::8")
	if v4 != "" || v6 != "" {
		t.Fatalf("reserved documentation ranges should be rejected, got v4=%q v6=%q", v4, v6)
	}
}
