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
			startupIPMode:      "auto",
			startupIPResolvers: "https://startup.example",
			startupStaticPubV4: "",
			startupStaticPubV6: "",
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

	// nil clears the override -> revert to startup flags.
	applyIPConfigOverride(cfg, nil)
	if cfg.IPMode != "auto" || cfg.staticPublicIP != "" || cfg.IPResolvers != "https://startup.example" {
		t.Fatalf("nil did not revert to startup: %+v", cfg)
	}

	// An empty mode is also a clear.
	cfg2 := newCfg()
	applyIPConfigOverride(cfg2, &model.NodeIPConfig{Mode: ""})
	if cfg2.IPMode != "auto" {
		t.Fatalf("empty mode should revert, got %q", cfg2.IPMode)
	}
}
