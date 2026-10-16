package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-node-agent/internal/prober"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Installers and the server read -compat-json; a binary that runs the M2a
// probe rules and reports probe methods says so there.
func TestCompatJSONListsProbeMethods(t *testing.T) {
	data, err := json.Marshal(compatibilityPayload())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"`+prober.Capability+`"`) {
		t.Fatalf("-compat-json %s lacks %s", data, prober.Capability)
	}
	if prober.Capability != "probe-methods-v1" {
		t.Fatalf("feature name changed to %q; installers and the server match it literally", prober.Capability)
	}
}

// Hello and every heartbeat carry probe_methods and probe_refusals as
// top-level keys, beside capabilities (design 29 D11).
func TestHelloAndHeartbeatCarryProbeFacts(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"hello":     helloPayload(agentConfig{NodeID: "n1"}),
		"heartbeat": metricsPayload(agentConfig{NodeID: "n1"}),
	} {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			ProbeMethods  []string          `json:"probe_methods"`
			ProbeRefusals map[string]string `json:"probe_refusals"`
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeHTTP} {
			if !slices.Contains(got.ProbeMethods, kind) {
				t.Fatalf("%s probe_methods %v lacks %s", name, got.ProbeMethods, kind)
			}
		}
		_, refused := got.ProbeRefusals[model.MonitorTypeICMP]
		if slices.Contains(got.ProbeMethods, model.MonitorTypeICMP) == refused {
			t.Fatalf("%s: icmp must be in exactly one of %v and %v", name, got.ProbeMethods, got.ProbeRefusals)
		}
		if got.ProbeRefusals == nil {
			t.Fatalf("%s: probe_refusals is sent as an object, even when empty: %s", name, data)
		}
	}
}

// A change to any field the probe reads restarts the monitor's goroutine;
// a change only the control plane reads does not.
func TestMonitorChangedCoversProbeFields(t *testing.T) {
	base := model.Monitor{ID: "m", Type: model.MonitorTypeHTTP, Target: "https://a.example/", IntervalSec: 30, TimeoutSec: 5,
		Headers: []model.MonitorHeader{{Name: "X-Api-Key", Value: "one", Secret: true}}, SecretsOrigin: "https://a.example:443"}
	for name, edit := range map[string]func(*model.Monitor){
		"target_node":   func(m *model.Monitor) { m.TargetNode = "n2" },
		"packets":       func(m *model.Monitor) { m.Packets = 3 },
		"expect_status": func(m *model.Monitor) { m.ExpectStatus = "200" },
		"header value": func(m *model.Monitor) {
			m.Headers = []model.MonitorHeader{{Name: "X-Api-Key", Value: "two", Secret: true}}
		},
		"header removed": func(m *model.Monitor) { m.Headers = nil },
		"secrets_origin": func(m *model.Monitor) { m.SecretsOrigin = "https://b.example:443" },
	} {
		changed := base
		changed.Headers = slices.Clone(base.Headers)
		edit(&changed)
		if !monitorChanged(base, changed) {
			t.Fatalf("%s change does not restart the probe", name)
		}
	}
	renamed := base
	renamed.Name, renamed.Version, renamed.AlertAfter = "renamed", 7, 4
	if monitorChanged(base, renamed) {
		t.Fatal("a control-plane-only change restarted the probe")
	}
}
