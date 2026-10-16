package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-node-agent/internal/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// -compat-json lists the beacon feature; installers and the server match
// the name literally.
func TestCompatJSONListsBeacon(t *testing.T) {
	data, err := json.Marshal(compatibilityPayload())
	if err != nil {
		t.Fatal(err)
	}
	if beacon.Capability != "beacon-v1" || !strings.Contains(string(data), `"beacon-v1"`) {
		t.Fatalf("-compat-json %s lacks beacon-v1", data)
	}
}

// Hello and every heartbeat carry the top-level "beacon" facts, and beacon
// is in probe_methods whether or not the node vetoes the responder, since
// the client only sends.
func TestHelloAndHeartbeatCarryBeaconFacts(t *testing.T) {
	for _, noBeacon := range []bool{false, true} {
		cfg := agentConfig{NodeID: "n1", NoBeacon: noBeacon, Beacon: beacon.NewNode(noBeacon)}
		for name, body := range map[string]map[string]any{
			"hello":     helloPayload(cfg),
			"heartbeat": metricsPayload(cfg),
			"bare":      helloPayload(agentConfig{NodeID: "n1", NoBeacon: noBeacon}),
		} {
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				ProbeMethods []string           `json:"probe_methods"`
				Beacon       *model.BeaconFacts `json:"beacon"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(got.ProbeMethods, model.MonitorTypeBeacon) || !slices.IsSorted(got.ProbeMethods) {
				t.Fatalf("%s (no-beacon %v): probe_methods %v", name, noBeacon, got.ProbeMethods)
			}
			want := model.BeaconFacts{Responder: true, State: model.BeaconAgentOff}
			if noBeacon {
				want = model.BeaconFacts{Responder: true, Refusal: model.PathReasonRefusedByNode, State: model.BeaconAgentRefused}
			}
			if got.Beacon == nil || *got.Beacon != want {
				t.Fatalf("%s (no-beacon %v): beacon %+v, want %+v", name, noBeacon, got.Beacon, want)
			}
		}
	}
}

// A beacon check goes to the node's beacon client, never to the prober,
// which would call it agent_too_old.
func TestBeaconChecksRunOnTheBeaconClient(t *testing.T) {
	m := model.Monitor{ID: "mon_latb_t1", Type: model.MonitorTypeBeacon, Target: "192.0.2.20:45000", TargetNode: "t1", Packets: 3, TimeoutSec: 1}
	res := runProbe(context.Background(), beacon.NewNode(true), m)
	if res.Reason != model.PathReasonBeaconNoKey || res.Sent != 0 {
		t.Fatalf("result %+v", res)
	}
	if got, want := monitorRunBudget(m), beacon.RunBudget(m); got != want {
		t.Fatalf("budget %v, want %v", got, want)
	}
}

// The config pull hands the keys to the node beacon, which wipes the
// decoded copy; no log line, debug line, debug sink entry or report body
// carries them, debug on or off.
func TestBeaconKeysStayOutOfLogsDebugAndReports(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xc0 + i)
	}
	pull := fmt.Sprintf(`{"debug":{"enabled":true,"collect":true},"beacon":{"source_id":3,"keys":[{"target_node":"t1","epoch":7,"key":%q}],"responder":{"bind":"192.0.2.1","port":45000,"limits":{"source_rate_per_second":20,"min_interval_sec":10,"packets_per_second_max":2},"table":[{"source_id":4,"epoch":7,"key":%q}]}}}`,
		base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(key))
	var remote model.AgentConfig
	if err := json.Unmarshal([]byte(pull), &remote); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)
	cfg := agentConfig{NodeID: "n1", LocalDebug: true, Debug: true, DebugSink: newDebugSink(100), Beacon: beacon.NewNode(false)}
	defer cfg.Beacon.Close()
	applyAgentConfig(&cfg, remote)
	debugf(cfg, "after config: %+v %v", cfg, cfg.Beacon)
	if f := cfg.Beacon.Facts(); f.State != model.BeaconAgentBindFailed && f.State != model.BeaconAgentListening {
		t.Fatalf("facts %+v", f)
	}
	var texts []string
	for _, body := range []map[string]any{helloPayload(cfg), metricsPayload(cfg)} {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, string(data))
	}
	texts = append(texts, logged.String(), strings.Join(cfg.DebugSink.drain(1000), "\n"), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg.Beacon))
	forms := []string{
		string(key), base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key[:12]),
		hex.EncodeToString(key[:12]), strings.Trim(fmt.Sprint(key[:12]), "[]"),
	}
	for i, text := range texts {
		for _, form := range forms {
			if strings.Contains(text, form) {
				t.Fatalf("text %d carries key material %q", i, form)
			}
		}
	}
	if !bytes.Equal(remote.Beacon.Keys[0].Key, make([]byte, 32)) || !bytes.Equal(remote.Beacon.Responder.Table[0].Key, make([]byte, 32)) {
		t.Fatal("the decoded pull still holds the keys")
	}
}
