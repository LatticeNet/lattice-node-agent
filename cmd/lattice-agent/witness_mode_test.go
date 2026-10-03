package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/witness"
)

// The heartbeat relays the witness status file and nothing else: a node with
// no witness sends no field, a broken file sends no field, and a valid file is
// re-encoded from its typed form so a field the witness does not define never
// leaves the node.
func TestHeartbeatRelaysTheWitnessStatusFile(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	t.Setenv(witnessStatusEnv, statusPath)

	beat := newHeartbeat(agentConfig{NodeID: "node-a", Interval: time.Second}, newLoopHealth(nil))
	var payloads []map[string]any
	beat.post = func(_ context.Context, _ agentConfig, payload map[string]any) error {
		payloads = append(payloads, payload)
		return nil
	}

	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := payloads[0]["witness"]; ok {
		t.Fatal("a node without a witness status file sent a witness field")
	}

	if err := os.WriteFile(statusPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := payloads[1]["witness"]; ok {
		t.Fatal("a corrupt witness status file was relayed")
	}

	checked := time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)
	doc := map[string]any{
		"version": witness.StateVersion, "config_sha256": "abc", "phase": witness.PhaseWatching,
		"health_url": "https://lattice.example.org/readyz", "last_check_at": checked, "last_check_ok": true,
		"device_key": "MUST-NOT-LEAVE", "extra": "dropped",
	}
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(statusPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := beat.once(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := payloads[2]["witness"].(*witness.State)
	if !ok || got == nil {
		t.Fatalf("witness field = %#v", payloads[2]["witness"])
	}
	if got.Phase != witness.PhaseWatching || !got.LastCheckAt.Equal(checked) || got.ConfigSHA256 != "abc" {
		t.Fatalf("relayed status = %+v", got)
	}
	wire, _ := json.Marshal(payloads[2])
	for _, leak := range []string{"MUST-NOT-LEAVE", "device_key", "extra"} {
		if strings.Contains(string(wire), leak) {
			t.Fatalf("heartbeat carried %q: %s", leak, wire)
		}
	}
}

func TestWitnessStatusRelayRefusesAnOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	big := `{"version":1,"phase":"watching","last_check_detail":"` + strings.Repeat("x", maxWitnessStatusBytes) + `"}`
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := readWitnessStatus(path); st != nil {
		t.Fatalf("oversized status relayed: phase %q", st.Phase)
	}
}

// -witness-check is what the apply script runs before it enables the unit. It
// must refuse a key file others can read, and its summary must never carry
// the key.
func TestWitnessCheckValidatesWithoutPrintingTheKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bark-device-key")
	const key = "SecretDeviceKey42"
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o644); err != nil { // #nosec G306 -- readable on purpose, to see it refused
		t.Fatal(err)
	}
	cfg := witness.Config{
		Version:           witness.ConfigVersion,
		NodeName:          "[cd]-gomami-jpn-pulse-nano",
		HealthURL:         "https://lattice.example.org/readyz",
		ReferenceURLs:     []string{"https://www.cloudflare.com/cdn-cgi/trace"},
		BarkURL:           "http://127.0.0.1:8080",
		BarkDeviceKeyFile: keyFile,
		StateFile:         filepath.Join(dir, "status.json"),
	}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "witness.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runWitnessMode(cfgPath, true, &out); err == nil {
		t.Fatal("a world-readable key file passed the check")
	} else if strings.Contains(err.Error(), key) {
		t.Fatalf("check error carried the key: %v", err)
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runWitnessMode(cfgPath, true, &out); err != nil {
		t.Fatalf("check: %v", err)
	}
	summary := out.String()
	if !strings.HasPrefix(summary, "witness config ok: sha256=") || !strings.Contains(summary, "key_file="+keyFile) {
		t.Fatalf("summary = %q", summary)
	}
	if strings.Contains(summary, key) {
		t.Fatalf("summary printed the key: %q", summary)
	}
	if _, err := os.Stat(cfg.StateFile); err == nil {
		t.Fatal("the check wrote a state file; it must only validate")
	}
	if err := runWitnessMode("", true, &out); err == nil {
		t.Fatal("an empty config path was accepted")
	}
}

// Witness mode is a property of the binary, so the capability is reported
// whether or not linechain recovery is ready, and -compat-json lists it for
// the apply script that copies this binary.
func TestWitnessCapabilityIsAlwaysAdvertised(t *testing.T) {
	for _, ready := range []bool{true, false} {
		found := false
		for _, c := range capabilitiesFor(ready) {
			found = found || c == witness.Capability
		}
		if !found {
			t.Fatalf("capabilitiesFor(%v) lacks %s", ready, witness.Capability)
		}
	}
	data, err := json.Marshal(compatibilityPayload())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"`+witness.Capability+`"`) {
		t.Fatalf("-compat-json %s lacks %s", data, witness.Capability)
	}
}
