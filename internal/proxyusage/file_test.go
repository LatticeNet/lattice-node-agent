package proxyusage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestLoadFileNormalizesNodeAndDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte(`{"core_uptime_sec":12,"user_bytes":{"alice":123}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadFile(path, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != "node-a" || snapshot.CoreUptimeSec != 12 || snapshot.UserBytes["alice"] != 123 || snapshot.At.IsZero() {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestLoadFileCarriesTrafficMaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	body := `{"user_bytes":{"u_a":30},"inbound_traffic":{"vless":{"uplink":10,"downlink":20}},"user_traffic":{"u_a":{"uplink":10,"downlink":20}},"outbound_traffic":{"direct":{"uplink":1,"downlink":2}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadFile(path, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UserBytes["u_a"] != 30 ||
		snapshot.InboundTraffic["vless"] != (model.ProxyTrafficCounter{Uplink: 10, Downlink: 20}) ||
		snapshot.UserTraffic["u_a"] != (model.ProxyTrafficCounter{Uplink: 10, Downlink: 20}) ||
		snapshot.OutboundTraffic["direct"] != (model.ProxyTrafficCounter{Uplink: 1, Downlink: 2}) {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestLoadFileRejectsNegativeCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte(`{"user_bytes":{"alice":-1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, "node-a"); err == nil {
		t.Fatal("expected negative counter error")
	}
}

func TestLoadFileRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	data := make([]byte, maxUsageFileBytes+1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, "node-a"); err == nil {
		t.Fatal("expected oversized file error")
	}
}
