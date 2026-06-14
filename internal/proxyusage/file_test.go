package proxyusage

import (
	"os"
	"path/filepath"
	"testing"
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
