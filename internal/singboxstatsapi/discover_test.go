package singboxstatsapi

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverAcceptsLoopbackListen(t *testing.T) {
	result, err := Discover([]string{fixture(t, "stats-off.json"), fixture(t, "stats-loopback.json")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Addr != "127.0.0.1:8080" || !strings.HasSuffix(result.Path, "stats-loopback.json") {
		t.Fatalf("result: %+v", result)
	}
}

func TestDiscoverRefusesNonLoopbackListen(t *testing.T) {
	result, err := Discover([]string{fixture(t, "stats-public.json"), fixture(t, "stats-loopback.json")})
	if err == nil || !strings.Contains(err.Error(), "loopback") || !strings.Contains(err.Error(), "stats-public.json") {
		t.Fatalf("non-loopback listen must be refused and name the file: %+v %v", result, err)
	}
	if result.Addr != "" {
		t.Fatalf("a refused listen must not yield an address: %+v", result)
	}
}

func TestDiscoverReportsNothingWhenStatsOff(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover([]string{missing, broken, fixture(t, "stats-off.json")})
	if err != nil || result != (Result{}) {
		t.Fatalf("stats off must be a clean miss: %+v %v", result, err)
	}
}

func TestDiscoverSkipsOversizedFile(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, make([]byte, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover([]string{big})
	if err != nil || result != (Result{}) {
		t.Fatalf("oversized file must be skipped: %+v %v", result, err)
	}
}

func TestConfigFilesWalksTrustedProcessArgsThenDefaults(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "single.json")
	confDir := filepath.Join(dir, "conf")
	defaultFile := filepath.Join(dir, "config.json")
	defaultDir := filepath.Join(dir, "conf.d")
	for _, p := range []string{confDir, defaultDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{single, filepath.Join(confDir, "b.json"), filepath.Join(confDir, "a.json"), filepath.Join(confDir, "notes.txt"), defaultFile, filepath.Join(defaultDir, "z.json")} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	processes := []singboxdiscover.TrustedProcess{
		{PID: 10, Args: []string{"/usr/local/bin/sing-box", "run", "-c", single, "-C", confDir}},
		// The same file named twice, once through the = form, appears once.
		{PID: 11, Args: []string{"/usr/local/bin/sing-box", "run", "--config=" + single, "-C=" + confDir}},
		// Relative and missing paths are dropped rather than resolved.
		{PID: 12, Args: []string{"/usr/local/bin/sing-box", "run", "-c", "relative.json", "-c", filepath.Join(dir, "missing.json")}},
	}
	got := configFiles(processes, defaultFile, defaultDir)
	want := []string{single, filepath.Join(confDir, "a.json"), filepath.Join(confDir, "b.json"), defaultFile, filepath.Join(defaultDir, "z.json")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config files:\n got %v\nwant %v", got, want)
	}
	if got := configFiles(nil, filepath.Join(dir, "absent.json"), filepath.Join(dir, "absent")); len(got) != 0 {
		t.Fatalf("no processes and no defaults must yield nothing: %v", got)
	}
}
