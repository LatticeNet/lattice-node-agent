package hostfacts

import (
	"runtime"
	"testing"
)

func TestCollectHasBaselineRuntimeFacts(t *testing.T) {
	facts := Collect()
	if facts.OS != runtime.GOOS {
		t.Fatalf("OS=%q want %q", facts.OS, runtime.GOOS)
	}
	if facts.Arch != runtime.GOARCH {
		t.Fatalf("Arch=%q want %q", facts.Arch, runtime.GOARCH)
	}
	if facts.CPUCores <= 0 {
		t.Fatalf("CPUCores=%d, want positive", facts.CPUCores)
	}
	if facts.ReportedAt.IsZero() {
		t.Fatal("ReportedAt must be set")
	}
}

func TestParseOSRelease(t *testing.T) {
	platform, version := parseOSRelease(`
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
`)
	if platform != "debian" || version != "12" {
		t.Fatalf("parseOSRelease = %q %q", platform, version)
	}
}

func TestParseMeminfo(t *testing.T) {
	mem, swap := parseMeminfo("MemTotal:       2048 kB\nSwapTotal:       512 kB\n")
	if mem != 2048*1024 || swap != 512*1024 {
		t.Fatalf("parseMeminfo = mem=%d swap=%d", mem, swap)
	}
}

func TestFirstCPUModel(t *testing.T) {
	got := firstCPUModel("processor: 0\nmodel name\t: Example CPU 3.2GHz\n")
	if got != "Example CPU 3.2GHz" {
		t.Fatalf("firstCPUModel=%q", got)
	}
}

func TestParseUptimeSeconds(t *testing.T) {
	if got := parseUptimeSeconds("123.45 678.90\n"); got != 123 {
		t.Fatalf("parseUptimeSeconds=%d", got)
	}
	if got := parseUptimeSeconds("bad"); got != 0 {
		t.Fatalf("bad uptime should return 0, got %d", got)
	}
}
