package hostfacts

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Collect returns slow-changing, advisory machine facts. Collection is
// best-effort: unreadable platform files leave fields empty rather than failing
// the agent's metrics loop.
func Collect() model.HostFacts {
	now := time.Now().UTC()
	facts := model.HostFacts{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CPUCores:   runtime.NumCPU(),
		ReportedAt: now,
	}
	if hostname, err := os.Hostname(); err == nil {
		facts.Hostname = hostname
	}
	facts.Platform, facts.PlatformVersion = parseOSRelease(readFile("/etc/os-release"))
	facts.KernelVersion = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	facts.CPUModel = firstCPUModel(readFile("/proc/cpuinfo"))
	facts.MemoryTotal, facts.SwapTotal = parseMeminfo(readFile("/proc/meminfo"))
	if up := parseUptimeSeconds(readFile("/proc/uptime")); up > 0 {
		facts.BootTime = now.Add(-time.Duration(up) * time.Second)
	}
	facts.Virtualization = detectVirtualization()
	return facts
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func parseOSRelease(data string) (platform, version string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		switch key {
		case "ID":
			platform = value
		case "VERSION_ID":
			version = value
		}
	}
	return platform, version
}

func parseMeminfo(data string) (memTotal, swapTotal uint64) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		bytes := value * 1024
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			memTotal = bytes
		case "SwapTotal":
			swapTotal = bytes
		}
	}
	return memTotal, swapTotal
}

func firstCPUModel(data string) string {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "model name" || key == "Hardware" || key == "Processor" {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func parseUptimeSeconds(data string) uint64 {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return uint64(seconds)
}

func detectVirtualization() string {
	if env := strings.TrimSpace(os.Getenv("container")); env != "" {
		return env
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "container"
	}
	cgroups := readFile("/proc/1/cgroup")
	for _, marker := range []string{"docker", "kubepods", "containerd", "lxc"} {
		if strings.Contains(cgroups, marker) {
			return marker
		}
	}
	cpuinfo := readFile("/proc/cpuinfo")
	if strings.Contains(cpuinfo, "hypervisor") {
		return "vm"
	}
	return "unknown"
}
