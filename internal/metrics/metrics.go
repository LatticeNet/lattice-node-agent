package metrics

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// cpuSampler holds the previous /proc/stat aggregate so each Collect call can
// compute CPU utilization over the real interval between calls, without
// blocking inside Collect. The first call returns 0 (no prior sample).
var cpuSampler struct {
	sync.Mutex
	prevTotal uint64
	prevIdle  uint64
	hasPrev   bool
}

func Collect() model.Metrics {
	now := time.Now().UTC()
	m := model.Metrics{CollectedAt: now}
	m.Load1 = readLoad1()
	m.MemoryUsed, m.MemoryTotal = readMemory()
	m.DiskUsed, m.DiskTotal = readDisk("/")
	m.NetRxBytes, m.NetTxBytes = readNetDev()
	m.UptimeSeconds = readUptime()
	m.CPUPercent = readCPUPercent(m.Load1, runtime.NumCPU())
	return m
}

// readCPUPercent computes busy CPU percentage from the delta of /proc/stat
// since the previous call. The first call falls back to load-average per core
// so newly enrolled nodes show CPU telemetry before the second metrics cycle.
func readCPUPercent(load1 float64, cpuCount int) float64 {
	total, idle, ok := readProcStat()
	if !ok {
		return cpuLoadFallback(load1, cpuCount)
	}
	cpuSampler.Lock()
	defer cpuSampler.Unlock()
	defer func() {
		cpuSampler.prevTotal = total
		cpuSampler.prevIdle = idle
		cpuSampler.hasPrev = true
	}()
	if !cpuSampler.hasPrev {
		return cpuLoadFallback(load1, cpuCount)
	}
	return cpuBusy(cpuSampler.prevTotal, cpuSampler.prevIdle, total, idle)
}

func cpuLoadFallback(load1 float64, cpuCount int) float64 {
	if load1 <= 0 || cpuCount <= 0 {
		return 0
	}
	return clampPercent(load1 / float64(cpuCount) * 100)
}

// cpuBusy computes the busy percentage between two /proc/stat snapshots. Pure
// and side-effect free so it can be unit tested without /proc.
func cpuBusy(prevTotal, prevIdle, total, idle uint64) float64 {
	totalDelta := float64(total - prevTotal)
	idleDelta := float64(idle - prevIdle)
	if totalDelta <= 0 {
		return 0
	}
	return clampPercent((totalDelta - idleDelta) / totalDelta * 100)
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// readProcStat parses the aggregate "cpu" line of /proc/stat into total jiffies
// and idle jiffies (idle + iowait).
func readProcStat() (total, idle uint64, ok bool) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var sum uint64
		for i, f := range fields {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				continue
			}
			sum += v
			// Fields 3 (idle) and 4 (iowait) count as idle time.
			if i == 3 || i == 4 {
				idle += v
			}
		}
		return sum, idle, true
	}
	return 0, 0, false
}

func readLoad1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

func readMemory() (used, total uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.Alloc, ms.Sys
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		values[key] = v * 1024
	}
	total = values["MemTotal"]
	available := values["MemAvailable"]
	if total > available {
		used = total - available
	}
	return used, total
}

func readDisk(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total > free {
		used = total - free
	}
	return used, total
}

func readNetDev() (rx, tx uint64) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx
}

func readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return uint64(v)
}
