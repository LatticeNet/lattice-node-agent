package metrics

import (
	"testing"
	"time"
)

func TestCPUBusy(t *testing.T) {
	cases := []struct {
		name           string
		pt, pi, tt, ti uint64
		want           float64
	}{
		{"half busy", 0, 0, 200, 100, 50},
		{"fully idle", 0, 0, 100, 100, 0},
		{"fully busy", 0, 0, 100, 0, 100},
		{"no progress", 100, 50, 100, 50, 0},
		{"counter reset guards", 500, 100, 100, 50, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cpuBusy(c.pt, c.pi, c.tt, c.ti); got != c.want {
				t.Fatalf("cpuBusy=%v want %v", got, c.want)
			}
		})
	}
}

func TestCPULoadFallback(t *testing.T) {
	cases := []struct {
		name     string
		load1    float64
		cpuCount int
		want     float64
	}{
		{"zero load", 0, 4, 0},
		{"single core half busy", 0.5, 1, 50},
		{"four cores", 1, 4, 25},
		{"clamps high load", 16, 4, 100},
		{"bad cpu count", 1, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cpuLoadFallback(c.load1, c.cpuCount); got != c.want {
				t.Fatalf("cpuLoadFallback=%v want %v", got, c.want)
			}
		})
	}
}

func TestNetRate(t *testing.T) {
	cases := []struct {
		name                   string
		prevRx, prevTx, rx, tx uint64
		elapsed                float64
		wantRx, wantTx         float64
	}{
		{"steady 1KB/2KB per s", 0, 0, 1000, 2000, 1, 1000, 2000},
		{"two second interval halves rate", 0, 0, 2000, 4000, 2, 1000, 2000},
		{"zero interval guards", 0, 0, 1000, 1000, 0, 0, 0},
		{"negative interval guards", 0, 0, 1000, 1000, -5, 0, 0},
		{"rx counter reset yields 0 rx", 5000, 0, 100, 2000, 1, 0, 2000},
		{"tx counter reset yields 0 tx", 0, 5000, 2000, 100, 1, 2000, 0},
		{"no traffic", 1000, 1000, 1000, 1000, 1, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotRx, gotTx := netRate(c.prevRx, c.prevTx, c.rx, c.tx, c.elapsed)
			if gotRx != c.wantRx || gotTx != c.wantTx {
				t.Fatalf("netRate=(%v,%v) want (%v,%v)", gotRx, gotTx, c.wantRx, c.wantTx)
			}
		})
	}
}

func TestNetSpeedFirstSampleIsZero(t *testing.T) {
	// A fresh process has no prior counter sample, so the first reading must be 0
	// rather than treating the whole cumulative counter as one interval's traffic.
	netSampler.Lock()
	netSampler.hasPrev = false
	netSampler.Unlock()
	rx, tx := netSpeed(123456, 654321, time.Now())
	if rx != 0 || tx != 0 {
		t.Fatalf("first netSpeed=(%v,%v) want (0,0)", rx, tx)
	}
}

func TestCollectDoesNotPanic(t *testing.T) {
	m := Collect()
	if m.CPUPercent < 0 || m.CPUPercent > 100 {
		t.Fatalf("cpu percent out of range: %v", m.CPUPercent)
	}
	if m.NetRxSpeed < 0 || m.NetTxSpeed < 0 {
		t.Fatalf("negative net speed: rx=%v tx=%v", m.NetRxSpeed, m.NetTxSpeed)
	}
	if m.Load1 < 0 || m.Load5 < 0 || m.Load15 < 0 {
		t.Fatalf("negative load: %v/%v/%v", m.Load1, m.Load5, m.Load15)
	}
}
