package metrics

import "testing"

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

func TestCollectDoesNotPanic(t *testing.T) {
	m := Collect()
	if m.CPUPercent < 0 || m.CPUPercent > 100 {
		t.Fatalf("cpu percent out of range: %v", m.CPUPercent)
	}
}
