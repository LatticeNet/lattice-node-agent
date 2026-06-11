// Package prober executes a single monitor probe (TCP connect or HTTP GET) and
// returns a timed result. ICMP is intentionally omitted in this version because
// it requires elevated privileges; TCP and HTTP cover the common reachability
// and latency checks without root.
package prober

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Probe runs the monitor once and returns a MonitorResult. It never blocks
// longer than the monitor's timeout.
func Probe(ctx context.Context, m model.Monitor) model.MonitorResult {
	timeout := time.Duration(m.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	res := model.MonitorResult{MonitorID: m.ID, At: time.Now().UTC()}
	start := time.Now()
	var err error
	switch m.Type {
	case model.MonitorTypeTCP:
		err = probeTCP(ctx, m.Target, timeout)
	case model.MonitorTypeHTTP:
		err = probeHTTP(ctx, m.Target, timeout)
	default:
		err = fmt.Errorf("unsupported monitor type %q", m.Type)
	}
	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		res.Success = false
		res.Error = err.Error()
	} else {
		res.Success = true
	}
	return res
}

func probeTCP(ctx context.Context, target string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

func probeHTTP(ctx context.Context, target string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	return nil
}
