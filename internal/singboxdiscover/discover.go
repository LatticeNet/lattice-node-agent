// Package singboxdiscover reads the on-box sing-box management state by invoking
// the 233boy `sb --json` interface (read-only: `list` + `provision`). It is the
// agent half of the Lattice adoption bridge — it lets the control plane SEE the
// proxies that already exist on a machine provisioned out-of-band, without
// taking over or modifying them. Every call is read-only; this source never adds,
// deletes, or rewrites a node, so it is safe to run continuously and is NOT gated
// behind the agent's general task-execution permission.
package singboxdiscover

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	defaultBinary  = "sb"
	defaultTimeout = 8 * time.Second
	maxOutputBytes = 1 << 20 // 1 MiB
)

// Source configures on-box sing-box discovery.
type Source struct {
	// Binary is the sb command (bare name on PATH or absolute path); default "sb".
	Binary string
	// Addr is the node's public address, passed as `--addr` so the rendered
	// share_url uses the right host without the script attempting IP autodetect
	// (which could block on a TTY). Optional but recommended.
	Addr string
	// Timeout bounds each sb invocation; default 8s.
	Timeout time.Duration
	// Now is a test seam.
	Now func() time.Time
	// runner is a test seam; production uses runBoundedCommand.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Discover runs `sb --json list` (and `sb --json provision` for the core
// version/health) and returns a populated inventory. A discovery failure returns
// an inventory with Status=error + Error set (and a nil node list) rather than a
// bare error, so the server can show "discovery failed" instead of a stale list.
func Discover(ctx context.Context, source Source, nodeID string) (model.SingBoxInventory, error) {
	binary := strings.TrimSpace(source.Binary)
	if binary == "" {
		binary = defaultBinary
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	at := now(source.Now)
	run := source.runner
	if run == nil {
		run = runBoundedCommand
	}

	// Common args: --addr (if set) keeps the script non-interactive, --json
	// selects machine output. Passed as an arg-vector (no shell).
	base := []string{}
	if addr := strings.TrimSpace(source.Addr); addr != "" {
		base = append(base, "--addr", addr)
	}
	base = append(base, "--json")

	inv := model.SingBoxInventory{NodeID: nodeID, At: at, Status: "ok", Nodes: []model.SingBoxNode{}}

	listCtx, cancel := context.WithTimeout(ctx, timeout)
	out, err := run(listCtx, binary, append(append([]string(nil), base...), "list")...)
	cancel()
	if err != nil {
		inv.Status = "error"
		inv.Error = boundedErr(err)
		return inv, err
	}
	var listResp struct {
		OK    bool                `json:"ok"`
		Count int                 `json:"count"`
		Nodes []model.SingBoxNode `json:"nodes"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &listResp); err != nil {
		inv.Status = "error"
		inv.Error = "decode list: " + boundedErr(err)
		return inv, fmt.Errorf("decode sb list: %w", err)
	}
	if listResp.Nodes != nil {
		inv.Nodes = listResp.Nodes
	}

	// Best-effort core version/health; a failure here must not fail discovery.
	provCtx, cancel2 := context.WithTimeout(ctx, timeout)
	provOut, provErr := run(provCtx, binary, append(append([]string(nil), base...), "provision")...)
	cancel2()
	if provErr == nil {
		var prov struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(bytes.TrimSpace(provOut), &prov) == nil {
			inv.CoreVersion = strings.TrimSpace(prov.Version)
		}
	}
	return inv, nil
}

func runBoundedCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, truncate(msg, 512))
		}
		return nil, err
	}
	if stdout.Len() > maxOutputBytes {
		return nil, fmt.Errorf("sb output exceeds %d bytes", maxOutputBytes)
	}
	return stdout.Bytes(), nil
}

func now(fn func() time.Time) time.Time {
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

func boundedErr(err error) string {
	if err == nil {
		return ""
	}
	return truncate(err.Error(), 512)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
