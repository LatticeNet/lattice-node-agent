package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/metrics"
	"github.com/LatticeNet/lattice-node-agent/internal/prober"
	"github.com/LatticeNet/lattice-node-agent/internal/sshwatch"
	"github.com/LatticeNet/lattice-node-agent/internal/taskexec"
	"github.com/LatticeNet/lattice-sdk/model"
)

const version = "0.1.0"

// httpClient bounds every agent request so a hung or black-holed server cannot
// wedge the agent's poll loop indefinitely. The total timeout comfortably
// exceeds task execution because task results are posted separately.
var httpClient = &http.Client{Timeout: 30 * time.Second}

type agentConfig struct {
	Server      string
	NodeID      string
	Token       string
	Interval    time.Duration
	AllowExec   bool
	PublicIP    string
	PublicIPv6  string
	WireGuardIP string
	WGPublicKey string
	WGEndpoint  string
	WGPort      int
	SSHAlerts   bool
}

func main() {
	var cfg agentConfig
	flag.StringVar(&cfg.Server, "server", env("LATTICE_SERVER", "http://127.0.0.1:8088"), "server base URL")
	flag.StringVar(&cfg.NodeID, "node-id", os.Getenv("LATTICE_NODE_ID"), "node id")
	flag.StringVar(&cfg.Token, "token", os.Getenv("LATTICE_NODE_TOKEN"), "node enrollment token")
	flag.DurationVar(&cfg.Interval, "interval", 10*time.Second, "metrics interval")
	flag.BoolVar(&cfg.AllowExec, "allow-exec", os.Getenv("LATTICE_AGENT_ALLOW_EXEC") == "1", "allow bounded task execution")
	flag.StringVar(&cfg.PublicIP, "public-ip", os.Getenv("LATTICE_PUBLIC_IP"), "public IPv4 metadata (server observes source IP if empty)")
	flag.StringVar(&cfg.PublicIPv6, "public-ip6", os.Getenv("LATTICE_PUBLIC_IP6"), "public IPv6 metadata")
	flag.StringVar(&cfg.WireGuardIP, "wg-ip", os.Getenv("LATTICE_WG_IP"), "WireGuard IP metadata")
	flag.BoolVar(&cfg.SSHAlerts, "ssh-alerts", os.Getenv("LATTICE_SSH_ALERTS") == "1", "report sshd accepted logins as events")
	flag.StringVar(&cfg.WGPublicKey, "wg-pubkey", os.Getenv("LATTICE_WG_PUBKEY"), "WireGuard public key (for mesh planning)")
	flag.StringVar(&cfg.WGEndpoint, "wg-endpoint", os.Getenv("LATTICE_WG_ENDPOINT"), "WireGuard public endpoint host:port (empty for dial-out-only nodes)")
	flag.IntVar(&cfg.WGPort, "wg-port", envInt("LATTICE_WG_PORT"), "WireGuard listen port")
	flag.Parse()
	if cfg.NodeID == "" || cfg.Token == "" {
		log.Fatal("node-id and token are required")
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if err := postJSON(cfg.Server+"/api/agent/hello", map[string]any{
		"node_id":              cfg.NodeID,
		"token":                cfg.Token,
		"version":              version,
		"public_ip":            cfg.PublicIP,
		"public_ipv6":          cfg.PublicIPv6,
		"wireguard_ip":         cfg.WireGuardIP,
		"wireguard_public_key": cfg.WGPublicKey,
		"wireguard_endpoint":   cfg.WGEndpoint,
		"wireguard_port":       cfg.WGPort,
	}, nil); err != nil {
		log.Fatalf("hello failed: %v", err)
	}
	log.Printf("lattice-agent connected node=%s server=%s allow_exec=%v", cfg.NodeID, cfg.Server, cfg.AllowExec)
	if cfg.SSHAlerts {
		go watchSSHLogins(context.Background(), cfg)
	}

	runner := taskexec.Runner{AllowExec: cfg.AllowExec}
	monitors := newMonitorManager(cfg)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		if err := reportMetrics(cfg); err != nil {
			log.Printf("metrics error: %v", err)
		}
		if err := runTasks(cfg, runner); err != nil {
			log.Printf("task poll error: %v", err)
		}
		if assigned, err := fetchMonitors(cfg); err != nil {
			log.Printf("monitor poll error: %v", err)
		} else {
			monitors.reconcile(assigned)
		}
		<-ticker.C
	}
}

// monitorManager keeps one goroutine per assigned monitor, each probing on its
// own interval. reconcile is called every poll to start new monitors, stop
// removed ones, and restart any whose definition changed.
type monitorManager struct {
	cfg    agentConfig
	mu     sync.Mutex
	active map[string]monitorEntry
}

type monitorEntry struct {
	cancel context.CancelFunc
	spec   model.Monitor
}

func newMonitorManager(cfg agentConfig) *monitorManager {
	return &monitorManager{cfg: cfg, active: map[string]monitorEntry{}}
}

func (mm *monitorManager) reconcile(monitors []model.Monitor) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	desired := make(map[string]model.Monitor, len(monitors))
	for _, m := range monitors {
		desired[m.ID] = m
	}
	for id, entry := range mm.active {
		if d, ok := desired[id]; !ok || monitorChanged(entry.spec, d) {
			entry.cancel()
			delete(mm.active, id)
		}
	}
	for id, m := range desired {
		if _, ok := mm.active[id]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		mm.active[id] = monitorEntry{cancel: cancel, spec: m}
		go mm.run(ctx, m)
	}
}

func (mm *monitorManager) run(ctx context.Context, m model.Monitor) {
	interval := time.Duration(m.IntervalSec) * time.Second
	if interval < time.Second {
		interval = 30 * time.Second
	}
	probeAndReport(mm.cfg, m)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeAndReport(mm.cfg, m)
		}
	}
}

func monitorChanged(a, b model.Monitor) bool {
	return a.Type != b.Type || a.Target != b.Target ||
		a.IntervalSec != b.IntervalSec || a.TimeoutSec != b.TimeoutSec
}

func probeAndReport(cfg agentConfig, m model.Monitor) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.TimeoutSec+2)*time.Second)
	defer cancel()
	res := prober.Probe(ctx, m)
	if err := postJSON(cfg.Server+"/api/agent/monitor-result", map[string]any{
		"node_id": cfg.NodeID,
		"token":   cfg.Token,
		"result":  res,
	}, nil); err != nil {
		log.Printf("monitor %s report error: %v", m.ID, err)
	}
}

func fetchMonitors(cfg agentConfig) ([]model.Monitor, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/monitors?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("monitors status %d", resp.StatusCode)
	}
	var monitors []model.Monitor
	if err := json.NewDecoder(resp.Body).Decode(&monitors); err != nil {
		return nil, err
	}
	return monitors, nil
}

func reportMetrics(cfg agentConfig) error {
	return postJSON(cfg.Server+"/api/agent/metrics", map[string]any{
		"node_id":      cfg.NodeID,
		"token":        cfg.Token,
		"version":      version,
		"public_ip":    cfg.PublicIP,
		"public_ipv6":  cfg.PublicIPv6,
		"wireguard_ip": cfg.WireGuardIP,
		"metrics":      metrics.Collect(),
	}, nil)
}

func runTasks(cfg agentConfig, runner taskexec.Runner) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/tasks?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	var tasks []model.Task
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		return err
	}
	for _, task := range tasks {
		result := runner.Run(task)
		result.NodeID = cfg.NodeID
		if err := postJSON(cfg.Server+"/api/agent/task-result", map[string]any{
			"node_id": cfg.NodeID,
			"token":   cfg.Token,
			"result":  result,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func postJSON(url string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func envInt(key string) int {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// watchSSHLogins streams sshd accepted-login lines from journald (preferred) or
// auth.log and reports each as an ssh_login event. It restarts the source if it
// ends. Requires read access to the logs (typically root).
func watchSSHLogins(ctx context.Context, cfg agentConfig) {
	for ctx.Err() == nil {
		cmd := sshLogCommand(ctx)
		if cmd == nil {
			log.Printf("ssh-alerts: no log source available (journalctl/auth.log)")
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("ssh-alerts: stdout pipe: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("ssh-alerts: start source: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		_ = sshwatch.Stream(ctx, stdout, func(ev sshwatch.LoginEvent) { reportSSHLogin(cfg, ev) })
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func sshLogCommand(ctx context.Context) *exec.Cmd {
	if path, err := exec.LookPath("journalctl"); err == nil {
		return exec.CommandContext(ctx, path, "-f", "-n", "0", "-o", "cat", "_COMM=sshd")
	}
	tail, err := exec.LookPath("tail")
	if err != nil {
		return nil
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(p); err == nil {
			return exec.CommandContext(ctx, tail, "-n", "0", "-F", p)
		}
	}
	return nil
}

func reportSSHLogin(cfg agentConfig, ev sshwatch.LoginEvent) {
	if err := postJSON(cfg.Server+"/api/agent/event", map[string]any{
		"node_id": cfg.NodeID,
		"token":   cfg.Token,
		"kind":    "ssh_login",
		"user":    ev.User,
		"address": ev.Address,
		"method":  ev.Method,
	}, nil); err != nil {
		log.Printf("ssh-alerts: report login: %v", err)
	}
}
