package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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
	Server    string
	NodeID    string
	Token     string
	Interval  time.Duration
	AllowExec bool
	AllowRoot bool
	NoExec    bool
	// AllowInsecureHTTP opts in to sending the node token over a non-loopback
	// http:// server URL. Default false: the agent refuses such a config because
	// the Authorization: Bearer token would travel in cleartext.
	AllowInsecureHTTP bool
	PublicIP          string
	PublicIPv6        string
	WireGuardIP       string
	WGPublicKey       string
	WGEndpoint        string
	WGPort            int
	SSHAlerts         bool
}

func main() {
	// If this process was re-executed as the task-execution rlimit shim, handle
	// it before anything else: the shim applies resource limits and execs the
	// target interpreter, never returning. On non-Linux this is a no-op.
	if taskexec.MaybeRunChildShim(os.Args) {
		return
	}

	var cfg agentConfig
	flag.StringVar(&cfg.Server, "server", env("LATTICE_SERVER", "http://127.0.0.1:8088"), "server base URL")
	flag.StringVar(&cfg.NodeID, "node-id", os.Getenv("LATTICE_NODE_ID"), "node id")
	flag.StringVar(&cfg.Token, "token", os.Getenv("LATTICE_NODE_TOKEN"), "node enrollment token")
	flag.DurationVar(&cfg.Interval, "interval", 10*time.Second, "metrics interval")
	flag.BoolVar(&cfg.AllowExec, "allow-exec", os.Getenv("LATTICE_AGENT_ALLOW_EXEC") == "1", "allow bounded task execution")
	// -allow-root-exec opts in to running operator scripts while the agent is
	// uid 0. Without it, a root agent refuses tasks rather than executing
	// arbitrary scripts with full host privileges. Required for tasks that
	// genuinely need root (e.g. nft/wg manipulation).
	flag.BoolVar(&cfg.AllowRoot, "allow-root-exec", os.Getenv("LATTICE_AGENT_ALLOW_ROOT_EXEC") == "1", "permit task execution when the agent runs as root (uid 0)")
	// -no-exec is a hard kill switch: it disables task execution entirely,
	// overriding -allow-exec. Use it to neutralize a node without redeploying.
	flag.BoolVar(&cfg.NoExec, "no-exec", os.Getenv("LATTICE_NO_EXEC") == "1", "disable all task execution (kill switch; overrides -allow-exec)")
	// -allow-insecure-http is an explicit escape hatch to permit a non-loopback
	// http:// -server. Off by default: sending the node token in the bearer
	// header over cleartext to a remote host leaks it. Operators should use
	// https:// instead; this flag exists only for deliberate, isolated setups.
	flag.BoolVar(&cfg.AllowInsecureHTTP, "allow-insecure-http", os.Getenv("LATTICE_ALLOW_INSECURE_HTTP") == "1", "permit a non-loopback http:// server URL (leaks the node token in cleartext; use https:// instead)")
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
	// The kill switch wins over the enable flag.
	if cfg.NoExec {
		cfg.AllowExec = false
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	// Fail closed if the node token would be sent over cleartext http:// to a
	// non-loopback host. Loopback http:// is fine; anything else must use https://
	// unless the operator explicitly opted in with -allow-insecure-http.
	if err := checkServerTransport(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	// Probe interpreter availability once at startup so operators learn early
	// which allowlisted interpreters are missing, rather than only discovering it
	// when a task fails. Non-fatal; task-time resolution is unchanged.
	if missing := taskexec.MissingInterpreters(); len(missing) > 0 {
		log.Printf("warning: allowlisted interpreters not found on PATH: %s (tasks using them will fail until installed)", strings.Join(missing, ", "))
	}
	if err := postAgentJSON(cfg, "/api/agent/hello", map[string]any{
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
	log.Printf("lattice-agent connected node=%s server=%s allow_exec=%v allow_root_exec=%v", cfg.NodeID, cfg.Server, cfg.AllowExec, cfg.AllowRoot)
	if cfg.SSHAlerts {
		go watchSSHLogins(context.Background(), cfg)
	}

	runner := taskexec.Runner{AllowExec: cfg.AllowExec, AllowRoot: cfg.AllowRoot}
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
	if err := postAgentJSON(cfg, "/api/agent/monitor-result", map[string]any{
		"result": res,
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
	return postAgentJSON(cfg, "/api/agent/metrics", map[string]any{
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
		if err := postAgentJSON(cfg, "/api/agent/task-result", map[string]any{
			"result": result,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func postAgentJSON(cfg agentConfig, path string, payload map[string]any, out any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["node_id"] = cfg.NodeID
	return postJSON(cfg.Server+path, cfg.Token, payload, out)
}

func postJSON(url string, bearerToken string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
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

// checkServerTransport enforces that the node token is never sent in cleartext
// to a remote host. It returns an error when rawURL uses http:// to a
// non-loopback host and allowInsecure is false. https:// is always allowed;
// loopback http:// is allowed (token never leaves the host); a non-loopback
// http:// target is refused unless explicitly overridden. It is a pure function
// (no I/O) so it is unit-testable.
func checkServerTransport(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid -server URL %q: %w", rawURL, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil // loopback cleartext never leaves the machine
		}
		if allowInsecure {
			log.Printf("warning: -server uses cleartext http:// to non-loopback host %q; the node token is sent in the clear (overridden by -allow-insecure-http)", u.Hostname())
			return nil
		}
		return fmt.Errorf("server %q uses cleartext http:// to a non-loopback host; the node token would leak. Use https:// (or pass -allow-insecure-http to override)", rawURL)
	default:
		return fmt.Errorf("server %q has unsupported scheme %q; use https:// (or http:// for loopback only)", rawURL, u.Scheme)
	}
}

// isLoopbackHost reports whether host (a URL hostname, no port) refers to the
// local machine: the literal "localhost", or any IP in 127.0.0.0/8 or ::1.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
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
	if err := postAgentJSON(cfg, "/api/agent/event", map[string]any{
		"kind":    "ssh_login",
		"user":    ev.User,
		"address": ev.Address,
		"method":  ev.Method,
	}, nil); err != nil {
		log.Printf("ssh-alerts: report login: %v", err)
	}
}
