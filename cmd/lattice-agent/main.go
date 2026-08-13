package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/guardreality"
	"github.com/LatticeNet/lattice-node-agent/internal/hostfacts"
	"github.com/LatticeNet/lattice-node-agent/internal/ipdiscover"
	"github.com/LatticeNet/lattice-node-agent/internal/linechain"
	"github.com/LatticeNet/lattice-node-agent/internal/metrics"
	"github.com/LatticeNet/lattice-node-agent/internal/prober"
	"github.com/LatticeNet/lattice-node-agent/internal/proxyusage"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
	"github.com/LatticeNet/lattice-node-agent/internal/sshwatch"
	"github.com/LatticeNet/lattice-node-agent/internal/taskexec"
	"github.com/LatticeNet/lattice-node-agent/internal/taskoutbox"
	"github.com/LatticeNet/lattice-sdk/model"
)

var version = "0.3.4-alpha.1"
var compatServerMin = "v0.2.2-alpha.19"
var compatDashboardMin = "v0.2.2-alpha.7"
var compatChannel = "alpha"

type agentCompatibility struct {
	ServerMin    string `json:"server_min"`
	DashboardMin string `json:"dashboard_min"`
	Channel      string `json:"channel"`
}

func compatibilityPayload() agentCompatibility {
	return agentCompatibility{
		ServerMin:    compatServerMin,
		DashboardMin: compatDashboardMin,
		Channel:      compatChannel,
	}
}

// httpClient bounds every agent request so a hung or black-holed server cannot
// wedge the agent's poll loop indefinitely. The total timeout comfortably
// exceeds task execution because task results are posted separately.
var httpClient = &http.Client{Timeout: 30 * time.Second}

const (
	defaultDebugMaxLineBytes    = 4096
	defaultDebugMaxBatchLines   = 100
	debugSinkMaxLines           = 1000
	guardRealityReportTimeout   = 10 * time.Second
	guardManagedSHACapability   = "netguard-managed-sha-v1"
	durableTaskResultCapability = "durable-task-result-v1"
	agentCapabilitiesHeader     = "X-Lattice-Agent-Capabilities"
)

func reportedCapabilities() []string {
	return []string{durableTaskResultCapability, guardManagedSHACapability}
}

func capabilitiesFor(linechainReady bool) []string {
	if linechainReady {
		return reportedCapabilities()
	}
	return []string{guardManagedSHACapability}
}

type agentConfig struct {
	Server              string
	NodeID              string
	Token               string
	Interval            time.Duration
	ReportGuardReality  bool
	AllowExec           bool
	AllowRoot           bool
	NoExec              bool
	TaskCgroupRoot      string
	TaskCgroupMemoryMax string
	TaskCgroupPidsMax   string
	TaskCgroupCPUMax    string
	TaskWorkRoot        string
	AllowTerminal       bool
	// TerminalTransport selects how an accepted terminal session moves bytes:
	// "poll" (default, legacy HTTP store-and-forward) or "stream" (agent-dialed
	// WebSocket bridge). Normalized after flag parsing; unknown values fall back
	// to "poll".
	TerminalTransport  string
	Debug              bool
	LocalDebug         bool
	ServerDebug        bool
	DebugCollect       bool
	DebugMaxLineBytes  int
	DebugMaxBatchLines int
	DebugSink          *debugSink
	// SelfcheckControlPlane runs a one-shot, unauthenticated reachability check
	// against /api/health and exits. It is used by rollback-protected firewall
	// apply tasks so the task shell never needs a node bearer token.
	SelfcheckControlPlane bool
	// UpdateNFTDomainSet runs a one-shot hostname -> nft named-set update and
	// exits. It is used by rollback-protected firewall apply tasks before the
	// control-plane selfcheck; it does not require or send the node token.
	UpdateNFTDomainSet bool
	// AllowInsecureHTTP opts in to sending the node token over a non-loopback
	// http:// server URL. Default false: the agent refuses such a config because
	// the Authorization: Bearer token would travel in cleartext.
	AllowInsecureHTTP   bool
	PublicIP            string
	PublicIPv6          string
	LatticeIdentityUUID string
	IPMode              string
	IPResolvers         string
	staticPublicIP      string
	staticPublicIPv6    string
	ipScript            string
	// startup* preserve the launch-time IP flags so a server-pushed NodeIPConfig
	// override can be cleared back to them.
	startupIPMode         string
	startupIPResolvers    string
	startupStaticPubV4    string
	startupStaticPubV6    string
	startupIPScript       string
	InternalIP            string
	InternalIPv6          string
	WireGuardIP           string
	WGPublicKey           string
	WGEndpoint            string
	WGPort                int
	SSHAlerts             bool
	NFTDomainHost         string
	NFTFamily             string
	NFTTable              string
	NFTSet                string
	NFTSet6               string
	ProxyUsageFile        string
	ProxyUsageURL         string
	ProxyUsageSecret      string
	ProxyUsageSecretFile  string
	ProxyUsageTimeout     time.Duration
	ProxyUsageXrayAPI     string
	ProxyUsageXrayBin     string
	ProxyUsageXrayPattern string
	SingBoxStatsAPI       string
	SingBoxDiscover       bool
	SingBoxBin            string
	SingBoxMeta           string
	LogStateDir           string
	TaskOutboxDir         string
	LinechainTxnDir       string
	LinechainReady        bool
}

type agentRuntimePayload struct {
	AllowExec             bool      `json:"allow_exec"`
	AllowRootExec         bool      `json:"allow_root_exec"`
	NoExec                bool      `json:"no_exec"`
	AllowTerminal         bool      `json:"allow_terminal"`
	TerminalTransport     string    `json:"terminal_transport,omitempty"`
	TaskSandbox           string    `json:"task_sandbox,omitempty"`
	TaskSandboxFeatures   []string  `json:"task_sandbox_features,omitempty"`
	TaskSandboxWarning    string    `json:"task_sandbox_warning,omitempty"`
	SSHAlerts             bool      `json:"ssh_alerts"`
	SingBoxDiscover       bool      `json:"singbox_discover"`
	SingBoxBin            string    `json:"singbox_bin,omitempty"`
	ProxyUsageFile        string    `json:"proxy_usage_file,omitempty"`
	ProxyUsageURL         string    `json:"proxy_usage_url,omitempty"`
	ProxyUsageXrayAPI     string    `json:"proxy_usage_xray_api,omitempty"`
	ProxyUsageXrayBin     string    `json:"proxy_usage_xray_bin,omitempty"`
	ProxyUsageXrayPattern string    `json:"proxy_usage_xray_pattern,omitempty"`
	SingBoxStatsAPI       string    `json:"singbox_stats_api,omitempty"`
	ReportedAt            time.Time `json:"reported_at,omitempty"`
}

func main() {
	// If this process was re-executed as the task-execution rlimit shim, handle
	// it before anything else: the shim applies resource limits and execs the
	// target interpreter, never returning. On non-Linux this is a no-op.
	if taskexec.MaybeRunChildShim(os.Args) {
		return
	}

	var cfg agentConfig
	var printVersion bool
	var printCompat bool
	var printGuardManagedSHA bool
	var applyLinechain bool
	flag.StringVar(&cfg.Server, "server", env("LATTICE_SERVER", "http://127.0.0.1:8088"), "server base URL")
	flag.StringVar(&cfg.NodeID, "node-id", os.Getenv("LATTICE_NODE_ID"), "node id")
	flag.StringVar(&cfg.Token, "token", os.Getenv("LATTICE_NODE_TOKEN"), "node enrollment token")
	flag.DurationVar(&cfg.Interval, "interval", 10*time.Second, "metrics interval")
	flag.BoolVar(&cfg.ReportGuardReality, "report-guard-reality", os.Getenv("LATTICE_REPORT_GUARD_REALITY") == "1", "report read-only NetGuard reality each interval")
	flag.BoolVar(&cfg.AllowExec, "allow-exec", os.Getenv("LATTICE_AGENT_ALLOW_EXEC") == "1", "allow bounded task execution")
	// -allow-root-exec opts in to running operator scripts while the agent is
	// uid 0. Without it, a root agent refuses tasks rather than executing
	// arbitrary scripts with full host privileges. Required for tasks that
	// genuinely need root (e.g. nft/wg manipulation).
	flag.BoolVar(&cfg.AllowRoot, "allow-root-exec", os.Getenv("LATTICE_AGENT_ALLOW_ROOT_EXEC") == "1", "permit task execution when the agent runs as root (uid 0)")
	// -no-exec is a hard kill switch: it disables task execution entirely,
	// overriding -allow-exec. Use it to neutralize a node without redeploying.
	flag.BoolVar(&cfg.NoExec, "no-exec", os.Getenv("LATTICE_NO_EXEC") == "1", "disable all task execution (kill switch; overrides -allow-exec)")
	flag.StringVar(&cfg.TaskCgroupRoot, "task-cgroup-root", os.Getenv("LATTICE_TASK_CGROUP_ROOT"), "Linux cgroup v2 root for per-task caps; use \"auto\" for the agent service cgroup or leave empty to disable")
	flag.StringVar(&cfg.TaskCgroupMemoryMax, "task-cgroup-memory-max", env("LATTICE_TASK_CGROUP_MEMORY_MAX", taskexec.DefaultCgroupMemoryMax), "memory.max value for per-task cgroups when -task-cgroup-root is set")
	flag.StringVar(&cfg.TaskCgroupPidsMax, "task-cgroup-pids-max", env("LATTICE_TASK_CGROUP_PIDS_MAX", taskexec.DefaultCgroupPidsMax), "pids.max value for per-task cgroups when -task-cgroup-root is set")
	flag.StringVar(&cfg.TaskCgroupCPUMax, "task-cgroup-cpu-max", env("LATTICE_TASK_CGROUP_CPU_MAX", taskexec.DefaultCgroupCPUMax), "cpu.max value for per-task cgroups when -task-cgroup-root is set")
	flag.StringVar(&cfg.TaskWorkRoot, "task-work-root", os.Getenv("LATTICE_TASK_WORK_ROOT"), "absolute directory for private per-task workdirs (empty uses OS temp dir)")
	flag.BoolVar(&cfg.AllowTerminal, "allow-terminal", os.Getenv("LATTICE_AGENT_ALLOW_TERMINAL") == "1", "allow audited interactive terminal sessions (high risk; runs as the agent user)")
	flag.StringVar(&cfg.TerminalTransport, "terminal-transport", env("LATTICE_TERMINAL_TRANSPORT", terminalTransportPoll), "terminal transport when -allow-terminal is set: \"poll\" (default) or \"stream\" (agent-dialed WebSocket)")
	flag.BoolVar(&cfg.LocalDebug, "debug", os.Getenv("LATTICE_AGENT_DEBUG") == "1", "enable verbose non-secret diagnostics")
	flag.BoolVar(&cfg.SelfcheckControlPlane, "selfcheck-controlplane", false, "run one-shot unauthenticated /api/health reachability check and exit")
	flag.BoolVar(&cfg.UpdateNFTDomainSet, "update-nft-domain-set", false, "resolve a hostname and update existing nft control-plane named sets, then exit")
	flag.StringVar(&cfg.NFTDomainHost, "host", "", "hostname for -update-nft-domain-set")
	flag.StringVar(&cfg.NFTFamily, "family", "inet", "nft family for -update-nft-domain-set (inet, ip, or ip6)")
	flag.StringVar(&cfg.NFTTable, "table", "", "nft table for -update-nft-domain-set")
	flag.StringVar(&cfg.NFTSet, "set", "", "IPv4 nft set for -update-nft-domain-set")
	flag.StringVar(&cfg.NFTSet6, "set6", "", "IPv6 nft set for -update-nft-domain-set")
	// -allow-insecure-http is an explicit escape hatch to permit a non-loopback
	// http:// -server. Off by default: sending the node token in the bearer
	// header over cleartext to a remote host leaks it. Operators should use
	// https:// instead; this flag exists only for deliberate, isolated setups.
	flag.BoolVar(&cfg.AllowInsecureHTTP, "allow-insecure-http", os.Getenv("LATTICE_ALLOW_INSECURE_HTTP") == "1", "permit a non-loopback http:// server URL (leaks the node token in cleartext; use https:// instead)")
	flag.StringVar(&cfg.PublicIP, "public-ip", os.Getenv("LATTICE_PUBLIC_IP"), "public IPv4 metadata (server observes source IP if empty)")
	flag.StringVar(&cfg.PublicIPv6, "public-ip6", os.Getenv("LATTICE_PUBLIC_IP6"), "public IPv6 metadata")
	flag.StringVar(&cfg.IPMode, "ip-mode", env("LATTICE_IP_MODE", "auto"), "public IP discovery: auto (static override else resolver) | static | resolver")
	flag.StringVar(&cfg.IPResolvers, "ip-resolvers", os.Getenv("LATTICE_IP_RESOLVERS"), "comma-separated IP-echo resolver URLs (overrides built-in defaults)")
	flag.StringVar(&cfg.ipScript, "ip-script", os.Getenv("LATTICE_IP_SCRIPT"), "custom public-IP discovery script for -ip-mode=script (requires -allow-exec, and -allow-root-exec when running as root)")
	flag.StringVar(&cfg.WireGuardIP, "wg-ip", os.Getenv("LATTICE_WG_IP"), "WireGuard IP metadata")
	flag.BoolVar(&cfg.SSHAlerts, "ssh-alerts", os.Getenv("LATTICE_SSH_ALERTS") == "1", "report sshd accepted logins as events")
	flag.StringVar(&cfg.WGPublicKey, "wg-pubkey", os.Getenv("LATTICE_WG_PUBKEY"), "WireGuard public key (for mesh planning)")
	flag.StringVar(&cfg.WGEndpoint, "wg-endpoint", os.Getenv("LATTICE_WG_ENDPOINT"), "WireGuard public endpoint host:port (empty for dial-out-only nodes)")
	flag.IntVar(&cfg.WGPort, "wg-port", envInt("LATTICE_WG_PORT"), "WireGuard listen port")
	flag.StringVar(&cfg.ProxyUsageFile, "proxy-usage-file", os.Getenv("LATTICE_PROXY_USAGE_FILE"), "optional JSON proxy usage snapshot file to report each interval")
	flag.StringVar(&cfg.ProxyUsageURL, "proxy-usage-url", os.Getenv("LATTICE_PROXY_USAGE_URL"), "optional loopback HTTP JSON proxy usage source to report each interval")
	flag.StringVar(&cfg.ProxyUsageSecret, "proxy-usage-secret", os.Getenv("LATTICE_PROXY_USAGE_SECRET"), "optional bearer secret for -proxy-usage-url (prefer -proxy-usage-secret-file for services)")
	flag.StringVar(&cfg.ProxyUsageSecretFile, "proxy-usage-secret-file", os.Getenv("LATTICE_PROXY_USAGE_SECRET_FILE"), "optional file containing bearer secret for -proxy-usage-url")
	flag.DurationVar(&cfg.ProxyUsageTimeout, "proxy-usage-timeout", envDuration("LATTICE_PROXY_USAGE_TIMEOUT", 3*time.Second), "timeout for -proxy-usage-url and -proxy-usage-xray-api")
	flag.StringVar(&cfg.ProxyUsageXrayAPI, "proxy-usage-xray-api", os.Getenv("LATTICE_PROXY_USAGE_XRAY_API"), "optional loopback host:port of the xray API inbound; the agent runs `xray api statsquery` against it each interval (no new dependency; see ADR-003)")
	flag.StringVar(&cfg.SingBoxStatsAPI, "singbox-stats-api", os.Getenv("LATTICE_SINGBOX_STATS_API"), "optional loopback host:port of the sing-box experimental stats API; the agent issues read-only gRPC QueryStats against it each interval (vendored proto; see ADR-004)")
	flag.StringVar(&cfg.ProxyUsageXrayBin, "proxy-usage-xray-bin", os.Getenv("LATTICE_PROXY_USAGE_XRAY_BIN"), "xray binary for -proxy-usage-xray-api (default \"xray\" resolved on PATH)")
	flag.StringVar(&cfg.ProxyUsageXrayPattern, "proxy-usage-xray-pattern", os.Getenv("LATTICE_PROXY_USAGE_XRAY_PATTERN"), "optional stat-name filter for -proxy-usage-xray-api (default \"user>>>\")")
	flag.BoolVar(&cfg.SingBoxDiscover, "singbox-discover", os.Getenv("LATTICE_SINGBOX_DISCOVER") == "1", "report on-box sing-box nodes each interval by running read-only `sb --json list` (adoption bridge; read-only, no node mutation)")
	flag.StringVar(&cfg.SingBoxBin, "singbox-bin", env("LATTICE_SINGBOX_BIN", "sb"), "sb management binary for -singbox-discover (default \"sb\" resolved on PATH)")
	flag.StringVar(&cfg.SingBoxMeta, "singbox-meta", env("LATTICE_SINGBOX_META", ""), "design-15 sing-box sidecar metadata path for -singbox-discover (default /etc/sing-box/lattice-metadata.json)")
	flag.StringVar(&cfg.LogStateDir, "log-state-dir", os.Getenv("LATTICE_LOG_STATE_DIR"), "directory for log-tail checkpoints (empty disables checkpoint persistence; sources still tail from end)")
	flag.StringVar(&cfg.TaskOutboxDir, "task-outbox-dir", os.Getenv("LATTICE_TASK_OUTBOX_DIR"), "base directory for durable task-result journals (default: log state dir, or the user cache directory for manual runs)")
	flag.StringVar(&cfg.LinechainTxnDir, "linechain-txn-dir", os.Getenv("LATTICE_LINECHAIN_TXN_DIR"), "private directory for crash-recoverable linechain transactions")
	flag.BoolVar(&applyLinechain, "linechain-apply", false, "apply one bounded linechain document from stdin and exit")
	flag.BoolVar(&printVersion, "version", false, "print lattice-agent version and exit")
	flag.BoolVar(&printCompat, "compat-json", false, "print embedded server/dashboard compatibility metadata and exit")
	flag.BoolVar(&printGuardManagedSHA, "guard-managed-sha", false, "print the canonical SHA-256 of the managed lattice_guard nft table and exit")
	flag.Parse()
	if printVersion {
		fmt.Println(version)
		return
	}
	if printCompat {
		if err := json.NewEncoder(os.Stdout).Encode(compatibilityPayload()); err != nil {
			log.Fatalf("compatibility encode failed: %v", err)
		}
		return
	}
	if printGuardManagedSHA {
		if err := writeGuardManagedSHA(context.Background(), os.Stdout, guardreality.CollectManagedTableSHA); err != nil {
			log.Fatalf("guard managed SHA collection failed: %v", err)
		}
		return
	}
	if applyLinechain {
		dir, err := linechainTransactionDir(cfg)
		if err != nil {
			log.Fatalf("linechain transaction path failed: %v", err)
		}
		manager, err := linechain.OpenHelper(dir)
		if err != nil {
			log.Fatalf("linechain transaction manager failed: %v", err)
		}
		defer manager.Close()
		if err := manager.ConfigureLayout(os.Getenv("LATTICE_LINECHAIN_CONFIG_DIR"), os.Getenv("LATTICE_LINECHAIN_SIDECAR_PATH")); err != nil {
			log.Fatalf("linechain local layout failed: %v", err)
		}
		if err := manager.Apply(context.Background(), os.Stdin, os.Getenv("LATTICE_TASK_ID"), os.Getenv("LATTICE_TASK_LEASE_ID")); err != nil {
			log.Fatalf("linechain apply failed: %v", err)
		}
		return
	}
	cfg.Debug = cfg.LocalDebug
	cfg.DebugMaxLineBytes = defaultDebugMaxLineBytes
	cfg.DebugMaxBatchLines = defaultDebugMaxBatchLines
	cfg.DebugSink = newDebugSink(debugSinkMaxLines)
	// Preserve the operator's static -public-ip flags; "auto"/"resolver" modes
	// may overwrite the effective cfg.PublicIP with a discovered value.
	cfg.staticPublicIP = cfg.PublicIP
	cfg.staticPublicIPv6 = cfg.PublicIPv6
	// Snapshot the launch-time IP flags so a server-pushed override is revertible.
	cfg.startupIPMode = cfg.IPMode
	cfg.startupIPResolvers = cfg.IPResolvers
	cfg.startupStaticPubV4 = cfg.staticPublicIP
	cfg.startupStaticPubV6 = cfg.staticPublicIPv6
	cfg.startupIPScript = cfg.ipScript
	// The kill switch wins over the enable flag.
	if cfg.NoExec {
		cfg.AllowExec = false
		cfg.AllowTerminal = false
	}
	if cfg.UpdateNFTDomainSet {
		if err := updateNFTDomainSet(context.Background(), nftDomainSetConfig{
			Host: cfg.NFTDomainHost, Family: cfg.NFTFamily, Table: cfg.NFTTable, Set: cfg.NFTSet, Set6: cfg.NFTSet6,
		}, lookupIPAddrs, runNFTCommand); err != nil {
			log.Fatalf("nft domain set update failed: %v", err)
		}
		log.Printf("nft domain set updated: family=%s table=%s set=%s set6=%s host=%s", cfg.NFTFamily, cfg.NFTTable, cfg.NFTSet, cfg.NFTSet6, cfg.NFTDomainHost)
		return
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	cfg.TerminalTransport = strings.ToLower(strings.TrimSpace(cfg.TerminalTransport))
	if cfg.TerminalTransport != terminalTransportStream {
		cfg.TerminalTransport = terminalTransportPoll
	}
	// Fail closed if the node token would be sent over cleartext http:// to a
	// non-loopback host. Loopback http:// is fine; anything else must use https://
	// unless the operator explicitly opted in with -allow-insecure-http.
	if err := checkServerTransport(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	if cfg.SelfcheckControlPlane {
		if err := selfcheckControlPlane(cfg.Server); err != nil {
			log.Fatalf("control-plane selfcheck failed: %v", err)
		}
		log.Printf("control-plane selfcheck ok: %s/api/health", cfg.Server)
		return
	}
	if err := resolveProxyUsageSecret(&cfg); err != nil {
		log.Fatalf("invalid proxy usage secret config: %v", err)
	}
	if err := validateProxyUsageConfig(cfg); err != nil {
		log.Fatalf("invalid proxy usage config: %v", err)
	}
	if cfg.NodeID == "" || cfg.Token == "" {
		log.Fatal("node-id and token are required")
	}
	outboxDir, err := taskResultOutboxDir(cfg)
	if err != nil {
		log.Fatalf("task result outbox path failed: %v", err)
	}
	taskResults, err := taskoutbox.Open(outboxDir)
	if err != nil {
		log.Fatalf("task result outbox initialization failed: %v", err)
	}
	defer taskResults.Close()
	linechainDir, err := linechainTransactionDir(cfg)
	if err != nil {
		log.Fatalf("linechain transaction path failed: %v", err)
	}
	linechainManager, err := linechain.Open(linechainDir)
	if err != nil {
		log.Fatalf("linechain transaction manager initialization failed: %v", err)
	}
	defer linechainManager.Close()
	linechainConfigDir, linechainSidecarPath, layoutErr := singboxdiscover.ResolveRuntimeLayout(cfg.SingBoxMeta)
	if layoutErr != nil {
		log.Printf("warning: durable linechain tasks disabled: %v", layoutErr)
	} else if err := linechainManager.ConfigureLayout(linechainConfigDir, linechainSidecarPath); err != nil {
		log.Printf("warning: durable linechain tasks disabled: %v", err)
	} else {
		cfg.LinechainReady = true
	}
	for {
		if err := requireLinechainRecovered(context.Background(), linechainManager, taskResults, cfg.NodeID); err == nil {
			break
		} else {
			log.Printf("linechain recovery blocked readiness: %v", err)
			if uploadErr := flushTaskResultsRetain(cfg, taskResults, true); uploadErr != nil {
				log.Printf("linechain terminal result upload error: %v", uploadErr)
			}
			time.Sleep(cfg.Interval)
		}
	}
	agentBinary, err := os.Executable()
	if err != nil {
		log.Fatalf("resolve lattice-agent executable failed: %v", err)
	}
	if !filepath.IsAbs(agentBinary) {
		log.Fatalf("resolved lattice-agent executable is not absolute: %q", agentBinary)
	}
	if cfg.AllowTerminal && os.Geteuid() == 0 && !cfg.AllowRoot {
		log.Printf("warning: terminal sessions disabled because agent is running as root without -allow-root-exec")
		cfg.AllowTerminal = false
	}
	debugf(cfg, "debug enabled: node=%s server=%s interval=%s report_guard_reality=%v allow_exec=%v allow_root_exec=%v allow_terminal=%v ssh_alerts=%v", cfg.NodeID, cfg.Server, cfg.Interval, cfg.ReportGuardReality, cfg.AllowExec, cfg.AllowRoot, cfg.AllowTerminal, cfg.SSHAlerts)
	// Probe interpreter availability once at startup so operators learn early
	// which allowlisted interpreters are missing, rather than only discovering it
	// when a task fails. Non-fatal; task-time resolution is unchanged.
	if missing := taskexec.MissingInterpreters(); len(missing) > 0 {
		log.Printf("warning: allowlisted interpreters not found on PATH: %s (tasks using them will fail until installed)", strings.Join(missing, ", "))
	}
	refreshIPs(&cfg)
	if err := postAgentJSON(cfg, "/api/agent/hello", map[string]any{
		"version":              version,
		"compatibility":        compatibilityPayload(),
		"capabilities":         capabilitiesFor(cfg.LinechainReady),
		"public_ip":            cfg.PublicIP,
		"public_ipv6":          cfg.PublicIPv6,
		"internal_ip":          cfg.InternalIP,
		"internal_ipv6":        cfg.InternalIPv6,
		"wireguard_ip":         cfg.WireGuardIP,
		"wireguard_public_key": cfg.WGPublicKey,
		"wireguard_endpoint":   cfg.WGEndpoint,
		"wireguard_port":       cfg.WGPort,
		"host_facts":           hostfacts.Collect(),
	}, nil); err != nil {
		log.Fatalf("hello failed: %v", err)
	}
	if agentCfg, err := fetchAgentConfig(cfg); err != nil {
		debugf(cfg, "agent config fetch failed: %v", err)
	} else {
		applyAgentConfig(&cfg, agentCfg)
	}
	log.Printf("lattice-agent connected node=%s server=%s report_guard_reality=%v allow_exec=%v allow_root_exec=%v task_cgroup=%v task_work_root=%v allow_terminal=%v terminal_transport=%s debug=%v", cfg.NodeID, cfg.Server, cfg.ReportGuardReality, cfg.AllowExec, cfg.AllowRoot, cfg.taskCgroupConfig().Root != "", strings.TrimSpace(cfg.TaskWorkRoot) != "", cfg.AllowTerminal, cfg.TerminalTransport, cfg.Debug)
	if cfg.SSHAlerts {
		go watchSSHLogins(context.Background(), cfg)
	}
	if cfg.AllowTerminal {
		go runTerminalLoop(context.Background(), cfg)
	}

	runner := taskexec.Runner{
		AllowExec: cfg.AllowExec, AllowRoot: cfg.AllowRoot, Cgroup: cfg.taskCgroupConfig(),
		WorkdirRoot: cfg.TaskWorkRoot, AgentBinary: agentBinary, LinechainTxnDir: linechainDir, LinechainConfigDir: linechainConfigDir, LinechainSidecarPath: linechainSidecarPath,
	}
	monitors := newMonitorManager(cfg)
	logTailers := newLogTailManager(cfg)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		if err := requireLinechainRecovered(context.Background(), linechainManager, taskResults, cfg.NodeID); err != nil {
			log.Printf("linechain recovery blocked cycle: %v", err)
			if uploadErr := flushTaskResultsRetain(cfg, taskResults, true); uploadErr != nil {
				log.Printf("linechain terminal result upload error: %v", uploadErr)
			}
			<-ticker.C
			continue
		}
		if agentCfg, err := fetchAgentConfig(cfg); err != nil {
			debugf(cfg, "agent config fetch failed: %v", err)
		} else {
			applyAgentConfig(&cfg, agentCfg)
			monitors.setConfig(cfg)
			logTailers.setConfig(cfg)
		}
		refreshIPs(&cfg)
		if err := reportMetrics(cfg); err != nil {
			log.Printf("metrics error: %v", err)
		}
		if err := reportProxyUsage(cfg); err != nil {
			log.Printf("proxy usage error: %v", err)
		}
		if err := reportSingBoxInventory(cfg); err != nil {
			log.Printf("singbox discover error: %v", err)
		}
		if err := runTasks(cfg, runner, taskResults, linechainManager); err != nil {
			log.Printf("task poll error: %v", err)
		}
		if assigned, err := fetchMonitors(cfg); err != nil {
			log.Printf("monitor poll error: %v", err)
		} else {
			monitors.reconcile(assigned)
		}
		if sources, err := fetchLogSources(cfg); err != nil {
			log.Printf("log source poll error: %v", err)
		} else {
			logTailers.reconcile(sources)
		}
		debugf(cfg, "poll cycle complete")
		if err := flushDebugEvents(cfg); err != nil {
			log.Printf("debug event report error: %v", err)
		}
		reportCtx, cancelReport := context.WithTimeout(context.Background(), guardRealityReportTimeout)
		if err := reportGuardReality(reportCtx, cfg, guardreality.Collect); err != nil {
			log.Printf("guard reality error: %v", err)
		}
		cancelReport()
		<-ticker.C
	}
}

var guardManagedSHARe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func writeGuardManagedSHA(ctx context.Context, out io.Writer, collect func(context.Context, guardreality.Source) (string, error)) error {
	sha, err := collect(ctx, guardreality.Source{})
	if err != nil {
		return err
	}
	if !guardManagedSHARe.MatchString(sha) {
		return fmt.Errorf("collector returned invalid managed table SHA")
	}
	_, err = fmt.Fprintln(out, sha)
	return err
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

func (mm *monitorManager) setConfig(cfg agentConfig) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.cfg = cfg
}

func (mm *monitorManager) snapshotConfig() agentConfig {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	return mm.cfg
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
	probeAndReport(mm.snapshotConfig(), m)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeAndReport(mm.snapshotConfig(), m)
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
	debugf(cfg, "monitor probe complete: monitor=%s success=%v latency_ms=%.1f error=%t", m.ID, res.Success, res.LatencyMs, res.Error != "")
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
		return nil, agentHTTPError(resp, "fetch monitors")
	}
	var monitors []model.Monitor
	if err := json.NewDecoder(resp.Body).Decode(&monitors); err != nil {
		return nil, err
	}
	debugf(cfg, "monitor assignments fetched: count=%d", len(monitors))
	return monitors, nil
}

func fetchAgentConfig(cfg agentConfig) (model.AgentConfig, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/config?node_id=%s", cfg.Server, url.QueryEscape(cfg.NodeID)), nil)
	if err != nil {
		return model.AgentConfig{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return model.AgentConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return model.AgentConfig{}, agentHTTPError(resp, "fetch agent config")
	}
	var out model.AgentConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return model.AgentConfig{}, err
	}
	return out, nil
}

func applyAgentConfig(cfg *agentConfig, remote model.AgentConfig) {
	oldDebug := cfg.Debug
	oldCollect := cfg.DebugCollect
	oldMaxLine := cfg.DebugMaxLineBytes
	oldMaxBatch := cfg.DebugMaxBatchLines

	cfg.ServerDebug = remote.Debug.Enabled
	cfg.DebugCollect = remote.Debug.Enabled && remote.Debug.Collect
	cfg.Debug = cfg.LocalDebug || cfg.ServerDebug
	cfg.DebugMaxLineBytes = remote.Debug.MaxLineBytes
	if cfg.DebugMaxLineBytes <= 0 {
		cfg.DebugMaxLineBytes = defaultDebugMaxLineBytes
	}
	cfg.DebugMaxBatchLines = remote.Debug.MaxBatchLines
	if cfg.DebugMaxBatchLines <= 0 {
		cfg.DebugMaxBatchLines = defaultDebugMaxBatchLines
	}
	if !cfg.DebugCollect && cfg.DebugSink != nil {
		cfg.DebugSink.clear()
	}
	if cfg.Debug != oldDebug || cfg.DebugCollect != oldCollect || cfg.DebugMaxLineBytes != oldMaxLine || cfg.DebugMaxBatchLines != oldMaxBatch {
		log.Printf("lattice-agent debug policy updated: local=%v server=%v collect=%v max_line_bytes=%d max_batch_lines=%d",
			cfg.LocalDebug, cfg.ServerDebug, cfg.DebugCollect, cfg.DebugMaxLineBytes, cfg.DebugMaxBatchLines)
	}

	// Phase 3 rollout lever: a server-pushed per-node transport override takes
	// effect for terminal sessions opened after this poll. Empty clears it (the
	// startup -terminal-transport value wins). Logged on change so a canary flip
	// is visible in the agent log.
	override := strings.ToLower(strings.TrimSpace(remote.TerminalTransport))
	oldEffective := effectiveTerminalTransport(cfg.TerminalTransport)
	setTerminalTransportOverride(override)
	if newEffective := effectiveTerminalTransport(cfg.TerminalTransport); newEffective != oldEffective {
		log.Printf("lattice-agent terminal transport updated: effective=%s (server override=%q, startup=%s)",
			newEffective, override, cfg.TerminalTransport)
	}
	if identity := strings.TrimSpace(remote.LatticeIdentityUUID); identity != "" && identity != cfg.LatticeIdentityUUID {
		cfg.LatticeIdentityUUID = identity
		log.Printf("lattice-agent identity updated: lattice_identity_uuid=%s", identity)
	}

	applyIPConfigOverride(cfg, remote.IPConfig)
}

// applyIPConfigOverride lets a server-pushed NodeIPConfig take precedence over
// the agent's startup IP flags. A nil config or empty Mode clears the override,
// reverting to the launch-time flags. On any change it resets the public-probe
// throttle so the new setting takes effect on the next refreshIPs, and logs the
// transition so a server-side flip is visible in the agent log.
func applyIPConfigOverride(cfg *agentConfig, ipc *model.NodeIPConfig) {
	oldMode, oldResolvers := cfg.IPMode, cfg.IPResolvers
	oldV4, oldV6 := cfg.staticPublicIP, cfg.staticPublicIPv6
	oldScript := cfg.ipScript
	if ipc != nil && strings.TrimSpace(ipc.Mode) != "" {
		cfg.IPMode = strings.ToLower(strings.TrimSpace(ipc.Mode))
		cfg.staticPublicIP = strings.TrimSpace(ipc.StaticIPv4)
		cfg.staticPublicIPv6 = strings.TrimSpace(ipc.StaticIPv6)
		cfg.IPResolvers = strings.Join(ipc.Resolvers, ",")
		cfg.ipScript = ipc.Script
	} else {
		cfg.IPMode = cfg.startupIPMode
		cfg.staticPublicIP = cfg.startupStaticPubV4
		cfg.staticPublicIPv6 = cfg.startupStaticPubV6
		cfg.IPResolvers = cfg.startupIPResolvers
		cfg.ipScript = cfg.startupIPScript
	}
	if cfg.IPMode != oldMode || cfg.IPResolvers != oldResolvers ||
		cfg.staticPublicIP != oldV4 || cfg.staticPublicIPv6 != oldV6 ||
		cfg.ipScript != oldScript {
		lastPublicProbe = time.Time{} // re-probe promptly on the next refreshIPs
		log.Printf("lattice-agent IP config updated: mode=%s static_v4=%q static_v6=%q resolvers=%q script=%v (server override=%v)",
			cfg.IPMode, cfg.staticPublicIP, cfg.staticPublicIPv6, cfg.IPResolvers,
			strings.TrimSpace(cfg.ipScript) != "",
			ipc != nil && strings.TrimSpace(ipc.Mode) != "")
	}
}

func (cfg agentConfig) taskCgroupConfig() taskexec.CgroupConfig {
	return taskexec.CgroupConfig{
		Root:      cfg.TaskCgroupRoot,
		MemoryMax: cfg.TaskCgroupMemoryMax,
		PidsMax:   cfg.TaskCgroupPidsMax,
		CPUMax:    cfg.TaskCgroupCPUMax,
	}
}

func (cfg agentConfig) taskSandboxOptions() taskexec.SandboxOptions {
	return taskexec.SandboxOptions{
		Cgroup:      cfg.taskCgroupConfig(),
		WorkdirRoot: cfg.TaskWorkRoot,
	}
}

func reportMetrics(cfg agentConfig) error {
	m := metrics.Collect()
	facts := hostfacts.Collect()
	sandbox := taskexec.SandboxProfileWithOptions(cfg.AllowExec, cfg.AllowRoot, os.Geteuid(), cfg.taskSandboxOptions())
	debugf(cfg, "metrics collected: cpu=%.1f load1=%.2f memory=%d/%d disk=%d/%d uptime=%d cpu_cores=%d cpu_model=%q", m.CPUPercent, m.Load1, m.MemoryUsed, m.MemoryTotal, m.DiskUsed, m.DiskTotal, m.UptimeSeconds, facts.CPUCores, facts.CPUModel)
	return postAgentJSON(cfg, "/api/agent/metrics", map[string]any{
		"version":       version,
		"compatibility": compatibilityPayload(),
		"capabilities":  capabilitiesFor(cfg.LinechainReady),
		"agent_runtime": agentRuntimePayload{
			AllowExec:             cfg.AllowExec,
			AllowRootExec:         cfg.AllowRoot,
			NoExec:                cfg.NoExec,
			AllowTerminal:         cfg.AllowTerminal,
			TerminalTransport:     effectiveTerminalTransport(cfg.TerminalTransport),
			TaskSandbox:           sandbox.Level,
			TaskSandboxFeatures:   sandbox.Features,
			TaskSandboxWarning:    sandbox.Warning,
			SSHAlerts:             cfg.SSHAlerts,
			SingBoxDiscover:       cfg.SingBoxDiscover,
			SingBoxBin:            cfg.SingBoxBin,
			ProxyUsageFile:        cfg.ProxyUsageFile,
			ProxyUsageURL:         cfg.ProxyUsageURL,
			ProxyUsageXrayAPI:     cfg.ProxyUsageXrayAPI,
			ProxyUsageXrayBin:     cfg.ProxyUsageXrayBin,
			ProxyUsageXrayPattern: cfg.ProxyUsageXrayPattern,
			SingBoxStatsAPI:       cfg.SingBoxStatsAPI,
			ReportedAt:            time.Now().UTC(),
		},
		"public_ip":     cfg.PublicIP,
		"public_ipv6":   cfg.PublicIPv6,
		"internal_ip":   cfg.InternalIP,
		"internal_ipv6": cfg.InternalIPv6,
		"wireguard_ip":  cfg.WireGuardIP,
		"metrics":       m,
		"host_facts":    facts,
	}, nil)
}

type guardRealityCollector func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error)

func reportGuardReality(ctx context.Context, cfg agentConfig, collect guardRealityCollector) error {
	if !cfg.ReportGuardReality {
		return nil
	}
	reality, err := collect(ctx, guardreality.Source{}, cfg.NodeID)
	if err != nil {
		return fmt.Errorf("collect guard reality: %w", err)
	}
	if err := postAgentJSONContext(ctx, cfg, "/api/agent/guard-reality", map[string]any{
		"reality": reality,
	}, nil); err != nil {
		return fmt.Errorf("report guard reality: %w", err)
	}
	return nil
}

// lastPublicProbe throttles outbound IP-echo requests so the agent does not hit
// resolvers on every metrics tick.
var lastPublicProbe time.Time

// refreshIPs updates the effective public IPs (per -ip-mode) and the internal
// LAN IPs on cfg. Internal IPs are refreshed every call (local, cheap); public
// resolver probes are throttled to ~2 minutes and keep their last good value.
func refreshIPs(cfg *agentConfig) {
	cfg.InternalIP, cfg.InternalIPv6 = ipdiscover.InternalIPs()
	mode := strings.ToLower(strings.TrimSpace(cfg.IPMode))
	if mode == "static" {
		cfg.PublicIP, cfg.PublicIPv6 = cfg.staticPublicIP, cfg.staticPublicIPv6
		return
	}
	if !lastPublicProbe.IsZero() && time.Since(lastPublicProbe) < 2*time.Minute {
		return
	}
	lastPublicProbe = time.Now()
	if mode == "script" {
		v4, v6, err := runIPDiscoveryScript(cfg)
		if err != nil {
			log.Printf("lattice-agent IP script discovery failed: %v", err)
			return
		}
		cfg.PublicIP, cfg.PublicIPv6 = v4, v6
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	probeV4 := ipdiscover.PublicIP(ctx, resolverList(cfg.IPResolvers, true), true)
	probeV6 := ipdiscover.PublicIP(ctx, resolverList(cfg.IPResolvers, false), false)
	if mode == "resolver" {
		cfg.PublicIP, cfg.PublicIPv6 = probeV4, probeV6
		return
	}
	// "auto" (default): a static override wins; otherwise use the resolver result.
	cfg.PublicIP = firstNonEmpty(cfg.staticPublicIP, probeV4)
	cfg.PublicIPv6 = firstNonEmpty(cfg.staticPublicIPv6, probeV6)
}

func runIPDiscoveryScript(cfg *agentConfig) (string, string, error) {
	script := strings.TrimSpace(cfg.ipScript)
	if script == "" {
		return "", "", fmt.Errorf("script mode has no script configured")
	}
	result := taskexec.Runner{
		AllowExec:   cfg.AllowExec && !cfg.NoExec,
		AllowRoot:   cfg.AllowRoot,
		Cgroup:      cfg.taskCgroupConfig(),
		WorkdirRoot: cfg.TaskWorkRoot,
	}.Run(model.Task{
		ID:          "ip-discovery",
		Interpreter: ipDiscoveryInterpreter(script),
		Script:      script,
		TimeoutSec:  8,
		OutputLimit: 4096,
	})
	if result.ExitCode != 0 || result.Error != "" {
		msg := strings.TrimSpace(result.Error)
		if msg == "" {
			msg = strings.TrimSpace(result.Stderr)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", result.ExitCode)
		}
		return "", "", errors.New(msg)
	}
	v4, v6 := parseIPDiscoveryOutput(result.Stdout)
	if v4 == "" && v6 == "" {
		return "", "", fmt.Errorf("script did not return a public IPv4 or IPv6 address")
	}
	return v4, v6, nil
}

func ipDiscoveryInterpreter(script string) string {
	firstLine, _, _ := strings.Cut(script, "\n")
	if strings.Contains(firstLine, "bash") {
		return "bash"
	}
	return "sh"
}

func parseIPDiscoveryOutput(output string) (string, string) {
	var v4, v6 string
	for _, field := range strings.Fields(output) {
		candidate := strings.Trim(field, " \t\r\n,;")
		ip := net.ParseIP(candidate)
		if !isPublicIP(ip) {
			continue
		}
		if ip.To4() != nil {
			if v4 == "" {
				v4 = ip.String()
			}
		} else if v6 == "" {
			v6 = ip.String()
		}
		if v4 != "" && v6 != "" {
			break
		}
	}
	return v4, v6
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	if !ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPublicIPPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedPublicIPPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func resolverList(custom string, v4 bool) []string {
	if list := splitComma(custom); len(list) > 0 {
		return list
	}
	if v4 {
		return ipdiscover.DefaultResolversV4
	}
	return ipdiscover.DefaultResolversV6
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func reportProxyUsage(cfg agentConfig) error {
	hasFile := strings.TrimSpace(cfg.ProxyUsageFile) != ""
	hasURL := strings.TrimSpace(cfg.ProxyUsageURL) != ""
	hasXray := strings.TrimSpace(cfg.ProxyUsageXrayAPI) != ""
	hasSingBox := strings.TrimSpace(cfg.SingBoxStatsAPI) != ""
	configured := 0
	for _, on := range []bool{hasFile, hasURL, hasXray, hasSingBox} {
		if on {
			configured++
		}
	}
	if configured == 0 {
		return nil
	}
	if configured > 1 {
		return fmt.Errorf("configure only one of proxy-usage-file, proxy-usage-url, proxy-usage-xray-api, or singbox-stats-api")
	}
	var (
		snapshot model.ProxyUsageSnapshot
		err      error
		source   string
	)
	switch {
	case hasFile:
		source = "file"
		snapshot, err = proxyusage.LoadFile(cfg.ProxyUsageFile, cfg.NodeID)
	case hasURL:
		source = "http"
		snapshot, err = proxyusage.LoadHTTP(context.Background(), proxyusage.HTTPSource{
			URL:     cfg.ProxyUsageURL,
			Secret:  cfg.ProxyUsageSecret,
			Timeout: cfg.ProxyUsageTimeout,
		}, cfg.NodeID)
	case hasSingBox:
		source = "singbox-stats"
		snapshot, err = proxyusage.LoadSingBoxStats(context.Background(), proxyusage.SingBoxStatsSource{
			APIAddr: cfg.SingBoxStatsAPI,
			Timeout: cfg.ProxyUsageTimeout,
		}, cfg.NodeID)
	default:
		source = "xray-cli"
		snapshot, err = proxyusage.LoadXrayCLI(context.Background(), proxyusage.XrayCLISource{
			Binary:  cfg.ProxyUsageXrayBin,
			APIAddr: cfg.ProxyUsageXrayAPI,
			Pattern: cfg.ProxyUsageXrayPattern,
			Timeout: cfg.ProxyUsageTimeout,
		}, cfg.NodeID)
	}
	if err != nil {
		if postErr := reportProxyUsageCollectorHealth(cfg, source, model.ProxyUsageCollectorStatusError, err); postErr != nil {
			return fmt.Errorf("%w; collector health report failed: %v", err, postErr)
		}
		return err
	}
	checkedAt := time.Now().UTC()
	snapshot.CollectorSource = source
	snapshot.CollectorStatus = model.ProxyUsageCollectorStatusOK
	snapshot.CollectorCheckedAt = checkedAt
	return postAgentJSON(cfg, "/api/agent/proxy-usage", map[string]any{
		"snapshot": snapshot,
	}, nil)
}

func reportProxyUsageCollectorHealth(cfg agentConfig, source, status string, cause error) error {
	now := time.Now().UTC()
	snapshot := model.ProxyUsageSnapshot{
		NodeID:             cfg.NodeID,
		At:                 now,
		CollectorSource:    source,
		CollectorStatus:    status,
		CollectorCheckedAt: now,
	}
	if cause != nil {
		snapshot.CollectorError = boundedProxyUsageError(cause)
	}
	return postAgentJSON(cfg, "/api/agent/proxy-usage", map[string]any{
		"snapshot": snapshot,
	}, nil)
}

// reportSingBoxInventory runs read-only on-box sing-box discovery (`sb --json
// list`) and reports the result so the control plane can see proxies that exist
// on the machine but are managed out-of-band (the adoption bridge). Opt-in via
// -singbox-discover; a discovery failure is reported as a status=error inventory
// (so the dashboard shows the failure) and also returned for logging.
func reportSingBoxInventory(cfg agentConfig) error {
	if !cfg.SingBoxDiscover {
		return nil
	}
	inv, derr := singboxdiscover.Discover(context.Background(), singboxdiscover.Source{
		Binary:   cfg.SingBoxBin,
		Addr:     cfg.PublicIP,
		MetaPath: cfg.SingBoxMeta,
	}, cfg.NodeID)
	// Always post what we have (ok list OR error status); the post error, if any,
	// is combined with any discovery error for the caller's log.
	postErr := postAgentJSON(cfg, "/api/agent/singbox-inventory", map[string]any{
		"inventory": inv,
	}, nil)
	switch {
	case derr != nil && postErr != nil:
		return fmt.Errorf("%w; report failed: %v", derr, postErr)
	case derr != nil:
		return derr
	default:
		return postErr
	}
}

func boundedProxyUsageError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	msg = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, msg)
	const maxRunes = 512
	runes := []rune(msg)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return string(runes)
}

func validateProxyUsageConfig(cfg agentConfig) error {
	hasFile := strings.TrimSpace(cfg.ProxyUsageFile) != ""
	hasURL := strings.TrimSpace(cfg.ProxyUsageURL) != ""
	hasXray := strings.TrimSpace(cfg.ProxyUsageXrayAPI) != ""
	hasSingBox := strings.TrimSpace(cfg.SingBoxStatsAPI) != ""
	hasSecretFile := strings.TrimSpace(cfg.ProxyUsageSecretFile) != ""
	configured := 0
	for _, on := range []bool{hasFile, hasURL, hasXray, hasSingBox} {
		if on {
			configured++
		}
	}
	if configured > 1 {
		return fmt.Errorf("configure only one of proxy-usage-file, proxy-usage-url, proxy-usage-xray-api, or singbox-stats-api")
	}
	if strings.TrimSpace(cfg.ProxyUsageSecret) != "" && hasSecretFile {
		return fmt.Errorf("configure either proxy-usage-secret or proxy-usage-secret-file, not both")
	}
	if strings.TrimSpace(cfg.ProxyUsageSecret) != "" && !hasURL {
		return fmt.Errorf("proxy-usage-secret requires proxy-usage-url")
	}
	if hasSecretFile && !hasURL {
		return fmt.Errorf("proxy-usage-secret-file requires proxy-usage-url")
	}
	if hasURL {
		if _, err := proxyusage.ValidateLocalHTTPURL(cfg.ProxyUsageURL); err != nil {
			return err
		}
	}
	if cfg.ProxyUsageXrayBin != "" && !hasXray {
		return fmt.Errorf("proxy-usage-xray-bin requires proxy-usage-xray-api")
	}
	if cfg.ProxyUsageXrayPattern != "" && !hasXray {
		return fmt.Errorf("proxy-usage-xray-pattern requires proxy-usage-xray-api")
	}
	if hasXray {
		if err := proxyusage.ValidateXrayCLISource(proxyusage.XrayCLISource{
			Binary:  cfg.ProxyUsageXrayBin,
			APIAddr: cfg.ProxyUsageXrayAPI,
			Pattern: cfg.ProxyUsageXrayPattern,
		}); err != nil {
			return err
		}
	}
	if hasSingBox {
		if err := proxyusage.ValidateSingBoxStatsSource(proxyusage.SingBoxStatsSource{
			APIAddr: cfg.SingBoxStatsAPI,
		}); err != nil {
			return err
		}
	}
	if cfg.ProxyUsageTimeout < 0 {
		return fmt.Errorf("proxy-usage-timeout cannot be negative")
	}
	return nil
}

func resolveProxyUsageSecret(cfg *agentConfig) error {
	file := strings.TrimSpace(cfg.ProxyUsageSecretFile)
	if file == "" {
		return nil
	}
	if strings.TrimSpace(cfg.ProxyUsageSecret) != "" {
		return fmt.Errorf("configure either proxy-usage-secret or proxy-usage-secret-file, not both")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) > 4096 {
		return fmt.Errorf("proxy usage secret file exceeds 4096 bytes")
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return fmt.Errorf("proxy usage secret file is empty")
	}
	cfg.ProxyUsageSecret = secret
	cfg.ProxyUsageSecretFile = ""
	return nil
}

type taskRunner interface {
	Run(model.Task) model.TaskResult
}

type taskResultOutbox interface {
	Begin(model.Task) (bool, error)
	Complete(model.TaskResult) (bool, error)
	ConfirmDurability() error
	RecoverInterrupted(string) error
	Pending() ([]taskoutbox.Entry, error)
	Remove(taskoutbox.Entry) error
}

type leasedAgentTask struct {
	model.Task
	DurableResult bool `json:"durable_result"`
}

func runTasks(cfg agentConfig, runner taskRunner, outbox taskResultOutbox, managers ...*linechain.Manager) error {
	var manager *linechain.Manager
	if len(managers) > 0 {
		manager = managers[0]
	}
	if manager != nil {
		if err := requireLinechainRecovered(context.Background(), manager, outbox, cfg.NodeID); err != nil {
			_ = flushTaskResultsRetain(cfg, outbox, true)
			return err
		}
	}
	if err := outbox.RecoverInterrupted(cfg.NodeID); err != nil {
		return fmt.Errorf("recover interrupted task results: %w", err)
	}
	if err := flushTaskResults(cfg, outbox); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/tasks?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set(agentCapabilitiesHeader, strings.Join(capabilitiesFor(cfg.LinechainReady), ","))
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentHTTPError(resp, "fetch tasks")
	}
	var tasks []leasedAgentTask
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		return err
	}
	debugf(cfg, "tasks fetched: count=%d", len(tasks))
	for _, leased := range tasks {
		task := leased.Task
		if !leased.DurableResult {
			debugf(cfg, "task start without durable-result protocol: id=%s interpreter=%s timeout=%ds", task.ID, task.Interpreter, task.TimeoutSec)
			result := runner.Run(task)
			result.NodeID = cfg.NodeID
			if result.FinishedAt.IsZero() {
				result.FinishedAt = time.Now().UTC()
			}
			if err := postAgentJSON(cfg, "/api/agent/task-result", map[string]any{"result": result}, nil); err != nil {
				return fmt.Errorf("post task result %s: %w", task.ID, err)
			}
			continue
		}
		committed, err := outbox.Begin(task)
		if err != nil {
			journalErr := fmt.Errorf("journal task lease %s before execution: %w", task.ID, err)
			if committed {
				// The lease journal is visible but its directory durability is
				// uncertain. Do not post a different direct result: the next poll
				// will recover this exact journal as an unknown outcome.
				return journalErr
			}
			// No host code ran, so it is safe to make one best-effort terminal
			// report even though durable retry storage is unavailable. This avoids
			// silently stranding the server lease while preserving the fail-closed
			// rule that an unjournaled task is never executed.
			failure := model.TaskResult{
				TaskID: task.ID, LeaseID: task.LeaseID, NodeID: cfg.NodeID, ExitCode: -1,
				Error:      "task was not executed because its durable lease journal could not be written",
				FinishedAt: time.Now().UTC(),
			}
			if postErr := postAgentJSON(cfg, "/api/agent/task-result", map[string]any{"result": failure}, nil); postErr != nil {
				return fmt.Errorf("%v; report unexecuted task: %w", journalErr, postErr)
			}
			return journalErr
		}
		if !committed {
			// The server intentionally redelivers an unacknowledged lease when a
			// prior task-poll response may have been lost. An exact existing journal
			// is the execution authority, so the duplicate response is a no-op.
			debugf(cfg, "task lease already journaled: id=%s", task.ID)
			continue
		}
		debugf(cfg, "task start: id=%s interpreter=%s timeout=%ds", task.ID, task.Interpreter, task.TimeoutSec)
		result := runner.Run(task)
		result.NodeID = cfg.NodeID
		if manager != nil && isLinechainTask(task) {
			result, err = manager.ResolveAfterRun(context.Background(), task, result)
			if err != nil {
				return fmt.Errorf("resolve linechain task %s: %w", task.ID, err)
			}
		}
		debugf(cfg, "task complete: id=%s exit_code=%d error=%t", task.ID, result.ExitCode, result.Error != "")
		completed, completeErr := outbox.Complete(result)
		if completeErr != nil {
			journalErr := fmt.Errorf("journal task result %s before upload: %w", task.ID, completeErr)
			if completed {
				// Rename published the exact result even though directory durability
				// was uncertain. Confirm the local transition before allowing the
				// server to commit the result; otherwise a crash could expose the old
				// leased journal and synthesize a conflicting unknown-outcome result.
				if confirmErr := outbox.ConfirmDurability(); confirmErr != nil {
					return fmt.Errorf("%v; confirm published task result: %w", journalErr, confirmErr)
				}
				if manager != nil && isLinechainTask(task) {
					if cleanupErr := manager.Cleanup(task.ID, task.LeaseID); cleanupErr != nil {
						if uploadErr := flushTaskResultsRetain(cfg, outbox, true); uploadErr != nil {
							return fmt.Errorf("%v; cleanup confirmed linechain task: %v; upload stable result: %w", journalErr, cleanupErr, uploadErr)
						}
						return fmt.Errorf("%v; cleanup confirmed linechain task: %w; result remains replayable", journalErr, cleanupErr)
					}
				}
				if flushErr := flushTaskResults(cfg, outbox); flushErr != nil {
					return fmt.Errorf("%v; upload confirmed task result: %w", journalErr, flushErr)
				}
			}
			return journalErr
		}
		if manager != nil && isLinechainTask(task) {
			if err := manager.Cleanup(task.ID, task.LeaseID); err != nil {
				if uploadErr := flushTaskResultsRetain(cfg, outbox, true); uploadErr != nil {
					return fmt.Errorf("cleanup linechain task %s: %v; upload stable result: %w", task.ID, err, uploadErr)
				}
				return fmt.Errorf("cleanup linechain task %s after durable outbox completion; result remains replayable: %w", task.ID, err)
			}
		}
		if err := flushTaskResults(cfg, outbox); err != nil {
			return err
		}
	}
	return nil
}

func isLinechainTask(task model.Task) bool {
	return strings.Contains(task.Script, "-linechain-apply")
}

func requireLinechainRecovered(ctx context.Context, manager *linechain.Manager, outbox taskResultOutbox, nodeID string) error {
	return manager.RequireRecovered(ctx, func(result model.TaskResult) error {
		committed, err := outbox.Complete(result)
		if err == nil {
			return nil
		}
		if committed {
			return outbox.ConfirmDurability()
		}
		// An exact completed outbox may remain after a crash before transaction
		// cleanup. Complete implementations treat that replay idempotently.
		return err
	}, nodeID)
}

func flushTaskResults(cfg agentConfig, outbox taskResultOutbox) error {
	return flushTaskResultsRetain(cfg, outbox, false)
}

func flushTaskResultsRetain(cfg agentConfig, outbox taskResultOutbox, retain bool) error {
	pending, err := outbox.Pending()
	if err != nil {
		return fmt.Errorf("read pending task results: %w", err)
	}
	for _, entry := range pending {
		if entry.Result == nil {
			return fmt.Errorf("pending task result %s is empty", entry.Task.ID)
		}
		if err := postAgentJSON(cfg, "/api/agent/task-result", map[string]any{
			"result": *entry.Result,
		}, nil); err != nil {
			return fmt.Errorf("flush durable task result %s: %w", entry.Task.ID, err)
		}
		if retain && isLinechainTask(entry.Task) {
			continue
		}
		if err := outbox.Remove(entry); err != nil {
			return fmt.Errorf("remove acknowledged task result %s: %w", entry.Task.ID, err)
		}
	}
	return nil
}

func taskResultOutboxDir(cfg agentConfig) (string, error) {
	base := strings.TrimSpace(cfg.TaskOutboxDir)
	if base == "" {
		base = strings.TrimSpace(cfg.LogStateDir)
	}
	if base == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(cacheDir, "lattice-agent")
	}
	nodeHash := sha256.Sum256([]byte(cfg.Server + "\x00" + cfg.NodeID))
	return filepath.Join(base, "task-outbox", fmt.Sprintf("%x", nodeHash[:])), nil
}

func linechainTransactionDir(cfg agentConfig) (string, error) {
	dir := strings.TrimSpace(cfg.LinechainTxnDir)
	if dir == "" {
		base := strings.TrimSpace(cfg.LogStateDir)
		if base == "" {
			cacheDir, err := os.UserCacheDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(cacheDir, "lattice-agent")
		}
		dir = filepath.Join(base, "linechain-txn")
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || dir == string(filepath.Separator) {
		return "", fmt.Errorf("linechain transaction directory must be absolute and non-root")
	}
	return dir, nil
}

func postAgentJSON(cfg agentConfig, path string, payload map[string]any, out any) error {
	return postAgentJSONContext(context.Background(), cfg, path, payload, out)
}

func postAgentJSONContext(ctx context.Context, cfg agentConfig, path string, payload map[string]any, out any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["node_id"] = cfg.NodeID
	debugf(cfg, "agent post start: path=%s keys=%s", path, strings.Join(payloadKeys(payload), ","))
	if err := postJSONContext(ctx, cfg.Server+path, cfg.Token, payload, out); err != nil {
		debugf(cfg, "agent post failed: path=%s err=%v", path, err)
		return err
	}
	debugf(cfg, "agent post ok: path=%s", path)
	return nil
}

func payloadKeys(payload map[string]any) []string {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func debugf(cfg agentConfig, format string, args ...any) {
	if !cfg.Debug {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Printf("debug: %s", msg)
	if cfg.DebugCollect && cfg.DebugSink != nil {
		cfg.DebugSink.append(msg, cfg.DebugMaxLineBytes)
	}
}

type debugSink struct {
	mu       sync.Mutex
	maxLines int
	lines    []string
}

func newDebugSink(maxLines int) *debugSink {
	if maxLines <= 0 {
		maxLines = debugSinkMaxLines
	}
	return &debugSink{maxLines: maxLines}
}

func (s *debugSink) append(line string, maxBytes int) {
	if s == nil {
		return
	}
	if maxBytes <= 0 {
		maxBytes = defaultDebugMaxLineBytes
	}
	if len(line) > maxBytes {
		line = line[:maxBytes] + "...truncated"
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	if over := len(s.lines) - s.maxLines; over > 0 {
		s.lines = s.lines[over:]
	}
}

func (s *debugSink) drain(maxLines int) []string {
	if s == nil {
		return nil
	}
	if maxLines <= 0 {
		maxLines = defaultDebugMaxBatchLines
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.lines) == 0 {
		return nil
	}
	n := len(s.lines)
	if n > maxLines {
		n = maxLines
	}
	out := append([]string(nil), s.lines[:n]...)
	s.lines = append([]string(nil), s.lines[n:]...)
	return out
}

func (s *debugSink) prepend(lines []string) {
	if s == nil || len(lines) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	combined := append(append([]string(nil), lines...), s.lines...)
	if over := len(combined) - s.maxLines; over > 0 {
		combined = combined[over:]
	}
	s.lines = combined
}

func (s *debugSink) clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = nil
}

func flushDebugEvents(cfg agentConfig) error {
	if !cfg.DebugCollect || cfg.DebugSink == nil {
		return nil
	}
	lines := cfg.DebugSink.drain(cfg.DebugMaxBatchLines)
	if len(lines) == 0 {
		return nil
	}
	batch := model.AgentDebugBatch{
		NodeID:     cfg.NodeID,
		Lines:      lines,
		CapturedAt: time.Now().UTC(),
	}
	if err := postAgentDebugBatch(cfg, batch); err != nil {
		cfg.DebugSink.prepend(lines)
		return err
	}
	return nil
}

func postAgentDebugBatch(cfg agentConfig, batch model.AgentDebugBatch) error {
	data, err := json.Marshal(map[string]any{"node_id": cfg.NodeID, "batch": batch})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.Server+"/api/agent/debug-events", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return agentHTTPError(resp, "post agent debug batch")
	}
	return nil
}

func postJSON(url string, bearerToken string, payload any, out any) error {
	return postJSONContext(context.Background(), url, bearerToken, payload, out)
}

func postJSONContext(ctx context.Context, url string, bearerToken string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
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
		return agentHTTPError(resp, "post "+req.URL.Path)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func selfcheckControlPlane(server string) error {
	return selfcheckControlPlaneWithClient(server, httpClient)
}

func selfcheckControlPlaneWithClient(server string, client *http.Client) error {
	server = strings.TrimRight(server, "/")
	if server == "" {
		return fmt.Errorf("server URL is required")
	}
	req, err := http.NewRequest(http.MethodGet, server+"/api/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentHTTPError(resp, "selfcheck control plane")
	}
	return nil
}

type nftDomainSetConfig struct {
	Host   string
	Family string
	Table  string
	Set    string
	Set6   string
}

type nftDomainResolver func(context.Context, string) ([]string, error)
type nftCommandRunner func(context.Context, ...string) error

var (
	nftIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	dnsHostRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

func updateNFTDomainSet(ctx context.Context, cfg nftDomainSetConfig, resolver nftDomainResolver, runner nftCommandRunner) error {
	host, err := normalizeNFTDomainHost(cfg.Host)
	if err != nil {
		return err
	}
	if err := validateNFTSetTarget(cfg); err != nil {
		return err
	}
	addrs, err := resolver(ctx, host)
	if err != nil {
		return err
	}
	ipv4 := uniqueSortedIPs(addrs, 4)
	ipv6 := uniqueSortedIPs(addrs, 6)
	switch {
	case cfg.Set != "" && cfg.Set6 != "":
		if len(ipv4)+len(ipv6) == 0 {
			return fmt.Errorf("no A or AAAA records resolved for %s", host)
		}
	case cfg.Set != "":
		if len(ipv4) == 0 {
			return fmt.Errorf("no IPv4 A records resolved for %s", host)
		}
	case cfg.Set6 != "":
		if len(ipv6) == 0 {
			return fmt.Errorf("no IPv6 AAAA records resolved for %s", host)
		}
	}
	if cfg.Set != "" {
		if err := updateNFTSet(ctx, runner, cfg.Family, cfg.Table, cfg.Set, ipv4); err != nil {
			return err
		}
	}
	if cfg.Set6 != "" {
		if err := updateNFTSet(ctx, runner, cfg.Family, cfg.Table, cfg.Set6, ipv6); err != nil {
			return err
		}
	}
	return nil
}

func normalizeNFTDomainHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || len(host) > 253 || !dnsHostRe.MatchString(host) {
		return "", fmt.Errorf("invalid hostname %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 {
			return "", fmt.Errorf("invalid hostname %q: label too long", host)
		}
	}
	return host, nil
}

func validateNFTSetTarget(cfg nftDomainSetConfig) error {
	switch cfg.Family {
	case "inet", "ip", "ip6":
	default:
		return fmt.Errorf("unsupported nft family %q", cfg.Family)
	}
	if cfg.Set == "" && cfg.Set6 == "" {
		return fmt.Errorf("at least one nft set is required")
	}
	if cfg.Family == "ip" && cfg.Set6 != "" {
		return fmt.Errorf("IPv6 set requires nft family inet or ip6")
	}
	if cfg.Family == "ip6" && cfg.Set != "" {
		return fmt.Errorf("IPv4 set requires nft family inet or ip")
	}
	if !nftIdentRe.MatchString(cfg.Table) {
		return fmt.Errorf("invalid nft table %q", cfg.Table)
	}
	if cfg.Set != "" && !nftIdentRe.MatchString(cfg.Set) {
		return fmt.Errorf("invalid nft set %q", cfg.Set)
	}
	if cfg.Set6 != "" && !nftIdentRe.MatchString(cfg.Set6) {
		return fmt.Errorf("invalid nft set %q", cfg.Set6)
	}
	return nil
}

func lookupIPAddrs(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if parsed := ip.IP; parsed != nil {
			out = append(out, parsed.String())
		}
	}
	return out, nil
}

func updateNFTSet(ctx context.Context, runner nftCommandRunner, family, table, set string, addrs []string) error {
	if err := runner(ctx, "flush", "set", family, table, set); err != nil {
		return err
	}
	if len(addrs) == 0 {
		return nil
	}
	return runner(ctx, "add", "element", family, table, set, "{ "+strings.Join(addrs, ", ")+" }")
}

func uniqueSortedIPs(values []string, version int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			continue
		}
		var canonical string
		switch version {
		case 4:
			if ip.To4() == nil {
				continue
			}
			canonical = ip.To4().String()
		case 6:
			if ip.To4() != nil || ip.To16() == nil {
				continue
			}
			canonical = ip.To16().String()
		default:
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Slice(out, func(i, j int) bool {
		if version == 4 {
			return bytes.Compare(net.ParseIP(out[i]).To4(), net.ParseIP(out[j]).To4()) < 0
		}
		return bytes.Compare(net.ParseIP(out[i]).To16(), net.ParseIP(out[j]).To16()) < 0
	})
	return out
}

func runNFTCommand(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
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

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
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
