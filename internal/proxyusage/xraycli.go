package proxyusage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	defaultXrayBinary       = "xray"
	defaultXrayStatsPattern = "user>>>"
	defaultXrayCLITimeout   = 5 * time.Second
	maxXrayStderrBytes      = 4096
)

// XrayCLISource collects proxy usage by invoking the on-node `xray` binary's
// `api statsquery` subcommand. The gRPC call to xray's StatsService stays inside
// the xray process, so the agent gains no gRPC dependency and remains pure-Go /
// zero-CGo (see ADR-003). The query is read-only — it never passes -reset — so
// the server keeps ownership of monotonic diffing, eligibility, and audit.
//
// The API address must be loopback: a node must not be configured into dialing
// arbitrary networks, mirroring the loopback rule on the HTTP source.
type XrayCLISource struct {
	Binary  string        // xray binary: bare command on PATH or absolute path; default "xray"
	APIAddr string        // loopback host:port of the xray API (gRPC) inbound
	Pattern string        // optional stat-name filter; default "user>>>"
	Timeout time.Duration // per-invocation timeout; default 5s
	Now     func() time.Time

	// runner is a test seam; production uses runBoundedCommand.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ValidateXrayCLISource checks the binary, loopback API address, and pattern
// without executing anything, so the agent can fail fast at startup.
func ValidateXrayCLISource(source XrayCLISource) error {
	if _, err := validateXrayBinary(source.Binary); err != nil {
		return err
	}
	if _, err := validateLoopbackHostPort(source.APIAddr); err != nil {
		return err
	}
	if pattern := strings.TrimSpace(source.Pattern); pattern != "" {
		if err := validateXrayStatsPattern(pattern); err != nil {
			return err
		}
	}
	return nil
}

// LoadXrayCLI runs one read-only xray stats query and normalizes it into a
// server-ingestible snapshot. An empty stats set (a freshly started core with no
// traffic yet) is a valid empty snapshot, not an error.
func LoadXrayCLI(ctx context.Context, source XrayCLISource, nodeID string) (model.ProxyUsageSnapshot, error) {
	binary, err := validateXrayBinary(source.Binary)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	addr, err := validateLoopbackHostPort(source.APIAddr)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	pattern := strings.TrimSpace(source.Pattern)
	if pattern == "" {
		pattern = defaultXrayStatsPattern
	}
	if err := validateXrayStatsPattern(pattern); err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultXrayCLITimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runner := source.runner
	if runner == nil {
		runner = runBoundedCommand
	}
	// Arguments are passed as an exec arg-vector (no shell), so the validated
	// address and pattern cannot inject commands.
	out, err := runner(ctx, binary, "api", "statsquery", "--server="+addr, "-pattern", pattern, "-reset=false")
	if err != nil {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("xray api statsquery: %w", err)
	}
	return decodeXrayStats(out, nodeID, now(source.Now))
}

// decodeXrayStats parses xray's `{"stat":[{"name":...,"value":...}]}` output.
// xray's protojson encoding emits int64 values as strings; the shared
// int64String/v2rayUserFromStatName helpers already tolerate both.
func decodeXrayStats(data []byte, nodeID string, at time.Time) (model.ProxyUsageSnapshot, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		// No output at all is treated as "no traffic yet", not a hard failure.
		return NormalizeSnapshot(model.ProxyUsageSnapshot{UserBytes: map[string]int64{}}, nodeID, at)
	}
	var payload struct {
		Stat json.RawMessage `json:"stat"`
	}
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("decode xray stats: %w", err)
	}
	if len(bytes.TrimSpace(payload.Stat)) == 0 || string(bytes.TrimSpace(payload.Stat)) == "null" {
		return NormalizeSnapshot(model.ProxyUsageSnapshot{UserBytes: map[string]int64{}}, nodeID, at)
	}
	return decodeV2RayStats(payload.Stat, nodeID, at)
}

func runBoundedCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &cappedBuffer{limit: maxUsageFileBytes}
	stderr := &cappedBuffer{limit: maxXrayStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.buf.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	if stdout.overflow {
		return nil, fmt.Errorf("xray stats output exceeds %d bytes", maxUsageFileBytes)
	}
	return stdout.buf.Bytes(), nil
}

// cappedBuffer records up to limit bytes and then silently discards the rest,
// flagging overflow. It always reports a full write so the child process is not
// killed by a short-write error; the caller inspects overflow afterwards.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.overflow {
		return len(p), nil
	}
	remaining := c.limit - int64(c.buf.Len())
	if remaining <= 0 {
		c.overflow = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		c.buf.Write(p[:remaining])
		c.overflow = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func validateXrayBinary(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultXrayBinary, nil
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return "", fmt.Errorf("xray binary contains control characters")
		}
	}
	// Reject shell metacharacters and whitespace. The binary is run via an
	// exec arg-vector (no shell), but constraining it avoids surprising PATH
	// lookups and keeps the value auditable. Absolute paths ("/usr/local/bin/xray")
	// and bare names ("xray") both pass.
	if strings.ContainsAny(value, " \t\n\"'`$;&|<>(){}[]*?!~\\") {
		return "", fmt.Errorf("xray binary contains unsafe characters")
	}
	return value, nil
}

func validateLoopbackHostPort(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("xray api address is required")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("xray api address must be host:port: %w", err)
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("xray api address host must be loopback")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("xray api address has invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

func validateXrayStatsPattern(value string) error {
	if len(value) > 128 {
		return fmt.Errorf("xray stats pattern is too long")
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return fmt.Errorf("xray stats pattern contains control characters")
		}
	}
	return nil
}
