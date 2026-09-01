// Package guardreality collects the read-only node facts NetGuard uses for
// reality-first firewall authoring. The package only observes host state; it
// never mutates nftables, interfaces, or processes.
package guardreality

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	defaultTimeout = 5 * time.Second
	maxOutputBytes = 1 << 20
	managedFamily  = "inet"
	managedTable   = "lattice_guard"
)

// Runner executes one command without a shell. Tests inject it so parser
// coverage never depends on the local host's nftables, ss, or ip state.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Source configures guard reality collection.
type Source struct {
	SSBinary  string
	IPBinary  string
	NFTBinary string
	Timeout   time.Duration
	Now       func() time.Time
	Runner    Runner
}

// CollectManagedTableSHA reads the current nftables ruleset and returns the
// canonical hash of the managed inet lattice_guard table. It fails closed when
// the command, JSON parsing, or managed-table lookup fails.
func CollectManagedTableSHA(ctx context.Context, source Source) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	run := source.Runner
	if run == nil {
		run = runBoundedCommand
	}
	nftBinary := firstNonEmpty(source.NFTBinary, "nft")

	rulesetOut, err := runStep(ctx, timeout, run, nftBinary, "-j", "list", "ruleset")
	if err != nil {
		return "", err
	}
	managedSHA, _, err := ParseNFTRuleset(rulesetOut)
	if err != nil {
		return "", fmt.Errorf("parse nft ruleset: %w", err)
	}
	if managedSHA == "" {
		return "", fmt.Errorf("managed nft table %s %s not found", managedFamily, managedTable)
	}
	hasContent, err := managedTableHasContent(rulesetOut)
	if err != nil {
		return "", fmt.Errorf("inspect managed nft table: %w", err)
	}
	if !hasContent {
		return "", fmt.Errorf("managed nft table %s %s is empty", managedFamily, managedTable)
	}
	return managedSHA, nil
}

func managedTableHasContent(raw []byte) (bool, error) {
	var payload struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &payload); err != nil {
		return false, err
	}
	for _, entry := range payload.NFTables {
		for kind, rawBody := range entry {
			if kind == "table" {
				continue
			}
			body, ok := rawBody.(map[string]any)
			if ok && nftObjectBelongsToManaged(kind, body) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Collect runs the read-only guard reality commands and normalizes their output
// into the shared SDK model. The caller-supplied node id wins over anything a
// command could report.
func Collect(ctx context.Context, source Source, nodeID string) (model.GuardNodeReality, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return model.GuardNodeReality{}, fmt.Errorf("node id is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	run := source.Runner
	if run == nil {
		run = runBoundedCommand
	}
	ssBinary := firstNonEmpty(source.SSBinary, "ss")
	ipBinary := firstNonEmpty(source.IPBinary, "ip")
	nftBinary := firstNonEmpty(source.NFTBinary, "nft")

	ssOut, err := runStep(ctx, timeout, run, ssBinary, "-tulpnH")
	if err != nil {
		return model.GuardNodeReality{}, err
	}
	listeners, err := ParseSSListeners(ssOut)
	if err != nil {
		return model.GuardNodeReality{}, fmt.Errorf("parse ss listeners: %w", err)
	}

	ipOut, err := runStep(ctx, timeout, run, ipBinary, "-j", "addr")
	if err != nil {
		return model.GuardNodeReality{}, err
	}
	interfaces, err := ParseIPAddr(ipOut)
	if err != nil {
		return model.GuardNodeReality{}, fmt.Errorf("parse ip addr: %w", err)
	}

	rulesetOut, err := runStep(ctx, timeout, run, nftBinary, "-j", "list", "ruleset")
	if err != nil {
		return model.GuardNodeReality{}, err
	}
	managedSHA, foreignTables, err := ParseNFTRuleset(rulesetOut)
	if err != nil {
		return model.GuardNodeReality{}, fmt.Errorf("parse nft ruleset: %w", err)
	}

	versionOut, err := runStep(ctx, timeout, run, nftBinary, "--version")
	if err != nil {
		return model.GuardNodeReality{}, err
	}
	at := time.Now().UTC()
	if source.Now != nil {
		at = source.Now().UTC()
	}
	return model.GuardNodeReality{
		NodeID:        nodeID,
		Listeners:     listeners,
		Interfaces:    interfaces,
		ManagedSHA:    managedSHA,
		ForeignTables: foreignTables,
		NFTVersion:    ParseNFTVersion(versionOut),
		CollectedAt:   at,
	}, nil
}

func runStep(ctx context.Context, timeout time.Duration, run Runner, name string, args ...string) ([]byte, error) {
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := run(stepCtx, name, args...)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

var ssProcessRe = regexp.MustCompile(`\(\("([^"]+)"`)

// ParseSSListeners parses `ss -tulpnH` output into deterministic listener facts.
func ParseSSListeners(raw []byte) ([]model.GuardListener, error) {
	lines := strings.Split(string(raw), "\n")
	seen := map[string]struct{}{}
	out := make([]model.GuardListener, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr, port, ok := parseHostPort(fields[4])
		if !ok || port <= 0 || port > 65535 {
			continue
		}
		process := ""
		if match := ssProcessRe.FindStringSubmatch(line); len(match) == 2 {
			process = trimBounded(match[1], 128)
		}
		listener := model.GuardListener{
			Protocol: proto,
			Port:     port,
			Address:  trimBounded(addr, 256),
			Process:  process,
		}
		key := fmt.Sprintf("%s/%d/%s/%s", listener.Protocol, listener.Port, listener.Address, listener.Process)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, listener)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Process < out[j].Process
	})
	return out, nil
}

func parseHostPort(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	var host, portText string
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end < 0 {
			return "", 0, false
		}
		host = value[1:end]
		portText = value[end+2:]
	} else {
		idx := strings.LastIndex(value, ":")
		if idx < 0 {
			return "", 0, false
		}
		host = value[:idx]
		portText = value[idx+1:]
	}
	if zone := strings.LastIndex(host, "%"); zone >= 0 {
		host = host[:zone]
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil {
		return "", 0, false
	}
	return strings.TrimSpace(host), port, true
}

type ipAddrEntry struct {
	IfName    string       `json:"ifname"`
	Flags     []string     `json:"flags"`
	OperState string       `json:"operstate"`
	AddrInfo  []ipAddrInfo `json:"addr_info"`
}

type ipAddrInfo struct {
	Local     string `json:"local"`
	PrefixLen *int   `json:"prefixlen"`
}

// ParseIPAddr parses `ip -j addr` output.
func ParseIPAddr(raw []byte) ([]model.GuardInterface, error) {
	var entries []ipAddrEntry
	if err := json.Unmarshal(bytes.TrimSpace(raw), &entries); err != nil {
		return nil, err
	}
	out := make([]model.GuardInterface, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.IfName)
		if name == "" {
			continue
		}
		addresses := make([]string, 0, len(entry.AddrInfo))
		for _, addr := range entry.AddrInfo {
			local := strings.TrimSpace(addr.Local)
			ip := net.ParseIP(local)
			if ip == nil {
				continue
			}
			canonical := ip.String()
			maxPrefix := 128
			if ip.To4() != nil {
				maxPrefix = 32
			}
			if addr.PrefixLen != nil && *addr.PrefixLen >= 0 && *addr.PrefixLen <= maxPrefix {
				canonical = fmt.Sprintf("%s/%d", canonical, *addr.PrefixLen)
			}
			addresses = append(addresses, canonical)
		}
		sort.Strings(addresses)
		out = append(out, model.GuardInterface{
			Name:      trimBounded(name, 128),
			Addresses: uniqueStrings(addresses),
			Up:        ifaceIsUp(entry),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func ifaceIsUp(entry ipAddrEntry) bool {
	for _, flag := range entry.Flags {
		if strings.EqualFold(flag, "UP") {
			return true
		}
	}
	return strings.EqualFold(entry.OperState, "UP")
}

// ParseNFTRuleset parses `nft -j list ruleset`, returning a deterministic hash
// of the managed lattice_guard table and sorted summaries of foreign tables.
func ParseNFTRuleset(raw []byte) (string, []string, error) {
	var payload struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &payload); err != nil {
		return "", nil, err
	}
	foreign := map[string]struct{}{}
	managedObjects := make([]map[string]any, 0)
	for _, entry := range payload.NFTables {
		for kind, rawBody := range entry {
			body, ok := rawBody.(map[string]any)
			if !ok {
				continue
			}
			if kind == "table" {
				family := stringField(body, "family")
				name := stringField(body, "name")
				if family == "" || name == "" {
					continue
				}
				if family != managedFamily || name != managedTable {
					foreign[family+" "+name] = struct{}{}
					continue
				}
			}
			if nftObjectBelongsToManaged(kind, body) {
				managedObjects = append(managedObjects, map[string]any{
					kind: stripNFTVolatile(body),
				})
			}
		}
	}
	foreignTables := make([]string, 0, len(foreign))
	for table := range foreign {
		foreignTables = append(foreignTables, table)
	}
	sort.Strings(foreignTables)
	if len(managedObjects) == 0 {
		return "", foreignTables, nil
	}
	encoded, err := json.Marshal(managedObjects)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), foreignTables, nil
}

func nftObjectBelongsToManaged(kind string, body map[string]any) bool {
	family := stringField(body, "family")
	switch kind {
	case "table":
		return family == managedFamily && stringField(body, "name") == managedTable
	default:
		return family == managedFamily && stringField(body, "table") == managedTable
	}
}

func stripNFTVolatile(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if key == "handle" {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out[key] = stripNFTVolatile(typed[key])
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, stripNFTVolatile(item))
		}
		return out
	default:
		return typed
	}
}

func stringField(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return strings.TrimSpace(value)
}

// ParseNFTVersion normalizes `nft --version` output for display.
func ParseNFTVersion(raw []byte) string {
	line := ""
	for _, candidate := range strings.Split(string(raw), "\n") {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			line = candidate
			break
		}
	}
	return trimBounded(line, 128)
}

// RunBoundedCommand is the production Runner: no shell, bounded output. It is
// exported so sibling read-only probes (singboxlive, design-19) execute
// commands under exactly the same discipline instead of growing their own.
var RunBoundedCommand Runner = runBoundedCommand

func runBoundedCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout limitedBuffer
	var stderr limitedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%w: %s", err, trimBounded(msg, 512))
		}
		return nil, err
	}
	if stdout.Truncated() {
		return nil, fmt.Errorf("%s output exceeded %d bytes", name, maxOutputBytes)
	}
	if stderr.Truncated() {
		return nil, fmt.Errorf("%s stderr exceeded %d bytes", name, maxOutputBytes)
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() < maxOutputBytes {
		remaining := maxOutputBytes - b.buf.Len()
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}

var _ io.Writer = (*limitedBuffer)(nil)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func trimBounded(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}
