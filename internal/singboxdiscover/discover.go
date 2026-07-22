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
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	defaultBinary  = "sb"
	defaultTimeout = 8 * time.Second
	maxOutputBytes = 1 << 20 // 1 MiB
	// defaultMetaPath is the design-15 sidecar written by the server/sb next to
	// (never inside) the sing-box -C directory; sing-box itself never reads it.
	defaultMetaPath = "/etc/sing-box/lattice-metadata.json"
	// maxInspectCalls bounds the per-line `sb --json inspect <name>` enrichment
	// so a large fleet cannot stretch the discovery cycle.
	maxInspectCalls            = 64
	maxInspectWorkers          = 4
	defaultInspectTotalTimeout = 2 * time.Second
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
	// MetaPath is the design-15 sidecar path; default
	// /etc/sing-box/lattice-metadata.json (LATTICE_SINGBOX_META in the agent).
	MetaPath string
	// MaxInspect bounds per-line `sb --json inspect` enrichment calls; default 64.
	MaxInspect int
	// Logf receives best-effort degradation notes (unavailable inspect, corrupt
	// sidecar); default log.Printf. Discovery never fails on these.
	Logf func(format string, args ...any)
	// Now is a test seam.
	Now func() time.Time
	// runner is a test seam; production uses runBoundedCommand.
	runner func(ctx context.Context, name string, args ...string) ([]byte, error)
	// runtimeFiles/readFile are test seams for the sing-box runtime config
	// fallback. Production discovers files from the running process/system
	// defaults and reads them directly.
	runtimeFiles func() []string
	readFile     func(string) ([]byte, error)
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
		if fallback, fallbackErr := discoverRuntimeConfig(source, nodeID, at); fallbackErr == nil {
			return fallback, nil
		}
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
		if fallback, fallbackErr := discoverRuntimeConfig(source, nodeID, at); fallbackErr == nil {
			return fallback, nil
		}
		inv.Status = "error"
		inv.Error = "decode list: " + boundedErr(err)
		return inv, fmt.Errorf("decode sb list: %w", err)
	}
	if listResp.Nodes != nil {
		inv.Nodes = listResp.Nodes
	}
	// `sb --json list` emits only per-inbound fields — no outbound/routing and no
	// `_lattice`. Best-effort enrich, first via per-line `sb --json inspect
	// <name>` (bounded; sb builds predating the subcommand degrade silently),
	// then from the on-box config (matched by inbound tag), which also resolves
	// the outbound server/port that inspect does not carry. Neither overwrites a
	// value sb already provided; both skip quietly when their source is missing.
	enrichSingBoxNodesFromInspect(ctx, source, run, binary, base, timeout, inv.Nodes)
	enrichSingBoxNodesFromConfig(source, inv.Nodes)
	// design-15 sidecar annotations (line_uuid + declared chain edges), joined by
	// inbound tag. Read-only: a missing/corrupt file never fails discovery.
	applySingBoxSidecar(source, inv.Nodes)

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

func discoverRuntimeConfig(source Source, nodeID string, at time.Time) (model.SingBoxInventory, error) {
	configs := loadSingBoxRuntimeConfigFiles(source)
	if len(configs) == 0 {
		return model.SingBoxInventory{}, fmt.Errorf("no readable sing-box runtime config files found")
	}
	routeMap := singBoxRouteMap(configs)
	outboundMap := singBoxOutboundMap(configs)
	inv := model.SingBoxInventory{NodeID: nodeID, At: at.UTC(), Status: "ok", Nodes: []model.SingBoxNode{}}
	for _, parsed := range configs {
		inv.Nodes = append(inv.Nodes, parseSingBoxRuntimeConfig(parsed.path, parsed.cfg, routeMap, outboundMap, strings.TrimSpace(source.Addr))...)
	}
	if inv.Nodes == nil {
		inv.Nodes = []model.SingBoxNode{}
	}
	// The sidecar joins by inbound tag, so the config-fallback path annotates
	// exactly like the primary path.
	applySingBoxSidecar(source, inv.Nodes)
	return inv, nil
}

// loadSingBoxRuntimeConfigFiles locates and reads the on-box sing-box config
// files (the running process's -c/-C paths plus the /etc/sing-box defaults) and
// returns each one that parsed successfully. Returns an empty slice when none
// are found or readable. Both the config-FALLBACK path and the PRIMARY-path
// enrichment use this to recover the route/outbound/_lattice data that
// `sb --json list` omits.
func loadSingBoxRuntimeConfigFiles(source Source) []singBoxRuntimeConfigFile {
	filesFn := source.runtimeFiles
	if filesFn == nil {
		filesFn = singBoxRuntimeConfigFiles
	}
	readFn := source.readFile
	if readFn == nil {
		readFn = os.ReadFile
	}
	configs := []singBoxRuntimeConfigFile{}
	for _, path := range filesFn() {
		raw, err := readFn(path)
		if err != nil {
			continue
		}
		var cfg singBoxRuntimeConfig
		if err := json.Unmarshal(bytes.TrimSpace(raw), &cfg); err != nil {
			continue
		}
		configs = append(configs, singBoxRuntimeConfigFile{path: path, cfg: cfg})
	}
	return configs
}

type singBoxLatticeIdentity struct {
	LineID   string
	NodeUUID string
}

// singBoxLatticeByInbound indexes each inbound's `_lattice` identity (line_id /
// node_uuid) by inbound tag, so a primary-path node can recover its LineID /
// NodeIdentityUUID by matching node.Name to the inbound tag. Inbounds without a
// tag or without either identity value are skipped.
func singBoxLatticeByInbound(configs []singBoxRuntimeConfigFile) map[string]singBoxLatticeIdentity {
	out := map[string]singBoxLatticeIdentity{}
	for _, parsed := range configs {
		for _, in := range parsed.cfg.Inbounds {
			tag := strings.TrimSpace(in.Tag)
			if tag == "" {
				continue
			}
			ident := singBoxLatticeIdentity{
				LineID:   singBoxLatticeString(in.Lattice, "line_id"),
				NodeUUID: singBoxLatticeString(in.Lattice, "node_uuid"),
			}
			if ident.LineID == "" && ident.NodeUUID == "" {
				continue
			}
			out[tag] = ident
		}
	}
	return out
}

// enrichSingBoxNodesFromConfig augments PRIMARY-path (`sb --json list`) nodes
// with the route/outbound/_lattice data that the sb JSON does not carry. It
// reads the on-box config ONCE, matches each node by its inbound tag
// (node.Name == config inbound tag / filename), and fills only fields sb left
// empty — it NEVER overwrites a value sb already provided. Best-effort: if the
// config cannot be read, the sb data is returned unchanged.
func enrichSingBoxNodesFromConfig(source Source, nodes []model.SingBoxNode) {
	if len(nodes) == 0 {
		return
	}
	configs := loadSingBoxRuntimeConfigFiles(source)
	if len(configs) == 0 {
		return
	}
	routeMap := singBoxRouteMap(configs)
	outboundMap := singBoxOutboundMap(configs)
	latticeByInbound := singBoxLatticeByInbound(configs)
	for i := range nodes {
		tag := strings.TrimSpace(nodes[i].Name)
		if tag == "" {
			continue
		}
		if nodes[i].OutboundRef == "" {
			if ref, ok := routeMap[tag]; ok {
				nodes[i].OutboundRef = ref
			}
		}
		if nodes[i].OutboundRef != "" {
			// outboundMap already zeroes Server/ServerPort for terminal/logical
			// outbounds (direct/block/dns/selector/urltest), so those inbounds
			// keep an empty OutboundServer/OutboundPort.
			if ob, ok := outboundMap[nodes[i].OutboundRef]; ok {
				if nodes[i].OutboundServer == "" {
					nodes[i].OutboundServer = ob.Server
				}
				if nodes[i].OutboundPort == "" && ob.ServerPort > 0 {
					nodes[i].OutboundPort = strconv.Itoa(ob.ServerPort)
				}
				if nodes[i].OutboundType == "" {
					nodes[i].OutboundType = ob.Type
				}
			}
		}
		if ident, ok := latticeByInbound[tag]; ok {
			if nodes[i].LineID == "" {
				nodes[i].LineID = ident.LineID
			}
			if nodes[i].NodeIdentityUUID == "" {
				nodes[i].NodeIdentityUUID = ident.NodeUUID
			}
		}
	}
}

// sbInspectLine mirrors the `sb --json inspect <name>` line object (core.sh
// line_json_obj): outbound tag/protocol, user roster, and the _lattice identity
// that the plain list omits. The outbound server/port is NOT part of this
// shape — the config join resolves those from the outbound tag.
type sbInspectLine struct {
	Tag        string            `json:"tag"`
	ListenHost string            `json:"listen_host"`
	ListenPort int               `json:"listen_port"`
	Users      []json.RawMessage `json:"users"`
	Outbound   struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
	} `json:"outbound"`
	Metadata struct {
		LineID   string `json:"line_id"`
		NodeUUID string `json:"node_uuid"`
	} `json:"metadata"`
}

// enrichSingBoxNodesFromInspect fills the per-line fields `sb --json list`
// omits (outbound tag/type, _lattice identity, user roster) by calling
// `sb --json inspect <name>` once per line. Bounded in call count
// (Source.MaxInspect, default maxInspectCalls), concurrency, and one aggregate
// deadline, so it cannot stretch the discovery cycle. If the FIRST inspect call
// fails or returns non-JSON, the deployed sb predates the subcommand and the
// remaining lines are left to the config join instead. Fill-only-empty: a value
// sb already provided is never overwritten.
func enrichSingBoxNodesFromInspect(ctx context.Context, source Source, run func(context.Context, string, ...string) ([]byte, error), binary string, base []string, timeout time.Duration, nodes []model.SingBoxNode) {
	maxInspect := source.MaxInspect
	if maxInspect <= 0 {
		maxInspect = maxInspectCalls
	}
	type candidate struct {
		index int
		name  string
	}
	candidates := make([]candidate, 0, maxInspect)
	for i := range nodes {
		if len(candidates) >= maxInspect {
			break
		}
		name := strings.TrimSpace(nodes[i].Name)
		if name == "" {
			continue
		}
		// A newer sb already emits these fields in the list; don't spend an
		// inspect call re-reading them.
		if nodes[i].OutboundRef != "" && nodes[i].LineID != "" && nodes[i].UserKnown {
			continue
		}
		candidates = append(candidates, candidate{index: i, name: name})
	}
	if len(candidates) == 0 {
		return
	}
	totalTimeout := timeout
	if totalTimeout <= 0 || totalTimeout > defaultInspectTotalTimeout {
		totalTimeout = defaultInspectTotalTimeout
	}
	inspectCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	inspect := func(c candidate) (sbInspectLine, error) {
		out, err := run(inspectCtx, binary, append(append([]string(nil), base...), "inspect", c.name)...)
		if err != nil {
			return sbInspectLine{}, err
		}
		var resp struct {
			Line sbInspectLine `json:"line"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
			return sbInspectLine{}, fmt.Errorf("decode inspect: %w", err)
		}
		return resp.Line, nil
	}
	apply := func(i int, line sbInspectLine) {
		if nodes[i].ListenHost == "" {
			nodes[i].ListenHost = strings.TrimSpace(line.ListenHost)
		}
		if nodes[i].Port == "" && line.ListenPort > 0 {
			nodes[i].Port = strconv.Itoa(line.ListenPort)
		}
		if nodes[i].OutboundRef == "" {
			nodes[i].OutboundRef = strings.TrimSpace(line.Outbound.Tag)
		}
		if nodes[i].OutboundType == "" {
			nodes[i].OutboundType = strings.TrimSpace(line.Outbound.Protocol)
		}
		if nodes[i].LineID == "" {
			nodes[i].LineID = strings.TrimSpace(line.Metadata.LineID)
		}
		if nodes[i].NodeIdentityUUID == "" {
			nodes[i].NodeIdentityUUID = strings.TrimSpace(line.Metadata.NodeUUID)
		}
		if !nodes[i].UserKnown && line.Users != nil {
			nodes[i].UserCount = len(line.Users)
			nodes[i].UserKnown = true
		}
	}

	// Probe once before launching workers. Old sb builds lack `inspect`; this
	// keeps their one-call degradation behavior while allowing supported builds
	// to enrich the remaining fleet concurrently under one discovery deadline.
	first, err := inspect(candidates[0])
	if err != nil {
		logf(source, "sing-box inspect unavailable (%v); continuing without per-line inspect enrichment", boundedErr(err))
		return
	}
	apply(candidates[0].index, first)
	if len(candidates) == 1 {
		return
	}

	jobs := make(chan candidate)
	type result struct {
		candidate candidate
		line      sbInspectLine
		err       error
	}
	results := make(chan result, len(candidates)-1)
	workers := maxInspectWorkers
	if workers > len(candidates)-1 {
		workers = len(candidates) - 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for c := range jobs {
				line, err := inspect(c)
				results <- result{candidate: c, line: line, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, c := range candidates[1:] {
			select {
			case jobs <- c:
			case <-inspectCtx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	for r := range results {
		if r.err == nil {
			apply(r.candidate.index, r.line)
		}
	}
}

// singBoxSidecar mirrors the design-15 sidecar (lattice.singbox-metadata.v2).
// Only the join fields are decoded; unknown keys are the writer's business.
// v1 sidecars (flat object, no schema marker / inbounds array) carry no
// per-line data: they are accepted and ignored, exactly like a missing file.
type singBoxSidecar struct {
	Schema   string `json:"schema"`
	Inbounds []struct {
		Tag      string `json:"tag"`
		LineUUID string `json:"line_uuid"`
		Chain    *struct {
			DownstreamLineUUID *string `json:"downstream_line_uuid"`
		} `json:"chain"`
	} `json:"inbounds"`
}

// applySingBoxSidecar annotates discovered nodes with the design-15 line
// identity (line_uuid) and the declared chain edge (downstream_line_uuid,
// null in the file means single-exit and stays empty), joined by inbound tag
// (node.Name == sidecar inbounds[].tag). Degrades quietly: a missing file or a
// legacy v1 sidecar leaves every field empty; a corrupt file is logged and
// skipped. The sidecar is a read-only annotation and must never fail discovery.
func applySingBoxSidecar(source Source, nodes []model.SingBoxNode) {
	if len(nodes) == 0 {
		return
	}
	metaPath := strings.TrimSpace(source.MetaPath)
	if metaPath == "" {
		metaPath = defaultMetaPath
	}
	readFn := source.readFile
	if readFn == nil {
		readFn = os.ReadFile
	}
	raw, err := readFn(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return // no sidecar on this node: nothing to annotate
		}
		logf(source, "sing-box sidecar %s unreadable (%v); reporting base inventory", metaPath, boundedErr(err))
		return
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	var meta singBoxSidecar
	if err := json.Unmarshal(raw, &meta); err != nil {
		logf(source, "sing-box sidecar %s unreadable (%v); reporting base inventory", metaPath, boundedErr(err))
		return
	}
	if meta.Schema == "" {
		return // legacy v1 flat sidecar: no per-line annotations
	}
	if err := validateSingBoxSidecar(meta); err != nil {
		logf(source, "sing-box sidecar %s invalid (%v); reporting base inventory", metaPath, boundedErr(err))
		return
	}
	type sidecarLine struct {
		lineUUID           string
		downstreamLineUUID string
	}
	byTag := map[string]sidecarLine{}
	for _, in := range meta.Inbounds {
		tag := strings.TrimSpace(in.Tag)
		if tag == "" {
			continue
		}
		entry := sidecarLine{lineUUID: strings.TrimSpace(in.LineUUID)}
		if in.Chain != nil && in.Chain.DownstreamLineUUID != nil {
			entry.downstreamLineUUID = strings.TrimSpace(*in.Chain.DownstreamLineUUID)
		}
		byTag[tag] = entry
	}
	for i := range nodes {
		entry, ok := byTag[strings.TrimSpace(nodes[i].Name)]
		if !ok {
			continue
		}
		if nodes[i].LineUUID == "" {
			nodes[i].LineUUID = entry.lineUUID
		}
		if nodes[i].DownstreamLineUUID == "" {
			nodes[i].DownstreamLineUUID = entry.downstreamLineUUID
		}
	}
}

func validateSingBoxSidecar(meta singBoxSidecar) error {
	if meta.Schema != "lattice.singbox-metadata.v2" {
		return fmt.Errorf("unsupported schema %q", meta.Schema)
	}
	byTag := make(map[string]struct{}, len(meta.Inbounds))
	byUUID := make(map[string]struct{}, len(meta.Inbounds))
	next := make(map[string]string, len(meta.Inbounds))
	for _, in := range meta.Inbounds {
		tag := strings.TrimSpace(in.Tag)
		lineUUID := strings.ToLower(strings.TrimSpace(in.LineUUID))
		if tag == "" || !isUUIDv4(lineUUID) {
			return fmt.Errorf("inbound has invalid tag or line_uuid")
		}
		if _, exists := byTag[tag]; exists {
			return fmt.Errorf("duplicate inbound tag %q", tag)
		}
		if _, exists := byUUID[lineUUID]; exists {
			return fmt.Errorf("duplicate line_uuid %q", lineUUID)
		}
		byTag[tag] = struct{}{}
		byUUID[lineUUID] = struct{}{}
		if in.Chain != nil && in.Chain.DownstreamLineUUID != nil {
			downstream := strings.ToLower(strings.TrimSpace(*in.Chain.DownstreamLineUUID))
			if !isUUIDv4(downstream) {
				return fmt.Errorf("inbound %q has invalid downstream_line_uuid", tag)
			}
			if downstream == lineUUID {
				return fmt.Errorf("inbound %q has a self-referential chain", tag)
			}
			next[lineUUID] = downstream
		}
	}
	for start := range next {
		seen := map[string]struct{}{}
		for current := start; current != ""; current = next[current] {
			if _, local := byUUID[current]; !local {
				break // a declared cross-node edge cannot be validated locally
			}
			if _, repeated := seen[current]; repeated {
				return fmt.Errorf("sidecar contains a local chain cycle")
			}
			seen[current] = struct{}{}
		}
	}
	return nil
}

func isUUIDv4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '4' {
		return false
	}
	if value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// logf routes a best-effort degradation note through the source's Logf seam
// (default log.Printf). Used only for non-fatal enrichment/annotation gaps.
func logf(source Source, format string, args ...any) {
	if source.Logf != nil {
		source.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func singBoxRuntimeConfigFiles() []string {
	seen := map[string]bool{}
	var out []string
	addFile := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		if st, err := os.Stat(clean); err == nil && !st.IsDir() {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	addDir := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		matches, _ := filepath.Glob(filepath.Join(filepath.Clean(path), "*.json"))
		sort.Strings(matches)
		for _, match := range matches {
			addFile(match)
		}
	}
	for _, args := range singBoxProcessArgs() {
		for i := 0; i < len(args); i++ {
			arg := args[i]
			switch arg {
			case "-c", "--config":
				if i+1 < len(args) {
					i++
					addFile(args[i])
				}
			case "-C", "--config-directory":
				if i+1 < len(args) {
					i++
					addDir(args[i])
				}
			default:
				if value, ok := strings.CutPrefix(arg, "-c="); ok {
					addFile(value)
				}
				if value, ok := strings.CutPrefix(arg, "--config="); ok {
					addFile(value)
				}
				if value, ok := strings.CutPrefix(arg, "-C="); ok {
					addDir(value)
				}
				if value, ok := strings.CutPrefix(arg, "--config-directory="); ok {
					addDir(value)
				}
			}
		}
	}
	addFile("/etc/sing-box/config.json")
	addDir("/etc/sing-box/conf")
	return out
}

func singBoxProcessArgs() [][]string {
	matches, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	var out [][]string
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) == 0 {
			continue
		}
		parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		args := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) > 0 {
				args = append(args, string(part))
			}
		}
		if len(args) == 0 {
			continue
		}
		base := filepath.Base(args[0])
		if strings.Contains(base, "sing-box") && containsArg(args, "run") {
			out = append(out, args)
		}
	}
	return out
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

type singBoxRuntimeConfig struct {
	Inbounds  []singBoxRuntimeInbound  `json:"inbounds"`
	Outbounds []singBoxRuntimeOutbound `json:"outbounds"`
	Route     *singBoxRuntimeRoute     `json:"route"`
}

type singBoxRuntimeConfigFile struct {
	path string
	cfg  singBoxRuntimeConfig
}

type singBoxRuntimeInbound struct {
	Tag        string                 `json:"tag"`
	Type       string                 `json:"type"`
	Listen     string                 `json:"listen"`
	ListenPort int                    `json:"listen_port"`
	Users      []json.RawMessage      `json:"users"`
	Lattice    map[string]any         `json:"_lattice"`
	TLS        *singBoxRuntimeTLS     `json:"tls"`
	Transport  *singBoxRuntimeNetwork `json:"transport"`
}

type singBoxRuntimeRoute struct {
	Rules []singBoxRuntimeRouteRule `json:"rules"`
}

type singBoxRuntimeRouteRule struct {
	Inbound  []string `json:"inbound"`
	Outbound string   `json:"outbound"`
	Action   string   `json:"action"`
}

type singBoxRuntimeOutbound struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type singBoxRuntimeNetwork struct {
	Type string `json:"type"`
}

type singBoxRuntimeTLS struct {
	Enabled    bool                   `json:"enabled"`
	ServerName string                 `json:"server_name"`
	Reality    *singBoxRuntimeReality `json:"reality"`
}

type singBoxRuntimeReality struct {
	Enabled   bool                         `json:"enabled"`
	Handshake *singBoxRuntimeRealityTarget `json:"handshake"`
}

type singBoxRuntimeRealityTarget struct {
	Server string `json:"server"`
}

func singBoxRouteMap(configs []singBoxRuntimeConfigFile) map[string]string {
	routes := map[string]string{}
	for _, parsed := range configs {
		if parsed.cfg.Route == nil {
			continue
		}
		for _, rule := range parsed.cfg.Route.Rules {
			outbound := strings.TrimSpace(rule.Outbound)
			if outbound == "" {
				continue
			}
			for _, inbound := range rule.Inbound {
				inbound = strings.TrimSpace(inbound)
				if inbound != "" {
					routes[inbound] = outbound
				}
			}
		}
	}
	return routes
}

// singBoxOutboundMap indexes every declared outbound by its tag across all config
// files so an inbound's outbound tag can be resolved to its downstream
// destination (server:port). Terminal/logical outbounds (direct/block/dns) and
// group outbounds (selector/urltest) carry no dest of their own — they still get
// recorded so the outbound type is known, but their Server/ServerPort stay empty.
func singBoxOutboundMap(configs []singBoxRuntimeConfigFile) map[string]singBoxRuntimeOutbound {
	outbounds := map[string]singBoxRuntimeOutbound{}
	for _, parsed := range configs {
		for _, ob := range parsed.cfg.Outbounds {
			tag := strings.TrimSpace(ob.Tag)
			if tag == "" {
				continue
			}
			ob.Tag = tag
			ob.Type = strings.TrimSpace(ob.Type)
			switch ob.Type {
			case "direct", "block", "dns", "selector", "urltest":
				ob.Server = ""
				ob.ServerPort = 0
			default:
				ob.Server = strings.TrimSpace(ob.Server)
			}
			outbounds[tag] = ob
		}
	}
	return outbounds
}

func parseSingBoxRuntimeConfig(path string, cfg singBoxRuntimeConfig, routeMap map[string]string, outboundMap map[string]singBoxRuntimeOutbound, addr string) []model.SingBoxNode {
	nodes := make([]model.SingBoxNode, 0, len(cfg.Inbounds))
	for _, in := range cfg.Inbounds {
		if strings.TrimSpace(in.Type) == "" && strings.TrimSpace(in.Tag) == "" && in.ListenPort == 0 {
			continue
		}
		name := strings.TrimSpace(in.Tag)
		if name == "" {
			name = filepath.Base(path)
		}
		network := ""
		if in.Transport != nil {
			network = strings.TrimSpace(in.Transport.Type)
		}
		sni := ""
		if in.TLS != nil {
			sni = strings.TrimSpace(in.TLS.ServerName)
			if sni == "" && in.TLS.Reality != nil && in.TLS.Reality.Handshake != nil {
				sni = strings.TrimSpace(in.TLS.Reality.Handshake.Server)
			}
			if network == "" && in.TLS.Reality != nil && in.TLS.Reality.Enabled {
				network = "reality"
			}
		}
		if network == "" {
			network = "tcp"
		}
		port := ""
		if in.ListenPort > 0 {
			port = strconv.Itoa(in.ListenPort)
		}
		node := model.SingBoxNode{
			Name:             name,
			LineID:           singBoxLatticeString(in.Lattice, "line_id"),
			NodeIdentityUUID: singBoxLatticeString(in.Lattice, "node_uuid"),
			Protocol:         strings.TrimSpace(in.Type),
			Network:          network,
			Address:          addr,
			Port:             port,
			SNI:              sni,
			ListenHost:       strings.TrimSpace(in.Listen),
			OutboundRef:      routeMap[name],
			UserCount:        len(in.Users),
			UserKnown:        in.Users != nil,
			Metadata:         singBoxRuntimeMetadata(in.Lattice),
		}
		// Resolve the outbound tag to its downstream destination so the server can
		// draw cross-node relay (jump) edges. Terminal outbounds (e.g. "direct")
		// carry no server/port and leave those fields empty.
		if ob, ok := outboundMap[node.OutboundRef]; ok {
			node.OutboundServer = ob.Server
			if ob.ServerPort > 0 {
				node.OutboundPort = strconv.Itoa(ob.ServerPort)
			}
			node.OutboundType = ob.Type
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func singBoxLatticeString(value map[string]any, key string) string {
	if len(value) == 0 {
		return ""
	}
	v, ok := value[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

func singBoxRuntimeMetadata(value map[string]any) map[string]string {
	if len(value) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, raw := range value {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				out[key] = strings.TrimSpace(v)
			}
		case map[string]any:
			if key != "labels" {
				continue
			}
			for lk, lv := range v {
				labelKey := strings.TrimSpace(lk)
				if labelKey == "" {
					continue
				}
				if s, ok := lv.(string); ok && strings.TrimSpace(s) != "" {
					out["label."+labelKey] = strings.TrimSpace(s)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
