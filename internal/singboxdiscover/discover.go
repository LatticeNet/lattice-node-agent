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
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	// defaultEndpointsPath is the node's own description of how the outside
	// reaches it. It is the mirror image of the sidecar above: that file is
	// written BY the control plane to assign identity, this one is written ON
	// the node and only read centrally, so a machine that leaves still carries
	// the mapping its provider gave it.
	defaultEndpointsPath = "/etc/sing-box/lattice-endpoints.json"
	// maxInspectCalls bounds the per-line `sb --json inspect <name>` enrichment
	// so a large fleet cannot stretch the discovery cycle.
	maxInspectCalls            = 64
	maxInspectWorkers          = 4
	defaultInspectTotalTimeout = 2 * time.Second
	// singBoxExecutableName is the exact binary name accepted as sing-box when
	// deciding whether a running process may name host paths for this agent. A
	// substring match ("contains sing-box") let any binary claim the identity.
	singBoxExecutableName = "sing-box"
	// maxRuntimeConfigBytes bounds one sing-box config file read. These paths
	// come from the running process, so they are root-controlled after the
	// selector fix, but an unbounded read of a file the agent does not own is
	// still a way to take the agent down with the disk.
	maxRuntimeConfigBytes = 8 << 20 // 8 MiB
	nodeEndpointsSchema   = "lattice.node-endpoints.v1"
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
	// EndpointsPath is the node-owned endpoint declaration; default
	// /etc/sing-box/lattice-endpoints.json.
	EndpointsPath string
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
	applyNodeEndpoints(source, &inv)

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
	applyNodeEndpoints(source, &inv)
	return inv, nil
}

// DiscoverRuntimeFiles parses an explicit locally resolved runtime config set.
// It is used by recovery/E2E verification after the same bounded layout resolver
// has established file authority.
func DiscoverRuntimeFiles(nodeID string, files []string, metaPath string) (model.SingBoxInventory, error) {
	copyFiles := append([]string(nil), files...)
	return discoverRuntimeConfig(Source{MetaPath: metaPath, runtimeFiles: func() []string { return copyFiles }}, nodeID, time.Now().UTC())
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
		readFn = readBoundedConfigFile
	}
	configs := []singBoxRuntimeConfigFile{}
	for _, path := range filesFn() {
		raw, err := readFn(path)
		if err != nil {
			continue
		}
		var cfg singBoxRuntimeConfig
		if err := json.Unmarshal(bytes.TrimSpace(raw), &cfg); err != nil {
			// Silence here hid a real gap for a long time: a file that does not
			// decode takes its outbounds, route rules and identity block with
			// it, while the lines it declares still arrive from `sb --json list`
			// and look fine.
			logf(source, "sing-box config %s does not decode (%v); its outbounds and route rules are not visible", path, boundedErr(err))
			continue
		}
		configs = append(configs, singBoxRuntimeConfigFile{path: path, cfg: cfg})
	}
	return configs
}

// readBoundedConfigFile reads one sing-box config file with a size ceiling, so a
// single oversized file cannot exhaust agent memory on every discovery cycle.
func readBoundedConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRuntimeConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRuntimeConfigBytes {
		return nil, fmt.Errorf("sing-box config %s exceeds %d bytes", path, maxRuntimeConfigBytes)
	}
	return data, nil
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
		// The route map is merged across every config file on the box, so it
		// sees the rule that steers this inbound even when the rule lives in a
		// different file than the inbound itself (a hub keeps its inbounds in
		// per-line files and its relay rules in a shared fragment). Both weaker
		// sources read one file at a time and call such a line terminal, so this
		// has to overrule them rather than only fill a gap.
		//
		// It used to only fill a gap, and the inspect pass that runs before this
		// one is bounded by a call count and a deadline. Which lines inspect
		// reached varied from cycle to cycle, and so did which lines kept the
		// correct cross-file answer: the reported outbound flipped between the
		// relay tag and "direct", which re-rendered the metadata sidecar and
		// re-queued an approval every time it moved.
		if ref, ok := routeMap[tag]; ok && ref != "" && nodes[i].OutboundRef != ref {
			nodes[i].OutboundRef = ref
			// Derived from the ref just replaced, so it cannot be kept; the
			// lookup below refills it from the outbound actually in use.
			nodes[i].OutboundType = ""
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
// nodeEndpoints is the node-owned endpoint declaration.
type nodeEndpoints struct {
	Schema     string `json:"schema"`
	Network    string `json:"network"`
	PublicHost string `json:"public_host"`
	// ProviderEdge is the hostname the provider forwards from. A relay elsewhere
	// in the fleet names it as its outbound server, so it is what the control
	// plane has to match a chain against; the node's own public host never
	// appears there.
	ProviderEdge string `json:"provider_edge"`
	Inbounds     []struct {
		Tag        string `json:"tag"`
		ListenPort int    `json:"listen_port"`
		PublicPort int    `json:"public_port"`
		PublicHost string `json:"public_host"`
	} `json:"inbounds"`
}

// applyNodeEndpoints annotates the inventory with how the outside reaches this
// node, and reports the declared network type.
//
// Only a NAT node needs it, and only that node can supply it: the port a
// provider forwards lives in the provider's router, not in any config here, so
// discovery would otherwise report the listen port as though it were reachable
// and every chain built on it would dial a closed door.
//
// A missing or unreadable file is not an error. Most nodes are reached on the
// port they listen on, and for them the absence is the correct answer.
func applyNodeEndpoints(source Source, inv *model.SingBoxInventory) {
	path := strings.TrimSpace(source.EndpointsPath)
	if path == "" {
		path = defaultEndpointsPath
	}
	readFn := source.readFile
	if readFn == nil {
		readFn = os.ReadFile
	}
	raw, err := readFn(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logf(source, "node endpoints %s unreadable (%v); reporting listen ports as public", path, boundedErr(err))
		}
		return
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	var doc nodeEndpoints
	if err := json.Unmarshal(raw, &doc); err != nil {
		logf(source, "node endpoints %s unreadable (%v); reporting listen ports as public", path, boundedErr(err))
		return
	}
	if doc.Schema != nodeEndpointsSchema {
		logf(source, "node endpoints %s has schema %q, want %q; ignoring", path, doc.Schema, nodeEndpointsSchema)
		return
	}
	inv.Network = strings.TrimSpace(doc.Network)
	inv.ProviderEdge = strings.TrimSpace(doc.ProviderEdge)
	byTag := map[string]int{}
	hostByTag := map[string]string{}
	for _, ib := range doc.Inbounds {
		tag := strings.TrimSpace(ib.Tag)
		if tag == "" || ib.PublicPort <= 0 || ib.PublicPort > 65535 {
			continue
		}
		byTag[tag] = ib.PublicPort
		if h := strings.TrimSpace(ib.PublicHost); h != "" {
			hostByTag[tag] = h
		}
	}
	fallbackHost := strings.TrimSpace(doc.PublicHost)
	for i := range inv.Nodes {
		tag := strings.TrimSpace(inv.Nodes[i].Name)
		if port, ok := byTag[tag]; ok {
			inv.Nodes[i].PublicPort = strconv.Itoa(port)
		}
		if h, ok := hostByTag[tag]; ok {
			inv.Nodes[i].Address = h
		} else if fallbackHost != "" {
			inv.Nodes[i].Address = fallbackHost
		}
	}
}

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
		if len(args) == 0 || !trustedSingBoxExecutable(args[0]) {
			continue
		}
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

// singBoxProcessArgs returns the argument vectors of the running sing-box
// processes the agent is willing to treat as local authority.
//
// This selector is a trust boundary, not a convenience filter: whatever it
// admits gets to name the directory the root agent uses as the linechain layout
// authority (ResolveRuntimeLayout) and as an inventory source
// (singBoxRuntimeConfigFiles). It previously admitted any process whose argv[0]
// basename merely contained "sing-box" and whose argv contained "run", so an
// unprivileged local user only had to run `cp /bin/sleep /tmp/sing-box &&
// /tmp/sing-box run -C /tmp/mine` to steer a root process.
//
// Three things are checked now, in order of how hard they are to forge:
//
//  1. The process runs as uid 0, read from the kernel's ownership of
//     /proc/<pid>. An unprivileged attacker cannot produce a root process, so
//     this is the check that actually excludes them.
//  2. Its executable is identified from /proc/<pid>/exe, which the kernel
//     maintains, rather than from the self-reported argv[0]. A process can set
//     argv[0] to anything; it cannot relabel its own exe link. When the link
//     cannot be read (a non-root agent lacks ptrace permission over a root
//     process) the self-reported path is used instead, which is sound only
//     because step 1 already established the process is root.
//  3. The resolved executable must be a sing-box binary living in a system
//     executable directory, owned by root and not group/world writable, so a
//     root-run script from a writable path is not authority either.
//
// The validated path replaces argv[0] in the returned vector, so every consumer
// downstream reasons about the kernel's answer rather than the process's claim.
func singBoxProcessArgs() [][]string {
	procs := TrustedProcesses()
	out := make([][]string, 0, len(procs))
	for _, p := range procs {
		out = append(out, p.Args)
	}
	return out
}

// TrustedProcess is one running sing-box process the trust selector accepted.
type TrustedProcess struct {
	PID  int
	Args []string
	// StartedAt is best-effort (the proc entry's mtime, which the kernel sets
	// at process creation); zero when it could not be read.
	StartedAt time.Time
}

// TrustedProcesses lists the running processes the selector accepts as
// sing-box, with their pids and best-effort start times. It applies exactly
// the trust rules documented above; the liveness probe (design-19) consumes
// it so that "a sing-box process exists" is decided by one selector in one
// place, never re-derived with looser rules.
func TrustedProcesses() []TrustedProcess {
	matches, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*", "cmdline"))
	var out []TrustedProcess
	for _, cmdlinePath := range matches {
		procDir := filepath.Dir(cmdlinePath)
		if !processRunsAsRoot(procDir) {
			continue
		}
		raw, err := os.ReadFile(cmdlinePath)
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
		if len(args) == 0 || !containsArg(args, "run") {
			continue
		}
		exe, err := os.Readlink(filepath.Join(procDir, "exe"))
		if err != nil {
			exe = args[0]
		}
		if !trustedSingBoxExecutable(exe) {
			continue
		}
		args[0] = filepath.Clean(exe)
		pid, err := strconv.Atoi(filepath.Base(procDir))
		if err != nil {
			continue
		}
		proc := TrustedProcess{PID: pid, Args: args}
		if info, err := os.Stat(procDir); err == nil {
			proc.StartedAt = info.ModTime()
		}
		out = append(out, proc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// procRoot is the process table the selector reads. It is a variable so a test
// can point the privileged half of this trust boundary at a fabricated tree;
// production always reads /proc.
var procRoot = "/proc"

// fileIdentity is the subset of file metadata the trust checks need: the mode
// decides regular-file and writability questions, the uid decides ownership.
type fileIdentity struct {
	mode os.FileMode
	uid  uint32
}

// statIdentity resolves a path's mode and owning uid. It is a package variable
// for one reason: ownership is the load-bearing half of this selector, and a
// test process that is not root cannot create a root-owned file to exercise it.
// Tests substitute the uid and keep the real mode, so only the fact under test
// is fabricated.
var statIdentity = func(path string) (fileIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, fmt.Errorf("no ownership metadata for %s", path)
	}
	return fileIdentity{mode: info.Mode(), uid: stat.Uid}, nil
}

// processRunsAsRoot reports whether /proc/<pid> is owned by uid 0. The kernel
// owns that directory to the process credentials, so it is not forgeable from
// inside the process.
func processRunsAsRoot(procDir string) bool {
	id, err := statIdentity(procDir)
	if err != nil {
		return false
	}
	return id.uid == 0
}

// trustedSingBoxExecutableDirs are the system executable directories a sing-box
// binary may live in to be accepted as local authority. Anything outside them
// (/tmp, a home directory, a world-writable app directory) is refused. A node
// whose sing-box lives elsewhere loses process-derived discovery and falls back
// to the conventional /etc/sing-box paths rather than trusting the process.
// ResolveTrustedExecutable applies the same list to sibling probes.
var trustedSingBoxExecutableDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
}

// trustedSingBoxExecutable reports whether an executable path may be treated as
// sing-box. The path rules are pure so both the /proc collector and the layout
// resolver apply the same identity; the ownership and permission rules are
// applied only when the file can be stat'd, and refuse anything that is not a
// root-owned, non-group/world-writable regular file.
func trustedSingBoxExecutable(exe string) bool {
	return explainSingBoxExecutable(exe) == ""
}

// explainSingBoxExecutable applies the executable rules and names the first
// one the path fails, or returns "" when the path is trusted. The reason is
// what the liveness probe reports when it cannot prove the service, so it
// says which rule and, where the file can be stat'd, who owns it.
func explainSingBoxExecutable(exe string) string {
	return explainTrustedExecutable(exe, singBoxExecutableName)
}

// ResolveTrustedExecutable looks for a binary named name in the trusted
// executable directories and applies the same ownership and permission rules
// the sing-box selector applies. It exists so a sibling probe that must run a
// root-only external command (the sshd facts step of the guard-reality
// report) executes from exactly this trust boundary instead of growing its
// own. It returns the first trusted path, or "" and the reason: the failed
// rule of the first candidate that exists, or a not-found note that names the
// directories searched.
func ResolveTrustedExecutable(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" || name != filepath.Base(name) {
		return "", "executable name must be a bare file name"
	}
	for _, dir := range trustedSingBoxExecutableDirs {
		candidate := filepath.Join(dir, name)
		if _, err := statIdentity(candidate); err != nil {
			continue
		}
		if reason := explainTrustedExecutable(candidate, name); reason != "" {
			return "", candidate + ": " + reason
		}
		return candidate, ""
	}
	return "", name + " not found in the trusted executable directories (" + strings.Join(trustedSingBoxExecutableDirs, ", ") + ")"
}

// explainTrustedExecutable is the rule set behind both selectors: absolute
// path, exact base name, trusted directory, and (where the file can be
// stat'd) a root-owned regular file nobody else can write.
func explainTrustedExecutable(exe, name string) string {
	exe = strings.TrimSpace(exe)
	if !filepath.IsAbs(exe) {
		return "executable path is not absolute"
	}
	clean := filepath.Clean(exe)
	if filepath.Base(clean) != name {
		return "executable is not named " + name
	}
	id, statErr := statIdentity(clean)
	owner := ""
	if statErr == nil && id.uid != 0 {
		owner = fmt.Sprintf("; owned by uid %d, not root", id.uid)
	}
	trustedDir := false
	for _, dir := range trustedSingBoxExecutableDirs {
		if filepath.Dir(clean) == dir {
			trustedDir = true
			break
		}
	}
	if !trustedDir {
		return "outside the trusted executable directories (" + strings.Join(trustedSingBoxExecutableDirs, ", ") + ")" + owner
	}
	if statErr != nil {
		// The binary is not visible from here (a test vector, or a chroot). The
		// path rules above still applied, and in the /proc collector the process
		// was already proven to be root.
		return ""
	}
	if !id.mode.IsRegular() {
		return "not a regular file"
	}
	if id.mode.Perm()&0o022 != 0 {
		return "group or world writable"
	}
	if id.uid != 0 {
		return fmt.Sprintf("owned by uid %d, not root", id.uid)
	}
	return ""
}

// RefusedProcess is a running process that presents as a sing-box `run` and
// that the trust selector did not accept, with the rule it failed. It exists
// so the liveness probe can say why it could not prove the service instead of
// reporting a bare unknown: on a fleet whose manager installs sing-box under
// /etc/sing-box/bin owned by an unprivileged uid, every node reads unknown
// and nothing says why.
type RefusedProcess struct {
	PID    int
	Exe    string
	Reason string
}

// maxRefusedProcesses bounds the listing; three candidates say everything a
// probe error can carry, and a host running hundreds of sing-box lookalikes
// is not a case worth a megabyte of reasons.
const maxRefusedProcesses = 3

// RefusedProcesses lists the sing-box candidates the selector refused. A
// candidate is any process whose command line carries `run` and whose
// executable, by argv[0] or by the kernel's exe link, is named sing-box. It
// applies the same rules as TrustedProcesses and keeps the rejections.
func RefusedProcesses() []RefusedProcess {
	matches, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*", "cmdline"))
	var out []RefusedProcess
	for _, cmdlinePath := range matches {
		if len(out) >= maxRefusedProcesses {
			break
		}
		procDir := filepath.Dir(cmdlinePath)
		raw, err := os.ReadFile(cmdlinePath)
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
		if len(args) == 0 || !containsArg(args, "run") {
			continue
		}
		exe, err := os.Readlink(filepath.Join(procDir, "exe"))
		if err != nil {
			exe = args[0]
		}
		if filepath.Base(exe) != singBoxExecutableName && filepath.Base(args[0]) != singBoxExecutableName {
			continue
		}
		pid, err := strconv.Atoi(filepath.Base(procDir))
		if err != nil {
			continue
		}
		reason := ""
		if !processRunsAsRoot(procDir) {
			reason = "process does not run as root"
		} else {
			reason = explainSingBoxExecutable(exe)
		}
		if reason == "" {
			continue
		}
		out = append(out, RefusedProcess{PID: pid, Exe: filepath.Clean(exe), Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// ResolveRuntimeLayout returns the one locally observed sing-box -C directory
// and the design-17 sidecar path. It never trusts a server task document to
// choose writable host paths.
func ResolveRuntimeLayout(metaPath string) (string, string, error) {
	return resolveRuntimeLayout(singBoxProcessArgs(), metaPath)
}

func resolveRuntimeLayout(processes [][]string, metaPath string) (string, string, error) {
	dirs := map[string]struct{}{}
	for _, args := range processes {
		// Second layer behind the /proc checks in singBoxProcessArgs: only a
		// process running a sing-box binary from a system executable directory
		// may name the config directory this agent treats as authority.
		if len(args) == 0 || !trustedSingBoxExecutable(args[0]) {
			continue
		}
		for i := 0; i < len(args); i++ {
			arg := args[i]
			var value string
			switch arg {
			case "-C", "--config-directory":
				if i+1 < len(args) {
					i++
					value = args[i]
				}
			default:
				for _, prefix := range []string{"-C=", "--config-directory="} {
					if v, ok := strings.CutPrefix(arg, prefix); ok {
						value = v
					}
				}
			}
			if value != "" && filepath.IsAbs(value) {
				dirs[filepath.Clean(value)] = struct{}{}
			}
		}
	}
	if len(dirs) == 0 {
		if info, err := os.Lstat("/etc/sing-box/conf"); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			dirs["/etc/sing-box/conf"] = struct{}{}
		}
	}
	if len(dirs) != 1 {
		return "", "", fmt.Errorf("resolve sing-box config directory: found %d active -C directories", len(dirs))
	}
	var configDir string
	for dir := range dirs {
		configDir = dir
	}
	info, err := os.Lstat(configDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("resolve sing-box config directory: path is not a real directory")
	}
	metaPath = strings.TrimSpace(metaPath)
	if metaPath == "" {
		metaPath = defaultMetaPath
	}
	if !filepath.IsAbs(metaPath) {
		return "", "", fmt.Errorf("resolve sing-box sidecar: path must be absolute")
	}
	return configDir, filepath.Clean(metaPath), nil
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
	Inbound  singBoxListable `json:"inbound"`
	Outbound string          `json:"outbound"`
	Action   string          `json:"action"`
}

// singBoxListable is a sing-box field that accepts either one value or a list
// of them. Typing it as a plain []string is not a cosmetic mismatch: the whole
// file fails to decode, loadSingBoxRuntimeConfigFiles drops it, and with it go
// that file's outbounds, route rules and identity block. One relay lost its
// downstream that way while the rest of the box looked healthy, because the
// line itself still arrived from `sb --json list`.
type singBoxListable []string

func (l *singBoxListable) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*l = nil
		return nil
	}
	if data[0] == '[' {
		var many []string
		if err := json.Unmarshal(data, &many); err != nil {
			return err
		}
		*l = many
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = []string{one}
	return nil
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
