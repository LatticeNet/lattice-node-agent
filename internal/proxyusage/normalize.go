package proxyusage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// maxTrafficEntries caps each direction-split traffic map. A node has a few
// inbounds and outbounds and at most a few hundred credentials, so 4096 is
// headroom, not a limit anyone reaches in practice; it exists so a core with a
// runaway tag set cannot turn one heartbeat into an unbounded upload.
const maxTrafficEntries = 4096

// NormalizeSnapshot pins the trust boundary for node-supplied proxy usage:
// the configured node id wins, timestamps are best-effort, and counters must
// be cumulative, non-negative per-user totals.
func NormalizeSnapshot(snapshot model.ProxyUsageSnapshot, nodeID string, now time.Time) (model.ProxyUsageSnapshot, error) {
	snapshot.NodeID = strings.TrimSpace(nodeID)
	if snapshot.At.IsZero() {
		if now.IsZero() {
			now = time.Now().UTC()
		}
		snapshot.At = now.UTC()
	}
	normalized := map[string]int64{}
	for userID, value := range snapshot.UserBytes {
		id := strings.TrimSpace(userID)
		if id == "" {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage user id cannot be empty")
		}
		if value < 0 {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage for %s cannot be negative", id)
		}
		normalized[id] += value
	}
	snapshot.UserBytes = normalized
	normalizedLines := map[string]map[string]int64{}
	lineUserTotals := map[string]int64{}
	for lineID, users := range snapshot.LineUserBytes {
		line := strings.TrimSpace(lineID)
		if line == "" {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage line id cannot be empty")
		}
		if len(line) > 256 {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage line id is too long")
		}
		dst := normalizedLines[line]
		if dst == nil {
			dst = map[string]int64{}
			normalizedLines[line] = dst
		}
		for userID, value := range users {
			id := strings.TrimSpace(userID)
			if id == "" {
				return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage user id cannot be empty")
			}
			if value < 0 {
				return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage for %s on line %s cannot be negative", id, line)
			}
			dst[id] += value
			lineUserTotals[id] += value
		}
	}
	if len(normalizedLines) > 0 {
		snapshot.LineUserBytes = normalizedLines
		if len(snapshot.UserBytes) == 0 {
			snapshot.UserBytes = lineUserTotals
		}
	} else {
		snapshot.LineUserBytes = nil
	}
	dropped := 0
	for _, entry := range []struct {
		label string
		m     *map[string]model.ProxyTrafficCounter
	}{
		{"inbound", &snapshot.InboundTraffic},
		{"user", &snapshot.UserTraffic},
		{"outbound", &snapshot.OutboundTraffic},
	} {
		out, n, err := normalizeTraffic(entry.label, *entry.m)
		if err != nil {
			return model.ProxyUsageSnapshot{}, err
		}
		*entry.m = out
		dropped += n
	}
	// The agent's own count replaces whatever the source claimed: the cap is
	// applied here, so only this function knows how many entries went missing.
	snapshot.IgnoredCounters = dropped
	return snapshot, nil
}

// normalizeTraffic trims keys, merges trimmed duplicates, refuses empty keys
// and negative counters, and keeps at most maxTrafficEntries entries. The kept
// set is chosen by sorted key rather than map order: the server diffs
// consecutive snapshots, so a kept set that changed on every interval would
// read as counters resetting. It returns the number of dropped entries.
func normalizeTraffic(label string, in map[string]model.ProxyTrafficCounter) (map[string]model.ProxyTrafficCounter, int, error) {
	if len(in) == 0 {
		return nil, 0, nil
	}
	out := make(map[string]model.ProxyTrafficCounter, len(in))
	for key, counter := range in {
		id := strings.TrimSpace(key)
		if id == "" {
			return nil, 0, fmt.Errorf("proxy usage %s traffic key cannot be empty", label)
		}
		if counter.Uplink < 0 || counter.Downlink < 0 {
			return nil, 0, fmt.Errorf("proxy usage %s traffic for %s cannot be negative", label, id)
		}
		prev := out[id]
		out[id] = model.ProxyTrafficCounter{Uplink: prev.Uplink + counter.Uplink, Downlink: prev.Downlink + counter.Downlink}
	}
	if len(out) <= maxTrafficEntries {
		return out, 0, nil
	}
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys[maxTrafficEntries:] {
		delete(out, key)
	}
	return out, len(keys) - maxTrafficEntries, nil
}
