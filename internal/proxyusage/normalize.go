package proxyusage

import (
	"fmt"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

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
	return snapshot, nil
}
