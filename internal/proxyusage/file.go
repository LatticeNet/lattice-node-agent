package proxyusage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const maxUsageFileBytes int64 = 1 << 20

// LoadFile reads a local proxy usage snapshot. It intentionally accepts only
// cumulative per-user byte counters; the server owns monotonic diffing,
// eligibility filtering, quota state, and audit.
func LoadFile(path, nodeID string) (model.ProxyUsageSnapshot, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	if info.Size() > maxUsageFileBytes {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage file exceeds %d bytes", maxUsageFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	var snapshot model.ProxyUsageSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	return NormalizeSnapshot(snapshot, nodeID, time.Now().UTC())
}
