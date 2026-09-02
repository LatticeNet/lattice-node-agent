package proxyusage

import (
	"fmt"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// nameValue is one raw counter as the core reports it, before any parsing.
type nameValue struct {
	name  string
	value int64
}

// v2rayTrafficStat is a parsed V2Ray-style traffic counter name. sing-box and
// xray both emit `<kind>>>><name>>>>traffic>>><direction>` where kind is user,
// inbound or outbound; every other counter shape (requests, api, dns) is not
// usage and is ignored by the parser.
type v2rayTrafficStat struct {
	kind      string // "user" | "inbound" | "outbound"
	name      string // credential name or tag, trimmed
	direction string // "uplink" | "downlink"
}

// parseV2RayTrafficStat is the only parser of counter names in the agent. It
// accepts exactly the three traffic kinds and the two directions and refuses
// everything else, so a future counter family cannot leak into usage maps
// without a deliberate change here.
func parseV2RayTrafficStat(raw string) (v2rayTrafficStat, bool) {
	parts := strings.Split(raw, ">>>")
	if len(parts) != 4 {
		return v2rayTrafficStat{}, false
	}
	switch parts[0] {
	case "user", "inbound", "outbound":
	default:
		return v2rayTrafficStat{}, false
	}
	if parts[2] != "traffic" {
		return v2rayTrafficStat{}, false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return v2rayTrafficStat{}, false
	}
	name := strings.TrimSpace(parts[1])
	if name == "" {
		return v2rayTrafficStat{}, false
	}
	return v2rayTrafficStat{kind: parts[0], name: name, direction: parts[3]}, true
}

// snapshotFromV2RayStats folds raw counters into an un-normalized snapshot.
// user_bytes is always filled (the per-user sum of both directions, which is
// what old servers read). The three direction-split maps are filled only when
// includeTraffic is set: the sing-box gRPC and V2Ray JSON sources carry tags
// the server can join, the xray CLI source does not report them. A negative
// counter is refused outright rather than clamped, because it means the
// source is not the cumulative counter set the server's diffing assumes.
func snapshotFromV2RayStats(stats []nameValue, includeTraffic bool) (model.ProxyUsageSnapshot, error) {
	snapshot := model.ProxyUsageSnapshot{UserBytes: map[string]int64{}}
	if includeTraffic {
		snapshot.UserTraffic = map[string]model.ProxyTrafficCounter{}
		snapshot.InboundTraffic = map[string]model.ProxyTrafficCounter{}
		snapshot.OutboundTraffic = map[string]model.ProxyTrafficCounter{}
	}
	for _, stat := range stats {
		if stat.value < 0 {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage stat %q cannot be negative", stat.name)
		}
		parsed, ok := parseV2RayTrafficStat(stat.name)
		if !ok {
			continue
		}
		if parsed.kind == "user" {
			snapshot.UserBytes[parsed.name] += stat.value
		}
		if !includeTraffic {
			continue
		}
		var dst map[string]model.ProxyTrafficCounter
		switch parsed.kind {
		case "user":
			dst = snapshot.UserTraffic
		case "inbound":
			dst = snapshot.InboundTraffic
		default:
			dst = snapshot.OutboundTraffic
		}
		counter := dst[parsed.name]
		if parsed.direction == "uplink" {
			counter.Uplink += stat.value
		} else {
			counter.Downlink += stat.value
		}
		dst[parsed.name] = counter
	}
	return snapshot, nil
}
