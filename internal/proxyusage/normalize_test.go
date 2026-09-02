package proxyusage

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestNormalizeSnapshotTrafficMapsTrimAndMerge(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	snapshot, err := NormalizeSnapshot(model.ProxyUsageSnapshot{
		InboundTraffic: map[string]model.ProxyTrafficCounter{
			" vless ": {Uplink: 1, Downlink: 2},
			"vless":   {Uplink: 10, Downlink: 20},
		},
		UserTraffic:     map[string]model.ProxyTrafficCounter{"u_a": {Uplink: 3}},
		OutboundTraffic: map[string]model.ProxyTrafficCounter{},
		IgnoredCounters: 99, // a source's own claim is replaced by the agent's count
	}, " node-a ", fixed)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NodeID != "node-a" || !snapshot.At.Equal(fixed) {
		t.Fatalf("pinning: %+v", snapshot)
	}
	if want := map[string]model.ProxyTrafficCounter{"vless": {Uplink: 11, Downlink: 22}}; !reflect.DeepEqual(snapshot.InboundTraffic, want) {
		t.Fatalf("inbound_traffic: %+v", snapshot.InboundTraffic)
	}
	if snapshot.UserTraffic["u_a"].Uplink != 3 || snapshot.OutboundTraffic != nil {
		t.Fatalf("user/outbound: %+v", snapshot)
	}
	if snapshot.IgnoredCounters != 0 {
		t.Fatalf("ignored_counters must be the agent's own count: %d", snapshot.IgnoredCounters)
	}
}

func TestNormalizeSnapshotRejectsBadTrafficEntries(t *testing.T) {
	cases := []model.ProxyUsageSnapshot{
		{InboundTraffic: map[string]model.ProxyTrafficCounter{"vless": {Uplink: -1}}},
		{UserTraffic: map[string]model.ProxyTrafficCounter{"u_a": {Downlink: -1}}},
		{OutboundTraffic: map[string]model.ProxyTrafficCounter{"direct": {Uplink: 1, Downlink: -1}}},
		{InboundTraffic: map[string]model.ProxyTrafficCounter{"  ": {Uplink: 1}}},
	}
	for i, c := range cases {
		if _, err := NormalizeSnapshot(c, "node-a", time.Now()); err == nil {
			t.Fatalf("case %d: expected error for %+v", i, c)
		}
	}
}

func TestNormalizeSnapshotCapsEachTrafficMapDeterministically(t *testing.T) {
	build := func(n int) map[string]model.ProxyTrafficCounter {
		m := make(map[string]model.ProxyTrafficCounter, n)
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("tag-%05d", i)] = model.ProxyTrafficCounter{Uplink: int64(i)}
		}
		return m
	}
	first, err := NormalizeSnapshot(model.ProxyUsageSnapshot{
		InboundTraffic:  build(maxTrafficEntries + 3),
		UserTraffic:     build(maxTrafficEntries),
		OutboundTraffic: build(maxTrafficEntries + 1),
	}, "node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.InboundTraffic) != maxTrafficEntries || len(first.UserTraffic) != maxTrafficEntries || len(first.OutboundTraffic) != maxTrafficEntries {
		t.Fatalf("caps: inbound=%d user=%d outbound=%d", len(first.InboundTraffic), len(first.UserTraffic), len(first.OutboundTraffic))
	}
	if first.IgnoredCounters != 4 {
		t.Fatalf("ignored_counters = %d, want 4", first.IgnoredCounters)
	}
	// The dropped entries are the highest sorted keys, so the kept set is the
	// same on every interval and the server's diff stays meaningful.
	for _, key := range []string{"tag-04096", "tag-04097", "tag-04098"} {
		if _, ok := first.InboundTraffic[key]; ok {
			t.Fatalf("%s should have been dropped", key)
		}
	}
	if _, ok := first.InboundTraffic["tag-00000"]; !ok {
		t.Fatal("tag-00000 should have been kept")
	}
	second, err := NormalizeSnapshot(model.ProxyUsageSnapshot{InboundTraffic: build(maxTrafficEntries + 3)}, "node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.InboundTraffic, second.InboundTraffic) {
		t.Fatal("the kept set must not depend on map iteration order")
	}
}

func TestNormalizeSnapshotErrorsNameTheMap(t *testing.T) {
	_, err := NormalizeSnapshot(model.ProxyUsageSnapshot{OutboundTraffic: map[string]model.ProxyTrafficCounter{"direct": {Uplink: -5}}}, "node-a", time.Now())
	if err == nil || !strings.Contains(err.Error(), "outbound") || !strings.Contains(err.Error(), "direct") {
		t.Fatalf("error should name the map and key: %v", err)
	}
}
