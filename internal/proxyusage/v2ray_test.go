package proxyusage

import (
	"reflect"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestParseV2RayTrafficStat(t *testing.T) {
	cases := []struct {
		name string
		want v2rayTrafficStat
		ok   bool
	}{
		{"user>>>u_0123abcd>>>traffic>>>uplink", v2rayTrafficStat{"user", "u_0123abcd", "uplink"}, true},
		{"user>>>u_0123abcd>>>traffic>>>downlink", v2rayTrafficStat{"user", "u_0123abcd", "downlink"}, true},
		{"inbound>>>vless-reality-443>>>traffic>>>uplink", v2rayTrafficStat{"inbound", "vless-reality-443", "uplink"}, true},
		{"outbound>>>direct>>>traffic>>>downlink", v2rayTrafficStat{"outbound", "direct", "downlink"}, true},
		{"user>>> alice >>>traffic>>>uplink", v2rayTrafficStat{"user", "alice", "uplink"}, true},
		{"user>>>alice>>>requests>>>total", v2rayTrafficStat{}, false},
		{"user>>>alice>>>traffic>>>sideways", v2rayTrafficStat{}, false},
		{"dns>>>local>>>traffic>>>uplink", v2rayTrafficStat{}, false},
		{"user>>>>>>traffic>>>uplink", v2rayTrafficStat{}, false},
		{"user>>>alice>>>traffic", v2rayTrafficStat{}, false},
		{"", v2rayTrafficStat{}, false},
	}
	for _, c := range cases {
		got, ok := parseV2RayTrafficStat(c.name)
		if ok != c.ok || got != c.want {
			t.Fatalf("parse(%q) = %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestSnapshotFromV2RayStatsSplitsDirectionsPerKind(t *testing.T) {
	stats := []nameValue{
		{"user>>>u_0123abcd>>>traffic>>>uplink", 100},
		{"user>>>u_0123abcd>>>traffic>>>downlink", 250},
		{"user>>>u_ef89>>>traffic>>>uplink", 7},
		{"inbound>>>vless-reality-443>>>traffic>>>uplink", 1000},
		{"inbound>>>vless-reality-443>>>traffic>>>downlink", 2000},
		{"inbound>>>legacy-ss>>>traffic>>>downlink", 5},
		{"outbound>>>direct>>>traffic>>>uplink", 30},
		{"outbound>>>direct>>>traffic>>>downlink", 40},
		{"user>>>u_0123abcd>>>traffic>>>uplink", 1}, // a repeated name sums
		{"api>>>traffic>>>uplink", 9},               // not a traffic counter
	}
	snapshot, err := snapshotFromV2RayStats(stats, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int64{"u_0123abcd": 351, "u_ef89": 7}; !reflect.DeepEqual(snapshot.UserBytes, want) {
		t.Fatalf("user_bytes stays the per-user sum: %+v", snapshot.UserBytes)
	}
	if want := map[string]model.ProxyTrafficCounter{
		"u_0123abcd": {Uplink: 101, Downlink: 250},
		"u_ef89":     {Uplink: 7},
	}; !reflect.DeepEqual(snapshot.UserTraffic, want) {
		t.Fatalf("user_traffic: %+v", snapshot.UserTraffic)
	}
	if want := map[string]model.ProxyTrafficCounter{
		"vless-reality-443": {Uplink: 1000, Downlink: 2000},
		"legacy-ss":         {Downlink: 5},
	}; !reflect.DeepEqual(snapshot.InboundTraffic, want) {
		t.Fatalf("inbound_traffic: %+v", snapshot.InboundTraffic)
	}
	if want := map[string]model.ProxyTrafficCounter{"direct": {Uplink: 30, Downlink: 40}}; !reflect.DeepEqual(snapshot.OutboundTraffic, want) {
		t.Fatalf("outbound_traffic: %+v", snapshot.OutboundTraffic)
	}
}

func TestSnapshotFromV2RayStatsUsersOnly(t *testing.T) {
	stats := []nameValue{
		{"user>>>alice>>>traffic>>>uplink", 100},
		{"inbound>>>api>>>traffic>>>uplink", 999},
		{"outbound>>>direct>>>traffic>>>uplink", 5},
	}
	snapshot, err := snapshotFromV2RayStats(stats, false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UserBytes["alice"] != 100 || len(snapshot.UserBytes) != 1 {
		t.Fatalf("user_bytes: %+v", snapshot.UserBytes)
	}
	if snapshot.UserTraffic != nil || snapshot.InboundTraffic != nil || snapshot.OutboundTraffic != nil {
		t.Fatalf("traffic maps must stay empty without includeTraffic: %+v", snapshot)
	}
}

func TestSnapshotFromV2RayStatsRejectsNegativeInAnyKind(t *testing.T) {
	for _, name := range []string{
		"user>>>alice>>>traffic>>>uplink",
		"inbound>>>vless>>>traffic>>>downlink",
		"outbound>>>direct>>>traffic>>>uplink",
		"api>>>traffic>>>uplink", // even an ignored counter cannot be negative
	} {
		if _, err := snapshotFromV2RayStats([]nameValue{{name, -1}}, true); err == nil {
			t.Fatalf("%s: negative counter must be refused", name)
		}
	}
}
