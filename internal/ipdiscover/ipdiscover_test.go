package ipdiscover

import (
	"net"
	"testing"
)

func TestParseIP(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		wantV4 bool
		want   string
	}{
		{"bare v4", "203.0.113.0\n", true, "203.0.113.0"}, // routable? 203.0.113 is TEST-NET → see below
		{"plain public v4", "8.8.8.8\n", true, "8.8.8.8"},
		{"trailing whitespace", "  1.1.1.1  \n", true, "1.1.1.1"},
		{"cloudflare trace", "fl=1\nip=9.9.9.9\nts=123\n", true, "9.9.9.9"},
		{"private rejected", "192.168.1.5\n", true, ""},
		{"loopback rejected", "127.0.0.1\n", true, ""},
		{"v4 body but want v6", "8.8.8.8\n", false, ""},
		{"public v6", "2606:4700:4700::1111\n", false, "2606:4700:4700::1111"},
		{"trace v6", "ip=2001:4860:4860::8888\n", false, "2001:4860:4860::8888"},
		{"garbage", "not-an-ip\n", true, ""},
		{"empty", "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseIP(tc.body, tc.wantV4)
			// 203.0.113.0 is globally routable per net.IP semantics (not private),
			// so it parses; document the expectation precisely.
			if tc.name == "bare v4" {
				if got != "203.0.113.0" {
					t.Fatalf("ParseIP(%q,%v)=%q want %q", tc.body, tc.wantV4, got, "203.0.113.0")
				}
				return
			}
			if got != tc.want {
				t.Fatalf("ParseIP(%q,%v)=%q want %q", tc.body, tc.wantV4, got, tc.want)
			}
		})
	}
}

func TestSelectInternal(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	ifaces := []ifaceAddrs{
		{name: "docker0", addrs: []net.IP{ip("172.18.0.1")}},           // skipped (virtual)
		{name: "veth123", addrs: []net.IP{ip("172.20.0.2")}},           // skipped (virtual)
		{name: "eth0", addrs: []net.IP{ip("fe80::1"), ip("10.0.0.5")}}, // link-local v6 skipped; 10.0.0.5 chosen
		{name: "eth1", addrs: []net.IP{ip("2001:db8::5")}},             // v6 chosen
	}
	v4, v6 := selectInternal(ifaces)
	if v4 != "10.0.0.5" {
		t.Fatalf("internal v4 = %q, want 10.0.0.5 (docker/veth must be skipped)", v4)
	}
	if v6 != "2001:db8::5" {
		t.Fatalf("internal v6 = %q, want 2001:db8::5", v6)
	}
}

func TestSelectInternalEmpty(t *testing.T) {
	v4, v6 := selectInternal([]ifaceAddrs{
		{name: "docker0", addrs: []net.IP{net.ParseIP("172.18.0.1")}},
		{name: "lo", addrs: []net.IP{net.ParseIP("127.0.0.1")}},
	})
	if v4 != "" || v6 != "" {
		t.Fatalf("expected no internal IPs from virtual-only set, got v4=%q v6=%q", v4, v6)
	}
}
