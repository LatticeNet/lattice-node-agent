package prober

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/ipv4"
)

// fakeResolver answers lookups from a table and counts them.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, host)
	raw, ok := f.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, a := range raw {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

// recordingDialer records every address a probe dials and connects each
// to an in-memory pipe.
type recordingDialer struct {
	mu     sync.Mutex
	dialed []string
	fail   map[string]bool
}

func (d *recordingDialer) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dialed = append(d.dialed, address)
	if d.fail[address] {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.AddrError{Err: "connection refused", Addr: address}}
	}
	client, server := net.Pipe()
	go func() { _ = server.Close() }()
	return client, nil
}

func (d *recordingDialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

func fakeNetProber(answers map[string][]string) (*prober, *fakeResolver, *recordingDialer) {
	r := &fakeResolver{answers: answers}
	d := &recordingDialer{}
	p := newProber()
	p.resolver = r
	p.dial = d.dial
	p.listenICMP = func() (icmpConn, error) { panic("an icmp socket was opened for a refused destination") }
	return p, r, d
}

// Every address class the contract refuses, as a literal.
var refusedLiterals = []string{
	"127.0.0.1",       // loopback
	"::1",             // loopback
	"10.1.2.3",        // RFC 1918
	"172.16.0.1",      // RFC 1918
	"192.168.1.1",     // RFC 1918
	"fc00::1",         // unique local
	"169.254.169.254", // metadata and link-local
	"fd00:ec2::254",   // metadata
	"fe80::1",         // link-local
	"100.64.0.1",      // carrier-grade NAT
	"224.0.0.1",       // multicast
	"ff02::1",         // multicast
	"0.0.0.0",         // unspecified
	"::",              // unspecified
	"255.255.255.255", // broadcast
	"::ffff:10.0.0.1", // IPv4-mapped, judged as IPv4
}

func monitorFor(kind, host string) model.Monitor {
	m := model.Monitor{ID: "m", Type: kind, TimeoutSec: 1}
	switch kind {
	case model.MonitorTypeTCP:
		m.Target = net.JoinHostPort(host, "443")
	case model.MonitorTypeHTTP:
		m.Target = "http://" + net.JoinHostPort(host, "80") + "/"
	default:
		m.Target = host
	}
	return m
}

func TestDestinationRulesRefuseLiterals(t *testing.T) {
	for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP} {
		for _, host := range refusedLiterals {
			p, r, d := fakeNetProber(nil)
			res := p.probe(context.Background(), monitorFor(kind, host))
			if res.Success || res.Reason != model.PathReasonDestinationRefused {
				t.Fatalf("%s %s: want %s, got %+v", kind, host, model.PathReasonDestinationRefused, res)
			}
			if len(d.addresses()) != 0 || len(r.lookups) != 0 {
				t.Fatalf("%s %s: a refused literal was looked up or dialed: lookups %v dials %v", kind, host, r.lookups, d.addresses())
			}
			if res.Sent != 0 {
				t.Fatalf("%s %s: nothing was sent: %+v", kind, host, res)
			}
		}
	}
}

// A name is judged by every address it resolves to: one private address
// beside public ones refuses the run, and nothing is dialed.
func TestDestinationRulesRefuseResolvedNames(t *testing.T) {
	answers := map[string][]string{
		"inside.example":   {"10.0.0.7"},
		"mixed.example":    {"203.0.113.10", "192.168.0.5"},
		"metadata.example": {"169.254.169.254"},
		"mapped.example":   {"::ffff:127.0.0.1"},
		"cgnat.example":    {"2001:db8::1", "100.100.1.1"},
	}
	for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeHTTP, model.MonitorTypeICMP} {
		for name := range answers {
			p, r, d := fakeNetProber(answers)
			res := p.probe(context.Background(), monitorFor(kind, name))
			if res.Reason != model.PathReasonDestinationRefused {
				t.Fatalf("%s %s: want %s, got %+v", kind, name, model.PathReasonDestinationRefused, res)
			}
			if len(r.lookups) != 1 {
				t.Fatalf("%s %s: want one lookup, got %v", kind, name, r.lookups)
			}
			if got := d.addresses(); len(got) != 0 {
				t.Fatalf("%s %s: refused run dialed %v", kind, name, got)
			}
		}
	}
}

// A public name resolves once and the probe dials only the judged
// addresses, in the resolver's order, falling through on failure.
func TestDestinationDialsOnlyJudgedAddresses(t *testing.T) {
	p, r, d := fakeNetProber(map[string][]string{"public.example": {"2001:4860::8888", "203.0.113.10"}})
	d.fail = map[string]bool{"[2001:4860::8888]:443": true}
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeTCP, Target: "public.example:443", TimeoutSec: 1})
	if !res.Success {
		t.Fatalf("expected success through the second address, got %+v", res)
	}
	if want := []string{"[2001:4860::8888]:443", "203.0.113.10:443"}; !slices.Equal(d.addresses(), want) {
		t.Fatalf("dialed %v, want %v", d.addresses(), want)
	}
	if len(r.lookups) != 1 {
		t.Fatalf("want exactly one lookup, got %v", r.lookups)
	}
}

func TestDestinationAllowsPublicLiteral(t *testing.T) {
	p, r, d := fakeNetProber(nil)
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeTCP, Target: "203.0.113.10:8443", TimeoutSec: 1})
	if !res.Success {
		t.Fatalf("a public literal is allowed: %+v", res)
	}
	if !slices.Equal(d.addresses(), []string{"203.0.113.10:8443"}) || len(r.lookups) != 0 {
		t.Fatalf("a literal is dialed as written without a lookup: dials %v lookups %v", d.addresses(), r.lookups)
	}
}

// A tcp or icmp target the control plane resolved from a node
// (target_node) skips the private-range rule: nodes reach each other over
// private networks. http never takes target_node (TestHTTPIgnoresTargetNode).
func TestDestinationTargetNodeBypass(t *testing.T) {
	for _, host := range []string{"10.1.2.3", "100.64.0.1", "127.0.0.1", "wg.example"} {
		p, _, d := fakeNetProber(map[string][]string{"wg.example": {"10.8.0.2"}})
		m := monitorFor(model.MonitorTypeTCP, host)
		m.TargetNode = testNode
		if res := p.probe(context.Background(), m); !res.Success {
			t.Fatalf("%s with target_node: want success, got %+v", host, res)
		}
		if len(d.addresses()) != 1 {
			t.Fatalf("%s with target_node: want one dial, got %v", host, d.addresses())
		}
	}
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		return []fakePacket{{from: netip.MustParseAddr("10.1.2.3"), wire: wireMessage(ipv4.ICMPTypeEchoReply, seq, data)}}
	})
	p := fakeICMPProber(conn)
	m := model.Monitor{Type: model.MonitorTypeICMP, Target: "10.1.2.3", TargetNode: testNode, Packets: 2, TimeoutSec: 1}
	if res := p.probe(context.Background(), m); !res.Success || res.Sent != 2 || res.Lost != 0 {
		t.Fatalf("icmp to a node's private address: want 2 of 2, got %+v", res)
	}
}

// IPv6 forms that embed or reach IPv4 space are judged by the IPv4 address
// they carry, or refused outright, beyond the shared rule; a zone does not
// change the verdict.
func TestDestinationRefusesTransitionForms(t *testing.T) {
	refused := []string{
		"64:ff9b::a9fe:a9fe",       // NAT64 of 169.254.169.254
		"64:ff9b::a00:1",           // NAT64 of 10.0.0.1
		"64:ff9b::7f00:1",          // NAT64 of 127.0.0.1
		"2002:7f00:1::",            // 6to4 of 127.0.0.1
		"2002:a9fe:a9fe::1",        // 6to4 of 169.254.169.254
		"::7f00:1",                 // IPv4-compatible
		"::808:808",                // IPv4-compatible, even of a public address
		"::ffff:0:a00:1",           // IPv4-translated 10.0.0.1
		"fec0::1",                  // site-local
		"2001:0:4136:e378::1",      // Teredo
		"64:ff9b:1::a00:1",         // local-use NAT64
		"64:ff9b::a9fe:a9fe%eth0",  // a zone does not hide it
		"2002:7f00:1::%lo",         // nor here
		"fd00:ec2::254%eth0",       // nor on the shared rule
		"::ffff:169.254.169.254",   // mapped metadata
		"[64:ff9b::a9fe:a9fe]",     // bracketed
		"64:FF9B::A9FE:A9FE",       // upper case
		"0:0:0:0:0:ffff:7f00:0001", // mapped loopback, long form
		"2002:c0a8:0101::",         // 6to4 of 192.168.1.1
		"64:ff9b::6440:1",          // NAT64 of 100.64.0.1
		"64:ff9b::e000:1",          // NAT64 of 224.0.0.1
		"64:ff9b::ffff:ffff",       // NAT64 of broadcast
		"64:ff9b::",                // NAT64 of 0.0.0.0
		"2002::",                   // 6to4 of 0.0.0.0
		"::ffff:0:0",               // IPv4-translated 0.0.0.0
		"::ffff:0:ffff:ffff",       // IPv4-translated broadcast
	}
	for _, raw := range refused {
		p, _, d := fakeNetProber(nil)
		res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeTCP, Target: net.JoinHostPort(strings.Trim(raw, "[]"), "443"), TimeoutSec: 1})
		if res.Reason != model.PathReasonDestinationRefused || len(d.addresses()) != 0 {
			t.Fatalf("%s: want %s and no dial, got %+v dials %v", raw, model.PathReasonDestinationRefused, res, d.addresses())
		}
	}
	allowed := []string{
		"64:ff9b::808:808", // NAT64 of 8.8.8.8
		"2002:808:808::1",  // 6to4 of 8.8.8.8
		"2001:4860::8888",  // global, outside Teredo's /32
		"2606:4700::1111",  // global
		"::ffff:0:808:808", // IPv4-translated 8.8.8.8
	}
	for _, raw := range allowed {
		if destinationRefused(netip.MustParseAddr(raw)) {
			t.Fatalf("%s is public and was refused", raw)
		}
	}
}
