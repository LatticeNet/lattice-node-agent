package prober

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
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

// A target the control plane resolved from a node (target_node) skips the
// private-range rule: nodes reach each other over private networks.
func TestDestinationTargetNodeBypass(t *testing.T) {
	for _, host := range []string{"10.1.2.3", "100.64.0.1", "127.0.0.1"} {
		p, _, d := fakeNetProber(nil)
		m := monitorFor(model.MonitorTypeTCP, host)
		m.TargetNode = testNode
		if res := p.probe(context.Background(), m); !res.Success {
			t.Fatalf("%s with target_node: want success, got %+v", host, res)
		}
		if len(d.addresses()) != 1 {
			t.Fatalf("%s with target_node: want one dial, got %v", host, d.addresses())
		}
	}
	p, _, d := fakeNetProber(map[string][]string{"wg.example": {"10.8.0.2"}})
	m := monitorFor(model.MonitorTypeHTTP, "wg.example")
	m.TargetNode = testNode
	res := p.probe(context.Background(), m)
	if res.Reason == model.PathReasonDestinationRefused {
		t.Fatalf("a node target resolving to a private address was refused: %+v", res)
	}
	if got := d.addresses(); len(got) != 1 || got[0] != "10.8.0.2:80" {
		t.Fatalf("dialed %v, want the resolved node address", got)
	}
}
