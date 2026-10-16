package beacon

import (
	"net"
	"net/netip"
	"testing"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
)

// Nothing on the drop path allocates: not the guard, not the length check,
// not a decision Handle drops, not a guard refusal.
func TestDropPathAllocatesNothing(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	l := newTestLoop(t, t0)
	replayed := signedRequest(t, testSource, testEpoch, now, 1)
	if n := l.process(now, replayed, sourceAddr); n != wire.ReplyLen {
		t.Fatalf("setup: %d bytes", n)
	}
	badTag := signedRequest(t, testSource, testEpoch, now, 2)
	badTag[95] ^= 1
	drops := map[string][]byte{
		"97 bytes":       append(signedRequest(t, testSource, testEpoch, now, 3), 0),
		"empty":          {},
		"wrong magic":    make([]byte, wire.RequestLen),
		"unknown source": signedRequest(t, 9, testEpoch, now, 4),
		"unknown epoch":  signedRequest(t, testSource, 9, now, 5),
		"bad tag":        badTag,
		"replay":         replayed,
	}
	for name, pkt := range drops {
		allocs := testing.AllocsPerRun(1000, func() {
			if n := l.process(now, pkt, sourceAddr); n != 0 {
				t.Fatalf("%s replied", name)
			}
		})
		if allocs != 0 {
			t.Fatalf("%s: %.1f allocations per datagram", name, allocs)
		}
	}
	// A guard refusal: one address over its bucket's budget.
	g := newTestLoop(t, t0)
	from := netip.MustParseAddrPort("203.0.113.9:9")
	for range guardPerBucketPerSecond {
		g.process(now, nil, from)
	}
	allocs := testing.AllocsPerRun(1000, func() { g.process(now, nil, from) })
	if allocs != 0 {
		t.Fatalf("guard refusal: %.1f allocations", allocs)
	}
	if g.guardDrops.Load() == 0 {
		t.Fatal("the guard refused nothing")
	}
}

// The same holds over a real socket: reading a datagram, deciding to drop
// it, and going back to the socket allocate nothing.
func TestSocketDropPathAllocatesNothing(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	to := server.LocalAddr().(*net.UDPAddr).AddrPort()
	l := newTestLoop(t, t0)
	l.conn = server
	pkt := signedRequest(t, 9, testEpoch, time.Now(), 1) // unknown source
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := client.WriteToUDPAddrPort(pkt, to); err != nil {
			t.Fatal(err)
		}
		n, from, err := l.conn.ReadFromUDPAddrPort(l.buf[:])
		if err != nil {
			t.Fatal(err)
		}
		if r := l.process(time.Now(), l.buf[:n], from); r != 0 {
			t.Fatal("replied")
		}
	})
	if allocs != 0 {
		t.Fatalf("%.1f allocations per datagram over a socket", allocs)
	}
}

// The guard caps each bucket and the whole second, then starts over.
func TestGuardBudgets(t *testing.T) {
	g := newGuard()
	sec := t0.UnixNano()
	one := netip.MustParseAddr("203.0.113.1")
	for i := range guardPerBucketPerSecond {
		if v := g.allow(one, sec); v != guardAllow {
			t.Fatalf("datagram %d refused: %v", i, v)
		}
	}
	if v := g.allow(one, sec); v != guardBucketFull {
		t.Fatalf("over the bucket: %v", v)
	}
	if v := g.allow(one, sec+int64(time.Second)); v != guardAllow {
		t.Fatalf("next second: %v", v)
	}
	// Many addresses together hit the global budget.
	g = newGuard()
	allowed := 0
	for i := range 3 * guardGlobalPerSecond {
		a := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if g.allow(a, sec) == guardAllow {
			allowed++
		}
	}
	if allowed > guardGlobalPerSecond || !g.full(sec) {
		t.Fatalf("allowed %d in one second, full %v", allowed, g.full(sec))
	}
	if g.full(sec + int64(time.Second)) {
		t.Fatal("full carried into the next second")
	}
}

// When the global budget is spent the loop stops reading for the rest of
// the second, and that second counts as hot for the breaker.
func TestLoopPausesWhenTheGlobalBudgetIsSpent(t *testing.T) {
	conn := newFakeConn()
	l := newTestLoop(t, t0)
	l.conn = conn
	clock := &fakeClock{t: t0.Add(time.Minute + 250*time.Millisecond)}
	var slept []time.Duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = l.serve(clock.now, func(d time.Duration) { slept = append(slept, d) })
	}()
	junk := make([]byte, wire.RequestLen)
	for i := range guardGlobalPerSecond {
		conn.send(datagram{pkt: junk, from: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 9)})
	}
	_ = conn.Close()
	<-done
	if len(slept) != 1 || slept[0] != 750*time.Millisecond {
		t.Fatalf("slept %v", slept)
	}
	if !l.breaker.saturated {
		t.Fatal("the spent second is not marked for the breaker")
	}
}

// The breaker opens only on a minute with at most six quiet seconds, the
// oldest second of the window included.
func TestBreakerWindow(t *testing.T) {
	hotSecond := func(b *breaker, sec int) {
		for i := range breakerDropsPerSecond {
			b.record(t0.Add(time.Duration(sec)*time.Second+time.Duration(i)).UnixNano(), true)
		}
	}
	var b breaker
	for sec := range 60 {
		if sec%10 == 5 {
			b.record(t0.Add(time.Duration(sec)*time.Second).UnixNano(), true) // a quiet second
			continue
		}
		hotSecond(&b, sec)
	}
	if !b.open() {
		t.Fatalf("54 hot seconds of 60, oldest hot: closed (%d hot)", b.hotSeconds())
	}
	var c breaker
	for sec := range 60 {
		if sec%5 == 2 {
			continue // twelve quiet seconds
		}
		hotSecond(&c, sec)
	}
	if c.open() {
		t.Fatalf("48 hot seconds opened the breaker")
	}
	// A clock that steps back keeps counting into the current second.
	var d breaker
	d.record(t0.UnixNano(), true)
	d.record(t0.Add(-time.Hour).UnixNano(), true)
	if d.drops != 2 {
		t.Fatalf("drops %d", d.drops)
	}
}
