package beacon

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

var t0 = time.Unix(1_800_000_000, 0)

// The loop answers a fresh signed request with a signed ok reply and every
// rejection D3 lists with nothing at all, or with only the one signed status
// reply D12 allows a request whose tag verified.
func TestProcessAnswersOnlySignedFreshRequests(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	l := newTestLoop(t, t0)
	ok := signedRequest(t, testSource, testEpoch, now.Add(-20*time.Millisecond), 1)
	n := l.process(now, ok, sourceAddr)
	if n != wire.ReplyLen {
		t.Fatalf("fresh request: reply of %d bytes", n)
	}
	k := pathKeyFor(testSource, testEpoch)
	rep, err := wire.ParseReply(l.out[:n], &k)
	if err != nil || rep.Status != wire.StatusOK || rep.Seq != 1 {
		t.Fatalf("reply %+v, %v", rep, err)
	}

	cases := []struct {
		name string
		pkt  func() []byte
	}{
		{"empty", func() []byte { return nil }},
		{"95 bytes", func() []byte { return signedRequest(t, testSource, testEpoch, now, 2)[:95] }},
		{"97 bytes with a valid 96-byte prefix", func() []byte {
			return append(signedRequest(t, testSource, testEpoch, now, 3), 0)
		}},
		{"128 bytes with a valid 96-byte prefix", func() []byte {
			return append(signedRequest(t, testSource, testEpoch, now, 4), make([]byte, 32)...)
		}},
		{"wrong tag", func() []byte { p := signedRequest(t, testSource, testEpoch, now, 5); p[95] ^= 1; return p }},
		{"body changed after signing", func() []byte { p := signedRequest(t, testSource, testEpoch, now, 6); p[20] ^= 1; return p }},
		{"signed with another source's key", func() []byte {
			p := signedRequest(t, 9, testEpoch, now, 7)
			p[12] = testSource // claims source 3, signed by 9's key
			return p
		}},
		{"unknown source id", func() []byte { return signedRequest(t, 9, testEpoch, now, 8) }},
		{"unknown epoch", func() []byte { return signedRequest(t, testSource, testEpoch+1, now, 9) }},
		{"replayed nonce", func() []byte { return ok }},
		{"zero padding replaced", func() []byte { p := signedRequest(t, testSource, testEpoch, now, 10); p[60] = 1; return p }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := l.out
			if n := l.process(now, c.pkt(), sourceAddr); n != 0 {
				t.Fatalf("replied %d bytes", n)
			}
			if l.out != before {
				t.Fatal("a drop wrote into the reply buffer")
			}
		})
	}
	if p := l.panics.Load(); p != 0 {
		t.Fatalf("%d panics", p)
	}
}

// Stale timestamps, timestamps before the responder started and retired
// epochs draw one signed status reply per second per source id, never a
// measurement and never more.
func TestProcessNamesStaleAndRetiredOnlyOncePerSecond(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	for _, c := range []struct {
		name          string
		at, sent      time.Time
		source, epoch uint32
		status        wire.Status
	}{
		{"older than the window", now, now.Add(-61 * time.Second), testSource, testEpoch, wire.StatusStale},
		{"ahead of the window", now, now.Add(61 * time.Second), testSource, testEpoch, wire.StatusStale},
		{"before the responder started", t0.Add(30 * time.Second), t0.Add(-time.Second), testSource, testEpoch, wire.StatusStale},
		{"retired epoch", now, now, 4, 1, wire.StatusUnknownEpoch},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newTestLoop(t, t0)
			n := l.process(c.at, signedRequest(t, c.source, c.epoch, c.sent, 1), sourceAddr)
			if n != wire.ReplyLen {
				t.Fatalf("first: %d bytes", n)
			}
			k := pathKeyFor(c.source, c.epoch)
			rep, err := wire.ParseReply(l.out[:n], &k)
			if err != nil || rep.Status != c.status {
				t.Fatalf("reply %+v, %v", rep, err)
			}
			if n := l.process(c.at.Add(500*time.Millisecond), signedRequest(t, c.source, c.epoch, c.sent, 2), sourceAddr); n != 0 {
				t.Fatalf("a second status reply inside a second: %d bytes", n)
			}
		})
	}
}

// Over socket: the responder replies with 64 bytes to a signed request and
// with nothing to a 97-byte datagram that starts with one, or to any other
// rejection. No reply is ever larger than the datagram it answers.
func TestResponderSocketRepliesNeverExceedRequests(t *testing.T) {
	_, _, addr := listeningResponder(t, nil)
	now := time.Now()
	rep := exchange(t, addr, signedRequest(t, testSource, testEpoch, now, 1), 2*time.Second)
	if len(rep) != wire.ReplyLen || len(rep) >= wire.RequestLen {
		t.Fatalf("reply of %d bytes to a %d-byte request", len(rep), wire.RequestLen)
	}
	k := pathKeyFor(testSource, testEpoch)
	if got, err := wire.ParseReply(rep, &k); err != nil || got.Status != wire.StatusOK {
		t.Fatalf("reply %+v, %v", got, err)
	}
	silent := map[string][]byte{
		"97 bytes, valid prefix": append(signedRequest(t, testSource, testEpoch, now, 2), 0),
		"1400 bytes":             append(signedRequest(t, testSource, testEpoch, now, 3), make([]byte, 1304)...),
		"wrong tag":              func() []byte { p := signedRequest(t, testSource, testEpoch, now, 4); p[90] ^= 0xff; return p }(),
		"unknown source":         signedRequest(t, 99, testEpoch, now, 5),
		"unknown epoch":          signedRequest(t, testSource, 99, now, 6),
		"short":                  []byte("LTB1"),
	}
	for name, pkt := range silent {
		if rep := exchange(t, addr, pkt, 300*time.Millisecond); rep != nil {
			t.Fatalf("%s: replied %d bytes", name, len(rep))
		}
	}
	// The socket still answers after all of that.
	if rep := exchange(t, addr, signedRequest(t, testSource, testEpoch, time.Now(), 7), 2*time.Second); len(rep) != wire.ReplyLen {
		t.Fatalf("after the rejections: reply of %d bytes", len(rep))
	}
}

// The node veto is checked before any bind: a responder built with
// -no-beacon never calls listen, reports refused_by_node, and still wipes
// the keys it was handed.
func TestNoBeaconRefusesBeforeBind(t *testing.T) {
	r := NewResponder(true)
	var called atomic.Bool
	r.listen = func(netip.AddrPort) (packetConn, error) {
		called.Store(true)
		return nil, errors.New("listen must not be called")
	}
	var changes atomic.Int32
	r.SetOnChange(func() { changes.Add(1) })
	cfg := responderConfig(45000)
	r.Apply(cfg)
	r.Apply(responderConfig(45001))
	if called.Load() {
		t.Fatal("a responder under -no-beacon called listen")
	}
	f := r.Facts()
	want := model.BeaconFacts{Responder: true, Refusal: model.PathReasonRefusedByNode, State: model.BeaconAgentRefused}
	if f != want {
		t.Fatalf("facts %+v, want %+v", f, want)
	}
	if !bytes.Equal(cfg.Table[0].Key, make([]byte, wire.KeyLen)) {
		t.Fatal("the refused configuration's key was not wiped")
	}
	if IdleFacts(true) != want {
		t.Fatalf("IdleFacts(true) = %+v", IdleFacts(true))
	}
}

// The bind address and port must be what the plan approved and of a class
// a beacon may use; the wildcard, loopback, link-local and privileged ports
// are refused without a bind.
func TestResponderRefusesBindAddressesOutsideTheRule(t *testing.T) {
	for _, c := range []struct {
		bind string
		port int
	}{
		{"0.0.0.0", 45000},
		{"", 45000},
		{"127.0.0.1", 45000},
		{"169.254.169.254", 45000},
		{"224.0.0.1", 45000},
		{"255.255.255.255", 45000},
		{"::", 45000},
		{"2001:db8::1", 45000},
		{"example.com", 45000},
		{"192.0.2.10", 53},
		{"192.0.2.10", 0},
		{"192.0.2.10", 70000},
	} {
		r := NewResponder(false)
		r.listen = func(netip.AddrPort) (packetConn, error) {
			t.Fatalf("listen called for %s:%d", c.bind, c.port)
			return nil, nil
		}
		cfg := responderConfig(c.port)
		cfg.Bind = c.bind
		r.Apply(cfg)
		if f := r.Facts(); f.State != model.BeaconAgentBindFailed || f.Error == "" || len(f.Error) > maxErrorLen {
			t.Fatalf("%s:%d: facts %+v", c.bind, c.port, f)
		}
	}
}

// A port in use is reported as bind_failed with a short error, retried only
// on the same address and port, and only after bindRetryInterval.
func TestBindFailureIsReportedAndNeverMoved(t *testing.T) {
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port
	clock := &fakeClock{t: t0}
	l := &loopbackListener{}
	r := NewResponder(false)
	r.listen, r.now = l.listen, clock.now
	t.Cleanup(r.Close)
	var changes atomic.Int32
	r.SetOnChange(func() { changes.Add(1) })
	r.Apply(responderConfig(port))
	f := r.Facts()
	if f.State != model.BeaconAgentBindFailed || f.Bind != plannedBind.String() || f.Port != port {
		t.Fatalf("facts %+v", f)
	}
	if !strings.Contains(f.Error, "address already in use") || len(f.Error) > maxErrorLen {
		t.Fatalf("error %q", f.Error)
	}
	if changes.Load() != 1 {
		t.Fatalf("%d change notices", changes.Load())
	}
	clock.set(t0.Add(30 * time.Second))
	r.Apply(responderConfig(port))
	if got := len(l.calls()); got != 1 {
		t.Fatalf("retried inside the interval: %d binds", got)
	}
	clock.set(t0.Add(bindRetryInterval + time.Second))
	r.Apply(responderConfig(port))
	calls := l.calls()
	if len(calls) != 2 {
		t.Fatalf("%d binds after the interval", len(calls))
	}
	for _, a := range calls {
		if a != netip.AddrPortFrom(plannedBind, uint16(port)) {
			t.Fatalf("bind tried %s, not the planned address", a)
		}
	}
	// Once the port is free the same address binds.
	_ = busy.Close()
	clock.set(t0.Add(2*bindRetryInterval + 2*time.Second))
	r.Apply(responderConfig(port))
	if f := r.Facts(); f.State != model.BeaconAgentListening || f.Error != "" || f.Epoch != testEpoch || f.Sources != 1 {
		t.Fatalf("facts after the port freed: %+v", f)
	}
}

// A pull without a responder closes the socket; a refreshed table keeps it.
func TestResponderClosesOnNilAndKeepsSocketAcrossTableRefresh(t *testing.T) {
	r, l, addr := listeningResponder(t, nil)
	cfg := responderConfig(int(l.calls()[0].Port()))
	k8 := pathKeyFor(testSource, testEpoch+1)
	cfg.Table = append(cfg.Table, model.BeaconTableKey{SourceID: testSource, Epoch: testEpoch + 1, Key: append([]byte(nil), k8[:]...)})
	r.Apply(cfg)
	if len(l.calls()) != 1 {
		t.Fatalf("a table refresh rebound the socket: %d binds", len(l.calls()))
	}
	if f := r.Facts(); f.Epoch != testEpoch+1 || f.Sources != 1 {
		t.Fatalf("facts %+v", f)
	}
	if rep := exchange(t, addr, signedRequest(t, testSource, testEpoch+1, time.Now(), 1), 2*time.Second); len(rep) != wire.ReplyLen {
		t.Fatalf("new epoch: %d bytes", len(rep))
	}
	r.Apply(nil)
	if f := r.Facts(); f.State != model.BeaconAgentOff || f.Bind != "" || f.Port != 0 || f.Epoch != 0 {
		t.Fatalf("facts after nil: %+v", f)
	}
	// Nothing listens there any more.
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(signedRequest(t, testSource, testEpoch, time.Now(), 2))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 128)); err == nil {
		t.Fatal("a closed responder replied")
	}
}

// A table the responder refuses closes the socket and reports why, without
// a key in the error.
func TestResponderRefusesABadTable(t *testing.T) {
	r, _, _ := listeningResponder(t, nil)
	cfg := responderConfig(45000)
	cfg.Table[0].Key = cfg.Table[0].Key[:31]
	r.Apply(cfg)
	if f := r.Facts(); f.State != model.BeaconAgentOff || !strings.Contains(f.Error, "31-byte key") {
		t.Fatalf("facts %+v", f)
	}
	cfg = responderConfig(45000)
	cfg.Table = append(cfg.Table, cfg.Table[0])
	r.Apply(cfg)
	if f := r.Facts(); f.State != model.BeaconAgentOff || !strings.Contains(f.Error, "twice") {
		t.Fatalf("facts %+v", f)
	}
}

// panicCore panics on datagrams whose first byte is 0xff and answers the
// rest through a real responder.
type panicCore struct {
	*wire.Responder
}

func (p panicCore) Handle(now time.Time, pkt, out []byte) (int, wire.Verdict) {
	if pkt[0] == 0xff {
		var table []int
		_ = table[len(pkt)] // an index error, as a parser bug would raise
	}
	return p.Responder.Handle(now, pkt, out)
}

// A panic while deciding a datagram drops that datagram; the loop goes on
// and answers the next signed request.
func TestReceiveLoopRecoversFromPanics(t *testing.T) {
	conn := newFakeConn()
	core := wire.NewResponder(t0)
	if err := core.SetTable([]wire.TableEntry{{SourceID: testSource, Epoch: testEpoch, Key: pathKeyFor(testSource, testEpoch)}}); err != nil {
		t.Fatal(err)
	}
	l := newLoop(conn, panicCore{core})
	clock := &fakeClock{t: t0.Add(time.Minute)}
	done := make(chan stopReason, 1)
	go func() {
		stop, _ := l.serve(clock.now, func(time.Duration) {})
		done <- stop
	}()
	bad := make([]byte, wire.RequestLen)
	bad[0] = 0xff
	for range 3 {
		conn.send(datagram{pkt: bad, from: sourceAddr})
	}
	conn.send(datagram{pkt: signedRequest(t, testSource, testEpoch, clock.now(), 1), from: sourceAddr})
	_ = conn.Close()
	if stop := <-done; stop != stopClosed {
		t.Fatalf("loop stopped with %v", stop)
	}
	if got := l.panics.Load(); got != 3 {
		t.Fatalf("%d panics counted", got)
	}
	if out := conn.written(); len(out) != 1 || len(out[0]) != wire.ReplyLen {
		t.Fatalf("replies after the panics: %d", len(out))
	}
}

// The breaker opens after a minute of drops above the threshold: the socket
// closes, the facts read circuit_open, and nothing binds again until the
// cooldown ends.
func TestCircuitBreakerClosesTheSocketForACooldown(t *testing.T) {
	clock := &fakeClock{t: t0}
	var conns []*fakeConn
	var binds atomic.Int32
	r := NewResponder(false)
	r.now = clock.now
	r.sleep = func(time.Duration) {}
	r.listen = func(netip.AddrPort) (packetConn, error) {
		binds.Add(1)
		c := newFakeConn()
		conns = append(conns, c)
		return c, nil
	}
	var changes atomic.Int32
	r.SetOnChange(func() { changes.Add(1) })
	r.Apply(responderConfig(45000))
	if f := r.Facts(); f.State != model.BeaconAgentListening {
		t.Fatalf("facts %+v", f)
	}
	conn := conns[0]
	junk := make([]byte, wire.RequestLen) // wrong magic: dropped before any HMAC
	opened := false
	for sec := range 120 {
		for i := range breakerDropsPerSecond + 10 {
			clock.set(t0.Add(time.Duration(sec)*time.Second + time.Duration(i)*time.Microsecond))
			if !conn.send(datagram{pkt: junk, from: netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 9)}) {
				opened = true
				break
			}
		}
		if opened {
			if sec < breakerWindowSeconds-1 {
				t.Fatalf("breaker opened after %d seconds", sec+1)
			}
			break
		}
	}
	if !opened {
		t.Fatal("two minutes of drops never opened the breaker")
	}
	waitFor(t, func() bool { return r.Facts().State == model.BeaconAgentCircuitOpen })
	f := r.Facts()
	if !conn.isClosed() || f.Bind != plannedBind.String() || f.Port != 45000 || f.Error == "" || len(f.Error) > maxErrorLen {
		t.Fatalf("facts %+v, closed %v", f, conn.isClosed())
	}
	if changes.Load() < 2 {
		t.Fatalf("the breaker did not announce itself: %d notices", changes.Load())
	}
	// During the cooldown a pull does not rebind.
	clock.set(clock.now().Add(breakerCooldown - time.Second))
	r.Apply(responderConfig(45000))
	if binds.Load() != 1 || r.Facts().State != model.BeaconAgentCircuitOpen {
		t.Fatalf("rebound during the cooldown: %d binds, %+v", binds.Load(), r.Facts())
	}
	clock.set(clock.now().Add(2 * time.Second))
	r.Apply(responderConfig(45000))
	if binds.Load() != 2 || r.Facts().State != model.BeaconAgentListening {
		t.Fatalf("after the cooldown: %d binds, %+v", binds.Load(), r.Facts())
	}
	r.Close()
}

// A flood shorter than a minute, or under the threshold, leaves the socket
// open.
func TestCircuitBreakerHoldsBelowAMinuteOrTheThreshold(t *testing.T) {
	for _, c := range []struct {
		name    string
		seconds int
		perSec  int
	}{
		{"58 seconds above the threshold", 58, breakerDropsPerSecond + 1},
		{"three minutes below it", 180, breakerDropsPerSecond - 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newTestLoop(t, t0)
			junk := make([]byte, wire.RequestLen)
			for sec := range c.seconds {
				for i := range c.perSec {
					at := t0.Add(time.Duration(sec)*time.Second + time.Duration(i)*time.Microsecond)
					l.process(at, junk, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 9))
					if l.breaker.open() {
						t.Fatalf("opened at second %d", sec)
					}
				}
			}
		})
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in 5 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An error is bounded to 200 bytes on a rune boundary.
func TestTruncateError(t *testing.T) {
	long := strings.Repeat("é", 150) // 300 bytes
	got := truncateError(long)
	if len(got) > maxErrorLen || !strings.HasPrefix(long, got) || strings.ContainsRune(got, '�') {
		t.Fatalf("%d bytes: %q", len(got), got)
	}
	if got := truncateError(" short "); got != "short" {
		t.Fatalf("%q", got)
	}
}

func TestBindErrorIsShort(t *testing.T) {
	err := &net.OpError{Op: "listen", Net: "udp4", Err: fmt.Errorf("bind: %w", syscall.EADDRINUSE)}
	got := bindError(netip.MustParseAddrPort("192.0.2.10:45000"), err)
	if got != "bind udp 192.0.2.10:45000: bind: address already in use" {
		t.Fatalf("%q", got)
	}
}
