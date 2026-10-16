package beacon

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// The planned addresses tests use. They are documentation addresses, which
// the bind and endpoint rules accept; the listen and dial hooks below move
// them to loopback, which those rules refuse.
var (
	plannedBind = netip.MustParseAddr("192.0.2.10")
	sourceAddr  = netip.MustParseAddrPort("198.51.100.7:40001")
)

const (
	testSource = 3
	testEpoch  = 7
)

// targetKey is a target key with distinctive bytes 0xa0 to 0xbf, so a test
// that looks for key material in logs and facts cannot match by accident.
func targetKey() wire.Key {
	var k wire.Key
	for i := range k {
		k[i] = byte(0xa0 + i)
	}
	return k
}

func pathKeyFor(source, epoch uint32) wire.Key {
	t := targetKey()
	return wire.DerivePathKey(&t, source, epoch)
}

// responderConfig is a responder configuration holding the path key of
// testSource at testEpoch, planned on plannedBind:port.
func responderConfig(port int) *model.BeaconResponderConfig {
	k := pathKeyFor(testSource, testEpoch)
	return &model.BeaconResponderConfig{
		Bind:   plannedBind.String(),
		Port:   port,
		Limits: model.DefaultBeaconLimits(),
		Table:  []model.BeaconTableKey{{SourceID: testSource, Epoch: testEpoch, Key: append([]byte(nil), k[:]...)}},
	}
}

// signedRequest encodes a request of source at epoch, sent at sent, with
// a nonce made from n.
func signedRequest(t testing.TB, source, epoch uint32, sent time.Time, n byte) []byte {
	t.Helper()
	k := pathKeyFor(source, epoch)
	req := wire.Request{Epoch: epoch, SourceID: source, Seq: uint32(n), SentUnixNano: sent.UnixNano()}
	req.Nonce[0], req.Nonce[1] = n, 0x5a
	buf := make([]byte, wire.RequestLen)
	if _, err := wire.EncodeRequest(buf, &k, &req); err != nil {
		t.Fatal(err)
	}
	return buf
}

// loopbackListener binds 127.0.0.1 on the planned port (0 picks one) and
// records every address the responder asked for.
type loopbackListener struct {
	mu    sync.Mutex
	asked []netip.AddrPort
	conns []*net.UDPConn
}

func (l *loopbackListener) listen(addr netip.AddrPort) (packetConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, addr)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(addr.Port())})
	if err != nil {
		return nil, err
	}
	l.conns = append(l.conns, conn)
	return conn, nil
}

func (l *loopbackListener) calls() []netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]netip.AddrPort(nil), l.asked...)
}

// localAddr is the loopback address the latest socket is bound to.
func (l *loopbackListener) localAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		t.Fatal("no socket was bound")
	}
	return l.conns[len(l.conns)-1].LocalAddr().(*net.UDPAddr).AddrPort()
}

// freeUDPPort returns a loopback UDP port that was free a moment ago.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// listeningResponder starts a responder on loopback with the test table.
func listeningResponder(t *testing.T, now func() time.Time) (*Responder, *loopbackListener, netip.AddrPort) {
	t.Helper()
	l := &loopbackListener{}
	r := NewResponder(false)
	r.listen = l.listen
	r.refuseSource = allowLoopback
	if now != nil {
		r.now = now
	}
	t.Cleanup(r.Close)
	r.Apply(responderConfig(freeUDPPort(t)))
	if f := r.Facts(); f.State != model.BeaconAgentListening {
		t.Fatalf("facts after apply: %+v", f)
	}
	return r, l, l.localAddr(t)
}

// exchange sends pkt to addr from a fresh socket and returns the reply, or
// nil when none comes within wait.
func exchange(t *testing.T, addr netip.AddrPort, pkt []byte, wait time.Duration) []byte {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(pkt); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

// fakeConn is a packetConn fed by a test, one datagram at a time.
type fakeConn struct {
	in     chan datagram
	mu     sync.Mutex
	out    [][]byte
	closed chan struct{}
	once   sync.Once
}

type datagram struct {
	pkt  []byte
	from netip.AddrPort
	// at, when set, is when the datagram arrives on the test's clock.
	at time.Time
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan datagram), closed: make(chan struct{})}
}

func (c *fakeConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-c.in:
		return copy(b, d.pkt), d.from, nil
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (c *fakeConn) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out = append(c.out, append([]byte(nil), b...))
	return len(b), nil
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.out...)
}

// send hands the loop one datagram, or reports false once the socket is
// closed.
func (c *fakeConn) send(d datagram) bool {
	select {
	case c.in <- d:
		return true
	case <-c.closed:
		return false
	}
}

// fakeClock is a clock a test moves.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newTestLoop is a receive loop around a real wire.Responder holding the
// test table, started at start.
func newTestLoop(t testing.TB, start time.Time) *loop {
	t.Helper()
	core := wire.NewResponder(start)
	if err := core.SetTable([]wire.TableEntry{
		{SourceID: testSource, Epoch: testEpoch, Key: pathKeyFor(testSource, testEpoch)},
		{SourceID: 4, Epoch: 1, Key: pathKeyFor(4, 1), Retired: true},
	}); err != nil {
		t.Fatal(err)
	}
	return newLoop(nil, core, start)
}

// allowLoopback is the sender rule with loopback allowed, for responders
// that tests reach over 127.0.0.1.
func allowLoopback(from netip.AddrPort) bool {
	return !from.Addr().IsLoopback() && sourceRefused(from)
}
