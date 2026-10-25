package prober

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// fakePacket is one datagram the fake echo socket delivers.
type fakePacket struct {
	from  netip.Addr
	wire  []byte
	delay time.Duration
}

// fakeICMP is an echo socket whose replies a test scripts per echo.
type fakeICMP struct {
	answer   func(seq int, data []byte) []fakePacket
	writeErr func(seq int) error // nil, or the error a send of seq gets
	readErrs []error             // returned by the next reads, in order
	inbox    chan fakePacket
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	sent     int
	reads    int
}

func newFakeICMP(answer func(seq int, data []byte) []fakePacket) *fakeICMP {
	return &fakeICMP{answer: answer, inbox: make(chan fakePacket, 64), closed: make(chan struct{})}
}

func (f *fakeICMP) WriteTo(b []byte, _ net.Addr) (int, error) {
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), b)
	if err != nil {
		return 0, err
	}
	body := msg.Body.(*icmp.Echo)
	if f.writeErr != nil {
		if err := f.writeErr(body.Seq); err != nil {
			return 0, err
		}
	}
	f.mu.Lock()
	f.sent++
	f.mu.Unlock()
	for _, pk := range f.answer(body.Seq, append([]byte(nil), body.Data...)) {
		time.AfterFunc(pk.delay, func() {
			select {
			case f.inbox <- pk:
			case <-f.closed:
			}
		})
	}
	return len(b), nil
}

func (f *fakeICMP) ReadFrom(b []byte) (int, net.Addr, error) {
	f.mu.Lock()
	f.reads++
	if len(f.readErrs) > 0 {
		err := f.readErrs[0]
		f.readErrs = f.readErrs[1:]
		f.mu.Unlock()
		return 0, nil, err
	}
	wait := time.Until(f.deadline)
	f.mu.Unlock()
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	select {
	case pk := <-f.inbox:
		return copy(b, pk.wire), &net.UDPAddr{IP: pk.from.AsSlice()}, nil
	case <-timer.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-f.closed:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeICMP) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline = t
	return nil
}

func (f *fakeICMP) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeICMP) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent
}

func wireMessage(t icmp.Type, seq int, data []byte) []byte {
	b, err := (&icmp.Message{Type: t, Body: &icmp.Echo{ID: 1, Seq: seq, Data: data}}).Marshal(nil)
	if err != nil {
		panic(err)
	}
	return b
}

var icmpTarget = netip.MustParseAddr("203.0.113.20")

func reply(seq int, data []byte, delay time.Duration) fakePacket {
	return fakePacket{from: icmpTarget, wire: wireMessage(ipv4.ICMPTypeEchoReply, seq, data), delay: delay}
}

func fakeICMPProber(conn *fakeICMP) *prober {
	p := newProber()
	p.spacing = 5 * time.Millisecond
	p.echoWait = 150 * time.Millisecond
	p.listenICMP = func() (icmpConn, error) { return conn, nil }
	p.caps = newCapabilities(p.listenICMP)
	return p
}

func icmpMonitor(packets int) model.Monitor {
	return model.Monitor{ID: "mi", Type: model.MonitorTypeICMP, Target: icmpTarget.String(), Packets: packets, TimeoutSec: 1}
}

// Only a reply from the target carrying an outstanding echo's exact
// payload counts. A reply with a forged payload, one from another host,
// an echo request and a duplicate do not.
func TestICMPCountsOnlyVerifiedReplies(t *testing.T) {
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		switch seq {
		case 0: // right source, payload guessed wrong
			forged := slices.Clone(data)
			forged[len(forged)-1] ^= 0xff
			return []fakePacket{reply(seq, forged, time.Millisecond)}
		case 1: // right payload, wrong source
			pk := reply(seq, data, time.Millisecond)
			pk.from = netip.MustParseAddr("198.51.100.66")
			return []fakePacket{pk}
		case 2: // an echo request is not a reply
			return []fakePacket{{from: icmpTarget, wire: wireMessage(ipv4.ICMPTypeEcho, seq, data), delay: time.Millisecond}}
		case 3: // the right reply, delivered twice
			return []fakePacket{reply(seq, data, time.Millisecond), reply(seq, data, 2*time.Millisecond)}
		}
		return nil // seq 4: lost
	})
	res := fakeICMPProber(conn).probe(context.Background(), icmpMonitor(5))
	if res.Sent != 5 || res.Lost != 4 || len(res.RTTsMs) != 1 {
		t.Fatalf("want sent 5 lost 4 and one RTT, got %+v", res)
	}
	if !res.Success || res.Reason != "" {
		t.Fatalf("one verified reply makes the run a success: %+v", res)
	}
}

// A truncated payload or one with the marker but someone else's random
// half is not a match either.
func TestICMPRejectsPartialPayloads(t *testing.T) {
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		switch seq {
		case 0:
			return []fakePacket{reply(seq, data[:len(data)-1], time.Millisecond)}
		default:
			other := slices.Clone(data)
			copy(other[len(icmpMarker):], make([]byte, icmpRandomLen))
			return []fakePacket{reply(seq, other, time.Millisecond)}
		}
	})
	res := fakeICMPProber(conn).probe(context.Background(), icmpMonitor(2))
	if res.Success || res.Sent != 2 || res.Lost != 2 || res.RTTsMs != nil {
		t.Fatalf("no reply should count: %+v", res)
	}
	if res.Error == "" || res.Reason != "" {
		t.Fatalf("all-loss is a failure with an error, not a reason: %+v", res)
	}
}

// RTTs come in send order, only for echoes that came back; LatencyMs is
// their median and lost echoes are counted.
func TestICMPMultiPacketCountsAndMedian(t *testing.T) {
	delays := map[int]time.Duration{0: 300 * time.Millisecond, 2: 20 * time.Millisecond, 3: 150 * time.Millisecond}
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		if d, ok := delays[seq]; ok {
			return []fakePacket{reply(seq, data, d)}
		}
		return nil
	})
	p := fakeICMPProber(conn)
	p.echoWait = time.Second
	res := p.probe(context.Background(), icmpMonitor(5))
	if res.Sent != 5 || res.Lost != 2 || len(res.RTTsMs) != 3 || conn.sentCount() != 5 {
		t.Fatalf("want sent 5 lost 2 and three RTTs, got %+v (socket saw %d)", res, conn.sentCount())
	}
	r := res.RTTsMs
	if !(r[0] > r[2] && r[2] > r[1]) {
		t.Fatalf("RTTs %v are not in send order (300, 20, 150 ms)", r)
	}
	if res.LatencyMs != r[2] {
		t.Fatalf("latency %v is not the median of %v", res.LatencyMs, r)
	}
	if !res.Success {
		t.Fatalf("replies came back: %+v", res)
	}
}

// A reply that arrives after its echo's wait is lost.
func TestICMPLateReplyIsLost(t *testing.T) {
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		return []fakePacket{reply(seq, data, 400*time.Millisecond)}
	})
	p := fakeICMPProber(conn)
	p.echoWait = 60 * time.Millisecond
	res := p.probe(context.Background(), icmpMonitor(1))
	if res.Success || res.Sent != 1 || res.Lost != 1 {
		t.Fatalf("a late reply counted: %+v", res)
	}
}

func TestICMPDefaultsToFivePacketsAndCapsAtTen(t *testing.T) {
	for _, c := range []struct{ packets, want int }{{0, 5}, {1, 1}, {10, 10}, {40, 10}} {
		conn := newFakeICMP(func(seq int, data []byte) []fakePacket { return []fakePacket{reply(seq, data, 0)} })
		res := fakeICMPProber(conn).probe(context.Background(), icmpMonitor(c.packets))
		if res.Sent != c.want || res.Lost != 0 || len(res.RTTsMs) != c.want {
			t.Fatalf("packets %d: want %d echoes, got %+v", c.packets, c.want, res)
		}
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{nil, 0},
		{[]float64{7}, 7},
		{[]float64{9, 1, 5}, 5},
		{[]float64{4, 1, 3, 2}, 2.5},
		{[]float64{10, 30}, 20},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Fatalf("median(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	in := []float64{3, 1, 2}
	median(in)
	if !slices.Equal(in, []float64{3, 1, 2}) {
		t.Fatalf("median reordered its input: %v", in)
	}
}

// When the kernel refuses the echo socket (ping_group_range excludes the
// agent), the run reports icmp_not_permitted with nothing sent, and the
// facts move icmp from probe_methods to probe_refusals at once.
func TestICMPPermissionFallback(t *testing.T) {
	for _, refusal := range []error{
		&os.SyscallError{Syscall: "socket", Err: syscall.EACCES},
		&os.SyscallError{Syscall: "socket", Err: syscall.EPERM},
		&net.OpError{Op: "listen", Net: "udp4", Err: &os.SyscallError{Syscall: "socket", Err: syscall.EPROTONOSUPPORT}},
	} {
		allowed := true
		listen := func() (icmpConn, error) {
			if allowed {
				return newFakeICMP(func(int, []byte) []fakePacket { return nil }), nil
			}
			return nil, refusal
		}
		p := newProber()
		p.listenICMP = listen
		p.caps = newCapabilities(listen)
		if methods, refusals := p.caps.facts(); !slices.Contains(methods, model.MonitorTypeICMP) || len(refusals) != 0 {
			t.Fatalf("permitted host: methods %v refusals %v", methods, refusals)
		}
		allowed = false
		res := p.probe(context.Background(), icmpMonitor(3))
		if res.Reason != model.PathReasonICMPNotPermitted || res.Success || res.Sent != 0 || res.Lost != 0 {
			t.Fatalf("%v: want %s with sent 0, got %+v", refusal, model.PathReasonICMPNotPermitted, res)
		}
		methods, refusals := p.caps.facts()
		if slices.Contains(methods, model.MonitorTypeICMP) || refusals[model.MonitorTypeICMP] != model.PathReasonICMPNotPermitted {
			t.Fatalf("%v: refused run did not move icmp to refusals: methods %v refusals %v", refusal, methods, refusals)
		}
		if !slices.Equal(methods, []string{model.MonitorTypeDNS, model.MonitorTypeHTTP, model.MonitorTypeTCP}) {
			t.Fatalf("dns, tcp and http always run: %v", methods)
		}
	}
}

// The facts ask the kernel again after capabilityRecheck, so a changed
// ping_group_range shows up without a restart; a transient error keeps
// what is known.
func TestCapabilitiesRecheck(t *testing.T) {
	var listenErr error = &os.SyscallError{Syscall: "socket", Err: syscall.EACCES}
	calls := 0
	c := newCapabilities(func() (icmpConn, error) {
		calls++
		if listenErr != nil {
			return nil, listenErr
		}
		return newFakeICMP(nil), nil
	})
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	_, refusals := c.facts()
	if refusals[model.MonitorTypeICMP] != model.PathReasonICMPNotPermitted {
		t.Fatalf("first check: refusals %v", refusals)
	}
	listenErr = nil
	now = now.Add(capabilityRecheck - time.Second)
	if _, refusals := c.facts(); len(refusals) != 1 || calls != 1 {
		t.Fatalf("rechecked early: refusals %v calls %d", refusals, calls)
	}
	now = now.Add(time.Second)
	if methods, refusals := c.facts(); !slices.Contains(methods, model.MonitorTypeICMP) || len(refusals) != 0 {
		t.Fatalf("after the recheck: methods %v refusals %v", methods, refusals)
	}
	listenErr = &os.SyscallError{Syscall: "socket", Err: syscall.EMFILE}
	now = now.Add(capabilityRecheck)
	if methods, _ := c.facts(); !slices.Contains(methods, model.MonitorTypeICMP) {
		t.Fatalf("a transient error dropped icmp: %v", methods)
	}
	if calls != 3 {
		t.Fatalf("want 3 kernel checks, got %d", calls)
	}
}

// Facts reports what this host allows; the real kernel decides.
func TestFactsAreConsistent(t *testing.T) {
	methods, refusals := Facts()
	for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeHTTP} {
		if !slices.Contains(methods, kind) {
			t.Fatalf("%s always runs: %v", kind, methods)
		}
	}
	_, refused := refusals[model.MonitorTypeICMP]
	if slices.Contains(methods, model.MonitorTypeICMP) == refused {
		t.Fatalf("icmp must be in exactly one of methods %v and refusals %v", methods, refusals)
	}
	if !slices.IsSorted(methods) || !slices.Equal(methods, model.NormalizeProbeMethods(methods)) {
		t.Fatalf("methods %v are not the normalized form", methods)
	}
}

func TestICMPTargetMustHaveIPv4(t *testing.T) {
	p, _, _ := fakeNetProber(map[string][]string{"v6only.example": {"2001:4860::8888"}})
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeICMP, Target: "v6only.example", TimeoutSec: 1})
	if res.Success || res.Sent != 0 || res.Reason != "" || res.Error == "" {
		t.Fatalf("want a failure with nothing sent, got %+v", res)
	}
}

// A real unprivileged echo socket to loopback. Where the kernel refuses
// the socket (Linux with ping_group_range excluding this user) the run
// must say so with icmp_not_permitted, and the test skips.
func TestICMPRealSocketLoopback(t *testing.T) {
	m := model.Monitor{ID: "loop", Type: model.MonitorTypeICMP, Target: "127.0.0.1", TargetNode: testNode, Packets: 3, TimeoutSec: 1}
	res := newProber().probe(context.Background(), m)
	if res.Reason == model.PathReasonICMPNotPermitted {
		if res.Sent != 0 {
			t.Fatalf("refused socket reported sent %d", res.Sent)
		}
		t.Skipf("kernel refuses unprivileged echo sockets here: %s", res.Error)
	}
	if !res.Success || res.Sent != 3 || res.Lost != 0 || len(res.RTTsMs) != 3 {
		t.Fatalf("loopback echoes: want 3 of 3 back, got %+v", res)
	}
	if res.LatencyMs != median(res.RTTsMs) {
		t.Fatalf("latency %v is not the median of %v", res.LatencyMs, res.RTTsMs)
	}
}

// Without target_node, loopback is refused before a socket opens.
func TestICMPRealSocketRefusesLoopbackWithoutNode(t *testing.T) {
	opened := false
	p := newProber()
	p.listenICMP = func() (icmpConn, error) { opened = true; return nil, errors.New("unreachable") }
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeICMP, Target: "127.0.0.1", TimeoutSec: 1})
	if res.Reason != model.PathReasonDestinationRefused || opened {
		t.Fatalf("want %s without a socket, got %+v opened=%v", model.PathReasonDestinationRefused, res, opened)
	}
}

// A reply that lands after its own echo's wait but while the run is still
// waiting for a later echo does not count.
func TestICMPReplyPastItsOwnWaitIsLost(t *testing.T) {
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket {
		if seq == 0 {
			return []fakePacket{reply(seq, data, 250*time.Millisecond)}
		}
		return []fakePacket{reply(seq, data, 10*time.Millisecond)}
	})
	p := fakeICMPProber(conn)
	p.spacing = 200 * time.Millisecond
	p.echoWait = 150 * time.Millisecond
	res := p.probe(context.Background(), icmpMonitor(2))
	if res.Sent != 2 || res.Lost != 1 || len(res.RTTsMs) != 1 || !res.Success {
		t.Fatalf("echo 0 answered at 250 ms with a 150 ms wait must be lost: %+v", res)
	}
	// A wait shorter than the spacing must not turn the loop into a spin
	// on a read deadline in the past.
	conn.mu.Lock()
	reads := conn.reads
	conn.mu.Unlock()
	if reads > 20 {
		t.Fatalf("the run read %d times for 2 echoes; it is spinning", reads)
	}
}

// An echo the kernel will not send never left: it is neither sent nor
// lost, sending stops there, and the run does not wait out its budget.
func TestICMPSendErrorEndsSending(t *testing.T) {
	unreachable := &os.SyscallError{Syscall: "sendto", Err: syscall.ENETUNREACH}

	conn := newFakeICMP(func(int, []byte) []fakePacket { return nil })
	conn.writeErr = func(int) error { return unreachable }
	p := fakeICMPProber(conn)
	p.echoWait = 2 * time.Second
	start := time.Now()
	res := p.probe(context.Background(), icmpMonitor(5))
	if res.Sent != 0 || res.Lost != 0 || res.Success || res.Reason != "" {
		t.Fatalf("no echo left: want sent 0 and a failure, got %+v", res)
	}
	if !strings.Contains(res.Error, "network is unreachable") {
		t.Fatalf("error %q does not say why", res.Error)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a run that sent nothing waited %s", took)
	}

	conn = newFakeICMP(func(seq int, data []byte) []fakePacket { return []fakePacket{reply(seq, data, time.Millisecond)} })
	conn.writeErr = func(seq int) error {
		if seq >= 2 {
			return unreachable
		}
		return nil
	}
	p = fakeICMPProber(conn)
	p.echoWait = 2 * time.Second
	start = time.Now()
	res = p.probe(context.Background(), icmpMonitor(5))
	if res.Sent != 2 || res.Lost != 0 || len(res.RTTsMs) != 2 || !res.Success {
		t.Fatalf("two echoes left and came back: want sent 2 lost 0, got %+v", res)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the run waited %s after every sent echo came back", took)
	}
}

// One read error is transient and the run goes on; a socket that keeps
// failing ends the run with the error instead of spinning.
func TestICMPReadErrors(t *testing.T) {
	transient := &os.SyscallError{Syscall: "recvfrom", Err: syscall.EINTR}
	conn := newFakeICMP(func(seq int, data []byte) []fakePacket { return []fakePacket{reply(seq, data, 5*time.Millisecond)} })
	conn.readErrs = []error{transient}
	res := fakeICMPProber(conn).probe(context.Background(), icmpMonitor(3))
	if res.Sent != 3 || res.Lost != 0 || !res.Success {
		t.Fatalf("one read error lost replies: %+v", res)
	}

	conn = newFakeICMP(func(int, []byte) []fakePacket { return nil })
	conn.readErrs = []error{transient, transient, transient, transient}
	p := fakeICMPProber(conn)
	p.echoWait = 2 * time.Second
	start := time.Now()
	res = p.probe(context.Background(), icmpMonitor(1))
	if res.Success || res.Sent != 1 || !strings.Contains(res.Error, "interrupted system call") {
		t.Fatalf("a failing socket: want a failure naming the read error, got %+v", res)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a failing socket held the run for %s", took)
	}
}

// blockingResolver never answers; only its context ends a lookup.
type blockingResolver struct{}

func (blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A run is bounded by its own deadline even when the caller's context has
// none: a lookup that never answers ends with the run's budget.
func TestICMPRunHasItsOwnDeadline(t *testing.T) {
	p := fakeICMPProber(newFakeICMP(nil))
	p.resolver = blockingResolver{}
	p.echoWait = 100 * time.Millisecond
	start := time.Now()
	res := p.probe(context.Background(), model.Monitor{Type: model.MonitorTypeICMP, Target: "slow.example", Packets: 1, TimeoutSec: 1})
	if res.Success || res.Sent != 0 || res.Error == "" {
		t.Fatalf("want a failure with nothing sent, got %+v", res)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("run took %s; its bound is the wait plus a second", took)
	}
}
