package prober

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpConn is the part of an ICMP echo socket a run uses;
// *icmp.PacketConn satisfies it.
type icmpConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// listenUDP4ICMP opens an unprivileged datagram ICMP echo socket. Linux
// lets the agent open one only when its group is inside
// net.ipv4.ping_group_range; it needs no CAP_NET_RAW.
func listenUDP4ICMP() (icmpConn, error) {
	return icmp.ListenPacket("udp4", "0.0.0.0")
}

// icmpRefused reports whether the kernel refused the echo socket itself
// (ping_group_range excludes the agent's groups, or the kernel has no
// unprivileged echo sockets), as opposed to a transient error.
func icmpRefused(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}

// Echo payloads are 32 bytes: a fixed 16-byte marker and 16 random bytes,
// fresh for every echo. A reply counts only if it carries an outstanding
// echo's whole payload and comes from the target, so an off-path host that
// guesses the kernel's identifier and sequence still cannot forge "up".
const (
	icmpPayloadLen = 32
	icmpRandomLen  = 16
	icmpReadBuffer = 1500
)

var icmpMarker = [icmpPayloadLen - icmpRandomLen]byte{'l', 'a', 't', 't', 'i', 'c', 'e', '-', 'e', 'c', 'h', 'o', '-', 'v', '1', 0}

type echo struct {
	payload [icmpPayloadLen]byte
	sentAt  time.Time
	sent    bool
	replied bool
	rtt     time.Duration
}

func icmpPackets(m model.Monitor) int {
	return min(model.MonitorPackets(m), model.MonitorPacketsMax)
}

// probeICMP sends icmpPackets(m) echoes spacing apart, each waiting up to
// timeout for its reply, and fills res: Sent, Lost, the RTTs of the echoes
// that came back in send order, their median as LatencyMs, and Success
// when at least one came back.
func (p *prober) probeICMP(ctx context.Context, m model.Monitor, timeout time.Duration, res *model.MonitorResult) {
	if p.echoWait > 0 {
		timeout = p.echoWait
	}
	// The run's own bound: every echo's spacing and wait, and a second of
	// slack for a name lookup and scheduling.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(icmpPackets(m)-1)*p.spacing+timeout+time.Second)
	defer cancel()
	target, err := p.icmpTarget(ctx, m)
	if err != nil {
		var refused *destinationError
		if errors.As(err, &refused) {
			res.Reason = model.PathReasonDestinationRefused
		}
		res.Error = err.Error()
		return
	}
	conn, err := p.listenICMP()
	if err != nil {
		if icmpRefused(err) {
			p.caps.observeICMP(false)
			res.Reason = model.PathReasonICMPNotPermitted
			res.Error = "the kernel refuses unprivileged icmp echo sockets to this agent (net.ipv4.ping_group_range)"
			return
		}
		res.Error = "open icmp socket: " + err.Error()
		return
	}
	p.caps.observeICMP(true)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	echoes := make([]echo, icmpPackets(m))
	for i := range echoes {
		copy(echoes[i].payload[:], icmpMarker[:])
		if _, err := rand.Read(echoes[i].payload[len(icmpMarker):]); err != nil {
			res.Error = "icmp payload: " + err.Error()
			return
		}
	}
	runErr := p.runEchoes(ctx, conn, target, echoes, timeout)
	fillICMPResult(res, echoes, runErr)
}

// icmpTarget resolves and judges the target and picks its IPv4 address;
// unprivileged echo sockets here are udp4 only.
func (p *prober) icmpTarget(ctx context.Context, m model.Monitor) (netip.Addr, error) {
	host := m.Target
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return netip.Addr{}, errors.New("icmp target has no address")
	}
	addrs, err := p.resolveTarget(ctx, host, m.TargetNode != "")
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if addr.Is4() {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("icmp target %s has no IPv4 address", host)
}

// maxReadErrors is how many read errors in a row end a run; one is
// tolerated as transient, a socket that keeps failing is not spun on.
const maxReadErrors = 3

// runEchoes sends the echoes on their schedule and reads replies in one
// goroutine until every sent echo replied or the last one's wait ran out.
// An echo the kernel will not send ends the sending there: it never left,
// so it is neither sent nor lost, and the run waits only for the echoes
// already out. It returns the error that cut the run short, if any.
func (p *prober) runEchoes(ctx context.Context, conn icmpConn, target netip.Addr, echoes []echo, timeout time.Duration) error {
	dst := &net.UDPAddr{IP: target.AsSlice()}
	id := os.Getpid() & 0xffff
	buf := make([]byte, icmpReadBuffer)
	start := time.Now()
	planned := len(echoes)
	var final time.Time // the wait of the last echo sent
	var runErr error
	next, sent, replied, readErrs := 0, 0, 0, 0
	for {
		if ctx.Err() != nil {
			return runErr
		}
		now := time.Now()
		if next < planned && !now.Before(start.Add(time.Duration(next)*p.spacing)) {
			e := &echoes[next]
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: next, Data: e.payload[:]}}
			wire, err := msg.Marshal(nil)
			if err == nil {
				e.sentAt = time.Now()
				_, err = conn.WriteTo(wire, dst)
			}
			if err != nil {
				runErr = fmt.Errorf("send: %w", err)
				planned = next
				continue
			}
			e.sent = true
			sent++
			final = e.sentAt.Add(timeout)
			next++
			continue
		}
		if next == planned && (replied == sent || !now.Before(final)) {
			return runErr
		}
		deadline := final
		if next < planned {
			if sendAt := start.Add(time.Duration(next) * p.spacing); final.IsZero() || sendAt.Before(deadline) {
				deadline = sendAt
			}
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		n, peer, err := conn.ReadFrom(buf)
		recvAt := time.Now()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if readErrs++; readErrs >= maxReadErrors || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return fmt.Errorf("read: %w", err)
			}
			continue
		}
		readErrs = 0
		if matchReply(buf[:n], peer, target, echoes, recvAt, timeout) {
			replied++
		}
	}
}

// matchReply marks the echo a reply answers. The reply must be an echo
// reply from target carrying, byte for byte, the payload of an echo that
// is sent, not yet answered and still inside its wait.
func matchReply(b []byte, peer net.Addr, target netip.Addr, echoes []echo, recvAt time.Time, timeout time.Duration) bool {
	if peerAddr(peer) != target {
		return false
	}
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), b)
	if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
		return false
	}
	body, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return false
	}
	for i := range echoes {
		e := &echoes[i]
		if !e.sent || e.replied || !bytes.Equal(body.Data, e.payload[:]) {
			continue
		}
		rtt := recvAt.Sub(e.sentAt)
		if rtt > timeout {
			return false
		}
		e.replied, e.rtt = true, rtt
		return true
	}
	return false
}

func peerAddr(peer net.Addr) netip.Addr {
	var ip net.IP
	switch a := peer.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// fillICMPResult reports the echoes that left. An error that cut the run
// short explains a run with no reply; a run with a reply is a success.
func fillICMPResult(res *model.MonitorResult, echoes []echo, runErr error) {
	for _, e := range echoes {
		if !e.sent {
			continue
		}
		res.Sent++
		if e.replied {
			res.RTTsMs = append(res.RTTsMs, elapsedMs(e.rtt))
		}
	}
	res.Lost = res.Sent - len(res.RTTsMs)
	if len(res.RTTsMs) > 0 {
		res.Success = true
		res.LatencyMs = median(res.RTTsMs)
		return
	}
	if runErr != nil {
		res.Error = fmt.Sprintf("icmp echo after %d sent: %v", res.Sent, runErr)
		return
	}
	res.Error = fmt.Sprintf("no reply to %d icmp echoes", res.Sent)
}

// median is the middle value, or the mean of the two middle values when
// there is an even number of them.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// capabilityRecheck is how often the agent asks the kernel again whether
// it may open echo sockets, so a changed ping_group_range shows up in the
// facts without a restart.
const capabilityRecheck = 10 * time.Minute

// capabilities tracks which probe methods this host lets the agent run.
// A run that the kernel refuses updates it at once; otherwise facts asks
// the kernel at most every capabilityRecheck.
type capabilities struct {
	mu          sync.Mutex
	listen      func() (icmpConn, error)
	now         func() time.Time
	checkedAt   time.Time
	icmpRefusal string
}

func newCapabilities(listen func() (icmpConn, error)) *capabilities {
	return &capabilities{listen: listen, now: time.Now}
}

func (c *capabilities) facts() ([]string, map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checkedAt.IsZero() || c.now().Sub(c.checkedAt) >= capabilityRecheck {
		c.checkICMPLocked()
	}
	methods := []string{model.MonitorTypeHTTP, model.MonitorTypeTCP}
	refusals := map[string]string{}
	if c.icmpRefusal == "" {
		methods = append(methods, model.MonitorTypeICMP)
	} else {
		refusals[model.MonitorTypeICMP] = c.icmpRefusal
	}
	slices.Sort(methods)
	return methods, refusals
}

func (c *capabilities) checkICMPLocked() {
	conn, err := c.listen()
	switch {
	case err == nil:
		_ = conn.Close()
		c.setICMPLocked(true)
	case icmpRefused(err):
		c.setICMPLocked(false)
	default:
		// A transient error (out of descriptors, say) says nothing about
		// the kernel's policy; keep what is known and ask again later.
		c.checkedAt = c.now()
	}
}

// observeICMP records what a run learned from opening its socket.
func (c *capabilities) observeICMP(permitted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setICMPLocked(permitted)
}

func (c *capabilities) setICMPLocked(permitted bool) {
	refusal := ""
	if !permitted {
		refusal = model.PathReasonICMPNotPermitted
	}
	if refusal != c.icmpRefusal || c.checkedAt.IsZero() {
		if permitted {
			log.Printf("icmp checks: the kernel allows unprivileged echo sockets to this agent")
		} else {
			log.Printf("icmp checks: the kernel refuses unprivileged echo sockets to this agent (net.ipv4.ping_group_range); icmp is reported as refused")
		}
	}
	c.icmpRefusal = refusal
	c.checkedAt = c.now()
}
