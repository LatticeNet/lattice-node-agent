// Package beacon runs the measurement beacon of design 29 (D3, wire
// contract D12) on a node: the responder, one authenticated UDP socket that
// answers only requests signed for it, and the client that runs beacon
// checks against other nodes' responders.
//
// The wire format and the responder's decision core are the SDK's package
// beacon, imported here as wire; nothing of it is re-implemented. This
// package owns what surrounds the core: the socket bound to exactly the
// planned address and port, the pre-authentication CPU guard, panic
// recovery per datagram, the circuit breaker, the node veto (-no-beacon) and
// the facts the agent reports.
//
// Path keys arrive only through the authenticated config pull and are held
// in memory only. Nothing in this package writes a file, and no log line,
// fact or error carries a key or a datagram's content.
package beacon

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Capability is the -compat-json feature of a binary that runs the beacon
// responder and client of design 29 M2b.
const Capability = "beacon-v1"

const (
	// bindRetryInterval is how often a failed bind is tried again. Only the
	// same address and port are ever tried: a beacon never moves to a port
	// the plan did not approve.
	bindRetryInterval = time.Minute
	// maxErrorLen bounds BeaconFacts.Error.
	maxErrorLen = 200
	// maxReadErrors is how many socket read errors in a row close the
	// socket; readErrorPause is the wait after each one.
	maxReadErrors  = 10
	readErrorPause = 50 * time.Millisecond
)

// packetConn is the part of a bound UDP socket the responder uses;
// *net.UDPConn satisfies it. Its methods take and return netip values, so a
// datagram costs no allocation.
type packetConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Close() error
}

// listenUDP4 binds exactly addr, never the wildcard. Go sets no
// SO_REUSEADDR or SO_REUSEPORT on a unicast UDP socket, so a port another
// process holds fails with EADDRINUSE instead of being shared.
func listenUDP4(addr netip.AddrPort) (packetConn, error) {
	return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
}

// handler is the decision core of one socket: wire.Responder.Handle, or a
// test's replacement.
type handler interface {
	Handle(now time.Time, pkt, out []byte) (int, wire.Verdict)
	SetTable(entries []wire.TableEntry) error
	LastAuthenticated() time.Time
}

// Responder runs the beacon responder of one node. Apply, Facts and Close
// are safe for concurrent use; the receive loop runs on its own goroutine
// per socket.
type Responder struct {
	// noBeacon is the node veto (-no-beacon). It is fixed at construction
	// and checked before anything else in Apply, so no configuration can
	// make this responder bind.
	noBeacon bool

	listen     func(netip.AddrPort) (packetConn, error)
	newHandler func(start time.Time) handler
	now        func() time.Time
	// sleep waits d or until quit closes.
	sleep func(d time.Duration, quit <-chan struct{})
	// refuseSource reports a sender no reply may go to (sourceRefused;
	// tests on loopback relax it).
	refuseSource func(netip.AddrPort) bool

	mu           sync.Mutex
	closed       bool
	onChange     func()
	state        string
	addr         netip.AddrPort // bound, or the last one tried
	errText      string
	epoch        uint32
	sources      int
	lastAuth     time.Time
	lastBind     time.Time
	circuitUntil time.Time
	cur          *socket
}

// socket is one bound socket and the loop that serves it. quit closes
// with the socket, so a loop paused by the guard wakes at once.
type socket struct {
	conn packetConn
	core handler
	loop *loop
	quit chan struct{}
	done chan struct{}
}

// NewResponder returns a responder that is off until Apply hands it a
// configuration. With noBeacon it never binds and reports the refusal.
func NewResponder(noBeacon bool) *Responder {
	return &Responder{
		noBeacon: noBeacon,
		listen:   listenUDP4,
		newHandler: func(start time.Time) handler {
			return wire.NewResponder(start)
		},
		now:          time.Now,
		sleep:        sleepOrQuit,
		refuseSource: sourceRefused,
		state:        model.BeaconAgentOff,
	}
}

func sleepOrQuit(d time.Duration, quit <-chan struct{}) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-quit:
	}
}

// sourceRefused reports a sender no reply may ever go to: a port of zero,
// or an address of a class wire.AddressRefused names (anything but IPv4,
// 0.0.0.0/8, loopback, link-local, multicast, 240.0.0.0/4 and broadcast).
// Go enables SO_BROADCAST on every UDP socket, so without this a request
// claiming 255.255.255.255 as its source would draw a broadcast reply.
func sourceRefused(from netip.AddrPort) bool {
	return from.Port() == 0 || wire.AddressRefused(from.Addr().Unmap())
}

// SetOnChange sets a function called, outside the responder's lock, after
// the reported facts change, so the agent can report them without waiting
// for its next heartbeat.
func (r *Responder) SetOnChange(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = fn
}

// Facts is what the agent reports as the "beacon" key of hello and
// heartbeat bodies. It never carries a key.
func (r *Responder) Facts() model.BeaconFacts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.factsLocked()
}

// IdleFacts are the facts of an agent that has not built its responder.
func IdleFacts(noBeacon bool) model.BeaconFacts {
	if noBeacon {
		return model.BeaconFacts{Responder: true, Refusal: model.PathReasonRefusedByNode, State: model.BeaconAgentRefused}
	}
	return model.BeaconFacts{Responder: true, State: model.BeaconAgentOff}
}

func (r *Responder) factsLocked() model.BeaconFacts {
	if r.noBeacon {
		return IdleFacts(true)
	}
	f := model.BeaconFacts{Responder: true, State: r.state, Error: r.errText, Epoch: r.epoch, Sources: r.sources}
	if r.addr.IsValid() && r.state != model.BeaconAgentOff {
		f.Bind = r.addr.Addr().String()
		f.Port = int(r.addr.Port())
	}
	f.LastAuthAt = r.lastAuth
	if r.cur != nil {
		if t := r.cur.core.LastAuthenticated(); t.After(f.LastAuthAt) {
			f.LastAuthAt = t
		}
	}
	return f
}

// Apply makes the responder match one successful config pull: nil closes
// any socket; otherwise the responder binds exactly cfg.Bind:cfg.Port (if it
// is not bound there already) and accepts the keys of cfg.Table. Under the
// node veto it does neither, whatever cfg says.
//
// Apply wipes the key bytes of cfg.Table once it has taken them, so the
// decoded configuration does not keep a second copy.
func (r *Responder) Apply(cfg *model.BeaconResponderConfig) {
	defer wipeTable(cfg)
	if r.noBeacon {
		// The veto is checked before anything else: no address is parsed,
		// no socket is opened.
		return
	}
	r.mu.Lock()
	if r.closed {
		// A pull that lands while the agent stops binds nothing.
		r.mu.Unlock()
		return
	}
	before := r.factsLocked()
	r.applyLocked(cfg)
	after := r.factsLocked()
	onChange := r.onChange
	r.mu.Unlock()
	if onChange != nil && !sameFacts(before, after) {
		onChange()
	}
}

func (r *Responder) applyLocked(cfg *model.BeaconResponderConfig) {
	now := r.now()
	if cfg == nil {
		r.closeLocked()
		r.setLocked(model.BeaconAgentOff, netip.AddrPort{}, "")
		return
	}
	addr, err := bindAddr(cfg.Bind, cfg.Port)
	if err != nil {
		r.closeLocked()
		r.setLocked(model.BeaconAgentBindFailed, netip.AddrPort{}, err.Error())
		return
	}
	entries, epoch, sources, err := tableEntries(cfg.Table)
	defer wipeEntries(entries)
	if err != nil {
		r.closeLocked()
		r.setLocked(model.BeaconAgentOff, addr, err.Error())
		return
	}
	if r.cur != nil && r.addr != addr {
		r.closeLocked()
	}
	if r.cur == nil {
		if now.Before(r.circuitUntil) {
			// The breaker's cooldown holds whatever the address: it
			// protects this host's CPU, which a new port does not change.
			if r.state != model.BeaconAgentCircuitOpen {
				r.setLocked(model.BeaconAgentCircuitOpen, addr, "circuit breaker open")
			}
			return
		}
		if r.state == model.BeaconAgentBindFailed && r.addr == addr && now.Sub(r.lastBind) < bindRetryInterval {
			return
		}
		r.lastBind = now
		conn, err := r.listen(addr)
		if err != nil {
			text := bindError(addr, err)
			if r.state != model.BeaconAgentBindFailed || r.errText != truncateError(text) {
				log.Printf("beacon: %s", text)
			}
			r.setLocked(model.BeaconAgentBindFailed, addr, text)
			return
		}
		core := r.newHandler(now)
		if err := core.SetTable(entries); err != nil {
			_ = conn.Close()
			r.setLocked(model.BeaconAgentOff, addr, err.Error())
			return
		}
		sk := &socket{conn: conn, core: core, loop: newLoop(conn, core, now), quit: make(chan struct{}), done: make(chan struct{})}
		sk.loop.refuseSource = r.refuseSource
		r.cur = sk
		go r.serve(sk)
		log.Printf("beacon: listening on udp %s for %d source ids", addr, sources)
	} else if err := r.cur.core.SetTable(entries); err != nil {
		r.closeLocked()
		r.setLocked(model.BeaconAgentOff, addr, err.Error())
		return
	}
	r.setLocked(model.BeaconAgentListening, addr, "")
	r.epoch, r.sources = epoch, sources
}

// setLocked records the responder's state. Only a listening responder has
// applied a table, so any other state reports no epoch and no sources.
func (r *Responder) setLocked(state string, addr netip.AddrPort, errText string) {
	r.state, r.addr, r.errText = state, addr, truncateError(errText)
	if state != model.BeaconAgentListening {
		r.epoch, r.sources = 0, 0
	}
}

// closeLocked closes the current socket, if any. Its loop sees the closed
// socket and exits on its own.
func (r *Responder) closeLocked() {
	if r.cur == nil {
		return
	}
	if t := r.cur.core.LastAuthenticated(); t.After(r.lastAuth) {
		r.lastAuth = t
	}
	close(r.cur.quit)
	_ = r.cur.conn.Close()
	log.Printf("beacon: socket on udp %s closed", r.addr)
	r.cur = nil
}

// Close closes the socket for good, as the agent stops; a later Apply binds
// nothing.
func (r *Responder) Close() {
	r.mu.Lock()
	r.closed = true
	sk := r.cur
	r.closeLocked()
	if !r.noBeacon {
		r.setLocked(model.BeaconAgentOff, netip.AddrPort{}, "")
	}
	r.mu.Unlock()
	if sk != nil {
		<-sk.done
	}
}

// serve runs one socket's loop and records why it ended.
func (r *Responder) serve(sk *socket) {
	defer close(sk.done)
	stop, err := sk.loop.serve(r.now, func(d time.Duration) { r.sleep(d, sk.quit) })
	r.loopEnded(sk, stop, err)
}

// loopEnded records why a socket's loop ended. A breaker trip starts the
// cooldown even when Apply has already replaced the socket, and closes the
// replacement too, so a new address cannot open straight into the flood
// that closed the old one.
func (r *Responder) loopEnded(sk *socket, stop stopReason, err error) {
	r.mu.Lock()
	now := r.now()
	if stop == stopBreaker {
		r.circuitUntil = now.Add(breakerCooldown)
	}
	switch {
	case r.cur == sk:
		if t := sk.core.LastAuthenticated(); t.After(r.lastAuth) {
			r.lastAuth = t
		}
		close(sk.quit)
		_ = sk.conn.Close()
		r.cur = nil
	case stop == stopBreaker && r.cur != nil:
		r.closeLocked()
	default:
		// Apply or Close closed this socket and the state says so.
		r.mu.Unlock()
		return
	}
	if stop == stopBreaker {
		r.setLocked(model.BeaconAgentCircuitOpen, r.addr, fmt.Sprintf("circuit breaker open: datagrams dropped in %d of the last %d seconds; the socket stays closed for %s", sk.loop.breaker.hotSeconds(), breakerWindowSeconds, breakerCooldown))
		log.Printf("beacon: circuit breaker opened on udp %s after a minute of dropped datagrams; closed for %s", r.addr, breakerCooldown)
	} else {
		r.lastBind = now
		r.setLocked(model.BeaconAgentBindFailed, r.addr, "socket failed: "+stopError(err))
		log.Printf("beacon: socket on udp %s failed: %s", r.addr, stopError(err))
	}
	onChange := r.onChange
	r.mu.Unlock()
	if onChange != nil {
		onChange()
	}
}

func stopError(err error) string {
	if err == nil {
		return "closed"
	}
	return err.Error()
}

// bindAddr reads the planned bind address and port: an IPv4 literal of a
// class wire.ParseIPv4 allows (never 0.0.0.0, loopback, link-local,
// multicast or reserved) and a port wire.ValidListenPort allows.
func bindAddr(bind string, port int) (netip.AddrPort, error) {
	addr, err := wire.ParseIPv4(bind)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bind address refused: %w", err)
	}
	if !wire.ValidListenPort(port) {
		return netip.AddrPort{}, fmt.Errorf("bind port %d refused: %w", port, wire.ErrPort)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil // #nosec G115 -- ValidListenPort bounds port to 1024..65535
}

// bindError is a short bind error for the facts: the address and the
// system error, without Go's operation prefix.
func bindError(addr netip.AddrPort, err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		err = opErr.Err
	}
	return fmt.Sprintf("bind udp %s: %v", addr, err)
}

// tableEntries converts the configured table. Every key must be KeyLen
// bytes and every id above zero; SetTable refuses duplicates and more than
// wire.MaxEpochsPerSource epochs per source.
func tableEntries(table []model.BeaconTableKey) (entries []wire.TableEntry, newest uint32, sources int, err error) {
	entries = make([]wire.TableEntry, 0, len(table))
	seen := map[uint32]struct{}{}
	for i, k := range table {
		if k.SourceID == 0 || k.Epoch == 0 {
			return entries, 0, 0, fmt.Errorf("responder table refused: entry %d has a zero source id or epoch", i)
		}
		if len(k.Key) != wire.KeyLen {
			return entries, 0, 0, fmt.Errorf("responder table refused: entry %d has a %d-byte key", i, len(k.Key))
		}
		e := wire.TableEntry{SourceID: k.SourceID, Epoch: k.Epoch, Retired: k.Retired}
		copy(e.Key[:], k.Key)
		entries = append(entries, e)
		seen[k.SourceID] = struct{}{}
		newest = max(newest, k.Epoch)
	}
	return entries, newest, len(seen), nil
}

func wipeEntries(entries []wire.TableEntry) {
	for i := range entries {
		clear(entries[i].Key[:])
	}
}

func wipeTable(cfg *model.BeaconResponderConfig) {
	if cfg == nil {
		return
	}
	for i := range cfg.Table {
		clear(cfg.Table[i].Key)
	}
}

// truncateError bounds an error to maxErrorLen bytes on a rune boundary.
func truncateError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxErrorLen {
		return s
	}
	cut := maxErrorLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func sameFacts(a, b model.BeaconFacts) bool {
	return a.State == b.State && a.Refusal == b.Refusal && a.Bind == b.Bind && a.Port == b.Port &&
		a.Epoch == b.Epoch && a.Sources == b.Sources && a.Error == b.Error
}

// stopReason is why a receive loop ended.
type stopReason uint8

const (
	stopClosed stopReason = iota
	stopBreaker
	stopReadError
	stopPanic
)

// loop is the receive loop of one socket. Every field but the counters is
// owned by the loop's goroutine.
type loop struct {
	conn packetConn
	core handler
	// base is when the loop started; the guard and the breaker count from
	// it on the monotonic clock.
	base         time.Time
	refuseSource func(netip.AddrPort) bool
	guard        guard
	breaker      breaker
	buf          [wire.ReadBufferLen]byte
	out          [wire.ReplyLen]byte

	// Counters, read by tests and never sent anywhere.
	verdicts    [verdictSlots]atomic.Uint64
	guardDrops  atomic.Uint64
	sourceDrops atomic.Uint64
	panics      atomic.Uint64
	replies     atomic.Uint64
}

// verdictSlots covers every wire.Verdict value.
const verdictSlots = 16

func newLoop(conn packetConn, core handler, base time.Time) *loop {
	return &loop{conn: conn, core: core, base: base, refuseSource: sourceRefused, guard: newGuard()}
}

// mono is how long after the loop started now is, never negative.
func (l *loop) mono(now time.Time) int64 {
	return max(int64(now.Sub(l.base)), 0)
}

// serve reads datagrams until the socket closes, the breaker opens, reads
// keep failing, or the loop itself panics.
func (l *loop) serve(now func() time.Time, sleep func(time.Duration)) (stop stopReason, err error) {
	defer func() {
		if p := recover(); p != nil {
			l.panics.Add(1)
			stop, err = stopPanic, errors.New("receive loop panicked")
		}
	}()
	readErrs := 0
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(l.buf[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return stopClosed, nil
			}
			if readErrs++; readErrs >= maxReadErrors {
				return stopReadError, err
			}
			sleep(readErrorPause)
			continue
		}
		readErrs = 0
		t := now()
		if r := l.process(t, l.buf[:n], from); r > 0 {
			if _, err := l.conn.WriteToUDPAddrPort(l.out[:r], from); err == nil {
				l.replies.Add(1)
			}
		}
		if l.breaker.open() {
			return stopBreaker, nil
		}
		if mono := l.mono(t); l.guard.full(mono) {
			// Stop reading until the next second: the kernel drops the
			// excess, which costs this process nothing.
			l.breaker.saturate(mono)
			sleep(time.Duration(int64(time.Second) - mono%int64(time.Second)))
		}
	}
}

// process decides one datagram received at now from from and returns the
// length of the reply it wrote into l.out, zero for none. The order is the
// guard, then the sender (no reply ever goes to a broadcast, multicast,
// loopback or port-zero address), then the length, then
// wire.Responder.Handle, which checks framing, source id and epoch before
// any HMAC, then the tag, then freshness, replay and rate. A reply is never
// longer than the datagram it answers. A panic drops the datagram and is
// counted; it never reaches the agent. Nothing here allocates.
func (l *loop) process(now time.Time, pkt []byte, from netip.AddrPort) (n int) {
	mono := l.mono(now)
	defer func() {
		if p := recover(); p != nil {
			l.panics.Add(1)
			l.breaker.record(mono, true)
			n = 0
		}
	}()
	switch l.guard.allow(from.Addr(), mono) {
	case guardGlobalFull:
		l.guardDrops.Add(1)
		l.breaker.saturate(mono)
		return 0
	case guardBucketFull:
		// One address over its share is the guard doing its job; the
		// breaker does not count it, so one host cannot close the socket.
		l.guardDrops.Add(1)
		l.breaker.record(mono, false)
		return 0
	}
	if l.refuseSource(from) {
		l.sourceDrops.Add(1)
		l.breaker.record(mono, true)
		return 0
	}
	if len(pkt) != wire.RequestLen {
		l.verdicts[wire.DropLength].Add(1)
		l.breaker.record(mono, true)
		return 0
	}
	n, v := l.core.Handle(now, pkt, l.out[:])
	if int(v) < verdictSlots {
		l.verdicts[v].Add(1)
	}
	if n <= 0 || n > len(pkt) || n > len(l.out) || !v.Replied() {
		l.breaker.record(mono, true)
		return 0
	}
	l.breaker.record(mono, false)
	return n
}
