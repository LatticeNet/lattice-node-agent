// Package sessionasm assembles sing-box connections out of two streams that
// each tell only half the story: the interleaved log lines singboxlog parses,
// and the periodic /connections snapshots singboxapi polls.
//
// One rule shapes everything here: never state more than was observed. The
// distinctions that rule forces are the reason this package exists at all.
//
//   - Bytes are unknown until a snapshot reported them. A connection shorter
//     than the poll interval is never sampled, so BytesKnown stays false and
//     nothing downstream may render a zero it did not measure.
//   - A close reason is CloseUnknown unless sing-box actually said how the
//     connection ended. A clean close is reported only when a clean close was
//     seen; an honest gap is cheaper than a wrong reassurance.
//   - A stall is asserted only from two samples that bracket the quiet window.
//     A connection that was never sampled is not stalled, it is unobserved.
//
// Three properties of the real v1.13.14 stream (see
// singboxlog/testdata/v1.13.14/) drive the state machine:
//
//   - Lines from different connections interleave, so grouping is by LogID
//     only and nothing may assume contiguity.
//   - The "outbound connection to" line is emitted twice, identically, so
//     every write has to be idempotent.
//   - A dial failure has no close line at all; the error line is terminal.
//   - The two half closes of one connection are logged at DIFFERENT levels:
//     "connection download finished" at debug, "connection upload closed" at
//     trace. Below a trace subscription only one of them is ever delivered, so
//     a connection must never be made to wait for both.
//
// The assembler is fed by the collector goroutine (Line, Snapshot, Tick,
// CoreRestart) and emptied by the shipper goroutine (Drain, Stats). One mutex
// guards all of it.
package sessionasm

import (
	"container/list"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Defaults. Each is the value in SINGBOX-TRACE-DESIGN.md section 4.2 and 4.6.
const (
	defaultMaxOpen       = 4096
	defaultOrphanTTL     = 10 * time.Minute
	defaultSnapshotEvery = 60 * time.Second
	defaultStallFloor    = 60 * time.Second
	defaultStallQuiet    = 30 * time.Second
	// defaultHalfCloseGrace is how long a connection waits for its second half
	// close before settling for the one it has. The two halves land in the
	// same millisecond in every capture, so this is three orders of magnitude
	// of headroom, and it is still well inside the /connections poll interval
	// so the grace resolves a connection before the snapshot rule has to.
	defaultHalfCloseGrace = 2 * time.Second

	// snapshotStartSkew bounds how far before a tracked connection a
	// /connections item may have started and still be joined to it. The join
	// key is src ip plus src port, and an ephemeral port is reused after the
	// kernel releases it, so without this guard a still listed older
	// connection would donate its byte counts to the newer one holding the
	// same port. The two clocks involved are both on this host, so anything
	// beyond a few seconds of disagreement means a different connection.
	snapshotStartSkew = 30 * time.Second
)

// managedUserName is the shape vpn-core renders for a Lattice user. Anything
// else that carries a name is a legacy or operator supplied label; the agent
// classifies the shape and stops there, because reversing a name to a user id
// needs the line read model that only the server has.
var managedUserName = regexp.MustCompile(`^u_[0-9a-f]{16}$`)

// Options configures an Assembler. The zero value of every duration means
// "use the default"; Now is the one field tests must set.
type Options struct {
	// NodeID stamps every record. It is the only identity the agent owns:
	// line uuid, user id and chain edge are resolved server side by traceattr.
	NodeID string

	// CoreGeneration is the generation records start in. It is not in the
	// original API sketch, and it is here because a generation of zero is
	// indistinguishable from "unset" in the (node, generation, log id) join
	// key that the server and the hop stitcher use. CoreRestart moves it on.
	CoreGeneration uint64

	MaxOpen       int           // cap on tracked connections; default 4096
	OrphanTTL     time.Duration // drop a connection with no evidence of life for this long; default 10m
	SnapshotEvery time.Duration // emit an Open snapshot for long lived connections; default 60s
	StallFloor    time.Duration // a connection must be older than this before it can be called stalled; default 60s
	StallQuiet    time.Duration // zero bytes both ways for this long marks stalled; default 30s
	// HalfCloseGrace is how long to wait for the second half close before
	// finalising on the first. It exists because the two halves are logged at
	// different levels, so below trace only one of them arrives and waiting
	// for the other parks a cleanly closed connection until the orphan TTL.
	// Default 2s.
	HalfCloseGrace time.Duration

	// Now is the clock of record for inputs that carry no usable timestamp.
	// Injectable so tests never sleep. Defaults to time.Now.
	Now func() time.Time
}

// Stats is the counter set an operator needs before trusting anything on
// screen. Each counter answers a different question and none may be folded
// into another.
type Stats struct {
	// Open is how many connections are tracked right now.
	Open int
	// Emitted counts every record handed to Drain, open snapshots included,
	// because that is the volume the shipper actually has to carry.
	Emitted uint64
	// Swept counts connections closed by CoreRestart. That number is the blast
	// radius of a restart and is displayed as such on the timeline.
	Swept uint64
	// Orphaned counts connections emitted with CloseUnknown after OrphanTTL.
	// A rising number means the parser or the stream is losing terminal lines.
	Orphaned uint64
	// Partial counts connections seen only at their close, with no source and
	// no destination, and therefore not emitted. It is normally a small
	// startup artifact; a persistently rising number means the log stream is
	// losing the opening lines of connections.
	Partial uint64
	// Dropped counts connections discarded under MaxOpen pressure, without a
	// record. They are discarded rather than emitted because the moment the
	// node is over the cap is the worst moment to multiply the record flood,
	// and a contentless unknown record would tell the operator less than this
	// counter does.
	Dropped uint64
}

// Snapshot is one /connections poll result. It is deliberately not the
// singboxapi type: this package has to be testable on its own, and the poller
// has to be replaceable when the 1.14 api service lands.
type Snapshot struct {
	At    time.Time
	Items []SnapshotItem
}

// SnapshotItem is one live connection as /connections reports it. There is no
// user field and the item id is a uuid unrelated to the log id, so src ip plus
// src port is the only usable join key; that was confirmed on a real node.
type SnapshotItem struct {
	SrcIP, SrcPort          string
	DstHost, DstPort        string
	InboundType, InboundTag string
	Network                 string
	Upload, Download        int64
	Rule                    string
	Chains                  []string
	Start                   time.Time
}

// closeCandidate is a close reason plus the evidence behind it. Rank exists so
// that two half closes settle deterministically rather than by arrival order.
type closeCandidate struct {
	reason string
	err    string
	rank   int
}

// Close evidence ranks. The ordering keeps a record's meaning independent of
// the subscription level: the cancel path half close only appears at trace
// level, so if it outranked the clean half the same connection would read as
// canceled at trace and as eof at info. Observed errors outrank both, because
// hiding an error behind a clean half close is exactly the reassurance this
// package refuses to give.
const (
	rankNone     = 0 // nothing was said
	rankSoft     = 1 // closed with no error: canceled, or udp idle
	rankEOF      = 2 // a direction genuinely finished
	rankError    = 3 // an error text was logged
	rankTerminal = 4 // the inbound or the dialler stated how it ended
)

// conn is the in-flight state for one log id.
type conn struct {
	rec model.ConnRecord

	// lastSeenAt is the last evidence that this connection exists: a log line,
	// or a /connections item. Snapshots count, because a long lived connection
	// emits no lines at all between its outbound line and its close, and
	// orphaning one we can currently see in the connection table would be a
	// lie told by a timer.
	lastSeenAt time.Time
	// lastElapsedMS is sing-box's own elapsed counter on the newest line. It
	// is the duration source for any connection that ended with a line.
	lastElapsedMS int64

	haveOutbound bool // the outbound line is emitted twice; only the first writes
	closedUp     bool
	closedDown   bool
	close        closeCandidate
	// firstHalfAt is when the first half close was logged. sing-box logs the
	// two halves at different levels, so the second one may never be
	// delivered; this starts the grace after which the connection settles for
	// the evidence it has.
	firstHalfAt time.Time

	sampled          bool
	lastSnapAt       time.Time
	lastByteChangeAt time.Time
	// lastSnapSeq is the poll that last listed this connection. A connection
	// missing from a strictly newer poll has left sing-box's connection table,
	// which is an authoritative and level independent statement that it ended.
	lastSnapSeq uint64

	lastEmitAt time.Time // last open snapshot, initialised to StartedAt
	srcKey     string
	elem       *list.Element // position in the insertion ordered list, for O(1) eviction
}

// Assembler turns lines and snapshots into records.
type Assembler struct {
	opts Options

	mu    sync.Mutex
	gen   uint64
	open  map[uint32]*conn
	order *list.List       // *conn in creation order; front is the oldest
	bySrc map[string]*conn // src ip and port to the newest connection holding it
	done  *doneSet         // log ids already emitted, so trailing lines cannot resurrect them
	out   []model.ConnRecord
	stats Stats
	// snapSeq counts /connections polls. Comparing it with a connection's own
	// last poll is what makes disappearance detectable without a timer.
	snapSeq uint64
}

// New builds an Assembler, filling in the defaults for anything unset.
func New(opts Options) *Assembler {
	if opts.MaxOpen <= 0 {
		opts.MaxOpen = defaultMaxOpen
	}
	if opts.OrphanTTL <= 0 {
		opts.OrphanTTL = defaultOrphanTTL
	}
	if opts.SnapshotEvery <= 0 {
		opts.SnapshotEvery = defaultSnapshotEvery
	}
	if opts.StallFloor <= 0 {
		opts.StallFloor = defaultStallFloor
	}
	if opts.StallQuiet <= 0 {
		opts.StallQuiet = defaultStallQuiet
	}
	if opts.HalfCloseGrace <= 0 {
		opts.HalfCloseGrace = defaultHalfCloseGrace
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Assembler{
		opts:  opts,
		gen:   opts.CoreGeneration,
		open:  make(map[uint32]*conn),
		order: list.New(),
		bySrc: make(map[string]*conn),
		done:  newDoneSet(opts.MaxOpen),
	}
}

// Line feeds one parsed log line.
func (a *Assembler) Line(l singboxlog.Line) {
	if !l.HasLogID {
		// Without an id there is no connection to attribute the line to.
		// Startup and listener lines land here and belong to the log store,
		// not to a record.
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	at := l.At
	if at.IsZero() {
		at = a.opts.Now()
	}

	c, live := a.open[l.LogID]
	switch {
	case l.Event == singboxlog.EventInboundFrom:
		if live {
			// Same id, and sing-box says a new connection is being accepted on
			// it. Log ids are rand.Uint32, so within one process lifetime they
			// can collide. Splitting into two records with the older one
			// honestly marked unknown beats merging two connections into one
			// row that is wrong about both.
			a.finish(c, closeCandidate{
				reason: model.CloseUnknown,
				err:    "log id collision: a new connection reused this log id",
				rank:   rankTerminal,
			}, at, durFromCore)
		}
		c = a.create(l, at)
	case !live:
		if a.done.has(l.LogID) {
			// A trailing line for a connection already emitted. The inbound's
			// own "connection closed" line routinely arrives after both
			// directions have reported, and recreating a connection from it
			// would manufacture a contentless phantom record per connection.
			return
		}
		// First line we ever saw for this id: the agent attached mid stream,
		// after a restart or a level change. Elapsed lets us reconstruct a
		// real start time, so the record is still worth something.
		c = a.create(l, at)
	}

	a.apply(c, l, at)
}

// create starts tracking a connection, evicting the oldest one first if the
// cap is already reached.
func (a *Assembler) create(l singboxlog.Line, at time.Time) *conn {
	if len(a.open) >= a.opts.MaxOpen {
		a.evictOldest()
	}
	started := at.Add(-time.Duration(l.ElapsedMS) * time.Millisecond)
	c := &conn{
		rec: model.ConnRecord{
			NodeID:    a.opts.NodeID,
			LogID:     l.LogID,
			Network:   networkOf(l),
			StartedAt: started,
			// Absent a name on the post auth line this stays unnamed. sing-box
			// logs an index rather than a name for users vpn-core never named,
			// and unnamed is the truthful label for that.
			UserKind: model.UserKindUnnamed,
		},
		lastSeenAt:    at,
		lastElapsedMS: l.ElapsedMS,
		lastEmitAt:    started,
	}
	a.open[l.LogID] = c
	c.elem = a.order.PushBack(c)
	return c
}

// apply folds one line into the connection it belongs to.
func (a *Assembler) apply(c *conn, l singboxlog.Line, at time.Time) {
	if l.Event == singboxlog.EventOutboundTo && c.haveOutbound {
		// The duplicate outbound line. It must not re-time or overwrite
		// anything, so it only counts as evidence that the connection lives.
		c.lastSeenAt = at
		return
	}

	c.lastSeenAt = at
	if l.ElapsedMS > c.lastElapsedMS {
		// Monotonic: out of order lines must not walk the duration backwards.
		c.lastElapsedMS = l.ElapsedMS
	}
	if c.rec.Network == "" {
		c.rec.Network = networkOf(l)
	}
	if l.TagKind == singboxlog.TagInbound {
		// Any inbound tagged line identifies the listener, including the
		// terminal "connection closed" one.
		if c.rec.InboundTag == "" {
			c.rec.InboundTag = l.TagName
		}
		if c.rec.InboundType == "" {
			c.rec.InboundType = l.TagType
		}
	}

	switch l.Event {
	case singboxlog.EventInboundFrom:
		c.rec.SrcIP = l.SrcIP
		c.rec.SrcPort = l.SrcPort
		a.indexSrc(c)

	case singboxlog.EventInboundTo:
		if l.DstHost != "" {
			c.rec.DstHost = l.DstHost
			c.rec.DstPort = l.DstPort
		}
		if l.Packet {
			c.rec.Network = "udp"
		}
		if l.User != "" {
			// UserID stays empty on purpose. The agent knows the name sing-box
			// printed and nothing else; the server reverses it through the
			// line read model, and a guess here would put a wrong identity on
			// a record that an operator will read as fact.
			c.rec.UserName = l.User
			if managedUserName.MatchString(l.User) {
				c.rec.UserKind = model.UserKindManaged
			} else {
				c.rec.UserKind = model.UserKindLegacy
			}
		}

	case singboxlog.EventRuleMatch:
		// Since 1.13 sniffing is a routing action, so "match[0] => sniff" is a
		// pre-routing step rather than the routing decision. Recording it
		// would overwrite the real decision with rule 0 and no text.
		if l.Action != "sniff" {
			if l.HasRule {
				c.rec.RuleIndex = l.RuleIndex
			}
			if l.RuleText != "" {
				c.rec.RuleText = l.RuleText
			}
			if l.Outbound != "" && c.rec.OutboundTag == "" {
				c.rec.OutboundTag = l.Outbound
			}
		}

	case singboxlog.EventSniffed:
		c.rec.SniffedProtocol = l.SniffProtocol
		c.rec.SniffedDomain = l.SniffDomain

	case singboxlog.EventOutboundTo:
		c.haveOutbound = true
		c.rec.OutboundTag = l.TagName
		c.rec.OutboundType = l.TagType
		if c.rec.DstHost == "" && l.DstHost != "" {
			c.rec.DstHost = l.DstHost
			c.rec.DstPort = l.DstPort
		}

	case singboxlog.EventDNS:
		// Only the lookup that resolved this connection's own destination is
		// worth keeping. The first answer is the address sing-box dialled.
		if c.rec.DstIP == "" && len(l.DNSResult) > 0 && sameHost(l.DNSDomain, c.rec.DstHost) {
			c.rec.DstIP = l.DNSResult[0]
		}

	case singboxlog.EventDialFailed:
		if c.rec.OutboundTag == "" {
			c.rec.OutboundTag = l.OutboundName
		}
		if c.rec.OutboundType == "" {
			c.rec.OutboundType = l.OutboundType
		}
		// Terminal. A dial failure produces no close line at all, so waiting
		// for one would leak the connection until the orphan sweep.
		a.finish(c, closeCandidate{reason: model.CloseDialFailed, err: l.Error, rank: rankTerminal}, at, durFromCore)

	case singboxlog.EventAuthFailed:
		// No user is knowable here by construction: the failure is what
		// stopped sing-box from naming one. The record keeps the source
		// address and stays UserKindUnnamed rather than borrowing a name.
		a.finish(c, closeCandidate{reason: model.CloseAuthFailed, err: l.Error, rank: rankTerminal}, at, durFromCore)

	case singboxlog.EventConnectionClosed:
		a.finish(c, closeCandidate{reason: closeReasonFor(l.Error, model.CloseEOF), err: l.Error, rank: rankTerminal}, at, durFromCore)

	case singboxlog.EventFinished:
		// A clean half close. Empty error means the copy reached EOF.
		c.offer(closeCandidate{reason: closeReasonFor(l.Error, model.CloseEOF), err: l.Error, rank: evidenceRank(l.Error, model.CloseEOF)})
		a.halfClosed(c, l, at)

	case singboxlog.EventClosed:
		// The cancel path half close. With no error it means the direction was
		// cancelled rather than finished, which for a packet connection is the
		// udp idle timeout.
		empty := model.CloseCanceled
		if l.Packet {
			empty = model.CloseUDPIdle
		}
		c.offer(closeCandidate{reason: closeReasonFor(l.Error, empty), err: l.Error, rank: evidenceRank(l.Error, empty)})
		a.halfClosed(c, l, at)
	}
}

// halfClosed records that one direction reported and finishes the connection
// once both have.
func (a *Assembler) halfClosed(c *conn, l singboxlog.Line, at time.Time) {
	if c.firstHalfAt.IsZero() {
		c.firstHalfAt = at
	}
	switch l.Direction {
	case singboxlog.DirectionUpload:
		c.closedUp = true
	case singboxlog.DirectionDownload:
		c.closedDown = true
	default:
		// Every observed half close names its direction. If a future format
		// stops naming it, fill the slots in order so that two undirected half
		// closes still complete the connection instead of leaking it to the
		// orphan sweep.
		if !c.closedUp {
			c.closedUp = true
		} else {
			c.closedDown = true
		}
	}
	if c.closedUp && c.closedDown {
		a.finish(c, c.close, at, durFromCore)
	}
}

// offer keeps the strongest close evidence seen so far. Ties keep the first,
// so the earliest error text survives.
func (c *conn) offer(cand closeCandidate) {
	if cand.rank > c.close.rank {
		c.close = cand
	}
}

// Snapshot feeds one /connections poll result.
func (a *Assembler) Snapshot(s Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()

	at := s.At
	if at.IsZero() {
		at = a.opts.Now()
	}
	a.snapSeq++
	for _, item := range s.Items {
		c := a.bySrc[srcKey(item.SrcIP, item.SrcPort)]
		if c == nil {
			// A live connection whose log lines we never saw. There is no id
			// to key a record on, so it stays out of the record stream rather
			// than becoming a row with no identity.
			continue
		}
		if !item.Start.IsZero() && item.Start.Before(c.rec.StartedAt.Add(-snapshotStartSkew)) {
			// Started well before the connection now holding this src port:
			// the port was reused and these bytes belong to somebody else.
			continue
		}
		a.join(c, item, at)
	}
	a.sweepVanished(at)
}

// sweepVanished finalises the connections this poll proves have ended. A
// connection that sing-box listed before and does not list now is closed, and
// that statement is authoritative and independent of the subscription level,
// unlike anything the log stream can say. Two guards keep it honest: a
// connection never sampled is untouched, because absence from a table it was
// never in proves nothing, and absence only counts when observed in a poll
// strictly newer than the one that last showed the connection, so a poll that
// never happened cannot close anything.
func (a *Assembler) sweepVanished(at time.Time) {
	for e := a.order.Front(); e != nil; {
		next := e.Next()
		c := e.Value.(*conn)
		if c.sampled && c.lastSnapSeq < a.snapSeq {
			cand := c.close
			src := durFromCore
			if cand.rank == rankNone {
				// It left the table without ever saying how it ended. The last
				// elapsed counter we have predates the whole silent stretch,
				// so the poll instant is the better bound: it is accurate to
				// one poll interval instead of understating by minutes.
				cand = closeCandidate{
					reason: model.CloseUnknown,
					err:    "connection left the sing-box connection table without a close line",
					rank:   rankTerminal,
				}
				src = durFromClock
			}
			a.finish(c, cand, at, src)
		}
		e = next
	}
}

// join folds one snapshot item into the connection it matched.
func (a *Assembler) join(c *conn, item SnapshotItem, at time.Time) {
	if !c.sampled || item.Upload != c.rec.Upload || item.Download != c.rec.Download {
		// Byte movement, or the first sample. The first sample is only a
		// baseline: it says nothing about whether bytes were moving before it,
		// so the quiet window starts here.
		c.lastByteChangeAt = at
		c.rec.StalledAt = time.Time{}
	}
	c.rec.Upload = item.Upload
	c.rec.Download = item.Download
	// BytesKnown is the whole point of the snapshot join: a measured zero and
	// an unmeasured connection are different facts and only this flag keeps
	// them apart downstream.
	c.rec.BytesKnown = true
	c.sampled = true
	c.lastSnapAt = at
	c.lastSnapSeq = a.snapSeq
	c.lastSeenAt = at

	if c.rec.InboundType == "" {
		c.rec.InboundType = item.InboundType
	}
	if c.rec.InboundTag == "" {
		c.rec.InboundTag = item.InboundTag
	}
	if c.rec.RuleText == "" {
		c.rec.RuleText = item.Rule
	}
	if c.rec.Network == "" {
		c.rec.Network = item.Network
	}
	if c.rec.DstHost == "" && item.DstHost != "" {
		c.rec.DstHost = item.DstHost
		c.rec.DstPort = atoiPort(item.DstPort)
	}
	if c.rec.OutboundTag == "" && len(item.Chains) > 0 {
		// Fallback only. The outbound log line names the outbound
		// unambiguously; the chain array's ordering is a Clash API convention
		// and is worth less, so it never overwrites a line.
		c.rec.OutboundTag = item.Chains[0]
	}
	c.evalStall(at, a.opts.StallFloor, a.opts.StallQuiet)
}

// evalStall applies the only stall signal there is. sing-box says nothing
// about a stuck TCP stream, so a stall is inferred from two samples that
// bracket the quiet window; anything weaker would flag connections that were
// simply never sampled, or connections that went quiet because polling did.
func (c *conn) evalStall(now time.Time, floor, quiet time.Duration) {
	if !c.sampled {
		return
	}
	if !c.rec.StalledAt.IsZero() {
		return // already flagged; only byte movement clears it
	}
	if now.Sub(c.rec.StartedAt) <= floor {
		return
	}
	if c.lastSnapAt.Sub(c.lastByteChangeAt) < quiet {
		return
	}
	// Quiet since the last time bytes actually moved, which is what an
	// operator asking "when did it stop" needs, not the detection instant.
	c.rec.StalledAt = c.lastByteChangeAt
}

// Tick drives everything time based: orphan sweeps, stall promotion, and the
// periodic open snapshots for long lived connections.
func (a *Assembler) Tick(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if now.IsZero() {
		now = a.opts.Now()
	}
	for e := a.order.Front(); e != nil; {
		next := e.Next() // captured before a finish removes e
		c := e.Value.(*conn)
		switch {
		case !c.firstHalfAt.IsZero() && now.Sub(c.firstHalfAt) >= a.opts.HalfCloseGrace:
			// One direction reported and the other one is not coming. The two
			// half closes are logged at different levels, so at anything below
			// a trace subscription exactly one of them is ever delivered.
			// Waiting for the second would park a cleanly closed connection
			// until the orphan TTL and then publish it as unknown, which is
			// the specific dishonesty this package exists to prevent. Settle
			// on the half we actually saw, and end the record when sing-box
			// logged it rather than when the grace expired.
			a.finish(c, c.close, c.firstHalfAt, durFromCore)
		case now.Sub(c.lastSeenAt) >= a.opts.OrphanTTL:
			// Neither a line nor a snapshot for the whole TTL. We do not know
			// how it ended, and saying so is the point of CloseUnknown.
			a.stats.Orphaned++
			// Whatever partial evidence exists is kept in CloseError: one
			// direction reporting "reset by peer" is worth showing even when
			// the reason has to stay unknown because the other never came.
			orphan := closeCandidate{reason: model.CloseUnknown, err: c.close.err, rank: rankTerminal}
			if orphan.err == "" {
				orphan.err = "no further log lines for this connection"
			}
			a.finish(c, orphan, now, durFromCore)
		default:
			c.evalStall(now, a.opts.StallFloor, a.opts.StallQuiet)
			if now.Sub(c.lastEmitAt) >= a.opts.SnapshotEvery {
				a.emitOpen(c, now)
			}
		}
		e = next
	}
}

// emitOpen publishes a complete snapshot of a still running connection.
// Snapshots replace each other downstream, so each has to carry every field
// the final record would.
func (a *Assembler) emitOpen(c *conn, now time.Time) {
	rec := c.rec
	rec.Open = true
	rec.CoreGeneration = a.gen
	// The connection has not ended, so its close reason is genuinely not known
	// yet. Empty would be a third state nothing downstream models, and Open
	// already tells the interface to render this as running rather than as a
	// mystery.
	rec.CloseReason = model.CloseUnknown
	// The only duration available while a connection runs. sing-box's elapsed
	// counter is stale between lines, and a long lived connection emits none,
	// so the agent clock is the honest source here; the final record replaces
	// this with sing-box's own number.
	rec.DurationMS = millis(now.Sub(c.rec.StartedAt))
	c.lastEmitAt = now
	a.push(rec)
}

// durationSource selects where a finished record's duration comes from.
type durationSource int

const (
	// durFromCore uses sing-box's elapsed counter on the newest line it sent
	// for this connection. It is measured from sing-box's own connection
	// start, which beats subtracting two agent timestamps, and for a sweep it
	// is a measured lower bound rather than a guess about the silent window.
	durFromCore durationSource = iota
	// durFromClock uses the agent clock up to the end instant. It is only for
	// endings the agent itself timed, where the connection provably lived
	// until that moment.
	durFromClock
)

// finish emits a connection's final record and stops tracking it.
func (a *Assembler) finish(c *conn, cand closeCandidate, endedAt time.Time, src durationSource) {
	rec := c.rec
	rec.Open = false
	rec.EndedAt = endedAt
	rec.CoreGeneration = a.gen
	rec.CloseReason = cand.reason
	if rec.CloseReason == "" {
		// Belt and braces: an empty reason would render as a blank cell that
		// reads like a clean close. Unknown is the honest floor.
		rec.CloseReason = model.CloseUnknown
	}
	rec.CloseError = cand.err
	switch src {
	case durFromClock:
		rec.DurationMS = millis(endedAt.Sub(c.rec.StartedAt))
	default:
		rec.DurationMS = c.lastElapsedMS
	}
	a.forget(c)
	a.done.add(rec.LogID)

	// A connection observed only at its close carries nothing: no source, no
	// destination, no user. It happens when the collector subscribes while a
	// connection is already in flight, so only the tail is seen. Emitting it
	// would put a row in the table that cannot be filtered, joined, or acted
	// on, and whose empty user reads as "unnamed" when the truth is
	// "unobserved". Count it instead, so the gap stays visible without
	// pretending to be a connection record.
	//
	// A long lived pre-existing connection is unaffected: the /connections poll
	// supplies its source, destination and inbound tag well before it closes.
	if rec.SrcIP == "" && rec.DstHost == "" {
		a.stats.Partial++
		return
	}
	a.push(rec)
}

// forget removes a connection from every index.
func (a *Assembler) forget(c *conn) {
	delete(a.open, c.rec.LogID)
	if c.elem != nil {
		a.order.Remove(c.elem)
		c.elem = nil
	}
	if c.srcKey != "" && a.bySrc[c.srcKey] == c {
		delete(a.bySrc, c.srcKey)
	}
}

// indexSrc points the src key at this connection. A reused ephemeral port
// moves the key to the newer connection, which is the one a snapshot is
// describing.
func (a *Assembler) indexSrc(c *conn) {
	if c.rec.SrcIP == "" {
		return
	}
	key := srcKey(c.rec.SrcIP, strconv.Itoa(c.rec.SrcPort))
	if c.srcKey != "" && c.srcKey != key && a.bySrc[c.srcKey] == c {
		delete(a.bySrc, c.srcKey)
	}
	c.srcKey = key
	a.bySrc[key] = c
}

// evictOldest drops the oldest tracked connection to stay inside MaxOpen. It
// emits nothing: see Stats.Dropped for why the counter is the honest answer
// here. The id joins the done set so its later lines cannot immediately
// recreate what we just dropped.
func (a *Assembler) evictOldest() {
	e := a.order.Front()
	if e == nil {
		return
	}
	c := e.Value.(*conn)
	a.forget(c)
	a.done.add(c.rec.LogID)
	a.stats.Dropped++
}

// CoreRestart closes every open connection to CloseCoreRestart and moves the
// generation on. The swept records keep the OLD generation, because their log
// ids belong to it and the (node, generation, log id) key has to stay true.
func (a *Assembler) CoreRestart(newGeneration uint64, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if at.IsZero() {
		at = a.opts.Now()
	}
	swept := uint64(0)
	for e := a.order.Front(); e != nil; {
		next := e.Next()
		c := e.Value.(*conn)
		// The agent timed this ending itself and the connection provably lived
		// until the restart, so the agent clock is the right duration source.
		a.finish(c, closeCandidate{reason: model.CloseCoreRestart, rank: rankTerminal}, at, durFromClock)
		swept++
		e = next
	}
	a.stats.Swept += swept
	// Ids are drawn afresh by the new process, so a stale done entry could
	// silence a legitimate line of the new generation.
	a.done.reset()
	a.gen = newGeneration
}

// Drain takes everything emitted since the last call.
func (a *Assembler) Drain() []model.ConnRecord {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := a.out
	a.out = nil
	return out
}

// Stats reports the counters. Open is live; the rest are cumulative.
func (a *Assembler) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	s := a.stats
	s.Open = len(a.open)
	return s
}

// push queues a record. The queue is unbounded on purpose: backpressure and
// the drop budget belong to traceship, which is the component that knows what
// the server is accepting. Drain has to be called regularly.
func (a *Assembler) push(rec model.ConnRecord) {
	a.out = append(a.out, rec)
	a.stats.Emitted++
}

// closeReasonFor maps an error text to a close reason. The order of the checks
// matters: "TLS handshake: EOF" is a handshake failure, not an EOF.
func closeReasonFor(errText, whenEmpty string) string {
	if strings.TrimSpace(errText) == "" {
		return whenEmpty
	}
	low := strings.ToLower(errText)
	switch {
	case strings.Contains(low, "reset by peer"):
		return model.CloseReset
	case strings.Contains(low, "i/o timeout"), strings.Contains(low, "deadline exceeded"):
		return model.CloseTimeout
	case strings.Contains(low, "handshake"):
		return model.CloseHandshakeFailed
	case strings.Contains(low, "eof"):
		return model.CloseEOF
	}
	// An error we do not model. The text is kept verbatim in CloseError, and
	// the reason stays unknown rather than being rounded to the nearest clean
	// close.
	return model.CloseUnknown
}

// evidenceRank scores a half close. An error text always outranks a clean
// half, so an error on one direction cannot be hidden by a clean other one.
func evidenceRank(errText, whenEmpty string) int {
	if strings.TrimSpace(errText) != "" {
		return rankError
	}
	if whenEmpty == model.CloseEOF {
		return rankEOF
	}
	return rankSoft
}

// networkOf reports the transport a line implies, and empty for the lines whose
// wording does not distinguish one. Router and dns lines say nothing about the
// transport, so a connection first seen through one of them stays blank until a
// line or a snapshot actually says; guessing tcp because it is the common case
// is exactly the kind of quiet invention this package avoids.
func networkOf(l singboxlog.Line) string {
	switch l.Event {
	case singboxlog.EventInboundFrom, singboxlog.EventInboundTo, singboxlog.EventOutboundTo,
		singboxlog.EventFinished, singboxlog.EventClosed, singboxlog.EventConnectionClosed,
		singboxlog.EventDialFailed:
		if l.Packet {
			return "udp"
		}
		return "tcp"
	}
	return ""
}

// sameHost compares a DNS answer's domain with the destination as logged,
// tolerating the trailing dot and the case that DNS lines carry.
func sameHost(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func srcKey(ip, port string) string {
	if ip == "" {
		return ""
	}
	return ip + "|" + port
}

func atoiPort(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// millis floors a duration to milliseconds and never reports a negative one,
// which only a clock jump could produce.
func millis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(d / time.Millisecond)
}

// doneSet is a bounded FIFO of log ids already emitted. It exists so that the
// lines that keep arriving after a connection is complete (the inbound's own
// close line lands after both directions have reported) are dropped instead of
// creating a phantom connection that the orphan sweep would later publish as
// an empty unknown record.
type doneSet struct {
	ids  map[uint32]struct{}
	ring []uint32
	cap  int
	pos  int
}

func newDoneSet(capacity int) *doneSet {
	if capacity < 1 {
		capacity = 1
	}
	return &doneSet{ids: make(map[uint32]struct{}), ring: make([]uint32, 0, capacity), cap: capacity}
}

func (d *doneSet) add(id uint32) {
	if _, ok := d.ids[id]; ok {
		return
	}
	if len(d.ring) < d.cap {
		d.ring = append(d.ring, id)
	} else {
		delete(d.ids, d.ring[d.pos])
		d.ring[d.pos] = id
		d.pos = (d.pos + 1) % d.cap
	}
	d.ids[id] = struct{}{}
}

func (d *doneSet) has(id uint32) bool {
	_, ok := d.ids[id]
	return ok
}

func (d *doneSet) reset() {
	d.ids = make(map[uint32]struct{})
	d.ring = d.ring[:0]
	d.pos = 0
}
