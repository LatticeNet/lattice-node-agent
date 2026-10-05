// Package traceshed is the trace collector's per-second line budget.
//
// The budget is a CPU guard measured in parsed lines. Over it, the guard sheds
// whole connections rather than lines: a log id first seen while the current
// second is over budget is marked shed for its lifetime and every line of it
// is skipped, while connections the assembler already holds keep every line.
// Cutting lines out of a connection the assembler is building produces a
// record that is wrong (no close line, no user, a guessed duration); not
// observing a connection at all produces no record and one honest count.
//
// Shedding needs the log id, so every line under the hard ceiling is parsed
// even when the second is over budget. The ceiling (HardCeilingFactor times the
// budget) is the brake on parse CPU: past it, entries are dropped before they
// are parsed and counted as dropped lines, exactly as the old line budget did.
package traceshed

import (
	"sync"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
)

const (
	// HardCeilingFactor is the pre-parse ceiling as a multiple of the budget.
	HardCeilingFactor = 4
	// DefaultRingCapacity bounds the shed ids remembered at once. It is the
	// same shape as the assembler's done set. When a still-open shed id is
	// evicted, its later lines reach the assembler mid-connection, which the
	// assembler already handles as a partial observation.
	DefaultRingCapacity = 65536
)

// Guard decides, per parsed line, whether the collector keeps it. It is safe
// for concurrent use: the stream goroutine admits lines while the assembler
// tick takes the counters and a policy change moves the budget.
type Guard struct {
	mu sync.Mutex

	budget int

	windowStart time.Time
	// entries counts what reached the guard in the current second, before
	// parsing; parsed counts the lines that passed the ceiling.
	entries int
	parsed  int

	shed shedRing

	shedN    uint64
	droppedN uint64
}

// New builds a guard. A budget below 1 is treated as 1; ringCapacity below 1
// uses DefaultRingCapacity.
func New(budget, ringCapacity int) *Guard {
	if ringCapacity < 1 {
		ringCapacity = DefaultRingCapacity
	}
	g := &Guard{shed: newShedRing(ringCapacity)}
	g.SetBudget(budget)
	return g
}

// SetBudget moves the per-second parsed-line budget. It takes effect on the
// next line.
func (g *Guard) SetBudget(n int) {
	if n < 1 {
		n = 1
	}
	g.mu.Lock()
	g.budget = n
	g.mu.Unlock()
}

// Budget reports the budget in force.
func (g *Guard) Budget() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.budget
}

// roll starts a new one second window when the current one has ended.
func (g *Guard) roll(now time.Time) {
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= time.Second || now.Before(g.windowStart) {
		g.windowStart = now
		g.entries = 0
		g.parsed = 0
	}
}

// Ceiling is called once per entry BEFORE it is parsed. It reports false, and
// counts a dropped line, once the current second has seen more than
// HardCeilingFactor times the budget. That is the only place lines are cut
// without regard to their connection, and only because parsing them would
// cost more than the node can spare.
func (g *Guard) Ceiling(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.roll(now)
	g.entries++
	if g.entries > g.budget*HardCeilingFactor {
		g.droppedN++
		return false
	}
	return true
}

// Admit is called once per parsed line. tracked reports whether the
// assembler holds or has already finished this log id. The rules, in order:
// the line counts in the current window; an id-less line over budget is
// dropped and counted, because it belongs to no record; an inbound-from line
// on a shed id clears the mark, because a new connection reused the id; a
// shed id is dropped for its lifetime without counting again; a tracked id is
// kept whatever the budget; an untracked id over budget is marked shed,
// counted once, and dropped; everything else is kept.
func (g *Guard) Admit(now time.Time, l singboxlog.Line, tracked bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.roll(now)
	g.parsed++
	over := g.parsed > g.budget
	if !l.HasLogID {
		if over {
			g.droppedN++
			return false
		}
		return true
	}
	if g.shed.has(l.LogID) {
		if l.Event != singboxlog.EventInboundFrom {
			return false
		}
		g.shed.remove(l.LogID)
	}
	if tracked {
		return true
	}
	if over {
		g.shed.add(l.LogID)
		g.shedN++
		return false
	}
	return true
}

// Reset forgets every shed id. Log ids are drawn afresh by a new sing-box
// process, so a stale mark would silence a connection of the new one.
func (g *Guard) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shed.reset()
}

// Take returns the counts since the last call and zeroes them: connections
// shed, and lines dropped (id-less lines over budget plus entries over the
// hard ceiling).
func (g *Guard) Take() (shed, droppedLines uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	shed, droppedLines = g.shedN, g.droppedN
	g.shedN, g.droppedN = 0, 0
	return shed, droppedLines
}

// shedRing is a bounded FIFO of shed log ids. Each mark carries the sequence
// number it was added under, so evicting an old slot never removes a newer
// mark of the same id that was cleared and set again in between.
type shedRing struct {
	ids  map[uint32]uint64
	ring []shedSlot
	cap  int
	pos  int
	seq  uint64
}

type shedSlot struct {
	id  uint32
	seq uint64
}

func newShedRing(capacity int) shedRing {
	return shedRing{ids: make(map[uint32]uint64), cap: capacity}
}

func (r *shedRing) has(id uint32) bool {
	_, ok := r.ids[id]
	return ok
}

func (r *shedRing) add(id uint32) {
	r.seq++
	slot := shedSlot{id: id, seq: r.seq}
	if len(r.ring) < r.cap {
		r.ring = append(r.ring, slot)
	} else {
		old := r.ring[r.pos]
		if r.ids[old.id] == old.seq {
			delete(r.ids, old.id)
		}
		r.ring[r.pos] = slot
		r.pos = (r.pos + 1) % r.cap
	}
	r.ids[id] = r.seq
}

// remove clears a mark. Its ring slot stays until it is overwritten, and the
// sequence check in add keeps that stale slot from touching a later mark.
func (r *shedRing) remove(id uint32) {
	delete(r.ids, id)
}

func (r *shedRing) len() int { return len(r.ids) }

func (r *shedRing) reset() {
	r.ids = make(map[uint32]uint64)
	r.ring = r.ring[:0]
	r.pos = 0
}
