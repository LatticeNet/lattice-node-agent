package traceshed

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
)

var t0 = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)

func idLine(id uint32, ev singboxlog.Event) singboxlog.Line {
	return singboxlog.Line{HasLogID: true, LogID: id, Event: ev}
}

func first(id uint32) singboxlog.Line { return idLine(id, singboxlog.EventInboundFrom) }
func later(id uint32) singboxlog.Line { return idLine(id, singboxlog.EventOutboundTo) }

// fill spends the current window's budget on lines of tracked connections.
func fill(g *Guard, at time.Time, n int) {
	for i := 0; i < n; i++ {
		g.Admit(at, later(1), true)
	}
}

// A connection first seen over budget is not observed at all: every one of its
// lines is dropped, including after the window has reset and the budget has
// room again. Admitting its later lines would hand the assembler a connection
// with no opening line, which is a wrong record rather than a missing one.
func TestOverBudgetShedsANewConnectionWhole(t *testing.T) {
	g := New(3, 0)
	fill(g, t0, 3)
	if g.Admit(t0, first(7), false) {
		t.Fatal("a new connection over budget was admitted")
	}
	if g.Admit(t0.Add(100*time.Millisecond), later(7), false) {
		t.Fatal("a later line of a shed connection was admitted in the same window")
	}
	// A fresh window with the budget unspent.
	for i, at := range []time.Time{t0.Add(1500 * time.Millisecond), t0.Add(3 * time.Second)} {
		if g.Admit(at, later(7), false) {
			t.Fatalf("line %d of the shed connection was admitted after the window reset", i)
		}
	}
	if !g.Admit(t0.Add(3*time.Second), first(8), false) {
		t.Fatal("a new connection under budget was refused")
	}
}

// Connections already being assembled keep every line whatever the budget,
// so nothing the assembler holds is ever cut mid-connection.
func TestTrackedConnectionsKeepEveryLineOverBudget(t *testing.T) {
	g := New(2, 0)
	fill(g, t0, 2)
	for i := 0; i < 50; i++ {
		if !g.Admit(t0, later(uint32(100+i%3)), true) {
			t.Fatalf("line %d of a tracked connection was dropped over budget", i)
		}
	}
	if shed, dropped := g.Take(); shed != 0 || dropped != 0 {
		t.Fatalf("tracked lines over budget were counted as loss: shed=%d dropped=%d", shed, dropped)
	}
}

// The loss is reported as connections, not lines: one connection with many
// lines counts once.
func TestShedCountsConnectionsNotLines(t *testing.T) {
	g := New(1, 0)
	fill(g, t0, 1)
	for _, id := range []uint32{11, 12} {
		g.Admit(t0, first(id), false)
		for i := 0; i < 8; i++ {
			g.Admit(t0, later(id), false)
		}
	}
	shed, dropped := g.Take()
	if shed != 2 || dropped != 0 {
		t.Fatalf("shed=%d dropped=%d, want 2 connections and no dropped lines", shed, dropped)
	}
	if shed, dropped := g.Take(); shed != 0 || dropped != 0 {
		t.Fatalf("Take did not zero the counters: shed=%d dropped=%d", shed, dropped)
	}
}

// Log ids are random and can be reused within one process. An inbound-from
// line on a shed id is a new connection, judged on its own merits.
func TestInboundFromOnAShedIDStartsFresh(t *testing.T) {
	g := New(1, 0)
	fill(g, t0, 1)
	g.Admit(t0, first(9), false)
	next := t0.Add(2 * time.Second)
	if !g.Admit(next, first(9), false) {
		t.Fatal("a new connection reusing a shed id was refused under budget")
	}
	if !g.Admit(next.Add(time.Millisecond), later(9), true) {
		t.Fatal("the new connection's later line was refused")
	}
	// And over budget the reused id is shed and counted again.
	fill(g, t0.Add(4*time.Second), 1)
	g.Admit(t0.Add(4*time.Second), first(10), false)
	g.Admit(t0.Add(6*time.Second), first(10), false)
	fill(g, t0.Add(6*time.Second), 1)
	g.Admit(t0.Add(6*time.Second), first(10), false)
	if shed, _ := g.Take(); shed != 3 {
		t.Fatalf("shed = %d, want 3: ids 9 and 10 once each, and 10 again after its reuse", shed)
	}
}

// Lines without a log id (startup, listener, DNS without a connection) belong
// to no record. Over budget they are dropped and counted as lines.
func TestIDLessLinesOverBudgetAreDroppedAndCounted(t *testing.T) {
	g := New(2, 0)
	bare := singboxlog.Line{Event: singboxlog.EventOther}
	if !g.Admit(t0, bare, false) || !g.Admit(t0, bare, false) {
		t.Fatal("id-less lines under budget were dropped")
	}
	for i := 0; i < 3; i++ {
		if g.Admit(t0, bare, false) {
			t.Fatal("an id-less line over budget was kept")
		}
	}
	if shed, dropped := g.Take(); shed != 0 || dropped != 3 {
		t.Fatalf("shed=%d dropped=%d, want 0 and 3", shed, dropped)
	}
}

// A sing-box restart starts log ids over, so a shed mark from the old process
// must not silence a connection of the new one.
func TestResetForgetsShedIDs(t *testing.T) {
	g := New(1, 0)
	fill(g, t0, 1)
	g.Admit(t0, first(5), false)
	g.Reset()
	if !g.Admit(t0.Add(2*time.Second), later(5), false) {
		t.Fatal("a shed mark survived Reset")
	}
}

// The ring is bounded: past its capacity the oldest mark is forgotten. A mark
// that was cleared and set again is not removed by its stale slot.
func TestShedRingIsBounded(t *testing.T) {
	g := New(1, 4)
	fill(g, t0, 1)
	for id := uint32(1); id <= 10; id++ {
		g.Admit(t0, first(1000+id), false)
	}
	if n := g.shed.len(); n != 4 {
		t.Fatalf("ring holds %d marks, want the capacity 4", n)
	}
	if g.shed.has(1001) || !g.shed.has(1010) {
		t.Fatal("the ring did not evict oldest first")
	}

	r := newShedRing(2)
	r.add(1)
	r.remove(1)
	r.add(1) // the same id marked again, in a new slot
	r.add(2) // ring full: [1(old), 1(new)] then 2 overwrites the old slot of 1
	if !r.has(1) {
		t.Fatal("evicting a stale slot removed a newer mark of the same id")
	}
}

// Past HardCeilingFactor times the budget, entries are dropped before they are
// parsed and counted as lines. Below it, every entry is offered to the parser.
func TestHardCeilingDropsBeforeParsing(t *testing.T) {
	g := New(5, 0)
	ceiling := 5 * HardCeilingFactor
	for i := 0; i < ceiling; i++ {
		if !g.Ceiling(t0) {
			t.Fatalf("entry %d under the ceiling of %d was dropped", i+1, ceiling)
		}
	}
	for i := 0; i < 7; i++ {
		if g.Ceiling(t0.Add(500 * time.Millisecond)) {
			t.Fatal("an entry over the hard ceiling was let through to the parser")
		}
	}
	if shed, dropped := g.Take(); shed != 0 || dropped != 7 {
		t.Fatalf("shed=%d dropped=%d, want 0 and 7", shed, dropped)
	}
	if !g.Ceiling(t0.Add(time.Second)) {
		t.Fatal("the ceiling did not reset with the window")
	}
	g.SetBudget(1)
	for i := 0; i < HardCeilingFactor-1; i++ {
		g.Ceiling(t0.Add(time.Second))
	}
	if g.Ceiling(t0.Add(time.Second)) {
		t.Fatal("a lower budget did not lower the ceiling on the running window")
	}
}
