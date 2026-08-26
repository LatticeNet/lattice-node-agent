package sessionasm

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-sdk/model"
)

// t0 is the deterministic base clock. No test in this package sleeps or reads
// the wall clock: every Options.Now is a closure over a fixed instant and every
// time based path is driven through Tick.
var t0 = time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)

func newAsm(t *testing.T, mutate func(*Options)) *Assembler {
	t.Helper()
	opts := Options{NodeID: "node-a", CoreGeneration: 1, Now: func() time.Time { return t0 }}
	if mutate != nil {
		mutate(&opts)
	}
	return New(opts)
}

func inFrom(id uint32, at time.Time, elapsedMS int64, ip string, port int) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "info", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "inbound/vless[vless-exit]", TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
		Event: singboxlog.EventInboundFrom, SrcIP: ip, SrcPort: port,
	}
}

func inTo(id uint32, at time.Time, elapsedMS int64, user, host string, port int) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "info", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "inbound/vless[vless-exit]", TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
		Event: singboxlog.EventInboundTo, User: user, DstHost: host, DstPort: port,
	}
}

func outTo(id uint32, at time.Time, elapsedMS int64, host string, port int) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "info", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "outbound/direct[direct-out]", TagKind: singboxlog.TagOutbound, TagType: "direct", TagName: "direct-out",
		Event: singboxlog.EventOutboundTo, DstHost: host, DstPort: port,
	}
}

func half(id uint32, at time.Time, elapsedMS int64, ev singboxlog.Event, dir singboxlog.Direction, errText string) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "debug", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "connection", TagKind: singboxlog.TagConnection,
		Event: ev, Direction: dir, Error: errText,
	}
}

// openConn feeds the three lines every connection starts with.
func openConn(a *Assembler, id uint32, at time.Time, port int, host string) {
	a.Line(inFrom(id, at, 0, "10.0.0.9", port))
	a.Line(inTo(id, at, 1, "u_a1b2c3d4e5f60718", host, 443))
	a.Line(outTo(id, at, 2, host, 443))
}

func drainOne(t *testing.T, a *Assembler) model.ConnRecord {
	t.Helper()
	recs := a.Drain()
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 record, got %d: %+v", len(recs), recs)
	}
	return recs[0]
}

// The outbound line is printed twice, identically, for every connection. The
// second one must leave the record byte for byte identical to the first.
func TestDuplicateOutboundLineIsIdempotent(t *testing.T) {
	build := func(dup bool) model.ConnRecord {
		a := newAsm(t, nil)
		a.Line(inFrom(1, t0, 0, "10.0.0.9", 5000))
		a.Line(inTo(1, t0.Add(time.Millisecond), 1, "u_a1b2c3d4e5f60718", "example.com", 443))
		a.Line(outTo(1, t0.Add(2*time.Millisecond), 2, "example.com", 443))
		if dup {
			a.Line(outTo(1, t0.Add(2*time.Millisecond), 2, "example.com", 443))
		}
		a.Line(half(1, t0.Add(9*time.Millisecond), 9, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
		a.Line(half(1, t0.Add(9*time.Millisecond), 9, singboxlog.EventClosed, singboxlog.DirectionUpload, ""))
		recs := a.Drain()
		if len(recs) != 1 {
			t.Fatalf("dup=%v: want 1 record, got %d", dup, len(recs))
		}
		return recs[0]
	}
	once, twice := build(false), build(true)
	if !reflect.DeepEqual(once, twice) {
		t.Fatalf("duplicate outbound line changed the record:\n once %+v\ntwice %+v", once, twice)
	}
	if once.OutboundTag != "direct-out" || once.OutboundType != "direct" {
		t.Fatalf("outbound = %q/%q", once.OutboundType, once.OutboundTag)
	}
	if once.DurationMS != 9 {
		t.Fatalf("duration = %dms, want the elapsed on the final line", once.DurationMS)
	}
}

// One direction reported and the other never did. The honest answer is
// unknown, and the partial evidence stays in CloseError.
func TestHalfCloseThenOrphanTTLYieldsUnknown(t *testing.T) {
	cases := []struct {
		name     string
		errText  string
		wantErr  string
		wantKind string
	}{
		{name: "clean half", errText: "", wantErr: "no further log lines for this connection"},
		{name: "error half", errText: "read: connection reset by peer", wantErr: "read: connection reset by peer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Open snapshots have their own test; turn them off here so what
			// comes out of Drain can only be the orphan sweep.
			a := newAsm(t, func(o *Options) { o.SnapshotEvery = time.Hour })
			openConn(a, 7, t0, 5001, "example.com")
			a.Line(half(7, t0.Add(20*time.Millisecond), 20, singboxlog.EventClosed, singboxlog.DirectionUpload, tc.errText))
			if recs := a.Drain(); len(recs) != 0 {
				t.Fatalf("one half close must not finish a connection, got %+v", recs)
			}
			a.Tick(t0.Add(9 * time.Minute))
			if recs := a.Drain(); len(recs) != 0 {
				t.Fatalf("orphan swept before the TTL: %+v", recs)
			}
			// The TTL runs from the last evidence of life, which is the half
			// close at 20ms, not from the connection's start.
			a.Tick(t0.Add(10*time.Minute + time.Second))
			rec := drainOne(t, a)
			if rec.CloseReason != model.CloseUnknown {
				t.Errorf("close reason = %q, want %q", rec.CloseReason, model.CloseUnknown)
			}
			if rec.CloseError != tc.wantErr {
				t.Errorf("close error = %q, want %q", rec.CloseError, tc.wantErr)
			}
			if rec.EndedAt != t0.Add(10*time.Minute+time.Second) {
				t.Errorf("ended at = %s", rec.EndedAt)
			}
			// The duration is sing-box's own last elapsed, a measured lower
			// bound, not the ten silent minutes the agent waited.
			if rec.DurationMS != 20 {
				t.Errorf("duration = %dms, want 20ms", rec.DurationMS)
			}
			if s := a.Stats(); s.Orphaned != 1 || s.Open != 0 {
				t.Errorf("stats = %+v, want one orphan and nothing open", s)
			}
		})
	}
}

func TestCoreRestartSweepsOpenConnections(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 11, t0, 5001, "a.example")
	openConn(a, 12, t0, 5002, "b.example")
	openConn(a, 13, t0, 5003, "c.example")
	// One of them closes normally before the restart, so it must not be swept.
	a.Line(half(13, t0.Add(time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(13, t0.Add(time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	if got := a.Drain(); len(got) != 1 || got[0].CloseReason != model.CloseEOF {
		t.Fatalf("expected one clean record before the restart, got %+v", got)
	}

	at := t0.Add(90 * time.Second)
	a.CoreRestart(2, at)
	swept := a.Drain()
	if len(swept) != 2 {
		t.Fatalf("swept %d records, want 2", len(swept))
	}
	for _, r := range swept {
		if r.CloseReason != model.CloseCoreRestart || r.CloseError != "" {
			t.Errorf("record %d: close = %q/%q", r.LogID, r.CloseReason, r.CloseError)
		}
		if !r.EndedAt.Equal(at) {
			t.Errorf("record %d: ended at %s, want %s", r.LogID, r.EndedAt, at)
		}
		// Swept records belong to the generation whose log ids they carry.
		if r.CoreGeneration != 1 {
			t.Errorf("record %d: generation = %d, want the pre-restart 1", r.LogID, r.CoreGeneration)
		}
		if r.DurationMS != 90_000 {
			t.Errorf("record %d: duration = %dms, want the 90s it provably lived", r.LogID, r.DurationMS)
		}
	}
	s := a.Stats()
	if s.Swept != 2 || s.Open != 0 {
		t.Fatalf("stats = %+v, want 2 swept and nothing open", s)
	}

	// Everything after the restart carries the new generation.
	openConn(a, 11, at.Add(time.Second), 5001, "a.example")
	a.Line(half(11, at.Add(2*time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(11, at.Add(2*time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	if rec := drainOne(t, a); rec.CoreGeneration != 2 {
		t.Fatalf("post restart generation = %d, want 2", rec.CoreGeneration)
	}
}

func TestMaxOpenDropsOldestAndCounts(t *testing.T) {
	a := newAsm(t, func(o *Options) { o.MaxOpen = 2 })
	openConn(a, 21, t0, 5001, "a.example")
	openConn(a, 22, t0.Add(time.Second), 5002, "b.example")
	openConn(a, 23, t0.Add(2*time.Second), 5003, "c.example")

	if recs := a.Drain(); len(recs) != 0 {
		t.Fatalf("an eviction must not emit a record, got %+v", recs)
	}
	s := a.Stats()
	if s.Open != 2 || s.Dropped != 1 || s.Emitted != 0 {
		t.Fatalf("stats = %+v, want 2 open and 1 dropped", s)
	}

	// The evicted id is remembered, so its trailing lines do not immediately
	// recreate what the cap just forced out.
	a.Line(half(21, t0.Add(3*time.Second), 3000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(21, t0.Add(3*time.Second), 3000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	if recs := a.Drain(); len(recs) != 0 {
		t.Fatalf("dropped connection came back: %+v", recs)
	}
	if s := a.Stats(); s.Open != 2 {
		t.Fatalf("open = %d, want the cap to hold at 2", s.Open)
	}
}

func TestStallSetsThenClears(t *testing.T) {
	a := newAsm(t, nil) // floor 60s, quiet 30s
	openConn(a, 31, t0, 5001, "long.example")

	snap := func(at time.Time, up, down int64) {
		a.Snapshot(Snapshot{At: at, Items: []SnapshotItem{{
			SrcIP: "10.0.0.9", SrcPort: "5001", DstHost: "long.example", DstPort: "443",
			InboundType: "vless", InboundTag: "vless-exit", Network: "tcp",
			Upload: up, Download: down, Rule: "final", Start: t0,
		}}})
	}

	// First sample is only a baseline: it says nothing about movement before it.
	snap(t0.Add(70*time.Second), 100, 200)
	a.Tick(t0.Add(70 * time.Second))
	if rec := a.Drain(); len(rec) != 1 || !rec[0].StalledAt.IsZero() {
		t.Fatalf("stalled on the first sample: %+v", rec)
	}

	// Same counters 40s later: two samples now bracket the quiet window.
	snap(t0.Add(110*time.Second), 100, 200)
	a.Tick(t0.Add(130 * time.Second))
	recs := a.Drain()
	if len(recs) != 1 {
		t.Fatalf("want one open snapshot, got %d", len(recs))
	}
	if !recs[0].StalledAt.Equal(t0.Add(70 * time.Second)) {
		t.Fatalf("stalled at = %s, want the last time bytes moved (%s)", recs[0].StalledAt, t0.Add(70*time.Second))
	}
	if !recs[0].Open || recs[0].CloseReason != model.CloseUnknown {
		t.Fatalf("open snapshot = open %v reason %q", recs[0].Open, recs[0].CloseReason)
	}

	// Bytes move again: the flag is a live judgement, not a permanent mark.
	snap(t0.Add(140*time.Second), 500, 200)
	a.Tick(t0.Add(200 * time.Second))
	recs = a.Drain()
	if len(recs) != 1 {
		t.Fatalf("want one open snapshot, got %d", len(recs))
	}
	if !recs[0].StalledAt.IsZero() {
		t.Fatalf("stall survived byte movement: %s", recs[0].StalledAt)
	}
	if recs[0].Upload != 500 || recs[0].Download != 200 || !recs[0].BytesKnown {
		t.Fatalf("bytes = %d/%d known %v", recs[0].Upload, recs[0].Download, recs[0].BytesKnown)
	}
}

// A connection nobody ever sampled is unobserved, never stalled.
func TestNeverSampledIsNeitherStalledNorCounted(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 41, t0, 5001, "short.example")
	a.Tick(t0.Add(5 * time.Minute))
	a.Line(half(41, t0.Add(5*time.Minute), 300_000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(41, t0.Add(5*time.Minute), 300_000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))

	for _, rec := range a.Drain() {
		if rec.BytesKnown {
			t.Errorf("record %d claims known bytes without a snapshot", rec.LogID)
		}
		if rec.Upload != 0 || rec.Download != 0 {
			t.Errorf("record %d invented bytes %d/%d", rec.LogID, rec.Upload, rec.Download)
		}
		if !rec.StalledAt.IsZero() {
			t.Errorf("record %d called stalled with no samples at all", rec.LogID)
		}
	}
}

// A snapshot that measured zeros is a different fact from never measuring.
func TestSnapshotZerosAreKnownZeros(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 51, t0, 5001, "idle.example")
	a.Snapshot(Snapshot{At: t0.Add(5 * time.Second), Items: []SnapshotItem{{
		SrcIP: "10.0.0.9", SrcPort: "5001", Upload: 0, Download: 0,
	}}})
	a.Line(half(51, t0.Add(6*time.Second), 6000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(51, t0.Add(6*time.Second), 6000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))

	rec := drainOne(t, a)
	if !rec.BytesKnown || rec.Upload != 0 || rec.Download != 0 {
		t.Fatalf("measured zeros = %d/%d known %v, want 0/0 known", rec.Upload, rec.Download, rec.BytesKnown)
	}
}

func TestSnapshotJoinsBySrcAndFillsGaps(t *testing.T) {
	a := newAsm(t, nil)
	// The accept line arrived with a tag the parser could not decompose and the
	// post auth line never came, so the snapshot is the only source for the
	// inbound identity and the destination.
	bare := inFrom(61, t0, 0, "10.0.0.9", 5001)
	bare.Tag, bare.TagType, bare.TagName = "inbound", "", ""
	a.Line(bare)
	a.Snapshot(Snapshot{At: t0.Add(time.Second), Items: []SnapshotItem{{
		SrcIP: "10.0.0.9", SrcPort: "5001", DstHost: "filled.example", DstPort: "8443",
		InboundType: "mixed", InboundTag: "mixed-entry", Network: "tcp",
		Upload: 10, Download: 20, Rule: "domain_suffix=filled.example",
		Chains: []string{"chain-to-exit"}, Start: t0,
	}}})
	a.Line(half(61, t0.Add(2*time.Second), 2000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(61, t0.Add(2*time.Second), 2000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))

	rec := drainOne(t, a)
	if rec.DstHost != "filled.example" || rec.DstPort != 8443 {
		t.Errorf("dst = %q:%d", rec.DstHost, rec.DstPort)
	}
	if rec.InboundTag != "mixed-entry" || rec.InboundType != "mixed" || rec.RuleText != "domain_suffix=filled.example" || rec.OutboundTag != "chain-to-exit" {
		t.Errorf("filled fields = %q %q %q %q", rec.InboundType, rec.InboundTag, rec.RuleText, rec.OutboundTag)
	}
	if rec.Upload != 10 || rec.Download != 20 || !rec.BytesKnown {
		t.Errorf("bytes = %d/%d known %v", rec.Upload, rec.Download, rec.BytesKnown)
	}

	// A log line always beats a snapshot: the inbound tag stays what sing-box
	// printed, not what the connection table guessed.
	b := newAsm(t, nil)
	openConn(b, 62, t0, 5002, "logged.example")
	b.Snapshot(Snapshot{At: t0.Add(time.Second), Items: []SnapshotItem{{
		SrcIP: "10.0.0.9", SrcPort: "5002", DstHost: "wrong.example", DstPort: "1",
		InboundType: "shadowsocks", InboundTag: "other-inbound", Chains: []string{"other-out"},
	}}})
	b.Line(half(62, t0.Add(2*time.Second), 2000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	b.Line(half(62, t0.Add(2*time.Second), 2000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	rec = drainOne(t, b)
	if rec.InboundTag != "vless-exit" || rec.DstHost != "logged.example" || rec.OutboundTag != "direct-out" {
		t.Fatalf("snapshot overwrote logged fields: %q %q %q", rec.InboundTag, rec.DstHost, rec.OutboundTag)
	}
}

// An ephemeral port comes back around. A still listed older connection must
// not donate its bytes to the new connection holding the same port.
func TestSnapshotIgnoresReusedSourcePort(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 71, t0.Add(time.Hour), 5001, "new.example")
	a.Snapshot(Snapshot{At: t0.Add(time.Hour), Items: []SnapshotItem{{
		SrcIP: "10.0.0.9", SrcPort: "5001", Upload: 999, Download: 999,
		Start: t0, // an hour before the connection now holding this port
	}}})
	a.Line(half(71, t0.Add(time.Hour+time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(71, t0.Add(time.Hour+time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))

	rec := drainOne(t, a)
	if rec.BytesKnown || rec.Upload != 0 {
		t.Fatalf("bytes from another connection were joined: %d/%d known %v", rec.Upload, rec.Download, rec.BytesKnown)
	}
}

// A connection sing-box still lists is alive, whatever the log stream says.
func TestSampledConnectionIsNotOrphaned(t *testing.T) {
	a := newAsm(t, func(o *Options) { o.OrphanTTL = time.Minute; o.SnapshotEvery = time.Hour })
	openConn(a, 81, t0, 5001, "long.example")
	for i := 1; i <= 5; i++ {
		at := t0.Add(time.Duration(i) * 30 * time.Second)
		a.Snapshot(Snapshot{At: at, Items: []SnapshotItem{{
			SrcIP: "10.0.0.9", SrcPort: "5001", Upload: int64(i) * 10, Download: int64(i) * 10,
		}}})
		a.Tick(at)
	}
	if recs := a.Drain(); len(recs) != 0 {
		t.Fatalf("a connection visible in /connections was orphaned: %+v", recs)
	}
	if s := a.Stats(); s.Open != 1 || s.Orphaned != 0 {
		t.Fatalf("stats = %+v, want it still open", s)
	}
	// Once it disappears from the connection table too, the TTL applies.
	a.Tick(t0.Add(5*30*time.Second + 61*time.Second))
	if rec := drainOne(t, a); rec.CloseReason != model.CloseUnknown {
		t.Fatalf("close reason = %q", rec.CloseReason)
	}
}

func TestOpenSnapshotsReplaceAndOnlyTheLastRecordIsClosed(t *testing.T) {
	a := newAsm(t, nil) // SnapshotEvery 60s
	openConn(a, 91, t0, 5001, "long.example")

	a.Tick(t0.Add(59 * time.Second))
	if recs := a.Drain(); len(recs) != 0 {
		t.Fatalf("snapshot before the interval: %+v", recs)
	}
	a.Tick(t0.Add(60 * time.Second))
	a.Tick(t0.Add(121 * time.Second))
	snaps := a.Drain()
	if len(snaps) != 2 {
		t.Fatalf("want 2 open snapshots, got %d", len(snaps))
	}
	for i, rec := range snaps {
		if !rec.Open {
			t.Errorf("snapshot %d is not marked open", i)
		}
		// Snapshots replace each other downstream, so each has to stand alone.
		if rec.UserName != "u_a1b2c3d4e5f60718" || rec.UserKind != model.UserKindManaged ||
			rec.DstHost != "long.example" || rec.OutboundTag != "direct-out" || rec.NodeID != "node-a" ||
			rec.SrcIP != "10.0.0.9" || rec.InboundTag != "vless-exit" || rec.CoreGeneration != 1 {
			t.Errorf("snapshot %d is not a complete record: %+v", i, rec)
		}
	}
	if snaps[0].DurationMS != 60_000 || snaps[1].DurationMS != 121_000 {
		t.Errorf("open durations = %d, %d", snaps[0].DurationMS, snaps[1].DurationMS)
	}

	a.Line(half(91, t0.Add(130*time.Second), 130_000, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(91, t0.Add(130*time.Second), 130_000, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	final := drainOne(t, a)
	if final.Open {
		t.Error("the final record must not be open")
	}
	if final.DurationMS != 130_000 {
		t.Errorf("final duration = %dms, want sing-box's own elapsed", final.DurationMS)
	}
	if s := a.Stats(); s.Emitted != 3 {
		t.Errorf("emitted = %d, want the two snapshots plus the final record", s.Emitted)
	}
}

func TestCloseReasonMapping(t *testing.T) {
	cases := []struct {
		name       string
		feed       func(a *Assembler)
		wantReason string
		wantErr    string
	}{
		{
			name: "dial failure is terminal with no close line",
			feed: func(a *Assembler) {
				a.Line(dialFailed(101, t0.Add(time.Second), 1000, "dial tcp: connect: connection refused"))
			},
			wantReason: model.CloseDialFailed,
			wantErr:    "dial tcp: connect: connection refused",
		},
		{
			name:       "reset by peer",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "read tcp: connection reset by peer")) },
			wantReason: model.CloseReset,
			wantErr:    "read tcp: connection reset by peer",
		},
		{
			name:       "i/o timeout",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "read tcp: i/o timeout")) },
			wantReason: model.CloseTimeout,
			wantErr:    "read tcp: i/o timeout",
		},
		{
			name:       "context deadline exceeded",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "context deadline exceeded")) },
			wantReason: model.CloseTimeout,
			wantErr:    "context deadline exceeded",
		},
		{
			name:       "TLS handshake beats the EOF inside it",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "TLS handshake: EOF")) },
			wantReason: model.CloseHandshakeFailed,
			wantErr:    "TLS handshake: EOF",
		},
		{
			name:       "plain EOF",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "read http request: EOF")) },
			wantReason: model.CloseEOF,
			wantErr:    "read http request: EOF",
		},
		{
			name:       "empty error on the inbound close is EOF",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "")) },
			wantReason: model.CloseEOF,
		},
		{
			name:       "an error we do not model stays unknown, text kept",
			feed:       func(a *Assembler) { a.Line(connClosed(101, t0, 5, "some future sing-box error")) },
			wantReason: model.CloseUnknown,
			wantErr:    "some future sing-box error",
		},
		{
			name: "both directions finish cleanly",
			feed: func(a *Assembler) {
				a.Line(half(101, t0, 5, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
				a.Line(half(101, t0, 5, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
			},
			wantReason: model.CloseEOF,
		},
		{
			name: "the trace level cancel half does not turn a finished connection into canceled",
			feed: func(a *Assembler) {
				a.Line(half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionUpload, ""))
				a.Line(half(101, t0, 5, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
			},
			wantReason: model.CloseEOF,
		},
		{
			name: "both directions cancelled",
			feed: func(a *Assembler) {
				a.Line(half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionUpload, ""))
				a.Line(half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionDownload, ""))
			},
			wantReason: model.CloseCanceled,
		},
		{
			name: "an error on one half is never hidden by a clean other half",
			feed: func(a *Assembler) {
				a.Line(half(101, t0, 5, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
				a.Line(half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionUpload, "write tcp: connection reset by peer"))
			},
			wantReason: model.CloseReset,
			wantErr:    "write tcp: connection reset by peer",
		},
		{
			name: "a cancelled packet connection is a udp idle timeout",
			feed: func(a *Assembler) {
				up := half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionUpload, "")
				up.Packet = true
				down := half(101, t0, 5, singboxlog.EventClosed, singboxlog.DirectionDownload, "")
				down.Packet = true
				a.Line(up)
				a.Line(down)
			},
			wantReason: model.CloseUDPIdle,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAsm(t, nil)
			openConn(a, 101, t0, 5001, "example.com")
			tc.feed(a)
			rec := drainOne(t, a)
			if rec.CloseReason != tc.wantReason {
				t.Errorf("close reason = %q, want %q", rec.CloseReason, tc.wantReason)
			}
			if rec.CloseError != tc.wantErr {
				t.Errorf("close error = %q, want %q", rec.CloseError, tc.wantErr)
			}
		})
	}
}

func dialFailed(id uint32, at time.Time, elapsedMS int64, errText string) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "error", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "connection", TagKind: singboxlog.TagConnection, Event: singboxlog.EventDialFailed,
		OutboundType: "direct", OutboundName: "direct-out", Error: errText,
	}
}

func connClosed(id uint32, at time.Time, elapsedMS int64, errText string) singboxlog.Line {
	return singboxlog.Line{
		At: at, Level: "debug", LogID: id, HasLogID: true, ElapsedMS: elapsedMS,
		Tag: "inbound/vless[vless-exit]", TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
		Event: singboxlog.EventConnectionClosed, Error: errText,
	}
}

// Authentication failed, so sing-box never named a user. The record carries the
// source address and nothing else about who it was.
func TestAuthFailedIsAttributedBySourceOnly(t *testing.T) {
	a := newAsm(t, nil)
	a.Line(inFrom(111, t0, 0, "203.0.113.7", 44321))
	a.Line(singboxlog.Line{
		At: t0.Add(time.Millisecond), Level: "error", LogID: 111, HasLogID: true, ElapsedMS: 1,
		Tag: "inbound/vless[vless-exit]", TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
		Event: singboxlog.EventAuthFailed, Error: "process connection from 203.0.113.7:44321: bad request",
	})
	rec := drainOne(t, a)
	if rec.CloseReason != model.CloseAuthFailed {
		t.Errorf("close reason = %q", rec.CloseReason)
	}
	if rec.UserName != "" || rec.UserID != "" || rec.UserKind != model.UserKindUnnamed {
		t.Errorf("a failed authentication produced a user: %q/%q/%q", rec.UserName, rec.UserID, rec.UserKind)
	}
	if rec.SrcIP != "203.0.113.7" || rec.SrcPort != 44321 {
		t.Errorf("src = %s:%d", rec.SrcIP, rec.SrcPort)
	}
}

func TestUserKindFollowsTheNameShape(t *testing.T) {
	cases := []struct {
		user     string
		wantName string
		wantKind string
	}{
		{user: "u_a1b2c3d4e5f60718", wantName: "u_a1b2c3d4e5f60718", wantKind: model.UserKindManaged},
		{user: "u_A1B2C3D4E5F60718", wantName: "u_A1B2C3D4E5F60718", wantKind: model.UserKindLegacy}, // hex is lower case in the rendered form
		{user: "u_a1b2c3d4e5f6071", wantName: "u_a1b2c3d4e5f6071", wantKind: model.UserKindLegacy},   // 15 digits
		{user: "alice-laptop", wantName: "alice-laptop", wantKind: model.UserKindLegacy},
		{user: "", wantName: "", wantKind: model.UserKindUnnamed},
	}
	for _, tc := range cases {
		t.Run(tc.user, func(t *testing.T) {
			a := newAsm(t, nil)
			a.Line(inFrom(121, t0, 0, "10.0.0.9", 5001))
			a.Line(inTo(121, t0, 1, tc.user, "example.com", 443))
			a.Line(connClosed(121, t0, 2, ""))
			rec := drainOne(t, a)
			if rec.UserName != tc.wantName || rec.UserKind != tc.wantKind {
				t.Fatalf("user = %q/%q, want %q/%q", rec.UserName, rec.UserKind, tc.wantName, tc.wantKind)
			}
			if rec.UserID != "" {
				t.Fatalf("agent resolved a user id: %q", rec.UserID)
			}
		})
	}
}

// Log ids are rand.Uint32 and can repeat inside one process lifetime. Two
// connections on one id become two records, and the one we lost track of says
// so rather than being merged into the newer one.
func TestLogIDCollisionSplitsIntoTwoRecords(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 131, t0, 5001, "first.example")
	openConn(a, 131, t0.Add(time.Minute), 5002, "second.example")

	first := drainOne(t, a)
	if first.CloseReason != model.CloseUnknown || first.DstHost != "first.example" {
		t.Fatalf("first record = %q %q", first.CloseReason, first.DstHost)
	}
	if first.CloseError == "" {
		t.Error("the collision should be visible in the close error")
	}
	a.Line(half(131, t0.Add(time.Minute), 100, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
	a.Line(half(131, t0.Add(time.Minute), 100, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
	second := drainOne(t, a)
	if second.DstHost != "second.example" || second.CloseReason != model.CloseEOF {
		t.Fatalf("second record = %q %q", second.DstHost, second.CloseReason)
	}
}

// The assembler is fed by the collector goroutine and emptied by the shipper.
// Run under -race this is the test that guards the mutex.
func TestConcurrentFeedAndDrain(t *testing.T) {
	a := newAsm(t, nil)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			id := uint32(1000 + i)
			at := t0.Add(time.Duration(i) * time.Millisecond)
			openConn(a, id, at, 6000+i, "example.com")
			a.Line(half(id, at, 1, singboxlog.EventFinished, singboxlog.DirectionDownload, ""))
			a.Line(half(id, at, 1, singboxlog.EventFinished, singboxlog.DirectionUpload, ""))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			a.Snapshot(Snapshot{At: t0.Add(time.Duration(i) * time.Millisecond), Items: []SnapshotItem{{
				SrcIP: "10.0.0.9", SrcPort: "6000", Upload: int64(i), Download: int64(i),
			}}})
			a.Tick(t0.Add(time.Duration(i) * time.Second))
		}
	}()
	total := 0
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			total += len(a.Drain())
			_ = a.Stats()
		}
	}()
	wg.Wait()

	total += len(a.Drain())
	if s := a.Stats(); uint64(total) != s.Emitted {
		t.Fatalf("drained %d records but %d were emitted", total, s.Emitted)
	}
}

func TestNewFillsDocumentedDefaults(t *testing.T) {
	a := New(Options{})
	if a.opts.MaxOpen != defaultMaxOpen || a.opts.OrphanTTL != defaultOrphanTTL ||
		a.opts.SnapshotEvery != defaultSnapshotEvery || a.opts.StallFloor != defaultStallFloor ||
		a.opts.StallQuiet != defaultStallQuiet || a.opts.Now == nil {
		t.Fatalf("defaults not applied: %+v", a.opts)
	}
	if a.opts.MaxOpen != 4096 || a.opts.OrphanTTL != 10*time.Minute || a.opts.SnapshotEvery != time.Minute ||
		a.opts.StallFloor != time.Minute || a.opts.StallQuiet != 30*time.Second {
		t.Fatalf("defaults drifted from the documented values: %+v", a.opts)
	}
}

// A line with no id cannot be attributed to a connection, and inventing one
// from it would put a row on screen that stands for nothing.
func TestLineWithoutLogIDIsIgnored(t *testing.T) {
	a := newAsm(t, nil)
	a.Line(singboxlog.Line{At: t0, Level: "info", Tag: "router", TagKind: singboxlog.TagRouter, Event: singboxlog.EventOther})
	if s := a.Stats(); s.Open != 0 || s.Emitted != 0 {
		t.Fatalf("stats = %+v, want nothing tracked", s)
	}
}

// Both observed captures name the direction on every half close. If a future
// format stops naming it, two undirected halves still complete the connection
// instead of leaking it to the orphan sweep.
func TestUndirectedHalfClosesStillComplete(t *testing.T) {
	a := newAsm(t, nil)
	openConn(a, 141, t0, 5001, "example.com")
	a.Line(half(141, t0.Add(time.Second), 1000, singboxlog.EventFinished, singboxlog.DirectionNone, ""))
	if recs := a.Drain(); len(recs) != 0 {
		t.Fatalf("one half closed the connection: %+v", recs)
	}
	a.Line(half(141, t0.Add(2*time.Second), 2000, singboxlog.EventFinished, singboxlog.DirectionNone, ""))
	rec := drainOne(t, a)
	if rec.CloseReason != model.CloseEOF || rec.DurationMS != 2000 {
		t.Fatalf("record = %q %dms", rec.CloseReason, rec.DurationMS)
	}
}

// The done set is what stops trailing lines from resurrecting an emitted
// connection, and it is bounded so that a busy node cannot grow it without
// limit. Past the cap the oldest ids are forgotten first.
func TestDoneSetIsBoundedFIFO(t *testing.T) {
	d := newDoneSet(3)
	for _, id := range []uint32{1, 2, 3} {
		d.add(id)
	}
	d.add(1) // already present, must not consume a slot
	if !d.has(1) || !d.has(2) || !d.has(3) {
		t.Fatal("a re-add evicted something")
	}
	d.add(4)
	if d.has(1) {
		t.Error("the oldest id should have been evicted first")
	}
	if !d.has(2) || !d.has(3) || !d.has(4) {
		t.Error("the newest three ids should be remembered")
	}
	if len(d.ids) != 3 || len(d.ring) != 3 {
		t.Fatalf("done set grew past its cap: %d ids, %d ring", len(d.ids), len(d.ring))
	}
	d.reset()
	if d.has(4) || len(d.ids) != 0 {
		t.Fatal("reset left ids behind")
	}
}

// sing-box words the udp messages as "inbound packet connection from", which
// the parser flags rather than restating in the text.
func TestPacketConnectionIsUDP(t *testing.T) {
	a := newAsm(t, nil)
	from := inFrom(151, t0, 0, "10.0.0.9", 5001)
	from.Packet = true
	to := inTo(151, t0, 1, "u_a1b2c3d4e5f60718", "8.8.8.8", 53)
	to.Packet = true
	a.Line(from)
	a.Line(to)
	up := half(151, t0.Add(time.Minute), 60_000, singboxlog.EventClosed, singboxlog.DirectionUpload, "")
	up.Packet = true
	down := half(151, t0.Add(time.Minute), 60_000, singboxlog.EventClosed, singboxlog.DirectionDownload, "")
	down.Packet = true
	a.Line(up)
	a.Line(down)

	rec := drainOne(t, a)
	if rec.Network != "udp" || rec.CloseReason != model.CloseUDPIdle {
		t.Fatalf("record = network %q reason %q", rec.Network, rec.CloseReason)
	}
}
