package sshwatch

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)

func feed(a *Aggregator, at time.Time, lines ...string) {
	for _, line := range lines {
		a.Observe(at, line)
	}
}

func TestAggregatorSummarisesAWindow(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	feed(a, base,
		`Failed password for invalid user admin from 203.0.113.5 port 22 ssh2`,
		`Invalid user admin from 203.0.113.5 port 22`,
		`Failed password for root from 203.0.113.5 port 22 ssh2`,
		`Aug 19 03:14:07 node1 sshd[4242]: Failed password for root from 198.51.100.7 port 22 ssh2`,
		`some unrelated line`,
	)
	if _, ok := a.Roll(base.Add(5 * time.Minute)); ok {
		t.Fatal("window closed before it elapsed")
	}
	w, ok := a.Roll(base.Add(10 * time.Minute))
	if !ok {
		t.Fatal("window with failures was not reported")
	}
	if w.Failures != 4 || w.InvalidUser != 2 || w.Sources != 2 {
		t.Fatalf("failures=%d invalid=%d sources=%d, want 4/2/2", w.Failures, w.InvalidUser, w.Sources)
	}
	if !w.Start.Equal(base) || !w.End.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("window span %v..%v", w.Start, w.End)
	}
	want := []SourcePressure{
		{Address: "203.0.113.5", Failures: 3, InvalidUser: 2},
		{Address: "198.51.100.7", Failures: 1},
	}
	if len(w.TopSources) != 2 || w.TopSources[0] != want[0] || w.TopSources[1] != want[1] {
		t.Fatalf("top sources = %+v, want %+v", w.TopSources, want)
	}
	// The next window starts clean.
	if w, ok := a.Roll(base.Add(20 * time.Minute)); ok || w.Failures != 0 {
		t.Fatalf("counters carried into the next window: ok=%v %+v", ok, w)
	}
}

// Thirty nodes reporting "nothing happened" every ten minutes is how a channel
// gets muted, so a quiet window produces nothing to send.
func TestAggregatorSkipsQuietWindows(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	if _, ok := a.Roll(base); ok {
		t.Fatal("reported before any observation")
	}
	feed(a, base, `Accepted password for alice from 203.0.113.5 port 22 ssh2`)
	if _, ok := a.Roll(base.Add(10 * time.Minute)); ok {
		t.Fatal("a window with only a clean login was reported")
	}
}

func TestSuccessAfterFailureIsFlaggedImmediatelyAndInTheWindow(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	for i := 0; i < 5; i++ {
		a.Observe(base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	}
	login, ok := a.Observe(base.Add(time.Minute), `Accepted password for root from 203.0.113.5 port 22 ssh2`)
	if !ok {
		t.Fatal("accepted login not reported")
	}
	if login.Event.User != "root" || login.PriorFailures != 5 {
		t.Fatalf("login = %+v, want root with 5 prior failures", login)
	}
	// The same session reconnecting must not push other suspects out of the list.
	a.Observe(base.Add(2*time.Minute), `Accepted password for root from 203.0.113.5 port 22 ssh2`)

	w, ok := a.Roll(base.Add(10 * time.Minute))
	if !ok || len(w.SuspectSuccess) != 1 {
		t.Fatalf("suspect successes = %+v", w.SuspectSuccess)
	}
	s := w.SuspectSuccess[0]
	if s.Address != "203.0.113.5" || s.User != "root" || s.Method != "password" || s.PriorFailures != 5 || s.Successes != 2 {
		t.Fatalf("suspect = %+v", s)
	}
}

func TestSuccessFromAQuietSourceIsNotSuspect(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	feed(a, base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	login, _ := a.Observe(base, `Accepted publickey for alice from 198.51.100.7 port 22 ssh2`)
	if login.PriorFailures != 0 {
		t.Fatalf("prior failures = %d for a source that never failed", login.PriorFailures)
	}
	w, _ := a.Roll(base.Add(10 * time.Minute))
	if len(w.SuspectSuccess) != 0 {
		t.Fatalf("suspect successes = %+v", w.SuspectSuccess)
	}
}

// Failures at 09:59 and a success at 10:01 are the same event. A per-window map
// alone would lose it at the boundary, which is why the suspect memory has its
// own lifetime.
func TestSuspectSurvivesTheWindowBoundary(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute, SuspectWindow: time.Hour})
	for i := 0; i < 3; i++ {
		a.Observe(base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	}
	if _, ok := a.Roll(base.Add(10 * time.Minute)); !ok {
		t.Fatal("first window not reported")
	}
	a.Observe(base.Add(11*time.Minute), `Accepted password for root from 203.0.113.5 port 22 ssh2`)
	w, ok := a.Roll(base.Add(20 * time.Minute))
	if !ok {
		t.Fatal("window carrying only a suspect success was not reported")
	}
	if len(w.SuspectSuccess) != 1 || w.SuspectSuccess[0].PriorFailures != 3 {
		t.Fatalf("suspect successes = %+v", w.SuspectSuccess)
	}
	if w.Failures != 0 {
		t.Fatalf("failures = %d, want the previous window's count to be gone", w.Failures)
	}
}

func TestSuspectExpires(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute, SuspectWindow: 30 * time.Minute})
	a.Observe(base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	a.Roll(base.Add(10 * time.Minute))
	login, _ := a.Observe(base.Add(31*time.Minute), `Accepted password for root from 203.0.113.5 port 22 ssh2`)
	if login.PriorFailures != 0 {
		t.Fatalf("prior failures = %d after the source went quiet", login.PriorFailures)
	}
}

// A distributed scan is exactly the input that would blow the structure up, and
// it must not push the one source that matters out of the ranking.
func TestSourceCapKeepsTheHeaviestAndKeepsTotalsExact(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute, MaxSources: 4})
	for i := 0; i < 20; i++ {
		a.Observe(base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	}
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf(`Invalid user admin from 198.51.100.%d port 22`, i+1)
		a.Observe(base.Add(time.Duration(i)*time.Second), line)
	}
	w, ok := a.Roll(base.Add(10 * time.Minute))
	if !ok {
		t.Fatal("window not reported")
	}
	if w.Failures != 30 || w.InvalidUser != 10 || w.Sources != 11 {
		t.Fatalf("failures=%d invalid=%d sources=%d, want 30/10/11", w.Failures, w.InvalidUser, w.Sources)
	}
	if w.SourcesDropped != 7 {
		t.Fatalf("sources dropped = %d, want 7", w.SourcesDropped)
	}
	if len(w.TopSources) != 4 {
		t.Fatalf("tracked sources = %d, want the cap of 4", len(w.TopSources))
	}
	if w.TopSources[0].Address != "203.0.113.5" || w.TopSources[0].Failures != 20 {
		t.Fatalf("the heaviest source was evicted: %+v", w.TopSources)
	}
	if got := len(a.src); got > 4 {
		t.Fatalf("tracking %d sources, cap is 4", got)
	}
}

func TestTopSourcesCap(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute, MaxTopSources: 2})
	for i := 0; i < 5; i++ {
		for n := 0; n <= i; n++ {
			a.Observe(base, fmt.Sprintf(`Failed password for root from 198.51.100.%d port 22 ssh2`, i+1))
		}
	}
	w, _ := a.Roll(base.Add(10 * time.Minute))
	if len(w.TopSources) != 2 {
		t.Fatalf("top sources = %d, want 2", len(w.TopSources))
	}
	if w.TopSources[0].Failures != 5 || w.TopSources[1].Failures != 4 {
		t.Fatalf("top sources not ranked by failures: %+v", w.TopSources)
	}
	if w.Sources != 5 {
		t.Fatalf("sources = %d, want the exact count even though the list is capped", w.Sources)
	}
}

func TestSuspectCap(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute, MaxSuspects: 2})
	for i := 1; i <= 4; i++ {
		addr := fmt.Sprintf("198.51.100.%d", i)
		a.Observe(base, fmt.Sprintf(`Failed password for root from %s port 22 ssh2`, addr))
		a.Observe(base, fmt.Sprintf(`Accepted password for root from %s port 22 ssh2`, addr))
	}
	w, _ := a.Roll(base.Add(10 * time.Minute))
	if len(w.SuspectSuccess) != 2 {
		t.Fatalf("suspect successes = %d, want the cap of 2", len(w.SuspectSuccess))
	}
}

// The username in a failure record is attacker text. It must not be able to
// manufacture the compromise signal.
func TestForgedSuccessDoesNotCreateASuspect(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	for i := 0; i < 3; i++ {
		a.Observe(base, `Failed password for root from 203.0.113.5 port 22 ssh2`)
	}
	a.Observe(base, `Invalid user Accepted password for root from 203.0.113.5 port 22 ssh2 from 198.51.100.7 port 22`)
	w, _ := a.Roll(base.Add(10 * time.Minute))
	if len(w.SuspectSuccess) != 0 {
		t.Fatalf("forged suspect success: %+v", w.SuspectSuccess)
	}
	if w.Failures != 4 || w.Sources != 2 {
		t.Fatalf("failures=%d sources=%d, want 4/2", w.Failures, w.Sources)
	}
}

// sshd is consistent about how it renders an address, but the failure and the
// login are read by two different parsers, so both are canonicalised before they
// are compared.
func TestIPv6SpellingsAreOneSource(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: 10 * time.Minute})
	a.Observe(base, `Failed password for root from 2001:0DB8::1 port 22 ssh2`)
	a.Observe(base, `Failed password for root from 2001:db8:0:0:0:0:0:1 port 22 ssh2`)
	login, _ := a.Observe(base, `Accepted password for root from 2001:db8:0:0::1 port 22 ssh2`)
	if login.PriorFailures != 2 {
		t.Fatalf("prior failures = %d, want 2 across three spellings", login.PriorFailures)
	}
	w, _ := a.Roll(base.Add(10 * time.Minute))
	if w.Sources != 1 || len(w.TopSources) != 1 || w.TopSources[0].Address != "2001:db8::1" {
		t.Fatalf("sources=%d top=%+v", w.Sources, w.TopSources)
	}
}

func TestStreamLinesFeedsTheAggregator(t *testing.T) {
	a := NewAggregator(AggregatorOptions{Window: time.Minute})
	input := strings.Join([]string{
		`Failed password for invalid user admin from 203.0.113.5 port 22 ssh2`,
		`noise`,
		`Accepted password for alice from 198.51.100.7 port 22 ssh2`,
	}, "\n")
	var logins []LoginEvent
	err := StreamLines(context.Background(), strings.NewReader(input), func(line string) {
		if l, ok := a.Observe(base, line); ok {
			logins = append(logins, l.Event)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(logins) != 1 || logins[0].User != "alice" {
		t.Fatalf("logins = %+v", logins)
	}
	w, ok := a.Roll(base.Add(time.Minute))
	if !ok || w.Failures != 1 || w.InvalidUser != 1 {
		t.Fatalf("ok=%v window=%+v", ok, w)
	}
}
