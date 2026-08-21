package sshwatch

import (
	"net"
	"sort"
	"sync"
	"time"
)

// One public node in this fleet logs 8449 password failures a day. Thirty of
// them log a quarter of a million lines a day between them, and nobody is ever
// going to read those lines, so they are counted here on the node and only the
// count leaves. The lines themselves never enter this package's output: a
// summary that carried raw log text would be both a memory hazard and a way for
// an unauthenticated peer to write into an operator's console.
//
// Alerting on "you are being brute forced" is worthless, because every public
// host is being brute forced. The one field here that is worth waking someone up
// for is SuspectSuccess: a source that failed and then got in.
const (
	defaultWindow        = 10 * time.Minute
	defaultSuspectWindow = time.Hour
	defaultMaxSources    = 1024
	defaultMaxTopSources = 10
	defaultMaxSuspects   = 16
	maxAddrLen           = 64
)

// SourcePressure is one address's share of a window.
type SourcePressure struct {
	Address     string
	Failures    int
	InvalidUser int
}

// SuspectSuccess is an accepted login from a source that had been failing. It is
// the highest-value signal the agent can produce from sshd's log, and the reason
// the aggregate is worth computing at all.
type SuspectSuccess struct {
	Address string
	User    string
	Method  string
	// PriorFailures is how many failures this source had accumulated since it
	// last went quiet for a whole suspect window.
	PriorFailures int
	// Successes counts repeats for the same address and user, so a reconnecting
	// session cannot push other suspects out of a capped list.
	Successes int
	At        time.Time
}

// PressureWindow is the whole report for one window: a fixed-size structure
// regardless of how many lines went into it.
//
// Failures counts every rejected record, which includes the publickey rejections
// a legitimate client produces while its agent offers keys it does not need.
// That noise is deliberate: the server compares a window against the node's own
// baseline, and a constant noise floor is part of the baseline. InvalidUser is
// the discriminator for "somebody is guessing account names", which no ordinary
// client produces.
type PressureWindow struct {
	Start time.Time
	End   time.Time

	Failures    int
	InvalidUser int
	// Sources is the exact number of distinct addresses that failed in this
	// window, counted even for sources the tracker later dropped.
	Sources int
	// SourcesDropped is how many tracked sources were evicted to stay inside
	// the memory cap. Non-zero means TopSources ranks the heaviest sources the
	// node was still holding, not every source that appeared.
	SourcesDropped int

	TopSources     []SourcePressure
	SuspectSuccess []SuspectSuccess
}

// Login is what Observe reports for an accepted-login line: the event the agent
// already posts on its own as ssh_login, plus the failure pressure the same
// source produced. Successes stay a separate report; this only annotates them,
// so a possible compromise does not have to wait for the window to close.
type Login struct {
	Event         LoginEvent
	PriorFailures int
}

// AggregatorOptions bounds both the window and the memory. Zero fields take the
// package defaults.
type AggregatorOptions struct {
	Window time.Duration
	// SuspectWindow is how long a source stays suspect after its last failure.
	// It is independent of Window on purpose: failures at 09:59 followed by a
	// success at 10:01 are exactly the case that must not be lost at a window
	// boundary.
	SuspectWindow time.Duration
	MaxSources    int
	MaxTopSources int
	MaxSuspects   int
}

func (o AggregatorOptions) withDefaults() AggregatorOptions {
	if o.Window <= 0 {
		o.Window = defaultWindow
	}
	if o.SuspectWindow <= 0 {
		o.SuspectWindow = defaultSuspectWindow
	}
	if o.MaxSources <= 0 {
		o.MaxSources = defaultMaxSources
	}
	if o.MaxTopSources <= 0 {
		o.MaxTopSources = defaultMaxTopSources
	}
	if o.MaxSuspects <= 0 {
		o.MaxSuspects = defaultMaxSuspects
	}
	return o
}

type sourceState struct {
	windowFailures int
	windowInvalid  int
	priorFailures  int
	last           time.Time
}

// Aggregator folds sshd log lines into one PressureWindow at a time. It holds no
// clock and no log source of its own: the caller supplies both, so the whole
// thing is testable without journald, files, or sleeping.
type Aggregator struct {
	opts AggregatorOptions

	mu       sync.Mutex
	start    time.Time
	failures int
	invalid  int
	sources  int
	dropped  int
	src      map[string]*sourceState
	suspects map[string]*SuspectSuccess
}

func NewAggregator(opts AggregatorOptions) *Aggregator {
	return &Aggregator{
		opts:     opts.withDefaults(),
		src:      make(map[string]*sourceState),
		suspects: make(map[string]*SuspectSuccess),
	}
}

// Observe folds one raw log line into the current window. It returns the
// accepted login when the line is one, so a caller already streaming lines can
// keep reporting successes on the existing path without parsing twice.
func (a *Aggregator) Observe(now time.Time, line string) (Login, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.start.IsZero() {
		a.start = now
	}
	if ev, ok := ParseFailure(line); ok {
		a.recordFailure(now, ev)
		return Login{}, false
	}
	ev, ok := Parse(line)
	if !ok {
		return Login{}, false
	}
	return a.recordLogin(now, ev), true
}

// Roll closes the window and returns its summary once Window has elapsed. ok is
// false while the window is still open and for a window that saw nothing worth
// sending, because thirty nodes reporting zero every ten minutes is how a signal
// gets ignored.
//
// Call it on a timer, not only when a line arrives: a node that goes quiet after
// being hammered is the case where the last window matters most, and it will not
// produce the line that would have closed it.
func (a *Aggregator) Roll(now time.Time) (PressureWindow, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.start.IsZero() {
		a.start = now
		return PressureWindow{}, false
	}
	if now.Before(a.start) {
		// A wall clock that steps backwards (an NTP correction after boot is
		// the usual one) would otherwise leave the window permanently unable to
		// close.
		a.start = now
		return PressureWindow{}, false
	}
	if now.Sub(a.start) < a.opts.Window {
		return PressureWindow{}, false
	}
	w := a.summarize(now)
	a.reset(now)
	return w, w.Failures > 0 || len(w.SuspectSuccess) > 0
}

func (a *Aggregator) recordFailure(now time.Time, ev FailureEvent) {
	a.failures++
	if ev.Invalid {
		a.invalid++
	}
	st := a.src[ev.Address]
	if st == nil {
		st = &sourceState{}
		a.src[ev.Address] = st
	}
	if now.Sub(st.last) > a.opts.SuspectWindow {
		st.priorFailures = 0
	}
	if st.windowFailures == 0 {
		a.sources++
	}
	st.windowFailures++
	if ev.Invalid {
		st.windowInvalid++
	}
	st.priorFailures++
	st.last = now
	if len(a.src) > a.opts.MaxSources {
		a.evictWeakest(ev.Address)
	}
}

func (a *Aggregator) recordLogin(now time.Time, ev LoginEvent) Login {
	addr := canonicalAddr(ev.Address)
	out := Login{Event: ev}
	st := a.src[addr]
	if st == nil || now.Sub(st.last) > a.opts.SuspectWindow || st.priorFailures == 0 {
		return out
	}
	out.PriorFailures = st.priorFailures
	user := clampLen(ev.User, maxUserLen)
	key := addr + "\x00" + user
	if s := a.suspects[key]; s != nil {
		s.PriorFailures = st.priorFailures
		s.Successes++
		s.At = now
		return out
	}
	if len(a.suspects) >= a.opts.MaxSuspects {
		return out
	}
	a.suspects[key] = &SuspectSuccess{
		Address:       addr,
		User:          user,
		Method:        clampLen(ev.Method, maxUserLen),
		PriorFailures: st.priorFailures,
		Successes:     1,
		At:            now,
	}
	return out
}

// evictWeakest drops the least interesting tracked source, never keep, so a
// distributed scan cannot lock a newly arrived heavy hitter out of the table.
// The totals are counted separately and stay exact; only the ranking loses an
// entry, and it loses the one that was contributing least to it.
func (a *Aggregator) evictWeakest(keep string) {
	var (
		victim string
		found  *sourceState
	)
	for addr, st := range a.src {
		if addr == keep {
			continue
		}
		if found == nil || weaker(st, addr, found, victim) {
			victim, found = addr, st
		}
	}
	if found == nil {
		return
	}
	delete(a.src, victim)
	a.dropped++
}

// weaker orders by failure count, then by age, then by address, so eviction is
// deterministic and a test can pin which entry goes.
func weaker(a *sourceState, addrA string, b *sourceState, addrB string) bool {
	if a.priorFailures != b.priorFailures {
		return a.priorFailures < b.priorFailures
	}
	if !a.last.Equal(b.last) {
		return a.last.Before(b.last)
	}
	return addrA < addrB
}

func canonicalAddr(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	// Parse does not validate its address field, so an unrecognised spelling is
	// kept as-is but bounded.
	return clampLen(s, maxAddrLen)
}

func (a *Aggregator) summarize(now time.Time) PressureWindow {
	w := PressureWindow{
		Start:          a.start,
		End:            now,
		Failures:       a.failures,
		InvalidUser:    a.invalid,
		Sources:        a.sources,
		SourcesDropped: a.dropped,
	}
	for addr, st := range a.src {
		if st.windowFailures == 0 {
			continue
		}
		w.TopSources = append(w.TopSources, SourcePressure{
			Address:     addr,
			Failures:    st.windowFailures,
			InvalidUser: st.windowInvalid,
		})
	}
	sort.Slice(w.TopSources, func(i, j int) bool {
		if w.TopSources[i].Failures != w.TopSources[j].Failures {
			return w.TopSources[i].Failures > w.TopSources[j].Failures
		}
		return w.TopSources[i].Address < w.TopSources[j].Address
	})
	if len(w.TopSources) > a.opts.MaxTopSources {
		w.TopSources = w.TopSources[:a.opts.MaxTopSources]
	}
	for _, s := range a.suspects {
		w.SuspectSuccess = append(w.SuspectSuccess, *s)
	}
	sort.Slice(w.SuspectSuccess, func(i, j int) bool {
		if w.SuspectSuccess[i].PriorFailures != w.SuspectSuccess[j].PriorFailures {
			return w.SuspectSuccess[i].PriorFailures > w.SuspectSuccess[j].PriorFailures
		}
		if w.SuspectSuccess[i].Address != w.SuspectSuccess[j].Address {
			return w.SuspectSuccess[i].Address < w.SuspectSuccess[j].Address
		}
		return w.SuspectSuccess[i].User < w.SuspectSuccess[j].User
	})
	return w
}

// reset opens the next window. Per-source counters go to zero but the sources
// themselves survive as long as they are still suspect, which is what lets a
// success in this window be tied to failures from the last one.
func (a *Aggregator) reset(now time.Time) {
	a.start = now
	a.failures, a.invalid, a.sources, a.dropped = 0, 0, 0, 0
	for addr, st := range a.src {
		if now.Sub(st.last) > a.opts.SuspectWindow {
			delete(a.src, addr)
			continue
		}
		st.windowFailures, st.windowInvalid = 0, 0
	}
	a.suspects = make(map[string]*SuspectSuccess)
}
