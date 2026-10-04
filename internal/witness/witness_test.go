package witness

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// scenario drives a witness with a fake clock, fake checks and a recording
// pusher, and persists its state the way the real one does, so a "restart"
// is a new witness built from the saved state. The clock has two readings,
// as the real one does: now is the wall clock and mono the monotonic one, so
// a test can step the wall clock alone.
type scenario struct {
	t      *testing.T
	cfg    Config
	sha    string
	now    time.Time
	mono   time.Duration
	next   CheckResult
	pushes []Push
	// pushFail, when set, is the failure kind every push returns.
	pushFail string
	// onHealth and onPush, when set, run inside the probe and the push, so a
	// test can stop the witness in the middle of either.
	onHealth func()
	onPush   func()
	saved    State
	saves    int
	w        *Witness
}

type fakeProber struct{ s *scenario }

func (f fakeProber) Health(ctx context.Context, _ string) (bool, string) {
	if f.s.onHealth != nil {
		f.s.onHealth()
		if ctx.Err() != nil {
			return false, "timeout"
		}
	}
	return f.s.next.OK, f.s.next.Detail
}

func (f fakeProber) Reachable(ctx context.Context, _ []string) bool {
	if ctx.Err() != nil {
		return false
	}
	return f.s.next.NetworkUp
}

type fakePusher struct{ s *scenario }

func (f fakePusher) Push(ctx context.Context, _ Config, p Push) string {
	if f.s.onPush != nil {
		f.s.onPush()
		if ctx.Err() != nil {
			return "timeout"
		}
	}
	if f.s.pushFail != "" {
		return f.s.pushFail
	}
	f.s.pushes = append(f.s.pushes, p)
	return ""
}

func testConfig() Config {
	return Config{
		Version:           ConfigVersion,
		NodeName:          "[cd]-gomami-jpn-pulse-nano",
		HealthURL:         "https://lattice.example.org/readyz",
		ReferenceURLs:     []string{"https://www.cloudflare.com/cdn-cgi/trace", "https://www.google.com/generate_204"},
		BarkURL:           "http://127.0.0.1:8080",
		BarkDeviceKeyFile: "/etc/lattice-witness/bark-device-key",
		IntervalSeconds:   30,
		HoldSeconds:       180,
		RecoverSeconds:    60,
	}
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	s := &scenario{t: t, cfg: testConfig(), sha: "sha-a", now: time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)}
	s.start()
	return s
}

// start builds a witness from whatever state was last saved: the first call
// starts fresh, a later one is a restart.
func (s *scenario) start() {
	s.w = New(s.cfg, s.sha, s.saved, fakeProber{s}, fakePusher{s}, func() time.Time { return s.now }, func(st State) error {
		s.saved = st
		s.saves++
		return nil
	})
	s.w.mono = func() time.Duration { return s.mono }
	s.w.logf = func(string, ...any) {}
}

// run performs n checks of the given result, one interval apart on both
// clocks, starting one interval after the previous check.
func (s *scenario) run(n int, res CheckResult) {
	for range n {
		s.now = s.now.Add(s.cfg.Interval())
		s.mono += s.cfg.Interval()
		s.next = res
		s.w.Tick(context.Background())
	}
}

var (
	cpDown      = CheckResult{Detail: "http 502", NetworkUp: true}
	cpUp        = CheckResult{OK: true}
	networkDown = CheckResult{Detail: "timeout", NetworkUp: false}
)

func (s *scenario) wantPushes(kinds ...string) {
	s.t.Helper()
	if len(s.pushes) != len(kinds) {
		s.t.Fatalf("pushes = %d (%v), want %v", len(s.pushes), pushKinds(s.pushes), kinds)
	}
	for i, k := range kinds {
		if s.pushes[i].Kind != k {
			s.t.Fatalf("push %d = %s, want %s (all: %v)", i, s.pushes[i].Kind, k, pushKinds(s.pushes))
		}
	}
}

func pushKinds(ps []Push) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Kind
	}
	return out
}

func TestPushesOnceAfterTheHoldAndNeverAgainWhileDown(t *testing.T) {
	s := newScenario(t)
	s.run(5, cpUp)
	// Six failures cover 150 s of the 180 s hold: nothing yet.
	s.run(6, cpDown)
	s.wantPushes()
	if got := s.saved.Phase; got != PhaseFailing {
		t.Fatalf("phase = %s, want failing", got)
	}
	// The seventh failure is 180 s after the first.
	s.run(1, cpDown)
	s.wantPushes(PushDown)
	p := s.pushes[0]
	if p.Level != "critical" || p.Title != "Lattice control plane not ready" {
		t.Fatalf("down push = %+v", p)
	}
	for _, want := range []string{"[cd]-gomami-jpn-pulse-nano", "lattice.example.org", "answered without reporting ready for about 3 min", "http 502", "7 checks", "own network is up", "first failed check 2026-10-03 03:03:00 UTC by this node's clock"} {
		if !strings.Contains(p.Body, want) {
			t.Fatalf("down body %q lacks %q", p.Body, want)
		}
	}
	// The duration leads; the node's clock comes second, labelled as such.
	if strings.Index(p.Body, "3 min") > strings.Index(p.Body, "03:03:00") {
		t.Fatalf("down body %q puts the node's clock before the duration", p.Body)
	}
	// An hour more of failures sends nothing more.
	s.run(120, cpDown)
	s.wantPushes(PushDown)
	if !s.saved.Alerted || s.saved.Phase != PhaseDown || s.saved.Pushes != 1 {
		t.Fatalf("state after down = %+v", s.saved)
	}
}

func TestPushesOneRecoveryOnceTheControlPlaneKeepsAnswering(t *testing.T) {
	s := newScenario(t)
	s.run(10, cpDown)
	s.wantPushes(PushDown)
	// One answer is not a recovery.
	s.run(1, cpUp)
	s.wantPushes(PushDown)
	if s.saved.Phase != PhaseDown {
		t.Fatalf("phase after one answer = %s, want down", s.saved.Phase)
	}
	// Answers spanning the 60 s recover window are.
	s.run(2, cpUp)
	s.wantPushes(PushDown, PushRecovery)
	r := s.pushes[1]
	if r.Level != "active" || r.Title != "Lattice control plane ready again" || !strings.Contains(r.Body, "reports ready again after about 5 min down") || !strings.Contains(r.Body, "answering for 1 min") {
		t.Fatalf("recovery push = %+v", r)
	}
	s.run(100, cpUp)
	s.wantPushes(PushDown, PushRecovery)
	if s.saved.Alerted || s.saved.Phase != PhaseWatching {
		t.Fatalf("state after recovery = %+v", s.saved)
	}
}

func TestOwnNetworkDownPushesNothing(t *testing.T) {
	s := newScenario(t)
	s.run(3, cpUp)
	// Two hours in which neither the control plane nor any reference answers.
	s.run(240, networkDown)
	s.wantPushes()
	if s.saved.Phase != PhaseNetworkDown || s.saved.NetworkDownSince.IsZero() || s.saved.ConsecutiveFailures != 0 {
		t.Fatalf("state = %+v", s.saved)
	}
	// The network comes back and so does the control plane: still nothing.
	s.run(3, cpUp)
	s.wantPushes()
}

func TestOwnNetworkDownNeitherCountsNorEndsTheRun(t *testing.T) {
	s := newScenario(t)
	s.run(3, cpDown) // 60 s of the hold
	s.run(10, networkDown)
	s.wantPushes()
	if s.saved.ConsecutiveFailures != 3 {
		t.Fatalf("network-down checks counted: %d failures", s.saved.ConsecutiveFailures)
	}
	// Back on the network and the control plane still does not answer. The
	// run began before the network dropped, so the hold is long past, but
	// the first check back only confirms: the network may still be settling.
	s.run(1, cpDown)
	s.wantPushes()
	if s.saved.Phase != PhaseFailing || s.saved.ConsecutiveFailures != 4 {
		t.Fatalf("first check back = %+v", s.saved)
	}
	// The next one, still failing with the network up, pushes.
	s.run(1, cpDown)
	s.wantPushes(PushDown)
	if !strings.Contains(s.pushes[0].Body, "5 checks") {
		t.Fatalf("down body %q", s.pushes[0].Body)
	}
}

// A node whose own network keeps dropping does not keep a real outage from
// being reported: the network-down checks pause the run, they do not end it.
func TestFlakyOwnNetworkStillReachesTheHold(t *testing.T) {
	s := newScenario(t)
	// Failures at 30 and 60 s, a drop, failures at 120 and 150 s, a drop.
	for range 2 {
		s.run(2, cpDown)
		s.run(1, networkDown)
	}
	s.wantPushes()
	// 210 s: past the hold, but the first check back only confirms.
	s.run(1, cpDown)
	s.wantPushes()
	// 240 s: pushes.
	s.run(1, cpDown)
	s.wantPushes(PushDown)
}

// A control plane that does not answer at all is unreachable; one that
// answers with anything but 200 is not ready, and the push says which.
func TestDownPushNamesUnreachableOrNotReady(t *testing.T) {
	for _, tc := range []struct {
		detail, title, body string
	}{
		{"connection refused", "Lattice control plane unreachable", "has not answered for about 3 min"},
		{"timeout", "Lattice control plane unreachable", "has not answered for about 3 min"},
		{"http 503", "Lattice control plane not ready", "has answered without reporting ready for about 3 min"},
		{"http 302", "Lattice control plane not ready", "has answered without reporting ready for about 3 min"},
	} {
		s := newScenario(t)
		s.run(8, CheckResult{Detail: tc.detail, NetworkUp: true})
		s.wantPushes(PushDown)
		p := s.pushes[0]
		if p.Title != tc.title || !strings.Contains(p.Body, tc.body) || !strings.Contains(p.Body, "last: "+tc.detail) {
			t.Errorf("%s: push = %+v", tc.detail, p)
		}
	}
}

func TestNetworkDownWhileAlertedHoldsTheAlertWithoutPushing(t *testing.T) {
	s := newScenario(t)
	s.run(8, cpDown)
	s.wantPushes(PushDown)
	s.run(30, networkDown)
	s.wantPushes(PushDown)
	if !s.saved.Alerted {
		t.Fatal("alert cleared while nothing could be reached")
	}
	// An answer, then the network drops again: the answers must be unbroken.
	s.run(2, cpUp)
	s.run(1, networkDown)
	s.run(2, cpUp)
	s.wantPushes(PushDown)
	s.run(1, cpUp)
	s.wantPushes(PushDown, PushRecovery)
}

func TestFlappingBeforeTheHoldPushesNothing(t *testing.T) {
	s := newScenario(t)
	for range 60 {
		s.run(3, cpDown)
		s.run(1, cpUp)
	}
	s.wantPushes()
}

func TestFlappingAfterTheAlertSendsNoMoreUntilStable(t *testing.T) {
	s := newScenario(t)
	s.run(7, cpDown)
	s.wantPushes(PushDown)
	for range 60 {
		s.run(1, cpUp)
		s.run(1, cpDown)
	}
	s.wantPushes(PushDown)
	s.run(3, cpUp)
	s.wantPushes(PushDown, PushRecovery)
}

func TestRestartAfterTheAlertDoesNotPushTwiceAndStillRecovers(t *testing.T) {
	s := newScenario(t)
	s.run(7, cpDown)
	s.wantPushes(PushDown)
	s.start() // restart in the middle of the outage
	if s.w.State().Phase != PhaseDown {
		t.Fatalf("phase after restart = %s, want down", s.w.State().Phase)
	}
	s.run(20, cpDown)
	s.wantPushes(PushDown)
	s.start()
	s.run(3, cpUp)
	s.wantPushes(PushDown, PushRecovery)
}

func TestRestartInsideTheHoldKeepsCountingFromTheFirstFailure(t *testing.T) {
	s := newScenario(t)
	s.run(4, cpDown) // 90 s
	s.start()
	s.run(2, cpDown) // 150 s
	s.wantPushes()
	s.run(1, cpDown) // 180 s
	s.wantPushes(PushDown)
}

func TestRestartAfterALongGapStartsCountingAgain(t *testing.T) {
	s := newScenario(t)
	s.run(5, cpDown) // 120 s
	// The witness itself was away for an hour.
	s.now = s.now.Add(time.Hour)
	s.start()
	s.run(6, cpDown) // 150 s of a new run
	s.wantPushes()
	s.run(1, cpDown)
	s.wantPushes(PushDown)
}

func TestRestartAfterALongGapWhileAlertedStillPushesTheRecovery(t *testing.T) {
	s := newScenario(t)
	s.run(7, cpDown)
	s.wantPushes(PushDown)
	s.now = s.now.Add(6 * time.Hour)
	s.start()
	s.run(3, cpUp)
	s.wantPushes(PushDown, PushRecovery)
}

// chrony stepping a slow clock forward mid-run must not turn a short failure
// into a page: the hold is measured on the monotonic clock.
func TestForwardWallClockStepDoesNotPageEarly(t *testing.T) {
	stepped := func() *scenario {
		s := newScenario(t)
		s.run(3, cpUp)
		s.run(1, cpDown)
		// The wall clock jumps 130 s ahead between two checks.
		s.now = s.now.Add(130 * time.Second)
		s.run(2, cpDown) // 60 s of failures, 190 s by the wall clock
		s.wantPushes()
		if s.saved.FailingFor != time.Minute || s.saved.ConsecutiveFailures != 3 {
			t.Fatalf("run after the step = %s over %d checks, want 1m0s over 3", s.saved.FailingFor, s.saved.ConsecutiveFailures)
		}
		return s
	}
	// A blip that ends here sends nothing at all.
	blip := stepped()
	blip.run(3, cpUp)
	blip.wantPushes()
	// One that keeps failing pages after a full hold, not before.
	s := stepped()
	s.run(3, cpDown) // 150 s
	s.wantPushes()
	s.run(1, cpDown) // 180 s
	s.wantPushes(PushDown)
	if !strings.Contains(s.pushes[0].Body, "for about 3 min (7 checks") {
		t.Fatalf("down body %q", s.pushes[0].Body)
	}
}

// A wall clock stepped back mid-run (a fast clock corrected) must not hold
// the page back by the size of the step.
func TestBackwardWallClockStepDoesNotDelayThePage(t *testing.T) {
	s := newScenario(t)
	s.run(2, cpDown) // 30 s
	s.now = s.now.Add(-time.Hour)
	s.run(4, cpDown) // 150 s
	s.wantPushes()
	s.run(1, cpDown) // 180 s
	s.wantPushes(PushDown)
}

// Across a restart only the saved wall time is left. A clock now behind the
// saved last check (a wrong RTC at boot, a VM resumed from an old snapshot)
// starts the count again, and the page comes one full hold later.
func TestBackwardWallClockAcrossARestartStartsCountingAgain(t *testing.T) {
	s := newScenario(t)
	s.run(5, cpDown) // 120 s
	s.now = s.now.Add(-10 * time.Minute)
	s.start()
	s.run(1, cpDown)
	if s.saved.ConsecutiveFailures != 1 || s.saved.FailingFor != 0 {
		t.Fatalf("first check after the restart = %d checks over %s, want a new run", s.saved.ConsecutiveFailures, s.saved.FailingFor)
	}
	s.run(5, cpDown) // 150 s of the new run
	s.wantPushes()
	s.run(1, cpDown) // 180 s
	s.wantPushes(PushDown)
}

// The monotonic clock stops while the machine is suspended. A wall clock that
// moved on by more than the gap while it stood still starts the count again,
// as a stopped witness does.
func TestSuspendLongerThanTheGapStartsCountingAgain(t *testing.T) {
	s := newScenario(t)
	s.run(5, cpDown) // 120 s
	s.now = s.now.Add(time.Hour)
	s.run(1, cpDown)
	if s.saved.ConsecutiveFailures != 1 {
		t.Fatalf("first check after the suspend = %d checks, want a new run", s.saved.ConsecutiveFailures)
	}
	s.run(5, cpDown)
	s.wantPushes()
	s.run(1, cpDown)
	s.wantPushes(PushDown)
}

func TestFailedPushIsRetriedAndDeliveredOnce(t *testing.T) {
	s := newScenario(t)
	s.pushFail = "connection refused"
	s.run(10, cpDown)
	s.wantPushes()
	if s.saved.Alerted || s.saved.LastPushOK || s.saved.LastPushError != "connection refused" || s.saved.LastPushKind != PushDown {
		t.Fatalf("state after failed pushes = %+v", s.saved)
	}
	s.pushFail = ""
	s.run(1, cpDown)
	s.wantPushes(PushDown)
	s.run(10, cpDown)
	s.wantPushes(PushDown)
}

func TestRecoveryBeforeAnUndeliveredAlertSendsNothing(t *testing.T) {
	s := newScenario(t)
	s.pushFail = "http 500"
	s.run(10, cpDown)
	s.pushFail = ""
	s.run(5, cpUp)
	s.wantPushes()
	if s.saved.Alerted {
		t.Fatal("an alert that was never delivered was recorded")
	}
}

// SIGTERM in the middle of a check cancels the probes, which then fail. That
// failure says nothing about the control plane or this node's network and
// must not be recorded.
func TestStopDuringACheckRecordsNothing(t *testing.T) {
	s := newScenario(t)
	s.run(3, cpUp)
	before, saves := s.saved, s.saves
	ctx, cancel := context.WithCancel(context.Background())
	s.onHealth = cancel
	s.now = s.now.Add(s.cfg.Interval())
	s.mono += s.cfg.Interval()
	s.next = cpUp
	s.w.Tick(ctx)
	if s.saves != saves {
		t.Fatal("a cancelled check was saved")
	}
	if st := s.w.State(); st.Phase != PhaseWatching || !st.LastCheckAt.Equal(before.LastCheckAt) || !st.NetworkDownSince.IsZero() {
		t.Fatalf("state after a cancelled check = %+v", st)
	}
	// Run stops the same way and saves what it had.
	s.w.Run(ctx)
	if s.saved.Phase != PhaseWatching || !s.saved.LastCheckAt.Equal(before.LastCheckAt) {
		t.Fatalf("saved after Run stopped = %+v", s.saved)
	}
}

// SIGTERM in the middle of a push cancels it. Whether it arrived is unknown,
// so it is not stored as a refused push, and it is owed again after the
// restart.
func TestStopDuringAPushDoesNotRecordItAsFailed(t *testing.T) {
	s := newScenario(t)
	s.run(6, cpDown) // 150 s
	ctx, cancel := context.WithCancel(context.Background())
	s.onPush = cancel
	s.now = s.now.Add(s.cfg.Interval())
	s.mono += s.cfg.Interval()
	s.next = cpDown
	s.w.Run(ctx)
	s.wantPushes()
	if s.saved.LastPushKind != "" || s.saved.LastPushError != "" || !s.saved.LastPushAt.IsZero() || s.saved.Alerted {
		t.Fatalf("a cancelled push was recorded: %+v", s.saved)
	}
	if s.saved.ConsecutiveFailures != 7 {
		t.Fatalf("the check before the push was lost: %+v", s.saved)
	}
	s.onPush = nil
	s.start()
	s.run(1, cpDown)
	s.wantPushes(PushDown)
	s.run(5, cpDown)
	s.wantPushes(PushDown)
}

func TestConfigChangeKeepsTheAlertAndRestartsTheRuns(t *testing.T) {
	s := newScenario(t)
	s.run(7, cpDown)
	s.wantPushes(PushDown)
	s.sha = "sha-b"
	s.cfg.HoldSeconds = 300
	s.start()
	st := s.w.State()
	if !st.Alerted || st.ConsecutiveFailures != 0 || st.ConfigSHA256 != "sha-b" || st.HoldSeconds != 300 {
		t.Fatalf("state after config change = %+v", st)
	}
	s.run(3, cpUp)
	s.wantPushes(PushDown, PushRecovery)
}

func TestConfigValidation(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	cases := map[string]func(*Config){
		"bark off loopback":       func(c *Config) { c.BarkURL = "https://bark.example.org" },
		"bark with a query":       func(c *Config) { c.BarkURL = "http://127.0.0.1:8080/?k=1" },
		"plain http health":       func(c *Config) { c.HealthURL = "http://lattice.example.org/readyz" },
		"health with credentials": func(c *Config) { c.HealthURL = "https://u:p@lattice.example.org/readyz" },
		"reference on cp host":    func(c *Config) { c.ReferenceURLs = []string{"https://lattice.example.org/"} },
		"no reference":            func(c *Config) { c.ReferenceURLs = nil },
		"four references": func(c *Config) {
			c.ReferenceURLs = []string{"https://a.example/", "https://b.example/", "https://c.example/", "https://d.example/"}
		},
		"relative key path":  func(c *Config) { c.BarkDeviceKeyFile = "bark.key" },
		"bad level":          func(c *Config) { c.BarkLevel = "loud" },
		"hold under two":     func(c *Config) { c.HoldSeconds = 45 },
		"interval too short": func(c *Config) { c.IntervalSeconds = 5 },
		"recover too short":  func(c *Config) { c.RecoverSeconds = 10 },
		"version":            func(c *Config) { c.Version = 2 },
		"no node name":       func(c *Config) { c.NodeName = " " },
		"relative state":     func(c *Config) { c.StateFile = "status.json" },
	}
	for name, mutate := range cases {
		c := testConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := testConfig()
	c.BarkURL = "http://[::1]:8080"
	c.HealthURL = "http://127.0.0.1:8088/readyz"
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback http refused: %v", err)
	}
}

func TestLoadConfigRefusesUnknownFieldsAndHashesTheBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "witness.json")
	data, _ := json.Marshal(testConfig())
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, sha, err := LoadConfig(path)
	if err != nil || len(sha) != 64 {
		t.Fatalf("LoadConfig = %q, %v", sha, err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"version":1`, `"version":1,"bark_key":"x"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestReadDeviceKeyRefusesAReadableOrMalformedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("AbCdEf0123456789xyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ReadDeviceKey(path)
	if err != nil || key != "AbCdEf0123456789xyz" {
		t.Fatalf("ReadDeviceKey = %q, %v", key, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeviceKey(path); err == nil || !strings.Contains(err.Error(), "0640") {
		t.Fatalf("group-readable key accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte("key with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeviceKey(path); err == nil || strings.Contains(err.Error(), "spaces") {
		t.Fatalf("malformed key: err = %v (must be refused without echoing it)", err)
	}
}

func TestStateFileRoundTripsAtomicallyAndWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "status.json")
	st := State{Version: StateVersion, ConfigSHA256: "abc", Phase: PhaseDown, Alerted: true, AlertedAt: time.Unix(1700000000, 0).UTC()}
	if err := SaveState(path, st); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("status file mode = %v, %v", info.Mode(), err)
	}
	got, err := LoadState(path)
	if err != nil || !got.Alerted || got.ConfigSHA256 != "abc" || !got.AlertedAt.Equal(st.AlertedAt) {
		t.Fatalf("LoadState = %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	missing, err := LoadState(filepath.Join(dir, "none.json"))
	if err != nil || missing.Version != 0 {
		t.Fatalf("missing state = %+v, %v", missing, err)
	}
}

func TestHTTPProberJudgesOnlyA200AsAnswering(t *testing.T) {
	var status int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if status == http.StatusFound {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	p := NewHTTPProber()
	for _, tc := range []struct {
		status int
		ok     bool
		detail string
	}{{200, true, ""}, {503, false, "http 503"}, {302, false, "http 302"}} {
		mu.Lock()
		status = tc.status
		mu.Unlock()
		ok, detail := p.Health(context.Background(), srv.URL+"/readyz")
		if ok != tc.ok || detail != tc.detail {
			t.Errorf("status %d: Health = %v %q, want %v %q", tc.status, ok, detail, tc.ok, tc.detail)
		}
	}
	closed := closedURL(t)
	if ok, detail := p.Health(context.Background(), closed); ok || detail != "connection refused" {
		t.Errorf("closed port: Health = %v %q", ok, detail)
	}
	mu.Lock()
	status = 500
	mu.Unlock()
	if !p.Reachable(context.Background(), []string{closed, srv.URL}) {
		t.Error("a reference that answered 500 did not count as reachable")
	}
	if p.Reachable(context.Background(), []string{closed}) {
		t.Error("a closed port counted as reachable")
	}
}

func closedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr + "/"
}

func TestBarkPusherPostsTheKeyFromItsFileToTheLocalServer(t *testing.T) {
	var got map[string]string
	var path string
	answer := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(answer)
	}))
	defer srv.Close()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("DeviceKey12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.BarkURL = srv.URL
	cfg.BarkDeviceKeyFile = keyFile
	b := NewBarkPusher()
	if kind := b.Push(context.Background(), cfg, Push{Kind: PushDown, Title: "t", Body: "b", Level: "critical"}); kind != "" {
		t.Fatalf("push failed: %s", kind)
	}
	if path != "POST /push" || got["device_key"] != "DeviceKey12345678" || got["level"] != "critical" || got["group"] != DefaultBarkGroup || got["title"] != "t" {
		t.Fatalf("bark request = %s %v", path, got)
	}
	answer = http.StatusBadRequest
	if kind := b.Push(context.Background(), cfg, Push{Kind: PushDown}); kind != "http 400" {
		t.Fatalf("refused push = %q", kind)
	}
	cfg.BarkDeviceKeyFile = filepath.Join(dir, "missing")
	if kind := b.Push(context.Background(), cfg, Push{Kind: PushDown}); kind != "key file" {
		t.Fatalf("missing key push = %q", kind)
	}
}

func TestStartRefusesAnUnsafeKeyFileBeforeWatching(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("DeviceKey12345678"), 0o644); err != nil { // #nosec G306 -- the test needs a readable key file to see it refused
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.BarkDeviceKeyFile = keyFile
	cfg.StateFile = filepath.Join(dir, "status.json")
	data, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "witness.json")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(cfgPath); err == nil {
		t.Fatal("a world-readable key file was accepted")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Start(cfgPath)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := w.State(); st.Phase != PhaseStarting || st.HealthURL != cfg.HealthURL || st.ReferenceCount != 2 {
		t.Fatalf("fresh state = %+v", st)
	}
}
