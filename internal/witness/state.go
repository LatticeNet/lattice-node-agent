package witness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StateVersion is the version of the state document.
const StateVersion = 1

// Phases, as the status file and the console name them.
const (
	PhaseStarting    = "starting"     // no check yet
	PhaseWatching    = "watching"     // the control plane answered the last check
	PhaseFailing     = "failing"      // failing, inside the hold window, nothing pushed
	PhaseDown        = "down"         // the unreachable push went out; no recovery yet
	PhaseNetworkDown = "network_down" // the last check could not reach anything
)

// Push kinds.
const (
	PushDown     = "down"
	PushRecovery = "recovery"
)

// State is the witness's whole memory. It is written after every check, so
// a witness restarted in the middle of an outage neither pushes twice nor
// forgets to push the recovery. It holds no secret: the main agent reads it
// and sends it to the control plane as the witness status.
type State struct {
	Version      int       `json:"version"`
	ConfigSHA256 string    `json:"config_sha256"`
	StartedAt    time.Time `json:"started_at"`
	Phase        string    `json:"phase"`

	// What is watched, copied from the config so the status names it.
	HealthURL       string `json:"health_url"`
	ReferenceCount  int    `json:"reference_count"`
	IntervalSeconds int    `json:"interval_seconds"`
	HoldSeconds     int    `json:"hold_seconds"`

	LastCheckAt     time.Time `json:"last_check_at,omitzero"`
	LastCheckOK     bool      `json:"last_check_ok"`
	LastCheckDetail string    `json:"last_check_detail,omitempty"`
	LastOKAt        time.Time `json:"last_ok_at,omitzero"`

	// The current run of failed checks with this node's network up.
	// FailingSince is when it began by this node's wall clock, for display;
	// FailingFor is how long it has lasted, summed from the time between
	// checks, and is what the hold is measured on (see sinceLastCheck).
	FailingSince        time.Time     `json:"failing_since,omitzero"`
	FailingFor          time.Duration `json:"failing_for_ns,omitempty"`
	ConsecutiveFailures int           `json:"consecutive_failures,omitempty"`
	// The current run of answered checks, kept the same way.
	OKSince       time.Time     `json:"ok_since,omitzero"`
	OKFor         time.Duration `json:"ok_for_ns,omitempty"`
	ConsecutiveOK int           `json:"consecutive_ok,omitempty"`
	// Set while checks reach neither the control plane nor any reference.
	NetworkDownSince time.Time `json:"network_down_since,omitzero"`

	// Alerted is set once the unreachable push was delivered and cleared once
	// the recovery push was. It survives restarts and config changes.
	Alerted   bool      `json:"alerted"`
	AlertedAt time.Time `json:"alerted_at,omitzero"`
	DownSince time.Time `json:"down_since,omitzero"`
	// OutageFor is how long the announced outage has lasted, from the run's
	// first failure, for the recovery push.
	OutageFor time.Duration `json:"outage_for_ns,omitempty"`

	LastPushAt    time.Time `json:"last_push_at,omitzero"`
	LastPushKind  string    `json:"last_push_kind,omitempty"`
	LastPushOK    bool      `json:"last_push_ok"`
	LastPushError string    `json:"last_push_error,omitempty"`
	Pushes        int       `json:"pushes,omitempty"`
}

// CheckResult is one check: did the control plane answer, and, when it did
// not, did anything else.
type CheckResult struct {
	OK bool
	// Detail is a classified reason ("http 503", "timeout", "dns", ...),
	// never raw error text.
	Detail string
	// NetworkUp is meaningful only when OK is false: whether any reference
	// answered.
	NetworkUp bool
}

// Push is a message the witness owes.
type Push struct {
	Kind  string
	Title string
	Body  string
	Level string
}

// sinceLastCheck is the time since the previous check and whether that gap
// breaks the runs, as the witness takes it from two clocks. Inside one
// process it uses mono, the time on the monotonic clock, which a step of the
// wall clock (NTP correcting a drifted clock, a wrong RTC fixed after boot)
// does not move: such a step neither pushes early nor holds a push back. The
// wall clock still breaks the runs when it moved ahead by more than maxGap:
// the monotonic clock stops while the machine is suspended, and restarting
// the count can only delay a push, never send one early. The first check
// after a start has only the saved wall time to go by, so a gap that is
// negative (the clock is now behind the saved check) or longer than maxGap
// breaks the runs too.
func sinceLastCheck(prev, now time.Time, mono time.Duration, inProcess bool, maxGap time.Duration) (time.Duration, bool) {
	if prev.IsZero() {
		return 0, false
	}
	wall := now.Sub(prev)
	if inProcess {
		return mono, mono > maxGap || wall > maxGap
	}
	return wall, wall < 0 || wall > maxGap
}

// observe folds one check into the state and returns the push it now owes,
// if any. now is the wall time, recorded for display; step is the time since
// the previous check and gap whether that time breaks the runs, both from
// sinceLastCheck. It is pure: the caller sends the push and reports the
// outcome with pushed.
func (s *State) observe(cfg Config, now time.Time, step time.Duration, gap bool, res CheckResult) *Push {
	s.LastCheckAt = now
	s.LastCheckOK = res.OK
	s.LastCheckDetail = res.Detail
	if gap {
		// The witness itself was away (stopped, the machine asleep or
		// rebooting) for longer than a run may pause, or the clock it has to
		// go by went backwards: whatever it counted before says nothing
		// about now.
		s.FailingSince, s.FailingFor, s.ConsecutiveFailures = time.Time{}, 0, 0
		s.OKSince, s.OKFor, s.ConsecutiveOK = time.Time{}, 0, 0
	} else {
		// The time since the last check belongs to the run still going on.
		if s.ConsecutiveFailures > 0 {
			s.FailingFor += step
		}
		if s.ConsecutiveOK > 0 {
			s.OKFor += step
		}
	}
	if s.Alerted && step > 0 {
		s.OutageFor += step
	}

	if res.OK {
		s.LastOKAt = now
		s.NetworkDownSince = time.Time{}
		s.FailingSince, s.FailingFor, s.ConsecutiveFailures = time.Time{}, 0, 0
		if s.ConsecutiveOK == 0 {
			s.OKSince, s.OKFor = now, 0
		}
		s.ConsecutiveOK++
		s.Phase = PhaseWatching
		if s.Alerted {
			s.Phase = PhaseDown
			if s.ConsecutiveOK >= 2 && s.OKFor >= cfg.Recover() {
				return recoveryPush(cfg, s)
			}
		}
		return nil
	}

	// A failed check ends any run of answers: a recovery has to be seen
	// answering without a break.
	s.OKSince, s.OKFor, s.ConsecutiveOK = time.Time{}, 0, 0
	if !res.NetworkUp {
		// Nothing answers, so this check says nothing about the control
		// plane: it is not counted as a failure and does not end the run.
		// The hold keeps running from the run's first failure, so a run that
		// began before the network dropped can be past its hold when the
		// network comes back.
		if s.NetworkDownSince.IsZero() {
			s.NetworkDownSince = now
		}
		s.Phase = PhaseNetworkDown
		return nil
	}
	// The first failed check after this node's own network came back does
	// not push on its own, however old the run: routes and DNS may still be
	// settling while a reference already answers. The next failed check, one
	// interval later, does. Restarting the whole run was rejected: on a node
	// whose network drops now and then it would keep a real outage from ever
	// reaching the hold.
	backFromNetworkDown := !s.NetworkDownSince.IsZero()
	s.NetworkDownSince = time.Time{}
	if s.ConsecutiveFailures == 0 {
		s.FailingSince, s.FailingFor = now, 0
	}
	s.ConsecutiveFailures++
	if s.Alerted {
		s.Phase = PhaseDown
		return nil
	}
	s.Phase = PhaseFailing
	if s.ConsecutiveFailures >= 2 && s.FailingFor >= cfg.Hold() && !backFromNetworkDown {
		return downPush(cfg, s)
	}
	return nil
}

// pushed records the outcome of a push observe asked for. Only a delivered
// push moves the alert: a failed one is owed again on the next check.
func (s *State) pushed(p *Push, now time.Time, errKind string) {
	s.LastPushAt = now
	s.LastPushKind = p.Kind
	s.LastPushOK = errKind == ""
	s.LastPushError = errKind
	if errKind != "" {
		return
	}
	s.Pushes++
	switch p.Kind {
	case PushDown:
		s.Alerted = true
		s.AlertedAt = now
		s.DownSince = s.FailingSince
		s.OutageFor = s.FailingFor
		s.Phase = PhaseDown
	case PushRecovery:
		s.Alerted = false
		s.AlertedAt = time.Time{}
		s.DownSince = time.Time{}
		s.OutageFor = 0
		s.Phase = PhaseWatching
	}
}

// downPush and recoveryPush lead with how long the outage has lasted, which
// is measured the same way the hold is. The node's clock may be off, so when
// a run began by that clock comes second and is labelled as such.
func downPush(cfg Config, s *State) *Push {
	host := hostOf(cfg.HealthURL)
	title, failed := "Lattice control plane unreachable", "has not answered"
	if strings.HasPrefix(s.LastCheckDetail, "http ") {
		// Something on the public path answers, just not with 200: the
		// server says it is not ready (its store or audit check failed), or a
		// proxy or CDN in front of it answers in its place. "Unreachable"
		// would send the operator after the network.
		title, failed = "Lattice control plane not ready", "has answered without reporting ready"
	}
	body := fmt.Sprintf("Seen from %s: %s %s for about %s (%d checks; last: %s; first failed check %s by this node's clock). This node's own network is up. Sent by the Lattice witness on %s through its local Bark server, because Lattice itself cannot send anything now.",
		cfg.NodeName, host, failed, roughDuration(s.FailingFor), s.ConsecutiveFailures, orUnknown(s.LastCheckDetail), clock(s.FailingSince), cfg.NodeName)
	return &Push{Kind: PushDown, Title: title, Body: body, Level: cfg.Level()}
}

func recoveryPush(cfg Config, s *State) *Push {
	host := hostOf(cfg.HealthURL)
	// OutageFor runs from the first failure to now and OKFor from the first
	// answer of this run to now, so the outage is the difference.
	outage := max(s.OutageFor-s.OKFor, 0)
	// A recovery is a run of 200s from /readyz, so "ready again" is true
	// after either kind of outage.
	body := fmt.Sprintf("Seen from %s: %s reports ready again after about %s down (answering for %s, since %s by this node's clock). Sent by the Lattice witness on %s.",
		cfg.NodeName, host, roughDuration(outage), roughDuration(s.OKFor), clock(s.OKSince), cfg.NodeName)
	return &Push{Kind: PushRecovery, Title: "Lattice control plane ready again", Body: body, Level: "active"}
}

func clock(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func orUnknown(s string) string {
	if s == "" {
		return "no answer"
	}
	return s
}

// roughDuration prints a duration the way a person reads it on a lock
// screen: "4 min", "2 h 5 min".
func roughDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	m := int(d.Minutes())
	if m < 60 {
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d h %d min", m/60, m%60)
}

// adopt prepares a loaded state for this process and config. A changed
// config restarts the runs (the URLs may have changed) but keeps the alert,
// so a recovery is still pushed for an outage announced under the old one.
func (s *State) adopt(cfg Config, configSHA string, now time.Time) {
	if s.Version != StateVersion || s.ConfigSHA256 != configSHA {
		alerted, alertedAt, downSince, outageFor := s.Alerted, s.AlertedAt, s.DownSince, s.OutageFor
		lastPushAt, lastPushKind, lastPushOK, lastPushErr, pushes := s.LastPushAt, s.LastPushKind, s.LastPushOK, s.LastPushError, s.Pushes
		*s = State{
			Alerted: alerted, AlertedAt: alertedAt, DownSince: downSince, OutageFor: outageFor,
			LastPushAt: lastPushAt, LastPushKind: lastPushKind, LastPushOK: lastPushOK, LastPushError: lastPushErr, Pushes: pushes,
		}
	}
	s.Version = StateVersion
	s.ConfigSHA256 = configSHA
	s.StartedAt = now
	s.HealthURL = cfg.HealthURL
	s.ReferenceCount = len(cfg.ReferenceURLs)
	s.IntervalSeconds = int(cfg.Interval().Seconds())
	s.HoldSeconds = int(cfg.Hold().Seconds())
	if s.LastCheckAt.IsZero() {
		s.Phase = PhaseStarting
	}
	if s.Alerted {
		s.Phase = PhaseDown
	}
}

// maxStateBytes bounds a state file read; the document is well under 2 KiB.
const maxStateBytes = 16 << 10

// LoadState reads a state file. A missing file is a fresh state; an
// unreadable or corrupt one is an error the caller logs before starting
// fresh, since refusing to watch would be worse than forgetting.
func LoadState(path string) (State, error) {
	raw, err := ReadBounded(path, maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("parse witness state: %w", err)
	}
	return st, nil
}

// ReadBounded reads at most limit bytes of a file and refuses a longer one.
func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("%s is over the %d byte bound", path, limit)
	}
	return buf, nil
}

// SaveState writes the state atomically: a temporary file in the same
// directory, synced, then renamed over the old one. The file is 0644 because
// the agent, which may run as another user, reads it as the status.
func SaveState(path string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the status directory is world-readable by design; it holds no secret
		return err
	}
	tmp, err := os.CreateTemp(dir, ".status-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302 -- read by the agent as the witness status; no secret in it
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
