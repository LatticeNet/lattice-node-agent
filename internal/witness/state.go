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
	FailingSince        time.Time `json:"failing_since,omitzero"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	// The current run of answered checks.
	OKSince       time.Time `json:"ok_since,omitzero"`
	ConsecutiveOK int       `json:"consecutive_ok,omitempty"`
	// Set while checks reach neither the control plane nor any reference.
	NetworkDownSince time.Time `json:"network_down_since,omitzero"`

	// Alerted is set once the unreachable push was delivered and cleared once
	// the recovery push was. It survives restarts and config changes.
	Alerted   bool      `json:"alerted"`
	AlertedAt time.Time `json:"alerted_at,omitzero"`
	DownSince time.Time `json:"down_since,omitzero"`

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

// observe folds one check into the state and returns the push it now owes,
// if any. It is pure: the caller sends the push and reports the outcome with
// pushed.
func (s *State) observe(cfg Config, now time.Time, res CheckResult) *Push {
	prev := s.LastCheckAt
	s.LastCheckAt = now
	s.LastCheckOK = res.OK
	s.LastCheckDetail = res.Detail
	if !prev.IsZero() && now.Sub(prev) > cfg.maxGap() {
		// The witness itself was away (stopped, the machine asleep or
		// rebooting) for longer than a run may pause: whatever it counted
		// before says nothing about now.
		s.FailingSince, s.ConsecutiveFailures = time.Time{}, 0
		s.OKSince, s.ConsecutiveOK = time.Time{}, 0
	}

	if res.OK {
		s.LastOKAt = now
		s.NetworkDownSince = time.Time{}
		s.FailingSince, s.ConsecutiveFailures = time.Time{}, 0
		if s.ConsecutiveOK == 0 {
			s.OKSince = now
		}
		s.ConsecutiveOK++
		s.Phase = PhaseWatching
		if s.Alerted {
			s.Phase = PhaseDown
			if s.ConsecutiveOK >= 2 && now.Sub(s.OKSince) >= cfg.Recover() {
				return recoveryPush(cfg, s, now)
			}
		}
		return nil
	}

	// A failed check ends any run of answers: a recovery has to be seen
	// answering without a break.
	s.OKSince, s.ConsecutiveOK = time.Time{}, 0
	if !res.NetworkUp {
		// Nothing answers, so this check says nothing about the control
		// plane: it is not counted as a failure and does not end the run.
		// The hold is measured on the clock from the run's first failure, so
		// a run that began before the network dropped can be past its hold
		// when the network comes back.
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
		s.FailingSince = now
	}
	s.ConsecutiveFailures++
	if s.Alerted {
		s.Phase = PhaseDown
		return nil
	}
	s.Phase = PhaseFailing
	if s.ConsecutiveFailures >= 2 && now.Sub(s.FailingSince) >= cfg.Hold() && !backFromNetworkDown {
		return downPush(cfg, s, now)
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
		s.Phase = PhaseDown
	case PushRecovery:
		s.Alerted = false
		s.AlertedAt = time.Time{}
		s.DownSince = time.Time{}
		s.Phase = PhaseWatching
	}
}

func downPush(cfg Config, s *State, now time.Time) *Push {
	host := hostOf(cfg.HealthURL)
	title, failed := "Lattice control plane unreachable", "has not answered since"
	if strings.HasPrefix(s.LastCheckDetail, "http ") {
		// Something on the public path answers, just not with 200: the
		// server says it is not ready (its store or audit check failed), or a
		// proxy or CDN in front of it answers in its place. "Unreachable"
		// would send the operator after the network.
		title, failed = "Lattice control plane not ready", "has answered without reporting ready since"
	}
	body := fmt.Sprintf("Seen from %s: %s %s %s (%d checks over %s; last: %s). This node's own network is up. Sent by the Lattice witness on %s through its local Bark server, because Lattice itself cannot send anything now.",
		cfg.NodeName, host, failed, clock(s.FailingSince), s.ConsecutiveFailures, roughDuration(now.Sub(s.FailingSince)), orUnknown(s.LastCheckDetail), cfg.NodeName)
	return &Push{Kind: PushDown, Title: title, Body: body, Level: cfg.Level()}
}

func recoveryPush(cfg Config, s *State, now time.Time) *Push {
	host := hostOf(cfg.HealthURL)
	since := s.DownSince
	if since.IsZero() {
		since = s.AlertedAt
	}
	// A recovery is a run of 200s from /readyz, so "ready again" is true
	// after either kind of outage.
	body := fmt.Sprintf("Seen from %s: %s reports ready again since %s, after about %s down. Sent by the Lattice witness on %s.",
		cfg.NodeName, host, clock(s.OKSince), roughDuration(s.OKSince.Sub(since)), cfg.NodeName)
	return &Push{Kind: PushRecovery, Title: "Lattice control plane ready again", Body: body, Level: "active"}
}

func clock(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") }

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
		alerted, alertedAt, downSince := s.Alerted, s.AlertedAt, s.DownSince
		lastPushAt, lastPushKind, lastPushOK, lastPushErr, pushes := s.LastPushAt, s.LastPushKind, s.LastPushOK, s.LastPushError, s.Pushes
		*s = State{
			Alerted: alerted, AlertedAt: alertedAt, DownSince: downSince,
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
