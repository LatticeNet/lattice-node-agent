// Package witness watches the control plane from one node and pushes a Bark
// message through that node's own bark-server when the control plane stops
// answering. It is the dead-man for the one failure Lattice cannot report
// itself: the control plane being down.
//
// It runs as its own process (lattice-agent -witness <config>), apart from the
// agent's loop, because the agent exits when its first hello fails and would
// therefore be absent for the whole of an outage that began before it
// restarted. The witness holds no node token, carries no fleet data, and
// talks only to the control plane's public health URL, the reference URLs and
// the bark-server on its own loopback interface. Standard library only.
package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Capability is what an agent binary that has witness mode advertises, in
// its hello capabilities and in -compat-json features. The server refuses to
// plan a witness for a node that does not advertise it, and the apply script
// checks the binary it copies for it.
const Capability = "control-plane-witness-v1"

// ConfigVersion is the only config document version this binary reads.
const ConfigVersion = 1

// Defaults and bounds. The server renders the same defaults into the plan; a
// config that leaves a field out gets the value below.
const (
	DefaultStateFile = "/var/lib/lattice-witness/status.json"
	DefaultInterval  = 30 * time.Second
	DefaultHold      = 3 * time.Minute
	DefaultRecover   = time.Minute
	DefaultBarkLevel = "critical"
	DefaultBarkGroup = "lattice-witness"

	minInterval = 15 * time.Second
	maxInterval = 10 * time.Minute
	maxHold     = time.Hour
	maxRefs     = 3
)

// barkLevels are the interruption levels bark-server accepts.
var barkLevels = []string{"active", "timeSensitive", "passive", "critical"}

// deviceKeyRe is the shape of a Bark device key. Anything else in the key
// file is refused rather than sent.
var deviceKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// Config is the witness document an approved plan writes on the node. Every
// field is visible in the approval; the device key is not a field, only the
// path of the root-only file that holds it.
type Config struct {
	Version  int    `json:"version"`
	NodeName string `json:"node_name"`
	// HealthURL is the control plane's public readiness endpoint, reached the
	// way any client reaches it. Only HTTP 200 counts as answering.
	HealthURL string `json:"health_url"`
	// ReferenceURLs prove this node's own network works. Any HTTP answer from
	// any of them counts. When the control plane and every reference fail
	// together, the witness assumes its own network is down and stays quiet.
	ReferenceURLs []string `json:"reference_urls"`
	// BarkURL is the bark-server on this node's loopback interface. A
	// non-loopback URL is refused, so the device key never leaves the node.
	BarkURL           string `json:"bark_url"`
	BarkDeviceKeyFile string `json:"bark_device_key_file"`
	BarkGroup         string `json:"bark_group,omitempty"`
	// BarkLevel is the level of the "unreachable" push. The recovery push is
	// always "active".
	BarkLevel       string `json:"bark_level,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	HoldSeconds     int    `json:"hold_seconds,omitempty"`
	RecoverSeconds  int    `json:"recover_seconds,omitempty"`
	StateFile       string `json:"state_file,omitempty"`
}

// Interval is the time between checks.
func (c Config) Interval() time.Duration { return secondsOr(c.IntervalSeconds, DefaultInterval) }

// Hold is how long the control plane must keep failing, with this node's
// network up, before the witness pushes.
func (c Config) Hold() time.Duration { return secondsOr(c.HoldSeconds, DefaultHold) }

// Recover is how long the control plane must keep answering before the
// witness pushes the recovery, so a flapping control plane sends nothing more.
func (c Config) Recover() time.Duration { return secondsOr(c.RecoverSeconds, DefaultRecover) }

// State is where the witness keeps its state and status.
func (c Config) State() string {
	if strings.TrimSpace(c.StateFile) == "" {
		return DefaultStateFile
	}
	return c.StateFile
}

// Level is the level of the unreachable push.
func (c Config) Level() string {
	if c.BarkLevel == "" {
		return DefaultBarkLevel
	}
	return c.BarkLevel
}

// Group is the Bark group both pushes use.
func (c Config) Group() string {
	if c.BarkGroup == "" {
		return DefaultBarkGroup
	}
	return c.BarkGroup
}

// maxGap is the longest silence between two checks that still continues a
// run. A witness that was itself stopped for longer than this does not know
// what happened in between, so it starts counting again.
func (c Config) maxGap() time.Duration {
	return max(3*c.Interval(), c.Hold())
}

func secondsOr(v int, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return time.Duration(v) * time.Second
}

// Validate refuses a config the witness cannot run safely.
func (c Config) Validate() error {
	if c.Version != ConfigVersion {
		return fmt.Errorf("config version %d is not supported (want %d)", c.Version, ConfigVersion)
	}
	if strings.TrimSpace(c.NodeName) == "" {
		return errors.New("node_name is required")
	}
	if err := checkWatchURL("health_url", c.HealthURL); err != nil {
		return err
	}
	if len(c.ReferenceURLs) == 0 || len(c.ReferenceURLs) > maxRefs {
		return fmt.Errorf("reference_urls needs 1 to %d URLs", maxRefs)
	}
	for i, ref := range c.ReferenceURLs {
		if err := checkWatchURL(fmt.Sprintf("reference_urls[%d]", i), ref); err != nil {
			return err
		}
		if sameHost(ref, c.HealthURL) {
			return fmt.Errorf("reference_urls[%d] is on the control plane's host; a reference must prove this node's network by another path", i)
		}
	}
	if err := checkLoopbackURL("bark_url", c.BarkURL); err != nil {
		return err
	}
	if !filepath.IsAbs(c.BarkDeviceKeyFile) {
		return errors.New("bark_device_key_file must be an absolute path")
	}
	if c.BarkLevel != "" && !slices.Contains(barkLevels, c.BarkLevel) {
		return fmt.Errorf("bark_level must be one of %s", strings.Join(barkLevels, ", "))
	}
	if c.BarkGroup != "" && (len(c.BarkGroup) > 64 || strings.ContainsAny(c.BarkGroup, "\r\n")) {
		return errors.New("bark_group must be one line of at most 64 bytes")
	}
	if c.StateFile != "" && !filepath.IsAbs(c.StateFile) {
		return errors.New("state_file must be an absolute path")
	}
	interval := c.Interval()
	if interval < minInterval || interval > maxInterval {
		return fmt.Errorf("interval_seconds must be between %d and %d", int(minInterval.Seconds()), int(maxInterval.Seconds()))
	}
	if hold := c.Hold(); hold < 2*interval || hold > maxHold {
		return fmt.Errorf("hold_seconds must be at least two intervals (%d) and at most %d", int((2 * interval).Seconds()), int(maxHold.Seconds()))
	}
	if rec := c.Recover(); rec < interval || rec > maxHold {
		return fmt.Errorf("recover_seconds must be at least one interval (%d) and at most %d", int(interval.Seconds()), int(maxHold.Seconds()))
	}
	return nil
}

// checkWatchURL accepts https URLs, and http only on a loopback host (tests
// and a control plane on the same machine).
func checkWatchURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry credentials", field)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s must use https unless it is on loopback", field)
	default:
		return fmt.Errorf("%s must use https", field)
	}
}

func checkLoopbackURL(field, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an http or https URL", field)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be a bare base URL", field)
	}
	if !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%s must be on this node's loopback interface (127.0.0.1, ::1 or localhost) so the device key never leaves the node", field)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// LoadConfig reads and validates the witness config. It returns the raw
// bytes' SHA-256 too, which the witness reports so the control plane can see
// that the node runs the config it approved. The config decides where the
// witness looks and where the key goes, so it must belong to the user the
// witness runs as and must not be writable by group or others. Reading it is
// harmless (it holds no secret, only the key file's path), so a readable
// config is accepted rather than turned into a witness that never starts.
func LoadConfig(path string) (Config, string, error) {
	raw, err := readChecked(path, "witness config", maxConfigBytes, 0o022, "group and others must not be able to write it")
	if err != nil {
		return Config{}, "", err
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, "", fmt.Errorf("parse witness config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, "", fmt.Errorf("witness config: %w", err)
	}
	sum := sha256.Sum256(raw)
	return cfg, hex.EncodeToString(sum[:]), nil
}

// ReadDeviceKey reads the Bark device key from its file. The file must give
// group and others no access and must belong to the user the witness runs
// as; the key must look like a Bark key. Nothing returned here ever carries
// the key except the key itself.
func ReadDeviceKey(path string) (string, error) {
	raw, err := readChecked(path, "device key file", maxKeyFileBytes, 0o077, "group and others must have no access")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(raw))
	if !deviceKeyRe.MatchString(key) {
		return "", errors.New("device key file does not hold a Bark device key")
	}
	return key, nil
}

// Bounds on the two files the witness reads at start. The config is well
// under 2 KiB; a Bark key is at most 128 bytes.
const (
	maxConfigBytes  = 64 << 10
	maxKeyFileBytes = 1 << 10
)

// readChecked reads a file the witness trusts: a regular file that belongs to
// the user the witness runs as and whose mode has none of the deny bits. The
// checks run on the opened file, not on the path, so the file checked is the
// file read; one swapped in between cannot slip past them. what names the
// file in errors and rule says what the mode must be; neither carries the
// file's contents.
func readChecked(path, what string, limit int64, deny fs.FileMode, rule string) ([]byte, error) {
	f, err := openForCheck(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", what)
	}
	if perm := info.Mode().Perm(); perm&deny != 0 {
		return nil, fmt.Errorf("%s mode is %04o; %s", what, perm, rule)
	}
	if err := checkOwner(what, info); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is over the %d byte bound", what, limit)
	}
	return raw, nil
}
