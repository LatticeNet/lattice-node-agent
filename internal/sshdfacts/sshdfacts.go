// Package sshdfacts reads the effective sshd configuration for the
// guard-reality report: which ports sshd is configured to serve, whether
// password authentication is on, and how root may log in. It runs `sshd -T`,
// the daemon's own rendering of its configuration after includes, Match
// blocks and defaults, because reading sshd_config by hand would have to
// reimplement that resolution and would get it wrong.
//
// The probe follows the sing-box liveness discipline: it runs only as root
// (sshd -T loads the host keys and refuses otherwise), only from an sshd in
// the trusted executable directories, under a short deadline, and a refusal
// or failure is reported as a note next to a nil fact block. It never
// substitutes a default for a value it could not read.
package sshdfacts

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/guardreality"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	// defaultTimeout bounds sshd -T. It answers in milliseconds; a host where
	// it takes seconds is one the report should not wait on.
	defaultTimeout = 3 * time.Second
	executableName = "sshd"
	// maxPorts and maxListenAddresses bound what the parser keeps. sshd
	// accepts any number of Port lines, but a report carrying hundreds says
	// something is wrong, and the server refuses it anyway.
	maxPorts           = 64
	maxListenAddresses = 64
	maxValueRunes      = 256
	maxNoteRunes       = 512
)

// Source configures a collection. Zero values select production behavior;
// tests inject Runner, EUID and Resolve so coverage never depends on the
// host being root or having sshd installed.
type Source struct {
	Timeout time.Duration
	Now     func() time.Time
	Runner  guardreality.Runner
	// EUID reports the effective uid the agent runs as.
	EUID func() int
	// Resolve locates the sshd binary and returns its path, or "" and the
	// reason it was refused.
	Resolve func(name string) (path, reason string)
}

func (s Source) withDefaults() Source {
	if s.Timeout <= 0 {
		s.Timeout = defaultTimeout
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Runner == nil {
		s.Runner = guardreality.RunBoundedCommand
	}
	if s.EUID == nil {
		s.EUID = os.Geteuid
	}
	if s.Resolve == nil {
		s.Resolve = singboxdiscover.ResolveTrustedExecutable
	}
	return s
}

// Collect returns the sshd facts, or nil and a note saying why nothing could
// be proven. It never returns an error: the note is the report, and the rest
// of the guard-reality snapshot posts with or without this block.
func Collect(ctx context.Context, src Source) (*model.GuardSSHDFacts, string) {
	src = src.withDefaults()
	if ctx == nil {
		ctx = context.Background()
	}
	if euid := src.EUID(); euid != 0 {
		return nil, fmt.Sprintf("sshd -T needs root to read the effective configuration; agent runs as uid %d", euid)
	}
	path, reason := src.Resolve(executableName)
	if path == "" {
		return nil, bounded(reason, maxNoteRunes)
	}
	runCtx, cancel := context.WithTimeout(ctx, src.Timeout)
	defer cancel()
	out, err := src.Runner(runCtx, path, "-T")
	if err != nil {
		return nil, bounded(fmt.Sprintf("%s -T: %v", path, err), maxNoteRunes)
	}
	facts, err := Parse(out)
	if err != nil {
		return nil, bounded(fmt.Sprintf("%s -T: %v", path, err), maxNoteRunes)
	}
	facts.ObservedAt = src.Now().UTC()
	return &facts, ""
}

// Parse reads `sshd -T` output: one `key value` line per option, keys in
// lower case, and repeated keys for port, listenaddress, hostkey and the
// like. It tolerates unknown keys, blank lines, CRLF and mixed-case keys. It
// fails when a fact the report exists to carry is missing or unreadable,
// because a default filled in here would be exactly the guess this probe
// exists to avoid.
func Parse(raw []byte) (model.GuardSSHDFacts, error) {
	var facts model.GuardSSHDFacts
	var sawPassword, sawPubkey, sawRootLogin bool
	ports := map[int]struct{}{}
	seenListen := map[string]struct{}{}
	var listen []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value := line, ""
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			key, value = line[:idx], strings.TrimSpace(line[idx+1:])
		}
		switch strings.ToLower(key) {
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return model.GuardSSHDFacts{}, fmt.Errorf("port %q is not a valid port", value)
			}
			ports[port] = struct{}{}
			if len(ports) > maxPorts {
				return model.GuardSSHDFacts{}, fmt.Errorf("more than %d distinct port lines", maxPorts)
			}
		case "listenaddress":
			value = bounded(value, maxValueRunes)
			if value == "" {
				continue
			}
			if _, ok := seenListen[value]; ok {
				continue
			}
			seenListen[value] = struct{}{}
			listen = append(listen, value)
			if len(listen) > maxListenAddresses {
				return model.GuardSSHDFacts{}, fmt.Errorf("more than %d listenaddress lines", maxListenAddresses)
			}
		case "passwordauthentication":
			enabled, err := parseYesNo("passwordauthentication", value)
			if err != nil {
				return model.GuardSSHDFacts{}, err
			}
			facts.PasswordAuthentication = enabled
			sawPassword = true
		case "pubkeyauthentication":
			enabled, err := parseYesNo("pubkeyauthentication", value)
			if err != nil {
				return model.GuardSSHDFacts{}, err
			}
			facts.PubkeyAuthentication = enabled
			sawPubkey = true
		case "permitrootlogin":
			value = bounded(value, maxValueRunes)
			if value == "" {
				return model.GuardSSHDFacts{}, fmt.Errorf("permitrootlogin line has no value")
			}
			facts.PermitRootLogin = value
			sawRootLogin = true
		case "maxauthtries":
			tries, err := strconv.Atoi(value)
			if err != nil || tries < 0 {
				return model.GuardSSHDFacts{}, fmt.Errorf("maxauthtries %q is not a count", value)
			}
			facts.MaxAuthTries = tries
		}
	}
	switch {
	case !sawPassword:
		return model.GuardSSHDFacts{}, fmt.Errorf("output has no passwordauthentication line")
	case !sawPubkey:
		return model.GuardSSHDFacts{}, fmt.Errorf("output has no pubkeyauthentication line")
	case !sawRootLogin:
		return model.GuardSSHDFacts{}, fmt.Errorf("output has no permitrootlogin line")
	case len(ports) == 0:
		return model.GuardSSHDFacts{}, fmt.Errorf("output has no port line")
	}
	facts.Ports = make([]int, 0, len(ports))
	for port := range ports {
		facts.Ports = append(facts.Ports, port)
	}
	sort.Ints(facts.Ports)
	facts.ListenAddresses = listen
	return facts, nil
}

func parseYesNo(key, value string) (bool, error) {
	switch strings.ToLower(value) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, fmt.Errorf("%s %q is neither yes nor no", key, value)
}

// bounded trims, strips control characters and caps a value so a hostile or
// broken sshd output cannot smuggle terminal escapes or megabytes into the
// report. Tabs survive because the note may quote a command line.
func bounded(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}
