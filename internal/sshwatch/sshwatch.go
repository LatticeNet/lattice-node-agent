// Package sshwatch detects successful SSH logins from sshd log lines so the
// agent can report them as security events. The parser is the testable core;
// the line source (journald or auth.log) is wired by the agent.
package sshwatch

import (
	"bufio"
	"context"
	"io"
	"regexp"
)

// LoginEvent describes one accepted SSH login.
type LoginEvent struct {
	User    string
	Address string
	Method  string
}

// sshd logs successful logins as:
//
//	Accepted password for alice from 203.0.113.5 port 51514 ssh2
//	Accepted publickey for bob from 2001:db8::1 port 40022 ssh2: RSA SHA256:...
//
// The "Accepted ..." text must be the START of the sshd syslog message, not just
// appear somewhere in the line. An unanchored match was forgeable: a value that
// sshd itself echoes (e.g. a crafted username in a "Failed"/"Invalid user" line)
// could embed the substring "Accepted <method> for <user> from <ip>" and mint a
// bogus ssh_login event. We therefore require the match to begin either at the
// very start of the line (bare-message sources such as `journalctl -o cat`) or
// immediately after the standard syslog "...sshd[pid]: " program prefix. Anything
// nested deeper in the message is rejected.
//
//	^                              start of line, OR
//	sshd(\[\d+\])?:\s              the sshd program tag + ": " from syslog
//
// followed immediately by the Accepted record.
var acceptedRe = regexp.MustCompile(`(?:^|sshd(?:\[\d+\])?:\s)Accepted (\S+) for (?:invalid user )?(\S+) from (\S+)`)

// Parse extracts a LoginEvent from a single log line, returning false when the
// line is not an accepted-login record.
func Parse(line string) (LoginEvent, bool) {
	m := acceptedRe.FindStringSubmatch(line)
	if m == nil {
		return LoginEvent{}, false
	}
	return LoginEvent{Method: m[1], User: m[2], Address: m[3]}, true
}

// Stream reads lines from r and invokes emit for each accepted login until r is
// exhausted or ctx is cancelled.
func Stream(ctx context.Context, r io.Reader, emit func(LoginEvent)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if ev, ok := Parse(scanner.Text()); ok {
			emit(ev)
		}
	}
	return scanner.Err()
}
