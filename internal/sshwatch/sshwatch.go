// Package sshwatch reads sshd log lines and turns them into security events the
// agent can report: accepted logins one at a time (Parse), and rejected
// authentication attempts folded into a per-window summary (ParseFailure,
// Aggregator), because a single public node logs thousands of the latter a day
// and shipping them line by line would cost real money to produce something
// nobody reads. The parsers and the aggregator are the testable core; the line
// source (journald or auth.log) is wired by the agent.
package sshwatch

import (
	"bufio"
	"context"
	"io"
	"path"
	"regexp"
	"strings"
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
// The login record must be the WHOLE message sshd logged, not text found
// somewhere inside it. That distinction is load-bearing: an SSH username is
// chosen by an unauthenticated remote peer and sshd echoes an unknown one
// verbatim ("Invalid user <name> from <ip> port <n>"), so anything the pattern
// will accept mid-message can be typed in by an attacker.
//
// Two earlier attempts tried to express that with a pattern over the whole line:
// first an unanchored match (forgeable by a username containing the record),
// then a match anchored to line start OR to an "sshd[pid]: " program tag. The
// second attempt failed the same way, one level deeper, because the tag arm was
// not itself anchored: a username of the form
//
//	sshd[1]: Accepted password for root from 198.51.100.7
//
// supplies its own program tag mid-message and satisfies it. Anchoring is the
// wrong tool here, so the framing is now split off structurally instead:
// splitSyslogMessage removes the syslog header exactly once, from the front, and
// the record is matched against the message field alone. A crafted username
// lands inside the message and can never become the message.
var acceptedRe = regexp.MustCompile(`^Accepted (\S+) for (?:invalid user )?(\S+) from (\S+)`)

// syslogHeaderRe matches the BSD (RFC 3164) or ISO-8601 framing that a file
// source such as /var/log/auth.log carries in front of the sshd message:
//
//	Jun 11 04:00:01 host sshd[123]: <message>
//	2026-08-19T03:14:07.123456+08:00 host sshd[123]: <message>
//
// It is anchored at line start and consumes timestamp, hostname and program tag
// in one pass, so it always splits at the FIRST tag on the line: the one syslog
// itself wrote. A second tag inside the message is part of the message.
// journald's `-o cat` output carries no header at all and is handled by leaving
// the line untouched.
var syslogHeaderRe = regexp.MustCompile(`^(?:[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+(\S+?)(?:\[\d+\])?:[ \t]`)

// splitSyslogMessage separates the syslog framing from the message the program
// logged. program is empty when the line carries no header (a bare message), in
// which case the whole line is the message.
func splitSyslogMessage(line string) (program, message string) {
	m := syslogHeaderRe.FindStringSubmatchIndex(line)
	if m == nil {
		return "", line
	}
	return line[m[2]:m[3]], line[m[1]:]
}

// isSSHDProgram reports whether a syslog program tag is sshd. OpenSSH 9.8 split
// the per-connection work into helper binaries that log under their own tags
// ("sshd-session", "sshd-auth"), so the sshd- prefix is accepted too; without it
// accepted logins go unreported on current OpenSSH.
func isSSHDProgram(program string) bool {
	base := path.Base(strings.TrimSpace(program))
	return base == "sshd" || strings.HasPrefix(base, "sshd-")
}

// Parse extracts a LoginEvent from a single log line, returning false when the
// line is not an accepted-login record.
func Parse(line string) (LoginEvent, bool) {
	program, message := splitSyslogMessage(line)
	if program != "" && !isSSHDProgram(program) {
		return LoginEvent{}, false
	}
	m := acceptedRe.FindStringSubmatch(message)
	if m == nil {
		return LoginEvent{}, false
	}
	return LoginEvent{Method: m[1], User: m[2], Address: m[3]}, true
}

// StreamLines reads lines from r and hands each one to fn until r is exhausted
// or ctx is cancelled. An Aggregator needs the whole line, not only the logins
// Stream reports, so the scan loop is shared instead of written twice.
func StreamLines(ctx context.Context, r io.Reader, fn func(string)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		fn(scanner.Text())
	}
	return scanner.Err()
}

// Stream reads lines from r and invokes emit for each accepted login until r is
// exhausted or ctx is cancelled.
func Stream(ctx context.Context, r io.Reader, emit func(LoginEvent)) error {
	return StreamLines(ctx, r, func(line string) {
		if ev, ok := Parse(line); ok {
			emit(ev)
		}
	})
}
