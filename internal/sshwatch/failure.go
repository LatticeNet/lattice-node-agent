package sshwatch

import (
	"net"
	"regexp"
)

// FailureEvent describes one rejected SSH authentication attempt.
type FailureEvent struct {
	User    string
	Address string
	// Method is empty for records that name no authentication method, such as
	// the ones sshd writes when a peer disappears mid-authentication.
	Method string
	// Invalid means sshd said the account does not exist on this host. It is
	// what separates someone guessing account names from someone guessing the
	// password of an account that is really there.
	Invalid bool
	// Aborted means the peer dropped the connection during authentication
	// instead of being told no. Scanners do this constantly; a human whose
	// password prompt timed out does it too.
	Aborted bool
}

// maxUserLen bounds what one parsed username can contribute to memory. sshd
// truncates the name it echoes to 100 bytes, but the patterns below deliberately
// let a username absorb the decoy text that follows it (see below), so the field
// is clamped rather than trusted.
const maxUserLen = 96

// A failure record is matched under the same framing rule as the accepted-login
// record: the pattern runs against the sshd message alone (splitSyslogMessage
// strips the syslog header exactly once, from the front) and is anchored at BOTH
// ends, so text sitting inside a longer message can never be the record.
//
// Anchoring alone is not enough here. Every one of these records prints the
// attacker-chosen username BEFORE the source address, and a username may contain
// spaces, so this is a line sshd really writes:
//
//	Invalid user "admin from 1.2.3.4" from 5.6.7.8 port 22
//
// Matching the username as \S+ would either reject the whole line or, on a
// slightly different payload, bind the address group to the text the attacker
// typed. Attributing failures to an address the attacker picked is worse than
// missing them: it frames a third party and poisons whatever the aggregate
// feeds.
//
// So the username is matched with a greedy `.*`. Greedy makes the engine bind
// the trailing ` from <addr> port <n>` to the LAST place it fits, and the last
// place is always the one sshd printed, because the attacker can only add text
// to the left of it and never to the right of it. The decoy is swallowed by the
// username and the address group gets the real peer.
//
// net.ParseIP is the second line: these fields come from ssh_remote_ipaddr and
// are always numeric, so a shape that reaches this point without being an IP
// literal is not a record worth trusting.
type failurePattern struct {
	re *regexp.Regexp
	// invalid and aborted carry what the record shape itself says, for the
	// patterns where it is not a capture group.
	invalid bool
	aborted bool
}

var failurePatterns = []failurePattern{
	// Failed password for alice from 203.0.113.5 port 51514 ssh2
	// Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
	// Failed publickey for bob from 2001:db8::1 port 22 ssh2: RSA SHA256:abc
	{re: regexp.MustCompile(`^Failed (?P<method>\S+) for (?:(?P<invalid>invalid) user )?(?P<user>.*) from (?P<addr>\S+) port \d+ ssh2(?:: .*)?(?: \[preauth\])?$`)},
	// Invalid user admin from 203.0.113.5 port 55314
	// Older sshd omits the port, so it is optional.
	{re: regexp.MustCompile(`^Invalid user (?P<user>.*) from (?P<addr>\S+)(?: port \d+)?$`), invalid: true},
	// Connection closed by authenticating user root 203.0.113.5 port 33984 [preauth]
	// Connection reset by invalid user admin 203.0.113.5 port 33984 [preauth]
	// Disconnected from authenticating user root 203.0.113.5 port 33984 [preauth]
	//
	// The user-qualified forms only. "Connection closed by 203.0.113.5 port 22"
	// is a port scan or a health check, not an authentication attempt, and
	// "Disconnected from user alice ..." is a session that already succeeded.
	// Counting either would bury the signal under traffic nobody can act on.
	{re: regexp.MustCompile(`^(?:Connection (?:closed|reset) by|Disconnected from) (?:(?P<invalid>invalid)|authenticating) user (?P<user>.*) (?P<addr>\S+) port \d+(?: \[preauth\])?$`), aborted: true},
	// error: maximum authentication attempts exceeded for root from 203.0.113.5 port 22 ssh2 [preauth]
	{re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:(?P<invalid>invalid) user )?(?P<user>.*) from (?P<addr>\S+) port \d+ ssh2(?: \[preauth\])?$`)},
}

// ParseFailure extracts a FailureEvent from a single log line, returning false
// when the line is not a rejected-authentication record.
func ParseFailure(line string) (FailureEvent, bool) {
	program, message := splitSyslogMessage(line)
	if program != "" && !isSSHDProgram(program) {
		return FailureEvent{}, false
	}
	for _, p := range failurePatterns {
		m := p.re.FindStringSubmatch(message)
		if m == nil {
			continue
		}
		// The patterns are mutually exclusive by their leading literal, so a
		// record that matches one and then fails validation is not retried
		// against the others: it is dropped.
		return p.event(m)
	}
	return FailureEvent{}, false
}

func (p failurePattern) event(m []string) (FailureEvent, bool) {
	ev := FailureEvent{Invalid: p.invalid, Aborted: p.aborted}
	for i, name := range p.re.SubexpNames() {
		switch name {
		case "method":
			ev.Method = m[i]
		case "user":
			ev.User = clampLen(m[i], maxUserLen)
		case "addr":
			ev.Address = m[i]
		case "invalid":
			if m[i] != "" {
				ev.Invalid = true
			}
		}
	}
	ip := net.ParseIP(ev.Address)
	if ip == nil {
		return FailureEvent{}, false
	}
	// Report the canonical spelling so two renderings of one IPv6 address
	// cannot split a source's failure count in two.
	ev.Address = ip.String()
	return ev, true
}

func clampLen(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
