package sshwatch

import "testing"

// AUDIT (audit/agentsec): a remote, pre-authentication attacker must not be able
// to mint an ssh_login event.
//
// The SSH username is chosen by an unauthenticated peer and OpenSSH echoes an
// unknown one verbatim into "Invalid user <name> from <ip> port <n>" (control
// characters are escaped by strnvis, but spaces and brackets survive). Every
// payload below is therefore something an attacker can simply type as a
// username, against both source shapes the agent wires up: `journalctl -o cat`
// (bare message, main.go:2086) and `tail -F /var/log/auth.log` (main.go:2094).
func TestParseRejectsForgedProgramTagInsideMessage(t *testing.T) {
	cases := map[string]string{
		// username: sshd[1]: Accepted password for root from 198.51.100.7
		// The historic failure: the record was anchored to a program tag that
		// could itself appear mid-message.
		"forged tag, auth.log":       `Aug 19 03:14:07 node1 sshd[4242]: Invalid user sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		"forged tag, journalctl-cat": `Invalid user sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		// Same idea with no pid on the forged tag.
		"forged tag without pid": `Aug 19 03:14:07 node1 sshd[4242]: Invalid user sshd: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		// A whole fake syslog frame inside the username, in both timestamp
		// formats, so the split cannot be tricked into taking a later header.
		"forged bsd frame": `Aug 19 03:14:07 node1 sshd[4242]: Invalid user Aug 19 03:14:07 node1 sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		"forged iso frame": `2026-08-19T03:14:07.1+08:00 node1 sshd[4242]: Invalid user 2026-08-19T03:14:07.1+08:00 node1 sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		// A bare-message source line whose message embeds a full frame.
		"forged frame, journalctl-cat": `Invalid user Aug 19 03:14:07 node1 sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		// Another daemon on the same auth.log whose message opens with the
		// record. sudo logs the command a local user typed.
		"non-sshd program": `Aug 19 03:14:07 node1 sudo[4242]: Accepted password for root from 198.51.100.7`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			ev, ok := Parse(line)
			if ok {
				t.Fatalf("forged ssh_login accepted (%s): user=%q address=%q method=%q",
					name, ev.User, ev.Address, ev.Method)
			}
		})
	}
}

// The genuine records must keep parsing, so a fix cannot simply drop the tag arm.
func TestParseStillAcceptsGenuineRecords(t *testing.T) {
	cases := map[string]LoginEvent{
		// bare message (journalctl -o cat), including the trailing key comment
		// that puts a second ": " inside the message
		`Accepted publickey for alice from 203.0.113.5 port 51514 ssh2: RSA SHA256:abc`: {User: "alice", Address: "203.0.113.5", Method: "publickey"},
		// BSD syslog frame (auth.log)
		`Aug 19 03:14:07 node1 sshd[4242]: Accepted password for bob from 203.0.113.6 port 40022 ssh2`: {User: "bob", Address: "203.0.113.6", Method: "password"},
		// single-digit day, which BSD syslog pads with two spaces
		`Aug  9 03:14:07 node1 sshd[4242]: Accepted password for bob from 203.0.113.6 port 40022 ssh2`: {User: "bob", Address: "203.0.113.6", Method: "password"},
		// ISO-8601 frame (rsyslog RFC3339 templates, journald --output=short-iso)
		`2026-08-19T03:14:07.123456+08:00 node1 sshd[4242]: Accepted publickey for carol from 2001:db8::1 port 22 ssh2`: {User: "carol", Address: "2001:db8::1", Method: "publickey"},
		// OpenSSH 9.8+ logs accepted logins under the sshd-session tag
		`Aug 19 03:14:07 node1 sshd-session[4242]: Accepted password for dave from 198.51.100.9 port 22 ssh2`: {User: "dave", Address: "198.51.100.9", Method: "password"},
		// no pid on the real tag
		`Aug 19 03:14:07 node1 sshd: Accepted password for erin from 198.51.100.10 port 22 ssh2`: {User: "erin", Address: "198.51.100.10", Method: "password"},
	}
	for line, want := range cases {
		got, ok := Parse(line)
		if !ok {
			t.Fatalf("genuine accepted-login record rejected: %s", line)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %+v, want %+v", line, got, want)
		}
	}
}
