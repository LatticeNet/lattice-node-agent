package sshwatch

import "testing"

// AUDIT (audit/agentsec): the accepted-login anchor is still forgeable.
//
// sshwatch.go:38 anchors the record at start-of-line OR immediately after an
// "sshd[pid]: " program tag found ANYWHERE in the line. A remote, unauthenticated
// attacker who can reach the node's sshd chooses the username, and OpenSSH echoes
// an unknown username verbatim into "Invalid user <name> from <ip> port <n>", so
// the username itself can carry a second, fake program tag. The agent then posts
// an ssh_login event for a login that never happened, with an attacker-chosen
// user and source address.
//
// Both source shapes the agent wires up are affected: `journalctl -o cat`
// (bare message, main.go:2086) and `tail -F /var/log/auth.log` (main.go:2094).
func TestParseRejectsForgedProgramTagInsideMessage(t *testing.T) {
	// username sent by the attacker:
	//   sshd[1]: Accepted password for root from 198.51.100.7
	cases := map[string]string{
		"auth.log":       `Aug 19 03:14:07 node1 sshd[4242]: Invalid user sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
		"journalctl-cat": `Invalid user sshd[1]: Accepted password for root from 198.51.100.7 from 203.0.113.9 port 55314`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			ev, ok := Parse(line)
			if ok {
				t.Fatalf("forged ssh_login accepted from an %s line: user=%q address=%q method=%q",
					name, ev.User, ev.Address, ev.Method)
			}
		})
	}
}

// The genuine records must keep parsing, so a fix cannot simply drop the tag arm.
func TestParseStillAcceptsGenuineRecords(t *testing.T) {
	for _, line := range []string{
		`Accepted publickey for alice from 203.0.113.5 port 51514 ssh2: RSA SHA256:abc`,
		`Aug 19 03:14:07 node1 sshd[4242]: Accepted password for bob from 203.0.113.6 port 40022 ssh2`,
	} {
		if _, ok := Parse(line); !ok {
			t.Fatalf("genuine accepted-login record rejected: %s", line)
		}
	}
}
