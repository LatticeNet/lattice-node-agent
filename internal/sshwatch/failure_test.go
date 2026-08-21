package sshwatch

import "testing"

func TestParseFailureGenuineRecords(t *testing.T) {
	cases := map[string]FailureEvent{
		// bare message, the shape journalctl -o cat delivers
		`Failed password for alice from 203.0.113.5 port 51514 ssh2`: {
			User: "alice", Address: "203.0.113.5", Method: "password",
		},
		`Failed password for invalid user admin from 203.0.113.5 port 22 ssh2`: {
			User: "admin", Address: "203.0.113.5", Method: "password", Invalid: true,
		},
		// the trailing key comment puts a second ": " inside the message
		`Failed publickey for bob from 2001:db8::1 port 22 ssh2: RSA SHA256:abc`: {
			User: "bob", Address: "2001:db8::1", Method: "publickey",
		},
		`Failed keyboard-interactive/pam for invalid user test from 198.51.100.3 port 40000 ssh2`: {
			User: "test", Address: "198.51.100.3", Method: "keyboard-interactive/pam", Invalid: true,
		},
		// BSD syslog frame (auth.log)
		`Aug 19 03:14:07 node1 sshd[4242]: Failed password for root from 203.0.113.9 port 55314 ssh2`: {
			User: "root", Address: "203.0.113.9", Method: "password",
		},
		// OpenSSH 9.8 split the per-connection work into its own tags
		`Aug 19 03:14:07 node1 sshd-auth[4242]: Failed password for root from 203.0.113.9 port 55314 ssh2`: {
			User: "root", Address: "203.0.113.9", Method: "password",
		},
		`Invalid user admin from 203.0.113.5 port 55314`: {
			User: "admin", Address: "203.0.113.5", Invalid: true,
		},
		// older sshd omits the port
		`Invalid user admin from 203.0.113.5`: {
			User: "admin", Address: "203.0.113.5", Invalid: true,
		},
		// an empty username is still an attempt against this host
		`Invalid user  from 203.0.113.5 port 22`: {
			Address: "203.0.113.5", Invalid: true,
		},
		`Connection closed by authenticating user root 203.0.113.5 port 33984 [preauth]`: {
			User: "root", Address: "203.0.113.5", Aborted: true,
		},
		`Connection closed by invalid user admin 203.0.113.5 port 33984 [preauth]`: {
			User: "admin", Address: "203.0.113.5", Invalid: true, Aborted: true,
		},
		`Connection reset by invalid user oracle 198.51.100.4 port 1234 [preauth]`: {
			User: "oracle", Address: "198.51.100.4", Invalid: true, Aborted: true,
		},
		`Disconnected from authenticating user root 203.0.113.5 port 33984 [preauth]`: {
			User: "root", Address: "203.0.113.5", Aborted: true,
		},
		`error: maximum authentication attempts exceeded for root from 203.0.113.5 port 22 ssh2 [preauth]`: {
			User: "root", Address: "203.0.113.5",
		},
		`error: maximum authentication attempts exceeded for invalid user admin from 203.0.113.5 port 22 ssh2 [preauth]`: {
			User: "admin", Address: "203.0.113.5", Invalid: true,
		},
		// two spellings of one IPv6 address must not become two sources
		`Failed password for root from 2001:0DB8:0000::1 port 22 ssh2`: {
			User: "root", Address: "2001:db8::1", Method: "password",
		},
	}
	for line, want := range cases {
		got, ok := ParseFailure(line)
		if !ok {
			t.Errorf("genuine failure record rejected: %s", line)
			continue
		}
		if got != want {
			t.Errorf("ParseFailure(%q) = %+v, want %+v", line, got, want)
		}
	}
}

func TestParseFailureIgnoresNonFailures(t *testing.T) {
	cases := map[string]string{
		"accepted login":     `Accepted password for alice from 203.0.113.5 port 51514 ssh2`,
		"port scan, no user": `Connection closed by 203.0.113.5 port 22 [preauth]`,
		// this one is a session that already authenticated; counting it as
		// pressure would put every normal logout into the attack numbers
		"post-auth disconnect": `Disconnected from user alice 203.0.113.5 port 51514`,
		"client disconnect":    `Received disconnect from 203.0.113.5 port 51514:11: disconnected by user`,
		"unrelated line":       `random log line`,
		// another daemon sharing auth.log must not feed the ssh numbers
		"non-sshd program": `Aug 19 03:14:07 node1 sudo[4242]: Failed password for root from 203.0.113.9 port 55314 ssh2`,
		// the address field is always numeric in these records
		"address is not an ip": `Invalid user admin from evil.example.com port 22`,
	}
	for name, line := range cases {
		if ev, ok := ParseFailure(line); ok {
			t.Errorf("%s: parsed as a failure: %+v (%s)", name, ev, line)
		}
	}
}

// A failure line must not reach the accepted-login path, and an accepted login
// must not reach the failure path. The two reports mean different things and the
// server acts on them differently.
func TestFailureAndLoginParsersDoNotOverlap(t *testing.T) {
	failure := `Failed password for alice from 203.0.113.5 port 51514 ssh2`
	if ev, ok := Parse(failure); ok {
		t.Fatalf("failure line parsed as a login: %+v", ev)
	}
	login := `Accepted password for alice from 203.0.113.5 port 51514 ssh2`
	if ev, ok := ParseFailure(login); ok {
		t.Fatalf("login line parsed as a failure: %+v", ev)
	}
}
