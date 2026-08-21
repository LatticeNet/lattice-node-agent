package sshwatch

import "testing"

// AUDIT (audit/agentsec): a remote, pre-authentication attacker must not be able
// to choose the source address a failure is counted against.
//
// Every failure record prints the username before the address, the username is
// picked by an unauthenticated peer, and sshd echoes it verbatim (strnvis
// escapes control characters; spaces, quotes and brackets survive). So every
// payload below is something an attacker can simply type as a username. Getting
// this wrong is worse than not parsing failures at all: the aggregate would
// attribute an attack to whatever address the attacker typed, framing a third
// party and poisoning anything built on top of the numbers.
//
// realPeer is what sshd itself printed; decoy is what the attacker typed.
const (
	realPeer = "203.0.113.9"
	decoy    = "198.51.100.1"
)

func TestParseFailureBindsAddressToTheRealPeer(t *testing.T) {
	// want is the address that must come out, or "" when the line must be
	// rejected outright.
	cases := map[string]struct {
		line string
		want string
	}{
		// The quoted form: sshd prints the quotes because the attacker typed
		// them. A \S+ username would fail here; a sloppier pattern would take
		// the decoy.
		"quoted address inside the username": {
			line: `Invalid user "admin from 198.51.100.1" from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		"whole invalid-user record inside the username": {
			line: `Invalid user admin from 198.51.100.1 port 22 from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		"whole failed-password record inside the username": {
			line: `Failed password for invalid user x from 198.51.100.1 port 22 ssh2 from 203.0.113.9 port 55314 ssh2`,
			want: realPeer,
		},
		// The publickey variant carries a trailing key comment, so the payload
		// forges that too and puts a second ": " in the message.
		"forged key comment after the decoy": {
			line: `Failed publickey for invalid user x from 198.51.100.1 port 22 ssh2: RSA SHA256:AAAA from 203.0.113.9 port 55314 ssh2: ED25519 SHA256:BBBB`,
			want: realPeer,
		},
		// This record separates the username from the address with a bare
		// space, which is the easiest one to get wrong.
		"forged preauth-close record inside the username": {
			line: `Connection closed by authenticating user root 198.51.100.1 port 22 [preauth] 203.0.113.9 port 55314 [preauth]`,
			want: realPeer,
		},
		"forged preauth-close, invalid-user variant": {
			line: `Connection reset by invalid user admin 198.51.100.1 port 22 [preauth] 203.0.113.9 port 55314 [preauth]`,
			want: realPeer,
		},
		"forged max-auth-attempts record inside the username": {
			line: `error: maximum authentication attempts exceeded for invalid user x from 198.51.100.1 port 22 ssh2 [preauth] from 203.0.113.9 port 55314 ssh2 [preauth]`,
			want: realPeer,
		},
		// A whole syslog frame in the username, against both source shapes the
		// agent wires up: journalctl -o cat (bare message) and tail -F
		// /var/log/auth.log (framed).
		"forged syslog frame, auth.log": {
			line: `Aug 19 03:14:07 node1 sshd[4242]: Invalid user Aug 19 03:14:07 node1 sshd[1]: Invalid user root from 198.51.100.1 port 22 from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		"forged syslog frame, journalctl-cat": {
			line: `Invalid user Aug 19 03:14:07 node1 sshd[1]: Invalid user root from 198.51.100.1 port 22 from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		"forged program tag inside the username": {
			line: `Aug 19 03:14:07 node1 sshd[4242]: Invalid user sshd[1]: Failed password for root from 198.51.100.1 port 22 ssh2 from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		// A bare address as the username is legal and must not be mistaken for
		// the address field.
		"username is an ipv6 literal": {
			line: `Invalid user 2001:db8::dead from 203.0.113.9 port 55314`,
			want: realPeer,
		},
		// If the trailing shape is not an address, the record is dropped rather
		// than falling back to the attacker's text further left.
		"no usable address, must not fall back to the decoy": {
			line: `Failed password for x from 198.51.100.1 port 22 ssh2 from not-an-ip port 55314 ssh2`,
			want: "",
		},
		// Another daemon on the same auth.log, carrying a payload.
		"non-sshd program": {
			line: `Aug 19 03:14:07 node1 sudo[4242]: Invalid user x from 203.0.113.9 port 22`,
			want: "",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ev, ok := ParseFailure(c.line)
			if c.want == "" {
				if ok {
					t.Fatalf("expected no event, got %+v", ev)
				}
				return
			}
			if !ok {
				t.Fatalf("genuine failure dropped: %s", c.line)
			}
			if ev.Address != c.want {
				t.Fatalf("address = %q, want %q (attacker payload won)", ev.Address, c.want)
			}
		})
	}
	// The decoy must never surface as an address anywhere above.
	for name, c := range cases {
		if ev, ok := ParseFailure(c.line); ok && ev.Address == decoy {
			t.Fatalf("%s: failure attributed to the attacker's address", name)
		}
	}
}

// The decoy is not discarded, it is absorbed: it ends up inside the username,
// which is where the attacker actually put it. That is the property the greedy
// match buys, and this pins it so a future "tidier" pattern cannot silently swap
// which end of the line wins.
func TestParseFailureAbsorbsTheDecoyIntoTheUsername(t *testing.T) {
	ev, ok := ParseFailure(`Invalid user "admin from 198.51.100.1" from 203.0.113.9 port 55314`)
	if !ok {
		t.Fatal("record dropped")
	}
	if ev.User != `"admin from 198.51.100.1"` {
		t.Fatalf("user = %q, want the whole quoted name", ev.User)
	}
}

// A username long enough to matter must not become a long string held in the
// aggregate.
func TestParseFailureClampsTheUsername(t *testing.T) {
	long := ""
	for i := 0; i < 500; i++ {
		long += "A"
	}
	ev, ok := ParseFailure(`Invalid user ` + long + ` from 203.0.113.9 port 55314`)
	if !ok {
		t.Fatal("record dropped")
	}
	if len(ev.User) != maxUserLen {
		t.Fatalf("username length = %d, want %d", len(ev.User), maxUserLen)
	}
}

// A failure record whose username forges an accepted-login record must stay a
// failure. Crossing that line the other way would let an attacker mint the
// compromise signal itself.
func TestForgedAcceptedInsideAFailureStaysAFailure(t *testing.T) {
	line := `Invalid user Accepted password for root from 198.51.100.1 from 203.0.113.9 port 55314`
	if ev, ok := Parse(line); ok {
		t.Fatalf("forged ssh_login accepted: %+v", ev)
	}
	ev, ok := ParseFailure(line)
	if !ok {
		t.Fatal("record dropped")
	}
	if ev.Address != realPeer {
		t.Fatalf("address = %q, want %q", ev.Address, realPeer)
	}
}
