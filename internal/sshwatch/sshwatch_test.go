package sshwatch

import (
	"context"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		line       string
		ok         bool
		user, addr string
		method     string
	}{
		{"Jun 11 04:00:01 host sshd[123]: Accepted password for alice from 203.0.113.5 port 51514 ssh2", true, "alice", "203.0.113.5", "password"},
		{"Accepted publickey for bob from 2001:db8::1 port 40022 ssh2: RSA SHA256:abc", true, "bob", "2001:db8::1", "publickey"},
		{"Accepted password for invalid user root from 10.0.0.9 port 22 ssh2", true, "root", "10.0.0.9", "password"},
		{"Failed password for alice from 203.0.113.5 port 51514 ssh2", false, "", "", ""},
		{"random log line", false, "", "", ""},
		// C18: the "Accepted ... for ... from ..." text must begin the sshd
		// message. A hostile username echoed by sshd in a Failed/Invalid-user
		// line embeds the substring mid-message and must NOT forge an event.
		{`Jun 11 04:00:01 host sshd[123]: Invalid user Accepted password for attacker from 6.6.6.6 from 203.0.113.5 port 51514 ssh2`, false, "", "", ""},
		{`Jun 11 04:00:01 host sshd[123]: Failed password for "Accepted password for evil from 1.1.1.1" from 203.0.113.5 port 51514 ssh2`, false, "", "", ""},
		// A genuine accepted-login line with the standard syslog sshd[pid] prefix
		// must still match and parse correctly.
		{`Jun 11 04:00:01 host sshd[123]: Accepted publickey for carol from 198.51.100.7 port 4242 ssh2: ED25519 SHA256:xyz`, true, "carol", "198.51.100.7", "publickey"},
		// OpenSSH 9.8 (Debian 13 / trixie) logs the accepted line from the
		// sshd-session helper, under its own program tag, in both the BSD and
		// the ISO-8601 syslog framings. Both must parse like plain sshd.
		{`Sep  4 03:14:07 gomami-hkg sshd-session[4321]: Accepted publickey for root from 203.0.113.9 port 51514 ssh2: ED25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAA`, true, "root", "203.0.113.9", "publickey"},
		{`2026-09-04T03:14:07.123456+00:00 gomami-jpn sshd-session[4321]: Accepted publickey for root from 2001:db8::9 port 51514 ssh2: ED25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAA`, true, "root", "2001:db8::9", "publickey"},
		// The pre-9.8 tag keeps working alongside it.
		{`Sep  4 03:14:07 dmit-1 sshd[77]: Accepted publickey for root from 203.0.113.10 port 4242 ssh2: ED25519 SHA256:xyz`, true, "root", "203.0.113.10", "publickey"},
		// Other program tags never produce a login, even with the same text.
		{`Sep  4 03:14:07 host sudo[5]: Accepted publickey for root from 203.0.113.9 port 1 ssh2`, false, "", "", ""},
	}
	for _, c := range cases {
		ev, ok := Parse(c.line)
		if ok != c.ok {
			t.Fatalf("Parse(%q) ok=%v want %v", c.line, ok, c.ok)
		}
		if ok && (ev.User != c.user || ev.Address != c.addr || ev.Method != c.method) {
			t.Fatalf("Parse(%q) = %+v, want user=%s addr=%s method=%s", c.line, ev, c.user, c.addr, c.method)
		}
	}
}

func TestStream(t *testing.T) {
	input := strings.Join([]string{
		"Accepted password for alice from 1.2.3.4 port 22 ssh2",
		"some noise",
		"Accepted publickey for bob from 5.6.7.8 port 22 ssh2",
	}, "\n")
	var got []LoginEvent
	if err := Stream(context.Background(), strings.NewReader(input), func(ev LoginEvent) { got = append(got, ev) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "alice" || got[1].User != "bob" {
		t.Fatalf("unexpected events: %+v", got)
	}
}
