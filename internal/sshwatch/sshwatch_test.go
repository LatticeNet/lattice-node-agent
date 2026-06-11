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
