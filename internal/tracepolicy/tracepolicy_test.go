package tracepolicy

import (
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-sdk/model"
)

var testNow = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func policy(enabled bool, level model.TraceLevel) model.TracePolicy {
	return model.TracePolicy{NodeID: "node-a", Enabled: enabled, Level: level}
}

func session(id string, level model.TraceLevel, ttl time.Duration) model.TraceAgentSession {
	return model.TraceAgentSession{ID: id, Level: level, ExpiresAt: testNow.Add(ttl)}
}

func line(level string) singboxlog.Line {
	return singboxlog.Line{At: testNow, Level: level, Tag: "inbound/vless[vless-entry]", TagType: "vless", TagName: "vless-entry"}
}

func TestBuildDropsExpiredSessionsAtTheBoundary(t *testing.T) {
	cases := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"expired a second ago", testNow.Add(-time.Second), false},
		{"expires exactly at now", testNow, false},
		{"expires one nanosecond later", testNow.Add(time.Nanosecond), true},
		{"no expiry at all", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := Build(model.TraceAgentConfig{
				Policy:   policy(true, model.TraceLevelInfo),
				Sessions: []model.TraceAgentSession{{ID: "s1", Level: model.TraceLevelTrace, ExpiresAt: tc.expiresAt}},
			}, testNow)
			got := len(set.ActiveSessions()) == 1
			if got != tc.want {
				t.Fatalf("session active = %v, want %v", got, tc.want)
			}
			// An expired session must not keep the node subscribed high; that
			// is the whole point of enforcing the TTL on the agent.
			wantLevel := model.TraceLevelInfo
			if tc.want {
				wantLevel = model.TraceLevelTrace
			}
			if set.SubscribeLevel() != wantLevel {
				t.Fatalf("subscribe level = %q, want %q", set.SubscribeLevel(), wantLevel)
			}
		})
	}
}

func TestBuildDropsUnusableSessions(t *testing.T) {
	set := Build(model.TraceAgentConfig{
		Policy: policy(true, model.TraceLevelInfo),
		Sessions: []model.TraceAgentSession{
			{ID: "  ", Level: model.TraceLevelTrace, ExpiresAt: testNow.Add(time.Hour)},
			{ID: "s-ok", Level: model.TraceLevelDebug, ExpiresAt: testNow.Add(time.Hour)},
		},
	}, testNow)
	active := set.ActiveSessions()
	if len(active) != 1 || active[0].ID != "s-ok" {
		t.Fatalf("active sessions = %+v, want only s-ok", active)
	}
}

func TestSubscribeLevelIsTheMaximum(t *testing.T) {
	cases := []struct {
		name     string
		policy   model.TracePolicy
		sessions []model.TraceAgentSession
		want     model.TraceLevel
	}{
		{"floor only", policy(true, model.TraceLevelInfo), nil, model.TraceLevelInfo},
		{"floor above sessions", policy(true, model.TraceLevelTrace), []model.TraceAgentSession{session("s1", model.TraceLevelInfo, time.Hour)}, model.TraceLevelTrace},
		{"session above floor", policy(true, model.TraceLevelInfo), []model.TraceAgentSession{session("s1", model.TraceLevelDebug, time.Hour)}, model.TraceLevelDebug},
		{"highest of several sessions", policy(true, model.TraceLevelInfo), []model.TraceAgentSession{
			session("s1", model.TraceLevelDebug, time.Hour),
			session("s2", model.TraceLevelTrace, time.Hour),
			session("s3", model.TraceLevelInfo, time.Hour),
		}, model.TraceLevelTrace},
		{"disabled floor does not raise the subscription", policy(false, model.TraceLevelTrace), []model.TraceAgentSession{session("s1", model.TraceLevelDebug, time.Hour)}, model.TraceLevelDebug},
		{"nothing at all falls back to info", policy(false, ""), nil, model.TraceLevelInfo},
		{"unknown level folds down to info", policy(true, model.TraceLevel("verbose")), nil, model.TraceLevelInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := Build(model.TraceAgentConfig{Policy: tc.policy, Sessions: tc.sessions}, testNow)
			if got := set.SubscribeLevel(); got != tc.want {
				t.Fatalf("subscribe level = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnabled(t *testing.T) {
	cases := []struct {
		name     string
		policy   model.TracePolicy
		sessions []model.TraceAgentSession
		want     bool
	}{
		{"floor on", policy(true, model.TraceLevelInfo), nil, true},
		{"floor off, no session", policy(false, model.TraceLevelInfo), nil, false},
		{"floor off, running session", policy(false, model.TraceLevelInfo), []model.TraceAgentSession{session("s1", model.TraceLevelDebug, time.Hour)}, true},
		{"floor off, expired session", policy(false, model.TraceLevelInfo), []model.TraceAgentSession{session("s1", model.TraceLevelDebug, -time.Hour)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := Build(model.TraceAgentConfig{Policy: tc.policy, Sessions: tc.sessions}, testNow)
			if got := set.Enabled(); got != tc.want {
				t.Fatalf("enabled = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestZeroSetKeepsNothing(t *testing.T) {
	var set Set
	if set.Enabled() {
		t.Fatal("zero set must not be enabled")
	}
	if d := set.Match(line("info"), "u_a", "example.com"); d.Keep {
		t.Fatalf("zero set kept a line: %+v", d)
	}
	if set.SubscribeLevel() != model.TraceLevelInfo {
		t.Fatalf("zero set subscribe level = %q, want info", set.SubscribeLevel())
	}
	if !set.ExpiresNext().IsZero() {
		t.Fatalf("zero set expires next = %v, want zero", set.ExpiresNext())
	}
}

func TestMatchNodeFloorLevels(t *testing.T) {
	cases := []struct {
		floor     model.TraceLevel
		lineLevel string
		want      bool
	}{
		{model.TraceLevelInfo, "info", true},
		{model.TraceLevelInfo, "warn", true},
		{model.TraceLevelInfo, "error", true},
		{model.TraceLevelInfo, "fatal", true},
		{model.TraceLevelInfo, "", true},
		{model.TraceLevelInfo, "debug", false},
		{model.TraceLevelInfo, "trace", false},
		{model.TraceLevelDebug, "debug", true},
		{model.TraceLevelDebug, "trace", false},
		{model.TraceLevelTrace, "trace", true},
		{model.TraceLevelTrace, "debug", true},
	}
	for _, tc := range cases {
		t.Run(string(tc.floor)+"/"+tc.lineLevel, func(t *testing.T) {
			set := Build(model.TraceAgentConfig{Policy: policy(true, tc.floor)}, testNow)
			d := set.Match(line(tc.lineLevel), "u_a", "example.com")
			if d.Keep != tc.want {
				t.Fatalf("keep = %v, want %v", d.Keep, tc.want)
			}
			if d.Keep && d.Level != tc.floor {
				t.Fatalf("level = %q, want %q", d.Level, tc.floor)
			}
			if len(d.SessionIDs) != 0 {
				t.Fatalf("session ids = %v, want none", d.SessionIDs)
			}
		})
	}
}

func TestMatchSessionDimensions(t *testing.T) {
	cases := []struct {
		name    string
		session model.TraceAgentSession
		line    singboxlog.Line
		user    string
		dstHost string
		want    bool
	}{
		{
			name:    "empty filter matches the whole node",
			session: session("s1", model.TraceLevelTrace, time.Hour),
			line:    line("trace"),
			want:    true,
		},
		{
			name:    "user name exact",
			session: withUsers(session("s1", model.TraceLevelDebug, time.Hour), "u_aaaa"),
			line:    line("debug"),
			user:    "u_aaaa",
			want:    true,
		},
		{
			name:    "user name is case sensitive",
			session: withUsers(session("s1", model.TraceLevelDebug, time.Hour), "u_aaaa"),
			line:    line("debug"),
			user:    "U_AAAA",
			want:    false,
		},
		{
			name:    "user name absent from the call cannot match",
			session: withUsers(session("s1", model.TraceLevelDebug, time.Hour), "u_aaaa"),
			line:    line("debug"),
			want:    false,
		},
		{
			name:    "inbound tag matches the decomposed name",
			session: withTags(session("s1", model.TraceLevelDebug, time.Hour), "vless-entry"),
			line:    line("debug"),
			want:    true,
		},
		{
			name:    "inbound tag matches the tag as sent",
			session: withTags(session("s1", model.TraceLevelDebug, time.Hour), "inbound/vless[vless-entry]"),
			line:    line("debug"),
			want:    true,
		},
		{
			name:    "inbound tag mismatch",
			session: withTags(session("s1", model.TraceLevelDebug, time.Hour), "mixed-entry"),
			line:    line("debug"),
			want:    false,
		},
		{
			name:    "dst pattern is a case insensitive substring",
			session: withDst(session("s1", model.TraceLevelDebug, time.Hour), "GITHUB"),
			line:    line("debug"),
			dstHost: "api.github.com",
			want:    true,
		},
		{
			name:    "dst pattern is not a glob",
			session: withDst(session("s1", model.TraceLevelDebug, time.Hour), "*.github.com"),
			line:    line("debug"),
			dstHost: "api.github.com",
			want:    false,
		},
		{
			name:    "dst pattern with no host cannot match",
			session: withDst(session("s1", model.TraceLevelDebug, time.Hour), "github"),
			line:    line("debug"),
			want:    false,
		},
		{
			name:    "all dimensions must match, one misses",
			session: withDst(withUsers(session("s1", model.TraceLevelDebug, time.Hour), "u_aaaa"), "github"),
			line:    line("debug"),
			user:    "u_aaaa",
			dstHost: "example.com",
			want:    false,
		},
		{
			name:    "all dimensions match",
			session: withDst(withTags(withUsers(session("s1", model.TraceLevelDebug, time.Hour), "u_aaaa"), "vless-entry"), "github"),
			line:    line("debug"),
			user:    "u_aaaa",
			dstHost: "api.github.com",
			want:    true,
		},
		{
			name:    "blank filter entries read as no constraint",
			session: withUsers(session("s1", model.TraceLevelDebug, time.Hour), "  "),
			line:    line("debug"),
			want:    true,
		},
		{
			name:    "session never sees above its own level",
			session: session("s1", model.TraceLevelDebug, time.Hour),
			line:    line("trace"),
			want:    false,
		},
		{
			name:    "tag only session matches with no user and no host",
			session: withTags(session("s1", model.TraceLevelTrace, time.Hour), "vless-entry"),
			line:    line("trace"),
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The node floor is info, so every debug or trace line here is kept
			// only when the session itself asked for it.
			set := Build(model.TraceAgentConfig{
				Policy:   policy(true, model.TraceLevelInfo),
				Sessions: []model.TraceAgentSession{tc.session},
			}, testNow)
			d := set.Match(tc.line, tc.user, tc.dstHost)
			if d.Keep != tc.want {
				t.Fatalf("keep = %v, want %v (decision %+v)", d.Keep, tc.want, d)
			}
			if tc.want {
				if !reflect.DeepEqual(d.SessionIDs, []string{"s1"}) {
					t.Fatalf("session ids = %v, want [s1]", d.SessionIDs)
				}
				if d.Level != tc.session.Level {
					t.Fatalf("level = %q, want %q", d.Level, tc.session.Level)
				}
			} else if len(d.SessionIDs) != 0 {
				t.Fatalf("session ids = %v, want none", d.SessionIDs)
			}
		})
	}
}

func TestMatchLabelsFloorKeptLinesToo(t *testing.T) {
	// An info line passes the floor on its own, but a session tailing that user
	// still needs it: the raw lines are what the operator reads.
	set := Build(model.TraceAgentConfig{
		Policy: policy(true, model.TraceLevelInfo),
		Sessions: []model.TraceAgentSession{
			withUsers(session("s1", model.TraceLevelInfo, time.Hour), "u_aaaa"),
		},
	}, testNow)
	d := set.Match(line("info"), "u_aaaa", "example.com")
	if !d.Keep || !reflect.DeepEqual(d.SessionIDs, []string{"s1"}) {
		t.Fatalf("decision = %+v, want kept and labelled s1", d)
	}
	if d.Level != model.TraceLevelInfo {
		t.Fatalf("level = %q, want info", d.Level)
	}
}

func TestMatchMultipleSessionsGiveSortedIDs(t *testing.T) {
	set := Build(model.TraceAgentConfig{
		Policy: policy(true, model.TraceLevelInfo),
		Sessions: []model.TraceAgentSession{
			withUsers(session("s-zulu", model.TraceLevelDebug, time.Hour), "u_aaaa"),
			session("s-alpha", model.TraceLevelTrace, time.Hour),
			withDst(session("s-mike", model.TraceLevelDebug, time.Hour), "github"),
			withUsers(session("s-other", model.TraceLevelTrace, time.Hour), "u_bbbb"),
		},
	}, testNow)
	d := set.Match(line("debug"), "u_aaaa", "api.github.com")
	want := []string{"s-alpha", "s-mike", "s-zulu"}
	if !reflect.DeepEqual(d.SessionIDs, want) {
		t.Fatalf("session ids = %v, want %v", d.SessionIDs, want)
	}
	// The most verbose matching session is what justified keeping the line.
	if d.Level != model.TraceLevelTrace {
		t.Fatalf("level = %q, want trace", d.Level)
	}
}

func TestMatchDisabledFloorStillKeepsSessionLines(t *testing.T) {
	set := Build(model.TraceAgentConfig{
		Policy: policy(false, model.TraceLevelTrace),
		Sessions: []model.TraceAgentSession{
			withUsers(session("s1", model.TraceLevelInfo, time.Hour), "u_aaaa"),
		},
	}, testNow)
	if d := set.Match(line("info"), "u_bbbb", ""); d.Keep {
		t.Fatalf("unrelated line kept with the floor off: %+v", d)
	}
	d := set.Match(line("info"), "u_aaaa", "")
	if !d.Keep || d.Level != model.TraceLevelInfo {
		t.Fatalf("decision = %+v, want kept at info", d)
	}
}

func TestActiveSessionsIsACopy(t *testing.T) {
	set := Build(model.TraceAgentConfig{
		Policy: policy(true, model.TraceLevelInfo),
		Sessions: []model.TraceAgentSession{
			session("s2", model.TraceLevelDebug, time.Hour),
			session("s1", model.TraceLevelInfo, 2*time.Hour),
		},
	}, testNow)
	active := set.ActiveSessions()
	if len(active) != 2 || active[0].ID != "s1" || active[1].ID != "s2" {
		t.Fatalf("active = %+v, want sorted s1, s2", active)
	}
	active[0].ID = "tampered"
	if set.ActiveSessions()[0].ID != "s1" {
		t.Fatal("mutating the returned slice changed the set")
	}
}

func TestExpiresNextIsTheEarliest(t *testing.T) {
	set := Build(model.TraceAgentConfig{Policy: policy(true, model.TraceLevelInfo)}, testNow)
	if !set.ExpiresNext().IsZero() {
		t.Fatalf("expires next = %v, want zero with no sessions", set.ExpiresNext())
	}
	set = Build(model.TraceAgentConfig{
		Policy: policy(true, model.TraceLevelInfo),
		Sessions: []model.TraceAgentSession{
			session("s1", model.TraceLevelInfo, 2*time.Hour),
			session("s2", model.TraceLevelInfo, 30*time.Minute),
			session("s3", model.TraceLevelInfo, -time.Minute),
		},
	}, testNow)
	if want := testNow.Add(30 * time.Minute); !set.ExpiresNext().Equal(want) {
		t.Fatalf("expires next = %v, want %v", set.ExpiresNext(), want)
	}
}

func withUsers(s model.TraceAgentSession, users ...string) model.TraceAgentSession {
	s.UserNames = users
	return s
}

func withTags(s model.TraceAgentSession, tags ...string) model.TraceAgentSession {
	s.InboundTags = tags
	return s
}

func withDst(s model.TraceAgentSession, patterns ...string) model.TraceAgentSession {
	s.DstPatterns = patterns
	return s
}
