// Package tracepolicy merges a node's trace collection policy with the trace
// sessions currently running on it, and answers the two questions the agent
// asks: what verbosity to subscribe at on the Clash API, and, for each parsed
// line, whether the line is kept and under whose session id.
//
// It is pure. No I/O, no goroutines, no clock of its own: the expiry cut is
// made against a time the caller passes in, because the agent enforces session
// TTLs itself. A session has to stop even if the server never says so, since
// an unbounded trace left running on a node is a privacy and disk problem
// nobody would notice.
//
// The subscribe-high, keep-narrow split is the whole point of the package.
// sing-box emits to Clash API subscribers without applying log.level, so one
// operator tracing one user forces the agent to subscribe at that user's level
// for the entire node. Keeping only what a session asked for is what stops
// that from multiplying the node's ingest.
package tracepolicy

import (
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Decision is what to do with one parsed line.
type Decision struct {
	// Keep is false for a line nobody asked for. Those lines are not evidence
	// of anything anyone is looking at, so they never enter a batch.
	Keep bool
	// SessionIDs are the sessions that asked for this line, in sorted order so
	// that the same input always produces the same batch.
	SessionIDs []string
	// Level is the verbosity that justified keeping the line: the node floor
	// where the floor alone would have kept it, otherwise the most verbose
	// session that matched. Empty when Keep is false.
	Level model.TraceLevel
}

// Set is the merged policy: the node floor plus the sessions still running.
// The zero Set keeps nothing, which is the safe state for an agent that has
// not yet heard from the server.
type Set struct {
	nodeEnabled bool
	nodeLevel   model.TraceLevel
	// sessions is held sorted by id, so Match can append ids in order without
	// sorting per line.
	sessions    []model.TraceAgentSession
	subscribe   model.TraceLevel
	expiresNext time.Time
}

// Build merges cfg into a Set, dropping every session that has expired at now.
//
// now is the caller's decision, not this package's: TraceAgentConfig carries
// ServerTime so the agent can bound clock skew, and the caller passes whatever
// clock it decided to trust. Build does not silently correct one against the
// other, because a policy that quietly extends its own TTL is the failure this
// enforcement exists to prevent.
//
// A session is expired at exactly its ExpiresAt, matching
// model.TraceSession.Active. A session with no ExpiresAt is malformed and is
// dropped for the same reason: nothing here may capture without a deadline.
func Build(cfg model.TraceAgentConfig, now time.Time) Set {
	s := Set{
		nodeEnabled: cfg.Policy.Enabled,
		nodeLevel:   normalizeLevel(cfg.Policy.Level),
		subscribe:   model.TraceLevelInfo,
	}
	if s.nodeEnabled {
		s.subscribe = s.nodeLevel
	}
	for _, raw := range cfg.Sessions {
		sess, ok := normalizeSession(raw)
		if !ok {
			continue
		}
		if !sess.ExpiresAt.After(now) {
			continue
		}
		s.sessions = append(s.sessions, sess)
		if model.TraceLevelAtLeast(sess.Level, s.subscribe) {
			s.subscribe = sess.Level
		}
		if s.expiresNext.IsZero() || sess.ExpiresAt.Before(s.expiresNext) {
			s.expiresNext = sess.ExpiresAt
		}
	}
	sort.Slice(s.sessions, func(i, j int) bool { return s.sessions[i].ID < s.sessions[j].ID })
	return s
}

// SubscribeLevel is what the agent asks sing-box for: the most verbose of the
// node floor and every running session. Subscribing lower would lose lines a
// session was started to see; subscribing higher costs the core a formatted
// message per line for nobody.
func (s Set) SubscribeLevel() model.TraceLevel {
	if s.subscribe == "" {
		return model.TraceLevelInfo
	}
	return s.subscribe
}

// Enabled reports whether the agent should be collecting at all. A running
// session turns collection on even when the node floor is off, because an
// operator who started a trace on this node asked for exactly that.
func (s Set) Enabled() bool {
	return s.nodeEnabled || len(s.sessions) > 0
}

// Match decides one line. user and dstHost come from the caller rather than
// from the line, because a single log line usually carries neither: the
// assembler knows the connection the line belongs to and resolves both from
// it. The line's own User and DstHost fields are deliberately not consulted,
// so that a line arriving before the connection is identified cannot match a
// filter the assembler would have answered differently.
//
// Both may be empty, and then only a session that matches the whole node or
// one constrained solely by inbound tag can match.
func (s Set) Match(l singboxlog.Line, user, dstHost string) Decision {
	var d Decision
	if !s.Enabled() {
		return d
	}
	lineLevel := normalizeLevel(model.TraceLevel(l.Level))
	var best model.TraceLevel
	for _, sess := range s.sessions {
		// A session never sees past its own level, whatever the agent happens
		// to be subscribed at for someone else.
		if !model.TraceLevelAtLeast(sess.Level, lineLevel) {
			continue
		}
		if !sessionMatches(sess, l, user, dstHost) {
			continue
		}
		d.SessionIDs = append(d.SessionIDs, sess.ID)
		if best == "" || model.TraceLevelAtLeast(sess.Level, best) {
			best = sess.Level
		}
	}
	floorKeeps := s.nodeEnabled && model.TraceLevelAtLeast(s.nodeLevel, lineLevel)
	d.Keep = floorKeeps || len(d.SessionIDs) > 0
	switch {
	case floorKeeps:
		d.Level = s.nodeLevel
	case d.Keep:
		d.Level = best
	}
	return d
}

// ActiveSessions returns the sessions that survived the expiry cut, sorted by
// id. The slice is a copy: a caller that reports session stats must not be
// able to reach back into the policy it was handed.
// Policy returns the node policy this set was built from, so a caller can
// rebuild the set locally when a session expires without a fresh config fetch.
func (s Set) Policy() model.TracePolicy {
	return model.TracePolicy{
		Enabled: s.nodeEnabled,
		Level:   s.nodeLevel,
	}
}

func (s Set) ActiveSessions() []model.TraceAgentSession {
	if len(s.sessions) == 0 {
		return nil
	}
	out := make([]model.TraceAgentSession, len(s.sessions))
	copy(out, s.sessions)
	return out
}

// ExpiresNext is when the earliest running session expires, zero if none is
// running. The caller uses it to schedule the next rebuild, so that a session
// ends on time instead of at the next poll.
func (s Set) ExpiresNext() time.Time {
	return s.expiresNext
}

func sessionMatches(sess model.TraceAgentSession, l singboxlog.Line, user, dstHost string) bool {
	// Every non-empty dimension must match. An empty dimension is no
	// constraint, so a session with all three empty captures the node.
	if len(sess.UserNames) > 0 && !containsExact(sess.UserNames, user) {
		return false
	}
	if len(sess.InboundTags) > 0 && !matchesInboundTag(sess.InboundTags, l) {
		return false
	}
	if len(sess.DstPatterns) > 0 && !matchesDstPattern(sess.DstPatterns, dstHost) {
		return false
	}
	return true
}

// containsExact is case-sensitive on purpose: sing-box user names are the
// u_<16hex> credentials Lattice rendered, and a case-folded match there would
// silently widen a filter across two distinct users.
func containsExact(values []string, want string) bool {
	if want == "" {
		return false
	}
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// matchesInboundTag accepts either the decomposed tag name ("vless-entry") or
// the tag exactly as sing-box sent it ("inbound/vless[vless-entry]"). The
// server expands line uuids into tag names, so the first is the normal case;
// the second keeps the bare tags (router, dns, connection) addressable.
func matchesInboundTag(tags []string, l singboxlog.Line) bool {
	for _, t := range tags {
		if t == l.TagName || t == l.Tag {
			return true
		}
	}
	return false
}

// matchesDstPattern is a case-insensitive substring test, not a glob: a
// substring is what an operator types when they mean "anything at this host".
func matchesDstPattern(patterns []string, dstHost string) bool {
	if dstHost == "" {
		return false
	}
	host := strings.ToLower(dstHost)
	for _, p := range patterns {
		if strings.Contains(host, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// normalizeSession trims the session and reports whether it is usable. A
// session with no id cannot label anything, so it is dropped rather than
// applied anonymously.
func normalizeSession(sess model.TraceAgentSession) (model.TraceAgentSession, bool) {
	sess.ID = strings.TrimSpace(sess.ID)
	if sess.ID == "" {
		return sess, false
	}
	sess.Level = normalizeLevel(sess.Level)
	sess.UserNames = cleanStrings(sess.UserNames)
	sess.InboundTags = cleanStrings(sess.InboundTags)
	sess.DstPatterns = cleanStrings(sess.DstPatterns)
	return sess, true
}

// cleanStrings drops blank entries so that a filter sent as [""] reads as no
// constraint rather than as a constraint nothing can satisfy.
func cleanStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeLevel folds an unknown level down to info rather than up. An agent
// that cannot read a level must not start collecting more than it was asked
// for; info is the always-on floor and is never a surprise.
func normalizeLevel(l model.TraceLevel) model.TraceLevel {
	candidate := model.TraceLevel(strings.ToLower(strings.TrimSpace(string(l))))
	if model.ValidTraceLevel(candidate) {
		return candidate
	}
	return model.TraceLevelInfo
}
