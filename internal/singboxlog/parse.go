package singboxlog

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Parsed reports whether the line was classified into a modelled event.
//
// A false result is the drift signal: the line reached the parser and its
// structure (id, tag, message) was read, but the message shape is one this
// package does not model. Callers should count these and alarm on a rising
// rate rather than dropping the line, because Raw still holds the evidence.
func (l Line) Parsed() bool { return l.Event != EventOther }

// ParseEntry parses one raw JSON entry from the Clash API /logs stream.
//
// The error is reserved for a payload that is not JSON at all. A payload whose
// message is unrecognised is not an error; it comes back as EventOther.
func ParseEntry(data []byte, at time.Time) (Line, error) {
	var entry struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return Line{At: at, Event: EventOther, Raw: string(data)}, fmt.Errorf("singboxlog: decode entry: %w", err)
	}
	return ParsePayload(entry.Payload, entry.Type, at), nil
}

// ParsePayload parses one /logs payload, "[<id> <elapsed>] <tag>: <message>".
// The level is carried alongside the payload in the entry, not inside it.
func ParsePayload(raw string, level string, at time.Time) Line {
	line := Line{At: at, Level: level, Raw: raw, Event: EventOther}
	parseBody(&line, stripANSI(raw))
	return line
}

// ParseFileLine parses one stderr or log-file line, which prefixes the payload
// form with a timestamp and the level:
//
//	-0700 2026-08-26 00:02:38 ERROR [2099970926 0ms] connection: open connection to ...
//
// The timestamp is written by sing-box but Line has nowhere to keep it, so the
// caller's at wins and the whole line is preserved in Raw instead. The reported
// level is lower-cased so it matches the Clash API spelling.
//
// It returns false when no level token is present, which is the only structural
// marker separating this shape from an arbitrary line of program output.
func ParseFileLine(raw string, at time.Time) (Line, bool) {
	level, body, ok := cutFileLevel(strings.TrimRight(stripANSI(raw), "\r\n"))
	if !ok {
		return Line{At: at, Event: EventOther, Raw: raw}, false
	}
	line := Line{At: at, Level: level, Raw: raw, Event: EventOther}
	parseBody(&line, body)
	return line, true
}

// parseBody fills everything that both entry points share: the id prefix, the
// tag, and the event classification.
func parseBody(l *Line, body string) {
	rest := strings.TrimSpace(body)
	if id, elapsed, tail, ok := cutLogID(rest); ok {
		l.LogID, l.HasLogID, l.ElapsedMS = id, true, elapsed
		rest = tail
	}
	l.Tag, l.Message = cutTag(rest)
	l.TagKind, l.TagType, l.TagName = decomposeTag(l.Tag)
	classify(l, l.Message)
}

// cutFileLevel finds the level token and returns everything after it. The
// timestamp layout is configurable, so the token is located by value rather
// than by position, bounded to the first few tokens so that the word ERROR
// inside a message can never be mistaken for the level.
func cutFileLevel(s string) (level string, rest string, ok bool) {
	const maxTokens = 4
	i := 0
	for token := 0; token < maxTokens; token++ {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != ' ' {
			i++
		}
		if start == i {
			break
		}
		if lower, isLevel := fileLevel(s[start:i]); isLevel {
			return lower, strings.TrimLeft(s[i:], " "), true
		}
	}
	return "", "", false
}

func fileLevel(token string) (string, bool) {
	switch token {
	case "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "PANIC":
		return strings.ToLower(token), true
	}
	return "", false
}

// cutLogID reads the "[<id> <elapsed>]" prefix. Lines from subsystems with no
// connection context have no prefix at all, which is not an error.
func cutLogID(s string) (id uint32, elapsedMS int64, rest string, ok bool) {
	if !strings.HasPrefix(s, "[") {
		return 0, 0, "", false
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return 0, 0, "", false
	}
	idText, durText, found := strings.Cut(s[1:end], " ")
	if !found {
		return 0, 0, "", false
	}
	n, err := strconv.ParseUint(idText, 10, 32)
	if err != nil {
		return 0, 0, "", false
	}
	// An unreadable duration must not cost us the id, which is the only key
	// the assembler has for grouping a connection.
	ms, _ := parseElapsedMS(durText)
	return uint32(n), ms, strings.TrimPrefix(s[end+1:], " "), true
}

// parseElapsedMS converts sing-box's own duration spelling to milliseconds.
//
// log/format.go FormatDuration prints sub-second values as "<ms>ms", values
// under a minute as int64(seconds) "." int64(seconds*100)%100 "s", and longer
// ones as "<minutes>m<seconds>s". The middle form does NOT zero-pad, so "1.4s"
// is 4 centiseconds past one second, that is 1040ms, not 1400ms. Reading the
// fraction as centiseconds is right for both that spelling and a zero-padded
// one, so it survives the day upstream fixes the padding.
//
// A fraction longer than two digits cannot be centiseconds, so it falls through
// to the standard decoder along with the forms sing-box never emits but a
// future or patched build might ("1.5m", "2h").
func parseElapsedMS(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	if v, ok := strings.CutSuffix(s, "ms"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	if v, ok := strings.CutSuffix(s, "s"); ok {
		if seconds, frac, found := strings.Cut(v, "."); found &&
			len(frac) >= 1 && len(frac) <= 2 && allDigits(seconds) && allDigits(frac) {
			whole, err := strconv.ParseInt(seconds, 10, 64)
			if err != nil {
				return 0, false
			}
			centis, err := strconv.ParseInt(frac, 10, 64)
			if err != nil {
				return 0, false
			}
			return whole*1000 + centis*10, true
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d.Milliseconds(), true
}

// cutTag splits "<tag>: <message>". Tags never contain a space, so a candidate
// that does means the line was logged with no tag and the colon belongs to the
// message.
func cutTag(s string) (tag string, message string) {
	i := strings.Index(s, ": ")
	if i <= 0 {
		return "", s
	}
	candidate := s[:i]
	if strings.ContainsAny(candidate, " \t") {
		return "", s
	}
	return candidate, s[i+2:]
}

// decomposeTag splits "<kind>/<type>[<name>]" and the bare subsystem tags.
// An unknown kind still gets decomposed so that a tag family added upstream
// keeps its type and name visible while its TagKind reads TagOther.
func decomposeTag(tag string) (TagKind, string, string) {
	if tag == "" {
		return TagOther, "", ""
	}
	kind, rest, ok := strings.Cut(tag, "/")
	if !ok {
		switch tag {
		case "inbound":
			return TagInbound, "", ""
		case "outbound":
			return TagOutbound, "", ""
		case "router":
			return TagRouter, "", ""
		case "connection":
			return TagConnection, "", ""
		case "dns":
			return TagDNS, "", ""
		}
		return TagOther, "", ""
	}
	tagKind := TagOther
	switch kind {
	case "inbound":
		tagKind = TagInbound
	case "outbound":
		tagKind = TagOutbound
	case "dns":
		tagKind = TagDNS
	}
	tagType, tagName := rest, ""
	if i := strings.IndexByte(rest, '['); i >= 0 && strings.HasSuffix(rest, "]") {
		tagType, tagName = rest[:i], rest[i+1:len(rest)-1]
	}
	return tagKind, tagType, tagName
}

func classify(l *Line, message string) {
	body := message
	// Only the inbound handlers prefix the message with the authenticated
	// user, so the bracket is read as a user only in front of those.
	if user, tail, ok := cutUserPrefix(message); ok && strings.HasPrefix(tail, "inbound ") {
		l.User = user
		body = tail
	}

	switch {
	case strings.HasPrefix(body, "inbound "):
		if classifyInbound(l, body[len("inbound "):]) {
			return
		}
	case strings.HasPrefix(body, "outbound "):
		if classifyOutbound(l, body[len("outbound "):]) {
			return
		}
	case strings.HasPrefix(body, "match["), strings.HasPrefix(body, "pre-match["):
		if classifyRuleMatch(l, body) {
			return
		}
	case strings.HasPrefix(body, "sniffed protocol: "):
		classifySniffed(l, body[len("sniffed protocol: "):])
		return
	case strings.HasPrefix(body, "open "):
		if classifyDialFailure(l, body) {
			return
		}
	case strings.HasPrefix(body, "process connection from "):
		classifyAuthFailure(l, body[len("process connection from "):])
		return
	case strings.HasPrefix(body, "connection "):
		if classifyConnection(l, body[len("connection "):]) {
			return
		}
	case strings.HasPrefix(body, "lookup "):
		if classifyLookup(l, body[len("lookup "):]) {
			return
		}
	}

	// The dns subsystem has more shapes than are worth modelling, "exchanged"
	// chief among them. The tag is enough to route them without guessing at
	// fields the message may not carry.
	if l.TagKind == TagDNS {
		l.Event = EventDNS
		return
	}
	l.Event = EventOther
}

// cutUserPrefix reads the "[<user>] " prefix the inbound handlers write after
// authentication. An unnamed user is logged as its index in the user list
// (protocol/vless/inbound.go:175-180), which is not an identity, so the
// returned user is empty and the caller learns only that the line was
// authenticated.
func cutUserPrefix(s string) (user string, rest string, ok bool) {
	if !strings.HasPrefix(s, "[") {
		return "", "", false
	}
	end := strings.Index(s, "] ")
	if end < 0 {
		return "", "", false
	}
	user = s[1:end]
	if user == "" || allDigits(user) {
		user = ""
	}
	return user, s[end+2:], true
}

func classifyInbound(l *Line, rest string) bool {
	if qualifier, dst, ok := cutQualified(rest, "connection to "); ok {
		l.Event = EventInboundTo
		l.Packet = strings.Contains(qualifier, "packet")
		l.DstHost, l.DstPort = splitHostPort(dst)
		return true
	}
	if qualifier, src, ok := cutQualified(rest, "connection from "); ok {
		l.Event = EventInboundFrom
		l.Packet = strings.Contains(qualifier, "packet")
		l.SrcIP, l.SrcPort = splitHostPort(src)
		return true
	}
	// A packet conversation with no fixed destination logs the bare form
	// (protocol/mixed/inbound.go:154).
	if qualifier, ok := strings.CutSuffix(rest, "connection"); ok && isQualifier(qualifier) {
		l.Event = EventInboundTo
		l.Packet = strings.Contains(qualifier, "packet")
		return true
	}
	return false
}

func classifyOutbound(l *Line, rest string) bool {
	if qualifier, dst, ok := cutQualified(rest, "connection to "); ok {
		l.Event = EventOutboundTo
		l.Packet = strings.Contains(qualifier, "packet")
		l.DstHost, l.DstPort = splitHostPort(dst)
		return true
	}
	if qualifier, ok := strings.CutSuffix(rest, "connection"); ok && isQualifier(qualifier) {
		l.Event = EventOutboundTo
		l.Packet = strings.Contains(qualifier, "packet")
		return true
	}
	return false
}

// cutQualified splits on sep only when what precedes it is a bare word run,
// which is how the connection messages spell their variants ("packet ",
// "multiplex ", "UoT packet "). It keeps an unrelated message that happens to
// contain the separator from being read as a connection line.
func cutQualified(s string, sep string) (qualifier string, value string, ok bool) {
	before, after, found := strings.Cut(s, sep)
	if !found || !isQualifier(before) {
		return "", "", false
	}
	return before, after, true
}

func isQualifier(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ':
		default:
			return false
		}
	}
	return true
}

// classifyRuleMatch reads "match[<n>] <rule> => <action>" and the condition-less
// "match[<n>] => <action>" that a rule with no matcher produces, plus the
// pre-match spelling of both (route/route.go:471-482).
func classifyRuleMatch(l *Line, body string) bool {
	rest := body
	if trimmed, ok := strings.CutPrefix(rest, "pre-match["); ok {
		rest = trimmed
	} else {
		rest = strings.TrimPrefix(rest, "match[")
	}
	index, tail, ok := strings.Cut(rest, "] ")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(index)
	if err != nil {
		return false
	}
	var ruleText, action string
	if trimmed, ok := strings.CutPrefix(tail, "=> "); ok {
		action = trimmed
	} else if i := strings.LastIndex(tail, " => "); i >= 0 {
		ruleText, action = tail[:i], tail[i+len(" => "):]
	} else {
		return false
	}

	l.Event = EventRuleMatch
	l.RuleIndex = n
	l.HasRule = true
	l.RuleText = ruleText
	l.Action = action
	if name, args, ok := cutParens(action); ok {
		l.Action = name
		// route and bypass lead their argument list with the outbound tag;
		// every other parenthesised action lists options only.
		if name == "route" || name == "bypass" {
			outbound, _, _ := strings.Cut(args, ",")
			l.Outbound = outbound
		}
	}
	return true
}

func cutParens(s string) (name string, args string, ok bool) {
	if !strings.HasSuffix(s, ")") {
		return "", "", false
	}
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1 : len(s)-1], true
}

// classifySniffed reads "<protocol>", "<protocol>, domain: <d>" and the form
// with ", client: <c>" appended. Line has no field for the client, so it is
// dropped rather than folded into another field.
func classifySniffed(l *Line, rest string) {
	l.Event = EventSniffed
	protocol, tail, _ := strings.Cut(rest, ", ")
	l.SniffProtocol = protocol
	for tail != "" {
		var part string
		part, tail, _ = strings.Cut(tail, ", ")
		if domain, ok := strings.CutPrefix(part, "domain: "); ok {
			l.SniffDomain = domain
		}
	}
}

// classifyDialFailure reads the terminal error of a connection that never
// opened. There is no close line after it (route/conn.go:106-120).
func classifyDialFailure(l *Line, body string) bool {
	rest, ok := strings.CutPrefix(body, "open connection to ")
	packet := false
	if !ok {
		rest, ok = strings.CutPrefix(body, "open packet connection to ")
		packet = ok
	}
	if !ok {
		return false
	}

	dst, errText := rest, ""
	if i := strings.Index(rest, " using outbound/"); i >= 0 {
		dst = rest[:i]
		outbound, cause, found := strings.Cut(rest[i+len(" using outbound/"):], ": ")
		if found {
			errText = cause
		}
		l.OutboundType, l.OutboundName = outbound, ""
		if j := strings.IndexByte(outbound, '['); j >= 0 && strings.HasSuffix(outbound, "]") {
			l.OutboundType, l.OutboundName = outbound[:j], outbound[j+1:len(outbound)-1]
		}
	} else if host, cause, found := strings.Cut(rest, ": "); found {
		dst, errText = host, cause
	}

	l.Event = EventDialFailed
	l.Packet = packet
	l.DstHost, l.DstPort = splitHostPort(dst)
	l.Error = errText
	return true
}

func classifyAuthFailure(l *Line, rest string) {
	l.Event = EventAuthFailed
	src, errText, _ := strings.Cut(rest, ": ")
	l.SrcIP, l.SrcPort = splitHostPort(src)
	l.Error = errText
}

// classifyConnection reads the half-close and route-level close lines. The
// handshake errors that share the "connection <direction> " prefix are left
// unmodelled on purpose, so they surface as drift rather than as a wrong event.
func classifyConnection(l *Line, rest string) bool {
	direction := DirectionNone
	switch {
	case strings.HasPrefix(rest, "upload "):
		direction, rest = DirectionUpload, rest[len("upload "):]
	case strings.HasPrefix(rest, "download "):
		direction, rest = DirectionDownload, rest[len("download "):]
	}

	if direction == DirectionNone {
		if errText, ok := strings.CutPrefix(rest, "closed: "); ok {
			l.Event = EventConnectionClosed
			l.Error = errText
			return true
		}
		if rest == "closed" {
			l.Event = EventConnectionClosed
			return true
		}
		return false
	}

	switch {
	case rest == "finished":
		l.Event = EventFinished
		l.Direction = direction
		return true
	case rest == "closed":
		l.Event = EventClosed
		l.Direction = direction
		return true
	}
	if errText, ok := strings.CutPrefix(rest, "closed: "); ok {
		l.Event = EventClosed
		l.Direction = direction
		l.Error = errText
		return true
	}
	return false
}

func classifyLookup(l *Line, rest string) bool {
	switch {
	case strings.HasPrefix(rest, "domain "):
		l.Event = EventDNS
		l.DNSDomain = rest[len("domain "):]
		return true
	case strings.HasPrefix(rest, "succeed for "):
		domain, addresses, _ := strings.Cut(rest[len("succeed for "):], ": ")
		l.Event = EventDNS
		l.DNSDomain = domain
		l.DNSResult = strings.Fields(addresses)
		return true
	case strings.HasPrefix(rest, "failed for "):
		domain, errText, _ := strings.Cut(rest[len("failed for "):], ": ")
		l.Event = EventDNS
		l.DNSDomain = domain
		l.Error = errText
		return true
	}
	return false
}

// splitHostPort accepts what M.Socksaddr prints: host:port, an IPv6 literal in
// brackets, and a bare host with no port at all. Anything it cannot split
// comes back whole as the host, never as a partial one.
func splitHostPort(s string) (host string, port int) {
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndexByte(s, ']')
		if end < 0 {
			return s, 0
		}
		inner, tail := s[1:end], s[end+1:]
		if tail == "" {
			return inner, 0
		}
		if text, ok := strings.CutPrefix(tail, ":"); ok {
			if n, ok := parsePort(text); ok {
				return inner, n
			}
		}
		return s, 0
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	// A colon earlier in the string means an unbracketed IPv6 literal, which
	// carries no port.
	if strings.IndexByte(s[:i], ':') >= 0 {
		return s, 0
	}
	n, ok := parsePort(s[i+1:])
	if !ok {
		return s, 0
	}
	return s[:i], n
}

func parsePort(s string) (int, bool) {
	if s == "" || !allDigits(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// stripANSI removes the colour escapes the file and stderr writers add. The
// Clash API payload is written with colours disabled, so this is defensive
// there and load-bearing for ParseFileLine.
func stripANSI(s string) string {
	if !strings.ContainsRune(s, 0x1b) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		if i < len(s) && s[i] == '[' {
			i++
			for i < len(s) && s[i] >= 0x20 && s[i] <= 0x3f {
				i++
			}
			if i < len(s) {
				i++
			}
		}
	}
	return b.String()
}
