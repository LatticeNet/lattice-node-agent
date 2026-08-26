// Package singboxlog parses the log lines sing-box publishes on its Clash API
// /logs stream into structured events.
//
// The payload shape was confirmed against a real v1.13.14 binary (see
// testdata/v1.13.14/, captured by the V1/V2 rig described in
// Lattice/SINGBOX-TRACE-DESIGN.md section 7):
//
//	{"type":"info","payload":"[2064424212 3ms] inbound/mixed[mixed-entry]: inbound connection to 127.0.0.1:18081"}
//
// Note the order: the connection id comes BEFORE the tag, not after. The file
// and stderr format differs (it prefixes a timestamp and the level, then the
// same "[id elapsed] tag: message"), and testdata/v1.13.14/exit_file_format.log
// holds one such line so both can be parsed by the same core.
//
// Three properties of the stream drive the design of everything downstream:
//
//   - Lines from different connections INTERLEAVE. Grouping is by LogID only;
//     nothing may assume a connection's lines arrive contiguously.
//   - The "outbound connection to" line is emitted TWICE, identically, for the
//     same connection. Consumers must be idempotent.
//   - A dial failure produces no close line at all. The error line IS the
//     terminal event for that connection.
package singboxlog

import "time"

// Event is the semantic classification of a parsed line. A line that parses
// structurally (id, tag, message) but whose message is not recognised gets
// EventOther, which is deliberately not the same as failing to parse: the
// former is a message we do not model, the latter means the format moved.
type Event string

const (
	// EventInboundFrom is a listener accepting a connection, before auth.
	// Carries Src. This is the first line of every connection.
	EventInboundFrom Event = "inbound_from"
	// EventInboundTo is the post-auth line. Carries Dst and, when the inbound
	// user has a name, User. This is where identity enters the stream.
	EventInboundTo Event = "inbound_to"
	// EventRuleMatch is a routing decision: "match[0] inbound=x => route(tag)"
	// or the condition-less "match[0] => sniff".
	EventRuleMatch Event = "rule_match"
	// EventSniffed carries the sniffed protocol and domain.
	EventSniffed Event = "sniffed"
	// EventOutboundTo is the outbound dialling. The outbound's type and tag are
	// in Tag, not in the message.
	EventOutboundTo Event = "outbound_to"
	// EventDNS covers the dns tag's lookup lines.
	EventDNS Event = "dns"
	// EventFinished is a clean half-close: "connection upload finished".
	EventFinished Event = "finished"
	// EventClosed is a cancelled half-close: "connection download closed",
	// optionally with an error.
	EventClosed Event = "closed"
	// EventConnectionClosed is the inbound's own terminal line, which carries
	// the reason: "connection closed: read http request: EOF".
	EventConnectionClosed Event = "connection_closed"
	// EventDialFailed is terminal: "open connection to X using outbound/t[n]: err".
	EventDialFailed Event = "dial_failed"
	// EventAuthFailed is "process connection from src: err". No user is known at
	// this point, by construction, so it can only ever be attributed to Src.
	EventAuthFailed Event = "auth_failed"
	// EventOther parsed structurally but is not a modelled message.
	EventOther Event = "other"
)

// TagKind is the subsystem that emitted the line, taken from the tag prefix.
type TagKind string

const (
	TagInbound    TagKind = "inbound"
	TagOutbound   TagKind = "outbound"
	TagRouter     TagKind = "router"
	TagConnection TagKind = "connection"
	TagDNS        TagKind = "dns"
	TagOther      TagKind = "other"
)

// Direction of a half-close.
type Direction string

const (
	DirectionUpload   Direction = "upload"
	DirectionDownload Direction = "download"
	DirectionNone     Direction = ""
)

// Line is one parsed log line.
//
// LogID is sing-box's per-connection id. It is rand.Uint32 (log/id.go), so it
// is neither globally unique nor stable across restarts; it identifies a
// connection only within one core generation on one node.
type Line struct {
	// At is when the agent received the line. sing-box does not timestamp the
	// Clash API payload, so this is the only clock available and it is the
	// agent's, in UTC.
	At    time.Time
	Level string

	LogID     uint32
	HasLogID  bool
	ElapsedMS int64

	// Tag as sent, e.g. "inbound/vless[vless-exit]" or "router".
	Tag     string
	TagKind TagKind
	// TagType and TagName are the decomposed "type[name]" part, empty for the
	// bare tags (router, connection, dns).
	TagType string
	TagName string

	Event   Event
	Message string
	// Raw is the payload exactly as received. Kept so that a parser gap can
	// never destroy the evidence it failed to read.
	Raw string

	// Fields below are populated per Event; a field not relevant to the event
	// stays zero. Which events set which is documented on the Event constants.
	User    string
	SrcIP   string
	SrcPort int
	DstHost string
	DstPort int

	RuleIndex int
	HasRule   bool
	RuleText  string
	Action    string // route | sniff | hijack-dns | reject | ...
	Outbound  string // outbound tag named by a route action

	SniffProtocol string
	SniffDomain   string

	DNSDomain string
	DNSResult []string

	Direction Direction
	Error     string

	// OutboundType and OutboundName are set on EventDialFailed, where the
	// outbound is named inside the message rather than in the tag.
	OutboundType string
	OutboundName string

	// Packet is true for the UDP variants of the connection messages, which
	// sing-box words as "inbound packet connection from" and so on.
	Packet bool
}
