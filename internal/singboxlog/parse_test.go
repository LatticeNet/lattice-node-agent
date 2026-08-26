package singboxlog

import (
	"reflect"
	"testing"
	"time"
)

var testAt = time.Date(2026, 8, 26, 0, 2, 38, 0, time.UTC)

// TestParsePayload pins one row per message shape the trace pipeline depends
// on. want carries every field except At, Level and Raw, which the harness
// fills from the row so the table stays about the parse and not the plumbing.
func TestParsePayload(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		payload string
		want    Line
	}{
		{
			name:    "inbound from",
			level:   "info",
			payload: `[2064424212 0ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62010`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 0,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventInboundFrom,
				Message: "inbound connection from 127.0.0.1:62010",
				SrcIP:   "127.0.0.1", SrcPort: 62010,
			},
		},
		{
			name:    "inbound packet from",
			level:   "info",
			payload: `[1 0ms] inbound/tun[tun-in]: inbound packet connection from 10.0.0.2:53`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "inbound/tun[tun-in]", TagKind: TagInbound, TagType: "tun", TagName: "tun-in",
				Event:   EventInboundFrom,
				Message: "inbound packet connection from 10.0.0.2:53",
				SrcIP:   "10.0.0.2", SrcPort: 53,
				Packet: true,
			},
		},
		{
			name:    "inbound to with named user",
			level:   "info",
			payload: `[291839386 1ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:18081`,
			want: Line{
				LogID: 291839386, HasLogID: true, ElapsedMS: 1,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundTo,
				Message: "[u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:18081",
				User:    "u_a1b2c3d4e5f60718",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			// An unnamed user is logged as its index in the user list, which is
			// not an identity, so User must stay empty.
			name:    "inbound to with user index",
			level:   "info",
			payload: `[291839386 1ms] inbound/vless[vless-exit]: [0] inbound connection to example.com:443`,
			want: Line{
				LogID: 291839386, HasLogID: true, ElapsedMS: 1,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundTo,
				Message: "[0] inbound connection to example.com:443",
				DstHost: "example.com", DstPort: 443,
			},
		},
		{
			name:    "inbound to without user",
			level:   "info",
			payload: `[2064424212 3ms] inbound/mixed[mixed-entry]: inbound connection to 127.0.0.1:18081`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 3,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventInboundTo,
				Message: "inbound connection to 127.0.0.1:18081",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			name:    "inbound to ipv6 literal",
			level:   "info",
			payload: `[7 2ms] inbound/vless[vless-exit]: [u_x] inbound connection to [2001:db8::1]:443`,
			want: Line{
				LogID: 7, HasLogID: true, ElapsedMS: 2,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundTo,
				Message: "[u_x] inbound connection to [2001:db8::1]:443",
				User:    "u_x",
				DstHost: "2001:db8::1", DstPort: 443,
			},
		},
		{
			name:    "inbound to host without port",
			level:   "info",
			payload: `[7 2ms] inbound/vless[vless-exit]: inbound connection to example.com`,
			want: Line{
				LogID: 7, HasLogID: true, ElapsedMS: 2,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundTo,
				Message: "inbound connection to example.com",
				DstHost: "example.com",
			},
		},
		{
			name:    "inbound packet connection without destination",
			level:   "info",
			payload: `[7 2ms] inbound/mixed[mixed-entry]: [u_x] inbound packet connection`,
			want: Line{
				LogID: 7, HasLogID: true, ElapsedMS: 2,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventInboundTo,
				Message: "[u_x] inbound packet connection",
				User:    "u_x",
				Packet:  true,
			},
		},
		{
			name:    "rule match route",
			level:   "debug",
			payload: `[2064424212 4ms] router: match[0] inbound=mixed-entry => route(chain-to-exit)`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 4,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[0] inbound=mixed-entry => route(chain-to-exit)",
				RuleIndex: 0, HasRule: true, RuleText: "inbound=mixed-entry",
				Action: "route", Outbound: "chain-to-exit",
			},
		},
		{
			name:    "rule match without condition",
			level:   "debug",
			payload: `[411327584 10ms] router: match[0] => sniff`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 10,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[0] => sniff",
				RuleIndex: 0, HasRule: true, RuleText: "",
				Action: "sniff",
			},
		},
		{
			name:    "rule match with several conditions",
			level:   "debug",
			payload: `[411327584 14ms] router: match[1] inbound=mixed-entry domain_suffix=example.com => route(chain-to-exit)`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[1] inbound=mixed-entry domain_suffix=example.com => route(chain-to-exit)",
				RuleIndex: 1, HasRule: true, RuleText: "inbound=mixed-entry domain_suffix=example.com",
				Action: "route", Outbound: "chain-to-exit",
			},
		},
		{
			name:    "pre-match",
			level:   "debug",
			payload: `[411327584 14ms] router: pre-match[2] inbound=mixed-entry => hijack-dns`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "pre-match[2] inbound=mixed-entry => hijack-dns",
				RuleIndex: 2, HasRule: true, RuleText: "inbound=mixed-entry",
				Action: "hijack-dns",
			},
		},
		{
			name:    "route action with options keeps only the outbound",
			level:   "debug",
			payload: `[1 0ms] router: match[3] inbound=x => route(exit,override-port=443)`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[3] inbound=x => route(exit,override-port=443)",
				RuleIndex: 3, HasRule: true, RuleText: "inbound=x",
				Action: "route", Outbound: "exit",
			},
		},
		{
			name:    "reject action names no outbound",
			level:   "debug",
			payload: `[1 0ms] router: match[4] domain=ads.example => reject(default)`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[4] domain=ads.example => reject(default)",
				RuleIndex: 4, HasRule: true, RuleText: "domain=ads.example",
				Action: "reject",
			},
		},
		{
			name:    "sniffed with domain",
			level:   "debug",
			payload: `[411327584 14ms] router: sniffed protocol: tls, domain: example.com`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:         EventSniffed,
				Message:       "sniffed protocol: tls, domain: example.com",
				SniffProtocol: "tls", SniffDomain: "example.com",
			},
		},
		{
			name:    "sniffed with client",
			level:   "debug",
			payload: `[411327584 14ms] router: sniffed protocol: tls, domain: example.com, client: chrome`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:         EventSniffed,
				Message:       "sniffed protocol: tls, domain: example.com, client: chrome",
				SniffProtocol: "tls", SniffDomain: "example.com",
			},
		},
		{
			name:    "sniffed protocol only",
			level:   "debug",
			payload: `[411327584 14ms] router: sniffed protocol: http`,
			want: Line{
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:         EventSniffed,
				Message:       "sniffed protocol: http",
				SniffProtocol: "http",
			},
		},
		{
			name:    "outbound to",
			level:   "info",
			payload: `[2064424212 5ms] outbound/vless[chain-to-exit]: outbound connection to 127.0.0.1:18081`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 5,
				Tag: "outbound/vless[chain-to-exit]", TagKind: TagOutbound, TagType: "vless", TagName: "chain-to-exit",
				Event:   EventOutboundTo,
				Message: "outbound connection to 127.0.0.1:18081",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			name:    "outbound packet to",
			level:   "info",
			payload: `[1 0ms] outbound/direct[direct-out]: outbound packet connection to 8.8.8.8:53`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "outbound/direct[direct-out]", TagKind: TagOutbound, TagType: "direct", TagName: "direct-out",
				Event:   EventOutboundTo,
				Message: "outbound packet connection to 8.8.8.8:53",
				DstHost: "8.8.8.8", DstPort: 53,
				Packet: true,
			},
		},
		{
			name:    "outbound multiplex to",
			level:   "info",
			payload: `[1 0ms] outbound/trojan[t-out]: outbound multiplex connection to example.com:443`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "outbound/trojan[t-out]", TagKind: TagOutbound, TagType: "trojan", TagName: "t-out",
				Event:   EventOutboundTo,
				Message: "outbound multiplex connection to example.com:443",
				DstHost: "example.com", DstPort: 443,
			},
		},
		{
			name:    "dns lookup domain",
			level:   "debug",
			payload: `[228733835 0ms] dns: lookup domain localhost`,
			want: Line{
				LogID: 228733835, HasLogID: true,
				Tag: "dns", TagKind: TagDNS,
				Event:     EventDNS,
				Message:   "lookup domain localhost",
				DNSDomain: "localhost",
			},
		},
		{
			name:    "dns lookup succeed",
			level:   "debug",
			payload: `[3281277749 100ms] dns: lookup succeed for example.com: 172.66.147.243 104.20.23.154`,
			want: Line{
				LogID: 3281277749, HasLogID: true, ElapsedMS: 100,
				Tag: "dns", TagKind: TagDNS,
				Event:     EventDNS,
				Message:   "lookup succeed for example.com: 172.66.147.243 104.20.23.154",
				DNSDomain: "example.com",
				DNSResult: []string{"172.66.147.243", "104.20.23.154"},
			},
		},
		{
			name:    "dns lookup failed",
			level:   "error",
			payload: `[1 0ms] dns: lookup failed for example.com: connection refused`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "dns", TagKind: TagDNS,
				Event:     EventDNS,
				Message:   "lookup failed for example.com: connection refused",
				DNSDomain: "example.com",
				Error:     "connection refused",
			},
		},
		{
			// The dns tag carries more shapes than are modelled; they stay
			// EventDNS with no invented fields rather than becoming drift.
			name:    "dns exchanged",
			level:   "debug",
			payload: `[228733835 1ms] dns: exchanged A localhost. 600 IN A 127.0.0.1`,
			want: Line{
				LogID: 228733835, HasLogID: true, ElapsedMS: 1,
				Tag: "dns", TagKind: TagDNS,
				Event:   EventDNS,
				Message: "exchanged A localhost. 600 IN A 127.0.0.1",
			},
		},
		{
			name:    "upload finished",
			level:   "debug",
			payload: `[2064424212 11ms] connection: connection upload finished`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 11,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventFinished,
				Message:   "connection upload finished",
				Direction: DirectionUpload,
			},
		},
		{
			name:    "download finished",
			level:   "debug",
			payload: `[2064424212 11ms] connection: connection download finished`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 11,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventFinished,
				Message:   "connection download finished",
				Direction: DirectionDownload,
			},
		},
		{
			name:    "upload closed",
			level:   "trace",
			payload: `[2064424212 11ms] connection: connection upload closed`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 11,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventClosed,
				Message:   "connection upload closed",
				Direction: DirectionUpload,
			},
		},
		{
			name:    "download closed with error",
			level:   "error",
			payload: `[1 0ms] connection: connection download closed: read tcp 127.0.0.1:1: i/o timeout`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventClosed,
				Message:   "connection download closed: read tcp 127.0.0.1:1: i/o timeout",
				Direction: DirectionDownload,
				Error:     "read tcp 127.0.0.1:1: i/o timeout",
			},
		},
		{
			// A handshake failure is terminal and real: the transport never came
			// up, so no bytes ever moved. Leaving it unmodelled meant the
			// connection was later published as unknown, hiding a failure that
			// has a precise cause.
			name:    "upload handshake error is its own terminal event",
			level:   "error",
			payload: `[1 0ms] connection: connection upload handshake: unexpected EOF`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventHandshakeFailed,
				Direction: DirectionUpload,
				Message:   "connection upload handshake: unexpected EOF",
				Error:     "unexpected EOF",
			},
		},
		{
			name:    "connection closed with reason",
			level:   "debug",
			payload: `[2064424212 11ms] inbound/mixed[mixed-entry]: connection closed: read http request: EOF`,
			want: Line{
				LogID: 2064424212, HasLogID: true, ElapsedMS: 11,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventConnectionClosed,
				Message: "connection closed: read http request: EOF",
				Error:   "read http request: EOF",
			},
		},
		{
			name:    "connection closed with nested error",
			level:   "debug",
			payload: `[3101221041 0ms] inbound/mixed[mixed-entry]: connection closed: (io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
			want: Line{
				LogID: 3101221041, HasLogID: true,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventConnectionClosed,
				Message: `connection closed: (io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
				Error:   `(io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
			},
		},
		{
			name:    "dial failed",
			level:   "error",
			payload: `[2099970926 0ms] connection: open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused`,
			want: Line{
				LogID: 2099970926, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:   EventDialFailed,
				Message: "open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused",
				DstHost: "127.0.0.1", DstPort: 19999,
				Error:        "dial tcp 127.0.0.1:19999: connect: connection refused",
				OutboundType: "direct", OutboundName: "direct-out",
			},
		},
		{
			name:    "dial failed packet with ipv6 destination",
			level:   "error",
			payload: `[1 0ms] connection: open packet connection to [2001:db8::1]:443 using outbound/direct[direct-out]: dial udp: network is unreachable`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:   EventDialFailed,
				Message: "open packet connection to [2001:db8::1]:443 using outbound/direct[direct-out]: dial udp: network is unreachable",
				DstHost: "2001:db8::1", DstPort: 443,
				Error:        "dial udp: network is unreachable",
				OutboundType: "direct", OutboundName: "direct-out",
				Packet: true,
			},
		},
		{
			// The default outbound never logs, so the dialer clause is absent
			// and only the destination and the cause survive.
			name:    "dial failed without an outbound clause",
			level:   "error",
			payload: `[1 0ms] connection: open connection to example.com:443: dial tcp: lookup example.com: no such host`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:   EventDialFailed,
				Message: "open connection to example.com:443: dial tcp: lookup example.com: no such host",
				DstHost: "example.com", DstPort: 443,
				Error: "dial tcp: lookup example.com: no such host",
			},
		},
		{
			name:    "auth failed",
			level:   "error",
			payload: `[1 0ms] inbound/vless[vless-exit]: process connection from 1.2.3.4:5678: bad request`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventAuthFailed,
				Message: "process connection from 1.2.3.4:5678: bad request",
				SrcIP:   "1.2.3.4", SrcPort: 5678,
				Error: "bad request",
			},
		},
		{
			// A TLS handshake failure is not a rejected credential. Reporting it
			// as one sends an operator to debug a user that never presented
			// anything. No user is known either way, so attribution stays by
			// source address.
			name:    "tls handshake failure from an ipv6 source is not an auth failure",
			level:   "error",
			payload: `[1 0ms] inbound/vless[vless-exit]: process connection from [2001:db8::9]:5678: TLS handshake: EOF`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventHandshakeFailed,
				Message: "process connection from [2001:db8::9]:5678: TLS handshake: EOF",
				SrcIP:   "2001:db8::9", SrcPort: 5678,
				Error: "TLS handshake: EOF",
			},
		},
		{
			name:    "outbound packet connection without destination",
			level:   "info",
			payload: `[1 0ms] outbound/direct[direct-out]: outbound packet connection`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "outbound/direct[direct-out]", TagKind: TagOutbound, TagType: "direct", TagName: "direct-out",
				Event:   EventOutboundTo,
				Message: "outbound packet connection",
				Packet:  true,
			},
		},
		{
			name:    "outbound line that is not a connection line",
			level:   "info",
			payload: `[1 0ms] outbound/direct[direct-out]: outbound something else entirely`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "outbound/direct[direct-out]", TagKind: TagOutbound, TagType: "direct", TagName: "direct-out",
				Event:   EventOther,
				Message: "outbound something else entirely",
			},
		},
		{
			name:    "connection closed without a reason",
			level:   "debug",
			payload: `[1 0ms] inbound/mixed[mixed-entry]: connection closed`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventConnectionClosed,
				Message: "connection closed",
			},
		},
		{
			name:    "connection line with no known verb",
			level:   "debug",
			payload: `[1 0ms] connection: connection sideways`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "connection", TagKind: TagConnection,
				Event:   EventOther,
				Message: "connection sideways",
			},
		},
		{
			name:    "line without a log id prefix",
			level:   "debug",
			payload: `router: match[0] => sniff`,
			want: Line{
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[0] => sniff",
				RuleIndex: 0, HasRule: true,
				Action: "sniff",
			},
		},
		{
			name:    "line without a log id or a tag",
			level:   "debug",
			payload: `connection upload finished`,
			want: Line{
				TagKind:   TagOther,
				Event:     EventFinished,
				Message:   "connection upload finished",
				Direction: DirectionUpload,
			},
		},
		{
			// A tag family added upstream keeps its type and name readable even
			// though its kind is not one we model.
			name:    "unknown tag family",
			level:   "info",
			payload: `[1 0ms] endpoint/wireguard[wg-out]: outbound connection to 10.0.0.1:51820`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "endpoint/wireguard[wg-out]", TagKind: TagOther, TagType: "wireguard", TagName: "wg-out",
				Event:   EventOutboundTo,
				Message: "outbound connection to 10.0.0.1:51820",
				DstHost: "10.0.0.1", DstPort: 51820,
			},
		},
		{
			name:    "unmodelled message keeps its evidence",
			level:   "warn",
			payload: `[1 0ms] router: something entirely new happened`,
			want: Line{
				LogID: 1, HasLogID: true,
				Tag: "router", TagKind: TagRouter,
				Event:   EventOther,
				Message: "something entirely new happened",
			},
		},
		{
			name:    "malformed input",
			level:   "info",
			payload: `garbage without any structure`,
			want: Line{
				TagKind: TagOther,
				Event:   EventOther,
				Message: "garbage without any structure",
			},
		},
		{
			name:    "empty payload",
			level:   "info",
			payload: ``,
			want: Line{
				TagKind: TagOther,
				Event:   EventOther,
			},
		},
		{
			name:    "unreadable id prefix is left in the message",
			level:   "debug",
			payload: `[abc def] router: match[0] => sniff`,
			want: Line{
				TagKind: TagOther,
				Event:   EventOther,
				Message: "[abc def] router: match[0] => sniff",
			},
		},
		{
			// The id is the assembler's only grouping key, so an unreadable
			// duration must not take it down with it.
			name:    "unreadable duration keeps the id",
			level:   "debug",
			payload: `[42 wat] router: match[0] => sniff`,
			want: Line{
				LogID: 42, HasLogID: true, ElapsedMS: 0,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[0] => sniff",
				RuleIndex: 0, HasRule: true,
				Action: "sniff",
			},
		},
		{
			name:    "colour escapes are stripped before parsing",
			level:   "info",
			payload: "[\x1b[38;5;121m291839386\x1b[0m 1ms] inbound/vless[vless-exit]: inbound connection from 127.0.0.1:62011",
			want: Line{
				LogID: 291839386, HasLogID: true, ElapsedMS: 1,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundFrom,
				Message: "inbound connection from 127.0.0.1:62011",
				SrcIP:   "127.0.0.1", SrcPort: 62011,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			want.At = testAt
			want.Level = tt.level
			want.Raw = tt.payload

			got := ParsePayload(tt.payload, tt.level, testAt)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ParsePayload(%q)\n got %+v\nwant %+v", tt.payload, got, want)
			}
			if got.Parsed() != (tt.want.Event != EventOther) {
				t.Errorf("Parsed() = %v for event %q", got.Parsed(), got.Event)
			}
		})
	}
}

// TestParseElapsedMS pins the duration spellings sing-box emits. The fraction
// in the seconds form is centiseconds, not a decimal fraction, because
// log/format.go prints int64(seconds*100)%100 without padding it.
func TestParseElapsedMS(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0ms", 0, true},
		{"3ms", 3, true},
		{"100ms", 100, true},
		{"999ms", 999, true},
		{"1.4s", 1040, true},
		{"1.04s", 1040, true},
		{"1.26s", 1260, true},
		{"1.40s", 1400, true},
		{"12.5s", 12050, true},
		{"1m30s", 90000, true},
		{"120m0s", 7200000, true},
		{"1.5m", 90000, true},
		{"2h", 7200000, true},
		{"1.234s", 1234, true},
		{"", 0, false},
		{"wat", 0, false},
		{"ms", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseElapsedMS(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseElapsedMS(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"127.0.0.1:62010", "127.0.0.1", 62010},
		{"example.com:443", "example.com", 443},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"[::1]:53", "::1", 53},
		{"example.com", "example.com", 0},
		{"127.0.0.1", "127.0.0.1", 0},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"2001:db8::1", "2001:db8::1", 0},
		{"example.com:notaport", "example.com:notaport", 0},
		{"example.com:70000", "example.com:70000", 0},
		{"", "", 0},
	}
	for _, tt := range tests {
		host, port := splitHostPort(tt.in)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %d), want (%q, %d)", tt.in, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestParseEntry(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		raw := []byte(`{"type":"info","payload":"[2064424212 0ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62010"}`)
		got, err := ParseEntry(raw, testAt)
		if err != nil {
			t.Fatalf("ParseEntry: %v", err)
		}
		if got.Level != "info" || got.LogID != 2064424212 || got.Event != EventInboundFrom || got.SrcPort != 62010 {
			t.Fatalf("unexpected line: %+v", got)
		}
		if got.Raw != "[2064424212 0ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62010" {
			t.Errorf("Raw = %q, want the payload alone", got.Raw)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		raw := []byte(`{"type":"info","payload":`)
		got, err := ParseEntry(raw, testAt)
		if err == nil {
			t.Fatal("expected an error for invalid JSON")
		}
		if got.Raw != string(raw) || got.Event != EventOther {
			t.Errorf("evidence lost on error: %+v", got)
		}
	})

	t.Run("missing payload is not an error", func(t *testing.T) {
		got, err := ParseEntry([]byte(`{"type":"info"}`), testAt)
		if err != nil {
			t.Fatalf("ParseEntry: %v", err)
		}
		if got.Event != EventOther || got.Parsed() {
			t.Errorf("unexpected line: %+v", got)
		}
	})

	t.Run("does not panic on truncated payloads", func(t *testing.T) {
		for _, payload := range []string{"[", "]", "[]", "[ ]", "[1", "[1 ", "[1 0ms", "[1 0ms]", ":", ": ", "a: ", "[1 0ms] :", "match[", "match[]", "match[x] => y", "[u_x] ", "inbound ", "outbound ", "connection ", "lookup ", "open ", "sniffed protocol: "} {
			_ = ParsePayload(payload, "info", testAt)
		}
	})
}

func TestParseFileLineRejectsOtherShapes(t *testing.T) {
	for _, raw := range []string{
		"",
		"just some program output",
		"[2064424212 0ms] router: match[0] => sniff",
		"-0700 2026-08-26 00:02:38 [2099970926 0ms] connection: connection upload finished",
		"a b c d ERROR [1 0ms] router: match[0] => sniff",
	} {
		if got, ok := ParseFileLine(raw, testAt); ok {
			t.Errorf("ParseFileLine(%q) accepted the line: %+v", raw, got)
		} else if got.Raw != raw {
			t.Errorf("ParseFileLine(%q) lost the evidence: %q", raw, got.Raw)
		}
	}
}
