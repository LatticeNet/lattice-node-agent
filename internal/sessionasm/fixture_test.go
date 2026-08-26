package sessionasm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxlog"
	"github.com/LatticeNet/lattice-sdk/model"
)

// The fixtures under singboxlog/testdata/v1.13.14/ are real output captured
// from a v1.13.14 binary. The Line values below are hand built rather than
// parsed, so that this package's tests do not depend on the parser being
// finished, but every hand built line carries the exact payload it came from
// and checkAgainstFixture asserts that payload, its log id, its elapsed
// counter and its level against the file. If the capture is ever replaced,
// these tests fail loudly instead of drifting away from reality.

// fixtureBase is an arbitrary deterministic wall clock. Nothing in the
// assembler reads the real clock during these tests.
var fixtureBase = time.Date(2026, 8, 26, 1, 35, 0, 0, time.UTC)

const (
	tagVlessExit  = "inbound/vless[vless-exit]"
	tagDirectOut  = "outbound/direct[direct-out]"
	tagMixedEntry = "inbound/mixed[mixed-entry]"
	tagChainExit  = "outbound/vless[chain-to-exit]"
	userExit      = "u_a1b2c3d4e5f60718"
)

// stamp fills At for every line. The agent receives a line as sing-box emits
// it, so At is the connection's own start plus sing-box's elapsed counter.
// That also exercises the assembler's start reconstruction: it subtracts
// elapsed to recover the offset it is asserted against.
func stamp(lines []singboxlog.Line, offsets map[uint32]time.Duration) []singboxlog.Line {
	out := make([]singboxlog.Line, len(lines))
	for i, l := range lines {
		// Every line in these captures carries an id; the parser sets the flag
		// and the assembler refuses to group without it.
		l.HasLogID = true
		l.At = fixtureBase.Add(offsets[l.LogID] + time.Duration(l.ElapsedMS)*time.Millisecond)
		out[i] = l
	}
	return out
}

var payloadPrefix = regexp.MustCompile(`^\[(\d+) ([^\]]+)\] `)

// checkAgainstFixture ties the hand built table to the captured file.
func checkAgainstFixture(t *testing.T, name string, lines []singboxlog.Line) {
	t.Helper()
	path := filepath.Join("..", "singboxlog", "testdata", "v1.13.14", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var payloads []struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
	}
	for _, b := range splitJSONLines(raw) {
		var rec struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("%s: bad json line: %v", name, err)
		}
		payloads = append(payloads, rec)
	}
	if len(payloads) != len(lines) {
		t.Fatalf("%s: fixture has %d lines, table has %d", name, len(payloads), len(lines))
	}
	for i, want := range payloads {
		got := lines[i]
		if got.Raw != want.Payload {
			t.Fatalf("%s line %d raw mismatch:\n got %q\nwant %q", name, i+1, got.Raw, want.Payload)
		}
		if got.Level != want.Type {
			t.Errorf("%s line %d level = %q, fixture says %q", name, i+1, got.Level, want.Type)
		}
		m := payloadPrefix.FindStringSubmatch(want.Payload)
		if m == nil {
			t.Fatalf("%s line %d has no [id elapsed] prefix: %q", name, i+1, want.Payload)
		}
		if id := m[1]; id != itoa(got.LogID) {
			t.Errorf("%s line %d log id = %d, fixture says %s", name, i+1, got.LogID, id)
		}
		d, err := time.ParseDuration(m[2])
		if err != nil {
			t.Fatalf("%s line %d elapsed %q: %v", name, i+1, m[2], err)
		}
		if ms := int64(d / time.Millisecond); ms != got.ElapsedMS {
			t.Errorf("%s line %d elapsed = %dms, fixture says %dms", name, i+1, got.ElapsedMS, ms)
		}
	}
}

func splitJSONLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '\n' {
			if line := trimSpaceBytes(raw[start:i]); len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpaceBytes(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func itoa(v uint32) string {
	return strconvItoa(uint64(v))
}

func strconvItoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// exitNosniffLines is testdata/v1.13.14/exit_nosniff.jsonl: four connections on
// the exit instance, one of which fails to dial. Lines stay in capture order.
func exitNosniffLines() []singboxlog.Line {
	return []singboxlog.Line{
		{Level: "info", LogID: 291839386, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62011,
			Raw: "[291839386 0ms] inbound/vless[vless-exit]: inbound connection from 127.0.0.1:62011"},
		{Level: "info", LogID: 291839386, ElapsedMS: 1, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundTo, User: userExit, DstHost: "127.0.0.1", DstPort: 18081,
			Raw: "[291839386 1ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:18081"},
		{Level: "info", LogID: 291839386, ElapsedMS: 2, Tag: tagDirectOut, TagKind: singboxlog.TagOutbound, TagType: "direct", TagName: "direct-out",
			Event: singboxlog.EventOutboundTo, DstHost: "127.0.0.1", DstPort: 18081,
			Raw: "[291839386 2ms] outbound/direct[direct-out]: outbound connection to 127.0.0.1:18081"},
		{Level: "trace", LogID: 291839386, ElapsedMS: 5, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventClosed, Direction: singboxlog.DirectionUpload,
			Raw: "[291839386 5ms] connection: connection upload closed"},
		{Level: "debug", LogID: 291839386, ElapsedMS: 5, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventFinished, Direction: singboxlog.DirectionDownload,
			Raw: "[291839386 5ms] connection: connection download finished"},

		{Level: "info", LogID: 228733835, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62014,
			Raw: "[228733835 0ms] inbound/vless[vless-exit]: inbound connection from 127.0.0.1:62014"},
		{Level: "info", LogID: 228733835, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundTo, User: userExit, DstHost: "localhost", DstPort: 18081,
			Raw: "[228733835 0ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to localhost:18081"},
		{Level: "info", LogID: 228733835, ElapsedMS: 0, Tag: tagDirectOut, TagKind: singboxlog.TagOutbound, TagType: "direct", TagName: "direct-out",
			Event: singboxlog.EventOutboundTo, DstHost: "localhost", DstPort: 18081,
			Raw: "[228733835 0ms] outbound/direct[direct-out]: outbound connection to localhost:18081"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 0, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost",
			Raw: "[228733835 0ms] dns: lookup domain localhost"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 1, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost",
			Raw: "[228733835 1ms] dns: exchanged localhost NOERROR 600"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 1, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost",
			Raw: "[228733835 1ms] dns: exchanged localhost NOERROR 600"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 1, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost.", DNSResult: []string{"127.0.0.1"},
			Raw: "[228733835 1ms] dns: exchanged A localhost. 600 IN A 127.0.0.1"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 1, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost.", DNSResult: []string{"::1"},
			Raw: "[228733835 1ms] dns: exchanged AAAA localhost. 600 IN AAAA ::1"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 1, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "localhost", DNSResult: []string{"127.0.0.1", "::1"},
			Raw: "[228733835 1ms] dns: lookup succeed for localhost: 127.0.0.1 ::1"},
		{Level: "trace", LogID: 228733835, ElapsedMS: 2, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventClosed, Direction: singboxlog.DirectionUpload,
			Raw: "[228733835 2ms] connection: connection upload closed"},
		{Level: "debug", LogID: 228733835, ElapsedMS: 2, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventFinished, Direction: singboxlog.DirectionDownload,
			Raw: "[228733835 2ms] connection: connection download finished"},

		{Level: "info", LogID: 2099970926, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62017,
			Raw: "[2099970926 0ms] inbound/vless[vless-exit]: inbound connection from 127.0.0.1:62017"},
		{Level: "info", LogID: 2099970926, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundTo, User: userExit, DstHost: "127.0.0.1", DstPort: 19999,
			Raw: "[2099970926 0ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:19999"},
		{Level: "info", LogID: 2099970926, ElapsedMS: 0, Tag: tagDirectOut, TagKind: singboxlog.TagOutbound, TagType: "direct", TagName: "direct-out",
			Event: singboxlog.EventOutboundTo, DstHost: "127.0.0.1", DstPort: 19999,
			Raw: "[2099970926 0ms] outbound/direct[direct-out]: outbound connection to 127.0.0.1:19999"},
		{Level: "error", LogID: 2099970926, ElapsedMS: 0, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventDialFailed, DstHost: "127.0.0.1", DstPort: 19999,
			OutboundType: "direct", OutboundName: "direct-out",
			Error: "dial tcp 127.0.0.1:19999: connect: connection refused",
			Raw:   "[2099970926 0ms] connection: open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused"},

		{Level: "info", LogID: 3281277749, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62020,
			Raw: "[3281277749 0ms] inbound/vless[vless-exit]: inbound connection from 127.0.0.1:62020"},
		{Level: "info", LogID: 3281277749, ElapsedMS: 0, Tag: tagVlessExit, TagKind: singboxlog.TagInbound, TagType: "vless", TagName: "vless-exit",
			Event: singboxlog.EventInboundTo, User: userExit, DstHost: "example.com", DstPort: 443,
			Raw: "[3281277749 0ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to example.com:443"},
		{Level: "info", LogID: 3281277749, ElapsedMS: 0, Tag: tagDirectOut, TagKind: singboxlog.TagOutbound, TagType: "direct", TagName: "direct-out",
			Event: singboxlog.EventOutboundTo, DstHost: "example.com", DstPort: 443,
			Raw: "[3281277749 0ms] outbound/direct[direct-out]: outbound connection to example.com:443"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 0, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com",
			Raw: "[3281277749 0ms] dns: lookup domain example.com"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 2, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com",
			Raw: "[3281277749 2ms] dns: exchanged example.com NOERROR 0"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 100, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com",
			Raw: "[3281277749 100ms] dns: exchanged example.com NOERROR 105"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 100, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com.", DNSResult: []string{"172.66.147.243"},
			Raw: "[3281277749 100ms] dns: exchanged A example.com. 105 IN A 172.66.147.243"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 100, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com.", DNSResult: []string{"104.20.23.154"},
			Raw: "[3281277749 100ms] dns: exchanged A example.com. 105 IN A 104.20.23.154"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 100, Tag: "dns", TagKind: singboxlog.TagDNS,
			Event: singboxlog.EventDNS, DNSDomain: "example.com", DNSResult: []string{"172.66.147.243", "104.20.23.154"},
			Raw: "[3281277749 100ms] dns: lookup succeed for example.com: 172.66.147.243 104.20.23.154"},
		{Level: "trace", LogID: 3281277749, ElapsedMS: 1400, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventClosed, Direction: singboxlog.DirectionDownload,
			Raw: "[3281277749 1.4s] connection: connection download closed"},
		{Level: "debug", LogID: 3281277749, ElapsedMS: 1400, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventFinished, Direction: singboxlog.DirectionUpload,
			Raw: "[3281277749 1.4s] connection: connection upload finished"},
	}
}

// entrySniffLines is testdata/v1.13.14/entry_sniff.jsonl: two connections whose
// lines interleave, both with the duplicated outbound line, one of them with a
// trailing inbound close line after both directions have already reported.
func entrySniffLines() []singboxlog.Line {
	return []singboxlog.Line{
		{Level: "info", LogID: 411327584, ElapsedMS: 3, Tag: tagMixedEntry, TagKind: singboxlog.TagInbound, TagType: "mixed", TagName: "mixed-entry",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62414,
			Raw: "[411327584 3ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62414"},
		{Level: "info", LogID: 3872684616, ElapsedMS: 0, Tag: tagMixedEntry, TagKind: singboxlog.TagInbound, TagType: "mixed", TagName: "mixed-entry",
			Event: singboxlog.EventInboundFrom, SrcIP: "127.0.0.1", SrcPort: 62415,
			Raw: "[3872684616 0ms] inbound/mixed[mixed-entry]: inbound connection from 127.0.0.1:62415"},
		{Level: "info", LogID: 411327584, ElapsedMS: 9, Tag: tagMixedEntry, TagKind: singboxlog.TagInbound, TagType: "mixed", TagName: "mixed-entry",
			Event: singboxlog.EventInboundTo, DstHost: "example.com", DstPort: 443,
			Raw: "[411327584 9ms] inbound/mixed[mixed-entry]: inbound connection to example.com:443"},
		{Level: "debug", LogID: 411327584, ElapsedMS: 10, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventRuleMatch, RuleIndex: 0, HasRule: true, Action: "sniff",
			Raw: "[411327584 10ms] router: match[0] => sniff"},
		{Level: "info", LogID: 3872684616, ElapsedMS: 7, Tag: tagMixedEntry, TagKind: singboxlog.TagInbound, TagType: "mixed", TagName: "mixed-entry",
			Event: singboxlog.EventInboundTo, DstHost: "127.0.0.1", DstPort: 18081,
			Raw: "[3872684616 7ms] inbound/mixed[mixed-entry]: inbound connection to 127.0.0.1:18081"},
		{Level: "debug", LogID: 3872684616, ElapsedMS: 7, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventRuleMatch, RuleIndex: 0, HasRule: true, Action: "sniff",
			Raw: "[3872684616 7ms] router: match[0] => sniff"},
		{Level: "debug", LogID: 3872684616, ElapsedMS: 8, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventSniffed, SniffProtocol: "http", SniffDomain: "127.0.0.1",
			Raw: "[3872684616 8ms] router: sniffed protocol: http, domain: 127.0.0.1"},
		{Level: "debug", LogID: 3872684616, ElapsedMS: 8, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventRuleMatch, RuleIndex: 2, HasRule: true, RuleText: "inbound=mixed-entry", Action: "route", Outbound: "chain-to-exit",
			Raw: "[3872684616 8ms] router: match[2] inbound=mixed-entry => route(chain-to-exit)"},
		{Level: "info", LogID: 3872684616, ElapsedMS: 8, Tag: tagChainExit, TagKind: singboxlog.TagOutbound, TagType: "vless", TagName: "chain-to-exit",
			Event: singboxlog.EventOutboundTo, DstHost: "127.0.0.1", DstPort: 18081,
			Raw: "[3872684616 8ms] outbound/vless[chain-to-exit]: outbound connection to 127.0.0.1:18081"},
		{Level: "info", LogID: 3872684616, ElapsedMS: 8, Tag: tagChainExit, TagKind: singboxlog.TagOutbound, TagType: "vless", TagName: "chain-to-exit",
			Event: singboxlog.EventOutboundTo, DstHost: "127.0.0.1", DstPort: 18081,
			Raw: "[3872684616 8ms] outbound/vless[chain-to-exit]: outbound connection to 127.0.0.1:18081"},
		{Level: "debug", LogID: 411327584, ElapsedMS: 14, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventSniffed, SniffProtocol: "tls", SniffDomain: "example.com",
			Raw: "[411327584 14ms] router: sniffed protocol: tls, domain: example.com"},
		{Level: "debug", LogID: 411327584, ElapsedMS: 14, Tag: "router", TagKind: singboxlog.TagRouter,
			Event: singboxlog.EventRuleMatch, RuleIndex: 1, HasRule: true, RuleText: "inbound=mixed-entry domain_suffix=example.com", Action: "route", Outbound: "chain-to-exit",
			Raw: "[411327584 14ms] router: match[1] inbound=mixed-entry domain_suffix=example.com => route(chain-to-exit)"},
		{Level: "info", LogID: 411327584, ElapsedMS: 14, Tag: tagChainExit, TagKind: singboxlog.TagOutbound, TagType: "vless", TagName: "chain-to-exit",
			Event: singboxlog.EventOutboundTo, DstHost: "example.com", DstPort: 443,
			Raw: "[411327584 14ms] outbound/vless[chain-to-exit]: outbound connection to example.com:443"},
		{Level: "info", LogID: 411327584, ElapsedMS: 14, Tag: tagChainExit, TagKind: singboxlog.TagOutbound, TagType: "vless", TagName: "chain-to-exit",
			Event: singboxlog.EventOutboundTo, DstHost: "example.com", DstPort: 443,
			Raw: "[411327584 14ms] outbound/vless[chain-to-exit]: outbound connection to example.com:443"},
		{Level: "debug", LogID: 3872684616, ElapsedMS: 16, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventFinished, Direction: singboxlog.DirectionDownload,
			Raw: "[3872684616 16ms] connection: connection download finished"},
		{Level: "trace", LogID: 3872684616, ElapsedMS: 16, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventClosed, Direction: singboxlog.DirectionUpload,
			Raw: "[3872684616 16ms] connection: connection upload closed"},
		{Level: "debug", LogID: 3872684616, ElapsedMS: 18, Tag: tagMixedEntry, TagKind: singboxlog.TagInbound, TagType: "mixed", TagName: "mixed-entry",
			Event: singboxlog.EventConnectionClosed, Error: "read http request: EOF",
			Raw: "[3872684616 18ms] inbound/mixed[mixed-entry]: connection closed: read http request: EOF"},
		{Level: "trace", LogID: 411327584, ElapsedMS: 1260, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventClosed, Direction: singboxlog.DirectionDownload,
			Raw: "[411327584 1.26s] connection: connection download closed"},
		{Level: "debug", LogID: 411327584, ElapsedMS: 1260, Tag: "connection", TagKind: singboxlog.TagConnection,
			Event: singboxlog.EventFinished, Direction: singboxlog.DirectionUpload,
			Raw: "[411327584 1.26s] connection: connection upload finished"},
	}
}

// wantRecord is the subset of a record this fixture test pins down.
type wantRecord struct {
	logID      uint32
	user       string
	userKind   string
	dstHost    string
	dstPort    int
	dstIP      string
	outbound   string
	reason     string
	closeErr   string
	durationMS int64
	startedAt  time.Time
}

func checkRecords(t *testing.T, got []model.ConnRecord, want []wantRecord) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.LogID != w.logID {
			t.Errorf("record %d: log id = %d, want %d", i, g.LogID, w.logID)
		}
		if g.UserName != w.user || g.UserKind != w.userKind {
			t.Errorf("record %d (%d): user = %q/%q, want %q/%q", i, g.LogID, g.UserName, g.UserKind, w.user, w.userKind)
		}
		if g.UserID != "" {
			t.Errorf("record %d (%d): user id = %q, the agent must never resolve one", i, g.LogID, g.UserID)
		}
		if g.DstHost != w.dstHost || g.DstPort != w.dstPort || g.DstIP != w.dstIP {
			t.Errorf("record %d (%d): dst = %q:%d ip %q, want %q:%d ip %q", i, g.LogID, g.DstHost, g.DstPort, g.DstIP, w.dstHost, w.dstPort, w.dstIP)
		}
		if g.OutboundTag != w.outbound {
			t.Errorf("record %d (%d): outbound = %q, want %q", i, g.LogID, g.OutboundTag, w.outbound)
		}
		if g.CloseReason != w.reason || g.CloseError != w.closeErr {
			t.Errorf("record %d (%d): close = %q/%q, want %q/%q", i, g.LogID, g.CloseReason, g.CloseError, w.reason, w.closeErr)
		}
		if g.DurationMS != w.durationMS {
			t.Errorf("record %d (%d): duration = %dms, want %dms", i, g.LogID, g.DurationMS, w.durationMS)
		}
		if !w.startedAt.IsZero() && !g.StartedAt.Equal(w.startedAt) {
			t.Errorf("record %d (%d): started = %s, want %s", i, g.LogID, g.StartedAt, w.startedAt)
		}
		if g.Open {
			t.Errorf("record %d (%d): final record must not be open", i, g.LogID)
		}
		if g.BytesKnown {
			t.Errorf("record %d (%d): no snapshot was fed, bytes cannot be known", i, g.LogID)
		}
	}
}

func TestFixtureExitNosniff(t *testing.T) {
	lines := exitNosniffLines()
	checkAgainstFixture(t, "exit_nosniff.jsonl", lines)

	offsets := map[uint32]time.Duration{
		291839386:  0,
		228733835:  time.Second,
		2099970926: 2 * time.Second,
		3281277749: 3 * time.Second,
	}
	a := New(Options{NodeID: "node-exit", CoreGeneration: 7, Now: func() time.Time { return fixtureBase }})
	for _, l := range stamp(lines, offsets) {
		a.Line(l)
	}
	got := a.Drain()

	checkRecords(t, got, []wantRecord{
		{logID: 291839386, user: userExit, userKind: model.UserKindManaged, dstHost: "127.0.0.1", dstPort: 18081,
			outbound: "direct-out", reason: model.CloseEOF, durationMS: 5, startedAt: fixtureBase},
		{logID: 228733835, user: userExit, userKind: model.UserKindManaged, dstHost: "localhost", dstPort: 18081, dstIP: "127.0.0.1",
			outbound: "direct-out", reason: model.CloseEOF, durationMS: 2, startedAt: fixtureBase.Add(time.Second)},
		{logID: 2099970926, user: userExit, userKind: model.UserKindManaged, dstHost: "127.0.0.1", dstPort: 19999,
			outbound: "direct-out", reason: model.CloseDialFailed,
			closeErr:  "dial tcp 127.0.0.1:19999: connect: connection refused",
			startedAt: fixtureBase.Add(2 * time.Second)},
		{logID: 3281277749, user: userExit, userKind: model.UserKindManaged, dstHost: "example.com", dstPort: 443, dstIP: "172.66.147.243",
			outbound: "direct-out", reason: model.CloseEOF, durationMS: 1400, startedAt: fixtureBase.Add(3 * time.Second)},
	})

	for _, r := range got {
		if r.NodeID != "node-exit" || r.CoreGeneration != 7 {
			t.Errorf("record %d: identity = %q gen %d, want node-exit gen 7", r.LogID, r.NodeID, r.CoreGeneration)
		}
		if r.InboundTag != "vless-exit" || r.InboundType != "vless" || r.Network != "tcp" {
			t.Errorf("record %d: inbound = %q/%q network %q", r.LogID, r.InboundType, r.InboundTag, r.Network)
		}
		if r.SrcIP != "127.0.0.1" {
			t.Errorf("record %d: src ip = %q", r.LogID, r.SrcIP)
		}
	}
	if s := a.Stats(); s.Open != 0 || s.Emitted != 4 || s.Orphaned != 0 || s.Dropped != 0 || s.Swept != 0 {
		t.Errorf("stats = %+v, want 4 emitted and nothing else", s)
	}
}

func TestFixtureEntrySniff(t *testing.T) {
	lines := entrySniffLines()
	checkAgainstFixture(t, "entry_sniff.jsonl", lines)

	offsets := map[uint32]time.Duration{
		411327584:  0,
		3872684616: time.Second,
	}
	a := New(Options{NodeID: "node-entry", CoreGeneration: 3, Now: func() time.Time { return fixtureBase }})
	for _, l := range stamp(lines, offsets) {
		a.Line(l)
	}
	got := a.Drain()

	// 3872684616 completes first: both of its directions report at 16ms, while
	// 411327584 runs on to 1.26s. The trailing inbound close line at 18ms is
	// dropped rather than resurrecting a connection already emitted.
	checkRecords(t, got, []wantRecord{
		{logID: 3872684616, userKind: model.UserKindUnnamed, dstHost: "127.0.0.1", dstPort: 18081,
			outbound: "chain-to-exit", reason: model.CloseEOF, durationMS: 16, startedAt: fixtureBase.Add(time.Second)},
		{logID: 411327584, userKind: model.UserKindUnnamed, dstHost: "example.com", dstPort: 443,
			outbound: "chain-to-exit", reason: model.CloseEOF, durationMS: 1260, startedAt: fixtureBase},
	})

	byID := map[uint32]model.ConnRecord{}
	for _, r := range got {
		byID[r.LogID] = r
	}
	if r := byID[411327584]; r.SniffedProtocol != "tls" || r.SniffedDomain != "example.com" || r.RuleIndex != 1 || r.RuleText != "inbound=mixed-entry domain_suffix=example.com" {
		t.Errorf("411327584 routing = %q/%q rule %d %q", r.SniffedProtocol, r.SniffedDomain, r.RuleIndex, r.RuleText)
	}
	if r := byID[3872684616]; r.SniffedProtocol != "http" || r.RuleIndex != 2 || r.OutboundType != "vless" {
		t.Errorf("3872684616 routing = %q rule %d outbound type %q", r.SniffedProtocol, r.RuleIndex, r.OutboundType)
	}
	if s := a.Stats(); s.Open != 0 || s.Emitted != 2 {
		t.Errorf("stats = %+v, want 2 emitted and nothing open", s)
	}
}

// TestFixturesNeverEmitAnEmptyCloseReason covers both captures at once: an
// empty reason would render as a blank cell that an operator reads as a clean
// close, which is the one thing this package must never produce.
func TestFixturesNeverEmitAnEmptyCloseReason(t *testing.T) {
	a := New(Options{NodeID: "node", Now: func() time.Time { return fixtureBase }})
	for _, l := range stamp(exitNosniffLines(), map[uint32]time.Duration{}) {
		a.Line(l)
	}
	for _, l := range stamp(entrySniffLines(), map[uint32]time.Duration{}) {
		a.Line(l)
	}
	// Leave one connection open, then sweep it two different ways.
	a.Line(singboxlog.Line{At: fixtureBase, HasLogID: true, LogID: 42, Event: singboxlog.EventInboundFrom, SrcIP: "10.0.0.1", SrcPort: 1234})
	a.Tick(fixtureBase.Add(90 * time.Second)) // open snapshot
	a.Line(singboxlog.Line{At: fixtureBase, HasLogID: true, LogID: 43, Event: singboxlog.EventInboundFrom, SrcIP: "10.0.0.2", SrcPort: 1235})
	a.Tick(fixtureBase.Add(2 * time.Hour)) // orphan sweep
	a.Line(singboxlog.Line{At: fixtureBase, HasLogID: true, LogID: 44, Event: singboxlog.EventInboundFrom, SrcIP: "10.0.0.3", SrcPort: 1236})
	a.CoreRestart(2, fixtureBase.Add(3*time.Hour))

	records := a.Drain()
	if len(records) == 0 {
		t.Fatal("no records")
	}
	for _, r := range records {
		if r.CloseReason == "" {
			t.Errorf("record %d (open=%v) has an empty close reason", r.LogID, r.Open)
		}
	}
}
