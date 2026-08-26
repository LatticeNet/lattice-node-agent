package singboxlog

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const fixtureDir = "testdata/v1.13.14"

// fixtureLine is one fixture entry kept with its provenance so a failure names
// the file and line rather than just the payload.
type fixtureLine struct {
	file string
	num  int
	raw  string
	Line
}

func loadFixtures(t *testing.T) []fixtureLine {
	t.Helper()
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("read fixture dir: %v", err)
	}
	var lines []fixtureLine
	files := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		files++
		data, err := os.ReadFile(filepath.Join(fixtureDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for i, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			line, err := ParseEntry([]byte(raw), testAt)
			if err != nil {
				t.Fatalf("%s:%d: %v", entry.Name(), i+1, err)
			}
			lines = append(lines, fixtureLine{file: entry.Name(), num: i + 1, raw: raw, Line: line})
		}
	}
	// A fixture that silently disappears would make every count below pass by
	// vacuum, so the set itself is pinned.
	if files != 4 {
		t.Fatalf("found %d jsonl fixtures, want 4", files)
	}
	return lines
}

// TestFixturesFullyClassified is the format-drift guard. Every line captured
// from the real binary must land on a modelled event; a new sing-box release
// that rewords a message fails here with the exact lines it moved.
func TestFixturesFullyClassified(t *testing.T) {
	lines := loadFixtures(t)
	if len(lines) != 101 {
		t.Fatalf("parsed %d fixture lines, want 101", len(lines))
	}
	for _, line := range lines {
		if !line.Parsed() {
			t.Errorf("unclassified %s:%d: %s", line.file, line.num, line.raw)
		}
		// Every line the rig captured came from a connection context. A line
		// without an id would mean the prefix parse broke, not that sing-box
		// stopped writing one.
		if !line.HasLogID {
			t.Errorf("no log id on %s:%d: %s", line.file, line.num, line.raw)
		}
	}
}

// TestFixtureEventCounts pins the shape of the whole capture. A parser change
// that reclassifies even one line moves a number here.
func TestFixtureEventCounts(t *testing.T) {
	lines := loadFixtures(t)

	perFile := map[string]int{}
	perEvent := map[Event]int{}
	ids := map[uint32]struct{}{}
	for _, line := range lines {
		perFile[line.file]++
		perEvent[line.Event]++
		if line.HasLogID {
			ids[line.LogID] = struct{}{}
		}
	}

	wantPerFile := map[string]int{
		"entry_nosniff.jsonl": 31,
		"entry_sniff.jsonl":   19,
		"exit_nosniff.jsonl":  31,
		"exit_sniff.jsonl":    20,
	}
	if !reflect.DeepEqual(perFile, wantPerFile) {
		t.Errorf("lines per file = %v, want %v", perFile, wantPerFile)
	}

	wantPerEvent := map[Event]int{
		EventInboundFrom:      12,
		EventInboundTo:        12,
		EventRuleMatch:        10,
		EventSniffed:          4,
		EventOutboundTo:       18,
		EventDNS:              18,
		EventFinished:         10,
		EventClosed:           12,
		EventConnectionClosed: 4,
		EventDialFailed:       1,
	}
	if !reflect.DeepEqual(perEvent, wantPerEvent) {
		t.Errorf("lines per event = %v, want %v", perEvent, wantPerEvent)
	}

	// Twelve connections, one "inbound connection from" each.
	if len(ids) != 12 {
		t.Errorf("distinct log ids = %d, want 12", len(ids))
	}
}

// TestFixtureKnownLines pins the exact parse of the distinctive lines the
// assembler depends on, taken verbatim from the capture.
func TestFixtureKnownLines(t *testing.T) {
	lines := loadFixtures(t)

	tests := []struct {
		name    string
		payload string
		count   int
		want    Line
	}{
		{
			name:    "authenticated inbound carries the user",
			payload: `[291839386 1ms] inbound/vless[vless-exit]: [u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:18081`,
			count:   1,
			want: Line{
				Level: "info",
				LogID: 291839386, HasLogID: true, ElapsedMS: 1,
				Tag: "inbound/vless[vless-exit]", TagKind: TagInbound, TagType: "vless", TagName: "vless-exit",
				Event:   EventInboundTo,
				Message: "[u_a1b2c3d4e5f60718] inbound connection to 127.0.0.1:18081",
				User:    "u_a1b2c3d4e5f60718",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			name:    "entry side logs no user",
			payload: `[2064424212 3ms] inbound/mixed[mixed-entry]: inbound connection to 127.0.0.1:18081`,
			count:   1,
			want: Line{
				Level: "info",
				LogID: 2064424212, HasLogID: true, ElapsedMS: 3,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventInboundTo,
				Message: "inbound connection to 127.0.0.1:18081",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			name:    "rule match with a condition",
			payload: `[411327584 14ms] router: match[1] inbound=mixed-entry domain_suffix=example.com => route(chain-to-exit)`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[1] inbound=mixed-entry domain_suffix=example.com => route(chain-to-exit)",
				RuleIndex: 1, HasRule: true, RuleText: "inbound=mixed-entry domain_suffix=example.com",
				Action: "route", Outbound: "chain-to-exit",
			},
		},
		{
			name:    "rule match without a condition",
			payload: `[3872684616 7ms] router: match[0] => sniff`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 3872684616, HasLogID: true, ElapsedMS: 7,
				Tag: "router", TagKind: TagRouter,
				Event:     EventRuleMatch,
				Message:   "match[0] => sniff",
				RuleIndex: 0, HasRule: true,
				Action: "sniff",
			},
		},
		{
			name:    "sniffed tls",
			payload: `[411327584 14ms] router: sniffed protocol: tls, domain: example.com`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 411327584, HasLogID: true, ElapsedMS: 14,
				Tag: "router", TagKind: TagRouter,
				Event:         EventSniffed,
				Message:       "sniffed protocol: tls, domain: example.com",
				SniffProtocol: "tls", SniffDomain: "example.com",
			},
		},
		{
			// Section 7 note 2: the outbound line is emitted twice, byte for
			// byte, for the same connection. The assembler has to be idempotent
			// and this is where the duplication is pinned.
			name:    "outbound line is emitted twice",
			payload: `[2064424212 5ms] outbound/vless[chain-to-exit]: outbound connection to 127.0.0.1:18081`,
			count:   2,
			want: Line{
				Level: "info",
				LogID: 2064424212, HasLogID: true, ElapsedMS: 5,
				Tag: "outbound/vless[chain-to-exit]", TagKind: TagOutbound, TagType: "vless", TagName: "chain-to-exit",
				Event:   EventOutboundTo,
				Message: "outbound connection to 127.0.0.1:18081",
				DstHost: "127.0.0.1", DstPort: 18081,
			},
		},
		{
			name:    "dial failure is the terminal line",
			payload: `[2099970926 0ms] connection: open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused`,
			count:   1,
			want: Line{
				Level: "error",
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
			name:    "route level close carries the reason",
			payload: `[3101221041 0ms] inbound/mixed[mixed-entry]: connection closed: (io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 3101221041, HasLogID: true,
				Tag: "inbound/mixed[mixed-entry]", TagKind: TagInbound, TagType: "mixed", TagName: "mixed-entry",
				Event:   EventConnectionClosed,
				Message: `connection closed: (io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
				Error:   `(io: read/write on closed pipe | Get "http://127.0.0.1:19999/": EOF)`,
			},
		},
		{
			name:    "dns lookup result",
			payload: `[3281277749 100ms] dns: lookup succeed for example.com: 172.66.147.243 104.20.23.154`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 3281277749, HasLogID: true, ElapsedMS: 100,
				Tag: "dns", TagKind: TagDNS,
				Event:     EventDNS,
				Message:   "lookup succeed for example.com: 172.66.147.243 104.20.23.154",
				DNSDomain: "example.com",
				DNSResult: []string{"172.66.147.243", "104.20.23.154"},
			},
		},
		{
			// log/format.go prints the sub-minute fraction as centiseconds and
			// does not pad it, so "1.4s" is 1040ms rather than 1400ms.
			name:    "elapsed crosses one second",
			payload: `[3575763107 1.4s] connection: connection download closed`,
			count:   1,
			want: Line{
				Level: "trace",
				LogID: 3575763107, HasLogID: true, ElapsedMS: 1040,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventClosed,
				Message:   "connection download closed",
				Direction: DirectionDownload,
			},
		},
		{
			name:    "clean half close",
			payload: `[411327584 1.26s] connection: connection upload finished`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 411327584, HasLogID: true, ElapsedMS: 1260,
				Tag: "connection", TagKind: TagConnection,
				Event:     EventFinished,
				Message:   "connection upload finished",
				Direction: DirectionUpload,
			},
		},
		{
			name:    "unmodelled dns line stays on the dns event",
			payload: `[228733835 1ms] dns: exchanged A localhost. 600 IN A 127.0.0.1`,
			count:   1,
			want: Line{
				Level: "debug",
				LogID: 228733835, HasLogID: true, ElapsedMS: 1,
				Tag: "dns", TagKind: TagDNS,
				Event:   EventDNS,
				Message: "exchanged A localhost. 600 IN A 127.0.0.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found []fixtureLine
			for _, line := range lines {
				if line.Raw == tt.payload {
					found = append(found, line)
				}
			}
			if len(found) != tt.count {
				t.Fatalf("payload appears %d times in the capture, want %d", len(found), tt.count)
			}
			want := tt.want
			want.At = testAt
			want.Raw = tt.payload
			for _, line := range found {
				if !reflect.DeepEqual(line.Line, want) {
					t.Errorf("%s:%d\n got %+v\nwant %+v", line.file, line.num, line.Line, want)
				}
			}
		})
	}
}

// TestParseFileLineFixture checks the stderr and file shape against the same
// event captured through the API, which is the only guarantee that one core
// serves both readers.
func TestParseFileLineFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtureDir, "exit_file_format.log"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	raw := strings.TrimRight(string(data), "\n")

	got, ok := ParseFileLine(raw, testAt)
	if !ok {
		t.Fatalf("ParseFileLine rejected the captured line: %q", raw)
	}

	want := Line{
		At:    testAt,
		Level: "error",
		Raw:   raw,
		LogID: 2099970926, HasLogID: true,
		Tag: "connection", TagKind: TagConnection,
		Event:   EventDialFailed,
		Message: "open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused",
		DstHost: "127.0.0.1", DstPort: 19999,
		Error:        "dial tcp 127.0.0.1:19999: connect: connection refused",
		OutboundType: "direct", OutboundName: "direct-out",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseFileLine\n got %+v\nwant %+v", got, want)
	}

	// The same event reached the API without the timestamp and the colours.
	// Everything except Raw, which keeps whichever form arrived, must match.
	api := ParsePayload(`[2099970926 0ms] connection: open connection to 127.0.0.1:19999 using outbound/direct[direct-out]: dial tcp 127.0.0.1:19999: connect: connection refused`, "error", testAt)
	got.Raw = api.Raw
	if !reflect.DeepEqual(got, api) {
		t.Errorf("file and API forms disagree\nfile %+v\n api %+v", got, api)
	}
}
