// Package singboxapi is a client for the sing-box Clash API, used over loopback
// only.
//
// The shapes here were checked against a real sing-box v1.13.14 binary. Three
// of its properties are load bearing and must not be "tidied up" by a later
// reader:
//
//   - /connections carries no user field. sing-box tracks the inbound user but
//     does not serialize it, so identity has to come from the log stream and
//     the join key between the two is SourceIP plus SourcePort.
//   - Connection.ID is a uuid minted by the traffic tracker. It is unrelated to
//     the id that appears in log lines, which is a rand.Uint32. Treating them
//     as the same identifier silently mixes up connections.
//   - Ports are serialized as JSON strings, not numbers. They stay strings on
//     the struct so a decode never fails on an unexpected value, and the int
//     accessors report a parse failure instead of returning a plausible zero.
package singboxapi

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version is the /version response.
type Version struct {
	Meta    bool   `json:"meta"`
	Premium bool   `json:"premium"`
	Version string `json:"version"`
}

// ConnectionsSnapshot is one /connections response.
//
// The totals are cumulative counters for the whole core process, not a delta
// since the previous poll, so a consumer computing rates has to difference them
// itself and has to cope with them resetting when the core restarts.
type ConnectionsSnapshot struct {
	Connections   []Connection `json:"connections"`
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Memory        int64        `json:"memory"`

	// At is when the agent received the response. The body carries no
	// timestamp, so this is the only clock available and it is the agent's,
	// in UTC. It is not part of the wire format.
	At time.Time `json:"-"`
}

// Connection is one live connection as the traffic tracker reports it.
type Connection struct {
	// ID is the tracker's uuid. See the package comment: it is not the log id.
	ID          string       `json:"id"`
	Upload      int64        `json:"upload"`
	Download    int64        `json:"download"`
	Start       time.Time    `json:"start"`
	Chains      []string     `json:"chains"`
	Rule        string       `json:"rule"`
	RulePayload string       `json:"rulePayload"`
	Metadata    ConnMetadata `json:"metadata"`
}

// ConnMetadata is the per-connection metadata block.
//
// There is deliberately no user field. sing-box does not send one.
type ConnMetadata struct {
	Network string `json:"network"`
	// Type is "<inboundType>/<inboundTag>", for example "vless/vless-exit".
	// Use InboundTypeAndTag to split it rather than indexing the string.
	Type            string `json:"type"`
	Host            string `json:"host"`
	SourceIP        string `json:"sourceIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationIP   string `json:"destinationIP"`
	DestinationPort string `json:"destinationPort"`
	DNSMode         string `json:"dnsMode"`
	ProcessPath     string `json:"processPath"`
}

// InboundTypeAndTag splits Type into the inbound type and the inbound tag.
//
// sing-box builds the field as inboundType + "/" + inboundTag and leaves it
// empty when there is no inbound, so a value with no separator is reported as a
// type with an empty tag rather than being guessed at. The split is on the
// first separator only, because an inbound tag is free text and may contain a
// slash while an inbound type never does.
func (m ConnMetadata) InboundTypeAndTag() (string, string) {
	inboundType, tag, found := strings.Cut(m.Type, "/")
	if !found {
		return m.Type, ""
	}
	return inboundType, tag
}

// SourcePortInt parses SourcePort.
func (m ConnMetadata) SourcePortInt() (int, error) {
	return parsePort("sourcePort", m.SourcePort)
}

// DestinationPortInt parses DestinationPort.
func (m ConnMetadata) DestinationPortInt() (int, error) {
	return parsePort("destinationPort", m.DestinationPort)
}

// parsePort converts one of the string ports to an int.
//
// It returns an error rather than a zero for an unparseable value because a
// port of 0 is a legal-looking number that would quietly corrupt the
// SourceIP:SourcePort join key used to match connections against log lines.
func parsePort(field, raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("singboxapi: %s is empty", field)
	}
	port, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("singboxapi: %s %q is not a number: %w", field, raw, err)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("singboxapi: %s %d is out of range", field, port)
	}
	return port, nil
}
