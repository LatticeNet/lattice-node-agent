package beacon

import (
	"context"
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Node is one node's beacon: the responder and the client, both fed by the
// "beacon" key of the agent config pull.
type Node struct {
	responder *Responder
	keys      *Keyring
	client    *Client
}

// NewNode returns a node beacon whose responder is off until a config pull
// turns it on. With noBeacon (the -no-beacon flag) the responder never
// binds; the client still runs beacon checks, since it only sends.
func NewNode(noBeacon bool) *Node {
	keys := &Keyring{}
	return &Node{responder: NewResponder(noBeacon), keys: keys, client: NewClient(keys)}
}

// SetOnChange sets a function called after the responder's facts change.
func (n *Node) SetOnChange(fn func()) { n.responder.SetOnChange(fn) }

// Apply takes one successful config pull. A nil cfg (a server that sends
// no beacon) leaves the node holding no keys and closes any responder
// socket. Apply wipes the key bytes of cfg once it has taken them.
func (n *Node) Apply(cfg *model.AgentBeaconConfig) {
	n.keys.Set(cfg)
	var responder *model.BeaconResponderConfig
	if cfg != nil {
		responder = cfg.Responder
	}
	n.responder.Apply(responder)
}

// Facts is the "beacon" key of hello and heartbeat bodies.
func (n *Node) Facts() model.BeaconFacts { return n.responder.Facts() }

// Probe runs one beacon check.
func (n *Node) Probe(ctx context.Context, m model.Monitor) model.MonitorResult {
	return n.client.Probe(ctx, m)
}

// Close closes the responder's socket as the agent stops.
func (n *Node) Close() { n.responder.Close() }

// String names the node beacon without any key.
func (n *Node) String() string {
	f := n.Facts()
	return fmt.Sprintf("beacon: responder %s, %s", f.State, n.keys)
}

// GoString is String, for %#v.
func (n *Node) GoString() string { return n.String() }
