package beacon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// Keyring holds this node's beacon source id and its path key per target
// node, in memory only. It is safe for concurrent use.
type Keyring struct {
	mu       sync.RWMutex
	sourceID uint32
	// keys holds pointers so a replaced key can be wiped where it lives.
	keys map[string]*pathKey
}

type pathKey struct {
	epoch uint32
	key   wire.Key
}

// String names the keyring without its keys, so a formatted value never
// prints one.
func (k *Keyring) String() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return fmt.Sprintf("beacon keyring: source %d, %d targets", k.sourceID, len(k.keys))
}

// GoString is String, for %#v.
func (k *Keyring) GoString() string { return k.String() }

// Set replaces the keyring with one successful config pull: nil, or a
// config without keys, leaves it holding none. An entry with no target, a
// zero epoch or a key that is not wire.KeyLen bytes is skipped; when a
// target appears twice the newest epoch wins. Set wipes the key bytes of
// cfg.Keys once it has taken them, and the keys it replaces.
func (k *Keyring) Set(cfg *model.AgentBeaconConfig) {
	next := map[string]*pathKey{}
	var source uint32
	if cfg != nil {
		source = cfg.SourceID
		for _, e := range cfg.Keys {
			target := strings.TrimSpace(e.TargetNode)
			if target == "" || e.Epoch == 0 || len(e.Key) != wire.KeyLen {
				continue
			}
			if have, ok := next[target]; ok {
				if have.epoch >= e.Epoch {
					continue
				}
				clear(have.key[:])
			}
			pk := &pathKey{epoch: e.Epoch}
			copy(pk.key[:], e.Key)
			next[target] = pk
		}
		for i := range cfg.Keys {
			clear(cfg.Keys[i].Key)
		}
	}
	k.mu.Lock()
	old := k.keys
	k.sourceID, k.keys = source, next
	k.mu.Unlock()
	for _, pk := range old {
		// A probe running now holds its own copy (lookup), so wiping the
		// replaced key here cannot change a run in flight.
		clear(pk.key[:])
	}
}

// lookup returns the source id and the path key for target.
func (k *Keyring) lookup(target string) (uint32, pathKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pk, ok := k.keys[target]
	if !ok || k.sourceID == 0 {
		return 0, pathKey{}, false
	}
	return k.sourceID, *pk, true
}

// clientConn is the part of a connected UDP socket a run uses;
// *net.UDPConn satisfies it.
type clientConn interface {
	Write(b []byte) (int, error)
	Read(b []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// Client runs beacon checks: signed requests over one connected UDP socket
// per run to a target's advertised endpoint. It only sends, so the node
// veto does not touch it.
type Client struct {
	keys *Keyring
	// dial opens a UDP socket connected to an endpoint wire.ParseEndpoint
	// accepted.
	dial func(ctx context.Context, ep netip.AddrPort) (clientConn, error)
	// spacing is the gap between two requests of one run.
	spacing time.Duration
	// wait, when set, replaces the monitor's timeout as the time a request
	// waits for its reply (tests only).
	wait time.Duration
}

// NewClient returns a client that signs with the keys in keys.
func NewClient(keys *Keyring) *Client {
	return &Client{keys: keys, dial: dialUDP4, spacing: model.MonitorPacketSpacingMs * time.Millisecond}
}

func dialUDP4(ctx context.Context, ep netip.AddrPort) (clientConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", ep.String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("not a udp socket")
	}
	return udp, nil
}

// defaultTimeout is a request's wait when the monitor names none, as for
// every other kind.
const defaultTimeout = 5 * time.Second

func monitorTimeout(m model.Monitor) time.Duration {
	if m.TimeoutSec <= 0 {
		return defaultTimeout
	}
	return time.Duration(m.TimeoutSec) * time.Second
}

func packets(m model.Monitor) int {
	return min(max(model.MonitorPackets(m), 1), model.MonitorPacketsMax)
}

// RunBudget is the longest a beacon run of m takes: the spacing of its
// requests and the last one's wait.
func RunBudget(m model.Monitor) time.Duration {
	return time.Duration(packets(m)-1)*model.MonitorPacketSpacingMs*time.Millisecond + monitorTimeout(m)
}

// request is one request of a run and what became of it.
type request struct {
	seq      uint32
	nonce    [wire.NonceLen]byte
	sentAt   time.Time // monotonic
	sent     bool
	answered bool
	ok       bool
	rtt      time.Duration
}

// Probe runs the beacon check m once. It refuses a check without a target
// node or with an endpoint wire.ParseEndpoint refuses (destination_refused)
// and reports beacon_no_key with nothing sent when the keyring holds no key
// for the target. Otherwise it sends packets requests spacing apart, each
// waiting the check's timeout, and drops any reply that does not verify or
// whose nonce is not one it is waiting for. RTTs come from the monotonic
// clock.
func (c *Client) Probe(ctx context.Context, m model.Monitor) model.MonitorResult {
	res := model.MonitorResult{MonitorID: m.ID, At: time.Now().UTC()}
	target := strings.TrimSpace(m.TargetNode)
	if target == "" {
		res.Reason = model.PathReasonDestinationRefused
		res.Error = "destination refused: a beacon check must name its target node"
		return res
	}
	ep, err := wire.ParseEndpoint(m.Target)
	if err != nil {
		res.Reason = model.PathReasonDestinationRefused
		res.Error = "destination refused: " + err.Error()
		return res
	}
	sourceID, pk, ok := c.keys.lookup(target)
	if !ok {
		res.Reason = model.PathReasonBeaconNoKey
		res.Error = fmt.Sprintf("this agent holds no beacon key for target node %s", target)
		return res
	}
	defer clear(pk.key[:])
	timeout := monitorTimeout(m)
	if c.wait > 0 {
		timeout = c.wait
	}
	reqs := make([]request, packets(m))
	for i := range reqs {
		reqs[i].seq = uint32(i + 1) // #nosec G115 -- at most model.MonitorPacketsMax requests
		if _, err := rand.Read(reqs[i].nonce[:]); err != nil {
			res.Error = "beacon nonce: " + err.Error()
			return res
		}
	}
	// The run's own bound: every request's spacing and wait, and a second
	// of slack for scheduling.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(len(reqs)-1)*c.spacing+timeout+time.Second)
	defer cancel()
	conn, err := c.dial(ctx, ep)
	if err != nil {
		res.Error = "beacon socket: " + err.Error()
		return res
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	out := c.run(ctx, conn, sourceID, &pk, reqs, timeout)
	fillResult(&res, reqs, out)
	return res
}

// runOutcome is what a run learned besides its replies.
type runOutcome struct {
	refusals int         // reads or writes that met ECONNREFUSED
	status   wire.Status // the last non-ok status a signed reply carried
	named    bool        // status is set
	err      error       // the error that cut the run short
}

// run sends the requests on their schedule and reads replies in one
// goroutine until every sent request was answered or the last one's wait
// ran out. A request the socket will not send ends the sending there.
// ECONNREFUSED is counted and the run goes on: one port-unreachable, which
// an off-path host that guessed the socket's port can forge, must not end
// a run whose authentic replies are still on their way.
func (c *Client) run(ctx context.Context, conn clientConn, sourceID uint32, pk *pathKey, reqs []request, timeout time.Duration) runOutcome {
	var out runOutcome
	var pkt [wire.RequestLen]byte
	var buf [wire.ReadBufferLen]byte
	start := time.Now()
	planned := len(reqs)
	var final time.Time
	next, sent, answered, readErrs := 0, 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			out.err = fmt.Errorf("run cut short: %w", err)
			return out
		}
		now := time.Now()
		if next < planned && !now.Before(start.Add(time.Duration(next)*c.spacing)) {
			r := &reqs[next]
			_, err := wire.EncodeRequest(pkt[:], &pk.key, &wire.Request{
				Epoch: pk.epoch, SourceID: sourceID, Seq: r.seq, SentUnixNano: now.UnixNano(), Nonce: r.nonce,
			})
			if err == nil {
				r.sentAt = time.Now()
				_, err = conn.Write(pkt[:])
			}
			if err != nil && refused(err) {
				// The socket reported an earlier port-unreachable and did
				// not send this request; the schedule goes on.
				out.refusals++
				next++
				continue
			}
			if err != nil {
				out.err = fmt.Errorf("send: %w", err)
				planned = next
				continue
			}
			r.sent = true
			sent++
			final = r.sentAt.Add(timeout)
			next++
			continue
		}
		if next == planned && (answered == sent || !now.Before(final)) {
			return out
		}
		deadline := final
		if next < planned {
			deadline = start.Add(time.Duration(next) * c.spacing)
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			out.err = fmt.Errorf("read: %w", err)
			return out
		}
		n, err := conn.Read(buf[:])
		recvAt := time.Now()
		if err != nil {
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				readErrs = 0
			case refused(err):
				out.refusals++
			default:
				if readErrs++; readErrs >= 3 || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					out.err = fmt.Errorf("read: %w", err)
					return out
				}
			}
			continue
		}
		readErrs = 0
		if matchReply(buf[:n], pk, reqs, recvAt, timeout, &out) {
			answered++
		}
	}
}

// refused reports a connected UDP socket's ECONNREFUSED: the target's
// kernel answered port unreachable, so nothing listens there.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// matchReply verifies a reply and marks the request it answers. It must
// verify under the path key and carry the nonce and sequence of a request
// that is sent, not yet answered and still inside its wait. An ok reply
// measures the request; any other status answers it unmeasured and is
// remembered as the run's reason.
func matchReply(b []byte, pk *pathKey, reqs []request, recvAt time.Time, timeout time.Duration, out *runOutcome) bool {
	rep, err := wire.ParseReply(b, &pk.key)
	if err != nil {
		return false
	}
	for i := range reqs {
		r := &reqs[i]
		if !r.sent || r.answered || r.nonce != rep.Nonce || r.seq != rep.Seq {
			continue
		}
		rtt := recvAt.Sub(r.sentAt)
		if rtt > timeout {
			return false
		}
		r.answered = true
		if rep.Status == wire.StatusOK {
			r.ok, r.rtt = true, rtt
		} else {
			out.status, out.named = rep.Status, true
		}
		return true
	}
	return false
}

// fillResult reports the requests that left. A run with an ok reply is a
// success; one without carries the reason it learned, if any.
func fillResult(res *model.MonitorResult, reqs []request, out runOutcome) {
	for _, r := range reqs {
		if !r.sent {
			continue
		}
		res.Sent++
		if r.ok {
			res.RTTsMs = append(res.RTTsMs, float64(r.rtt.Microseconds())/1000.0)
		}
	}
	res.Lost = res.Sent - len(res.RTTsMs)
	if len(res.RTTsMs) > 0 {
		res.Success = true
		res.LatencyMs = median(res.RTTsMs)
		return
	}
	switch {
	case out.refusals >= 2 || (out.refusals == 1 && res.Sent <= 1):
		// A port-unreachable for more than one request, or for the only
		// one: a single refusal among several requests may be forged or
		// transient and reads as plain loss.
		res.Reason = model.PathReasonBeaconNotListening
		res.Error = fmt.Sprintf("nothing listens at the beacon endpoint: the target refused the datagrams (port unreachable) after %d sent", res.Sent)
	case out.named:
		res.Reason, res.Error = statusReason(out.status)
	case out.err != nil:
		res.Error = fmt.Sprintf("beacon request after %d sent: %v", res.Sent, out.err)
	default:
		res.Error = fmt.Sprintf("no reply to %d beacon requests", res.Sent)
	}
}

// statusReason maps a signed non-ok status to its result reason.
func statusReason(s wire.Status) (reason, text string) {
	switch s {
	case wire.StatusStale:
		return model.PathReasonBeaconStale, "the target's beacon answered stale: this node's clock is more than a minute from the target's"
	case wire.StatusUnknownEpoch:
		return model.PathReasonBeaconUnknownEpoch, "the target's beacon answered unknown epoch: this node's key is behind a rotation"
	default:
		return model.PathReasonBeaconRateLimited, "the target's beacon answered rate limited"
	}
}

// median is the middle value, or the mean of the two middle values when
// there is an even number of them.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}
