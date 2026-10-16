package beacon

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
)

// FuzzReceiveLoop feeds arbitrary datagrams from arbitrary IPv4 senders to
// the agent's receive-loop wrapper around a responder with a table. The
// wrapper recovers panics so the agent survives one; this test counts them
// and fails on any. It also fails on a reply to anything but an exactly
// 96-byte datagram, on a reply longer than its datagram or not exactly 64
// bytes, and on a reply that does not verify under the path key.
func FuzzReceiveLoop(f *testing.F) {
	now := t0.Add(10 * time.Minute)
	good := signedRequest(f, testSource, testEpoch, now, 1)
	f.Add(good, uint32(0xc6336407), uint16(40001))
	f.Add(good[:95], uint32(1), uint16(1))
	f.Add(append(append([]byte(nil), good...), 0), uint32(2), uint16(2))
	f.Add([]byte(wire.Magic), uint32(3), uint16(3))
	f.Add(make([]byte, wire.RequestLen), uint32(4), uint16(4))
	f.Add(make([]byte, wire.ReadBufferLen), uint32(5), uint16(5))
	f.Add(signedRequest(f, 4, 1, now, 2), uint32(6), uint16(6))
	f.Add(signedRequest(f, testSource, testEpoch, now.Add(-time.Hour), 3), uint32(7), uint16(7))
	l := newTestLoop(f, t0)
	k3 := pathKeyFor(testSource, testEpoch)
	k4 := pathKeyFor(4, 1)
	f.Fuzz(func(t *testing.T, pkt []byte, ip uint32, port uint16) {
		if len(pkt) > wire.ReadBufferLen {
			// The socket reads into a 128-byte buffer; a longer datagram
			// arrives truncated to 128 bytes.
			pkt = pkt[:wire.ReadBufferLen]
		}
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), port)
		// Each input is judged on its own, not against the budget earlier
		// inputs spent.
		l.guard.total = 0
		clear(l.guard.buckets[:])
		before := l.panics.Load()
		n := l.process(now, pkt, from)
		if l.panics.Load() != before {
			t.Fatalf("the receive loop panicked on %x", pkt)
		}
		if n == 0 {
			return
		}
		if n != wire.ReplyLen || n > len(pkt) || len(pkt) != wire.RequestLen {
			t.Fatalf("reply of %d bytes to a %d-byte datagram", n, len(pkt))
		}
		if _, err := wire.ParseReply(l.out[:n], &k3); err != nil {
			if _, err := wire.ParseReply(l.out[:n], &k4); err != nil {
				t.Fatalf("reply does not verify: %v", err)
			}
		}
	})
}
