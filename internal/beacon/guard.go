package beacon

import (
	"hash/maphash"
	"math/bits"
	"net/netip"
	"time"
)

// The pre-authentication CPU guard and the circuit breaker of design 29 D3.
// Both are owned by one receive loop and are not safe for concurrent use.

const (
	// guardGlobalPerSecond is the most datagrams one second hands to
	// Handle. Past it the receive loop stops reading until the next second,
	// so the kernel drops the excess and the rest of the agent keeps its
	// CPU.
	guardGlobalPerSecond = 20000
	// guardBuckets is the size of the counter array the guard indexes by a
	// seeded hash of the sender's address. It is fixed: the guard never
	// keeps a map keyed by addresses an attacker chooses.
	guardBuckets = 1024
	// guardPerBucketPerSecond is the most datagrams one bucket hands to
	// Handle in one second, so one flooding address cannot take the whole
	// global budget. A real source sends a few requests a second and the
	// responder answers at most 20 a second per source id.
	guardPerBucketPerSecond = 1000
)

// guardVerdict is what the guard decided for one datagram.
type guardVerdict uint8

const (
	guardAllow guardVerdict = iota
	// guardBucketFull: the sender's bucket spent its budget this second.
	guardBucketFull
	// guardGlobalFull: every bucket together spent the global budget.
	guardGlobalFull
)

// guard counts datagrams per second, globally and in a fixed array of
// buckets. It allocates nothing.
type guard struct {
	seed    maphash.Seed
	sec     int64
	total   uint32
	buckets [guardBuckets]uint32
}

func newGuard() guard {
	return guard{seed: maphash.MakeSeed()}
}

// allow spends one datagram of the budgets of the second nowNs falls in.
func (g *guard) allow(from netip.Addr, nowNs int64) guardVerdict {
	if sec := nowNs / int64(time.Second); sec != g.sec {
		clear(g.buckets[:])
		g.total = 0
		g.sec = sec
	}
	if g.total >= guardGlobalPerSecond {
		return guardGlobalFull
	}
	g.total++
	a := from.As16()
	i := maphash.Bytes(g.seed, a[:]) & (guardBuckets - 1)
	if g.buckets[i] >= guardPerBucketPerSecond {
		return guardBucketFull
	}
	g.buckets[i]++
	return guardAllow
}

// full reports whether the global budget of the second nowNs falls in is
// spent.
func (g *guard) full(nowNs int64) bool {
	return nowNs/int64(time.Second) == g.sec && g.total >= guardGlobalPerSecond
}

const (
	// breakerDropsPerSecond makes a second hot: at least this many
	// datagrams dropped in it, or the guard's global budget spent.
	breakerDropsPerSecond = 1000
	// breakerWindowSeconds and breakerHotSeconds: the breaker opens when
	// the hot seconds of the last breakerWindowSeconds number at least
	// breakerHotSeconds and the oldest of them was hot, so it opens on a
	// flood that has lasted a full minute and tolerates a few quiet
	// seconds inside it.
	breakerWindowSeconds = 60
	breakerHotSeconds    = 54
	// breakerCooldown is how long the socket stays closed once the breaker
	// opens.
	breakerCooldown = 5 * time.Minute
)

// breaker watches drops per second and opens after a minute of them.
type breaker struct {
	sec       int64  // the second drops counts
	drops     uint32 // drops in sec
	saturated bool   // the guard's global budget ran out in sec
	// hot holds one bit per closed second, the newest in bit 0: hot[i] is
	// second sec-1-i.
	hot uint64
}

// advance closes every second before nowSec. A clock that steps back keeps
// counting into the current second.
func (b *breaker) advance(nowSec int64) {
	if nowSec <= b.sec {
		return
	}
	if b.sec != 0 {
		var bit uint64
		if b.isHot() {
			bit = 1
		}
		b.hot = b.hot<<1 | bit
		if gap := nowSec - b.sec - 1; gap >= 64 {
			b.hot = 0
		} else if gap > 0 {
			b.hot <<= uint(gap)
		}
	}
	b.sec, b.drops, b.saturated = nowSec, 0, false
}

func (b *breaker) isHot() bool {
	return b.saturated || b.drops >= breakerDropsPerSecond
}

// record counts one datagram at nowNs, dropped or answered.
func (b *breaker) record(nowNs int64, dropped bool) {
	b.advance(nowNs / int64(time.Second))
	if dropped && b.drops < ^uint32(0) {
		b.drops++
	}
}

// saturate marks the second nowNs falls in as one whose global budget ran
// out: the kernel dropped what the loop did not read.
func (b *breaker) saturate(nowNs int64) {
	b.advance(nowNs / int64(time.Second))
	b.saturated = true
}

// open reports whether the last minute was a flood: the current second and
// the 59 before it hold at least breakerHotSeconds hot ones, the oldest of
// them included.
func (b *breaker) open() bool {
	const closed = breakerWindowSeconds - 1
	window := b.hot & (1<<closed - 1)
	if window&(1<<(closed-1)) == 0 {
		return false
	}
	n := bits.OnesCount64(window)
	if b.isHot() {
		n++
	}
	return n >= breakerHotSeconds
}

// hotSeconds is how many seconds of the last minute were hot, for the
// report when the breaker opens.
func (b *breaker) hotSeconds() int {
	n := bits.OnesCount64(b.hot & (1<<(breakerWindowSeconds-1) - 1))
	if b.isHot() {
		n++
	}
	return n
}
