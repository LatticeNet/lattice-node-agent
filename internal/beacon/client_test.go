package beacon

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// plannedEndpoint is the advertised endpoint the tests' checks name; the
// dial hook moves it to the loopback address under test.
const plannedEndpoint = "192.0.2.20:45000"

// testClient is a client holding testSource's key for target node "t1",
// whose sockets go to local instead of the planned endpoint.
func testClient(t *testing.T, local netip.AddrPort, epoch uint32) (*Client, *[]netip.AddrPort) {
	t.Helper()
	keys := &Keyring{}
	k := pathKeyFor(testSource, epoch)
	keys.Set(&model.AgentBeaconConfig{SourceID: testSource, Keys: []model.BeaconPathKey{{TargetNode: "t1", Epoch: epoch, Key: append([]byte(nil), k[:]...)}}})
	c := NewClient(keys)
	c.spacing = 10 * time.Millisecond
	c.wait = 300 * time.Millisecond
	var dialed []netip.AddrPort
	c.dial = func(ctx context.Context, ep netip.AddrPort) (clientConn, error) {
		dialed = append(dialed, ep)
		return dialUDP4(ctx, local)
	}
	return c, &dialed
}

func beaconCheck(packets int) model.Monitor {
	return model.Monitor{ID: "mon_latb_t1", Type: model.MonitorTypeBeacon, Target: plannedEndpoint, TargetNode: "t1", Packets: packets, TimeoutSec: 1, IntervalSec: 30}
}

// Against a real responder, a run sends its packets and measures each ok
// reply.
func TestClientMeasuresARealResponder(t *testing.T) {
	_, _, local := listeningResponder(t, nil)
	c, dialed := testClient(t, local, testEpoch)
	res := c.Probe(context.Background(), beaconCheck(5))
	if !res.Success || res.Sent != 5 || res.Lost != 0 || len(res.RTTsMs) != 5 || res.Reason != "" || res.Error != "" {
		t.Fatalf("result %+v", res)
	}
	if res.LatencyMs != median(res.RTTsMs) || res.MonitorID != "mon_latb_t1" {
		t.Fatalf("latency %v of %v", res.LatencyMs, res.RTTsMs)
	}
	if len(*dialed) != 1 || (*dialed)[0] != netip.MustParseAddrPort(plannedEndpoint) {
		t.Fatalf("dialed %v; one connected socket per run to the endpoint", *dialed)
	}
	// Zero packets reads as five; more than ten is held to ten.
	if res := c.Probe(context.Background(), beaconCheck(0)); res.Sent != model.MonitorPacketsDefault {
		t.Fatalf("packets 0 sent %d", res.Sent)
	}
	if res := c.Probe(context.Background(), beaconCheck(50)); res.Sent != model.MonitorPacketsMax {
		t.Fatalf("packets 50 sent %d", res.Sent)
	}
}

// A responder whose clock is two minutes ahead answers stale, once per
// second; the run reads beacon_stale with every request lost.
func TestClientReportsStaleFromARealResponder(t *testing.T) {
	_, _, local := listeningResponder(t, func() time.Time { return time.Now().Add(2 * time.Minute) })
	c, _ := testClient(t, local, testEpoch)
	res := c.Probe(context.Background(), beaconCheck(3))
	if res.Success || res.Reason != model.PathReasonBeaconStale || res.Sent != 3 || res.Lost != 3 || len(res.RTTsMs) != 0 {
		t.Fatalf("result %+v", res)
	}
}

// A source still sending with a retired epoch reads beacon_unknown_epoch.
func TestClientReportsUnknownEpochFromARealResponder(t *testing.T) {
	r, l, local := listeningResponder(t, nil)
	cfg := responderConfig(int(l.calls()[0].Port()))
	cfg.Table[0].Retired = true
	k8 := pathKeyFor(testSource, testEpoch+1)
	cfg.Table = append(cfg.Table, model.BeaconTableKey{SourceID: testSource, Epoch: testEpoch + 1, Key: append([]byte(nil), k8[:]...)})
	r.Apply(cfg)
	c, _ := testClient(t, local, testEpoch)
	res := c.Probe(context.Background(), beaconCheck(2))
	if res.Success || res.Reason != model.PathReasonBeaconUnknownEpoch || res.Sent != 2 || res.Lost != 2 {
		t.Fatalf("result %+v", res)
	}
}

// fakeTarget answers each request with what reply returns, signed with
// key, from a loopback socket.
func fakeTarget(t *testing.T, key wire.Key, reply func(req wire.Request, n int) [][]byte) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 256)
		count := 0
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			req, err := wire.ParseRequest(buf[:n])
			if err != nil || !wire.VerifyRequest(buf[:n], &key) {
				continue
			}
			count++
			for _, d := range reply(req, count) {
				_, _ = conn.WriteToUDPAddrPort(d, from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// encodeReply signs a reply; it runs on the fake target's goroutine, so a
// failure shows as a missing reply rather than through t.
func encodeReply(_ *testing.T, key wire.Key, rep wire.Reply) []byte {
	b := make([]byte, wire.ReplyLen)
	if _, err := wire.EncodeReply(b, &key, &rep); err != nil {
		return nil
	}
	return b
}

// A rate-limited reply names the reason; an ok reply after a refusal still
// measures; a reply whose nonce or sequence the run did not send, one that
// does not verify, and one longer than a reply are all dropped.
func TestClientJudgesReplies(t *testing.T) {
	key := pathKeyFor(testSource, testEpoch)
	other := pathKeyFor(testSource, testEpoch+5)
	t.Run("rate limited", func(t *testing.T) {
		local := fakeTarget(t, key, func(req wire.Request, n int) [][]byte {
			return [][]byte{encodeReply(t, key, wire.Reply{Status: wire.StatusRateLimited, Seq: req.Seq, Nonce: req.Nonce})}
		})
		c, _ := testClient(t, local, testEpoch)
		res := c.Probe(context.Background(), beaconCheck(3))
		if res.Success || res.Reason != model.PathReasonBeaconRateLimited || res.Sent != 3 || res.Lost != 3 {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("one ok among refusals is a success without a reason", func(t *testing.T) {
		local := fakeTarget(t, key, func(req wire.Request, n int) [][]byte {
			status := wire.StatusRateLimited
			if n == 2 {
				status = wire.StatusOK
			}
			return [][]byte{encodeReply(t, key, wire.Reply{Status: status, Seq: req.Seq, Nonce: req.Nonce})}
		})
		c, _ := testClient(t, local, testEpoch)
		res := c.Probe(context.Background(), beaconCheck(3))
		if !res.Success || res.Reason != "" || res.Sent != 3 || res.Lost != 2 || len(res.RTTsMs) != 1 {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("forged and foreign replies are dropped", func(t *testing.T) {
		local := fakeTarget(t, key, func(req wire.Request, n int) [][]byte {
			wrongNonce := req.Nonce
			wrongNonce[0] ^= 1
			long := append(encodeReply(t, key, wire.Reply{Status: wire.StatusOK, Seq: req.Seq, Nonce: req.Nonce}), 0)
			return [][]byte{
				encodeReply(t, key, wire.Reply{Status: wire.StatusOK, Seq: req.Seq, Nonce: wrongNonce}),
				encodeReply(t, key, wire.Reply{Status: wire.StatusOK, Seq: req.Seq + 100, Nonce: req.Nonce}),
				encodeReply(t, other, wire.Reply{Status: wire.StatusOK, Seq: req.Seq, Nonce: req.Nonce}),
				encodeReply(t, key, wire.Reply{Status: wire.StatusStale, Seq: req.Seq, Nonce: wrongNonce}),
				long,
			}
		})
		c, _ := testClient(t, local, testEpoch)
		res := c.Probe(context.Background(), beaconCheck(3))
		if res.Success || res.Reason != "" || res.Sent != 3 || res.Lost != 3 || !strings.Contains(res.Error, "no reply to 3") {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("plain loss carries no reason", func(t *testing.T) {
		local := fakeTarget(t, key, func(wire.Request, int) [][]byte { return nil })
		c, _ := testClient(t, local, testEpoch)
		res := c.Probe(context.Background(), beaconCheck(2))
		if res.Success || res.Reason != "" || res.Sent != 2 || res.Lost != 2 || res.Error == "" {
			t.Fatalf("result %+v", res)
		}
	})
}

// A connected socket that reads ECONNREFUSED means nothing listens at the
// endpoint: beacon_not_listening.
func TestClientReportsNotListening(t *testing.T) {
	closed := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(freeUDPPort(t)))
	c, _ := testClient(t, closed, testEpoch)
	c.wait = 2 * time.Second
	res := c.Probe(context.Background(), beaconCheck(3))
	if res.Success || res.Reason != model.PathReasonBeaconNotListening || res.Sent == 0 || res.Lost != res.Sent {
		t.Fatalf("result %+v", res)
	}
}

// Without a key for the target, nothing is sent: beacon_no_key.
func TestClientWithoutAKeySendsNothing(t *testing.T) {
	keys := &Keyring{}
	c := NewClient(keys)
	c.dial = func(context.Context, netip.AddrPort) (clientConn, error) {
		t.Fatal("dialed without a key")
		return nil, nil
	}
	res := c.Probe(context.Background(), beaconCheck(5))
	if res.Reason != model.PathReasonBeaconNoKey || res.Sent != 0 || res.Success {
		t.Fatalf("result %+v", res)
	}
	// A key for another target, or a key without a source id, is no key.
	k := pathKeyFor(testSource, testEpoch)
	keys.Set(&model.AgentBeaconConfig{SourceID: testSource, Keys: []model.BeaconPathKey{{TargetNode: "t2", Epoch: 1, Key: append([]byte(nil), k[:]...)}}})
	if res := c.Probe(context.Background(), beaconCheck(5)); res.Reason != model.PathReasonBeaconNoKey {
		t.Fatalf("result %+v", res)
	}
	keys.Set(&model.AgentBeaconConfig{Keys: []model.BeaconPathKey{{TargetNode: "t1", Epoch: 1, Key: append([]byte(nil), k[:]...)}}})
	if res := c.Probe(context.Background(), beaconCheck(5)); res.Reason != model.PathReasonBeaconNoKey {
		t.Fatalf("result %+v", res)
	}
}

// An endpoint beacon.ParseEndpoint refuses, or a check without a target
// node, is refused before anything is dialed.
func TestClientRefusesEndpoints(t *testing.T) {
	_, _, local := listeningResponder(t, nil)
	c, dialed := testClient(t, local, testEpoch)
	for _, target := range []string{
		"localhost:45000", "127.0.0.1:45000", "0.0.0.0:45000", "169.254.169.254:80", "224.0.0.1:45000",
		"255.255.255.255:45000", "[::1]:45000", "[2001:db8::1]:45000", "192.0.2.20", "192.0.2.20:0",
		"192.0.2.20:70000", "beacon.example.com:45000", "",
	} {
		m := beaconCheck(3)
		m.Target = target
		res := c.Probe(context.Background(), m)
		if res.Reason != model.PathReasonDestinationRefused || res.Sent != 0 {
			t.Fatalf("%q: result %+v", target, res)
		}
	}
	m := beaconCheck(3)
	m.TargetNode = ""
	if res := c.Probe(context.Background(), m); res.Reason != model.PathReasonDestinationRefused {
		t.Fatalf("no target node: %+v", res)
	}
	if len(*dialed) != 0 {
		t.Fatalf("dialed %v", *dialed)
	}
}

// The keyring keeps the newest epoch per target, skips malformed entries,
// and wipes the decoded keys it was handed and the keys it replaces.
func TestKeyringSetWipesAndValidates(t *testing.T) {
	keys := &Keyring{}
	k := pathKeyFor(testSource, testEpoch)
	k2 := pathKeyFor(testSource, testEpoch+1)
	cfg := &model.AgentBeaconConfig{SourceID: testSource, Keys: []model.BeaconPathKey{
		{TargetNode: "t1", Epoch: testEpoch + 1, Key: append([]byte(nil), k2[:]...)},
		{TargetNode: "t1", Epoch: testEpoch, Key: append([]byte(nil), k[:]...)},
		{TargetNode: "t2", Epoch: 1, Key: append([]byte(nil), k[:31]...)},
		{TargetNode: "", Epoch: 1, Key: append([]byte(nil), k[:]...)},
		{TargetNode: "t3", Epoch: 0, Key: append([]byte(nil), k[:]...)},
	}}
	keys.Set(cfg)
	for i, e := range cfg.Keys {
		if !bytes.Equal(e.Key, make([]byte, len(e.Key))) {
			t.Fatalf("entry %d not wiped", i)
		}
	}
	src, pk, ok := keys.lookup("t1")
	if !ok || src != testSource || pk.epoch != testEpoch+1 || pk.key != k2 {
		t.Fatalf("lookup t1: %d %d %v", src, pk.epoch, ok)
	}
	for _, target := range []string{"t2", "t3", ""} {
		if _, _, ok := keys.lookup(target); ok {
			t.Fatalf("malformed entry for %q kept", target)
		}
	}
	held := keys.keys
	keys.Set(nil)
	if len(held) != 0 {
		t.Fatal("the replaced map still holds keys")
	}
	if _, _, ok := keys.lookup("t1"); ok {
		t.Fatal("a nil config left a key")
	}
}

// Requests within one run never repeat a nonce, and runs never share one.
func TestClientNoncesAreFresh(t *testing.T) {
	key := pathKeyFor(testSource, testEpoch)
	var mu sync.Mutex
	seen := map[[wire.NonceLen]byte]bool{}
	dup := false
	local := fakeTarget(t, key, func(req wire.Request, n int) [][]byte {
		mu.Lock()
		if seen[req.Nonce] {
			dup = true
		}
		seen[req.Nonce] = true
		mu.Unlock()
		return [][]byte{encodeReply(t, key, wire.Reply{Status: wire.StatusOK, Seq: req.Seq, Nonce: req.Nonce})}
	})
	c, _ := testClient(t, local, testEpoch)
	for range 3 {
		if res := c.Probe(context.Background(), beaconCheck(10)); !res.Success || res.Lost != 0 {
			t.Fatalf("result %+v", res)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if dup || len(seen) != 30 {
		t.Fatalf("%d distinct nonces, duplicate %v", len(seen), dup)
	}
}

// The run budget covers the spacing of every request and the last wait.
func TestRunBudget(t *testing.T) {
	m := beaconCheck(5)
	m.TimeoutSec = 2
	if got := RunBudget(m); got != 4*200*time.Millisecond+2*time.Second {
		t.Fatalf("budget %v", got)
	}
}
