package prober

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsHandler answers one query; it returns the packed response, or nil to
// send nothing. network is "udp" or "tcp" (DoT and DoH answer as "tcp").
type dnsHandler func(network string, q dnsmessage.Message) []byte

// dnsStub is a resolver on loopback: UDP and TCP on their own ports, the
// TCP side optionally inside TLS. queries counts the queries it read.
type dnsStub struct {
	udp     net.PacketConn
	tcp     net.Listener
	queries atomic.Int32
	handle  dnsHandler
}

func newDNSStub(t *testing.T, tlsConfig *tls.Config, handle dnsHandler) *dnsStub {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		tcp = tls.NewListener(tcp, tlsConfig)
	}
	s := &dnsStub{udp: udp, tcp: tcp, handle: handle}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	go s.serveUDP()
	go s.serveTCP()
	return s
}

func (s *dnsStub) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			continue
		}
		s.queries.Add(1)
		if out := s.handle("udp", q); out != nil {
			_, _ = s.udp.WriteTo(out, from)
		}
	}
}

func (s *dnsStub) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			raw := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(conn, raw); err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(raw) != nil {
				return
			}
			s.queries.Add(1)
			out := s.handle("tcp", q)
			if out == nil {
				return
			}
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(out)))
			_, _ = conn.Write(append(frame, out...))
		}()
	}
}

// dnsProber resolves testHost to testPublicAddr and carries a dial to that
// address to the stub's socket of the same network, so the destination
// rules run as on a node. roots verifies DoT and DoH.
func dnsProber(t *testing.T, udp, tcp net.Addr, roots *x509.CertPool) *prober {
	t.Helper()
	real := &net.Dialer{}
	p := newProber()
	p.resolver = &fakeResolver{answers: map[string][]string{testHost: {testPublicAddr}, "internal.example": {"10.0.0.5"}}}
	p.rootCAs = roots
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != testPublicAddr {
			return nil, fmt.Errorf("test dialer: unexpected address %s", address)
		}
		switch network {
		case "udp":
			return real.DialContext(ctx, network, udp.String())
		case "tcp":
			return real.DialContext(ctx, network, tcp.String())
		}
		return nil, fmt.Errorf("test dialer: unexpected network %s", network)
	}
	return p
}

// testCert is a self-signed certificate for names, and a pool that trusts it.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second).UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, notAfter
}

// dnsReply builds the response to q. A code above 15 carries its upper
// bits in an EDNS(0) record, as a resolver sends it.
func dnsReply(q dnsmessage.Message, rcode dnsmessage.RCode, truncated bool, answers ...dnsmessage.Resource) []byte {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RCode: rcode & 0xF, Truncated: truncated},
		Questions: q.Questions,
		Answers:   answers,
	}
	if rcode > 0xF {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(1232, rcode, false); err != nil {
			panic(err)
		}
		msg.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	out, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return out
}

func rrHeader(q dnsmessage.Message, typ dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: typ, Class: dnsmessage.ClassINET, TTL: 60}
}

func aRecord(q dnsmessage.Message, addr string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: netip.MustParseAddr(addr).As4()}}
}

// answerA answers every A question with addrs.
func answerA(addrs ...string) dnsHandler {
	return func(_ string, q dnsmessage.Message) []byte {
		var rrs []dnsmessage.Resource
		for _, a := range addrs {
			rrs = append(rrs, aRecord(q, a))
		}
		return dnsReply(q, dnsmessage.RCodeSuccess, false, rrs...)
	}
}

func dnsMonitor(target string) model.Monitor {
	return model.Monitor{ID: "mon_dns", Type: model.MonitorTypeDNS, Target: target, TimeoutSec: 2, DNSName: "www.example.org"}
}

func failureCode(res model.MonitorResult) string {
	code, _, _ := strings.Cut(res.Error, ":")
	return code
}

// Every transport: a pass with the default judgement (an answer of the
// asked type), a pass with the expected set, and a mismatch that reports
// what came back.
func TestDNSPassAndMismatchOverEveryTransport(t *testing.T) {
	cert, roots, notAfter := testCert(t, testHost)
	plain := newDNSStub(t, nil, answerA("192.0.2.1", "192.0.2.2"))
	secure := newDNSStub(t, &tls.Config{Certificates: []tls.Certificate{cert}}, answerA("192.0.2.1", "192.0.2.2"))
	doh := dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerA("192.0.2.1", "192.0.2.2")("tcp", q))
	})
	for _, tc := range []struct {
		name   string
		p      *prober
		target string
		cert   bool
	}{
		{"udp", dnsProber(t, plain.udp.LocalAddr(), plain.tcp.Addr(), nil), "udp://" + testHost, false},
		{"tcp", dnsProber(t, plain.udp.LocalAddr(), plain.tcp.Addr(), nil), "tcp://" + testHost, false},
		{"dot", dnsProber(t, plain.udp.LocalAddr(), secure.tcp.Addr(), roots), "tls://" + testHost, true},
		{"doh", dnsProber(t, plain.udp.LocalAddr(), doh.Listener.Addr(), roots), "https://" + testHost + "/dns-query", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := dnsMonitor(tc.target)
			res := tc.p.probe(context.Background(), m)
			if !res.Success || res.DNSRcode != "NOERROR" || !slices.Equal(res.DNSAnswers, []string{"192.0.2.1", "192.0.2.2"}) || res.Error != "" {
				t.Fatalf("default judgement: %+v", res)
			}
			if res.LatencyMs <= 0 {
				t.Fatalf("no latency recorded: %+v", res)
			}
			if tc.cert != !res.CertNotAfter.IsZero() || (tc.cert && !res.CertNotAfter.Equal(notAfter)) {
				t.Fatalf("cert_not_after = %v, want %v (recorded: %v)", res.CertNotAfter, notAfter, tc.cert)
			}
			m.DNSExpect = []string{"192.0.2.2"}
			if res := tc.p.probe(context.Background(), m); !res.Success {
				t.Fatalf("expected value present: %+v", res)
			}
			m.DNSExpect = []string{"192.0.2.2", "198.51.100.7"}
			res = tc.p.probe(context.Background(), m)
			if res.Success || failureCode(res) != model.DNSFailureMismatch || !strings.Contains(res.Error, "198.51.100.7") ||
				!slices.Equal(res.DNSAnswers, []string{"192.0.2.1", "192.0.2.2"}) || res.Reason != "" {
				t.Fatalf("mismatch: %+v", res)
			}
		})
	}
}

// NXDOMAIN expected and received passes; NXDOMAIN when an answer is
// expected fails with the code; an answer when NXDOMAIN is expected fails
// too; SERVFAIL fails naming SERVFAIL.
func TestDNSResponseCodes(t *testing.T) {
	var rcode atomic.Int32
	stub := newDNSStub(t, nil, func(_ string, q dnsmessage.Message) []byte {
		code := dnsmessage.RCode(rcode.Load())
		if code == dnsmessage.RCodeSuccess {
			return answerA("192.0.2.1")("udp", q)
		}
		return dnsReply(q, code, false)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	m := dnsMonitor("udp://" + testHost)

	rcode.Store(int32(dnsmessage.RCodeNameError))
	res := p.probe(context.Background(), m)
	if res.Success || failureCode(res) != model.DNSFailureRcode || res.DNSRcode != "NXDOMAIN" {
		t.Fatalf("NXDOMAIN for a name expected to resolve: %+v", res)
	}
	m.DNSExpectRcode = model.DNSRcodeNXDomain
	if res := p.probe(context.Background(), m); !res.Success || res.DNSRcode != "NXDOMAIN" {
		t.Fatalf("NXDOMAIN expected and received: %+v", res)
	}
	rcode.Store(int32(dnsmessage.RCodeSuccess))
	if res := p.probe(context.Background(), m); res.Success || failureCode(res) != model.DNSFailureRcode || res.DNSRcode != "NOERROR" {
		t.Fatalf("a name that must not resolve resolved: %+v", res)
	}
	m.DNSExpectRcode = ""
	rcode.Store(int32(dnsmessage.RCodeServerFailure))
	res = p.probe(context.Background(), m)
	if res.Success || failureCode(res) != model.DNSFailureRcode || res.DNSRcode != "SERVFAIL" || !strings.Contains(res.Error, "SERVFAIL") || res.Reason != "" {
		t.Fatalf("SERVFAIL: %+v", res)
	}
	rcode.Store(23)
	if res := p.probe(context.Background(), m); res.DNSRcode != "BADCOOKIE" {
		t.Fatalf("a code above 15 needs the EDNS record to read; got %+v", res)
	}
}

// NOERROR with no answer of the asked type (here only a CNAME) is
// dns_no_answer.
func TestDNSNoAnswerOfTheAskedType(t *testing.T) {
	stub := newDNSStub(t, nil, func(_ string, q dnsmessage.Message) []byte {
		target := dnsmessage.MustNewName("edge.example.net.")
		return dnsReply(q, dnsmessage.RCodeSuccess, false, dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: target}})
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	res := p.probe(context.Background(), dnsMonitor("udp://"+testHost))
	if res.Success || failureCode(res) != model.DNSFailureNoAnswer || res.DNSRcode != "NOERROR" || len(res.DNSAnswers) != 0 {
		t.Fatalf("CNAME only for an A question: %+v", res)
	}
	m := dnsMonitor("udp://" + testHost)
	m.DNSType, m.DNSExpect = model.DNSTypeCNAME, []string{"EDGE.example.net."}
	if res := p.probe(context.Background(), m); !res.Success || !slices.Equal(res.DNSAnswers, []string{"edge.example.net"}) {
		t.Fatalf("CNAME compared without case or the trailing dot: %+v", res)
	}
}

// Values of the other types compare in the SDK's canonical form: AAAA as
// parsed addresses, MX as the exchange, TXT as the joined strings.
func TestDNSValueForms(t *testing.T) {
	stub := newDNSStub(t, nil, func(_ string, q dnsmessage.Message) []byte {
		switch q.Questions[0].Type {
		case dnsmessage.TypeAAAA:
			return dnsReply(q, dnsmessage.RCodeSuccess, false, dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeAAAA),
				Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}})
		case dnsmessage.TypeMX:
			return dnsReply(q, dnsmessage.RCodeSuccess, false, dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeMX),
				Body: &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("Mx1.Example.org.")}})
		case dnsmessage.TypeTXT:
			return dnsReply(q, dnsmessage.RCodeSuccess, false, dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeTXT),
				Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1 ", "-all"}}})
		}
		return dnsReply(q, dnsmessage.RCodeSuccess, false)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	for typ, expect := range map[string]string{
		model.DNSTypeAAAA: "2001:DB8:0::1",
		model.DNSTypeMX:   "mx1.example.org",
		model.DNSTypeTXT:  "v=spf1 -all",
	} {
		m := dnsMonitor("udp://" + testHost)
		m.DNSType, m.DNSExpect = typ, []string{expect}
		if res := p.probe(context.Background(), m); !res.Success {
			t.Errorf("%s %q: %+v", typ, expect, res)
		}
	}
}

// A truncated UDP answer is asked again once over TCP, and the TCP answer
// is judged.
func TestDNSTruncatedUDPRetriesOverTCP(t *testing.T) {
	var udpQueries, tcpQueries atomic.Int32
	stub := newDNSStub(t, nil, func(network string, q dnsmessage.Message) []byte {
		if network == "udp" {
			udpQueries.Add(1)
			return dnsReply(q, dnsmessage.RCodeSuccess, true)
		}
		tcpQueries.Add(1)
		return answerA("192.0.2.9")(network, q)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	m := dnsMonitor("udp://" + testHost)
	m.DNSExpect = []string{"192.0.2.9"}
	res := p.probe(context.Background(), m)
	if !res.Success || !slices.Equal(res.DNSAnswers, []string{"192.0.2.9"}) {
		t.Fatalf("truncated answer not retried over TCP: %+v", res)
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("queries udp=%d tcp=%d, want one each", udpQueries.Load(), tcpQueries.Load())
	}
}

// A DoH status other than 200 is dns_transport naming the status, and the
// certificate is still recorded.
func TestDNSDoHServerError(t *testing.T) {
	cert, roots, notAfter := testCert(t, testHost)
	doh := dohServer(t, cert, func(w http.ResponseWriter, _ dnsmessage.Message) {
		http.Error(w, "upstream down", http.StatusInternalServerError)
	})
	p := dnsProber(t, nil, doh.Listener.Addr(), roots)
	res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query"))
	if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "500") || res.Reason != "" || res.DNSRcode != "" {
		t.Fatalf("DoH 500: %+v", res)
	}
	if !res.CertNotAfter.Equal(notAfter) {
		t.Fatalf("the handshake completed; cert_not_after = %v", res.CertNotAfter)
	}
}

// A certificate for another name fails the handshake, over DoT and DoH,
// before any query is sent, and records no expiry.
func TestDNSCertificateForAnotherName(t *testing.T) {
	cert, roots, _ := testCert(t, "other.example")
	dot := newDNSStub(t, &tls.Config{Certificates: []tls.Certificate{cert}}, answerA("192.0.2.1"))
	var dohQueries atomic.Int32
	doh := dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
		dohQueries.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerA("192.0.2.1")("tcp", q))
	})
	for name, tc := range map[string]struct {
		p      *prober
		target string
	}{
		"dot": {dnsProber(t, nil, dot.tcp.Addr(), roots), "tls://" + testHost},
		"doh": {dnsProber(t, nil, doh.Listener.Addr(), roots), "https://" + testHost + "/dns-query"},
	} {
		res := tc.p.probe(context.Background(), dnsMonitor(tc.target))
		if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "certificate") || !res.CertNotAfter.IsZero() {
			t.Fatalf("%s: a certificate for other.example was accepted for %s: %+v", name, testHost, res)
		}
	}
	if dot.queries.Load() != 0 || dohQueries.Load() != 0 {
		t.Fatalf("a query reached a resolver whose certificate failed: dot=%d doh=%d", dot.queries.Load(), dohQueries.Load())
	}
}

// A resolver slower than the timeout fails within the timeout, over UDP
// and DoH alike.
func TestDNSSlowerThanTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	slow := newDNSStub(t, nil, func(network string, q dnsmessage.Message) []byte {
		<-release
		return nil
	})
	cert, roots, _ := testCert(t, testHost)
	doh := dohServer(t, cert, func(w http.ResponseWriter, _ dnsmessage.Message) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	for name, tc := range map[string]struct {
		p      *prober
		target string
	}{
		"udp": {dnsProber(t, slow.udp.LocalAddr(), slow.tcp.Addr(), nil), "udp://" + testHost},
		"tcp": {dnsProber(t, slow.udp.LocalAddr(), slow.tcp.Addr(), nil), "tcp://" + testHost},
		"doh": {dnsProber(t, nil, doh.Listener.Addr(), roots), "https://" + testHost + "/dns-query"},
	} {
		m := dnsMonitor(tc.target)
		m.TimeoutSec = 1
		start := time.Now()
		res := tc.p.probe(context.Background(), m)
		if took := time.Since(start); took > 1500*time.Millisecond {
			t.Fatalf("%s: the run took %s past a 1 s timeout", name, took)
		}
		if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "timeout") {
			t.Fatalf("%s: slow resolver: %+v", name, res)
		}
	}
}

// A DoH body over 64 KiB is refused, whether or not it declares its
// length.
func TestDNSResponseOver64KiB(t *testing.T) {
	cert, roots, _ := testCert(t, testHost)
	for _, declared := range []bool{true, false} {
		doh := dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
			body := append(answerA("192.0.2.1")("tcp", q), make([]byte, model.MonitorDNSResponseMax)...)
			w.Header().Set("Content-Type", "application/dns-message")
			if declared {
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			} else {
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write(body)
		})
		p := dnsProber(t, nil, doh.Listener.Addr(), roots)
		res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query"))
		if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "64 KiB") {
			t.Fatalf("declared=%v: oversized response: %+v", declared, res)
		}
	}
}

// A DoH answer that is not a DNS message (a wrong path serving HTML) is a
// transport failure naming the content type.
func TestDNSDoHWrongContentType(t *testing.T) {
	cert, roots, _ := testCert(t, testHost)
	doh := dohServer(t, cert, func(w http.ResponseWriter, _ dnsmessage.Message) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})
	p := dnsProber(t, nil, doh.Listener.Addr(), roots)
	res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query"))
	if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "text/html") {
		t.Fatalf("html answer: %+v", res)
	}
}

// A resolver whose name resolves to a private address is refused before
// any query: the destination_refused reason, not a failure, and nothing
// dialed.
func TestDNSPrivateResolverRefusedBeforeQuery(t *testing.T) {
	for _, target := range []string{"udp://internal.example", "tls://internal.example", "https://internal.example/dns-query", "tcp://10.0.0.5", "udp://169.254.169.254"} {
		p, _, dialer := fakeNetProber(map[string][]string{"internal.example": {"10.0.0.5"}})
		res := p.probe(context.Background(), dnsMonitor(target))
		if res.Reason != model.PathReasonDestinationRefused || res.Success || res.DNSRcode != "" {
			t.Fatalf("%s: %+v", target, res)
		}
		if got := dialer.addresses(); len(got) != 0 {
			t.Fatalf("%s: dialed %v", target, got)
		}
	}
}

// An answer that does not echo the query's ID is ignored, so a stray or
// spoofed datagram cannot pass the check.
func TestDNSUDPIgnoresAnswerToAnotherQuery(t *testing.T) {
	stub := newDNSStub(t, nil, func(_ string, q dnsmessage.Message) []byte {
		q.ID++
		return answerA("192.0.2.1")("udp", q)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	m := dnsMonitor("udp://" + testHost)
	m.TimeoutSec = 1
	if res := p.probe(context.Background(), m); res.Success || failureCode(res) != model.DNSFailureTransport {
		t.Fatalf("an answer with another ID was taken: %+v", res)
	}
}

// Answers are reported bounded: at most 16, each at most 255 bytes, while
// the judgement still sees every answer.
func TestDNSAnswersReportedBounded(t *testing.T) {
	long := strings.Repeat("x", 250)
	stub := newDNSStub(t, nil, func(network string, q dnsmessage.Message) []byte {
		if q.Questions[0].Type == dnsmessage.TypeTXT {
			return dnsReply(q, dnsmessage.RCodeSuccess, false, dnsmessage.Resource{Header: rrHeader(q, dnsmessage.TypeTXT),
				Body: &dnsmessage.TXTResource{TXT: []string{long, long}}})
		}
		var addrs []string
		for i := 1; i <= 20; i++ {
			addrs = append(addrs, "192.0.2."+strconv.Itoa(i))
		}
		return answerA(addrs...)(network, q)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	m := dnsMonitor("tcp://" + testHost)
	m.DNSExpect = []string{"192.0.2.20"}
	res := p.probe(context.Background(), m)
	if !res.Success || len(res.DNSAnswers) != model.MonitorDNSAnswersMax {
		t.Fatalf("20 answers: %+v", res)
	}
	m.DNSType, m.DNSExpect = model.DNSTypeTXT, nil
	res = p.probe(context.Background(), m)
	if !res.Success || len(res.DNSAnswers) != 1 || len(res.DNSAnswers[0]) != model.MonitorDNSValueMax {
		t.Fatalf("a 500-byte TXT value: %+v", res)
	}
}

// The query asks with recursion desired and an EDNS(0) record; a DoH query
// carries ID 0 (RFC 8484 section 4.1).
func TestDNSQueryShape(t *testing.T) {
	q, err := dnsQuestionOf(model.Monitor{DNSName: "Example.org.", DNSType: "aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	for _, doh := range []bool{false, true} {
		raw, id, err := dnsQuery(q, doh)
		if err != nil {
			t.Fatal(err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if !msg.RecursionDesired || msg.ID != id || (doh && id != 0) || len(msg.Questions) != 1 ||
			msg.Questions[0].Name.String() != "example.org." || msg.Questions[0].Type != dnsmessage.TypeAAAA ||
			len(msg.Additionals) != 1 || msg.Additionals[0].Header.Type != dnsmessage.TypeOPT {
			t.Fatalf("doh=%v query = %+v", doh, msg)
		}
	}
}

// A dns check the control plane would refuse is refused by the agent too,
// as a failure that names the field, before anything is resolved.
func TestDNSInvalidCheckFails(t *testing.T) {
	p, resolver, _ := fakeNetProber(map[string][]string{testHost: {testPublicAddr}})
	for name, m := range map[string]model.Monitor{
		"scheme":     dnsMonitor("quic://" + testHost),
		"no path":    dnsMonitor("https://" + testHost),
		"empty name": {Type: model.MonitorTypeDNS, Target: "udp://" + testHost},
		"type":       {Type: model.MonitorTypeDNS, Target: "udp://" + testHost, DNSName: "a.example", DNSType: "HTTPS"},
		"expect":     {Type: model.MonitorTypeDNS, Target: "udp://" + testHost, DNSName: "a.example", DNSExpect: []string{"not-an-address"}},
		"rcode":      {Type: model.MonitorTypeDNS, Target: "udp://" + testHost, DNSName: "a.example", DNSExpectRcode: "SERVFAIL"},
	} {
		res := p.probe(context.Background(), m)
		if res.Success || res.Error == "" || res.Reason != "" {
			t.Fatalf("%s: %+v", name, res)
		}
	}
	if len(resolver.lookups) != 0 {
		t.Fatalf("an invalid check was resolved: %v", resolver.lookups)
	}
}

// dohServer is an https server for testHost on loopback whose handler gets
// the decoded query of every POST of application/dns-message.
func dohServer(t *testing.T, cert tls.Certificate, handle func(http.ResponseWriter, dnsmessage.Message)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "not a DoH query", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if err == nil {
			err = q.Unpack(raw)
		}
		if err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		handle(w, q)
	}))
	srv.EnableHTTP2 = true
	// A handshake the client refuses is the point of some tests.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// A truncated answer that cannot be asked again (TCP, DoT, DoH, or the TCP
// retry itself) is a transport failure, never a response code.
func TestDNSTruncatedWithoutRetryIsTransport(t *testing.T) {
	stub := newDNSStub(t, nil, func(_ string, q dnsmessage.Message) []byte {
		return dnsReply(q, dnsmessage.RCodeSuccess, true)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	for _, target := range []string{"tcp://" + testHost, "udp://" + testHost} {
		m := dnsMonitor(target)
		m.DNSExpectRcode = model.DNSRcodeNXDomain
		res := p.probe(context.Background(), m)
		if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "truncated") || res.DNSRcode != "" {
			t.Fatalf("%s: a truncated answer = %+v", target, res)
		}
	}
}

// A response that echoes the ID but answers another question is refused.
func TestDNSAnswerToAnotherQuestionIsRefused(t *testing.T) {
	stub := newDNSStub(t, nil, func(network string, q dnsmessage.Message) []byte {
		q.Questions[0].Name = dnsmessage.MustNewName("other.example.")
		return answerA("192.0.2.1")(network, q)
	})
	p := dnsProber(t, stub.udp.LocalAddr(), stub.tcp.Addr(), nil)
	res := p.probe(context.Background(), dnsMonitor("tcp://"+testHost))
	if res.Success || failureCode(res) != model.DNSFailureTransport {
		t.Fatalf("an answer to another question was taken: %+v", res)
	}
}

// A DoH response is bound to its request by HTTP, so its ID is not judged.
func TestDNSDoHAcceptsAnyResponseID(t *testing.T) {
	cert, roots, _ := testCert(t, testHost)
	doh := dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
		q.ID = 4242
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerA("192.0.2.1")("tcp", q))
	})
	p := dnsProber(t, nil, doh.Listener.Addr(), roots)
	if res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query")); !res.Success {
		t.Fatalf("a DoH answer with another ID = %+v", res)
	}
}

// A reported value is cut at a character boundary and never grows past the bound.
func TestDNSReportedValuesKeepTheirBound(t *testing.T) {
	v := strings.Repeat("a", model.MonitorDNSValueMax-1) + "é"
	got := dnsReported([]string{v, "ok\xff"})
	if len(got[0]) > model.MonitorDNSValueMax || !utf8.ValidString(got[0]) || got[0] != strings.Repeat("a", model.MonitorDNSValueMax-1) {
		t.Fatalf("cut value = %q (%d bytes)", got[0], len(got[0]))
	}
	if got[1] != "ok" {
		t.Fatalf("invalid bytes = %q", got[1])
	}
}

// A DoH 3xx is the run's failure and is never followed, wherever it
// points: loopback, a private range, the metadata service. Nothing reaches
// the address it names.
func TestDNSDoHRedirectIsReportedNotFollowed(t *testing.T) {
	var landed atomic.Int32
	inside := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { landed.Add(1) }))
	t.Cleanup(inside.Close)
	cert, roots, _ := testCert(t, testHost)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, location := range []string{inside.URL + "/dns-query", "http://10.0.0.5/dns-query", "http://169.254.169.254/latest/meta-data/"} {
			doh := dohServer(t, cert, func(w http.ResponseWriter, _ dnsmessage.Message) {
				w.Header().Set("Location", location)
				w.WriteHeader(status)
			})
			p := dnsProber(t, nil, doh.Listener.Addr(), roots)
			res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query"))
			if res.Success || res.Reason != "" || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, "http status "+strconv.Itoa(status)) {
				t.Fatalf("%d to %s: want a reported redirect, got %+v", status, location, res)
			}
		}
	}
	if n := landed.Load(); n != 0 {
		t.Fatalf("a redirect was followed to loopback %d times", n)
	}
}

// A proxy named in the environment is never used for DoH: the query goes
// to the resolver's judged address and the proxy sees no connection.
func TestDNSDoHIgnoresEnvironmentProxy(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	var proxied atomic.Int32
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = conn.Close()
		}
	}()
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(name, "http://"+proxy.Addr().String())
	}
	cert, roots, _ := testCert(t, testHost)
	doh := dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerA("192.0.2.1")("tcp", q))
	})
	p := dnsProber(t, nil, doh.Listener.Addr(), roots)
	// net/http reads the environment's proxy once per process, so the
	// transport is checked as well as the run.
	if tr, ok := p.dohClient(testHost, nil).Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatal("the DoH transport carries a proxy function")
	}
	res := p.probe(context.Background(), dnsMonitor("https://"+testHost+"/dns-query"))
	if !res.Success {
		t.Fatalf("DoH with a proxy in the environment: %+v", res)
	}
	if n := proxied.Load(); n != 0 {
		t.Fatalf("the proxy saw %d connections", n)
	}
}

// A DoH request leaves only for the resolver's host. A request for any
// other host, which is what a followed redirect or a proxy would make, is
// refused before anything is dialed.
func TestDNSDoHDialsOnlyTheTarget(t *testing.T) {
	p, _, d := fakeNetProber(nil)
	client := p.dohClient(testHost, []netip.Addr{netip.MustParseAddr(testPublicAddr)})
	for _, u := range []string{"https://other.example/dns-query", "https://127.0.0.1/dns-query", "http://169.254.169.254/latest/meta-data/"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		cancel()
		if resp != nil {
			_ = resp.Body.Close()
		}
		var refused *destinationError
		if !errors.As(err, &refused) {
			t.Fatalf("%s: want destination refused, got %v", u, err)
		}
	}
	if got := d.addresses(); len(got) != 0 {
		t.Fatalf("a request for another host dialed %v", got)
	}
}

// A resolver name with a private address among its public ones is refused
// before any query, whichever order the addresses come in and over every
// transport: one refused address refuses the run, and nothing is dialed.
func TestDNSResolverWithOnePrivateAddressRefused(t *testing.T) {
	for _, addrs := range [][]string{{testPublicAddr, "10.0.0.5"}, {"10.0.0.5", testPublicAddr}} {
		for _, target := range []string{"udp://mixed.example", "tcp://mixed.example", "tls://mixed.example", "https://mixed.example/dns-query"} {
			p, r, d := fakeNetProber(map[string][]string{"mixed.example": addrs})
			res := p.probe(context.Background(), dnsMonitor(target))
			if res.Reason != model.PathReasonDestinationRefused || res.Success || !strings.Contains(res.Error, "10.0.0.5") {
				t.Fatalf("%s resolving to %v: %+v", target, addrs, res)
			}
			if got := d.addresses(); len(got) != 0 {
				t.Fatalf("%s resolving to %v: dialed %v", target, addrs, got)
			}
			if !slices.Equal(r.lookups, []string{"mixed.example"}) {
				t.Fatalf("%s: lookups %v, want one", target, r.lookups)
			}
		}
	}
}

// Text the resolver chooses reaches a result's error only in short pieces:
// a content type, a certificate's names, an HTTP response it garbles. The
// error is shipped from every node and stored, so its size is the agent's
// to bound.
func TestDNSResolverTextInErrorsIsBounded(t *testing.T) {
	long := strings.Repeat("a", 60<<10)
	var names []string
	for i := range 200 {
		names = append(names, fmt.Sprintf("%s%d.example", strings.Repeat("n", 50), i))
	}
	many, manyRoots, _ := testCert(t, names...)
	cert, roots, _ := testCert(t, testHost)
	contentType := func(value string) *httptest.Server {
		return dohServer(t, cert, func(w http.ResponseWriter, q dnsmessage.Message) {
			w.Header().Set("Content-Type", value)
			_, _ = w.Write(answerA("192.0.2.1")("tcp", q))
		})
	}
	garbled, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = garbled.Close() })
	go func() {
		for {
			conn, err := garbled.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 4096))
				_, _ = io.WriteString(conn, "XTTP/"+long[:8<<10]+"\r\n\r\n")
			}()
		}
	}()
	dot := newDNSStub(t, &tls.Config{Certificates: []tls.Certificate{many}}, answerA("192.0.2.1"))
	manyDoH := dohServer(t, many, func(http.ResponseWriter, dnsmessage.Message) {})
	doh := "https://" + testHost + "/dns-query"
	for name, tc := range map[string]struct {
		p      *prober
		target string
		want   string
	}{
		"long media type":    {dnsProber(t, nil, contentType(long).Listener.Addr(), roots), doh, "content type"},
		"long parameter":     {dnsProber(t, nil, contentType("text/html; x="+long).Listener.Addr(), roots), doh, `"text/html"`},
		"dot cert names":     {dnsProber(t, nil, dot.tcp.Addr(), manyRoots), "tls://" + testHost, "does not cover " + testHost},
		"doh cert names":     {dnsProber(t, nil, manyDoH.Listener.Addr(), manyRoots), doh, "does not cover " + testHost},
		"garbled http reply": {dnsProber(t, nil, garbled.Addr(), roots), doh, "XTTP/"},
	} {
		res := tc.p.probe(context.Background(), dnsMonitor(tc.target))
		if res.Success || failureCode(res) != model.DNSFailureTransport || !strings.Contains(res.Error, tc.want) {
			t.Fatalf("%s: %+v", name, res)
		}
		if len(res.Error) > dnsErrorMax || !utf8.ValidString(res.Error) ||
			strings.Contains(res.Error, strings.Repeat("a", dnsDetailMax+1)) || strings.Contains(res.Error, strings.Repeat("n", dnsQuotedMax+1)) {
			t.Fatalf("%s: error of %d bytes carries the resolver's text unbounded: %.300q", name, len(res.Error), res.Error)
		}
	}
}
