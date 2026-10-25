package prober

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/dns/dnsmessage"
)

// A dns check (design 32 S5a) asks one resolver one question: DoH (RFC
// 8484, a POST of application/dns-message), DoT (RFC 7858, the message
// behind a two-byte length over TLS), or plain DNS over UDP or TCP. A run
// resolves the resolver's host once and judges every address as every
// other kind does, sends the query to the first address that answers (one
// that cannot be reached or stays silent passes it to the next), asks once
// more over TCP only when a UDP answer comes back truncated, and judges the
// answer against the check's expectation. The timeout bounds the whole
// exchange.

// dnsUDPPayload is the EDNS(0) payload size a query advertises, the size
// DNS Flag Day 2020 settled on to avoid fragmented UDP answers.
const dnsUDPPayload = 1232

// dnsMediaType is the DoH request and response body type.
const dnsMediaType = "application/dns-message"

// dnsQuestion is a dns check's question and judgement, checked and in
// canonical form.
type dnsQuestion struct {
	name   string // without the trailing dot
	typ    string // a model.DNSTypes value
	qtype  dnsmessage.Type
	rcode  string // "" for NOERROR, or model.DNSRcodeNXDomain
	expect []string
}

var dnsQTypes = map[string]dnsmessage.Type{
	model.DNSTypeA:     dnsmessage.TypeA,
	model.DNSTypeAAAA:  dnsmessage.TypeAAAA,
	model.DNSTypeCNAME: dnsmessage.TypeCNAME,
	model.DNSTypeTXT:   dnsmessage.TypeTXT,
	model.DNSTypeMX:    dnsmessage.TypeMX,
	model.DNSTypeNS:    dnsmessage.TypeNS,
}

// dnsQuestionOf reads m's question with the rules the control plane saved
// it under, so a check it would refuse is refused here too.
func dnsQuestionOf(m model.Monitor) (dnsQuestion, error) {
	var q dnsQuestion
	var err error
	if q.name, err = model.NormalizeDNSName(m.DNSName); err != nil {
		return q, fmt.Errorf("dns_name: %w", err)
	}
	if q.typ, err = model.NormalizeDNSType(m.DNSType); err != nil {
		return q, err
	}
	q.qtype = dnsQTypes[q.typ]
	if q.rcode, err = model.NormalizeDNSExpectRcode(m.DNSExpectRcode); err != nil {
		return q, err
	}
	if len(m.DNSExpect) > model.MonitorDNSExpectMax {
		return q, fmt.Errorf("dns_expect has %d values; at most %d", len(m.DNSExpect), model.MonitorDNSExpectMax)
	}
	for _, raw := range m.DNSExpect {
		v, err := model.CanonicalDNSValue(q.typ, raw)
		if err != nil {
			return q, fmt.Errorf("dns_expect: %w", err)
		}
		q.expect = append(q.expect, v)
	}
	return q, nil
}

// Bounds on the text a result's error takes from the resolver's side: a
// header value or certificate name is quoted at most dnsQuotedMax bytes, a
// transport error (which can quote the resolver's bytes) at most
// dnsDetailMax, and the whole error at most dnsErrorMax, the server's bound
// on a stored error, so a node never sends text the server would cut.
const (
	dnsQuotedMax = 64
	dnsDetailMax = 160
	dnsErrorMax  = 512
)

// cutUTF8 is s with invalid UTF-8 dropped, cut to at most n bytes at a
// character boundary.
func cutUTF8(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// dnsFailure is a run that failed with a model.DNSFailure* code.
type dnsFailure struct {
	code string
	msg  string
}

func (e *dnsFailure) Error() string { return e.code + ": " + e.msg }

func dnsTransportError(err error) *dnsFailure {
	var failure *dnsFailure
	if errors.As(err, &failure) {
		return failure
	}
	if errors.Is(err, context.Canceled) {
		return &dnsFailure{code: model.DNSFailureTransport, msg: "the run was cancelled before an answer"}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return &dnsFailure{code: model.DNSFailureTransport, msg: "no answer before the check's timeout"}
	}
	return &dnsFailure{code: model.DNSFailureTransport, msg: cutUTF8(err.Error(), dnsDetailMax)}
}

// dnsCertNamesShown is how many of a certificate's names a failure lists.
const dnsCertNamesShown = 3

// dnsTLSFailure names a refused handshake. A certificate's names are the
// resolver's to choose, so a few are listed, each cut short.
func dnsTLSFailure(err error) *dnsFailure {
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	var msg string
	switch {
	case errors.As(err, &hostErr) && hostErr.Certificate != nil:
		msg = fmt.Sprintf("the certificate does not cover %s (it names %s)", hostErr.Host, dnsCertNames(hostErr.Certificate))
	case errors.As(err, &authErr):
		msg = "the certificate is signed by an unknown authority"
	default:
		msg = cutUTF8(strings.TrimPrefix(err.Error(), "tls: "), dnsDetailMax)
	}
	return &dnsFailure{code: model.DNSFailureTransport, msg: "tls: " + msg}
}

func dnsCertNames(c *x509.Certificate) string {
	if len(c.DNSNames) == 0 {
		return "no DNS names"
	}
	shown := make([]string, 0, dnsCertNamesShown)
	for _, name := range c.DNSNames[:min(len(c.DNSNames), dnsCertNamesShown)] {
		shown = append(shown, cutUTF8(name, dnsQuotedMax))
	}
	out := strings.Join(shown, ", ")
	if more := len(c.DNSNames) - len(shown); more > 0 {
		out += fmt.Sprintf(" and %d more", more)
	}
	return out
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dnsAnswer is a decoded response: its code and the values of the asked
// type, in canonical form and in the order they came.
type dnsAnswer struct {
	rcode     string
	values    []string
	truncated bool
}

func (p *prober) probeDNS(ctx context.Context, m model.Monitor, timeout time.Duration, res *model.MonitorResult) {
	defer func() { res.Error = cutUTF8(res.Error, dnsErrorMax) }()
	resolver, err := model.ParseDNSResolver(m.Target)
	if err != nil {
		res.Error = err.Error()
		return
	}
	q, err := dnsQuestionOf(m)
	if err != nil {
		res.Error = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// dns never takes target_node, so the destination rules always apply.
	addrs, err := p.resolveTarget(ctx, resolver.Host, false)
	if err != nil {
		var refused *destinationError
		if errors.As(err, &refused) {
			res.Reason = model.PathReasonDestinationRefused
			res.Error = refused.Error()
			return
		}
		res.Error = dnsTransportError(err).Error()
		return
	}
	query, id, err := dnsQuery(q, resolver.Transport == model.DNSTransportDoH)
	if err != nil {
		res.Error = err.Error()
		return
	}
	start := time.Now()
	var raw []byte
	var answeredBy netip.Addr
	switch resolver.Transport {
	case model.DNSTransportDoH:
		raw, err = p.exchangeDoH(ctx, resolver, addrs, query, res)
	case model.DNSTransportDoT:
		raw, err = p.exchangeDoT(ctx, resolver, addrs, query, res)
	case model.DNSTransportTCP:
		raw, err = p.exchangeTCP(ctx, addrs, strconv.Itoa(resolver.Port), query)
	default:
		raw, answeredBy, err = p.exchangeUDP(ctx, addrs, strconv.Itoa(resolver.Port), query, id)
	}
	// A DoH answer is bound to its request by HTTP, and its ID is 0.
	checkID := resolver.Transport != model.DNSTransportDoH
	var answer dnsAnswer
	if err == nil {
		answer, err = dnsDecode(raw, id, checkID, q)
	}
	if err == nil && answer.truncated && resolver.Transport == model.DNSTransportUDP {
		// The one retry a run makes: the same question over TCP to the
		// address the UDP answer came from, as a stub resolver does with a
		// truncated answer.
		raw, err = p.exchangeTCP(ctx, []netip.Addr{answeredBy}, strconv.Itoa(resolver.Port), query)
		if err == nil {
			answer, err = dnsDecode(raw, id, checkID, q)
		}
	}
	if err == nil && answer.truncated {
		// Nothing is asked again: a truncated answer over TCP, DoT or DoH,
		// or a second one after the retry, is not an answer to judge.
		err = &dnsFailure{code: model.DNSFailureTransport, msg: "the response is truncated"}
	}
	res.LatencyMs = elapsedMs(time.Since(start))
	if err != nil {
		var refused *destinationError
		if errors.As(err, &refused) {
			res.LatencyMs = 0
			res.Reason = model.PathReasonDestinationRefused
			res.Error = refused.Error()
			return
		}
		// A read the run's cancellation woke fails on its closed
		// connection; the result says what ended it.
		if errors.Is(ctx.Err(), context.Canceled) {
			err = ctx.Err()
		}
		res.Error = dnsTransportError(err).Error()
		return
	}
	res.DNSRcode = answer.rcode
	res.DNSAnswers = dnsReported(answer.values)
	if failure := q.judge(answer); failure != nil {
		res.Error = failure.Error()
		return
	}
	res.Success = true
}

// judge is the check's verdict on a decoded answer, nil when it passes.
func (q dnsQuestion) judge(a dnsAnswer) *dnsFailure {
	if q.rcode == model.DNSRcodeNXDomain {
		if a.rcode != model.DNSRcodeNXDomain {
			return &dnsFailure{code: model.DNSFailureRcode, msg: fmt.Sprintf("%s answered %s; the check expects NXDOMAIN", q.name, a.rcode)}
		}
		return nil
	}
	if a.rcode != model.DNSRcodeNoError {
		return &dnsFailure{code: model.DNSFailureRcode, msg: fmt.Sprintf("%s answered %s", q.name, a.rcode)}
	}
	if len(a.values) == 0 {
		return &dnsFailure{code: model.DNSFailureNoAnswer, msg: fmt.Sprintf("no %s answer for %s", q.typ, q.name)}
	}
	var missing []string
	for _, want := range q.expect {
		if !slices.Contains(a.values, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return &dnsFailure{code: model.DNSFailureMismatch, msg: fmt.Sprintf("the %s answer for %s lacks %s", q.typ, q.name, strings.Join(missing, ", "))}
	}
	return nil
}

// dnsReported is what a result carries of the answer: at most
// model.MonitorDNSAnswersMax values of at most model.MonitorDNSValueMax
// bytes each, invalid UTF-8 dropped and cut at a character boundary.
func dnsReported(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(values), model.MonitorDNSAnswersMax))
	for _, v := range values[:min(len(values), model.MonitorDNSAnswersMax)] {
		out = append(out, cutUTF8(v, model.MonitorDNSValueMax))
	}
	return out
}

// dnsQuery packs the question with recursion desired and an EDNS(0)
// record. A DoH query carries ID 0, as RFC 8484 asks, so caches can share
// it; the others a random ID the answer must echo.
func dnsQuery(q dnsQuestion, doh bool) ([]byte, uint16, error) {
	var id uint16
	if !doh {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, 0, err
		}
		id = binary.BigEndian.Uint16(b[:])
	}
	name, err := dnsmessage.NewName(q.name + ".")
	if err != nil {
		return nil, 0, fmt.Errorf("dns_name: %w", err)
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: q.qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, 0, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(dnsUDPPayload, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, 0, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	return msg, id, err
}

// dnsDecode reads a response to the query with id (judged when checkID):
// its response code, extended by an EDNS(0) record when there is one, and
// the values of answers of the asked type and class. A response that
// echoes a question must echo the one asked.
func dnsDecode(raw []byte, id uint16, checkID bool, q dnsQuestion) (dnsAnswer, error) {
	var parser dnsmessage.Parser
	h, err := parser.Start(raw)
	if err != nil {
		return dnsAnswer{}, &dnsFailure{code: model.DNSFailureTransport, msg: "the response is not a DNS message: " + err.Error()}
	}
	notOurs := &dnsFailure{code: model.DNSFailureTransport, msg: "the response does not answer the query"}
	if !h.Response || (checkID && h.ID != id) {
		return dnsAnswer{}, notOurs
	}
	a := dnsAnswer{truncated: h.Truncated}
	if a.truncated {
		return a, nil
	}
	malformed := func(err error) error {
		return &dnsFailure{code: model.DNSFailureTransport, msg: "the response is malformed: " + err.Error()}
	}
	for {
		question, err := parser.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return dnsAnswer{}, malformed(err)
		}
		if dnsName(question.Name) != q.name || question.Type != q.qtype || question.Class != dnsmessage.ClassINET {
			return dnsAnswer{}, notOurs
		}
	}
	for {
		ah, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return dnsAnswer{}, malformed(err)
		}
		if ah.Type != q.qtype || ah.Class != dnsmessage.ClassINET {
			if err := parser.SkipAnswer(); err != nil {
				return dnsAnswer{}, malformed(err)
			}
			continue
		}
		v, err := dnsValue(&parser, q.qtype)
		if err != nil {
			return dnsAnswer{}, malformed(err)
		}
		a.values = append(a.values, v)
	}
	rcode := h.RCode
	// An EDNS(0) record carries the upper bits of the response code. A
	// response that ends badly after its answers keeps the header's code.
	if parser.SkipAllAuthorities() == nil {
		for {
			ah, err := parser.AdditionalHeader()
			if err != nil {
				break
			}
			if ah.Type == dnsmessage.TypeOPT {
				rcode = ah.ExtendedRCode(h.RCode)
			}
			if parser.SkipAdditional() != nil {
				break
			}
		}
	}
	a.rcode = dnsRcodeName(rcode)
	return a, nil
}

// dnsValue decodes the answer the parser is at, of type t, into the form
// model.CanonicalDNSValue gives an expected value.
func dnsValue(parser *dnsmessage.Parser, t dnsmessage.Type) (string, error) {
	switch t {
	case dnsmessage.TypeA:
		r, err := parser.AResource()
		return netip.AddrFrom4(r.A).String(), err
	case dnsmessage.TypeAAAA:
		r, err := parser.AAAAResource()
		return netip.AddrFrom16(r.AAAA).String(), err
	case dnsmessage.TypeCNAME:
		r, err := parser.CNAMEResource()
		return dnsName(r.CNAME), err
	case dnsmessage.TypeNS:
		r, err := parser.NSResource()
		return dnsName(r.NS), err
	case dnsmessage.TypeMX:
		r, err := parser.MXResource()
		return dnsName(r.MX), err
	case dnsmessage.TypeTXT:
		r, err := parser.TXTResource()
		return strings.Join(r.TXT, ""), err
	}
	return "", fmt.Errorf("type %s is not asked", t)
}

func dnsName(n dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(n.String(), "."))
}

// dnsRcodeNames are the IANA mnemonics of the response codes a resolver
// returns (RFC 6895 and its registry).
var dnsRcodeNames = map[dnsmessage.RCode]string{
	0: model.DNSRcodeNoError, 1: "FORMERR", 2: "SERVFAIL", 3: model.DNSRcodeNXDomain,
	4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET",
	9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS", 23: "BADCOOKIE",
}

func dnsRcodeName(code dnsmessage.RCode) string {
	if name, ok := dnsRcodeNames[code]; ok {
		return name
	}
	return "RCODE" + strconv.Itoa(int(code))
}

// exchangeUDP asks the judged addresses in turn, each for its share of the
// run's time (addrContext), and returns the first answer and the address
// that sent it. An address that cannot be reached or stays silent passes
// the question to the next; an answer, right or wrong, ends the exchange.
func (p *prober) exchangeUDP(ctx context.Context, addrs []netip.Addr, port string, query []byte, id uint16) ([]byte, netip.Addr, error) {
	var firstErr error
	for i, addr := range addrs {
		actx, cancel := addrContext(ctx, len(addrs)-i)
		raw, err := p.askUDP(actx, addr, port, query, id)
		cancel()
		if err == nil {
			return raw, addr, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, netip.Addr{}, firstErr
}

// askUDP sends the query to addr and reads datagrams until one answers it.
// A connected socket takes datagrams from that address only; one that does
// not echo id is ignored.
func (p *prober) askUDP(ctx context.Context, addr netip.Addr, port string, query []byte, id uint16) ([]byte, error) {
	conn, err := p.dialJudged(ctx, "udp", []netip.Addr{addr}, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer bindConn(ctx, conn)()
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, model.MonitorDNSResponseMax)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == id {
			return slices.Clone(buf[:n]), nil
		}
	}
}

// exchangeTCP sends the query over TCP to the first judged address that
// accepts, behind its two-byte length.
func (p *prober) exchangeTCP(ctx context.Context, addrs []netip.Addr, port string, query []byte) ([]byte, error) {
	conn, err := p.dialJudged(ctx, "tcp", addrs, port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer bindConn(ctx, conn)()
	return dnsStreamExchange(conn, query)
}

// exchangeDoT is exchangeTCP inside TLS verified against the resolver's
// host. The certificate's expiry is recorded once the handshake completes.
func (p *prober) exchangeDoT(ctx context.Context, r model.DNSResolver, addrs []netip.Addr, query []byte, res *model.MonitorResult) ([]byte, error) {
	raw, err := p.dialJudged(ctx, "tcp", addrs, strconv.Itoa(r.Port))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	defer bindConn(ctx, raw)()
	conn := tls.Client(raw, &tls.Config{ServerName: r.Host, RootCAs: p.rootCAs, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return nil, err
		}
		return nil, dnsTLSFailure(err)
	}
	recordCert(conn.ConnectionState().PeerCertificates, res)
	return dnsStreamExchange(conn, query)
}

// dnsStreamExchange writes one length-prefixed query and reads one
// length-prefixed response (RFC 1035 section 4.2.2, RFC 7858). The length
// is two bytes, so a response is never over model.MonitorDNSResponseMax.
func dnsStreamExchange(conn net.Conn, query []byte) ([]byte, error) {
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query))) // #nosec G115 -- one question of a name of at most 255 bytes, far under 65535
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	out := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, out); err != nil {
		return nil, err
	}
	return out, nil
}

// exchangeDoH posts the query to the resolver's URL through the http
// check's transport: only the judged addresses are dialed, no proxy, no
// redirect, the certificate verified against the host. A body over
// model.MonitorDNSResponseMax is refused rather than read.
func (p *prober) exchangeDoH(ctx context.Context, r model.DNSResolver, addrs []netip.Addr, query []byte, res *model.MonitorResult) ([]byte, error) {
	client := p.dohClient(r.Host, addrs)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsMediaType)
	req.Header.Set("Accept", dnsMediaType)
	resp, err := client.Do(req)
	if err != nil {
		var refused *destinationError
		if errors.As(err, &refused) {
			return nil, refused
		}
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return nil, dnsTLSFailure(cert)
		}
		return nil, unwrapURLError(err)
	}
	defer resp.Body.Close()
	if resp.TLS != nil {
		recordCert(resp.TLS.PeerCertificates, res)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &dnsFailure{code: model.DNSFailureTransport, msg: fmt.Sprintf("http status %d", resp.StatusCode)}
	}
	// Only the parsed media type is named, cut short: the header is the
	// resolver's text, up to the transport's 64 KiB header bound.
	header := resp.Header.Get("Content-Type")
	if media, _, _ := mime.ParseMediaType(header); media != dnsMediaType {
		got := "no content type"
		switch {
		case media != "":
			got = fmt.Sprintf("content type %q", cutUTF8(media, dnsQuotedMax))
		case header != "":
			got = "a content type that does not parse"
		}
		return nil, &dnsFailure{code: model.DNSFailureTransport, msg: fmt.Sprintf("http 200 with %s, not %s", got, dnsMediaType)}
	}
	tooLarge := &dnsFailure{code: model.DNSFailureTransport, msg: fmt.Sprintf("the response is over %d KiB", model.MonitorDNSResponseMax>>10)}
	if resp.ContentLength > model.MonitorDNSResponseMax {
		return nil, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, model.MonitorDNSResponseMax+1))
	if err != nil {
		return nil, err
	}
	if len(body) > model.MonitorDNSResponseMax {
		return nil, tooLarge
	}
	return body, nil
}

// dohClient is what a DoH exchange posts through: the http check's
// transport, which dials only the judged addresses of host and takes no
// proxy from the environment, and a redirect reported rather than followed.
func (p *prober) dohClient(host string, addrs []netip.Addr) *http.Client {
	return &http.Client{
		Transport:     p.httpTransport(host, addrs),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// unwrapURLError drops the method and URL net/http puts before a request
// error; the check's target already names them.
func unwrapURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

func recordCert(chain []*x509.Certificate, res *model.MonitorResult) {
	if len(chain) > 0 {
		res.CertNotAfter = chain[0].NotAfter.UTC()
	}
}

// bindConn bounds every read and write on conn by ctx: by its deadline,
// and by its cancellation, which closes conn so a read in progress wakes
// rather than waiting out the deadline. A deadline that passes is left to
// the connection's own timeout, so a slow resolver still reads as a
// timeout. The returned func releases ctx's hold on conn.
func bindConn(ctx context.Context, conn net.Conn) (stop func() bool) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			_ = conn.Close()
		}
	})
}
