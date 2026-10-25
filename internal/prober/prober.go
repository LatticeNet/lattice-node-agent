// Package prober runs one monitor probe and returns a timed result: a TCP
// connect, an HTTP GET, a run of ICMP echoes (design 29 M2a) or one DNS
// query over DoH, DoT, UDP or TCP (design 32 S5a). Every kind
// resolves its target once, refuses private and local destinations unless
// the control plane resolved a tcp or icmp target from a node, and dials
// only an address it judged. A kind this agent does not run is reported with the
// agent_too_old reason, never as a failure.
package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Capability is the -compat-json feature name of a binary that reports
// probe_methods and probe_refusals and runs the M2a probe rules.
const Capability = "probe-methods-v1"

// defaultTimeout is a probe's timeout when the monitor names none.
const defaultTimeout = 5 * time.Second

// resolver looks up a host's addresses; net.DefaultResolver satisfies it.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// prober holds what a probe reaches outside the process, so tests can
// replace it. Fields are read-only once built.
type prober struct {
	resolver resolver
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	// rootCAs verifies https targets; nil means the system roots.
	rootCAs *x509.CertPool
	// listenICMP opens an unprivileged ICMP echo socket.
	listenICMP func() (icmpConn, error)
	// spacing is the gap between two echoes of one run.
	spacing time.Duration
	// echoWait, when set, replaces the monitor's timeout as the time an
	// echo waits for its reply (tests only).
	echoWait time.Duration
	caps     *capabilities
}

func newProber() *prober {
	d := &net.Dialer{}
	p := &prober{
		resolver:   net.DefaultResolver,
		dial:       d.DialContext,
		listenICMP: listenUDP4ICMP,
		spacing:    model.MonitorPacketSpacingMs * time.Millisecond,
	}
	p.caps = newCapabilities(p.listenICMP)
	return p
}

var std = newProber()

// Probe runs the monitor once and returns its result. It returns within
// RunBudget(m) and a second of slack for scheduling, or sooner when ctx
// ends.
func Probe(ctx context.Context, m model.Monitor) model.MonitorResult {
	return std.probe(ctx, m)
}

// Facts reports the monitor kinds this agent runs on this host now and the
// kinds the host refuses, each with its reason code, for the probe_methods
// and probe_refusals keys of hello and heartbeat bodies. A refused kind is
// not in methods.
func Facts() (methods []string, refusals map[string]string) {
	return std.caps.facts()
}

// RunBudget is the longest a run of m may take: its timeout, plus the
// spacing of the echoes of a multi-packet run.
func RunBudget(m model.Monitor) time.Duration {
	budget := monitorTimeout(m)
	if m.Type == model.MonitorTypeICMP {
		budget += time.Duration(icmpPackets(m)-1) * model.MonitorPacketSpacingMs * time.Millisecond
	}
	return budget
}

func monitorTimeout(m model.Monitor) time.Duration {
	if m.TimeoutSec <= 0 {
		return defaultTimeout
	}
	return time.Duration(m.TimeoutSec) * time.Second
}

func (p *prober) probe(ctx context.Context, m model.Monitor) model.MonitorResult {
	res := model.MonitorResult{MonitorID: m.ID, At: time.Now().UTC()}
	timeout := monitorTimeout(m)
	var err error
	start := time.Now()
	switch m.Type {
	case model.MonitorTypeTCP:
		err = p.probeTCP(ctx, m, timeout)
	case model.MonitorTypeHTTP:
		err = p.probeHTTP(ctx, m, timeout)
	case model.MonitorTypeICMP:
		p.probeICMP(ctx, m, timeout, &res)
		return res
	case model.MonitorTypeDNS:
		p.probeDNS(ctx, m, timeout, &res)
		return res
	default:
		res.Reason = model.PathReasonAgentTooOld
		res.Error = fmt.Sprintf("this agent does not run %q checks", m.Type)
		return res
	}
	var refused *destinationError
	switch {
	case errors.As(err, &refused):
		res.Reason = model.PathReasonDestinationRefused
		res.Error = refused.Error()
	case err != nil:
		res.LatencyMs = elapsedMs(time.Since(start))
		res.Error = err.Error()
	default:
		res.LatencyMs = elapsedMs(time.Since(start))
		res.Success = true
	}
	return res
}

func elapsedMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func (p *prober) probeTCP(ctx context.Context, m model.Monitor, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, port, err := splitHostPort(m.Target)
	if err != nil {
		return err
	}
	addrs, err := p.resolveTarget(ctx, host, m.TargetNode != "")
	if err != nil {
		return err
	}
	conn, err := p.dialJudged(ctx, "tcp", addrs, port)
	if err != nil {
		return err
	}
	return conn.Close()
}

// splitHostPort splits a tcp target and checks its port, which may be a
// service name as net.Dial accepts.
func splitHostPort(target string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(target)
	if err != nil {
		return "", "", fmt.Errorf("target %q is not host:port", target)
	}
	if host == "" {
		return "", "", fmt.Errorf("target %q has no host", target)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		n, err := net.LookupPort("tcp", port)
		if err != nil {
			return "", "", fmt.Errorf("target %q has no usable port", target)
		}
		port = strconv.Itoa(n)
	}
	return host, port, nil
}

func (p *prober) probeHTTP(ctx context.Context, m model.Monitor, timeout time.Duration) error {
	u, err := url.Parse(strings.TrimSpace(m.Target))
	if err != nil {
		return errors.New("target is not a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" {
		return errors.New("target must be an http or https URL with a host")
	}
	expect, err := model.ParseMonitorStatusSet(m.ExpectStatus)
	if err != nil {
		return fmt.Errorf("expect_status: %w", err)
	}
	header, err := requestHeader(m, scheme)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, err := asciiHost(u.Hostname())
	if err != nil {
		return err
	}
	// http never takes target_node (design 29 D11), so a check that
	// carries one is still judged: only the control plane's resolution of
	// a node lifts the rule, and it does not resolve http targets.
	addrs, err := p.resolveTarget(ctx, host, false)
	if err != nil {
		return err
	}
	transport := p.httpTransport(host, addrs)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A 3xx is the answer and is judged against expect_status; no
		// redirect is ever followed, so a request reaches only the target.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("target is not a valid request URL")
	}
	req.Header = header
	resp, err := client.Do(req)
	if err != nil {
		var refused *destinationError
		if errors.As(err, &refused) {
			return refused
		}
		return errors.New(redactHTTPError(err, m))
	}
	// Latency is the time to the response headers; the body is never read.
	_ = resp.Body.Close()
	if !expect.Contains(resp.StatusCode) {
		return fmt.Errorf("http status %d, expected %s", resp.StatusCode, expect)
	}
	return nil
}

// httpTransport dials only the judged addresses of host, ignores proxy
// settings from the environment and keeps no connection after the probe.
func (p *prober) httpTransport(host string, addrs []netip.Addr) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			dialHost, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if !strings.EqualFold(dialHost, host) {
				return nil, &destinationError{msg: fmt.Sprintf("destination refused: a request left for %s, not the target", dialHost)}
			}
			return p.dialJudged(ctx, "tcp", addrs, port)
		},
		TLSClientConfig:        &tls.Config{RootCAs: p.rootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// requestHeader builds a check's request headers. Secret headers go only
// over https to the origin they were saved for; when they cannot, the run
// is refused before anything is sent.
func requestHeader(m model.Monitor, scheme string) (http.Header, error) {
	header := http.Header{}
	if model.MonitorHasSecrets(m) {
		origin, err := model.MonitorOrigin(m.Target)
		if err != nil || scheme != "https" || m.SecretsOrigin == "" || origin != m.SecretsOrigin {
			return nil, &destinationError{msg: "destination refused: secret headers go only over https to the origin they were saved for; nothing was sent"}
		}
	}
	for _, h := range m.Headers {
		name := model.CanonicalMonitorHeaderName(h.Name)
		if err := model.ValidateMonitorHeader(name, h.Value); err != nil {
			return nil, fmt.Errorf("header %s cannot be sent: %w", name, err)
		}
		header.Set(name, h.Value)
	}
	return header, nil
}

// redactHTTPError renders a request error without the URL's user info,
// query or fragment and without any header value.
func redactHTTPError(err error, m model.Monitor) string {
	text := err.Error()
	var uerr *url.Error
	if errors.As(err, &uerr) {
		text = uerr.Op + " " + strconv.Quote(redactURL(uerr.URL)) + ": " + uerr.Err.Error()
	}
	return scrubText(text, m)
}

// redactURL drops the user info, query and fragment of a URL.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "target"
	}
	u.User = nil
	u.RawQuery, u.ForceQuery = "", false
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

// minScrubLen is the shortest header value scrubbed out of error text;
// shorter ones would erase ordinary words.
const minScrubLen = 4

// scrubText removes from error text anything of the target's user info and
// query and every header value, whatever form an error put them in.
func scrubText(text string, m model.Monitor) string {
	if u, err := url.Parse(strings.TrimSpace(m.Target)); err == nil {
		var secrets []string
		if u.User != nil {
			secrets = append(secrets, u.User.String(), u.User.Username())
			if pw, ok := u.User.Password(); ok {
				secrets = append(secrets, pw)
			}
		}
		if u.RawQuery != "" {
			secrets = append(secrets, "?"+u.RawQuery, u.RawQuery)
			if q, err := url.QueryUnescape(u.RawQuery); err == nil {
				secrets = append(secrets, q)
			}
		}
		for _, s := range secrets {
			if len(s) >= minScrubLen {
				text = strings.ReplaceAll(text, s, "[redacted]")
			}
		}
	}
	for _, h := range m.Headers {
		if len(h.Value) >= minScrubLen {
			text = strings.ReplaceAll(text, h.Value, "[redacted]")
		}
	}
	return text
}
