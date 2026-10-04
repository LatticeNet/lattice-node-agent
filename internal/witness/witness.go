package witness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

const (
	healthTimeout    = 10 * time.Second
	referenceTimeout = 8 * time.Second
	pushTimeout      = 10 * time.Second
	// maxBodyRead bounds how much of any answer the witness reads.
	maxBodyRead = 4 << 10
)

// Prober checks the control plane and the references.
type Prober interface {
	// Health reports whether the control plane answered HTTP 200, and a
	// classified reason when it did not.
	Health(ctx context.Context, rawURL string) (bool, string)
	// Reachable reports whether any reference gave any HTTP answer.
	Reachable(ctx context.Context, rawURLs []string) bool
}

// Pusher sends one Bark message.
type Pusher interface {
	// Push sends p and returns a classified failure kind, or "" when the
	// bark-server accepted it.
	Push(ctx context.Context, cfg Config, p Push) string
}

// Witness is one running witness.
type Witness struct {
	cfg       Config
	configSHA string
	state     State
	prober    Prober
	pusher    Pusher
	now       func() time.Time
	// mono is how long this witness has been running, on the monotonic
	// clock. lastMono is its value at this process's previous check, and
	// checked says whether there was one.
	mono      func() time.Duration
	lastMono  time.Duration
	checked   bool
	save      func(State) error
	logf      func(string, ...any)
	lastPhase string
	// pushFailLogged is the push kind and failure last logged, so a push that
	// keeps failing during a long outage logs once, not at every check.
	pushFailLogged string
}

// New builds a witness around a loaded state. A nil prober or pusher uses
// the HTTP ones; a nil clock uses time.Now; a nil save writes the state file.
func New(cfg Config, configSHA string, state State, prober Prober, pusher Pusher, now func() time.Time, save func(State) error) *Witness {
	if prober == nil {
		prober = NewHTTPProber()
	}
	if pusher == nil {
		pusher = NewBarkPusher()
	}
	if now == nil {
		now = time.Now
	}
	if save == nil {
		path := cfg.State()
		save = func(st State) error { return SaveState(path, st) }
	}
	// A time.Now reading carries Go's monotonic clock reading, and Sub
	// between two such readings uses it, so a step of the wall clock does
	// not move mono. clock drops that reading (UTC does), so no elapsed time
	// is ever taken from it.
	start := now()
	mono := func() time.Duration { return now().Sub(start) }
	w := &Witness{cfg: cfg, configSHA: configSHA, state: state, prober: prober, pusher: pusher, now: now, mono: mono, save: save, logf: log.Printf}
	w.state.adopt(cfg, configSHA, w.clock())
	w.lastPhase = w.state.Phase
	return w
}

// clock is the wall time the witness records and shows, in UTC.
func (w *Witness) clock() time.Time { return w.now().UTC() }

// State returns a copy of the current state.
func (w *Witness) State() State { return w.state }

// Tick runs one check, sends any push it owes, and saves the state.
func (w *Witness) Tick(ctx context.Context) {
	res := w.check(ctx)
	now, mono := w.clock(), w.mono()
	step, gap := sinceLastCheck(w.state.LastCheckAt, now, mono-w.lastMono, w.checked, w.cfg.maxGap())
	w.lastMono, w.checked = mono, true
	if p := w.state.observe(w.cfg, now, step, gap, res); p != nil {
		kind := w.pusher.Push(ctx, w.cfg, *p)
		w.state.pushed(p, w.clock(), kind)
		switch {
		case kind == "":
			w.logf("witness: pushed %q (%s)", p.Title, p.Kind)
			w.pushFailLogged = ""
		case w.pushFailLogged != p.Kind+"/"+kind:
			w.logf("witness: %s push not delivered (%s); retrying at every check", p.Kind, kind)
			w.pushFailLogged = p.Kind + "/" + kind
		}
	}
	if w.state.Phase != w.lastPhase {
		w.logf("witness: %s -> %s (last check: %s)", w.lastPhase, w.state.Phase, describeCheck(res))
		w.lastPhase = w.state.Phase
	}
	if err := w.save(w.state); err != nil {
		w.logf("witness: save state: %v", err)
	}
}

func describeCheck(res CheckResult) string {
	switch {
	case res.OK:
		return "answered"
	case !res.NetworkUp:
		return res.Detail + ", references unreachable too"
	default:
		return res.Detail
	}
}

// check asks the control plane, and the references only when it failed.
func (w *Witness) check(ctx context.Context) CheckResult {
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	ok, detail := w.prober.Health(hctx, w.cfg.HealthURL)
	cancel()
	if ok {
		return CheckResult{OK: true}
	}
	rctx, cancel := context.WithTimeout(ctx, referenceTimeout)
	up := w.prober.Reachable(rctx, w.cfg.ReferenceURLs)
	cancel()
	return CheckResult{Detail: detail, NetworkUp: up}
}

// Run checks at once and then every interval until ctx ends, saving the
// state one last time on the way out.
func (w *Witness) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval())
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			if err := w.save(w.state); err != nil {
				w.logf("witness: save state: %v", err)
			}
			return
		case <-t.C:
		}
	}
}

// Start loads the config, the key file and the state, and returns a witness
// ready to Run. A key file that cannot be read safely stops it here, not at
// the first push during an outage.
func Start(configPath string) (*Witness, error) {
	cfg, sha, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if _, err := ReadDeviceKey(cfg.BarkDeviceKeyFile); err != nil {
		return nil, err
	}
	st, err := LoadState(cfg.State())
	if err != nil {
		log.Printf("witness: %v; starting from a fresh state", err)
		st = State{}
	}
	return New(cfg, sha, st, nil, nil, nil, nil), nil
}

// newClient is an HTTP client for the witness: no proxy from the
// environment (the witness tests this node's direct path), no redirects (a
// redirect is not the control plane answering), and its own timeout.
func newClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: -1}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// HTTPProber is the real prober.
type HTTPProber struct {
	health *http.Client
	ref    *http.Client
}

// NewHTTPProber builds the real prober.
func NewHTTPProber() *HTTPProber {
	return &HTTPProber{health: newClient(healthTimeout), ref: newClient(referenceTimeout)}
}

// Health implements Prober.
func (p *HTTPProber) Health(ctx context.Context, rawURL string) (bool, string) {
	status, err := get(ctx, p.health, rawURL)
	if err != nil {
		return false, classify(err)
	}
	if status != http.StatusOK {
		return false, fmt.Sprintf("http %d", status)
	}
	return true, ""
}

// Reachable implements Prober: every reference is asked at once and the
// first answer settles it.
func (p *HTTPProber) Reachable(ctx context.Context, rawURLs []string) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	answers := make(chan bool, len(rawURLs))
	var wg sync.WaitGroup
	for _, u := range rawURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			_, err := get(ctx, p.ref, u)
			answers <- err == nil
		}(u)
	}
	go func() { wg.Wait(); close(answers) }()
	for ok := range answers {
		if ok {
			return true
		}
	}
	return false
}

func get(ctx context.Context, client *http.Client, rawURL string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "lattice-witness/1")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead))
	return resp.StatusCode, nil
}

// classify turns a transport error into a fixed reason. Raw error text is
// never stored or reported: it can carry URLs and remote text.
func classify(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var recordErr tls.RecordHeaderError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.As(err, &certErr), errors.As(err, &unknownAuth), errors.As(err, &hostErr), errors.As(err, &recordErr):
		return "tls"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		var ue *url.Error
		if errors.As(err, &ue) {
			return "network"
		}
		return "error"
	}
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// BarkPusher sends through bark-server's v2 API, POST <base>/push.
type BarkPusher struct {
	client  *http.Client
	readKey func(string) (string, error)
}

// NewBarkPusher builds the real pusher. The key is read from its file at
// every push, so a key rotated by a new plan is used at once and the key is
// held in memory only while a push is in flight.
func NewBarkPusher() *BarkPusher {
	return &BarkPusher{client: newClient(pushTimeout), readKey: ReadDeviceKey}
}

// Push implements Pusher.
func (b *BarkPusher) Push(ctx context.Context, cfg Config, p Push) string {
	key, err := b.readKey(cfg.BarkDeviceKeyFile)
	if err != nil {
		return "key file"
	}
	payload, err := json.Marshal(struct {
		DeviceKey string `json:"device_key"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		Level     string `json:"level"`
		Group     string `json:"group"`
	}{key, p.Title, p.Body, p.Level, cfg.Group()})
	if err != nil {
		return "error"
	}
	pctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	base, err := url.Parse(cfg.BarkURL)
	if err != nil {
		return "error"
	}
	endpoint := base.JoinPath("push").String()
	req, err := http.NewRequestWithContext(pctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "error"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return classify(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyRead))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Sprintf("http %d", resp.StatusCode)
	}
	return ""
}
