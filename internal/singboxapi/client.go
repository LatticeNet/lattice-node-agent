package singboxapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultRequestTimeout bounds the unary calls. It is applied per request
	// through the context rather than through http.Client.Timeout, because the
	// same client also serves the long lived /logs stream and a client level
	// timeout would tear that stream down on a fixed schedule.
	defaultRequestTimeout = 5 * time.Second

	// maxUnaryResponseBytes caps a /version or /connections body. A node with
	// many thousands of connections still fits well inside this, and the cap
	// stops a misbehaving or compromised core from driving the agent out of
	// memory with an unbounded body.
	maxUnaryResponseBytes = 32 << 20
)

// Config configures a Client.
type Config struct {
	// Addr is the Clash API listen address as host:port, for example
	// "127.0.0.1:9090". It must be loopback. New rejects anything else.
	Addr string

	// Secret is the Clash API secret. When non-empty it is sent as
	// "Authorization: Bearer <secret>".
	Secret string

	// HTTPClient is optional and exists for tests. A supplied client must not
	// set Timeout: that field applies to the whole request including the body,
	// so it would kill the /logs stream. Use the request context instead.
	HTTPClient *http.Client
}

// Client talks to one sing-box Clash API over loopback.
type Client struct {
	baseURL string
	secret  string
	http    *http.Client

	// Backoff parameters for StreamLogsWithRetry. They are fields rather than
	// constants so tests can compress a reconnect sequence into milliseconds.
	backoffBase       time.Duration
	backoffMax        time.Duration
	backoffResetAfter time.Duration

	// jitter returns a value in [0,1). It is a field so a test can make the
	// backoff deterministic.
	jitter func() float64
}

// New builds a Client.
//
// It fails closed on a non-loopback address. The Clash API has no transport
// security and its secret is a bearer token, so pointing this at anything other
// than loopback would put that token, and full control of the local core, on
// the wire. This is a security boundary, not a convenience check.
func New(cfg Config) (*Client, error) {
	addr, err := validateLoopbackAddr(cfg.Addr)
	if err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			// Refuse redirects. The loopback check only covers the address we
			// dial, so a compromised core could otherwise 30x-bounce the agent,
			// and the bearer token, to an off-host target.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("singboxapi: clash api must not redirect")
			},
		}
	}
	return &Client{
		baseURL:           "http://" + addr,
		secret:            strings.TrimSpace(cfg.Secret),
		http:              httpClient,
		backoffBase:       time.Second,
		backoffMax:        30 * time.Second,
		backoffResetAfter: 30 * time.Second,
		jitter:            defaultJitter,
	}, nil
}

// validateLoopbackAddr normalizes and checks a host:port Clash API address.
//
// This mirrors ValidateLocalHTTPURL in internal/proxyusage, which guards the
// same class of local API for the same reason. It is duplicated rather than
// imported so the two packages stay independent.
func validateLoopbackAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", fmt.Errorf("singboxapi: clash api address is required")
	}
	// Reject a URL outright instead of trying to salvage a host from it. The
	// field is documented as host:port, and quietly accepting other shapes is
	// how a scheme, a path, or userinfo slips past the loopback check.
	if strings.Contains(addr, "//") || strings.Contains(addr, "@") {
		return "", fmt.Errorf("singboxapi: clash api address %q must be host:port, not a URL", raw)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("singboxapi: clash api address %q must be host:port: %w", raw, err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("singboxapi: clash api address %q has an invalid port", raw)
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("singboxapi: clash api host %q must be loopback", host)
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}

// isLoopbackHost reports whether host is a loopback literal or "localhost".
//
// "localhost" is accepted because that is how the address is usually written in
// configuration and it is what internal/proxyusage accepts. Every other name is
// rejected without resolving it: a DNS lookup here would make the security
// boundary depend on a resolver a hostile local core can influence.
func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	// Strip an IPv6 zone, which ParseIP does not accept.
	if idx := strings.Index(host, "%"); idx >= 0 {
		host = host[:idx]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Version fetches /version.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var version Version
	if err := c.getJSON(ctx, "/version", nil, &version); err != nil {
		return Version{}, err
	}
	return version, nil
}

// Connections fetches /connections.
//
// The returned snapshot's At is stamped on receipt, since the response carries
// no timestamp of its own.
func (c *Client) Connections(ctx context.Context) (ConnectionsSnapshot, error) {
	var snapshot ConnectionsSnapshot
	if err := c.getJSON(ctx, "/connections", nil, &snapshot); err != nil {
		return ConnectionsSnapshot{}, err
	}
	snapshot.At = time.Now().UTC()
	return snapshot, nil
}

// getJSON performs one bounded GET and decodes the body.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	resp, err := c.do(ctx, path, query)
	if err != nil {
		return err
	}
	defer drainAndClose(resp.Body)

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUnaryResponseBytes+1))
	if err != nil {
		return fmt.Errorf("singboxapi: read %s: %w", path, err)
	}
	if int64(len(data)) > maxUnaryResponseBytes {
		return fmt.Errorf("singboxapi: %s response exceeds %d bytes", path, int64(maxUnaryResponseBytes))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("singboxapi: decode %s: %w", path, err)
	}
	return nil
}

// do issues the request and rejects a non-2xx status.
//
// On a non-2xx it closes the body itself, so the caller only has to close it on
// the success path.
func (c *Client) do(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("singboxapi: get %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.Status
		drainAndClose(resp.Body)
		return nil, fmt.Errorf("singboxapi: %s returned %s", path, status)
	}
	return resp, nil
}

// drainAndClose consumes a bounded remainder of the body before closing it, so
// the keep-alive connection can be reused instead of being dropped.
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4<<10))
	_ = body.Close()
}
