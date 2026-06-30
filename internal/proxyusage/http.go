package proxyusage

import (
	"bytes"
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

	"github.com/LatticeNet/lattice-sdk/model"
)

const defaultHTTPTimeout = 3 * time.Second

// HTTPSource describes a local HTTP JSON usage source. It is deliberately
// loopback-only so a node cannot be configured into polling arbitrary networks
// or leaking a local API secret off-host.
type HTTPSource struct {
	URL     string
	Secret  string
	Timeout time.Duration
	Client  *http.Client
	Now     func() time.Time
}

// LoadHTTP fetches one local proxy usage snapshot. Supported response bodies:
//
//   - model.ProxyUsageSnapshot JSON
//   - {"snapshot": model.ProxyUsageSnapshot}
//   - V2Ray-style stats JSON:
//     {"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":123}]}
//
// The V2Ray shape is transport-agnostic; a future sing-box/xray gRPC adapter can
// reuse the same parser after obtaining QueryStats output.
func LoadHTTP(ctx context.Context, source HTTPSource, nodeID string) (model.ProxyUsageSnapshot, error) {
	endpoint, err := ValidateLocalHTTPURL(source.URL)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	if secret := strings.TrimSpace(source.Secret); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	req.Header.Set("Accept", "application/json")

	client := source.Client
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			// Refuse redirects: a compromised local core must not be able to
			// 30x-bounce the agent to an off-loopback or internal target. The
			// loopback check only validates the initial URL.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("proxy usage source must not redirect")
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage source returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUsageFileBytes+1))
	if err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	if int64(len(data)) > maxUsageFileBytes {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage source exceeds %d bytes", maxUsageFileBytes)
	}
	return DecodeUsageSnapshot(data, nodeID, now(source.Now))
}

// ValidateLocalHTTPURL normalizes and validates the local usage source URL.
func ValidateLocalHTTPURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("proxy usage URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.User != nil {
		return "", fmt.Errorf("proxy usage URL must not contain userinfo")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("proxy usage URL must use http or https")
	}
	host := u.Hostname()
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("proxy usage URL host must be loopback")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// DecodeUsageSnapshot decodes one of the supported local source response
// formats and normalizes it for server ingestion.
func DecodeUsageSnapshot(data []byte, nodeID string, now time.Time) (model.ProxyUsageSnapshot, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage source returned empty body")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	if raw, ok := top["snapshot"]; ok {
		var snapshot model.ProxyUsageSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return model.ProxyUsageSnapshot{}, err
		}
		return NormalizeSnapshot(snapshot, nodeID, now)
	}
	if raw, ok := top["stat"]; ok {
		return decodeV2RayStats(raw, nodeID, now)
	}
	if _, ok := top["user_bytes"]; ok || top["line_user_bytes"] != nil || top["core_uptime_sec"] != nil || top["at"] != nil {
		var snapshot model.ProxyUsageSnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			return model.ProxyUsageSnapshot{}, err
		}
		return NormalizeSnapshot(snapshot, nodeID, now)
	}
	return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage source JSON has no supported snapshot fields")
}

func decodeV2RayStats(raw json.RawMessage, nodeID string, at time.Time) (model.ProxyUsageSnapshot, error) {
	var stats []struct {
		Name  string `json:"name"`
		Value int64String
	}
	if err := json.Unmarshal(raw, &stats); err != nil {
		return model.ProxyUsageSnapshot{}, err
	}
	snapshot := model.ProxyUsageSnapshot{UserBytes: map[string]int64{}}
	for _, stat := range stats {
		value := int64(stat.Value)
		if value < 0 {
			return model.ProxyUsageSnapshot{}, fmt.Errorf("proxy usage stat %q cannot be negative", stat.Name)
		}
		user, ok := v2rayUserFromStatName(stat.Name)
		if !ok {
			continue
		}
		snapshot.UserBytes[user] += value
	}
	return NormalizeSnapshot(snapshot, nodeID, at)
}

// int64String accepts either JSON numbers or protobuf-JSON int64 strings.
type int64String int64

func (v *int64String) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	raw = strings.Trim(raw, `"`)
	if raw == "" {
		return fmt.Errorf("empty int64 value")
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return err
	}
	*v = int64String(n)
	return nil
}

func v2rayUserFromStatName(name string) (string, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 {
		return "", false
	}
	if parts[0] != "user" || parts[2] != "traffic" {
		return "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", false
	}
	user := strings.TrimSpace(parts[1])
	return user, user != ""
}

func now(fn func() time.Time) time.Time {
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
