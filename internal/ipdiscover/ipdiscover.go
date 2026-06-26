// Package ipdiscover determines a node's authoritative public IP (via external
// IP-echo resolvers or a static override) and its internal/LAN IP (by
// enumerating local interfaces). The agent is the source of truth for its own
// public IP: relying on the server observing the connection source breaks behind
// a reverse proxy / CDN (the server sees the proxy/bridge address, not the node).
package ipdiscover

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultResolversV4 are public IPv4 echo endpoints, queried in order until one
// returns a routable global-unicast address.
var DefaultResolversV4 = []string{
	"https://api.ipify.org",
	"https://ifconfig.co/ip",
	"https://1.1.1.1/cdn-cgi/trace",
}

// DefaultResolversV6 are public IPv6 echo endpoints.
var DefaultResolversV6 = []string{
	"https://api64.ipify.org",
	"https://ifconfig.co/ip",
}

const maxResolverBody = 4096

var httpClient = &http.Client{Timeout: 8 * time.Second}

// PublicIP queries resolvers in order and returns the first routable
// global-unicast address of the requested family (wantV4 true => IPv4). Returns
// "" if none yield a usable address. Never fabricates an address.
func PublicIP(ctx context.Context, resolvers []string, wantV4 bool) string {
	for _, url := range resolvers {
		if ip := fetchIP(ctx, url, wantV4); ip != "" {
			return ip
		}
	}
	return ""
}

func fetchIP(ctx context.Context, url string, wantV4 bool) string {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResolverBody))
	return ParseIP(string(body), wantV4)
}

// ParseIP extracts the first routable global-unicast IP of the wanted family
// from a resolver response body. It handles both a bare body ("1.2.3.4\n") and
// the Cloudflare trace format (a line "ip=1.2.3.4").
func ParseIP(body string, wantV4 bool) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ip=") {
			line = strings.TrimSpace(line[len("ip="):])
		}
		if ip := normalize(line, wantV4); ip != "" {
			return ip
		}
	}
	return ""
}

func normalize(s string, wantV4 bool) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if (ip.To4() != nil) != wantV4 {
		return ""
	}
	if !routable(ip) {
		return ""
	}
	return ip.String()
}

func routable(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast()
}

// virtualIfacePrefixes names interfaces that are containers/overlays/tunnels and
// should not be reported as the node's primary internal address.
var virtualIfacePrefixes = []string{
	"docker", "veth", "br-", "wg", "tailscale", "cni", "kube",
	"flannel", "lo", "utun", "llw", "awdl", "gif", "stf", "tun", "tap",
}

func skipIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// ifaceAddrs is the testable shape of a network interface: a name and its IPs.
type ifaceAddrs struct {
	name  string
	addrs []net.IP
}

// InternalIPs returns the node's first non-loopback IPv4 and IPv6 from a real
// (non-virtual) interface. Both may be "".
func InternalIPs() (v4, v6 string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	list := make([]ifaceAddrs, 0, len(ifaces))
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ips = append(ips, ipnet.IP)
			}
		}
		list = append(list, ifaceAddrs{name: ifi.Name, addrs: ips})
	}
	return selectInternal(list)
}

// selectInternal picks the first usable IPv4 and IPv6 across non-virtual
// interfaces (pure, for testing).
func selectInternal(ifaces []ifaceAddrs) (v4, v6 string) {
	for _, ifi := range ifaces {
		if skipIface(ifi.name) {
			continue
		}
		for _, ip := range ifi.addrs {
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if ip.To4() != nil {
				if v4 == "" {
					v4 = ip.String()
				}
			} else if v6 == "" && ip.To16() != nil {
				v6 = ip.String()
			}
		}
		if v4 != "" && v6 != "" {
			break
		}
	}
	return v4, v6
}
