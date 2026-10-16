package prober

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"golang.org/x/net/idna"
)

// destinationError marks a run the destination rules refused. It becomes
// the destination_refused reason, not a failure.
type destinationError struct{ msg string }

func (e *destinationError) Error() string { return e.msg }

// resolveTarget resolves host once (an IP literal is not looked up) and
// judges every address it got with destinationRefused, unless the control
// plane resolved the target from a node (nodeTarget). One refused address
// refuses the run, so a name cannot smuggle a private address past the
// rule beside a public one. The run then dials only the addresses returned
// here; nothing looks the name up again.
func (p *prober) resolveTarget(ctx context.Context, host string, nodeTarget bool) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	var addrs []netip.Addr
	addr, err := netip.ParseAddr(host)
	literal := err == nil
	if literal {
		addrs = []netip.Addr{addr}
	} else {
		name, err := asciiHost(host)
		if err != nil {
			return nil, err
		}
		found, err := p.resolver.LookupNetIP(ctx, "ip", name)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("lookup %s: no addresses", host)
		}
		addrs = found
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	if nodeTarget {
		return addrs, nil
	}
	for _, addr := range addrs {
		if destinationRefused(addr) {
			if literal {
				return nil, &destinationError{msg: fmt.Sprintf("destination refused: %s is not a public address", addr)}
			}
			return nil, &destinationError{msg: fmt.Sprintf("destination refused: %s resolves to %s, which is not a public address", host, addr)}
		}
	}
	return addrs, nil
}

// asciiHost is the form of a host name that is looked up and dialed:
// punycode for an internationalized name, as net/http dials it.
func asciiHost(host string) (string, error) {
	for i := 0; i < len(host); i++ {
		if host[i] >= utf8.RuneSelf {
			ascii, err := idna.Lookup.ToASCII(host)
			if err != nil {
				return "", fmt.Errorf("target host %q is not a valid name", host)
			}
			return ascii, nil
		}
	}
	return host, nil
}

// Addresses model.MonitorDestinationRefused does not judge yet: reserved
// IPv4 ranges, and IPv6 forms that carry or reach IPv4 space. The agent
// refuses them as well, failing closed, until the shared rule covers them;
// then this layer goes.
var (
	reservedIPv4 = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments, RFC 6890
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking, RFC 2544
		netip.MustParsePrefix("240.0.0.0/4"),   // reserved, RFC 1112
	}
	// Judged by the IPv4 address they embed.
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")    // RFC 6052, last 32 bits
	ipv4Translated = netip.MustParsePrefix("::ffff:0:0:0/96") // RFC 2765, last 32 bits
	sixToFour      = netip.MustParsePrefix("2002::/16")       // RFC 3056, bits 16 to 47
	transitionDeny = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64, RFC 8215
		netip.MustParsePrefix("::/96"),          // IPv4-compatible, deprecated
		netip.MustParsePrefix("fec0::/10"),      // site-local, deprecated
		netip.MustParsePrefix("2001::/32"),      // Teredo
	}
)

// destinationRefused is the shared rule, model.MonitorDestinationRefused,
// plus the ranges and forms above. An IPv6 transition address is judged by
// the IPv4 address it embeds, by this same rule. A zone never changes the
// verdict.
func destinationRefused(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if model.MonitorDestinationRefused(addr) {
		return true
	}
	if addr.Is4() {
		return inAnyPrefix(reservedIPv4, addr)
	}
	if inAnyPrefix(transitionDeny, addr) {
		return true
	}
	b := addr.As16()
	var embedded [4]byte
	switch {
	case nat64WellKnown.Contains(addr), ipv4Translated.Contains(addr):
		copy(embedded[:], b[12:16])
	case sixToFour.Contains(addr):
		copy(embedded[:], b[2:6])
	default:
		return false
	}
	return destinationRefused(netip.AddrFrom4(embedded))
}

func inAnyPrefix(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// minDialSlice is the least time one address of several gets, as
// net.Dialer gives each address of a serial fallback.
const minDialSlice = 2 * time.Second

// dialJudged connects to the first of addrs that answers on port, in the
// order the resolver gave them, sharing the time left between the
// addresses not yet tried as net.Dialer does. addrs are IP literals, so the
// dial makes no lookup.
func (p *prober) dialJudged(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address to dial")
	}
	var firstErr error
	for i, addr := range addrs {
		dctx, cancel := ctx, context.CancelFunc(func() {})
		if left := len(addrs) - i; left > 1 {
			if deadline, ok := ctx.Deadline(); ok {
				slice := time.Until(deadline) / time.Duration(left)
				if slice < minDialSlice {
					slice = min(minDialSlice, time.Until(deadline))
				}
				dctx, cancel = context.WithTimeout(ctx, slice)
			}
		}
		conn, err := p.dial(dctx, "tcp", net.JoinHostPort(addr.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}
