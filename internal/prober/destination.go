package prober

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// destinationError marks a run the destination rules refused. It becomes
// the destination_refused reason, not a failure.
type destinationError struct{ msg string }

func (e *destinationError) Error() string { return e.msg }

// resolveTarget resolves host once (an IP literal is not looked up) and
// judges every address it got with model.MonitorDestinationRefused, unless
// the control plane resolved the target from a node (nodeTarget). One
// refused address refuses the run, so a name cannot smuggle a private
// address past the rule beside a public one. The run then dials only the
// addresses returned here; nothing looks the name up again.
func (p *prober) resolveTarget(ctx context.Context, host string, nodeTarget bool) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	var addrs []netip.Addr
	addr, err := netip.ParseAddr(host)
	literal := err == nil
	if literal {
		addrs = []netip.Addr{addr}
	} else {
		found, err := p.resolver.LookupNetIP(ctx, "ip", host)
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
		if model.MonitorDestinationRefused(addr) {
			if literal {
				return nil, &destinationError{msg: fmt.Sprintf("destination refused: %s is not a public address", addr)}
			}
			return nil, &destinationError{msg: fmt.Sprintf("destination refused: %s resolves to %s, which is not a public address", host, addr)}
		}
	}
	return addrs, nil
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
