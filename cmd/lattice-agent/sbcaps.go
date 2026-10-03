package main

import (
	"context"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
)

const (
	// singBoxCapsInterval is how long one answer from `sb --json caps` is
	// reused. A script update reaches the server within this window.
	singBoxCapsInterval = 10 * time.Minute
	// singBoxCapsTimeout bounds one `sb --json caps` call. The verb only
	// prints a constant list, so this is generous.
	singBoxCapsTimeout = 5 * time.Second
	// singBoxCapPrefix marks a capability of the node's sb script, as opposed
	// to one of the agent binary. The server reads "sb:user-del-by-name".
	singBoxCapPrefix = "sb:"
)

// knownSingBoxCaps is every sb script capability the agent passes on: the
// names cmd_json_caps lists in lr00rl/sing-box v1.24.3-alpha.8. Whatever the
// script answers is filtered through this set, so a broken or hostile script
// cannot put an arbitrary string into the capabilities the server trusts. A
// capability a later script adds reaches the server only after it is named
// here.
var knownSingBoxCaps = map[string]bool{
	// `user del` accepts a payload with only the user's name.
	"user-del-by-name": true,
	// `user park` and `user unpark`, batched, one restart.
	"user-park": true,
	// `user parked`, and parked_* keys in `list` metadata.
	"user-parked-list": true,
	// del and park refuse to empty a socks/http/mixed line.
	"user-open-proxy-guard": true,
	// user results carry matched.
	"user-match-counts": true,
	// socks users are written without the name the core rejects.
	"user-socks-add": true,
	// user add/del/park/unpark run one at a time on the node; listed only
	// when the node has flock.
	"user-lock": true,
}

// singBoxCapsProbe asks the node's sb script what it can do, at most once per
// singBoxCapsInterval, and keeps the answer for the hello and heartbeat
// bodies. Only the work loop calls refresh; the heartbeat reads the result
// from the config the loop hands it.
type singBoxCapsProbe struct {
	probe func(ctx context.Context, binary string) ([]string, error)
	now   func() time.Time

	checked   bool
	checkedAt time.Time
	binary    string
	caps      []string
}

func newSingBoxCapsProbe() *singBoxCapsProbe {
	return &singBoxCapsProbe{
		probe: func(ctx context.Context, binary string) ([]string, error) {
			return singboxdiscover.Caps(ctx, singboxdiscover.Source{Binary: binary, Timeout: singBoxCapsTimeout})
		},
		now: time.Now,
	}
}

// refresh sets cfg.SingBoxScriptCaps. The script is only run with
// -singbox-discover, the flag that already lets the agent run `sb --json
// list` every interval. A script that has no caps verb (v1.24.3-alpha.7 and
// older), fails, hangs past the timeout, or prints anything other than the
// expected answer reports no capabilities: one debug line, and the beat goes
// out as before.
func (p *singBoxCapsProbe) refresh(cfg *agentConfig) {
	if !cfg.SingBoxDiscover {
		p.checked, p.checkedAt, p.binary, p.caps = false, time.Time{}, "", nil
		cfg.SingBoxScriptCaps = nil
		return
	}
	now := p.now()
	if p.checked && p.binary == cfg.SingBoxBin && now.Sub(p.checkedAt) < singBoxCapsInterval {
		cfg.SingBoxScriptCaps = p.caps
		return
	}
	p.checked, p.checkedAt, p.binary = true, now, cfg.SingBoxBin
	names, err := p.probe(context.Background(), cfg.SingBoxBin)
	if err != nil {
		debugf(*cfg, "sing-box script reports no caps: %v", err)
		names = nil
	}
	caps := allowedSingBoxCaps(names)
	if !slices.Equal(caps, p.caps) {
		if len(caps) == 0 {
			log.Printf("sing-box script no longer reports caps")
		} else {
			log.Printf("sing-box script caps: %s", strings.Join(caps, ","))
		}
	}
	p.caps = caps
	cfg.SingBoxScriptCaps = caps
}

// allowedSingBoxCaps keeps the names in knownSingBoxCaps, prefixed and sorted
// so an unchanged answer compares equal.
func allowedSingBoxCaps(names []string) []string {
	var out []string
	for _, name := range names {
		if !knownSingBoxCaps[name] {
			continue
		}
		prefixed := singBoxCapPrefix + name
		if !slices.Contains(out, prefixed) {
			out = append(out, prefixed)
		}
	}
	slices.Sort(out)
	return out
}

// payloadCapabilities is the capability list for the hello and heartbeat
// bodies, the two places the server reads a node's capabilities from: the
// agent's own, then the sb script's. The task poll header keeps only the
// agent's own, since the lease reads nothing else from it.
func payloadCapabilities(cfg agentConfig) []string {
	return append(capabilitiesFor(cfg.LinechainReady), cfg.SingBoxScriptCaps...)
}
