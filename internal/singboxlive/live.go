// Package singboxlive collects service-liveness evidence for sing-box
// (design-19): is a trusted process running, what does systemd say about the
// unit, and which ports does the process actually hold. It answers a
// different question than singboxdiscover, which reads configuration; this
// package reads the world. Everything here is read-only, command output is
// bounded, and a probe failure is reported as data rather than silently
// dropped, because "could not check" must never render as "running".
package singboxlive

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/guardreality"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
	"github.com/LatticeNet/lattice-sdk/model"
)

// maxProbeOutput bounds every command's parsed output. systemctl show emits a
// few lines and ss a few hundred; a megabyte means something is wrong.
const maxProbeOutput = 1 << 20

// Source configures a collection. Zero values select production behavior;
// tests inject Runner and Processes so coverage never depends on the host.
type Source struct {
	SystemctlBinary string
	SSBinary        string
	UnitName        string
	Timeout         time.Duration
	Now             func() time.Time
	Runner          guardreality.Runner
	Processes       func() []singboxdiscover.TrustedProcess
	// Refused lists the sing-box candidates the trust selector turned down.
	// Consulted only when Processes finds nothing, so the probe error can say
	// why the service could not be proven rather than leaving a bare unknown.
	Refused func() []singboxdiscover.RefusedProcess
}

func (s Source) withDefaults() Source {
	if s.SystemctlBinary == "" {
		s.SystemctlBinary = "systemctl"
	}
	if s.SSBinary == "" {
		s.SSBinary = "ss"
	}
	if s.UnitName == "" {
		s.UnitName = "sing-box"
	}
	if s.Timeout <= 0 {
		s.Timeout = 5 * time.Second
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Processes == nil {
		s.Processes = singboxdiscover.TrustedProcesses
	}
	if s.Refused == nil {
		s.Refused = singboxdiscover.RefusedProcesses
	}
	return s
}

// BoundPorts is the set of listen ports held by the sing-box process, or
// unknown when the listener probe failed. The two cases must stay distinct:
// an empty set says "nothing is listening", unknown says "nobody could look".
type BoundPorts struct {
	Known bool
	Ports map[int]string // port -> owning process name
}

// Collect gathers the runtime block and the bound-port set. It never returns
// an error: every failure lands in the runtime's ProbeError or in
// BoundPorts.Known, because a liveness probe that aborts on first error
// reports nothing exactly when the machine is at its strangest.
func Collect(ctx context.Context, src Source) (model.SingBoxRuntime, BoundPorts) {
	src = src.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, src.Timeout)
	defer cancel()

	rt := model.SingBoxRuntime{ProbedAt: src.Now().UTC()}
	var problems []string

	// Kernel evidence first: the trusted /proc selector decides whether a
	// sing-box process exists. systemd's opinion is recorded alongside but
	// never overrides the process table.
	procs := src.Processes()
	if len(procs) > 0 {
		rt.Running = true
		rt.PID = procs[0].PID
		if !procs[0].StartedAt.IsZero() {
			rt.StartedAt = procs[0].StartedAt.UTC()
		}
	} else {
		// Nothing trusted is running. If something that looks like sing-box
		// is, say so and say which rule refused it: the server turns "unit
		// active, no trusted process" into unknown, and unknown without a
		// reason is the state an operator cannot act on.
		for _, refused := range src.Refused() {
			problems = append(problems, fmt.Sprintf("refused sing-box candidate %s (pid %d): %s", refused.Exe, refused.PID, refused.Reason))
		}
	}

	if src.Runner == nil {
		rt.ProbeError = strings.Join(append(problems, "no runner configured"), "; ")
		return rt, BoundPorts{}
	}

	out, err := src.Runner(ctx, src.SystemctlBinary,
		"show", src.UnitName, "--property=ActiveState,SubState,NRestarts")
	if err != nil {
		// Not fatal and not necessarily wrong: non-systemd hosts land here.
		// The process-table answer above stands on its own.
		problems = append(problems, fmt.Sprintf("systemctl: %v", err))
	} else {
		applySystemdShow(&rt, bounded(out))
	}

	ports := BoundPorts{}
	out, err = src.Runner(ctx, src.SSBinary, "-tulpnH")
	if err != nil {
		problems = append(problems, fmt.Sprintf("ss: %v", err))
	} else if listeners, perr := guardreality.ParseSSListeners(bounded(out)); perr != nil {
		problems = append(problems, fmt.Sprintf("ss parse: %v", perr))
	} else {
		ports.Known = true
		ports.Ports = map[int]string{}
		for _, l := range listeners {
			if l.Process == src.UnitName {
				ports.Ports[l.Port] = l.Process
			}
		}
	}
	rt.ProbeError = strings.Join(problems, "; ")
	return rt, ports
}

func bounded(out []byte) []byte {
	if len(out) > maxProbeOutput {
		return out[:maxProbeOutput]
	}
	return out
}

// applySystemdShow parses `systemctl show -p ActiveState,SubState,NRestarts`
// key=value lines. Unknown keys are ignored; a malformed NRestarts is left at
// zero rather than failing the probe.
func applySystemdShow(rt *model.SingBoxRuntime, out []byte) {
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			rt.ActiveState = value
		case "SubState":
			rt.SubState = value
		case "NRestarts":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 {
				rt.RestartCount = n
			}
		}
	}
}
