package singboxlive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
)

func fixedNow() time.Time { return time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC) }

func runner(outputs map[string][]byte, errs map[string]error) func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := name
		if err, ok := errs[key]; ok {
			return nil, err
		}
		return outputs[key], nil
	}
}

func TestCollectRunningWithBoundPorts(t *testing.T) {
	rt, ports := Collect(context.Background(), Source{
		Now: fixedNow,
		Processes: func() []singboxdiscover.TrustedProcess {
			return []singboxdiscover.TrustedProcess{{PID: 4242, StartedAt: fixedNow().Add(-time.Hour)}}
		},
		Runner: runner(map[string][]byte{
			"systemctl": []byte("ActiveState=active\nSubState=running\nNRestarts=3\n"),
			"ss": []byte(strings.Join([]string{
				`tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("sing-box",pid=4242,fd=8))`,
				`udp UNCONN 0 0 *:8443 *:* users:(("sing-box",pid=4242,fd=9))`,
				`tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=9,fd=3))`,
			}, "\n")),
		}, nil),
	})
	if !rt.Running || rt.PID != 4242 || rt.ActiveState != "active" || rt.SubState != "running" || rt.RestartCount != 3 {
		t.Fatalf("runtime wrong: %+v", rt)
	}
	if rt.ProbeError != "" {
		t.Fatalf("unexpected probe error: %q", rt.ProbeError)
	}
	if rt.ProbedAt != fixedNow() {
		t.Fatalf("ProbedAt not stamped: %v", rt.ProbedAt)
	}
	if !ports.Known {
		t.Fatal("ports must be known when ss succeeded")
	}
	if len(ports.Ports) != 2 || ports.Ports[443] != "sing-box" || ports.Ports[8443] != "sing-box" {
		t.Fatalf("sing-box ports wrong (sshd must be excluded): %+v", ports.Ports)
	}
}

func TestCollectDeadServiceWithIntactConfigIsDown(t *testing.T) {
	// The incident replay: no process, unit failed, nothing bound. The probe
	// must say so plainly, with no error masking the answer.
	rt, ports := Collect(context.Background(), Source{
		Now:       fixedNow,
		Processes: func() []singboxdiscover.TrustedProcess { return nil },
		Runner: runner(map[string][]byte{
			"systemctl": []byte("ActiveState=failed\nSubState=failed\nNRestarts=221347\n"),
			"ss":        []byte(`tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=9,fd=3))`),
		}, nil),
	})
	if rt.Running {
		t.Fatal("no trusted process must mean not running")
	}
	if rt.ActiveState != "failed" || rt.RestartCount != 221347 {
		t.Fatalf("unit evidence lost: %+v", rt)
	}
	if !ports.Known || len(ports.Ports) != 0 {
		t.Fatalf("want known-empty ports, got %+v", ports)
	}
}

func TestCollectSystemctlFailureKeepsProcessAnswer(t *testing.T) {
	// Non-systemd hosts: systemctl fails, the process table still decides.
	rt, ports := Collect(context.Background(), Source{
		Now: fixedNow,
		Processes: func() []singboxdiscover.TrustedProcess {
			return []singboxdiscover.TrustedProcess{{PID: 7}}
		},
		Runner: runner(map[string][]byte{
			"ss": []byte(`tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("sing-box",pid=7,fd=8))`),
		}, map[string]error{"systemctl": errors.New("not found")}),
	})
	if !rt.Running || rt.PID != 7 {
		t.Fatalf("process answer lost: %+v", rt)
	}
	if !strings.Contains(rt.ProbeError, "systemctl") {
		t.Fatalf("systemctl failure must be reported as data: %q", rt.ProbeError)
	}
	if !ports.Known || ports.Ports[443] != "sing-box" {
		t.Fatalf("listener probe must survive systemctl failure: %+v", ports)
	}
}

func TestCollectListenerFailureIsUnknownNotEmpty(t *testing.T) {
	rt, ports := Collect(context.Background(), Source{
		Now:       fixedNow,
		Processes: func() []singboxdiscover.TrustedProcess { return nil },
		Runner: runner(map[string][]byte{
			"systemctl": []byte("ActiveState=active\nSubState=running\nNRestarts=0\n"),
		}, map[string]error{"ss": errors.New("exec format error")}),
	})
	if ports.Known {
		t.Fatal("a failed listener probe must be unknown, not an empty set")
	}
	if !strings.Contains(rt.ProbeError, "ss") {
		t.Fatalf("ss failure must be reported: %q", rt.ProbeError)
	}
}
