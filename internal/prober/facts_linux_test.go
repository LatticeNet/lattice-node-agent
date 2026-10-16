//go:build linux

package prober

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// On Linux the kernel lets a process open an unprivileged echo socket only
// when its effective group or a supplementary group lies inside
// net.ipv4.ping_group_range, whatever its capabilities. The facts must
// agree with that range. Run it with the range excluding the test's groups
// (for example `docker run --sysctl net.ipv4.ping_group_range="1 0"`) to
// exercise the refusal against the real kernel.
func TestFactsFollowPingGroupRange(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range")
	if err != nil {
		t.Skipf("ping_group_range unreadable: %v", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Fatalf("unexpected ping_group_range %q", raw)
	}
	lo, errLo := strconv.ParseInt(fields[0], 10, 64)
	hi, errHi := strconv.ParseInt(fields[1], 10, 64)
	if errLo != nil || errHi != nil {
		t.Fatalf("unexpected ping_group_range %q", raw)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, os.Getegid())
	inside := slices.ContainsFunc(groups, func(g int) bool { return int64(g) >= lo && int64(g) <= hi })

	p := newProber()
	methods, refusals := p.caps.facts()
	if inside != slices.Contains(methods, model.MonitorTypeICMP) {
		t.Fatalf("groups %v, range %d-%d: methods %v refusals %v", groups, lo, hi, methods, refusals)
	}
	if !inside && refusals[model.MonitorTypeICMP] != model.PathReasonICMPNotPermitted {
		t.Fatalf("excluded groups: want icmp refused with %s, got %v", model.PathReasonICMPNotPermitted, refusals)
	}
	t.Logf("groups %v, ping_group_range %d-%d, icmp permitted %v", groups, lo, hi, inside)
}
