package guardreality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// What this node's firewall actually is, as opposed to what the control plane
// believes it declared.
//
// The server has collected, stored and compared these snapshots since NetGuard
// landed; nothing ever sent one, so every node read "never reported" and drift
// was permanently unknown. The same gap left `--guard-managed-sha` unimplemented
// while the apply script called it, so a NetGuard apply could not record what it
// had installed either. Both are this package.
//
// Everything here is best-effort and read-only. A box without nft, without root,
// or without /proc still produces a report — with fewer fields — because a
// partial snapshot is what tells an operator "I can see this machine but not its
// ruleset", and refusing to report would look identical to a node that is gone.

// ManagedTable is the table NetGuard owns. Anything else on the box is foreign:
// still in force, still worth showing, but not ours to render.
const ManagedTable = "lattice_guard"

const (
	managedFamily      = "inet"
	collectTimeout     = 5 * time.Second
	maxInterfaces      = 64
	maxForeignTables   = 64
	maxAddressesPerInt = 16
)

// handleComment matches the ` # handle 42` fragments nft appends. They are
// assigned at insert time and change on every reload of an identical ruleset,
// so hashing them would report drift for a table nobody touched.
var handleComment = regexp.MustCompile(`\s*#\s*handle\s+\d+\s*$`)

// Collect builds the snapshot the server's /api/agent/guard-reality expects.
func Collect(ctx context.Context) model.GuardNodeReality {
	return model.GuardNodeReality{
		Listeners:     Listeners(),
		Interfaces:    Interfaces(),
		ManagedSHA:    ManagedSHA(ctx),
		ForeignTables: ForeignTables(ctx),
		NFTVersion:    NFTVersion(ctx),
		CollectedAt:   time.Now().UTC(),
	}
}

// ManagedSHA hashes the live managed table in a canonical form.
//
// This is the same value `--guard-managed-sha` prints after an apply, which is
// what makes drift detection mean anything: the server compares the hash the
// agent recorded when it installed a plan against the hash the agent reports
// later, so a difference is genuinely "this table changed since we applied it"
// rather than an artefact of two different renderers disagreeing about
// whitespace. Returns "" when nft is absent or the table does not exist — the
// server treats an empty hash as "not comparable", never as "in sync".
func ManagedSHA(ctx context.Context) string {
	out, err := runNFT(ctx, "list", "table", managedFamily, ManagedTable)
	if err != nil {
		return ""
	}
	canonical := canonicalizeRuleset(out)
	if canonical == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// canonicalizeRuleset removes what varies between reads of an unchanged table:
// handle numbers, trailing whitespace and blank lines. Rule ORDER is preserved,
// because in nftables order is meaning.
func canonicalizeRuleset(raw string) string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = handleComment.ReplaceAllString(line, "")
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// ForeignTables lists tables this node carries that NetGuard did not write.
// They are reported rather than touched: their rules apply to the machine
// whatever the control plane thinks, and an operator reviewing a firewall needs
// to know they exist.
func ForeignTables(ctx context.Context) []string {
	out, err := runNFT(ctx, "list", "tables")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	tables := make([]string, 0, 8)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// `table <family> <name>`
		if len(fields) < 3 || fields[0] != "table" {
			continue
		}
		family, name := fields[1], fields[2]
		if family == managedFamily && name == ManagedTable {
			continue
		}
		label := family + " " + name
		if seen[label] {
			continue
		}
		seen[label] = true
		tables = append(tables, label)
	}
	sort.Strings(tables)
	if len(tables) > maxForeignTables {
		tables = tables[:maxForeignTables]
	}
	return tables
}

// NFTVersion records which nft produced the ruleset, so a rule that behaves
// differently across versions is diagnosable from the snapshot alone.
func NFTVersion(ctx context.Context) string {
	out, err := runNFT(ctx, "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
}

// Interfaces reports addressable interfaces. Link-local and loopback are kept:
// a rule that trusts lo or a WireGuard link is exactly what review is about.
func Interfaces() []model.GuardInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]model.GuardInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := model.GuardInterface{Name: iface.Name, Up: iface.Flags&net.FlagUp != 0}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if len(entry.Addresses) >= maxAddressesPerInt {
					break
				}
				entry.Addresses = append(entry.Addresses, addr.String())
			}
		}
		out = append(out, entry)
		if len(out) >= maxInterfaces {
			break
		}
	}
	return out
}

func runNFT(ctx context.Context, args ...string) (string, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
