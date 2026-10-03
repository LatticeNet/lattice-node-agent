package singboxdiscover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// maxCapsNames bounds how many names one `sb --json caps` answer may carry.
// The fork lists seven; anything far past that is not a capability list.
const maxCapsNames = 64

// Caps runs the read-only `sb --json caps` and returns the capability names
// the script lists. lr00rl/sing-box v1.24.3-alpha.8 added the verb and answers
// {"ok":true,"script":"v1.24.3-alpha.8","caps":[...]} with exit status 0. A
// script older than that routes the unknown verb to its change command, which
// refuses it with {"ok":false,"error":"error",...} and exit status 1.
//
// Every answer other than ok:true with a caps list is an error: a non-zero
// exit, a timeout (Source.Timeout, default 8s), output that is not that JSON
// object. The caller reads an error as "this script reports no capabilities".
// Names come back trimmed, de-duplicated, in the script's order; which of them
// to trust is the caller's decision.
func Caps(ctx context.Context, source Source) ([]string, error) {
	binary := strings.TrimSpace(source.Binary)
	if binary == "" {
		binary = defaultBinary
	}
	timeout := source.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	run := source.runner
	if run == nil {
		run = runBoundedCommand
	}
	capsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := run(capsCtx, binary, "--json", "caps")
	if err != nil {
		return nil, err
	}
	return parseCaps(out)
}

func parseCaps(out []byte) ([]string, error) {
	var resp struct {
		OK   bool  `json:"ok"`
		Caps []any `json:"caps"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		return nil, fmt.Errorf("sb caps output is not a JSON object: %w", err)
	}
	if !resp.OK {
		return nil, errors.New("sb caps answered ok=false")
	}
	if resp.Caps == nil {
		return nil, errors.New("sb caps answered without a caps list")
	}
	if len(resp.Caps) > maxCapsNames {
		return nil, fmt.Errorf("sb caps listed %d names, more than %d", len(resp.Caps), maxCapsNames)
	}
	names := make([]string, 0, len(resp.Caps))
	seen := make(map[string]bool, len(resp.Caps))
	for _, raw := range resp.Caps {
		name, ok := raw.(string)
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
