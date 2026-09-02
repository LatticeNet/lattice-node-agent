package main

import "strings"

// terminalShellEnv builds the environment an operator's shell starts with.
//
// The agent's own environment carries whatever the unit file or the operator
// put there: the node token, usage secrets, and anything a host happens to
// export (cloud credentials, registry logins). A denylist keyed on the
// LATTICE_ prefix caught the first group and passed the rest into an
// interactive shell. The shell now starts from an allowlist of the variables a
// login shell needs, plus the two the console reads back; everything else
// stays with the agent.
var terminalPassthroughEnvKeys = map[string]struct{}{
	"PATH":      {},
	"HOME":      {},
	"USER":      {},
	"LOGNAME":   {},
	"SHELL":     {},
	"LANG":      {},
	"LANGUAGE":  {},
	"TZ":        {},
	"TMPDIR":    {},
	"COLORTERM": {},
}

func terminalShellEnv(base []string, sessionID, nodeID string) []string {
	env := make([]string, 0, len(terminalPassthroughEnvKeys)+3)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		if !terminalEnvPassesThrough(key) {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"TERM=xterm-256color",
		"LATTICE_TERMINAL_SESSION_ID="+sessionID,
		"LATTICE_NODE_ID="+nodeID,
	)
}

func terminalEnvPassesThrough(key string) bool {
	if _, ok := terminalPassthroughEnvKeys[key]; ok {
		return true
	}
	// Locale categories (LC_ALL, LC_CTYPE, ...) shape how the shell prints and
	// carry nothing secret.
	return strings.HasPrefix(key, "LC_")
}
