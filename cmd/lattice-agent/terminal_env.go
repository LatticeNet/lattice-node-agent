package main

import "strings"

var terminalReservedEnvKeys = map[string]struct{}{
	"TERM":                        {},
	"LATTICE_TERMINAL_SESSION_ID": {},
	"LATTICE_NODE_ID":             {},
}

func terminalShellEnv(base []string, sessionID, nodeID string) []string {
	env := make([]string, 0, len(base)+3)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		if _, reserved := terminalReservedEnvKeys[key]; reserved {
			continue
		}
		if isTerminalSensitiveEnvKey(key) {
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

func isTerminalSensitiveEnvKey(key string) bool {
	if !strings.HasPrefix(key, "LATTICE_") {
		return false
	}
	return strings.Contains(key, "TOKEN") ||
		strings.Contains(key, "SECRET") ||
		strings.Contains(key, "PASSWORD") ||
		strings.Contains(key, "PRIVATE_KEY")
}
