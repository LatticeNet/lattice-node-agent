package main

import "testing"

func TestTerminalShellEnvScrubsLatticeSecretsAndOverridesReserved(t *testing.T) {
	env := terminalShellEnv([]string{
		"PATH=/usr/bin",
		"TERM=dumb",
		"LATTICE_NODE_ID=old-node",
		"LATTICE_TERMINAL_SESSION_ID=old-session",
		"LATTICE_NODE_TOKEN=node-secret",
		"LATTICE_PROXY_USAGE_SECRET=usage-secret",
		"LATTICE_PROXY_USAGE_SECRET_FILE=/etc/lattice/usage.secret",
		"LATTICE_API_PASSWORD=password",
		"LATTICE_WG_PRIVATE_KEY=private-key",
		"LATTICE_SERVER=https://lattice.example",
		"OTHER_TOKEN=not-lattice",
	}, "session-a", "node-a")

	for _, key := range []string{
		"LATTICE_NODE_TOKEN",
		"LATTICE_PROXY_USAGE_SECRET",
		"LATTICE_PROXY_USAGE_SECRET_FILE",
		"LATTICE_API_PASSWORD",
		"LATTICE_WG_PRIVATE_KEY",
	} {
		if value, ok := envValue(env, key); ok {
			t.Fatalf("terminal env leaked %s=%q", key, value)
		}
	}
	for key, want := range map[string]string{
		"PATH":                        "/usr/bin",
		"LATTICE_SERVER":              "https://lattice.example",
		"OTHER_TOKEN":                 "not-lattice",
		"TERM":                        "xterm-256color",
		"LATTICE_TERMINAL_SESSION_ID": "session-a",
		"LATTICE_NODE_ID":             "node-a",
	} {
		if got, ok := envValue(env, key); !ok || got != want {
			t.Fatalf("terminal env %s = %q, %v; want %q, true", key, got, ok, want)
		}
	}
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range env {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			return entry[len(prefix):], true
		}
	}
	return "", false
}
