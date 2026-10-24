package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The shell a terminal session starts comes from the server, and the agent
// may run as root, so the agent holds it to the same five shells the server
// normalises every request to. A session naming any other executable fails
// before anything runs, on either transport.
func TestTerminalRefusesAShellOutsideTheAllowlist(t *testing.T) {
	for name, run := range map[string]func(*terminalRunner, context.Context){
		"poll":   (*terminalRunner).runPoll,
		"stream": (*terminalRunner).runStream,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "ran")
			shell := filepath.Join(dir, "not-a-shell")
			if err := os.WriteFile(shell, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil { // #nosec G306 -- an executable test stub in a temp dir
				t.Fatal(err)
			}

			oldClient := httpClient
			defer func() { httpClient = oldClient }()
			var mu sync.Mutex
			var posted []string
			httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodPost && r.Body != nil {
					b, _ := io.ReadAll(r.Body)
					mu.Lock()
					posted = append(posted, string(b))
					mu.Unlock()
					return testResponse(http.StatusOK, `{}`), nil
				}
				return testResponse(http.StatusNotFound, `{"error":{"code":"terminal_missing","message":"gone"}}`), nil
			})}

			runner := &terminalRunner{
				cfg:     agentConfig{Server: "http://lattice.test", NodeID: "node-a", Token: "node-secret"},
				session: model.TerminalSession{ID: "term-a", Shell: shell, Cols: 80, Rows: 24},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			run(runner, ctx)

			// A started shell runs on its own; give it the time it would take.
			time.Sleep(200 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the agent ran a shell outside the allowlist")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(posted) == 0 || !strings.Contains(posted[0], model.TerminalFailed) || !strings.Contains(posted[0], "not an allowed terminal shell") {
				t.Fatalf("first status posted = %q, want a failed status naming the shell", posted)
			}
		})
	}
}

func TestTerminalShellDefaultsAndAllowlist(t *testing.T) {
	if got, err := terminalShell(""); err != nil || got != "/bin/sh" {
		t.Fatalf(`terminalShell("") = %q, %v; want /bin/sh`, got, err)
	}
	for _, s := range []string{"/bin/sh", "/bin/bash", "/usr/bin/bash", "/usr/bin/zsh", "/bin/zsh"} {
		if got, err := terminalShell(s); err != nil || got != s {
			t.Errorf("terminalShell(%q) = %q, %v; want it allowed", s, got, err)
		}
	}
	for _, s := range []string{"bash", "/tmp/sh", "/bin/sh -c id", "/bin/../tmp/x", " /bin/sh"} {
		if _, err := terminalShell(s); err == nil {
			t.Errorf("terminalShell(%q) allowed, want refused", s)
		}
	}
}
