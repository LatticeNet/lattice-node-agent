package main

import "testing"

func TestTerminalControlURLUsesWebSocketScheme(t *testing.T) {
	got, err := terminalControlURL("https://lattice.example", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "wss://lattice.example/api/agent/control/stream?node_id=node-a" {
		t.Fatalf("terminalControlURL https = %q", got)
	}

	got, err = terminalControlURL("http://127.0.0.1:8088/", "node a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ws://127.0.0.1:8088/api/agent/control/stream?node_id=node+a" {
		t.Fatalf("terminalControlURL http = %q", got)
	}
}
