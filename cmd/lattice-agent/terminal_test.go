package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestPollInputsStopsOnMissingTerminalSession(t *testing.T) {
	cases := []int{http.StatusNotFound, http.StatusGone}
	for _, status := range cases {
		t.Run(http.StatusText(status), func(t *testing.T) {
			oldClient := httpClient
			defer func() { httpClient = oldClient }()

			seen := false
			httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				seen = true
				if r.URL.Path != "/api/agent/terminal/sessions/term-a/inputs" {
					return testResponse(http.StatusBadRequest, "bad path"), nil
				}
				if r.URL.Query().Get("node_id") != "node-a" || r.URL.Query().Get("cursor") != "0" {
					return testResponse(http.StatusBadRequest, "bad query"), nil
				}
				if r.Header.Get("Authorization") != "Bearer node-secret" {
					return testResponse(http.StatusBadRequest, "missing bearer"), nil
				}
				return testResponse(status, `{"error":{"code":"terminal_missing","message":"terminal session not found"}}`), nil
			})}

			runner := terminalRunner{
				cfg: agentConfig{
					Server: "http://lattice.test",
					NodeID: "node-a",
					Token:  "node-secret",
				},
				session: model.TerminalSession{ID: "term-a"},
			}
			err := runner.pollInputs(nil)
			if !errors.Is(err, errTerminalSessionGone) {
				t.Fatalf("pollInputs error = %v, want errTerminalSessionGone", err)
			}
			if !seen {
				t.Fatal("pollInputs did not call server")
			}
		})
	}
}

func TestAgentHTTPErrorExposesStatusCode(t *testing.T) {
	err := agentHTTPError(testResponse(http.StatusGone, "gone"), "fetch terminal input")

	status, ok := agentHTTPStatusCode(err)
	if !ok || status != http.StatusGone {
		t.Fatalf("agentHTTPStatusCode = %d, %v; want 410, true", status, ok)
	}
}
