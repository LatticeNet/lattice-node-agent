package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/creack/pty"
)

const (
	terminalPollInterval  = 5 * time.Second
	terminalInputInterval = 250 * time.Millisecond
	terminalReadChunk     = 4096

	// Transport selector values (see -terminal-transport / LATTICE_TERMINAL_TRANSPORT).
	terminalTransportPoll   = "poll"   // legacy HTTP store-and-forward (default)
	terminalTransportStream = "stream" // agent-dialed WebSocket bridge (see terminal_stream.go)
)

type terminalManager struct {
	cfg    agentConfig
	mu     sync.Mutex
	active map[string]struct{}
}

func runTerminalLoop(ctx context.Context, cfg agentConfig) {
	manager := &terminalManager{cfg: cfg, active: map[string]struct{}{}}
	ticker := time.NewTicker(terminalPollInterval)
	defer ticker.Stop()
	for {
		if err := manager.poll(ctx); err != nil {
			log.Printf("terminal poll error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *terminalManager) poll(ctx context.Context) error {
	var body struct {
		Sessions []model.TerminalSession `json:"sessions"`
	}
	path := "/api/agent/terminal/sessions?node_id=" + url.QueryEscape(m.cfg.NodeID)
	if err := getAgentJSON(m.cfg, path, &body); err != nil {
		return err
	}
	for _, session := range body.Sessions {
		m.mu.Lock()
		if _, exists := m.active[session.ID]; exists {
			m.mu.Unlock()
			continue
		}
		m.active[session.ID] = struct{}{}
		m.mu.Unlock()
		runner := &terminalRunner{cfg: m.cfg, session: session}
		go func() {
			defer m.remove(session.ID)
			runner.run(ctx)
		}()
	}
	return nil
}

func (m *terminalManager) remove(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, sessionID)
}

type terminalRunner struct {
	cfg         agentConfig
	session     model.TerminalSession
	inputCursor int64
}

// run selects the transport. The default (poll) path is unchanged; stream dials
// an outbound WebSocket per session and keeps the PTY alive across transient
// disconnects (see terminal_stream.go). NOTE (Phase 5): once stream is the
// default and has soaked, the poll path (runPoll, pollInputs, postEvents and the
// inputCursor field) is dead code to delete.
func (r *terminalRunner) run(ctx context.Context) {
	// Resolve the transport at session start: a server-pushed override (Phase 3
	// rollout lever) wins over the startup default; in-flight sessions already
	// running keep whichever transport they started with.
	if effectiveTerminalTransport(r.cfg.TerminalTransport) == terminalTransportStream {
		r.runStream(ctx)
		return
	}
	r.runPoll(ctx)
}

func (r *terminalRunner) runPoll(ctx context.Context) {
	shell := r.session.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	if _, err := os.Stat(shell); err != nil {
		_ = r.postStatus(model.TerminalFailed, fmt.Sprintf("shell not available: %v", err))
		return
	}
	cmd := exec.CommandContext(ctx, shell)
	cmd.Env = terminalShellEnv(os.Environ(), r.session.ID, r.cfg.NodeID)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(r.session.Cols), Rows: uint16(r.session.Rows)})
	if err != nil {
		_ = r.postStatus(model.TerminalFailed, err.Error())
		return
	}
	defer ptmx.Close()
	if err := r.postStatus(model.TerminalOpen, ""); err != nil {
		log.Printf("terminal status post error: %v", err)
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, terminalReadChunk)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				data := string(bytes.Clone(buf[:n]))
				if err := r.postEvents([]model.TerminalEvent{{Kind: "output", Data: data}}); err != nil {
					log.Printf("terminal output post error: %v", err)
				}
			}
			if err != nil {
				if err != io.EOF && ctx.Err() == nil {
					debugf(r.cfg, "terminal read ended: session=%s err=%v", r.session.ID, err)
				}
				return
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	inputTicker := time.NewTicker(terminalInputInterval)
	defer inputTicker.Stop()
	var waitErr error
	finished := false
	for !finished {
		select {
		case <-ctx.Done():
			_ = ptmx.Close()
			waitErr = ctx.Err()
			finished = true
		case waitErr = <-waitDone:
			finished = true
		case <-inputTicker.C:
			if err := r.pollInputs(ptmx); err != nil {
				if errors.Is(err, errTerminalSessionGone) {
					_ = ptmx.Close()
					waitErr = err
					finished = true
					continue
				}
				log.Printf("terminal input poll error: %v", err)
			}
		}
	}
	_ = ptmx.Close()
	<-readDone
	if waitErr != nil && ctx.Err() == nil {
		_ = r.postStatus(model.TerminalClosed, waitErr.Error())
		return
	}
	_ = r.postStatus(model.TerminalClosed, "")
}

func (r *terminalRunner) pollInputs(ptmx *os.File) error {
	var body struct {
		Inputs []model.TerminalInput `json:"inputs"`
	}
	path := fmt.Sprintf("/api/agent/terminal/sessions/%s/inputs?node_id=%s&cursor=%d",
		url.PathEscape(r.session.ID), url.QueryEscape(r.cfg.NodeID), r.inputCursor)
	if err := getAgentJSON(r.cfg, path, &body); err != nil {
		if status, ok := agentHTTPStatusCode(err); ok && (status == http.StatusNotFound || status == http.StatusGone) {
			return errTerminalSessionGone
		}
		return err
	}
	for _, input := range body.Inputs {
		if input.Seq > r.inputCursor {
			r.inputCursor = input.Seq
		}
		switch input.Kind {
		case "data":
			if input.Data != "" {
				if _, err := ptmx.Write([]byte(input.Data)); err != nil {
					return err
				}
			}
		case "resize":
			if input.Cols > 0 && input.Rows > 0 {
				if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(input.Cols), Rows: uint16(input.Rows)}); err != nil {
					return err
				}
			}
		case "close":
			return ptmx.Close()
		}
	}
	return nil
}

func (r *terminalRunner) postStatus(status, message string) error {
	return r.postTerminalPayload(map[string]any{
		"status": status,
		"error":  message,
	})
}

func (r *terminalRunner) postEvents(events []model.TerminalEvent) error {
	return r.postTerminalPayload(map[string]any{
		"events": events,
	})
}

func (r *terminalRunner) postTerminalPayload(payload map[string]any) error {
	payload["node_id"] = r.cfg.NodeID
	path := "/api/agent/terminal/sessions/" + url.PathEscape(r.session.ID) + "/events"
	return postJSON(r.cfg.Server+path, r.cfg.Token, payload, nil)
}

func getAgentJSON(cfg agentConfig, path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, cfg.Server+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return agentHTTPError(resp, "get "+path)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
