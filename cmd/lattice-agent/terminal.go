package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/gorilla/websocket"
)

const (
	terminalPollInterval  = 750 * time.Millisecond
	terminalInputInterval = 250 * time.Millisecond
	terminalReadChunk     = 4096

	// Transport selector values (see -terminal-transport / LATTICE_TERMINAL_TRANSPORT).
	terminalTransportPoll   = "poll"   // legacy HTTP store-and-forward (default)
	terminalTransportStream = "stream" // agent-dialed WebSocket bridge

	// Stream transport tunables.
	terminalStreamChunk        = 32 * 1024        // PTY->WS copy buffer (fewer syscalls than the 4 KiB poll chunk)
	terminalStreamReadLimit    = 64 * 1024        // bound a single inbound frame; the server caps browser input at 16 KiB
	terminalStreamDialTimeout  = 15 * time.Second // WebSocket handshake timeout
	terminalStreamPingInterval = 10 * time.Second // keepalive ping cadence (keeps the conn hot through CF idle)
	terminalStreamPongWait     = 30 * time.Second // read deadline; reset on each pong, must exceed ping interval
	terminalStreamWriteWait    = 10 * time.Second // deadline for a single control-frame write

	// In-band opcode prefix on browser->agent frames (agent->browser is raw bytes).
	terminalOpcodeStdin  = 0x00 // payload[1:] written verbatim to the PTY
	terminalOpcodeResize = 0x01 // payload[1:] is JSON {"cols":N,"rows":M}
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
// an outbound WebSocket per session. NOTE (Phase 4): once stream is the default
// and has soaked, the poll path (runPoll, pollInputs, postEvents/postStatus and
// the inputCursor field) is dead code to delete.
func (r *terminalRunner) run(ctx context.Context) {
	if r.cfg.TerminalTransport == terminalTransportStream {
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
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"LATTICE_TERMINAL_SESSION_ID="+r.session.ID,
		"LATTICE_NODE_ID="+r.cfg.NodeID,
	)
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

// runStream is the WebSocket transport: dial the server's per-session stream
// endpoint, then splice the PTY to the socket. Output is raw PTY bytes; input is
// opcode-framed (stdin/resize). The server owns session status in this mode
// (markOpen on dial, markClosed when the browser bridge tears down), so no
// status POSTs are sent.
func (r *terminalRunner) runStream(ctx context.Context) {
	shell := r.session.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	if _, err := os.Stat(shell); err != nil {
		debugf(r.cfg, "terminal stream shell not available: session=%s err=%v", r.session.ID, err)
		return
	}
	// Dial first: only spawn the PTY once the bridge is accepted, so a failed
	// dial never orphans a shell. The token rides the Authorization header (not
	// the query string) to keep it out of access logs.
	conn, err := r.dialTerminalStream(ctx)
	if err != nil {
		debugf(r.cfg, "terminal stream dial failed: session=%s err=%v", r.session.ID, err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(terminalStreamReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	})

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"LATTICE_TERMINAL_SESSION_ID="+r.session.ID,
		"LATTICE_NODE_ID="+r.cfg.NodeID,
	)
	// Run the shell in its own process group so teardown SIGKILLs the whole tree
	// (e.g. vim/top grandchildren), not just the shell. No-op where unsupported.
	terminalSetPGID(cmd)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(r.session.Cols), Rows: uint16(r.session.Rows)})
	if err != nil {
		debugf(r.cfg, "terminal stream pty start failed: session=%s err=%v", r.session.ID, err)
		return
	}

	wsa := newWSConn(conn)

	// Output: PTY -> WS as raw binary frames (no opcode prefix). Ends on PTY
	// EOF (shell exit) or a WS write error.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		buf := make([]byte, terminalStreamChunk)
		_, _ = io.CopyBuffer(wsa, ptmx, buf)
	}()

	// Input: WS -> PTY, decoding the in-band opcode. Ends on WS read error/close.
	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		r.pumpInput(conn, ptmx)
	}()

	// Keepalive: ping the server so the relay stays hot through CF's idle timeout
	// and a half-open conn is detected — the server auto-pongs from its io.Copy
	// read path, resetting our read deadline; a dead conn yields no pong, the
	// deadline fires, and the input loop unblocks into teardown.
	pingStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(terminalStreamPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pingStop:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(terminalStreamWriteWait)); err != nil {
					return
				}
			}
		}
	}()

	// Block until either leg ends or the agent is shutting down.
	select {
	case <-ctx.Done():
	case <-outDone:
	case <-inDone:
	}

	// Deterministic teardown: stop pings, close the conn (unblocks input), SIGKILL
	// the shell's process group and reap, then close the PTY (unblocks output).
	close(pingStop)
	_ = conn.Close()
	terminalKillProcessGroup(cmd)
	_ = ptmx.Close()
	<-outDone
	<-inDone
}

// pumpInput reads browser->agent frames and applies them to the PTY. Each frame
// is [1-byte opcode][payload]; 0x00 = stdin (write verbatim), 0x01 = resize
// (JSON {"cols","rows"}). Zero-length keepalive frames and unknown opcodes are
// ignored.
func (r *terminalRunner) pumpInput(conn *websocket.Conn, ptmx *os.File) {
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			debugf(r.cfg, "terminal stream input ended: session=%s err=%v", r.session.ID, err)
			return
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case terminalOpcodeStdin:
			if len(payload) > 1 {
				if _, err := ptmx.Write(payload[1:]); err != nil {
					debugf(r.cfg, "terminal stream pty write failed: session=%s err=%v", r.session.ID, err)
					return
				}
			}
		case terminalOpcodeResize:
			var rs struct {
				Cols int `json:"cols"`
				Rows int `json:"rows"`
			}
			if err := json.Unmarshal(payload[1:], &rs); err != nil {
				debugf(r.cfg, "terminal stream resize decode failed: session=%s err=%v", r.session.ID, err)
				continue
			}
			if rs.Cols > 0 && rs.Rows > 0 {
				cols, rows := rs.Cols, rs.Rows
				if cols > 1000 {
					cols = 1000
				}
				if rows > 1000 {
					rows = 1000
				}
				if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}); err != nil {
					debugf(r.cfg, "terminal stream resize failed: session=%s err=%v", r.session.ID, err)
				}
			}
		default:
			debugf(r.cfg, "terminal stream unknown opcode 0x%02x: session=%s", payload[0], r.session.ID)
		}
	}
}

func (r *terminalRunner) dialTerminalStream(ctx context.Context) (*websocket.Conn, error) {
	wsURL, err := terminalStreamURL(r.cfg.Server, r.cfg.NodeID, r.session.ID)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+r.cfg.Token)
	dialer := websocket.Dialer{
		HandshakeTimeout: terminalStreamDialTimeout,
		ReadBufferSize:   terminalStreamChunk,
		WriteBufferSize:  terminalStreamChunk,
	}
	conn, resp, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		if resp != nil {
			status := resp.Status
			_ = resp.Body.Close()
			return nil, fmt.Errorf("dial terminal stream: %w (server %s)", err, status)
		}
		return nil, fmt.Errorf("dial terminal stream: %w", err)
	}
	return conn, nil
}

// terminalStreamURL builds the agent stream URL from the server base URL,
// swapping http->ws / https->wss. The node token is NOT placed in the query; it
// is sent in the Authorization header by the dialer.
func terminalStreamURL(server, nodeID, sessionID string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
		// already a websocket scheme
	default:
		return "", fmt.Errorf("unsupported server scheme %q for terminal stream", u.Scheme)
	}
	u.Path = "/api/agent/terminal/stream"
	q := url.Values{}
	q.Set("node_id", nodeID)
	q.Set("session_id", sessionID)
	u.RawQuery = q.Encode()
	return u.String(), nil
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
