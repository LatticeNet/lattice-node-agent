package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	// Stream transport tunables.
	terminalStreamChunk        = 32 * 1024        // PTY->WS copy buffer (fewer syscalls than the 4 KiB poll chunk)
	terminalStreamReadLimit    = 64 * 1024        // bound a single inbound frame; the server caps browser input at 16 KiB
	terminalStreamDialTimeout  = 15 * time.Second // WebSocket handshake timeout
	terminalStreamPingInterval = 10 * time.Second // keepalive ping cadence (keeps the conn hot through CF idle)
	terminalStreamPongWait     = 30 * time.Second // read deadline; reset on each pong, must exceed ping interval
	// terminalStreamWriteWait bounds a single frame write. It is per-frame (≤32 KiB),
	// so it tolerates a consumer as slow as a few KiB/s and only trips on an
	// effectively dead connection; ping/pong is the primary liveness check. A
	// stalled write errors the leg and the session redials rather than pinning the
	// PTY drain.
	terminalStreamWriteWait = 10 * time.Second

	// Reconnect / replay tunables. The agent keeps the PTY alive across a transient
	// WebSocket drop and redials, replaying recent output so the browser resumes
	// seamlessly.
	terminalStreamRingBytes     = 512 * 1024             // per-session replay ring (recent output)
	terminalStreamRedialMin     = 500 * time.Millisecond // initial redial backoff
	terminalStreamRedialMax     = 8 * time.Second        // capped redial backoff
	terminalStreamDetachCeiling = 90 * time.Second       // give up redialing after this much continuous disconnection
	terminalStreamResumeWait    = 2 * time.Second        // wait for the browser's resume frame before replaying the full ring

	// Defense-in-depth agent-side caps. The server is authoritative for lifecycle,
	// but the agent owns every byte and so enforces the real idle cap (no PTY
	// output AND no stdin) and an absolute max-life cap directly.
	terminalStreamIdleCap = 30 * time.Minute
	terminalStreamMaxLife = 8 * time.Hour

	// In-band opcode prefix on browser->agent frames (agent->browser is raw bytes).
	terminalOpcodeStdin  = 0x00 // payload[1:] written verbatim to the PTY
	terminalOpcodeResize = 0x01 // payload[1:] is JSON {"cols":N,"rows":M}
	terminalOpcodeClose  = 0x02 // browser requested an orderly PTY close
	// terminalOpcodeResume carries the absolute count of output bytes the browser
	// has already rendered (decimal ASCII). The agent replays only output beyond
	// that offset from its ring, so a reconnect resumes without re-rendering or
	// losing the browser's existing scrollback.
	terminalOpcodeResume = 0x04
)

// errTerminalSessionGone signals that the server reports the session no longer
// exists (404) or the node token was rejected (401) on a (re)dial; the agent
// stops redialing and tears the local PTY down.
var errTerminalSessionGone = errors.New("terminal session gone")

// terminalTransportOverride is the server-pushed per-node transport override
// (Phase 3 rollout lever). Empty string means "no override" — the startup
// -terminal-transport value wins. It is read at session start and written by the
// agent's config poll, so flipping a node poll<->stream takes effect for new
// sessions without a redeploy and never disturbs an in-flight session.
var terminalTransportOverride atomic.Value // string

func setTerminalTransportOverride(transport string) {
	switch transport {
	case terminalTransportPoll, terminalTransportStream:
		terminalTransportOverride.Store(transport)
	default:
		terminalTransportOverride.Store("") // unknown/empty clears the override
	}
}

func effectiveTerminalTransport(startup string) string {
	if v, ok := terminalTransportOverride.Load().(string); ok && v != "" {
		return v
	}
	return startup
}

// outputRing is a bounded byte buffer of the most recent PTY output, tracking the
// absolute stream offset of its contents so the agent can replay exactly the tail
// a reconnecting browser is missing. Not safe for concurrent use; the streamSink
// owns it under a mutex.
type outputRing struct {
	buf      []byte
	capBytes int
	headOff  int64 // absolute offset of buf[0] in the output stream
	totalOff int64 // absolute offset just past the last byte (== bytes ever written)
}

func newOutputRing(capBytes int) *outputRing { return &outputRing{capBytes: capBytes} }

func (r *outputRing) append(p []byte) {
	r.totalOff += int64(len(p))
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.capBytes {
		drop := len(r.buf) - r.capBytes
		n := copy(r.buf, r.buf[drop:])
		r.buf = r.buf[:n]
		r.headOff += int64(drop)
	}
}

// tailFrom returns a copy of buffered output at or after absolute offset off and
// whether a gap occurred (off referred to output already evicted from the ring).
func (r *outputRing) tailFrom(off int64) ([]byte, bool) {
	if off >= r.totalOff {
		return nil, false
	}
	if off < r.headOff {
		return append([]byte(nil), r.buf...), true
	}
	start := int(off - r.headOff)
	return append([]byte(nil), r.buf[start:]...), false
}

// streamSink couples the per-session output ring to the current (swappable) live
// WebSocket connection. The long-lived PTY reader writes here; output is always
// recorded to the ring and forwarded to the live conn when one is attached. On a
// (re)connect the sink replays the ring tail beyond the browser's rendered offset
// before going live, all under one lock so no live byte interleaves the replay.
type streamSink struct {
	mu   sync.Mutex
	ring *outputRing
	conn io.Writer // current live conn (*wsConn in prod); nil while detached or before resume
}

func newStreamSink() *streamSink { return &streamSink{ring: newOutputRing(terminalStreamRingBytes)} }

// Write records output to the ring and forwards to the live conn. A forward
// error detaches the conn so the PTY drain is not pinned to a dead socket; the
// serve loop observes the broken conn via its read side and redials.
func (s *streamSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring.append(p)
	if s.conn != nil {
		if _, err := s.conn.Write(p); err != nil {
			s.conn = nil
		}
	}
	return len(p), nil
}

// resumeOnce attaches conn as the live sink, replaying buffered output beyond the
// browser's rendered offset. It returns true if it performed the resume (false if
// conn is already the live sink). The replay and the transition to live happen
// under the lock, so subsequent live output is strictly ordered after the replay.
func (s *streamSink) resumeOnce(conn io.Writer, browserOff int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		return false
	}
	tail, gap := s.ring.tailFrom(browserOff)
	if gap {
		// The browser missed more output than the ring retained. Note the gap so a
		// garbled top line is explained rather than silently corrupting the view.
		_, _ = conn.Write([]byte("\r\n\x1b[33m[lattice] reconnected — earlier output was dropped\x1b[0m\r\n"))
	}
	if len(tail) > 0 {
		if _, err := conn.Write(tail); err != nil {
			// Replay failed mid-flight; leave detached so the serve loop redials.
			return true
		}
	}
	s.conn = conn
	return true
}

func (s *streamSink) detach(conn io.Writer) {
	s.mu.Lock()
	if s.conn == conn {
		s.conn = nil
	}
	s.mu.Unlock()
}

// runStream is the WebSocket transport. Unlike poll, the PTY is spawned ONCE and
// kept alive across transient WebSocket drops: a long-lived reader drains the PTY
// into a replay ring, while an outer loop (re)dials the server's per-session
// stream endpoint and splices the live connection. The shell is killed only on
// agent shutdown, shell exit, an idle/max cap, or the server reporting the
// session gone — never on a mere network blip. The server owns session status in
// this mode; the agent posts a final closed status so the server need not wait
// out the detach grace.
func (r *terminalRunner) runStream(ctx context.Context) {
	shell := r.session.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	if _, err := os.Stat(shell); err != nil {
		debugf(r.cfg, "terminal stream shell not available: session=%s err=%v", r.session.ID, err)
		_ = r.postStatus(model.TerminalFailed, fmt.Sprintf("shell not available: %v", err))
		return
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"LATTICE_TERMINAL_SESSION_ID="+r.session.ID,
		"LATTICE_NODE_ID="+r.cfg.NodeID,
	)
	// Do NOT set Setpgid here. creack/pty's StartWithSize already sets Setsid,
	// which makes the shell a session+group leader (pgrp == pid) — that is the
	// process group teardown later SIGKILLs via Getpgid + Kill(-pgid). Setting
	// Setpgid as well makes the child's setpgid() fail right after its setsid()
	// (a session leader cannot move its own pgrp), so fork/exec returns EPERM
	// ("operation not permitted") and no shell ever starts.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(r.session.Cols), Rows: uint16(r.session.Rows)})
	if err != nil {
		debugf(r.cfg, "terminal stream pty start failed: session=%s err=%v", r.session.ID, err)
		_ = r.postStatus(model.TerminalFailed, err.Error())
		return
	}

	sink := newStreamSink()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }

	// Long-lived PTY reader: ptmx -> ring (+ live conn). Ends on PTY EOF (shell
	// exit) or read error. Decoupled from any single WebSocket so a drop never
	// stops it draining.
	ptyDone := make(chan struct{})
	go func() {
		defer close(ptyDone)
		buf := make([]byte, terminalStreamChunk)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				_, _ = sink.Write(buf[:n])
				touch()
			}
			if err != nil {
				return
			}
		}
	}()

	// Teardown: kill the process group and close the PTY (unblocks the reader),
	// then join it. Runs on every exit path.
	defer func() {
		terminalKillProcessGroup(cmd)
		_ = ptmx.Close()
		<-ptyDone
	}()

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()

	// Watchdog: enforce the idle (no output AND no input) and absolute max-life
	// caps. On a cap it records the reason and cancels sctx, which unwinds the
	// redial loop into a clean close.
	var capReason atomic.Pointer[string]
	go func() {
		started := time.Now()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > terminalStreamIdleCap {
					reason := "terminal session idle timeout"
					capReason.CompareAndSwap(nil, &reason)
					scancel()
					return
				}
				if time.Since(started) > terminalStreamMaxLife {
					reason := "terminal session reached maximum duration"
					capReason.CompareAndSwap(nil, &reason)
					scancel()
					return
				}
			}
		}
	}()

	backoff := terminalStreamRedialMin
	var disconnectedSince time.Time
	for {
		select {
		case <-sctx.Done():
			r.finishStream(ctx, capReason.Load())
			return
		case <-ptyDone:
			r.finishStream(ctx, nil) // clean shell exit
			return
		default:
		}

		conn, err := r.dialTerminalStream(sctx)
		if err != nil {
			if errors.Is(err, errTerminalSessionGone) {
				return // server closed the session; tear down locally (deferred)
			}
			if sctx.Err() != nil {
				r.finishStream(ctx, capReason.Load())
				return
			}
			if disconnectedSince.IsZero() {
				disconnectedSince = time.Now()
			}
			if time.Since(disconnectedSince) > terminalStreamDetachCeiling {
				debugf(r.cfg, "terminal stream giving up after %v offline: session=%s", terminalStreamDetachCeiling, r.session.ID)
				return
			}
			debugf(r.cfg, "terminal stream redial in %v: session=%s err=%v", backoff, r.session.ID, err)
			if !sleepCtx(sctx, backoff) {
				continue
			}
			backoff = minDuration(backoff*2, terminalStreamRedialMax)
			continue
		}

		bridged := r.serveStreamConn(sctx, conn, ptmx, sink, touch, ptyDone)
		if bridged {
			disconnectedSince = time.Time{}
			backoff = terminalStreamRedialMin
		} else if disconnectedSince.IsZero() {
			disconnectedSince = time.Now()
		}
		if !disconnectedSince.IsZero() && time.Since(disconnectedSince) > terminalStreamDetachCeiling {
			return
		}
		// Brief backoff before re-dialing so a session whose browser has gone for
		// good (detach grace lapses server-side) does not spin.
		if !sleepCtx(sctx, backoff) {
			continue
		}
		if !bridged {
			backoff = minDuration(backoff*2, terminalStreamRedialMax)
		}
	}
}

// serveStreamConn splices one WebSocket connection to the PTY until the conn
// breaks or the session ends (sctx/ptyDone). It returns whether a live browser
// resumed on this connection (a real bridge), which the caller uses to reset its
// redial backoff.
func (r *terminalRunner) serveStreamConn(sctx context.Context, conn *websocket.Conn, ptmx *os.File, sink *streamSink, touch func(), ptyDone <-chan struct{}) bool {
	defer conn.Close()
	conn.SetReadLimit(terminalStreamReadLimit)
	_ = conn.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(terminalStreamPongWait))
	})
	wsa := newWSConn(conn)
	wsa.SetWriteWait(terminalStreamWriteWait)

	// Keepalive ping. WriteControl is concurrency-safe with the data writer.
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

	resumed := make(chan struct{})
	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		r.pumpInput(conn, ptmx, sink, wsa, touch, resumed)
	}()

	// If the browser does not send a resume frame promptly (older client, or a
	// race), replay the full ring from offset 0 so output still flows.
	go func() {
		select {
		case <-resumed:
		case <-inDone:
		case <-time.After(terminalStreamResumeWait):
			sink.resumeOnce(wsa, 0)
		}
	}()

	select {
	case <-sctx.Done():
	case <-ptyDone:
	case <-inDone:
	}

	close(pingStop)
	sink.detach(wsa)
	_ = conn.Close()
	<-inDone

	select {
	case <-resumed:
		return true
	default:
		return false
	}
}

// pumpInput reads browser->agent frames and applies them to the PTY. Each frame
// is [1-byte opcode][payload]: 0x00 stdin (verbatim), 0x01 resize (JSON), 0x04
// resume (rendered byte offset, triggers ring replay). Zero-length keepalive
// frames and unknown opcodes are ignored. Closes resumed once the sink resumes.
func (r *terminalRunner) pumpInput(conn *websocket.Conn, ptmx *os.File, sink *streamSink, wsa *wsConn, touch func(), resumed chan struct{}) {
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
		case terminalOpcodeResume:
			off, perr := strconv.ParseInt(string(payload[1:]), 10, 64)
			if perr != nil || off < 0 {
				off = 0
			}
			if sink.resumeOnce(wsa, off) {
				select {
				case <-resumed:
				default:
					close(resumed)
				}
			}
		case terminalOpcodeStdin:
			if len(payload) > 1 {
				if _, err := ptmx.Write(payload[1:]); err != nil {
					debugf(r.cfg, "terminal stream pty write failed: session=%s err=%v", r.session.ID, err)
					return
				}
				touch()
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
				touch()
			}
		case terminalOpcodeClose:
			touch()
			_ = ptmx.Close()
			return
		default:
			debugf(r.cfg, "terminal stream unknown opcode 0x%02x: session=%s", payload[0], r.session.ID)
		}
	}
}

// finishStream posts a final closed status so the server closes the session
// immediately instead of waiting out the detach grace. Best effort: on agent
// shutdown the server may be unreachable. reason is nil for a clean shell exit.
func (r *terminalRunner) finishStream(ctx context.Context, reason *string) {
	msg := ""
	if reason != nil {
		msg = *reason
	}
	if msg == "" && ctx.Err() != nil {
		msg = "agent shutting down"
	}
	_ = r.postStatus(model.TerminalClosed, msg)
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
			status := resp.StatusCode
			_ = resp.Body.Close()
			if status == http.StatusNotFound || status == http.StatusUnauthorized {
				return nil, errTerminalSessionGone
			}
			return nil, fmt.Errorf("dial terminal stream: %w (server %d)", err, status)
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

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
