package main

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn adapts a gorilla *websocket.Conn for the terminal stream transport.
//
// gorilla forbids concurrent data writers (NextWriter / WriteMessage); a single
// mutex serializes Write so the PTY-output writer never races any other writer.
// Server keepalive pings are auto-ponged by gorilla from the read path via the
// promoted, concurrency-safe WriteControl, so no opcode demux lives here — the
// input loop decodes the in-band opcode itself.
type wsConn struct {
	*websocket.Conn
	writeMu   sync.Mutex
	writeWait time.Duration
}

func newWSConn(conn *websocket.Conn) *wsConn {
	return &wsConn{Conn: conn}
}

// SetWriteWait bounds every subsequent Write with a per-write deadline so a
// stalled or half-open connection (a frozen relay, a dead browser through a
// proxy) errors the write instead of blocking the PTY drain indefinitely. d<=0
// disables it. Set under the write mutex so it is always paired with its write.
func (c *wsConn) SetWriteWait(d time.Duration) {
	c.writeMu.Lock()
	c.writeWait = d
	c.writeMu.Unlock()
}

// Write emits data as a single binary WebSocket frame: raw PTY output bytes with
// no opcode prefix, per the agent→browser half of the wire contract.
func (c *wsConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeWait > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.writeWait))
	}
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}
