package main

import (
	"sync"

	"github.com/gorilla/websocket"
)

// wsConn adapts a gorilla *websocket.Conn for the terminal stream transport.
//
// gorilla forbids concurrent data writers (NextWriter / WriteMessage); a single
// mutex serializes Write so the PTY-output io.Copy goroutine never races any
// other writer. Server keepalive pings are auto-ponged by gorilla from the read
// path via the promoted, concurrency-safe WriteControl, so no opcode demux lives
// here — the input loop decodes the in-band opcode itself.
type wsConn struct {
	*websocket.Conn
	writeMu sync.Mutex
}

func newWSConn(conn *websocket.Conn) *wsConn {
	return &wsConn{Conn: conn}
}

// Write emits data as a single binary WebSocket frame: raw PTY output bytes with
// no opcode prefix, per the agent→browser half of the wire contract. It
// satisfies io.Writer so the output path is a plain io.Copy(conn, ptmx).
func (c *wsConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}
