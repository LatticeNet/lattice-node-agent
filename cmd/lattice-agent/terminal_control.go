package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/gorilla/websocket"
)

const (
	terminalControlPath        = "/api/agent/control/stream"
	terminalControlReadLimit   = 16 * 1024
	terminalControlDialTimeout = 15 * time.Second
	terminalControlBackoffMin  = 1 * time.Second
	terminalControlBackoffMax  = 30 * time.Second
)

type terminalControlMessage struct {
	Type    string                `json:"type"`
	Session model.TerminalSession `json:"session,omitempty"`
}

func (m *terminalManager) runControlLoop(ctx context.Context) {
	backoff := terminalControlBackoffMin
	for ctx.Err() == nil {
		if err := m.runControlOnce(ctx); err != nil && ctx.Err() == nil {
			m.logControlError(err)
		}
		m.setControlConnected(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < terminalControlBackoffMax {
			backoff *= 2
			if backoff > terminalControlBackoffMax {
				backoff = terminalControlBackoffMax
			}
		}
	}
}

func (m *terminalManager) runControlOnce(ctx context.Context) error {
	controlURL, err := terminalControlURL(m.cfg.Server, m.cfg.NodeID)
	if err != nil {
		return err
	}
	dialer := websocket.Dialer{HandshakeTimeout: terminalControlDialTimeout}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+m.cfg.Token)
	conn, resp, err := dialer.DialContext(ctx, controlURL, header)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("terminal control stream: server returned %s", resp.Status)
		}
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(terminalControlReadLimit)
	m.setControlConnected(true)
	debugf(m.cfg, "terminal control stream connected")
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var msg terminalControlMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			debugf(m.cfg, "terminal control message decode error: %v", err)
			continue
		}
		switch msg.Type {
		case "terminal.open":
			if msg.Session.ID == "" || msg.Session.NodeID != m.cfg.NodeID {
				debugf(m.cfg, "terminal control ignored invalid session: type=%s session=%s node=%s", msg.Type, msg.Session.ID, msg.Session.NodeID)
				continue
			}
			m.startSession(ctx, msg.Session)
		default:
			debugf(m.cfg, "terminal control ignored unknown message: %s", msg.Type)
		}
	}
}

func terminalControlURL(server, nodeID string) (string, error) {
	base, err := url.Parse(strings.TrimRight(server, "/") + terminalControlPath)
	if err != nil {
		return "", err
	}
	switch base.Scheme {
	case "https":
		base.Scheme = "wss"
	case "http":
		base.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported terminal control server scheme: %s", base.Scheme)
	}
	q := base.Query()
	q.Set("node_id", nodeID)
	base.RawQuery = q.Encode()
	return base.String(), nil
}
