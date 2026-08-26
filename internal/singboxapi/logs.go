package singboxapi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"time"
)

// maxLogLineBytes caps a single /logs entry. sing-box payloads are one short
// line each, so anything near this is already pathological, but the cap has to
// exist: the stream is unbounded and a single unterminated line would otherwise
// grow without limit.
const maxLogLineBytes = 1 << 20

// logReadBufferBytes is the initial buffered reader size. Entries are far
// smaller than this; the buffer only grows by refilling, never by allocating
// per line.
const logReadBufferBytes = 64 << 10

// ErrStreamClosed reports that the peer ended the /logs stream without an error
// of its own. It is the ordinary shape of a sing-box restart, which is why
// StreamLogsWithRetry surfaces it through onError like any other disconnect.
var ErrStreamClosed = errors.New("singboxapi: log stream closed by peer")

// StreamLogs consumes /logs and calls fn once per entry.
//
// The endpoint is a plain chunked HTTP response carrying newline delimited JSON
// objects. It is not a websocket on this path, so it is read with an ordinary
// buffered reader and entries are handed over as they arrive rather than being
// accumulated. fn receives the raw JSON object with the newline stripped;
// parsing is left to the caller so a parser gap can never destroy the evidence
// it failed to read.
//
// The slice passed to fn is only valid for the duration of the call. A caller
// that keeps an entry must copy it.
//
// An entry longer than maxLogLineBytes is skipped and the stream continues. One
// oversized line is not a reason to lose every line after it.
//
// A partial trailing line, meaning bytes with no terminating newline when the
// stream ends, is discarded. Half a JSON object is not an entry.
//
// StreamLogs returns nil when the peer closes the stream cleanly, ctx.Err()
// when ctx is cancelled, and an error otherwise. The response body is closed on
// every path.
func (c *Client) StreamLogs(ctx context.Context, level string, fn func(entry []byte)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if fn == nil {
		return fmt.Errorf("singboxapi: StreamLogs requires a callback")
	}
	query := url.Values{}
	query.Set("level", normalizeLevel(level))

	// No timeout on this context. The stream is meant to stay open, and the
	// only thing that should end it is ctx or the peer.
	resp, err := c.do(ctx, "/logs", query)
	if err != nil {
		// A cancellation during the handshake is a cancellation, not a
		// transport failure, and the retry loop has to be able to tell them
		// apart.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	// Close only. Draining is deliberate elsewhere but wrong here: the body is
	// unbounded, so a drain would block until the peer went away.
	defer resp.Body.Close()

	reader := bufio.NewReaderSize(resp.Body, logReadBufferBytes)
	for {
		line, _, readErr := readLimitedLine(reader, maxLogLineBytes)
		if len(line) > 0 {
			fn(line)
		}
		if readErr != nil {
			// ctx wins over the read error. Cancelling the request surfaces as
			// a transport failure on the body, and reporting that would make
			// an orderly shutdown look like a broken core.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			// Only a clean end of stream is a nil return. An abrupt
			// truncation arrives as io.ErrUnexpectedEOF and is reported,
			// because losing the tail of the stream is not the same as the
			// peer finishing with it.
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("singboxapi: read log stream: %w", readErr)
		}
	}
}

// readLimitedLine reads one newline terminated line, discarding it if it grows
// past limit.
//
// It returns the line without its terminator, whether an oversized line was
// discarded, and the read error. A line and an error are never returned
// together: a run of bytes with no terminating newline is not a line.
func readLimitedLine(reader *bufio.Reader, limit int) (line []byte, oversized bool, err error) {
	var buf []byte
	discarding := false
	for {
		chunk, readErr := reader.ReadSlice('\n')
		if readErr == nil {
			if discarding || len(buf)+len(chunk) > limit {
				return nil, true, nil
			}
			// ReadSlice returns a view into the reader's buffer, which the next
			// read invalidates, so the bytes have to be copied out.
			buf = append(buf, chunk...)
			return trimEntry(buf), false, nil
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			// The line is longer than the buffer. Keep accumulating until the
			// limit, then stop copying and just consume until the newline.
			if !discarding {
				if len(buf)+len(chunk) > limit {
					discarding = true
					buf = nil
				} else {
					buf = append(buf, chunk...)
				}
			}
			continue
		}
		// The stream ended or the transport failed. Whatever is buffered has no
		// terminator, so it is dropped.
		return nil, discarding, readErr
	}
}

// trimEntry strips the line terminator and surrounding whitespace, and returns
// nil for a blank line so a keep-alive newline is never delivered as an entry.
func trimEntry(raw []byte) []byte {
	trimmed := bytes.TrimRight(raw, "\r\n")
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}

// normalizeLevel defaults the /logs level.
func normalizeLevel(level string) string {
	if level == "" {
		return "info"
	}
	return level
}

// StreamLogsWithRetry runs StreamLogs and reconnects until ctx is done.
//
// A sing-box restart drops the stream, and the agent has to come back on its
// own. That recovery is also the signal used to detect the restart, so onError
// is called for every disconnect, including a clean close by the peer, which
// arrives as ErrStreamClosed. onError may be nil.
//
// Backoff is exponential from backoffBase to backoffMax with jitter, and resets
// once a stream has stayed up for backoffResetAfter. Without that reset a node
// that flaps every few minutes would creep to the maximum delay and stay there.
//
// It returns only when ctx is done, with ctx.Err().
func (c *Client) StreamLogsWithRetry(ctx context.Context, level string, fn func(entry []byte), onError func(error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if fn == nil {
		return fmt.Errorf("singboxapi: StreamLogsWithRetry requires a callback")
	}
	attempt := 0
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		startedAt := time.Now()
		err := c.StreamLogs(ctx, level, fn)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err == nil {
			err = ErrStreamClosed
		}
		if onError != nil {
			onError(err)
		}
		// A stream that stayed up long enough counts as healthy, so the next
		// failure starts from the bottom of the ladder again.
		if time.Since(startedAt) >= c.backoffResetAfter {
			attempt = 0
		}
		if err := sleepContext(ctx, c.backoffFor(attempt)); err != nil {
			return err
		}
		attempt++
	}
}

// backoffFor returns the delay before retry number attempt, counting from zero.
//
// This is equal jitter: half the delay is fixed and half is random. Full jitter
// would allow a near zero wait, which defeats the point of backing off when a
// core is restarting, and no jitter would let a fleet of nodes reconnect in
// lockstep after a shared outage.
func (c *Client) backoffFor(attempt int) time.Duration {
	base := c.backoffBase
	if base <= 0 {
		return 0
	}
	ceiling := c.backoffMax
	if ceiling < base {
		ceiling = base
	}
	delay := base
	for i := 0; i < attempt && delay < ceiling; i++ {
		delay *= 2
	}
	if delay > ceiling || delay <= 0 {
		delay = ceiling
	}
	jitter := c.jitter
	if jitter == nil {
		jitter = defaultJitter
	}
	half := delay / 2
	return half + time.Duration(jitter()*float64(delay-half))
}

func defaultJitter() float64 {
	return rand.Float64()
}

// sleepContext waits for d, or returns early with ctx.Err() if ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
