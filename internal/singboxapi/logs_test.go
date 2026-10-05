package singboxapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flush pushes whatever the handler has written to the client immediately, so
// a test can observe streaming rather than a single buffered write at the end.
func flush(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatalf("ResponseWriter does not implement http.Flusher")
	}
	flusher.Flush()
}

// collect runs StreamLogs in the background and reports entries on a channel.
func collect(ctx context.Context, client *Client, level string, entries chan<- string) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- client.StreamLogs(ctx, level, func(entry []byte) {
			entries <- string(entry)
		})
	}()
	return done
}

func expectEntry(t *testing.T, entries <-chan string, want string) {
	t.Helper()
	select {
	case got := <-entries:
		if got != want {
			t.Fatalf("entry = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for entry %q", want)
	}
}

func expectDone(t *testing.T, done <-chan error, check func(error) bool, describe string) {
	t.Helper()
	select {
	case err := <-done:
		if !check(err) {
			t.Fatalf("StreamLogs returned %v, want %s", err, describe)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("StreamLogs did not return, want %s", describe)
	}
}

// TestStreamLogsDeliversEntriesAsTheyArrive proves the stream is consumed
// incrementally. The handler stays open until the test has seen both entries,
// so a client that buffered the whole body would deadlock here rather than
// pass.
func TestStreamLogsDeliversEntriesAsTheyArrive(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" {
			t.Errorf("path = %q, want /logs", r.URL.Path)
		}
		if got := r.URL.Query().Get("level"); got != "debug" {
			t.Errorf("level = %q, want debug", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want Bearer s3cret", got)
		}
		_, _ = io.WriteString(w, `{"type":"info","payload":"first"}`+"\n")
		_, _ = io.WriteString(w, `{"type":"info","payload":"second"}`+"\n")
		flush(t, w)
		<-release
	}))
	defer srv.Close()

	entries := make(chan string, 8)
	done := collect(context.Background(), newTestClient(t, srv), "debug", entries)

	expectEntry(t, entries, `{"type":"info","payload":"first"}`)
	expectEntry(t, entries, `{"type":"info","payload":"second"}`)

	close(release)
	expectDone(t, done, func(err error) bool { return err == nil }, "nil on a clean close")

	select {
	case extra := <-entries:
		t.Fatalf("unexpected extra entry %q", extra)
	default:
	}
}

// TestStreamLogsDropsPartialTrailingLine covers a core that dies mid write.
// Half a JSON object is not an entry and must not reach the callback.
func TestStreamLogsDropsPartialTrailingLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"type":"info","payload":"complete"}`+"\n")
		_, _ = io.WriteString(w, `{"type":"info","payload":"trunc`)
		flush(t, w)
	}))
	defer srv.Close()

	entries := make(chan string, 8)
	done := collect(context.Background(), newTestClient(t, srv), "", entries)

	expectEntry(t, entries, `{"type":"info","payload":"complete"}`)
	expectDone(t, done, func(err error) bool { return err == nil }, "nil on a clean close")

	select {
	case extra := <-entries:
		t.Fatalf("partial trailing line was delivered as %q", extra)
	default:
	}
}

// TestStreamLogsSkipsOversizedEntry proves one pathological line does not cost
// every line after it.
func TestStreamLogsSkipsOversizedEntry(t *testing.T) {
	oversized := strings.Repeat("x", 2*maxLogLineBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"type":"info","payload":"before"}`+"\n")
		_, _ = io.WriteString(w, oversized+"\n")
		_, _ = io.WriteString(w, `{"type":"info","payload":"after"}`+"\n")
		flush(t, w)
	}))
	defer srv.Close()

	entries := make(chan string, 8)
	done := collect(context.Background(), newTestClient(t, srv), "info", entries)

	expectEntry(t, entries, `{"type":"info","payload":"before"}`)
	expectEntry(t, entries, `{"type":"info","payload":"after"}`)
	expectDone(t, done, func(err error) bool { return err == nil }, "nil on a clean close")
}

func TestStreamLogsSkipsBlankLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "\n\n"+`{"type":"info","payload":"only"}`+"\r\n\n")
		flush(t, w)
	}))
	defer srv.Close()

	entries := make(chan string, 8)
	done := collect(context.Background(), newTestClient(t, srv), "info", entries)

	expectEntry(t, entries, `{"type":"info","payload":"only"}`)
	expectDone(t, done, func(err error) bool { return err == nil }, "nil on a clean close")

	select {
	case extra := <-entries:
		t.Fatalf("blank line delivered as %q", extra)
	default:
	}
}

// TestStreamLogsReturnsOnContextCancel checks an orderly shutdown. The handler
// holds the stream open, so the only thing that can end the call is ctx.
func TestStreamLogsReturnsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"type":"info","payload":"one"}`+"\n")
		flush(t, w)
		<-r.Context().Done()
	}))
	defer srv.Close()

	entries := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := collect(ctx, newTestClient(t, srv), "info", entries)

	expectEntry(t, entries, `{"type":"info","payload":"one"}`)

	cancel()
	start := time.Now()
	expectDone(t, done, func(err error) bool { return errors.Is(err, context.Canceled) }, "context.Canceled")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v, want prompt", elapsed)
	}
}

func TestStreamLogsRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := newTestClient(t, srv).StreamLogs(context.Background(), "info", func([]byte) {})
	if err == nil {
		t.Fatal("StreamLogs accepted a 401 response")
	}
}

// TestStreamLogsWithRetryReconnects covers the recovery path a sing-box restart
// forces. The first two attempts are dropped abruptly, the third stays up.
// onError has to fire once per disconnect, because that call is also the signal
// the agent uses to notice the core restarted.
func TestStreamLogsWithRetryReconnects(t *testing.T) {
	var attempts atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		_, _ = fmt.Fprintf(w, `{"type":"info","payload":"attempt-%d"}`+"\n", n)
		flush(t, w)
		if n <= 2 {
			// Abrupt drop mid stream, the way a core going away ends it.
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		<-release
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	// Compress the ladder so the test runs in milliseconds. jitter of 1 makes
	// the delay exactly the nominal value, which keeps the timing assertion
	// below deterministic.
	client.backoffBase = time.Millisecond
	client.backoffMax = 4 * time.Millisecond
	client.backoffResetAfter = time.Hour
	client.jitter = func() float64 { return 1 }

	entries := make(chan string, 16)
	errs := make(chan error, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- client.StreamLogsWithRetry(ctx, "info",
			func(entry []byte) { entries <- string(entry) },
			func(err error) { errs <- err })
	}()

	for i := 1; i <= 3; i++ {
		expectEntry(t, entries, fmt.Sprintf(`{"type":"info","payload":"attempt-%d"}`, i))
	}
	// Two disconnects means two onError calls, no more and no fewer.
	for i := 1; i <= 2; i++ {
		select {
		case err := <-errs:
			if err == nil {
				t.Fatalf("onError call %d got a nil error", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for onError call %d", i)
		}
	}
	// Backoff is bounded: two retries at 1ms and 2ms nominal cannot account for
	// anything close to this, so a regression to the 1s production ladder fails.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("three attempts took %v, backoff was not bounded", elapsed)
	}
	// The third stream is still up, so nothing further should be reported.
	select {
	case err := <-errs:
		t.Fatalf("unexpected extra disconnect: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamLogsWithRetry returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StreamLogsWithRetry did not return after cancel")
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want exactly 3", got)
	}
}

// TestStreamLogsWithRetryReportsCleanClose pins the case where the peer ends
// the stream without an error of its own. That is still a disconnect and the
// agent still has to hear about it.
func TestStreamLogsWithRetryReportsCleanClose(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.WriteString(w, `{"type":"info","payload":"bye"}`+"\n")
		flush(t, w)
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	client.backoffBase = time.Millisecond
	client.backoffMax = 2 * time.Millisecond
	client.backoffResetAfter = time.Hour
	client.jitter = func() float64 { return 0 }

	errs := make(chan error, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.StreamLogsWithRetry(ctx, "info", func([]byte) {}, func(err error) { errs <- err })
	}()

	select {
	case err := <-errs:
		if !errors.Is(err, ErrStreamClosed) {
			t.Fatalf("onError got %v, want ErrStreamClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a clean close to be reported")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StreamLogsWithRetry did not return after cancel")
	}
}

// TestStreamLogsWithRetryReturnsOnCancelledContext makes sure a context that is
// already done never opens a connection at all.
func TestStreamLogsWithRetryReturnsOnCancelledContext(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := newTestClient(t, srv).StreamLogsWithRetry(ctx, "info", func([]byte) {}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("returned %v, want context.Canceled", err)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("attempts = %d, want 0", got)
	}
}

func TestBackoffForIsBoundedAndClimbs(t *testing.T) {
	client := &Client{
		backoffBase: time.Second,
		backoffMax:  30 * time.Second,
		jitter:      func() float64 { return 0 },
	}
	// Equal jitter: the floor is half the nominal delay, so a retry always
	// waits a real interval instead of hot looping.
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		// Attempt 5 would nominally be 32s, past backoffMax, so it clamps.
		{5, 15 * time.Second},
		{10, 15 * time.Second},
	} {
		if got := client.backoffFor(tc.attempt); got != tc.want {
			t.Errorf("backoffFor(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
	// Whatever the jitter draw and however many failures have piled up, the
	// delay stays inside [0, backoffMax]. A large attempt must not overflow.
	for _, attempt := range []int{0, 1, 5, 10, 62, 1000} {
		for _, draw := range []float64{0, 0.5, 0.9999} {
			client.jitter = func() float64 { return draw }
			got := client.backoffFor(attempt)
			if got < 0 || got > client.backoffMax {
				t.Errorf("backoffFor(%d) with jitter %v = %v, out of bounds", attempt, draw, got)
			}
		}
	}
}

func TestStreamLogsRequiresCallback(t *testing.T) {
	client, err := New(Config{Addr: "127.0.0.1:9090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.StreamLogs(context.Background(), "info", nil); err == nil {
		t.Error("StreamLogs accepted a nil callback")
	}
	if err := client.StreamLogsWithRetry(context.Background(), "info", nil, nil); err == nil {
		t.Error("StreamLogsWithRetry accepted a nil callback")
	}
}

// The Open hook is the collector's only positive signal that the stream is up,
// so it must not fire for a refused subscription. Here the API refuses twice
// with 401 and then accepts: two Errors, no Open, then exactly one Open before
// the first entry.
func TestOpenHookFiresOnlyAfterA2xx(t *testing.T) {
	var attempts atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 2 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintln(w, `{"type":"info","payload":"up"}`)
		flush(t, w)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	client := newTestClient(t, srv)
	client.backoffBase = time.Millisecond
	client.backoffMax = 2 * time.Millisecond
	client.jitter = func() float64 { return 1 }

	events := make(chan string, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.StreamLogsWithHooks(ctx, "info", StreamHooks{
			Entry: func(entry []byte) { events <- "entry" },
			Open:  func() { events <- "open" },
			Error: func(err error) {
				if !strings.Contains(err.Error(), "401") {
					t.Errorf("refusal reported as %v, want the 401", err)
				}
				events <- "error"
			},
		})
	}()

	var got []string
	for len(got) < 4 {
		select {
		case ev := <-events:
			got = append(got, ev)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out; events so far %v", got)
		}
	}
	if want := []string{"error", "error", "open", "entry"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", got, want)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamLogsWithHooks returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StreamLogsWithHooks did not return after cancel")
	}
}

// StreamLogsWithRetry is now a wrapper over StreamLogsWithHooks with no Open
// hook. Its contract is unchanged: entries arrive and every refusal reaches
// onError.
func TestStreamLogsWithRetryStillWorksWithoutHooks(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprintln(w, `{"type":"info","payload":"after-refusal"}`)
		flush(t, w)
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	client.backoffBase = time.Millisecond
	client.backoffMax = 2 * time.Millisecond
	client.jitter = func() float64 { return 1 }

	entries := make(chan string, 4)
	errs := make(chan error, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.StreamLogsWithRetry(ctx, "info",
			func(entry []byte) { entries <- string(entry) },
			func(err error) { errs <- err })
	}()
	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), "503") {
			t.Fatalf("onError got %v, want the 503", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the refused attempt never reached onError")
	}
	expectEntry(t, entries, `{"type":"info","payload":"after-refusal"}`)
}

// A subscription the peer accepts at the TCP level but never answers must not
// hang forever: the first answer has a deadline, the hang reaches the Error
// hook, Open never fires, and the retry loop goes on.
func TestStreamOpenDeadlineEndsAHungSubscription(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		<-r.Context().Done() // never writes a header
	}))
	defer srv.Close()

	client, err := New(Config{Addr: addrOf(t, srv), HTTPClient: srv.Client(), StreamOpenTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	client.backoffBase = time.Millisecond
	client.backoffMax = 2 * time.Millisecond
	client.jitter = func() float64 { return 1 }

	errs := make(chan error, 16)
	var opened atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.StreamLogsWithHooks(ctx, "info", StreamHooks{
			Entry: func([]byte) {},
			Open:  func() { opened.Store(true) },
			Error: func(err error) { errs <- err },
		})
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if !strings.Contains(err.Error(), "no answer within") {
				t.Fatalf("hang reported as %v, want the first-answer deadline", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a hung subscription never reached the Error hook")
		}
	}
	if opened.Load() {
		t.Fatal("Open fired for a subscription that never answered")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamLogsWithHooks returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StreamLogsWithHooks did not return after cancel")
	}
	if attempts.Load() < 2 {
		t.Fatalf("attempts = %d, want the retry loop to go on after the deadline", attempts.Load())
	}
}

// The deadline covers the first answer only: a stream that answered and then
// stays quiet for longer than the deadline is still open.
func TestStreamOpenDeadlineDoesNotBoundAnOpenStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flush(t, w)
		select {
		case <-time.After(300 * time.Millisecond):
			_, _ = fmt.Fprintln(w, `{"type":"info","payload":"late"}`)
			flush(t, w)
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	client, err := New(Config{Addr: addrOf(t, srv), HTTPClient: srv.Client(), StreamOpenTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	entries := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.StreamLogs(ctx, "info", func(entry []byte) { entries <- string(entry) })
	}()
	expectEntry(t, entries, `{"type":"info","payload":"late"}`)
}
