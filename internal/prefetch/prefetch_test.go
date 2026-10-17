package prefetch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const testToken = "node-token-secret"

// testServer is the control plane's prefetch route as the agent sees it:
// it serves one object at its path, with ranges and the digest as ETag, to
// the node's bearer token, and records every request.
type testServer struct {
	*httptest.Server
	data   []byte
	digest string
	path   string

	mu       sync.Mutex
	requests []*http.Request
	// behave decides each response by its index; nil serves normally.
	behave func(n int, w http.ResponseWriter, r *http.Request) bool
}

func newTestServer(t *testing.T, data []byte, target Target) *testServer {
	t.Helper()
	ts := &testServer{data: data, digest: target.served(), path: "/api/agent/prefetch-binary/" + target.objectPath()}
	ts.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		n := len(ts.requests)
		ts.requests = append(ts.requests, r.Clone(r.Context()))
		behave := ts.behave
		ts.mu.Unlock()
		if behave != nil && behave(n, w, r) {
			return
		}
		ts.serve(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *testServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken || r.URL.Query().Get("node_id") != "node-a" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.URL.Path != ts.path {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("ETag", `"`+ts.digest+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(ts.data))
}

func (ts *testServer) seen() []*http.Request {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]*http.Request(nil), ts.requests...)
}

// cutAfter answers request n with the first k bytes of what it would send,
// then drops the connection.
func cutAfter(ts *testServer, n, k int) func(int, http.ResponseWriter, *http.Request) bool {
	return func(i int, w http.ResponseWriter, r *http.Request) bool {
		if i != n {
			return false
		}
		ts.serve(&cutWriter{ResponseWriter: w, left: k}, r)
		return true
	}
}

type cutWriter struct {
	http.ResponseWriter
	left int
}

func (w *cutWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		panic(http.ErrAbortHandler)
	}
	if len(p) > w.left {
		p = p[:w.left]
	}
	n, err := w.ResponseWriter.Write(p)
	w.left -= n
	w.ResponseWriter.(http.Flusher).Flush()
	return n, err
}

type fixture struct {
	dir    string
	exe    string
	data   []byte
	target Target
	ts     *testServer
	now    atomic.Int64
	free   atomic.Uint64
	opts   Options
}

func testData(size int) []byte {
	rng := rand.New(rand.NewSource(int64(size)))
	data := make([]byte, size)
	rng.Read(data)
	return data
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newFixture is an agent installed at <dir>/lattice-agent with a default
// install path in the plan, so the script keeps its download in dir, and a
// control plane serving the file. compressed names the file by a second
// digest, as a compressed plan does; prefetch treats the bytes the same.
func newFixture(t *testing.T, size int, compressed bool) *fixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := testData(size)
	target := Target{
		ApprovalID: "approval-1", Version: "0.3.10-alpha.7", OS: "linux", Arch: "amd64",
		SHA256: digestOf(data), Size: int64(len(data)), BinarySize: int64(len(data)),
		InstallPath: defaultInstallPath,
	}
	if compressed {
		target.SHA256 = digestOf(append([]byte("binary:"), data...))
		target.CompressedSHA256 = digestOf(data)
		target.BinarySize = int64(len(data)) * 2
	}
	f := &fixture{dir: dir, exe: filepath.Join(dir, "lattice-agent"), data: data, target: target}
	f.ts = newTestServer(t, data, target)
	f.now.Store(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC).UnixNano())
	f.free.Store(1 << 40)
	f.opts = Options{
		Server: f.ts.URL, NodeID: "node-a", Token: testToken,
		Executable: f.exe, AgentVersion: "0.3.10-alpha.6",
		Root: true, CanRunUpdate: true,
		Transport: f.ts.Client().Transport,
		FreeSpace: func(string) (uint64, error) { return f.free.Load(), nil },
		GOOS:      "linux", GOARCH: "amd64",
		Now: func() time.Time { return time.Unix(0, f.now.Load()) },
	}
	return f
}

func (f *fixture) partial() string {
	return filepath.Join(f.dir, PartialPrefix+f.target.served())
}

func (f *fixture) config() *Config {
	t := f.target
	return &Config{Prefetch: &t, Keep: []string{f.target.SHA256, f.target.served()}}
}

func (f *fixture) advance(d time.Duration) { f.now.Add(int64(d)) }

// waitState waits until the prefetcher reports state with no download in
// flight.
func waitState(t *testing.T, p *Prefetcher, state string) *Facts {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		facts := p.Facts()
		p.mu.Lock()
		idle := p.run == nil
		p.mu.Unlock()
		if facts != nil && facts.State == state && idle {
			return facts
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("prefetch never reached %q: %+v", state, p.Facts())
	return nil
}

func requireScriptFile(t *testing.T, path string, want []byte) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		t.Fatalf("the script continues only a regular file of its own user: mode %v uid %d nlink %d", fi.Mode(), st.Uid, st.Nlink)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, want) {
		t.Fatalf("file holds %d bytes, want %d", len(got), len(want))
	}
}

// A download cut short resumes from the bytes on disk, also in a new agent
// process, is held to its digest at the end, and leaves exactly the file the
// update script continues: .lattice-agent-download-<digest> beside the
// agent's binary, regular, 0600, owned by the agent's user.
func TestPrefetchResumesVerifiesAndLeavesTheScriptsFile(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("compressed=%v", compressed), func(t *testing.T) {
			f := newFixture(t, 256<<10, compressed)
			cut := len(f.data) / 3
			f.ts.behave = cutAfter(f.ts, 0, cut)
			p := New(f.opts)
			p.Update(f.config())
			facts := waitState(t, p, StateWaiting)
			kept, _ := os.ReadFile(f.partial())
			if facts.Bytes != int64(cut) || len(kept) != cut || !bytes.Equal(kept, f.data[:cut]) {
				t.Fatalf("a cut download must keep what arrived: facts %+v, %d bytes on disk", facts, len(kept))
			}
			if facts.ApprovalID != "approval-1" || facts.SHA256 != f.target.served() || facts.Size != int64(len(f.data)) {
				t.Fatalf("facts %+v", facts)
			}
			p.Close()

			// The agent restarts; the new process continues the same file.
			again := New(f.opts)
			again.Update(f.config())
			facts = waitState(t, again, StateComplete)
			if facts.Bytes != int64(len(f.data)) {
				t.Fatalf("facts %+v", facts)
			}
			requireScriptFile(t, f.partial(), f.data)
			seen := f.ts.seen()
			if len(seen) != 2 || seen[0].Header.Get("Range") != "" ||
				seen[1].Header.Get("Range") != fmt.Sprintf("bytes=%d-", cut) || seen[1].Header.Get("If-Range") != `"`+f.target.served()+`"` {
				t.Fatalf("the second attempt must ask for the rest of the pinned file: %d requests", len(seen))
			}
			for _, r := range seen {
				if r.Header.Get("Accept-Encoding") != "identity" {
					t.Fatalf("a range addresses stored bytes; no transfer encoding may be asked for: %q", r.Header.Get("Accept-Encoding"))
				}
			}

			// A complete file is kept as it is: no request, no rewrite.
			again.Update(f.config())
			third := New(f.opts)
			third.Update(f.config())
			waitState(t, third, StateComplete)
			if n := len(f.ts.seen()); n != 2 {
				t.Fatalf("a complete file must not be fetched again: %d requests", n)
			}
		})
	}
}

// A kept file of full length that fails its digest is discarded and fetched
// whole, and a finished download that fails its digest is discarded too.
func TestPrefetchHoldsTheFileToItsDigest(t *testing.T) {
	f := newFixture(t, 64<<10, true)
	wrong := append([]byte(nil), f.data...)
	wrong[100] ^= 0xff
	if err := os.WriteFile(f.partial(), wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	p := New(f.opts)
	p.Update(f.config())
	waitState(t, p, StateComplete)
	requireScriptFile(t, f.partial(), f.data)
	if seen := f.ts.seen(); len(seen) != 1 || seen[0].Header.Get("Range") != "" {
		t.Fatalf("a full-length wrong file must be fetched whole: %d requests", len(seen))
	}

	g := newFixture(t, 64<<10, false)
	g.ts.data = wrong
	q := New(g.opts)
	q.Update(g.config())
	facts := waitState(t, q, StateWaiting)
	if !strings.Contains(facts.Reason, "did not match its digest") {
		t.Fatalf("facts %+v", facts)
	}
	if fi, err := os.Stat(g.partial()); err != nil || fi.Size() != 0 {
		t.Fatal("a download that fails its digest must not be left for the script")
	}
}

// A server that sends more than the named size never makes the file larger
// than that size, and the digest decides.
func TestPrefetchNeverWritesPastTheNamedSize(t *testing.T) {
	f := newFixture(t, 32<<10, false)
	f.ts.behave = func(_ int, w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("ETag", `"`+f.target.served()+`"`)
		w.WriteHeader(http.StatusOK)
		w.Write(f.data)
		w.Write(bytes.Repeat([]byte{'x'}, 1<<20))
		return true
	}
	p := New(f.opts)
	p.Update(f.config())
	waitState(t, p, StateComplete)
	requireScriptFile(t, f.partial(), f.data)
}

// blockingServer serves the first bytes of the file and then waits until the
// request ends, so a test can stop a download in flight.
func blockingServer(f *fixture, started chan<- struct{}, ended *atomic.Int32) func(int, http.ResponseWriter, *http.Request) bool {
	return func(_ int, w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("ETag", `"`+f.target.served()+`"`)
		start := 0
		if rng := r.Header.Get("Range"); rng != "" {
			fmt.Sscanf(rng, "bytes=%d-", &start)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(f.data)-1, len(f.data)))
			w.WriteHeader(http.StatusPartialContent)
		}
		w.Write(f.data[start : start+1024])
		w.(http.Flusher).Flush()
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		ended.Add(1)
		return true
	}
}

// A config pull that no longer names the file stops the download, and the
// file goes with it when keep no longer names its digest either.
func TestPrefetchStopsWhenTheApprovalDisappears(t *testing.T) {
	for _, kept := range []bool{true, false} {
		t.Run(fmt.Sprintf("still in keep=%v", kept), func(t *testing.T) {
			f := newFixture(t, 64<<10, true)
			started := make(chan struct{}, 1)
			var ended atomic.Int32
			f.ts.behave = blockingServer(f, started, &ended)
			p := New(f.opts)
			p.Update(f.config())
			<-started
			cfg := &Config{Keep: []string{}}
			if kept {
				cfg.Keep = []string{f.target.served()}
			}
			p.Update(cfg)
			deadline := time.Now().Add(5 * time.Second)
			for ended.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if ended.Load() == 0 {
				t.Fatal("the download must stop when the approval is gone")
			}
			p.mu.Lock()
			idle := p.run == nil
			p.mu.Unlock()
			for !idle && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
				p.mu.Lock()
				idle = p.run == nil
				p.mu.Unlock()
			}
			if p.Facts() != nil {
				t.Fatalf("nothing is reported once no file is named: %+v", p.Facts())
			}
			p.Update(cfg)
			_, err := os.Lstat(f.partial())
			if kept != (err == nil) {
				t.Fatalf("the partial must stay exactly when keep names it: kept=%v, stat err %v", kept, err)
			}
		})
	}
}

// Hold stops the download and returns only once the file is closed, so the
// task that runs next is the file's only writer. Nothing starts while held,
// nor on release: the next config pull resumes it.
func TestPrefetchHoldHandsTheFileToTheTask(t *testing.T) {
	f := newFixture(t, 64<<10, false)
	started := make(chan struct{}, 1)
	var ended atomic.Int32
	f.ts.behave = blockingServer(f, started, &ended)
	p := New(f.opts)
	p.Update(f.config())
	<-started
	deadline := time.Now().Add(5 * time.Second)
	for p.Facts().Bytes < 1024 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	p.Hold()
	p.mu.Lock()
	running := p.run != nil
	p.mu.Unlock()
	if running {
		t.Fatal("Hold must return only after the download has stopped")
	}
	size := func() int64 {
		fi, err := os.Stat(f.partial())
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	before := size()
	if before != 1024 {
		t.Fatalf("the partial must hold what arrived before the hold: %d", before)
	}
	p.Update(f.config())
	p.Release()
	time.Sleep(50 * time.Millisecond)
	if n := len(f.ts.seen()); n != 1 || size() != before {
		t.Fatalf("nothing may run while held or on release alone: %d requests, %d bytes", n, size())
	}
	f.ts.behave = nil
	p.Update(f.config())
	waitState(t, p, StateComplete)
	seen := f.ts.seen()
	if len(seen) != 2 || seen[1].Header.Get("Range") != "bytes=1024-" {
		t.Fatalf("the next pull must resume the file: %d requests", len(seen))
	}
}

// A download that would leave the disk short is refused and reported, and
// nothing is created; it is tried again after the backoff.
func TestPrefetchRespectsTheFreeSpaceBound(t *testing.T) {
	f := newFixture(t, 64<<10, true)
	need := uint64(f.target.Size) + 3*uint64(f.target.BinarySize) + reserveBytes
	f.free.Store(need - 1)
	p := New(f.opts)
	p.Update(f.config())
	facts := waitState(t, p, StateRefused)
	if !strings.Contains(facts.Reason, "bytes free beside the agent") || facts.Bytes != 0 {
		t.Fatalf("facts %+v", facts)
	}
	if _, err := os.Lstat(f.partial()); err == nil || len(f.ts.seen()) != 0 {
		t.Fatal("a refused download must create nothing and ask for nothing")
	}
	f.free.Store(need)
	p.Update(f.config())
	time.Sleep(20 * time.Millisecond)
	if len(f.ts.seen()) != 0 {
		t.Fatal("a refusal is retried after its backoff, not on every pull")
	}
	f.advance(firstBackoff)
	p.Update(f.config())
	waitState(t, p, StateComplete)
}

// The node veto stops everything: no request, no file, and no removal of a
// kept download, whatever the server names.
func TestPrefetchVetoFetchesAndRemovesNothing(t *testing.T) {
	f := newFixture(t, 16<<10, false)
	stale := filepath.Join(f.dir, PartialPrefix+strings.Repeat("a", 64))
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.Veto = true
	p := New(f.opts)
	p.Update(f.config())
	facts := p.Facts()
	if facts == nil || facts.State != StateRefused || !strings.Contains(facts.Reason, "-no-prefetch") {
		t.Fatalf("facts %+v", facts)
	}
	time.Sleep(20 * time.Millisecond)
	if len(f.ts.seen()) != 0 {
		t.Fatal("a vetoed node must not fetch")
	}
	if _, err := os.Lstat(f.partial()); err == nil {
		t.Fatal("a vetoed node must not create the file")
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Fatal("a vetoed node must not remove anything")
	}
}

// What the agent cannot use, it does not fetch: a non-root agent, an agent
// that may not run tasks, a file for another platform or the running
// version, a plan installing somewhere other than over this agent, and any
// field outside the shapes the server sends.
func TestPrefetchRefusesWhatItCannotUse(t *testing.T) {
	cases := map[string]struct {
		opts   func(o *Options)
		target func(t *Target)
		reason string
	}{
		"not root":            {opts: func(o *Options) { o.Root = false }, reason: "does not run as root"},
		"no task execution":   {opts: func(o *Options) { o.CanRunUpdate = false }, reason: "task execution is disabled"},
		"another arch":        {target: func(t *Target) { t.Arch = "arm64" }, reason: "this agent runs on linux/amd64"},
		"the running version": {target: func(t *Target) { t.Version = "v0.3.10-alpha.6" }, reason: "already runs"},
		"a custom install path elsewhere": {target: func(t *Target) { t.InstallPath = "/srv/other/lattice-agent" },
			reason: "not over this agent's own binary"},
		"a relative install path":    {target: func(t *Target) { t.InstallPath = "lattice-agent" }, reason: "clean absolute path"},
		"an unclean install path":    {target: func(t *Target) { t.InstallPath = "/opt/lattice/../lattice-agent" }, reason: "clean absolute path"},
		"a version with a separator": {target: func(t *Target) { t.Version = "../../x" }, reason: "plain version"},
		"a version naming a host":    {target: func(t *Target) { t.Version = "x@evil.example" }, reason: "plain version"},
		"an uppercase digest":        {target: func(t *Target) { t.SHA256 = strings.ToUpper(t.SHA256) }, reason: "lowercase hex"},
		"a short compressed digest":  {target: func(t *Target) { t.CompressedSHA256 = "abc" }, reason: "compressed sha256"},
		"an oversized file":          {target: func(t *Target) { t.Size = maxFileBytes + 1 }, reason: "sizes must be"},
		"an uncompressed size mismatch": {target: func(t *Target) {
			t.CompressedSHA256 = ""
			t.BinarySize = t.Size + 1
		}, reason: "size of the binary"},
		"an approval id with a separator": {target: func(t *Target) { t.ApprovalID = "a/b" }, reason: "approval id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 16<<10, true)
			if tc.opts != nil {
				tc.opts(&f.opts)
			}
			if tc.target != nil {
				tc.target(&f.target)
			}
			p := New(f.opts)
			p.Update(f.config())
			facts := p.Facts()
			if facts == nil || facts.State != StateRefused || !strings.Contains(facts.Reason, tc.reason) {
				t.Fatalf("facts %+v, want a refusal naming %q", facts, tc.reason)
			}
			time.Sleep(20 * time.Millisecond)
			if len(f.ts.seen()) != 0 {
				t.Fatal("a refused file must not be fetched")
			}
		})
	}
}

// The node credential goes to the enrolled server and nowhere else: a
// redirect is never followed, so a server, a proxy in its place or a path
// that answers 3xx cannot send the bearer token, or the agent, elsewhere.
func TestPrefetchNeverFollowsARedirect(t *testing.T) {
	f := newFixture(t, 16<<10, false)
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Write(f.data)
	}))
	defer other.Close()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		f.ts.behave = func(_ int, w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, other.URL+r.URL.Path, code)
			return true
		}
		p := New(f.opts)
		p.Update(f.config())
		facts := waitState(t, p, StateWaiting)
		if !strings.Contains(facts.Reason, "redirect") {
			t.Fatalf("%d: facts %+v", code, facts)
		}
		p.Close()
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("a redirect was followed %d times", elsewhere.Load())
	}
	for _, r := range f.ts.seen() {
		if r.Host != strings.TrimPrefix(f.ts.URL, "https://") {
			t.Fatalf("a request went to %q", r.Host)
		}
	}
}

// Every request goes to the enrolled server's own route for exactly the
// named object, carries the token only in the Authorization header, and
// carries the node id; nothing the server names becomes a host.
func TestPrefetchSendsTheCredentialOnlyToItsServer(t *testing.T) {
	f := newFixture(t, 16<<10, true)
	p := New(f.opts)
	p.Update(f.config())
	waitState(t, p, StateComplete)
	seen := f.ts.seen()
	if len(seen) != 1 {
		t.Fatalf("%d requests", len(seen))
	}
	r := seen[0]
	want := fmt.Sprintf("/api/agent/prefetch-binary/0.3.10-alpha.7/linux/amd64/%s/%s.gz", f.target.SHA256, f.target.CompressedSHA256)
	if r.URL.Path != want || r.URL.RawQuery != "node_id=node-a" {
		t.Fatalf("request %s?%s, want %s?node_id=node-a", r.URL.Path, r.URL.RawQuery, want)
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken || strings.Contains(r.URL.String(), testToken) {
		t.Fatal("the token travels in the Authorization header only")
	}
	// The prefetcher has no way to reach another host: the URL is the
	// enrolled server plus validated path segments.
	if got := p.opts.Server; got != f.ts.URL {
		t.Fatalf("server %q", got)
	}
}

// A server that answers with another ETag, another range or another total
// is not continued.
func TestPrefetchRefusesAResponseForOtherBytes(t *testing.T) {
	cases := map[string]func(f *fixture) func(int, http.ResponseWriter, *http.Request) bool{
		"another etag": func(f *fixture) func(int, http.ResponseWriter, *http.Request) bool {
			return func(_ int, w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("ETag", `"`+strings.Repeat("0", 64)+`"`)
				w.Write(f.data)
				return true
			}
		},
		"another range start": func(f *fixture) func(int, http.ResponseWriter, *http.Request) bool {
			return func(_ int, w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("ETag", `"`+f.target.served()+`"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 10-%d/%d", len(f.data)-1, len(f.data)))
				w.WriteHeader(http.StatusPartialContent)
				w.Write(f.data[10:])
				return true
			}
		},
		"another total": func(f *fixture) func(int, http.ResponseWriter, *http.Request) bool {
			return func(_ int, w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("ETag", `"`+f.target.served()+`"`)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 100-%d/%d", len(f.data)-1, len(f.data)+5))
				w.WriteHeader(http.StatusPartialContent)
				w.Write(f.data[100:])
				return true
			}
		},
	}
	for name, behave := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 16<<10, false)
			if err := os.WriteFile(f.partial(), f.data[:100], 0o600); err != nil {
				t.Fatal(err)
			}
			f.ts.behave = behave(f)
			p := New(f.opts)
			p.Update(f.config())
			waitState(t, p, StateWaiting)
			got, _ := os.ReadFile(f.partial())
			if !bytes.Equal(got, f.data[:100]) {
				t.Fatalf("the kept bytes must be left as they were: %d bytes", len(got))
			}
		})
	}
}

// Pruning removes kept downloads no open update names, beside the agent
// only: a directory and other files stay, a symlink goes as a name and its
// target stays, and an older server, which sends no block, prunes nothing.
func TestPrefetchPrunesDownloadsNoOpenUpdateNames(t *testing.T) {
	f := newFixture(t, 16<<10, false)
	outside := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(outside, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := PartialPrefix + strings.Repeat("a", 64)
	keptByKeep := PartialPrefix + strings.Repeat("b", 64)
	link := PartialPrefix + strings.Repeat("c", 64)
	dirName := PartialPrefix + strings.Repeat("d", 64)
	other := "lattice-agent.bak"
	for _, name := range []string{stale, keptByKeep, other} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(f.dir, link)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.dir, dirName), 0o700); err != nil {
		t.Fatal(err)
	}
	exists := func(name string) bool {
		_, err := os.Lstat(filepath.Join(f.dir, name))
		return err == nil
	}

	p := New(f.opts)
	p.Update(nil)
	if !exists(stale) || !exists(link) {
		t.Fatal("an older server's config must prune nothing")
	}
	p.Update(&Config{Keep: []string{strings.Repeat("b", 64)}})
	if exists(stale) || exists(link) || !exists(keptByKeep) || !exists(dirName) || !exists(other) {
		t.Fatalf("stale %v link %v keep %v dir %v other %v", exists(stale), exists(link), exists(keptByKeep), exists(dirName), exists(other))
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "precious" {
		t.Fatal("a symlink's target must never be touched")
	}
	if len(f.ts.seen()) != 0 {
		t.Fatal("pruning fetches nothing")
	}
}

// The partial's name is never followed: a symlink or a second hard link at
// it is replaced by a new file, and what it pointed at is untouched.
func TestPrefetchNeverWritesThroughTheName(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, 16<<10, false)
			victim := filepath.Join(f.dir, "victim")
			if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "symlink" {
				err = os.Symlink(victim, f.partial())
			} else {
				err = os.Link(victim, f.partial())
			}
			if err != nil {
				t.Fatal(err)
			}
			p := New(f.opts)
			p.Update(f.config())
			waitState(t, p, StateComplete)
			if b, _ := os.ReadFile(victim); string(b) != "victim" {
				t.Fatalf("the %s's target was written: %q", kind, b)
			}
			requireScriptFile(t, f.partial(), f.data)
		})
	}
}

// A directory another user can change is refused: a name there could be
// swapped between the agent's checks and the script's.
func TestPrefetchRefusesADirectoryOthersCanWrite(t *testing.T) {
	f := newFixture(t, 16<<10, false)
	if err := os.Chmod(f.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.dir, 0o700)
	p := New(f.opts)
	p.Update(f.config())
	facts := p.Facts()
	if facts == nil || facts.State != StateRefused || !strings.Contains(facts.Reason, "can be changed by a user other than root") {
		t.Fatalf("facts %+v", facts)
	}
	time.Sleep(20 * time.Millisecond)
	if len(f.ts.seen()) != 0 {
		t.Fatal("nothing may be fetched into such a directory")
	}
}

// A failed attempt is retried after a backoff that doubles, not in a loop.
func TestPrefetchBacksOffAfterAFailure(t *testing.T) {
	f := newFixture(t, 16<<10, false)
	f.ts.behave = func(_ int, w http.ResponseWriter, _ *http.Request) bool {
		http.Error(w, "busy", http.StatusTooManyRequests)
		return true
	}
	p := New(f.opts)
	p.Update(f.config())
	waitState(t, p, StateWaiting)
	for i, wait := range []time.Duration{firstBackoff, 2 * firstBackoff} {
		p.Update(f.config())
		time.Sleep(20 * time.Millisecond)
		if n := len(f.ts.seen()); n != i+1 {
			t.Fatalf("retry %d came before its backoff: %d requests", i, n)
		}
		f.advance(wait)
		p.Update(f.config())
		deadline := time.Now().Add(5 * time.Second)
		for len(f.ts.seen()) != i+2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		waitState(t, p, StateWaiting)
	}
}

// ScriptDir follows the update script's rule for the directory its download
// lives in, and answers only for the agent's own binary.
func TestScriptDirFollowsTheScriptsRule(t *testing.T) {
	cases := []struct {
		install, exe, dir string
		ok                bool
	}{
		{defaultInstallPath, "/opt/lattice/node-agent/lattice-agent", "/opt/lattice/node-agent", true},
		{defaultInstallPath, "/usr/local/bin/lattice-agent", "/usr/local/bin", true},
		{oldDefaultInstallPath, "/srv/x/lattice-agent", "/srv/x", true},
		{legacyInstallPath, "/opt/lattice/node-agent/lattice-agent", "/opt/lattice/node-agent", true},
		{"/srv/custom/agent", "/srv/custom/agent", "/srv/custom", true},
		{"/srv/custom/lattice-agent", "/opt/lattice/node-agent/lattice-agent", "", false},
		{defaultInstallPath, "/opt/lattice/node-agent/lattice-agent (deleted)", "", false},
		{defaultInstallPath, "/opt/lattice/node-agent/agent", "", false},
		{defaultInstallPath, "", "", false},
	}
	for _, tc := range cases {
		dir, ok := ScriptDir(tc.install, tc.exe)
		if dir != tc.dir || ok != tc.ok {
			t.Errorf("ScriptDir(%q, %q) = %q %v, want %q %v", tc.install, tc.exe, dir, ok, tc.dir, tc.ok)
		}
	}
}
