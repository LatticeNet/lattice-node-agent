// Package prefetch fetches the binary of this node's open agent update in the
// background, before its task runs (design 31, S4).
//
// An agent update task downloads one binary inside a fixed budget, and a node
// whose own line is slow cannot finish inside any budget. The server's config
// pull therefore names the file of the node's open update, pending or
// approved but not yet running, by digests and sizes. The agent fetches that
// file with no deadline, resuming where it stopped, into exactly the file the
// update script continues: .lattice-agent-download-<digest>, beside the
// binary the script will replace, root-only. When the task runs it finds the
// file complete, or nearly so, holds it to the pinned digest as always, and
// installs. The script does not change.
//
// Nothing runs because of a prefetch. The bytes land in a root-only file
// named by a validated digest; only the approved task's own digest and
// version checks decide whether they ever execute.
//
// Safe defaults: the agent fetches only from its own enrolled server, with
// its node credential, and never follows a redirect; the server names
// digests and sizes, never a URL; the file is written only beside the
// agent's own binary, in a directory no other user can write, never through
// a symlink and never past the named size; it is refused when the disk would
// be left short; and partials no open update names are removed. A node veto
// (-no-prefetch) turns all of it off.
package prefetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PartialPrefix names the download the update script keeps beside the
// binary it installs; the pinned digest completes the name. It must equal
// agentUpdatePartialPrefix in lattice-server.
const PartialPrefix = ".lattice-agent-download-"

// The install paths the update script replaces with the running agent's own
// path (lattice-server agentUpdateApplyScript). They must equal
// defaultAgentInstallPath, previousDefaultAgentInstallPath and
// legacyAgentInstallPath there.
const (
	defaultInstallPath    = "/opt/lattice/node-agent/lattice-agent"
	oldDefaultInstallPath = "/opt/lattice/lattice-agent"
	legacyInstallPath     = "/usr/local/bin/lattice-agent"
)

const (
	// maxFileBytes bounds the file the server may name. It equals the
	// server's maxAgentArtifactBytes: no stored binary is larger.
	maxFileBytes = 48 << 20

	// reserveBytes is what the disk keeps free after the download, beyond
	// three copies of the binary the update itself writes (the decompressed
	// candidate, the new install and the backup). One node in the fleet has
	// run its disk to 99 percent; prefetch must never be what fills one.
	reserveBytes = 256 << 20

	// stallTimeout ends a response that delivers nothing for this long; the
	// next attempt resumes from what arrived.
	stallTimeout = 2 * time.Minute

	firstBackoff = 30 * time.Second
	maxBackoff   = 15 * time.Minute
	// progressRetry is the pause before continuing a response that ended
	// after delivering bytes, about one config pull.
	progressRetry = 10 * time.Second

	// RoutePrefix is the control plane's prefetch route. It must equal
	// agentPrefetchPathPrefix in lattice-server.
	RoutePrefix = "/api/agent/prefetch-binary/"

	maxKeep   = 16
	maxReason = 200
)

// States reported in Facts.
const (
	StateFetching = "fetching"
	StateComplete = "complete"
	StateWaiting  = "waiting"
	StateRefused  = "refused"
)

var (
	approvalIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	versionRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`)
	digestRe     = regexp.MustCompile(`^[a-f0-9]{64}$`)

	errRedirect = errors.New("the server answered with a redirect, which prefetch never follows")
)

// Target is the file the server names: the agent_update.prefetch block of
// the config pull. Size is the size of the file fetched, the compressed one
// when CompressedSHA256 is set; BinarySize is that of the binary the update
// installs.
type Target struct {
	ApprovalID       string `json:"approval_id"`
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	SHA256           string `json:"sha256"`
	CompressedSHA256 string `json:"compressed_sha256,omitempty"`
	Size             int64  `json:"size"`
	BinarySize       int64  `json:"binary_size"`
	InstallPath      string `json:"install_path"`
}

// Config is the agent_update block of the config pull. A server that serves
// prefetch always sends it; Keep lists the digests of every pending or
// approved update of this node, running ones included.
type Config struct {
	Prefetch *Target  `json:"prefetch,omitempty"`
	Keep     []string `json:"keep"`
}

// Facts is what the agent reports in its heartbeat while the server names a
// file: which file, how much of it is on disk, and what the agent is doing
// about it.
type Facts struct {
	ApprovalID string `json:"approval_id"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Size       int64  `json:"size"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
}

// served is the digest of the bytes fetched and the name of their file.
func (t Target) served() string {
	if t.CompressedSHA256 != "" {
		return t.CompressedSHA256
	}
	return t.SHA256
}

func (t Target) validate() error {
	switch {
	case !approvalIDRe.MatchString(t.ApprovalID):
		return errors.New("approval id is not a plain identifier")
	case !versionRe.MatchString(t.Version):
		return errors.New("version is not a plain version string")
	case !digestRe.MatchString(t.SHA256):
		return errors.New("sha256 is not a 64-character lowercase hex digest")
	case t.CompressedSHA256 != "" && !digestRe.MatchString(t.CompressedSHA256):
		return errors.New("compressed sha256 is not a 64-character lowercase hex digest")
	case t.Size <= 0 || t.Size > maxFileBytes || t.BinarySize <= 0 || t.BinarySize > maxFileBytes:
		return fmt.Errorf("sizes must be between 1 and %d bytes", maxFileBytes)
	case t.CompressedSHA256 == "" && t.Size != t.BinarySize:
		return errors.New("an uncompressed file must be the size of the binary")
	case !filepath.IsAbs(t.InstallPath) || filepath.Clean(t.InstallPath) != t.InstallPath || strings.ContainsRune(t.InstallPath, 0):
		return errors.New("install path is not a clean absolute path")
	}
	return nil
}

// objectPath is the server's object path for the file:
// version/os/arch/sha256, with /<compressed sha256>.gz for the compressed
// form. Every part was validated, so none can hold a separator.
func (t Target) objectPath() string {
	p := url.PathEscape(t.Version) + "/" + t.OS + "/" + t.Arch + "/" + t.SHA256
	if t.CompressedSHA256 != "" {
		p += "/" + t.CompressedSHA256 + ".gz"
	}
	return p
}

// ScriptDir is the directory the update script keeps its download in, by the
// script's own rule: the plan's install path, except that a default or
// legacy path follows the running agent when its path ends in
// /lattice-agent. Prefetch writes only beside the agent's own binary, so it
// answers false when the script would resolve anything else.
func ScriptDir(installPath, executable string) (string, bool) {
	target := installPath
	if strings.HasSuffix(executable, "/lattice-agent") {
		switch target {
		case defaultInstallPath, oldDefaultInstallPath, legacyInstallPath:
			target = executable
		}
	}
	if executable == "" || target != executable {
		return "", false
	}
	return filepath.Dir(target), true
}

// Options configures a Prefetcher. Server, NodeID and Token are the agent's
// own enrollment; nothing the server sends can change where a request goes.
type Options struct {
	Server, NodeID, Token string
	// Executable is the running agent's path as the update script reads it:
	// readlink of /proc/self/exe.
	Executable   string
	AgentVersion string
	// Veto is the node's -no-prefetch: nothing is fetched or removed.
	Veto bool
	// Root says the agent runs as root. The update script runs as the
	// agent's user and continues only a download that user owns; a non-root
	// agent cannot run the update at all.
	Root bool
	// CanRunUpdate says this agent may run tasks, so an update can use the
	// file.
	CanRunUpdate bool

	// OnChange is called, on its own goroutine, when the reported state
	// changes; the agent nudges its heartbeat with it.
	OnChange func()
	// Logf receives state changes. It is called with the prefetcher's lock
	// held and must not call back into the Prefetcher.
	Logf func(format string, args ...any)

	// The rest is for tests.
	Transport    http.RoundTripper
	FreeSpace    func(dir string) (uint64, error)
	GOOS         string
	GOARCH       string
	Now          func() time.Time
	StallTimeout time.Duration
}

// Prefetcher runs at most one download at a time and holds it while a task
// runs. Update, Hold, Release, Close and Facts are safe from any goroutine.
type Prefetcher struct {
	opts   Options
	client *http.Client

	mu     sync.Mutex
	known  bool
	cfg    Config
	held   int
	closed bool
	run    *fetchRun
	// The state reported for the current target.
	key      string
	state    string
	reason   string
	bytes    int64
	failures int
	retryAt  time.Time
	// verified records the size and modification time of a file that was
	// last checked complete, so it is not hashed again on every update.
	verified fileStamp
	progress atomic.Int64
}

type fetchRun struct {
	key    string
	cancel context.CancelFunc
	done   chan struct{}
}

type fileStamp struct {
	path  string
	size  int64
	mtime time.Time
}

// New returns a Prefetcher that does nothing until the first Update.
func New(opts Options) *Prefetcher {
	if opts.FreeSpace == nil {
		opts.FreeSpace = freeSpace
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.StallTimeout <= 0 {
		opts.StallTimeout = stallTimeout
	}
	opts.Server = strings.TrimRight(opts.Server, "/")
	transport := opts.Transport
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.DialContext = (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		base.TLSHandshakeTimeout = 20 * time.Second
		base.ResponseHeaderTimeout = time.Minute
		// The server sends the stored bytes as they are, and a range must
		// address those bytes; no transparent decoding.
		base.DisableCompression = true
		transport = base
	}
	return &Prefetcher{
		opts: opts,
		client: &http.Client{
			Transport: transport,
			// The node credential goes to the enrolled server and nowhere
			// else, so no redirect is ever followed: the 3xx is the answer.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Update applies one config pull. nil means the server sent no agent_update
// block, an older server: nothing is fetched and nothing is removed. While a
// task holds the prefetcher the config is kept and acted on only once an
// update arrives after the task.
func (p *Prefetcher) Update(cfg *Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cfg == nil {
		p.known = false
		p.cfg = Config{}
	} else {
		p.known = true
		p.cfg = *cfg
	}
	p.kickLocked()
}

// Hold stops any download and returns once its file is closed, so a task
// that runs after Hold returns is the only writer of the partial. Every
// task holds: an update task for another digest removes this file, and
// prefetch should not compete with a task for the node's line.
func (p *Prefetcher) Hold() {
	p.mu.Lock()
	p.held++
	run := p.run
	if run != nil {
		run.cancel()
	}
	p.mu.Unlock()
	if run != nil {
		<-run.done
	}
}

// Release ends one Hold. Nothing starts until the next Update: the config in
// hand was pulled before the task finished and may name a file the task has
// since installed and removed.
func (p *Prefetcher) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held > 0 {
		p.held--
	}
}

// Close stops for good, for agent shutdown.
func (p *Prefetcher) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.Hold()
}

// Facts is the heartbeat's "prefetch" value, nil while the server names no
// file.
func (p *Prefetcher) Facts() *Facts {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.cfg.Prefetch
	if !p.known || t == nil || p.state == "" {
		return nil
	}
	facts := &Facts{
		ApprovalID: boundReason(t.ApprovalID, 64), SHA256: boundReason(t.served(), 64),
		Bytes: p.bytes, Size: t.Size, State: p.state, Reason: p.reason,
	}
	if p.key != p.keyLocked() {
		// The download of the file named before is still stopping; nothing
		// of it describes the file named now.
		facts.Bytes, facts.State, facts.Reason = 0, StateWaiting, "switching to the file the server names now"
	} else if p.run != nil {
		facts.Bytes = p.progress.Load()
	}
	return facts
}

// keyLocked names the file the current config asks for, "" for none.
func (p *Prefetcher) keyLocked() string {
	t := p.cfg.Prefetch
	if !p.known || t == nil {
		return ""
	}
	return t.ApprovalID + "|" + t.served() + "|" + t.InstallPath
}

// kickLocked decides what to do with the current config: prune, refuse,
// keep a complete file, or start a download.
func (p *Prefetcher) kickLocked() {
	if p.closed || p.held > 0 {
		return
	}
	t := p.cfg.Prefetch
	key := p.keyLocked()
	if p.run != nil {
		if p.run.key != key {
			// The approval moved on or went away; the download stops and
			// the next update decides again.
			p.run.cancel()
		}
		return
	}
	if key != p.key {
		p.key, p.state, p.reason, p.bytes, p.failures, p.retryAt = key, "", "", 0, 0, time.Time{}
	}
	if !p.known {
		return
	}
	if p.opts.Veto {
		if t != nil {
			p.setLocked(StateRefused, "the node vetoes prefetch (-no-prefetch)", 0)
		}
		return
	}
	if !p.opts.Root {
		if t != nil {
			p.setLocked(StateRefused, "the agent does not run as root, and the update continues only a download root owns", 0)
		}
		return
	}
	// The agent writes and removes only beside its own binary.
	ownDir := ""
	if filepath.IsAbs(p.opts.Executable) {
		ownDir = filepath.Dir(p.opts.Executable)
	}
	dirErr := errors.New("the agent cannot read its own path")
	if ownDir != "" {
		dirErr = secureDir(ownDir)
	}
	if dirErr == nil {
		p.pruneLocked(ownDir, t)
	}
	if t == nil {
		return
	}
	if !p.opts.CanRunUpdate {
		p.setLocked(StateRefused, "task execution is disabled on this node, so no update can use the file", 0)
		return
	}
	if err := t.validate(); err != nil {
		p.setLocked(StateRefused, "the server named a file this agent does not fetch: "+err.Error(), 0)
		return
	}
	if t.OS != p.opts.GOOS || t.Arch != p.opts.GOARCH {
		p.setLocked(StateRefused, fmt.Sprintf("the file is for %s/%s and this agent runs on %s/%s", t.OS, t.Arch, p.opts.GOOS, p.opts.GOARCH), 0)
		return
	}
	if strings.TrimPrefix(t.Version, "v") == strings.TrimPrefix(p.opts.AgentVersion, "v") {
		p.setLocked(StateRefused, "this agent already runs version "+t.Version, 0)
		return
	}
	dir, ok := ScriptDir(t.InstallPath, p.opts.Executable)
	if !ok {
		p.setLocked(StateRefused, "the update installs to "+boundReason(t.InstallPath, 80)+", not over this agent's own binary, and prefetch writes only beside that", 0)
		return
	}
	if dirErr != nil {
		p.setLocked(StateRefused, dirErr.Error(), 0)
		return
	}
	path := filepath.Join(dir, PartialPrefix+t.served())
	if p.state == StateComplete && p.verified.matches(path) {
		return
	}
	if p.opts.Now().Before(p.retryAt) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &fetchRun{key: key, cancel: cancel, done: make(chan struct{})}
	p.run = run
	p.progress.Store(p.bytes)
	p.setLocked(StateFetching, "", p.bytes)
	go p.fetch(ctx, run, *t, path)
}

func (p *Prefetcher) setLocked(state, reason string, bytes int64) {
	reason = boundReason(reason, maxReason)
	changed := state != p.state || reason != p.reason
	p.state, p.reason, p.bytes = state, reason, bytes
	if changed {
		if state == StateRefused || state == StateWaiting {
			p.opts.Logf("agent update prefetch %s: %s", state, reason)
		} else {
			p.opts.Logf("agent update prefetch %s", state)
		}
		if p.opts.OnChange != nil {
			go p.opts.OnChange()
		}
	}
}

// pruneLocked removes kept downloads in dir whose digest no open update
// names: the files earlier attempts left when a policy moved on or an
// operator rejected a plan. A directory is left alone, and a symlink is
// removed as a name, never followed.
func (p *Prefetcher) pruneLocked(dir string, t *Target) {
	keep := map[string]bool{}
	for i, digest := range p.cfg.Keep {
		if i >= maxKeep {
			break
		}
		if digestRe.MatchString(digest) {
			keep[digest] = true
		}
	}
	if t != nil && t.validate() == nil {
		keep[t.SHA256] = true
		keep[t.served()] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		digest, ok := strings.CutPrefix(name, PartialPrefix)
		if !ok || keep[digest] || e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			p.opts.Logf("agent update prefetch: removed %s, which no open update names", name)
		}
	}
}

// fetch runs one download attempt and records what came of it.
func (p *Prefetcher) fetch(ctx context.Context, run *fetchRun, t Target, path string) {
	state, reason, have, gained := p.attempt(ctx, t, path)
	p.mu.Lock()
	if p.run == run {
		p.run = nil
	}
	if p.key == run.key {
		switch {
		case state == StateComplete:
			p.failures, p.retryAt = 0, time.Time{}
			p.verified = stampOf(path)
		case ctx.Err() != nil:
			// Stopped by Hold or by a new config, not failed: no backoff.
			// The stall timer cancels only the request, never this context.
			state, reason = StateWaiting, "stopped for a task or a new config; the next config pull resumes it"
		case gained > 0:
			// The response delivered bytes before it ended: a line too slow
			// for the server's 30 minute response, or one that drops or
			// stalls. That is progress, so it continues after a short pause
			// rather than the backoff, which is for attempts that move
			// nothing; the pause keeps a server that sends a byte and hangs
			// up from turning this into a loop.
			p.failures, p.retryAt = 0, p.opts.Now().Add(progressRetry)
		default:
			// A failure or a refusal (the disk, the server) is retried
			// after a backoff that doubles up to maxBackoff, never in a
			// loop.
			backoff := maxBackoff
			if p.failures < 10 {
				backoff = min(firstBackoff<<p.failures, maxBackoff)
			}
			p.failures++
			p.retryAt = p.opts.Now().Add(backoff)
		}
		p.setLocked(state, reason, have)
	}
	p.kickLocked()
	p.mu.Unlock()
	close(run.done)
}

// attempt fetches what the file still lacks and verifies a file that reached
// its size. It returns the state, a reason, how many bytes the file holds,
// and how many this attempt added. The file is closed before it returns.
func (p *Prefetcher) attempt(ctx context.Context, t Target, path string) (state, reason string, have, gained int64) {
	// The disk is checked before anything is created. A kept file of full
	// length needs nothing more, and if it fails its digest, truncating it
	// frees what the download then takes.
	kept := int64(0)
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		kept = min(fi.Size(), t.Size)
	}
	if kept < t.Size {
		avail, err := p.opts.FreeSpace(filepath.Dir(path))
		if err != nil {
			return StateRefused, "cannot read the free space: " + err.Error(), kept, 0
		}
		need := uint64(t.Size-kept) + 3*uint64(t.BinarySize) + reserveBytes
		if avail < need {
			return StateRefused, fmt.Sprintf("%d bytes free beside the agent; the download needs %d more and must leave room for the update and %d spare", avail, t.Size-kept, reserveBytes), kept, 0
		}
	}
	f, have, err := openPartial(path)
	if err != nil {
		return StateWaiting, "cannot open the download: " + err.Error(), 0, 0
	}
	defer f.Close()
	if have > t.Size {
		if err := f.Truncate(0); err != nil {
			return StateWaiting, "cannot reset the download: " + err.Error(), have, 0
		}
		have = 0
	}
	if have == t.Size {
		if ok, err := fileMatches(f, t.served()); err != nil {
			return StateWaiting, "cannot read the download: " + err.Error(), have, 0
		} else if ok {
			return StateComplete, "", have, 0
		}
		if err := f.Truncate(0); err != nil {
			return StateWaiting, "cannot reset the download: " + err.Error(), have, 0
		}
		have = 0
	}
	before := have
	have, err = p.download(ctx, f, t, have)
	gained = max(have-before, 0)
	if err != nil {
		return StateWaiting, err.Error(), have, gained
	}
	if err := f.Sync(); err != nil {
		return StateWaiting, "cannot sync the download: " + err.Error(), have, gained
	}
	ok, err := fileMatches(f, t.served())
	if err != nil {
		return StateWaiting, "cannot read the download: " + err.Error(), have, gained
	}
	if !ok {
		// A wrong file of full length cannot be continued; the task would
		// delete it too. Start over after the backoff.
		_ = f.Truncate(0)
		return StateWaiting, "the finished download did not match its digest and was discarded", 0, 0
	}
	return StateComplete, "", have, gained
}

// download asks the server for the rest of the file and appends it. It
// returns the file's size afterwards.
func (p *Prefetcher) download(ctx context.Context, f *os.File, t Target, have int64) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	target := p.opts.Server + RoutePrefix + t.objectPath() + "?node_id=" + url.QueryEscape(p.opts.NodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return have, err
	}
	etag := `"` + t.served() + `"`
	req.Header.Set("Authorization", "Bearer "+p.opts.Token)
	// A range addresses the stored bytes. Naming the encoding keeps any
	// transport from asking for gzip on the wire and decoding it.
	req.Header.Set("Accept-Encoding", "identity")
	if have > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(have, 10)+"-")
		req.Header.Set("If-Range", etag)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return have, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	start := int64(0)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusPartialContent:
		var total int64
		start, total, err = parseContentRange(resp.Header.Get("Content-Range"))
		if err != nil || start != have || total != t.Size {
			return have, fmt.Errorf("the server answered range %q for a download of %d of %d bytes", boundReason(resp.Header.Get("Content-Range"), 80), have, t.Size)
		}
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return have, errRedirect
	default:
		return have, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != etag {
		return have, fmt.Errorf("the server's ETag %q does not name the pinned file", boundReason(got, 80))
	}
	if resp.StatusCode == http.StatusOK && have > 0 {
		// The server sent the whole file instead of the rest.
		if err := f.Truncate(0); err != nil {
			return have, err
		}
		have = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return have, err
	}
	p.progress.Store(start)
	body := &stallReader{r: resp.Body, after: p.opts.StallTimeout}
	body.timer = time.AfterFunc(body.after, func() {
		body.fired.Store(true)
		cancel()
	})
	defer body.timer.Stop()
	w := &progressWriter{f: f, n: start, progress: &p.progress}
	_, err = io.Copy(w, io.LimitReader(body, t.Size-start))
	have = w.n
	if err != nil {
		if body.fired.Load() {
			return have, fmt.Errorf("no bytes for %s; kept %d bytes", body.after, have)
		}
		return have, fmt.Errorf("download cut after %d bytes: %w", have, err)
	}
	if have < t.Size {
		return have, fmt.Errorf("download ended after %d of %d bytes", have, t.Size)
	}
	return have, nil
}

// stallReader re-arms its timer on every read that returns bytes; the timer
// cancels the request when a response delivers nothing for stallTimeout.
type stallReader struct {
	r     io.Reader
	after time.Duration
	timer *time.Timer
	fired atomic.Bool
}

func (s *stallReader) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if n > 0 {
		s.timer.Reset(s.after)
	}
	return n, err
}

// parseContentRange reads "bytes <first>-<last>/<total>".
func parseContentRange(v string) (first, total int64, err error) {
	rest, ok := strings.CutPrefix(v, "bytes ")
	span, size, ok2 := strings.Cut(rest, "/")
	from, _, ok3 := strings.Cut(span, "-")
	if !ok || !ok2 || !ok3 {
		return 0, 0, errors.New("malformed Content-Range")
	}
	if first, err = strconv.ParseInt(from, 10, 64); err != nil {
		return 0, 0, err
	}
	if total, err = strconv.ParseInt(size, 10, 64); err != nil {
		return 0, 0, err
	}
	return first, total, nil
}

type progressWriter struct {
	f        *os.File
	n        int64
	progress *atomic.Int64
}

func (w *progressWriter) Write(b []byte) (int, error) {
	n, err := w.f.Write(b)
	w.n += int64(n)
	w.progress.Store(w.n)
	return n, err
}

// fileMatches hashes the whole file and compares it with the digest.
func fileMatches(f *os.File, digest string) (bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == digest, nil
}

func stampOf(path string) fileStamp {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{path: path, size: fi.Size(), mtime: fi.ModTime()}
}

func (s fileStamp) matches(path string) bool {
	if s.path == "" || s.path != path {
		return false
	}
	now := stampOf(path)
	return now.size == s.size && now.mtime.Equal(s.mtime)
}

// boundReason keeps printable ASCII and cuts to n bytes.
func boundReason(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
