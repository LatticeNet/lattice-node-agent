package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// outsideAllowlist is the sentence an operator reads on the node's loop
// health: what was refused, and the one setting that would let it through.
const outsideAllowlist = "outside this node's log allowlist; widen it with LATTICE_LOG_PATH_ALLOW on the node"

// The node tails only files under its own allowlist: /var/log/ unless the
// node's configuration (-log-path-allow, LATTICE_LOG_PATH_ALLOW) widens it.
// Nothing the server sends can widen it.
func TestLogPathAllowlistDefaultsAndWidening(t *testing.T) {
	if p := newLogPathPolicy(""); !slices.Contains(p.allow, "/var/log/") {
		t.Fatalf("default allowlist %q lacks /var/log/", p.allow)
	}
	p := newLogPathPolicy(" /opt/app/logs , relative/dir, /srv/x/ ,")
	for _, want := range []string{"/var/log/", "/opt/app/logs/", "/srv/x/"} {
		if !slices.Contains(p.allow, want) {
			t.Errorf("allowlist %q lacks %q", p.allow, want)
		}
	}
	for _, prefix := range p.allow {
		if !strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") {
			t.Errorf("allowlist entry %q is not an absolute directory prefix", prefix)
		}
	}
}

// allowedDir is a temp directory the policy allows, with one regular log in
// it, and outside is a file beside it that the policy does not allow.
func allowedDir(t *testing.T) (p logPathPolicy, dir, outside string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "logs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside = filepath.Join(root, "secret")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.log"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return newLogPathPolicy(dir), dir, outside
}

// Every refusal says what the node refused and why, in words the operator
// sees on the node's loop health.
func TestLogPathPolicyRefusesWhatItCannotVouchFor(t *testing.T) {
	p, dir, outside := allowedDir(t)
	if err := os.Symlink(outside, filepath.Join(dir, "link.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.log"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := p.check(filepath.Join(dir, "app.log")); err != nil {
		t.Fatalf("a regular log in the allowlist was refused: %v", err)
	}
	if err := p.check(filepath.Join(dir, "not-yet.log")); err != nil {
		t.Fatalf("a log that does not exist yet is judged when it appears, not refused: %v", err)
	}
	for path, reason := range map[string]string{
		"singbox://legend-sg":                              outsideAllowlist,
		"singbox://../../etc/shadow":                       outsideAllowlist,
		"agent-debug://node-a":                             outsideAllowlist,
		"unknown://x":                                      outsideAllowlist,
		"relative.log":                                     outsideAllowlist,
		outside:                                            outsideAllowlist,
		filepath.Join(dir, "..", "secret"):                 outsideAllowlist,
		filepath.Join(dir, "link.log"):                     outsideAllowlist,
		filepath.Join(dir, "sub.log"):                      "not a regular file",
		filepath.Join(dir, "fifo.log"):                     "not a regular file",
		filepath.Join(dir, "app.log") + "\x00x":            outsideAllowlist,
		"/var/log/../../etc/shadow":                        outsideAllowlist,
		filepath.Join(dir, "nested", "..", "..", "secret"): outsideAllowlist,
	} {
		err := p.check(path)
		if !errors.Is(err, errLogPathRefused) || !strings.Contains(err.Error(), reason) {
			t.Errorf("check(%q) = %v, want a refusal saying %q", path, err, reason)
		}
	}
}

// The check runs again on every open, so a log rotated into a symlink that
// leaves the allowlist is refused at the reopen, and nothing of the file it
// points at is read.
func TestLogTailerRefusesARotationOutOfTheAllowlist(t *testing.T) {
	p, dir, outside := allowedDir(t)
	path := filepath.Join(dir, "app.log")
	tl := newSourceTailer(model.LogSource{ID: "logsrc_a", Path: path}, "", p)
	defer tl.Close()
	var got []string
	poll := func() error {
		lines, err := tl.Poll()
		got = append(got, lines...)
		return err
	}
	if err := poll(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("b\n")
	_ = f.Close()
	if err := poll(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	var refused error
	for i := 0; i < 3 && refused == nil; i++ {
		if err := poll(); err != nil {
			refused = err
		}
	}
	if !errors.Is(refused, errLogPathRefused) {
		t.Fatalf("reopen after rotation into a symlink: %v, want a refusal", refused)
	}
	if !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("shipped %q, want only the line written inside the allowlist", got)
	}
}

// A source retargeted to another file under the same id starts at the end of
// the new file, never at 0, so retargeting cannot ship a file's contents.
func TestRetargetedLogSourceStartsAtTheEnd(t *testing.T) {
	p, dir, _ := allowedDir(t)
	big := filepath.Join(dir, "big.log")
	if err := os.WriteFile(big, []byte(strings.Repeat("x\n", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	ckpt := filepath.Join(t.TempDir(), "logsrc_a.ckpt")
	saveLogCheckpoint(ckpt, big, 8192, 0)

	small := filepath.Join(dir, "app.log") // holds "a\n", shorter than the old offset
	for name, write := range map[string]func(){
		"bound to the old file": func() { saveLogCheckpoint(ckpt, big, 8192, 0) },
		// An older agent's checkpoint names no file at all.
		"written by an older agent": func() {
			if err := os.WriteFile(ckpt, []byte("8192:0"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		write()
		tl := newSourceTailer(model.LogSource{ID: "logsrc_a", Path: small}, ckpt, p)
		lines, err := tl.Poll()
		tl.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 0 {
			t.Fatalf("checkpoint %s: retargeted source shipped %q from the new file's existing content", name, lines)
		}
	}
}

// A refused source is not tailed, and the refusal is the log_sources step's
// error, which the heartbeat carries to the server as loop health.
func TestRefusedLogSourceIsReportedAndNotTailed(t *testing.T) {
	_, dir, outside := allowedDir(t)
	m := newLogTailManager(agentConfig{LogPathAllow: dir})
	defer m.reconcile(nil)
	m.reconcile([]model.LogSource{
		{ID: "logsrc_ok", Path: filepath.Join(dir, "app.log")},
		{ID: "logsrc_bad", Path: outside},
	})
	err := m.refusals()
	if err == nil || !strings.Contains(err.Error(), "refused by the node: "+outsideAllowlist) ||
		!strings.Contains(err.Error(), "logsrc_bad") || strings.Contains(err.Error(), "logsrc_ok") {
		t.Fatalf("refusals() = %v, want only logsrc_bad named as refused", err)
	}
	m.mu.Lock()
	_, okActive := m.active["logsrc_ok"]
	_, badActive := m.active["logsrc_bad"]
	m.mu.Unlock()
	if !okActive || badActive {
		t.Fatalf("active sources: ok=%t bad=%t, want only the allowed one tailed", okActive, badActive)
	}
	m.reconcile([]model.LogSource{{ID: "logsrc_ok", Path: filepath.Join(dir, "app.log")}})
	if err := m.refusals(); err != nil {
		t.Fatalf("refusals() after the refused source went away = %v, want nil", err)
	}
}

// -no-log-tail (LATTICE_NO_LOG_TAIL) is the node's kill switch: it tails no
// source at all, whatever the server assigns, and says so for each one.
func TestNoLogTailRefusesEverySource(t *testing.T) {
	_, dir, _ := allowedDir(t)
	m := newLogTailManager(agentConfig{NoLogTail: true, LogPathAllow: dir})
	defer m.reconcile(nil)
	m.reconcile([]model.LogSource{{ID: "logsrc_ok", Path: filepath.Join(dir, "app.log")}})
	m.mu.Lock()
	_, active := m.active["logsrc_ok"]
	m.mu.Unlock()
	if active {
		t.Fatal("a source was tailed under -no-log-tail")
	}
	err := m.refusals()
	if err == nil || !strings.Contains(err.Error(), "log tailing is turned off on this node") || !strings.Contains(err.Error(), "logsrc_ok") {
		t.Fatalf("refusals() = %v, want logsrc_ok refused because tailing is off", err)
	}
}

// Several refusals keep each actionable sentence in front of the sources it
// covers, so the 200-rune loop health still says what to do.
func TestLogRefusalsGroupByReason(t *testing.T) {
	p, dir, outside := allowedDir(t)
	if err := os.Mkdir(filepath.Join(dir, "sub.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := newLogTailManager(agentConfig{LogPathAllow: dir})
	_ = p
	defer m.reconcile(nil)
	m.reconcile([]model.LogSource{
		{ID: "logsrc_b", Path: outside},
		{ID: "logsrc_a", Path: "/etc/shadow"},
		{ID: "logsrc_c", Path: filepath.Join(dir, "sub.log")},
	})
	err := m.refusals()
	if err == nil {
		t.Fatal("no refusals reported")
	}
	got := err.Error()
	if !strings.HasPrefix(got, "refused by the node: "+outsideAllowlist+`: "logsrc_a" `) {
		t.Fatalf("refusals() = %q, want the allowlist sentence first, then its sources by id", got)
	}
	if !strings.Contains(got, `"logsrc_b"`) || !strings.Contains(got, `not a regular file: "logsrc_c"`) {
		t.Fatalf("refusals() = %q, want every refused source under its reason", got)
	}
}
