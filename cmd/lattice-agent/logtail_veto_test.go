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
		"singbox://legend-sg":                              "outside its log allowlist",
		"singbox://../../etc/shadow":                       "outside its log allowlist",
		"agent-debug://node-a":                             "outside its log allowlist",
		"unknown://x":                                      "outside its log allowlist",
		"relative.log":                                     "outside its log allowlist",
		outside:                                            "outside its log allowlist",
		filepath.Join(dir, "..", "secret"):                 "outside its log allowlist",
		filepath.Join(dir, "link.log"):                     "outside its log allowlist",
		filepath.Join(dir, "sub.log"):                      "not a regular file",
		filepath.Join(dir, "fifo.log"):                     "not a regular file",
		filepath.Join(dir, "app.log") + "\x00x":            "outside its log allowlist",
		"/var/log/../../etc/shadow":                        "outside its log allowlist",
		filepath.Join(dir, "nested", "..", "..", "secret"): "outside its log allowlist",
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
	tl := newSourceTailer(model.LogSource{ID: "logsrc_a", Path: small}, ckpt, p)
	defer tl.Close()
	lines, err := tl.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("retargeted source shipped %q from the new file's existing content", lines)
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
	if err == nil || !strings.Contains(err.Error(), "refused by the node: outside its log allowlist") ||
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
