package singboxdiscover

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// alpha8Caps is what lr00rl/sing-box v1.24.3-alpha.8 prints for
// `sb --json caps` on a node with flock (cmd_json_caps in src/core.sh).
const alpha8Caps = `{"ok":true,"script":"v1.24.3-alpha.8","caps":["user-del-by-name","user-park","user-parked-list","user-open-proxy-guard","user-match-counts","user-socks-add","user-lock"]}` + "\n"

// alpha7Caps is what v1.24.3-alpha.7 and older print for the same call: the
// verb falls through to change, which refuses it, and the script exits 1.
const alpha7Caps = `{"ok":false,"error":"error","message":"无法识别 (caps), 获取帮助请使用: sing-box help"}` + "\n"

func capsRunner(t *testing.T, out string, err error) func(context.Context, string, ...string) ([]byte, error) {
	t.Helper()
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "sb" || !reflect.DeepEqual(args, []string{"--json", "caps"}) {
			t.Fatalf("ran %s %v, want sb --json caps", name, args)
		}
		return []byte(out), err
	}
}

func TestCapsParsesAlpha8Answer(t *testing.T) {
	got, err := Caps(context.Background(), Source{runner: capsRunner(t, alpha8Caps, nil)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user-del-by-name", "user-park", "user-parked-list", "user-open-proxy-guard", "user-match-counts", "user-socks-add", "user-lock"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
}

func TestCapsWithoutFlockLeavesOutUserLock(t *testing.T) {
	out := `{"ok":true,"script":"v1.24.3-alpha.8","caps":["user-del-by-name","user-park","user-parked-list","user-open-proxy-guard","user-match-counts","user-socks-add"]}`
	got, err := Caps(context.Background(), Source{runner: capsRunner(t, out, nil)})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range got {
		if name == "user-lock" {
			t.Fatalf("caps = %v, want no user-lock", got)
		}
	}
	if len(got) != 6 {
		t.Fatalf("caps = %v, want six names", got)
	}
}

func TestCapsTrimsDeduplicatesAndSkipsNonStrings(t *testing.T) {
	out := `{"ok":true,"caps":[" user-lock ","user-lock",7,{"x":1},"","user-del-by-name"]}`
	got, err := Caps(context.Background(), Source{runner: capsRunner(t, out, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"user-lock", "user-del-by-name"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
}

func TestCapsRefusesEveryAlpha7Answer(t *testing.T) {
	exit1 := errors.New("exit status 1")
	for _, tc := range []struct {
		name string
		out  string
		err  error
	}{
		{"unknown verb, exit 1", alpha7Caps, exit1},
		{"unknown verb printed with exit 0", alpha7Caps, nil},
		{"human error text", "\n错误! 无法识别 (caps)\n", nil},
		{"empty output", "", nil},
		{"ok without caps", `{"ok":true}`, nil},
		{"caps not a list", `{"ok":true,"caps":"user-lock"}`, nil},
		{"two objects", `{"ok":true,"caps":[]}{"ok":true,"caps":["user-lock"]}`, nil},
		{"binary missing", "", exec.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Caps(context.Background(), Source{runner: capsRunner(t, tc.out, tc.err)})
			if err == nil {
				t.Fatalf("caps = %v, want an error", got)
			}
			if got != nil {
				t.Fatalf("caps = %v alongside error %v", got, err)
			}
		})
	}
}

func TestCapsRefusesAnOversizedList(t *testing.T) {
	out := `{"ok":true,"caps":[`
	for i := 0; i <= maxCapsNames; i++ {
		if i > 0 {
			out += ","
		}
		out += `"user-lock"`
	}
	out += `]}`
	if got, err := Caps(context.Background(), Source{runner: capsRunner(t, out, nil)}); err == nil {
		t.Fatalf("caps = %v, want an error past %d names", got, maxCapsNames)
	}
}

func TestCapsTimesOut(t *testing.T) {
	src := Source{
		Timeout: 20 * time.Millisecond,
		runner: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	start := time.Now()
	got, err := Caps(context.Background(), src)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caps = %v, err = %v, want a deadline error", got, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

// The scripts below run through the production runner, so the exit status
// and the timeout are the real ones, not a fake's.
func TestCapsAgainstRealScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	alpha8 := write("sb-alpha8", "[ \"$1 $2\" = '--json caps' ] || exit 2\ncat <<'EOF'\n"+alpha8Caps+"EOF\n")
	alpha7 := write("sb-alpha7", "cat <<'EOF'\n"+alpha7Caps+"EOF\nexit 1\n")
	hung := write("sb-hung", "exec sleep 30\n")
	// The shell stays the parent and its sleep child keeps stdout open after
	// the shell is killed at the deadline.
	hungChild := write("sb-hung-child", "sleep 30\n")

	got, err := Caps(context.Background(), Source{Binary: alpha8, Timeout: 5 * time.Second})
	if err != nil || len(got) != 7 {
		t.Fatalf("alpha.8 caps = %v, %v", got, err)
	}
	if got, err := Caps(context.Background(), Source{Binary: alpha7, Timeout: 5 * time.Second}); err == nil {
		t.Fatalf("alpha.7 caps = %v, want an error", got)
	}
	for _, script := range []string{hung, hungChild} {
		start := time.Now()
		if got, err := Caps(context.Background(), Source{Binary: script, Timeout: 100 * time.Millisecond}); err == nil {
			t.Fatalf("%s caps = %v, want an error", filepath.Base(script), got)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond+commandWaitDelay+2*time.Second {
			t.Fatalf("%s held the probe for %s", filepath.Base(script), elapsed)
		}
	}
}
