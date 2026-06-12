package taskexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// nonRootUID injects a non-root effective uid so tests that genuinely execute
// tasks are not blocked by the root-refusal guard. CI and container test
// environments frequently run as uid 0, which would otherwise trip the guard.
func nonRootUID() int { return 1000 }

// TestMain lets the compiled test binary act as the rlimit shim when it is
// re-executed with the sentinel argv. The Runner re-execs /proc/self/exe to
// apply rlimits before running the interpreter; under `go test` that path is
// the test binary, so it must honor the sentinel exactly like the agent's main
// does. Without this, a re-exec would rerun the whole test suite.
func TestMain(m *testing.M) {
	if MaybeRunChildShim(os.Args) {
		return
	}
	os.Exit(m.Run())
}

func TestRunnerRequiresExplicitExecEnable(t *testing.T) {
	r := Runner{}
	result := r.Run(model.Task{ID: "task_1", Interpreter: "sh", Script: "echo no"})
	if result.Error == "" || result.ExitCode != -1 {
		t.Fatalf("expected disabled execution error, got %#v", result)
	}
}

func TestRunnerCapsOutput(t *testing.T) {
	r := Runner{AllowExec: true, getUID: nonRootUID}
	result := r.Run(model.Task{
		ID:          "task_1",
		Interpreter: "sh",
		Script:      "printf 'abcdef'",
		TimeoutSec:  5,
		OutputLimit: 3,
	})
	if result.ExitCode != 0 {
		t.Fatalf("expected success, got %#v", result)
	}
	if result.Stdout != "abc" {
		t.Fatalf("expected capped stdout, got %q", result.Stdout)
	}
}

func TestRunnerPropagatesLeaseID(t *testing.T) {
	r := Runner{AllowExec: true, getUID: nonRootUID}
	result := r.Run(model.Task{
		ID:          "task_1",
		LeaseID:     "lease_abc",
		Interpreter: "sh",
		Script:      "printf \"$LATTICE_TASK_LEASE_ID\"",
		TimeoutSec:  5,
		OutputLimit: 64,
	})
	if result.LeaseID != "lease_abc" {
		t.Fatalf("expected lease id in result, got %q", result.LeaseID)
	}
	if result.Stdout != "lease_abc" {
		t.Fatalf("expected lease id in task env, got %q", result.Stdout)
	}
}

func TestRunnerRejectsUnknownInterpreter(t *testing.T) {
	r := Runner{AllowExec: true, getUID: nonRootUID}
	result := r.Run(model.Task{ID: "task_1", Interpreter: "perl", Script: "print 1"})
	if !strings.Contains(result.Error, "allowlisted") {
		t.Fatalf("expected allowlist error, got %#v", result)
	}
}

// TestRunnerGuards covers the security gates that must each return a clean
// TaskResult (non-zero exit, populated Error, no panic) rather than executing.
func TestRunnerGuards(t *testing.T) {
	asRoot := func() int { return 0 }
	asUser := func() int { return 1000 }

	tests := []struct {
		name      string
		runner    Runner
		task      model.Task
		wantErrIn string
	}{
		{
			name:      "kill switch refuses",
			runner:    Runner{AllowExec: false},
			task:      model.Task{ID: "t", Interpreter: "sh", Script: "echo hi"},
			wantErrIn: "disabled",
		},
		{
			name:      "root without opt-in refuses",
			runner:    Runner{AllowExec: true, getUID: asRoot},
			task:      model.Task{ID: "t", Interpreter: "sh", Script: "echo hi", TimeoutSec: 5},
			wantErrIn: "root",
		},
		{
			name:      "unknown interpreter refuses",
			runner:    Runner{AllowExec: true, getUID: asUser},
			task:      model.Task{ID: "t", Interpreter: "perl", Script: "print 1"},
			wantErrIn: "allowlisted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.runner.Run(tc.task)
			if result.ExitCode != -1 {
				t.Fatalf("expected exit -1, got %#v", result)
			}
			if !strings.Contains(result.Error, tc.wantErrIn) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErrIn, result.Error)
			}
			if result.TaskID != tc.task.ID {
				t.Fatalf("expected task id %q echoed back, got %q", tc.task.ID, result.TaskID)
			}
			if result.FinishedAt.IsZero() {
				t.Fatalf("expected FinishedAt to be set, got zero")
			}
		})
	}
}

// TestRunnerRootOptInExecutes confirms that with AllowRoot the simulated-root
// path proceeds to actually run the task instead of refusing.
func TestRunnerRootOptInExecutes(t *testing.T) {
	r := Runner{AllowExec: true, AllowRoot: true, getUID: func() int { return 0 }}
	result := r.Run(model.Task{
		ID:          "t",
		Interpreter: "sh",
		Script:      "printf ok",
		TimeoutSec:  5,
		OutputLimit: 64,
	})
	if result.ExitCode != 0 {
		t.Fatalf("expected success under AllowRoot, got %#v", result)
	}
	if result.Stdout != "ok" {
		t.Fatalf("expected stdout ok, got %q", result.Stdout)
	}
}

// TestRunnerTimeoutKillsProcessGroup verifies that a task which spawns a
// background grandchild is fully reaped after the task times out: the
// grandchild must not outlive the task. Linux-only because it relies on the
// process-group kill + rlimit shim path; on other platforms the cleanup
// guarantees differ and we skip.
func TestRunnerTimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("process-group reaping is asserted on linux only (GOOS=%s)", runtime.GOOS)
	}

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")

	// Spawn a long-lived background process that records its pid, then block so
	// the task exceeds its timeout. If the group is killed, the background
	// process (a grandchild relative to the agent) dies too.
	script := "sleep 300 & echo $! > " + pidFile + "\nsleep 300\n"

	r := Runner{AllowExec: true, getUID: func() int { return 1000 }}
	start := time.Now()
	result := r.Run(model.Task{
		ID:          "timeout_task",
		Interpreter: "sh",
		Script:      script,
		TimeoutSec:  1,
		OutputLimit: 64,
	})
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("run took too long (%s); timeout not enforced", elapsed)
	}
	if result.ExitCode != -1 || !strings.Contains(result.Error, "deadline") {
		t.Fatalf("expected deadline-exceeded result, got %#v", result)
	}

	pid := readPID(t, pidFile)

	// Poll briefly for the grandchild to be reaped by the process-group kill.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !processAlive(pid) {
			return // success: grandchild reaped
		}
		if time.Now().After(deadline) {
			// Clean up the stray so we don't leak it out of the test run.
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild pid %d still alive after timeout; process group not killed", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" {
				pid, perr := strconv.Atoi(s)
				if perr != nil {
					t.Fatalf("bad pid %q: %v", s, perr)
				}
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild never recorded its pid at %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// processAlive reports whether a process with the given pid currently exists.
// signal 0 performs error checking without actually sending a signal.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	// ESRCH: no such process. EPERM: exists but not ours (still "alive").
	return err == syscall.EPERM
}
