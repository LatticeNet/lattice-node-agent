package taskexec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

var allowedInterpreters = map[string]string{
	"sh":      "/bin/sh",
	"bash":    "/bin/bash",
	"python3": "python3",
	"node":    "node",
}

// Resource-limit caps applied to child task processes on Linux (see
// taskexec_linux.go). They bound a misbehaving or hostile script so a single
// task cannot exhaust the node. On non-Linux platforms these are advisory only
// because applyResourceLimits is a no-op there.
const (
	// maxFileSizeBytes caps the size of any single file the task may write,
	// preventing a runaway script from filling the disk.
	maxFileSizeBytes = 8 * 1024 * 1024 // 8 MiB
	// maxProcessHeadroom is the extra number of processes/threads a task may
	// add above the agent user's current Linux-wide usage. RLIMIT_NPROC is
	// scoped to the real UID rather than the task process tree, so using a fixed
	// absolute cap can prevent the interpreter from forking at all on busy CI or
	// shared hosts.
	maxProcessHeadroom = 64
	// maxAddressSpaceBytes caps total VIRTUAL address space (RLIMIT_AS). This is
	// a coarse backstop, NOT a resident-memory limit: RLIMIT_AS counts every
	// mmap'd region (including large PROT_NONE reservations the runtime never
	// touches). Modern runtimes reserve multiple GiB of virtual space up front —
	// V8 (node) and current glibc/python3 in particular — so a tight cap here
	// causes spurious mmap/ENOMEM failures rather than bounding real memory use.
	// We therefore set it high enough not to break the allowlisted interpreters
	// while still catching pathological virtual-space blowups, and rely on
	// RLIMIT_DATA (below) as the meaningful data-segment guard. The real
	// resident-memory guard is a cgroup v2 memory.max on the task's process,
	// which is a deferred improvement (not implemented here).
	maxAddressSpaceBytes = 8 * 1024 * 1024 * 1024 // 8 GiB (virtual-space backstop only)
	// maxDataBytes caps the data segment (RLIMIT_DATA). This is the meaningful
	// per-task memory guard: unlike RLIMIT_AS it bounds the heap/brk and
	// anonymous mappings that actually back allocations, without tripping on the
	// large virtual reservations interpreters make at startup.
	maxDataBytes = 512 * 1024 * 1024 // 512 MiB
	// cpuGraceSeconds is added to the wall-clock timeout when deriving the
	// CPU-seconds rlimit, so a CPU-bound task is killed by SIGXCPU shortly
	// after the context deadline rather than long before it.
	cpuGraceSeconds = 5
)

// MissingInterpreters returns the sorted list of allowlisted interpreter names
// that cannot currently be resolved on PATH. It performs the same exec.LookPath
// resolution used at task time, but as a one-shot startup probe so operators
// learn early which interpreters are absent. It does not change task-time
// behavior: interpreters are still resolved per task, so an interpreter
// installed after startup will work, and one removed after startup will fail at
// task time regardless of this probe.
func MissingInterpreters() []string {
	var missing []string
	for name, target := range allowedInterpreters {
		if _, err := exec.LookPath(target); err != nil {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// Runner executes allow-listed operator tasks in a bounded, hardened sandbox.
type Runner struct {
	// AllowExec gates execution entirely. When false, every task is refused
	// with a clear error result (the kill switch).
	AllowExec bool
	// AllowRoot opts in to running tasks while the agent itself is uid 0.
	// Without it, a root agent refuses to execute arbitrary operator scripts,
	// since that would run them with full host privileges. Operators that
	// genuinely need root (nft/wg manipulation) set this explicitly.
	AllowRoot bool
	// getUID returns the effective uid of the agent process. It is a field so
	// tests can simulate "running as root" without actually being root. When
	// nil it defaults to os.Geteuid.
	getUID func() int
}

// SandboxReport describes the runtime isolation level operators should see for
// this agent. It is an observability contract only; Runner remains the
// authoritative execution gate.
type SandboxReport struct {
	Level    string   `json:"task_sandbox"`
	Features []string `json:"task_sandbox_features,omitempty"`
	Warning  string   `json:"task_sandbox_warning,omitempty"`
}

// SandboxProfile summarizes the task-execution hardening that will apply if a
// task is leased to this agent under the current flags and OS.
func SandboxProfile(allowExec, allowRoot bool, effectiveUID int) SandboxReport {
	if !allowExec {
		return SandboxReport{
			Level:    "disabled",
			Features: []string{"exec-kill-switch"},
		}
	}
	if effectiveUID == 0 && !allowRoot {
		return SandboxReport{
			Level:    "root-refused",
			Features: []string{"root-exec-guard"},
			Warning:  "agent runs as root but task execution is refused until -allow-root-exec is set",
		}
	}

	features := []string{
		"interpreter-allowlist",
		"minimal-env",
		"output-cap",
		"temp-workdir",
		"timeout",
	}
	report := SandboxReport{Features: features}
	if runtime.GOOS == "linux" {
		report.Level = "linux-rlimit-process-group"
		report.Features = append(report.Features,
			"process-group-kill",
			"rlimit-as",
			"rlimit-cpu",
			"rlimit-data",
			"rlimit-fsize",
			"rlimit-nproc",
		)
	} else {
		report.Level = "basic"
		report.Warning = "non-linux task execution lacks Linux rlimit/process-group hardening"
	}
	sort.Strings(report.Features)
	if effectiveUID == 0 && allowRoot {
		if report.Warning == "" {
			report.Warning = "task scripts run as root"
		} else {
			report.Warning += "; task scripts run as root"
		}
	}
	return report
}

func (r Runner) effectiveUID() int {
	if r.getUID != nil {
		return r.getUID()
	}
	return os.Geteuid()
}

func (r Runner) Run(task model.Task) model.TaskResult {
	start := time.Now().UTC()
	result := model.TaskResult{
		TaskID:    task.ID,
		LeaseID:   task.LeaseID,
		StartedAt: start,
	}
	if !r.AllowExec {
		result.ExitCode = -1
		result.Error = "agent task execution disabled; restart with -allow-exec=true to enable"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	// Refuse to run arbitrary operator scripts as root unless explicitly
	// opted in. We deliberately do NOT drop privileges by switching uid
	// mid-process (unsafe and racy in Go); refusing is the testable,
	// predictable safe default.
	if r.effectiveUID() == 0 && !r.AllowRoot {
		result.ExitCode = -1
		result.Error = "refusing to execute task as root; restart with -allow-root-exec=true to opt in"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	interp, ok := allowedInterpreters[task.Interpreter]
	if !ok {
		result.ExitCode = -1
		result.Error = "interpreter is not allowlisted"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	// Resolve to an absolute path. On Linux the rlimit shim execs the
	// interpreter via syscall.Exec, which (unlike exec.Command) does NOT search
	// PATH, so a bare name like "sh" would fail with ENOENT.
	interpPath, err := exec.LookPath(interp)
	if err != nil {
		result.ExitCode = -1
		result.Error = "interpreter not found: " + interp
		result.FinishedAt = time.Now().UTC()
		return result
	}
	interp = interpPath
	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 30 * time.Second
	}
	limit := task.OutputLimit
	if limit <= 0 || limit > 256*1024 {
		limit = 64 * 1024
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "lattice-task-*")
	if err != nil {
		result.ExitCode = -1
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	defer os.RemoveAll(dir)

	scriptPath := filepath.Join(dir, "script")
	// 0600: readable/writable only by the agent user; the interpreter reads it
	// by path so it need not be executable.
	if err := os.WriteFile(scriptPath, []byte(task.Script), 0o600); err != nil {
		result.ExitCode = -1
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	// We manage process lifetime ourselves (process-group kill on timeout)
	// rather than letting exec.CommandContext SIGKILL only the direct child,
	// which would orphan grandchildren. ctx is still used to detect deadline.
	//
	// buildHardenedCmd constructs the command with platform isolation. On Linux
	// it routes the interpreter through a self-exec shim that applies rlimits
	// (inherited across exec into the whole tree) and puts the child in its own
	// process group. On other platforms it is a plain exec of the interpreter.
	cmd := buildHardenedCmd(interp, scriptPath, timeout)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=" + dir, "LATTICE_TASK_ID=" + task.ID, "LATTICE_TASK_LEASE_ID=" + task.LeaseID}

	var stdout, stderr cappedBuffer
	stdout.limit = limit
	stderr.limit = limit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
		result.ExitCode = -1
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	// Wait in a goroutine so we can race the context deadline. On timeout we
	// kill the entire process group, reaping child-spawned descendants too.
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	var timedOut bool
	select {
	case <-ctx.Done():
		timedOut = true
		killProcessGroup(cmd)
		<-waitErr // ensure the process is reaped and Wait returns
	case err = <-waitErr:
	}

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	if timedOut {
		result.ExitCode = -1
		result.Error = ctx.Err().Error()
	} else {
		result.ExitCode = exitCode(err)
		if err != nil {
			result.Error = err.Error()
		}
	}
	if truncated := outputTruncationError(stdout, stderr); truncated != "" {
		if result.Error != "" {
			result.Error += "; " + truncated
		} else {
			result.Error = truncated
		}
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}

func outputTruncationError(stdout, stderr cappedBuffer) string {
	var streams []string
	if stdout.truncated {
		streams = append(streams, "stdout")
	}
	if stderr.truncated {
		streams = append(streams, "stderr")
	}
	if len(streams) == 0 {
		return ""
	}
	return strings.Join(streams, " and ") + " exceeded task output limit; output truncated"
}
