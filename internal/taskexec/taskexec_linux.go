//go:build linux

package taskexec

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// shimSentinel is the argv[1] marker that re-routes a freshly exec'd copy of
// the agent binary into the rlimit shim instead of the normal agent. The agent
// runs tasks by re-executing itself as:
//
//	/proc/self/exe <shimSentinel> <cpuSecs> <interp> <scriptPath>
//
// The shim sets resource rlimits on itself (which are inherited across the
// following exec and into any descendants) and then execs the real interpreter.
// This is the portable, race-free way to apply rlimits to a child in Go: the
// standard library's SysProcAttr cannot set rlimits, and setting them in the
// parent would also constrain the agent itself.
const shimSentinel = "__lattice_taskexec_rlimit_shim__"

// rlimitNProc is RLIMIT_NPROC. The standard library's syscall package does not
// export it (only golang.org/x/sys/unix does), but its value is 6 across every
// Linux architecture (generic ABI). Defined locally to avoid adding an external
// dependency just for one constant.
const rlimitNProc = 0x6

// MaybeRunChildShim inspects argv; if it is a re-exec into the rlimit shim, it
// applies rlimits and execs the target interpreter, never returning. Otherwise
// it returns false and normal startup proceeds. main must call this before any
// other work so the sentinel argv is handled.
//
// argv layout: [exe, shimSentinel, cpuSecs, interp, scriptPath].
func MaybeRunChildShim(argv []string) bool {
	if len(argv) < 2 || argv[1] != shimSentinel {
		return false
	}
	if len(argv) != 5 {
		fmt.Fprintln(os.Stderr, "taskexec shim: malformed arguments")
		os.Exit(2)
	}
	cpuSecs, err := strconv.ParseUint(argv[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskexec shim: bad cpu seconds: %v\n", err)
		os.Exit(2)
	}
	interp := argv[3]
	scriptPath := argv[4]

	applyResourceLimits(cpuSecs)

	// Exec replaces this shim process with the interpreter, preserving the
	// process group (set by Setpgid on the parent command) and the rlimits
	// just installed. The environment is already the sandbox env set by the
	// parent on the shim command.
	if err := syscall.Exec(interp, []string{interp, scriptPath}, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "taskexec shim: exec %s: %v\n", interp, err)
		os.Exit(126)
	}
	return true // unreachable
}

// applyResourceLimits installs the task rlimits on the current (shim) process.
// They are inherited across the subsequent exec and by any child processes.
func applyResourceLimits(cpuSecs uint64) {
	setRlimit(syscall.RLIMIT_CPU, cpuSecs, cpuSecs+1)
	setRlimit(syscall.RLIMIT_FSIZE, maxFileSizeBytes, maxFileSizeBytes)
	// RLIMIT_NPROC on Linux limits the number of processes/threads for the
	// process's REAL UID across the WHOLE SYSTEM, not per-task. The cap is
	// therefore shared with the agent's own threads and every other concurrent
	// task running under the same uid, so it blunts fork bombs but does not give
	// true per-task isolation (one task can consume the budget and starve
	// others, and the count includes unrelated processes of that uid). Real
	// per-task process isolation requires a PID namespace plus a cgroup
	// pids.max scoped to the task — a deferred improvement, not implemented here.
	nproc := nprocLimit()
	setRlimit(rlimitNProc, nproc, nproc)
	// RLIMIT_AS is a coarse virtual-space backstop only (see maxAddressSpaceBytes);
	// RLIMIT_DATA below is the meaningful data-segment memory guard.
	setRlimit(syscall.RLIMIT_AS, maxAddressSpaceBytes, maxAddressSpaceBytes)
	setRlimit(syscall.RLIMIT_DATA, maxDataBytes, maxDataBytes)
}

func nprocLimit() uint64 {
	current, err := currentUIDThreadCount()
	if err != nil || current == 0 {
		return maxProcessHeadroom
	}
	if current > ^uint64(0)-maxProcessHeadroom {
		return ^uint64(0)
	}
	return current + maxProcessHeadroom
}

func currentUIDThreadCount() (uint64, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	uid := uint32(os.Getuid())
	var count uint64
	for _, entry := range entries {
		if !entry.IsDir() || !isProcPID(entry.Name()) {
			continue
		}
		procPath := "/proc/" + entry.Name()
		info, err := os.Stat(procPath)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uid {
			continue
		}
		tasks, err := os.ReadDir(procPath + "/task")
		if err != nil {
			count++
			continue
		}
		count += uint64(len(tasks))
	}
	return count, nil
}

func isProcPID(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func setRlimit(resource int, cur, max uint64) {
	// Best effort: if the kernel rejects a limit (e.g. NPROC for an
	// unprivileged user already at the cap), keep going rather than abort the
	// task. The other limits still apply.
	_ = syscall.Setrlimit(resource, &syscall.Rlimit{Cur: cur, Max: max})
}

// buildHardenedCmd constructs the task command on Linux. It re-execs the agent
// binary into the rlimit shim (which then execs the interpreter) and places the
// child in its own process group so the whole tree can be killed on timeout.
func buildHardenedCmd(interp, scriptPath string, timeout time.Duration) *exec.Cmd {
	cpuSecs := uint64(timeout/time.Second) + cpuGraceSeconds
	if cpuSecs < cpuGraceSeconds {
		cpuSecs = cpuGraceSeconds
	}
	self := selfExe()
	cmd := exec.Command(self, shimSentinel, strconv.FormatUint(cpuSecs, 10), interp, scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	return cmd
}

// selfExe resolves the path to the running agent binary for re-exec. It prefers
// /proc/self/exe (always correct even if argv[0] is relative or the binary was
// moved) and falls back to os.Executable.
func selfExe() string {
	if _, err := os.Stat("/proc/self/exe"); err == nil {
		return "/proc/self/exe"
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return os.Args[0]
}

// killProcessGroup sends SIGKILL to the whole process group led by the task's
// pid (negative pid). This reaps grandchildren the script forked, so nothing
// outlives the task on timeout/cancel.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// Negative pid targets the entire group. Ignore the error: the group may
	// already be gone.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
