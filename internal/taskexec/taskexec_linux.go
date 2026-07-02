//go:build linux

package taskexec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// shimSentinel is the argv[1] marker that re-routes a freshly exec'd copy of
// the agent binary into the rlimit shim instead of the normal agent. The agent
// runs tasks by re-executing itself as:
//
//	/proc/self/exe <shimSentinel> <cpuSecs> <interp> <scriptPath>
//	/proc/self/exe <shimSentinel> <cpuSecs> <cgroupPath> <interp> <scriptPath>
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

// prSetNoNewPrivs is PR_SET_NO_NEW_PRIVS. The syscall package does not expose
// the prctl option constants; defining the Linux ABI value locally avoids a new
// dependency for one hardening bit.
const prSetNoNewPrivs = 38

// MaybeRunChildShim inspects argv; if it is a re-exec into the rlimit shim, it
// applies rlimits and execs the target interpreter, never returning. Otherwise
// it returns false and normal startup proceeds. main must call this before any
// other work so the sentinel argv is handled.
//
// argv layout: [exe, shimSentinel, cpuSecs, interp, scriptPath] or
// [exe, shimSentinel, cpuSecs, cgroupPath, interp, scriptPath].
func MaybeRunChildShim(argv []string) bool {
	if len(argv) < 2 || argv[1] != shimSentinel {
		return false
	}
	if len(argv) != 5 && len(argv) != 6 {
		fmt.Fprintln(os.Stderr, "taskexec shim: malformed arguments")
		os.Exit(2)
	}
	cpuSecs, err := strconv.ParseUint(argv[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskexec shim: bad cpu seconds: %v\n", err)
		os.Exit(2)
	}
	var cgroupPath string
	interpArg := 3
	if len(argv) == 6 {
		cgroupPath = argv[3]
		interpArg = 4
	}
	interp := argv[interpArg]
	scriptPath := argv[interpArg+1]

	applyResourceLimits(cpuSecs)
	if err := setNoNewPrivileges(); err != nil {
		fmt.Fprintf(os.Stderr, "taskexec shim: set no_new_privs: %v\n", err)
		os.Exit(126)
	}
	if cgroupPath != "" {
		if err := joinTaskCgroup(cgroupPath); err != nil {
			fmt.Fprintf(os.Stderr, "taskexec shim: join cgroup: %v\n", err)
			os.Exit(126)
		}
	}

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
	// others, and the count includes unrelated processes of that uid). Configure
	// cgroup v2 pids.max for a real per-task process/thread cap.
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

func setNoNewPrivileges() error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(prSetNoNewPrivs), 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func prepareTaskCgroup(config CgroupConfig, taskID string) (preparedCgroup, error) {
	config = config.normalized()
	if !config.enabled() {
		return preparedCgroup{}, nil
	}
	root, err := resolveCgroupRoot(config.Root)
	if err != nil {
		return preparedCgroup{}, err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return preparedCgroup{}, fmt.Errorf("prepare task cgroup root %s: %w", root, err)
	}
	if err := ensureCgroupV2Root(root, config); err != nil {
		return preparedCgroup{}, err
	}
	name := "task-" + safeCgroupName(taskID) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	path := filepath.Join(root, name)
	if err := os.Mkdir(path, 0o750); err != nil {
		return preparedCgroup{}, fmt.Errorf("create task cgroup %s: %w", path, err)
	}
	cleanup := func() {
		// cgroup.kill is not available on every cgroup v2 kernel. Use it when
		// present to make cleanup robust, then remove the cgroup best-effort.
		_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o644)
		if err := os.Remove(path); err != nil {
			for _, name := range []string{"memory.max", "pids.max", "cpu.max", "cgroup.procs", "cgroup.kill"} {
				_ = os.Remove(filepath.Join(path, name))
			}
			_ = os.Remove(path)
		}
	}
	if err := configureTaskCgroup(path, config); err != nil {
		cleanup()
		return preparedCgroup{}, err
	}
	return preparedCgroup{path: path, cleanup: cleanup}, nil
}

func resolveCgroupRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("task cgroup root is empty")
	}
	if root != "auto" {
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("task cgroup root must be absolute or \"auto\": %q", root)
		}
		return filepath.Clean(root), nil
	}
	self, err := selfCgroupPath()
	if err != nil {
		return "", err
	}
	rel := strings.TrimPrefix(filepath.Clean(self), string(filepath.Separator))
	return filepath.Join("/sys/fs/cgroup", rel, "lattice-tasks"), nil
}

func selfCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/cgroup: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if path == "" {
				path = "/"
			}
			return path, nil
		}
	}
	return "", fmt.Errorf("cgroup v2 unified hierarchy not found in /proc/self/cgroup")
}

func safeCgroupName(taskID string) string {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range taskID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func ensureCgroupV2Root(root string, config CgroupConfig) error {
	required := requiredCgroupControllers(config)
	controllersPath := filepath.Join(root, "cgroup.controllers")
	data, err := os.ReadFile(controllersPath)
	if err != nil {
		return fmt.Errorf("task cgroup root %s is not a cgroup v2 directory: %w", root, err)
	}
	if len(required) == 0 {
		return nil
	}
	available := map[string]bool{}
	for _, controller := range strings.Fields(string(data)) {
		available[controller] = true
	}
	for _, controller := range required {
		if !available[controller] {
			return fmt.Errorf("task cgroup root %s does not expose %s controller", root, controller)
		}
	}
	subtreePath := filepath.Join(root, "cgroup.subtree_control")
	if _, err := os.Stat(subtreePath); err != nil {
		return fmt.Errorf("task cgroup root %s cannot delegate controllers: %w", root, err)
	}
	var enable []string
	for _, controller := range required {
		enable = append(enable, "+"+controller)
	}
	if err := os.WriteFile(subtreePath, []byte(strings.Join(enable, " ")), 0o644); err != nil {
		return fmt.Errorf("enable task cgroup controllers %s: %w", strings.Join(enable, " "), err)
	}
	return nil
}

func requiredCgroupControllers(config CgroupConfig) []string {
	config = config.normalized()
	var controllers []string
	if config.CPUMax != "" && config.CPUMax != "max" {
		controllers = append(controllers, "cpu")
	}
	if config.MemoryMax != "" && config.MemoryMax != "max" {
		controllers = append(controllers, "memory")
	}
	if config.PidsMax != "" && config.PidsMax != "max" {
		controllers = append(controllers, "pids")
	}
	return controllers
}

func configureTaskCgroup(path string, config CgroupConfig) error {
	if err := writeCgroupControl(path, "memory.max", config.MemoryMax); err != nil {
		return err
	}
	if err := writeCgroupControl(path, "pids.max", config.PidsMax); err != nil {
		return err
	}
	if err := writeCgroupControl(path, "cpu.max", config.CPUMax); err != nil {
		return err
	}
	return nil
}

func writeCgroupControl(path, file, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(path, file), []byte(value), 0o644); err != nil {
		return fmt.Errorf("write task cgroup %s=%q: %w", file, value, err)
	}
	return nil
}

func joinTaskCgroup(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644)
}

// buildHardenedCmd constructs the task command on Linux. It re-execs the agent
// binary into the rlimit shim (which then execs the interpreter) and places the
// child in its own process group so the whole tree can be killed on timeout.
func buildHardenedCmd(interp, scriptPath string, timeout time.Duration, cgroupPath string) *exec.Cmd {
	cpuSecs := uint64(timeout/time.Second) + cpuGraceSeconds
	if cpuSecs < cpuGraceSeconds {
		cpuSecs = cpuGraceSeconds
	}
	self := selfExe()
	args := []string{shimSentinel, strconv.FormatUint(cpuSecs, 10)}
	if cgroupPath != "" {
		args = append(args, cgroupPath)
	}
	args = append(args, interp, scriptPath)
	cmd := exec.Command(self, args...)
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
