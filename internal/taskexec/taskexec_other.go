//go:build !linux

package taskexec

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// MaybeRunChildShim is a no-op on non-Linux platforms: the rlimit shim is only
// used on Linux. It always returns false so normal startup proceeds. It exists
// so main can call it unconditionally regardless of platform.
func MaybeRunChildShim(argv []string) bool { return false }

func prepareTaskCgroup(config CgroupConfig, _ string) (preparedCgroup, error) {
	if config.enabled() {
		return preparedCgroup{}, fmt.Errorf("task cgroups are only supported on Linux")
	}
	return preparedCgroup{}, nil
}

// buildHardenedCmd builds the task command on non-Linux platforms (dev/macOS).
// There is no rlimit shim here, but we still place the child in its own process
// group (supported on Unix-like systems) so killProcessGroup can reap the whole
// tree on timeout. Resource rlimits are deliberately not applied off Linux;
// this path is for development and is documented as such.
func buildHardenedCmd(interp, scriptPath string, _ time.Duration, _ string) *exec.Cmd {
	cmd := exec.Command(interp, scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	return cmd
}

// killProcessGroup sends SIGKILL to the child's process group (negative pid) so
// descendants are reaped too. On platforms without process-group semantics this
// falls back to killing the direct process.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
