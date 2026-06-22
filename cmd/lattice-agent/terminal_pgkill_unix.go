//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// terminalSetPGID makes cmd start in its own process group so the whole subtree
// can later be signalled with Kill(-pgid).
func terminalSetPGID(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminalKillProcessGroup SIGKILLs the shell's entire process group and reaps
// it. When the pgid cannot be resolved to a safe positive value it falls back to
// killing the single process — it must NEVER issue Kill(-0), which would signal
// the agent's own process group and take the agent down.
func terminalKillProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if pgid := resolveGroupKillPgid(cmd.Process.Pid); pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	} else {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

// resolveGroupKillPgid returns a pgid safe for Kill(-pgid), or 0 ("do not group
// kill") when Getpgid fails or returns a non-positive value. The 0 guard is the
// load-bearing safety contract: Kill(-0, SIGKILL) would hit the caller's own
// process group and kill the agent.
func resolveGroupKillPgid(pid int) int {
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid <= 0 {
		return 0
	}
	return pgid
}
