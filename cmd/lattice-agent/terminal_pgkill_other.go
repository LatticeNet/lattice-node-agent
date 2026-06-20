//go:build !unix

package main

import "os/exec"

// terminalSetPGID is a no-op on platforms without POSIX process groups.
func terminalSetPGID(cmd *exec.Cmd) {}

// terminalKillProcessGroup kills the single shell process and reaps it; process
// groups are unavailable on this platform.
func terminalKillProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
