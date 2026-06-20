//go:build unix

package main

import (
	"os/exec"
	"syscall"
	"testing"
)

// Regression for the Kill(-0) footgun: when Getpgid fails, resolveGroupKillPgid
// MUST return 0 so terminalKillProcessGroup falls back to a single-process kill
// instead of syscall.Kill(-0, SIGKILL), which would signal the agent's own
// process group and take the whole agent down.
func TestResolveGroupKillPgid_GetpgidFailureReturnsZero(t *testing.T) {
	const sentinelPid = -424242
	if _, err := syscall.Getpgid(sentinelPid); err == nil {
		t.Skipf("Getpgid(%d) unexpectedly succeeded; pick another sentinel", sentinelPid)
	}
	if pgid := resolveGroupKillPgid(sentinelPid); pgid != 0 {
		t.Fatalf("Getpgid failure must yield pgid=0 (single-process kill), got %d", pgid)
	}
}

// A real backgrounded child created with Setpgid:true must resolve to its own
// positive pgid so the group-kill path is taken, and that pgid must differ from
// the test runner's own group (else a group kill would hit us).
func TestResolveGroupKillPgid_ValidProcessReturnsOwnGroup(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pgid := resolveGroupKillPgid(cmd.Process.Pid)
	if pgid <= 0 {
		t.Fatalf("valid Setpgid child must resolve to a positive pgid, got %d", pgid)
	}
	want, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Getpgid: %v", err)
	}
	if pgid != want {
		t.Fatalf("resolved pgid %d must equal Getpgid %d", pgid, want)
	}
	if pgid == syscall.Getpgrp() {
		t.Fatalf("child pgid must differ from the test runner's group %d", pgid)
	}
}

// terminalKillProcessGroup must actually terminate a backgrounded child set up
// via terminalSetPGID, and reap it so the pid is gone afterward.
func TestTerminalKillProcessGroup_KillsChild(t *testing.T) {
	cmd := exec.Command("sleep", "120")
	terminalSetPGID(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	terminalKillProcessGroup(cmd)
	// After reap the process is gone, so signal 0 must fail (ESRCH).
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("process %d still alive after terminalKillProcessGroup", pid)
	}
}
