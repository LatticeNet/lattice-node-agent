//go:build linux

package taskexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestPrepareTaskCgroupWritesControlsAndCleansFakeRoot(t *testing.T) {
	root := fakeCgroupRoot(t)
	cgroup, err := prepareTaskCgroup(CgroupConfig{
		Root:      root,
		MemoryMax: "1048576",
		PidsMax:   "12",
		CPUMax:    "50000 100000",
	}, "task/weird id")
	if err != nil {
		t.Fatalf("prepareTaskCgroup returned error: %v", err)
	}
	if cgroup.Path() == "" {
		t.Fatalf("expected prepared cgroup path")
	}
	if !strings.HasPrefix(filepath.Base(cgroup.Path()), "task-task_weird_id-") {
		t.Fatalf("cgroup name was not sanitized: %s", cgroup.Path())
	}
	assertFile(t, filepath.Join(cgroup.Path(), "memory.max"), "1048576")
	assertFile(t, filepath.Join(cgroup.Path(), "pids.max"), "12")
	assertFile(t, filepath.Join(cgroup.Path(), "cpu.max"), "50000 100000")

	cgroup.Cleanup()
	if _, err := os.Stat(cgroup.Path()); !os.IsNotExist(err) {
		t.Fatalf("expected fake cgroup to be removed, stat err=%v", err)
	}
}

func TestRunnerWithConfiguredFakeCgroupExecutesThroughShim(t *testing.T) {
	r := Runner{
		AllowExec: true,
		getUID:    nonRootUID,
		Cgroup: CgroupConfig{
			Root:      fakeCgroupRoot(t),
			MemoryMax: "1048576",
			PidsMax:   "16",
			CPUMax:    "100000 100000",
		},
	}
	result := r.Run(model.Task{
		ID:          "task/cgroup",
		Interpreter: "sh",
		Script:      "printf ok",
		TimeoutSec:  5,
		OutputLimit: 64,
	})
	if result.ExitCode != 0 || result.Stdout != "ok" {
		t.Fatalf("expected fake-cgroup task to execute, got %#v", result)
	}
}

func TestRunnerFailsClosedForInvalidCgroupRoot(t *testing.T) {
	r := Runner{
		AllowExec: true,
		getUID:    nonRootUID,
		Cgroup:    CgroupConfig{Root: "relative"},
	}
	result := r.Run(model.Task{
		ID:          "task_bad_cgroup",
		Interpreter: "sh",
		Script:      "printf should-not-run",
		TimeoutSec:  5,
		OutputLimit: 64,
	})
	if result.ExitCode != -1 {
		t.Fatalf("expected fail-closed cgroup error, got %#v", result)
	}
	if !strings.Contains(result.Error, "absolute") {
		t.Fatalf("expected absolute-root error, got %#v", result)
	}
	if result.Stdout != "" {
		t.Fatalf("script should not have run, stdout=%q", result.Stdout)
	}
}

func TestRunnerFailsClosedForOrdinaryDirectoryCgroupRoot(t *testing.T) {
	r := Runner{
		AllowExec: true,
		getUID:    nonRootUID,
		Cgroup:    CgroupConfig{Root: t.TempDir()},
	}
	result := r.Run(model.Task{
		ID:          "task_plain_dir_cgroup",
		Interpreter: "sh",
		Script:      "printf should-not-run",
		TimeoutSec:  5,
		OutputLimit: 64,
	})
	if result.ExitCode != -1 {
		t.Fatalf("expected fail-closed cgroup error, got %#v", result)
	}
	if !strings.Contains(result.Error, "not a cgroup v2 directory") {
		t.Fatalf("expected cgroup-v2-root error, got %#v", result)
	}
	if result.Stdout != "" {
		t.Fatalf("script should not have run, stdout=%q", result.Stdout)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}

func fakeCgroupRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids"), 0o600); err != nil {
		t.Fatalf("write fake controllers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o600); err != nil {
		t.Fatalf("write fake subtree control: %v", err)
	}
	return root
}
