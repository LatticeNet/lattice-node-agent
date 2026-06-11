package taskexec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

var allowedInterpreters = map[string]string{
	"sh":      "/bin/sh",
	"bash":    "/bin/bash",
	"python3": "python3",
	"node":    "node",
}

type Runner struct {
	AllowExec bool
}

func (r Runner) Run(task model.Task) model.TaskResult {
	start := time.Now().UTC()
	result := model.TaskResult{
		TaskID:    task.ID,
		StartedAt: start,
	}
	if !r.AllowExec {
		result.ExitCode = -1
		result.Error = "agent task execution disabled; restart with -allow-exec=true to enable"
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
	if err := os.WriteFile(scriptPath, []byte(task.Script), 0o700); err != nil {
		result.ExitCode = -1
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}

	cmd := exec.CommandContext(ctx, interp, scriptPath)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/local/bin", "HOME=" + dir, "LATTICE_TASK_ID=" + task.ID}
	var stdout, stderr cappedBuffer
	stdout.limit = limit
	stderr.limit = limit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.ExitCode = exitCode(err)
	if ctx.Err() != nil {
		result.Error = ctx.Err().Error()
	} else if err != nil {
		result.Error = err.Error()
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
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}
