package taskexec

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestRunnerRequiresExplicitExecEnable(t *testing.T) {
	r := Runner{}
	result := r.Run(model.Task{ID: "task_1", Interpreter: "sh", Script: "echo no"})
	if result.Error == "" || result.ExitCode != -1 {
		t.Fatalf("expected disabled execution error, got %#v", result)
	}
}

func TestRunnerCapsOutput(t *testing.T) {
	r := Runner{AllowExec: true}
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

func TestRunnerRejectsUnknownInterpreter(t *testing.T) {
	r := Runner{AllowExec: true}
	result := r.Run(model.Task{ID: "task_1", Interpreter: "perl", Script: "print 1"})
	if !strings.Contains(result.Error, "allowlisted") {
		t.Fatalf("expected allowlist error, got %#v", result)
	}
}
