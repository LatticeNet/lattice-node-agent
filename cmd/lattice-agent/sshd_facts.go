package main

import (
	"context"

	"github.com/LatticeNet/lattice-node-agent/internal/sshdfacts"
	"github.com/LatticeNet/lattice-sdk/model"
)

// reportSSHDFacts is the production sshd step of the guard-reality report:
// root only, a trusted sshd only, three seconds, and a note instead of a
// guess when any of that fails. It is a named function rather than a closure
// so the wiring test can check the collector was handed to the report.
func reportSSHDFacts(ctx context.Context) (*model.GuardSSHDFacts, string) {
	return sshdfacts.Collect(ctx, sshdfacts.Source{})
}
