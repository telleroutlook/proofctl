// Package release implements the release gate for the ProofGraph Engine.
//
// The gate is fail-closed: any missing attestation or policy violation blocks release.
// DryRun and Release share the same internal check function. Only Release may write
// STATUS.json, and it does so via temp file + fsync + atomic rename.
package release

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/status"
)

// StatusFile is the name of the release status file written by Release.
const StatusFile = "STATUS.json"

// ReleaseStatus is written to STATUS.json on a successful release.
type ReleaseStatus struct {
	CertifiedRadius string            `json:"certified_radius"`
	PolicyVersion   string            `json:"policy_version"`
	Blockers        []string          `json:"blockers,omitempty"`
	Defects         map[string]string `json:"defects,omitempty"` // D-number → block_reason
	Released        bool              `json:"released"`
}

// Gate performs release checks for a proof graph.
type Gate struct {
	OutputDir string
}

// checkResult holds the outcome of the shared internal check.
type checkResult struct {
	pass     bool
	blockers []string
	statuses map[string]ir.Status
	defects  map[string]string // claim ID → block_reason
}

// check is the single shared implementation for DryRun and Release.
func (g *Gate) check(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) checkResult {
	statuses := status.Compute(graph, attestations)

	// Fail-closed: any non-accepted claim blocks release.
	var blockers []string
	for id, s := range statuses {
		if s != ir.StatusAccepted {
			blockers = append(blockers, fmt.Sprintf("claim %q status is %q", id, s))
		}
	}

	// Run policy evaluation.
	pass, policyBlockers := policy.Evaluate(graph, attestations, pol)
	if !pass {
		blockers = append(blockers, policyBlockers...)
	}

	// Collect D-defect reasons from blocked attestations.
	defects := make(map[string]string)
	for id, att := range attestations {
		if att.BlockReason != "" {
			defects[id] = att.BlockReason
		}
	}

	return checkResult{
		pass:     len(blockers) == 0,
		blockers: blockers,
		statuses: statuses,
		defects:  defects,
	}
}

// DryRun performs all release checks but does not write STATUS.json.
// Returns (pass, blockers).
func (g *Gate) DryRun(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) (bool, []string) {
	r := g.check(graph, attestations, pol)
	return r.pass, r.blockers
}

// Release performs all release checks. On success it atomically writes STATUS.json
// to the configured OutputDir. It is the only function allowed to write STATUS.json.
// Returns (pass, blockers).
func (g *Gate) Release(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) (bool, []string, error) {
	r := g.check(graph, attestations, pol)

	rs := ReleaseStatus{
		Released:      r.pass,
		PolicyVersion: pol.Version,
		Blockers:      r.blockers,
		Defects:       r.defects,
	}
	if r.pass {
		rs.CertifiedRadius = pol.Target
	}

	if err := g.writeStatus(rs); err != nil {
		return false, r.blockers, fmt.Errorf("release: write status: %w", err)
	}
	return r.pass, r.blockers, nil
}

// writeStatus atomically writes the ReleaseStatus to STATUS.json in OutputDir.
func (g *Gate) writeStatus(rs ReleaseStatus) error {
	if err := os.MkdirAll(g.OutputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	target := filepath.Join(g.OutputDir, StatusFile)

	// Write to a temp file in the same directory, fsync, then rename.
	tmp, err := os.CreateTemp(g.OutputDir, "status-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync temp: %w", syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", closeErr)
	}
	if renameErr := os.Rename(tmpName, target); renameErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", renameErr)
	}
	return nil
}
