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
	"time"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/status"
)

// StatusFile is the name of the release status file written by Release.
const StatusFile = "STATUS.json"

// ReleaseStatus is written to STATUS.json on a successful release.
type ReleaseStatus struct {
	// ReleaseTarget is the policy target claim ID, set only on a successful release.
	ReleaseTarget string            `json:"release_target,omitempty"`
	PolicyVersion string            `json:"policy_version"`
	AsOf          string            `json:"as_of,omitempty"`
	ClaimSummary  *ClaimSummary     `json:"claim_summary,omitempty"`
	Blockers      []string          `json:"blockers,omitempty"`
	Defects       map[string]string `json:"defects,omitempty"`
	Conditions    []ConditionResult `json:"conditions,omitempty"`
	Released      bool              `json:"released"`
}

// ClaimSummary captures accepted/blocked/open/rejected counts.
type ClaimSummary struct {
	Accepted int `json:"accepted"`
	Blocked  int `json:"blocked"`
	Open     int `json:"open"`
	Rejected int `json:"rejected"`
}

// Gate performs release checks for a proof graph.
type Gate struct {
	OutputDir   string
	ProjectRoot string // if non-empty, release-manifest.json is written here on success
}

// checkResult holds the outcome of the shared internal check.
type checkResult struct {
	pass       bool
	blockers   []string
	statuses   map[string]ir.Status
	defects    map[string]string // claim ID → block_reason
	conditions []ConditionResult
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

	// Evaluate the 13 Weil release conditions.
	condResults := EvaluateConditions(graph, attestations, pol)
	blockers = append(blockers, Blockers(condResults)...)

	return checkResult{
		pass:       len(blockers) == 0,
		blockers:   blockers,
		statuses:   statuses,
		defects:    defects,
		conditions: condResults,
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
// to the configured OutputDir. If ProjectRoot is set and release passes, also writes
// release-manifest.json to ProjectRoot. It is the only function allowed to write STATUS.json.
// Returns (pass, blockers).
func (g *Gate) Release(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
	evidence []ir.EvidenceDescriptor,
) (bool, []string, error) {
	r := g.check(graph, attestations, pol)

	rs := ReleaseStatus{
		Released:     r.pass,
		PolicyVersion: pol.Version,
		AsOf:         time.Now().UTC().Format("2006-01-02"),
		ClaimSummary: buildClaimSummary(r.statuses),
		Blockers:     r.blockers,
		Defects:      r.defects,
		Conditions:   r.conditions,
	}
	if r.pass {
		rs.ReleaseTarget = pol.Target
	}

	if err := g.writeStatus(rs); err != nil {
		return false, r.blockers, fmt.Errorf("release: write status: %w", err)
	}

	if r.pass && g.ProjectRoot != "" {
		if err := g.writeManifest(pol, attestations, evidence, rs.AsOf); err != nil {
			return false, r.blockers, fmt.Errorf("release: write manifest: %w", err)
		}
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

// buildClaimSummary counts claims by status.
func buildClaimSummary(statuses map[string]ir.Status) *ClaimSummary {	s := &ClaimSummary{}
	for _, st := range statuses {
		switch st {
		case ir.StatusAccepted:
			s.Accepted++
		case ir.StatusBlocked:
			s.Blocked++
		case ir.StatusOpen:
			s.Open++
		case ir.StatusRejected:
			s.Rejected++
		}
	}
	return s
}

// ManifestFile is the name of the release manifest written by Release.
const ManifestFile = "release-manifest.json"

// releaseManifest is written alongside STATUS.json on a successful release.
type releaseManifest struct {
	FormatVersion string             `json:"format_version"`
	Status        string             `json:"status"`
	Generated     string             `json:"generated"`
	ReleaseTarget string             `json:"release_target"`
	Certificates  []manifestCertEntry `json:"certificates"`
}

type manifestCertEntry struct {
	Path          string `json:"path"`
	Digest        string `json:"digest"`
	MediaType     string `json:"media_type,omitempty"`
	CAPFormat     string `json:"cap_format_version,omitempty"`
	CheckerExit   string `json:"checker_exit,omitempty"`
	MarginRatio   string `json:"margin_ratio,omitempty"`
	ColdReplayDate string `json:"cold_replay_date,omitempty"`
}

// writeManifest writes release-manifest.json to ProjectRoot.
func (g *Gate) writeManifest(
	pol policy.ReleasePolicy,
	attestations map[string]*ir.Attestation,
	evidence []ir.EvidenceDescriptor,
	asOf string,
) error {
	// Build a metadata index from all attestations.
	meta := make(map[string]string)
	for _, att := range attestations {
		for k, v := range att.Metadata {
			if meta[k] == "" {
				meta[k] = v
			}
		}
	}

	entries := make([]manifestCertEntry, 0, len(evidence))
	for _, ev := range evidence {
		e := manifestCertEntry{
			Path:        ev.PathHint,
			Digest:      ev.Digest,
			MediaType:   ev.MediaType,
			CAPFormat:   meta["cap_format_version"],
			MarginRatio: meta["pivot_radius_ratio"],
		}
		if meta["ldlt_passes"] == "true" {
			e.CheckerExit = "0"
		}
		if asOf != "" {
			e.ColdReplayDate = asOf
		}
		entries = append(entries, e)
	}

	manifest := releaseManifest{
		FormatVersion: "2.0",
		Status:        "RELEASED — " + pol.Target + " gate passed " + asOf,
		Generated:     asOf,
		ReleaseTarget: pol.Target,
		Certificates:  entries,
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')

	target := filepath.Join(g.ProjectRoot, ManifestFile)
	tmp, err := os.CreateTemp(g.ProjectRoot, "manifest-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
	}
	tmpName := tmp.Name()
	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write manifest: %w", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync manifest: %w", syncErr)
	}
	_ = tmp.Close()
	if renameErr := os.Rename(tmpName, target); renameErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename manifest: %w", renameErr)
	}
	return nil
}
