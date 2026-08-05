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
	"github.com/telleroutlook/proofctl/internal/errors"
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
	KeysDir     string // directory containing *.pub files for C05 signature verification
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
	// T-M31-1: reject any v1 attestation — they are not eligible for release.
	for claimID, att := range attestations {
		if att.Checker.ProtocolVersion != 2 {
			return checkResult{
				pass:     false,
				blockers: []string{fmt.Sprintf("%s: claim %q uses v1 attestation (protocol_version=%d): %s", errors.CodeLegacyAttestation, claimID, att.Checker.ProtocolVersion, "migrate to v2 before release")},
				statuses: map[string]ir.Status{},
				defects:  map[string]string{},
			}
		}
	}

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
	condResults := EvaluateConditions(graph, attestations, pol, g.KeysDir)
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
// and release-snapshot.json to the configured OutputDir. If ProjectRoot is set and
// release passes, also writes release-manifest.json to ProjectRoot.
// It is the only function allowed to write STATUS.json.
// Returns (pass, blockers).
//
// TODO M25: v2 must re-derive claim states from internal/kernel (proofverify kernel)
// rather than trusting attestation.Outcome (a writable field). The current v1 path
// reads attestation.Outcome directly, which means a hand-crafted attestation JSON
// with "outcome":"accepted" can bypass release checks. The v2 path will call
// kernel/derive.DeriveClaimState for each node and feed the result into the gate.
func (g *Gate) Release(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
	evidence []ir.EvidenceDescriptor,
) (bool, []string, error) {
	r := g.check(graph, attestations, pol)

	asOf := time.Now().UTC().Format("2006-01-02")
	rs := ReleaseStatus{
		Released:      r.pass,
		PolicyVersion: pol.Version,
		AsOf:          asOf,
		ClaimSummary:  buildClaimSummary(r.statuses),
		Blockers:      r.blockers,
		Defects:       r.defects,
		Conditions:    r.conditions,
	}
	if r.pass {
		rs.ReleaseTarget = pol.Target
	}

	if err := g.writeStatus(rs); err != nil {
		return false, r.blockers, fmt.Errorf("release: write status: %w", err)
	}

	if r.pass {
		snap := buildSnapshot(pol, attestations, evidence, asOf, buildClaimSummary(r.statuses), graph)
		if err := g.writeSnapshot(snap); err != nil {
			return false, r.blockers, fmt.Errorf("release: write snapshot: %w", err)
		}
	}

	if r.pass && g.ProjectRoot != "" {
		if err := g.writeManifest(pol, attestations, evidence, asOf); err != nil {
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
func buildClaimSummary(statuses map[string]ir.Status) *ClaimSummary {
	s := &ClaimSummary{}
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

// SnapshotFile is the name of the rich release snapshot written by Release on success.
const SnapshotFile = "release-snapshot.json"

// ReleaseSnapshot is a human- and machine-readable summary of a successful release.
// It contains enough information to replace a hand-maintained STATUS.json.
type ReleaseSnapshot struct {
	ReleaseTarget   string                  `json:"release_target"`
	Generated       string                  `json:"generated"`
	ClaimSummary    *ClaimSummary           `json:"claim_summary"`
	Evidence        []SnapshotEvidenceEntry `json:"evidence"`
	CrossDomainDeps []string                `json:"cross_domain_deps,omitempty"` // union of all claim cross_domain_deps
}

// SnapshotEvidenceEntry records per-certificate metadata from checker attestations.
type SnapshotEvidenceEntry struct {
	Digest    string            `json:"digest"`
	PathHint  string            `json:"path_hint,omitempty"`
	MediaType string            `json:"media_type,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// buildSnapshot assembles a ReleaseSnapshot from attestation metadata and evidence descriptors.
func buildSnapshot(
	pol policy.ReleasePolicy,
	attestations map[string]*ir.Attestation,
	evidence []ir.EvidenceDescriptor,
	asOf string,
	summary *ClaimSummary,
	graph *dag.DAG,
) ReleaseSnapshot {
	// Build a per-digest metadata index from all attestations.
	// Later attestations for the same digest overwrite earlier ones (last writer wins).
	// Toolchain fields are merged into metadata with a "toolchain." prefix.
	digestMeta := make(map[string]map[string]string)
	for _, att := range attestations {
		for _, ev := range att.Evidence {
			if _, ok := digestMeta[ev.Digest]; !ok {
				digestMeta[ev.Digest] = make(map[string]string)
			}
			for k, v := range att.Metadata {
				digestMeta[ev.Digest][k] = v
			}
			for k, v := range att.Toolchain {
				digestMeta[ev.Digest]["toolchain."+k] = v
			}
		}
	}

	entries := make([]SnapshotEvidenceEntry, 0, len(evidence))
	for _, ev := range evidence {
		e := SnapshotEvidenceEntry{
			Digest:    ev.Digest,
			PathHint:  ev.PathHint,
			MediaType: ev.MediaType,
			Metadata:  digestMeta[ev.Digest],
		}
		entries = append(entries, e)
	}

	// Collect all cross_domain_deps across all claims.
	var crossDeps []string
	if graph != nil {
		seen := map[string]bool{}
		for _, c := range graph.Claims() {
			for _, xd := range c.CrossDomainDeps {
				if !seen[xd] {
					seen[xd] = true
					crossDeps = append(crossDeps, xd)
				}
			}
		}
	}

	return ReleaseSnapshot{
		ReleaseTarget:   pol.Target,
		Generated:       asOf,
		ClaimSummary:    summary,
		Evidence:        entries,
		CrossDomainDeps: crossDeps,
	}
}

// writeSnapshot atomically writes the ReleaseSnapshot to release-snapshot.json in OutputDir.
func (g *Gate) writeSnapshot(snap ReleaseSnapshot) error {
	if err := os.MkdirAll(g.OutputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	data = append(data, '\n')
	target := filepath.Join(g.OutputDir, SnapshotFile)
	tmp, err := os.CreateTemp(g.OutputDir, "snapshot-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write snapshot: %w", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync snapshot: %w", syncErr)
	}
	_ = tmp.Close()
	if renameErr := os.Rename(tmpName, target); renameErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename snapshot: %w", renameErr)
	}
	return nil
}

// ManifestFile is the name of the release manifest written by Release.
const ManifestFile = "release-manifest.json"

// releaseManifest is written alongside STATUS.json on a successful release.
type releaseManifest struct {
	FormatVersion string              `json:"format_version"`
	Status        string              `json:"status"`
	Generated     string              `json:"generated"`
	ReleaseTarget string              `json:"release_target"`
	Certificates  []manifestCertEntry `json:"certificates"`
}

type manifestCertEntry struct {
	Path           string `json:"path"`
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type,omitempty"`
	CAPFormat      string `json:"cap_format_version,omitempty"`
	CheckerExit    string `json:"checker_exit,omitempty"`
	MarginRatio    string `json:"margin_ratio,omitempty"`
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
