// Package verify orchestrates the full verification pipeline for a single claim.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/checker"
	"github.com/telleroutlook/proofctl/internal/dag"
	proofErr "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/freshness"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/pkg/protocol"
)

// Pipeline runs the full verification pipeline for one claim.
type Pipeline struct {
	DAG       *dag.DAG
	CAS       *cas.Store
	AttestDir string // directory for attestation JSON files
	Runner    runner.Runner
}

// Result is returned by Pipeline.Run.
type Result struct {
	Attestation *ir.Attestation
	CacheHit    bool
	CacheKey    string
}

// Run executes the verification pipeline for one claim.
//
//  1. Resolve claim and direct dependencies from DAG
//  2. Verify each evidence descriptor via CAS
//  3. Compute cache key
//  4. Check attestation cache — return cached result if hit
//  5. Pre-run freshness snapshot
//  6. Run checker
//  7. Post-run freshness snapshot — fail-closed on drift
//  8. Parse and validate checker output
//  9. Build, persist, and return attestation
func (p *Pipeline) Run(
	ctx context.Context,
	claimID string,
	checkerID ir.CheckerIdentity,
	evidence []ir.EvidenceDescriptor,
	policyDigest string,
) (*Result, error) {
	// Validate claim ID before any path operations (defense in depth).
	if err := ir.ValidateClaimID(claimID); err != nil {
		return nil, proofErr.Newf(proofErr.CodeMissingDependency, "%v", err)
	}

	// 1. Resolve claim.
	claim := p.DAG.Claim(claimID)
	if claim == nil {
		return nil, proofErr.Newf(proofErr.CodeMissingDependency, "unknown claim %q", claimID)
	}

	// Collect direct dependency claims.
	deps := make([]*ir.Claim, 0, len(claim.DependsOn))
	for _, depID := range claim.DependsOn {
		d := p.DAG.Claim(depID)
		if d == nil {
			return nil, proofErr.Newf(proofErr.CodeMissingDependency, "claim %q depends on unknown claim %q", claimID, depID)
		}
		deps = append(deps, d)
	}

	// 2. Verify evidence via CAS.
	for _, desc := range evidence {
		if err := p.CAS.Verify(desc); err != nil {
			return nil, proofErr.Newf(proofErr.CodeMissingEvidence, "evidence %s: %v", desc.Digest, err)
		}
	}

	// 3. Compute cache key.
	cacheKey := checker.CacheKey(claim, deps, evidence, checkerID, checkerID.SchemaDigest, policyDigest)

	// 4. Check attestation cache.
	if hit, err := p.loadCachedAttestation(claimID, cacheKey); err == nil && hit != nil {
		return &Result{Attestation: hit, CacheHit: true, CacheKey: cacheKey}, nil
	}

	// 5. Pre-run freshness snapshot.
	evidencePaths := make([]string, 0, len(evidence))
	for _, desc := range evidence {
		if desc.PathHint != "" {
			evidencePaths = append(evidencePaths, desc.PathHint)
		}
	}
	preFreshness, err := freshness.Snapshot(evidencePaths)
	if err != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "pre-run freshness snapshot: %v", err)
	}

	// Build checker input.
	depDigests := make(map[string]string, len(deps))
	for _, d := range deps {
		depDigests[d.ID] = d.Statement.Digest
	}
	evidenceRefs := make([]protocol.EvidenceRef, 0, len(evidence))
	for _, desc := range evidence {
		evidenceRefs = append(evidenceRefs, protocol.EvidenceRef{
			MediaType: desc.MediaType,
			Digest:    desc.Digest,
			Size:      desc.Size,
			LocalPath: desc.PathHint,
		})
	}
	checkerInput := protocol.CheckerInput{
		ProtocolVersion:   protocol.ProtocolVersion,
		ClaimID:           claimID,
		StatementDigest:   claim.Statement.Digest,
		StatementText:     claim.Statement.Text,
		DependencyDigests: depDigests,
		Evidence:          evidenceRefs,
		PolicyDigest:      policyDigest,
	}
	inputJSON, err := json.Marshal(checkerInput)
	if err != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "marshal checker input: %v", err)
	}

	// Record start time.
	startTime := time.Now()

	// 6. Run checker.
	outputBytes, runErr := p.Runner.Run(ctx, checkerID, bytes.NewReader(inputJSON))

	wallMillis := time.Since(startTime).Milliseconds()

	// 7. Post-run freshness snapshot — fail-closed on drift.
	postFreshness, snapErr := freshness.Snapshot(evidencePaths)
	if snapErr != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "post-run freshness snapshot: %v", snapErr)
	}
	if driftErr := freshness.Verify(preFreshness, postFreshness); driftErr != nil {
		return nil, proofErr.Newf(proofErr.CodeFreshnessViolation, "evidence drift detected: %v", driftErr)
	}

	// Handle runner errors — some still produce an attestation (ExitFail).
	var checkerOut *protocol.CheckerOutput
	var outcomeStr string
	var assuranceStr string
	var errorCode string

	if runErr != nil {
		var re *runner.RunError
		switch {
		case isRunError(runErr, &re) && re.IsCheckerFail():
			// Exit 1: checker ran, claim rejected. Parse output if available.
			checkerOut = tryParseCheckerOutput(outputBytes)
			if checkerOut != nil {
				outcomeStr = checkerOut.Outcome
				assuranceStr = checkerOut.Assurance
			} else {
				outcomeStr = "rejected"
				assuranceStr = ""
			}
		case isRunError(runErr, &re) && re.IsUnavailable():
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker unavailable: %v", runErr)
		case isRunError(runErr, &re) && re.IsProtocolError():
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker protocol error: %v", runErr)
		default:
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker failed: %v", runErr)
		}
	} else {
		// 8. Parse and validate checker output.
		checkerOut, err = parseCheckerOutput(outputBytes)
		if err != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "invalid checker output: %v", err)
		}
		outcomeStr = checkerOut.Outcome
		assuranceStr = checkerOut.Assurance
		errorCode = checkerOut.ErrorCode
	}

	// Compute dependency digests list.
	depDigestList := make([]string, 0, len(deps))
	for _, d := range deps {
		depDigestList = append(depDigestList, d.Statement.Digest)
	}

	// 9. Build attestation.
	att := &ir.Attestation{
		ClaimID:           claimID,
		StatementDigest:   claim.Statement.Digest,
		DependencyDigests: depDigestList,
		Evidence:          evidence,
		Checker:           checkerID,
		Outcome:           outcomeStr,
		Assurance:         ir.Assurance(assuranceStr),
		ErrorCode:         errorCode,
		Resources: ir.ResourceStats{
			WallMillis: wallMillis,
		},
		CacheKey: cacheKey,
	}
	if checkerOut != nil {
		att.Resources.WallMillis = checkerOut.Resources.WallMillis
		att.Resources.CPUMillis = checkerOut.Resources.CPUMillis
		att.Resources.MemBytes = checkerOut.Resources.MemBytes
		if len(checkerOut.Metadata) > 0 {
			att.Metadata = checkerOut.Metadata
		}
	}

	// Compute self-digest (zero out field first).
	att.SelfDigest = ""
	selfDigest, err := ir.DigestOf(att)
	if err != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "compute self-digest: %v", err)
	}
	att.SelfDigest = selfDigest

	// Write attestation atomically.
	if err := writeAttestationAtomic(p.AttestDir, claimID, att); err != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "write attestation: %v", err)
	}

	return &Result{Attestation: att, CacheHit: false, CacheKey: cacheKey}, nil
}

// loadCachedAttestation returns the stored attestation for claimID if its
// CacheKey matches the provided cacheKey; otherwise returns nil.
func (p *Pipeline) loadCachedAttestation(claimID, cacheKey string) (*ir.Attestation, error) {
	if err := ir.ValidateClaimID(claimID); err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	path := filepath.Join(p.AttestDir, claimID+".json")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	att, err := ir.DecodeAttestation(f)
	if err != nil {
		return nil, err
	}
	if att.CacheKey != cacheKey {
		return nil, fmt.Errorf("cache key mismatch")
	}
	return att, nil
}

// writeAttestationAtomic writes att as JSON to <dir>/<claimID>.json using
// a temp file + fsync + rename for durability.
// claimID must pass ir.ValidateClaimID before this function is called.
func writeAttestationAtomic(dir, claimID string, att *ir.Attestation) error {
	if err := ir.ValidateClaimID(claimID); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(att, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".attest-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op if renamed

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	dest := filepath.Join(dir, claimID+".json")
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// parseCheckerOutput decodes and validates the checker's stdout payload.
func parseCheckerOutput(data []byte) (*protocol.CheckerOutput, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	var out protocol.CheckerOutput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if out.Outcome == "" {
		return nil, fmt.Errorf("missing outcome field")
	}
	return &out, nil
}

// tryParseCheckerOutput attempts to parse checker output, returning nil on failure.
func tryParseCheckerOutput(data []byte) *protocol.CheckerOutput {
	if len(data) == 0 {
		return nil
	}
	out, err := parseCheckerOutput(data)
	if err != nil {
		return nil
	}
	return out
}

// isRunError checks if err is a *runner.RunError and, if so, sets target.
func isRunError(err error, target **runner.RunError) bool {
	if re, ok := err.(*runner.RunError); ok {
		*target = re
		return true
	}
	return false
}
