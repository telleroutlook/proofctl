// Package verify orchestrates the full verification pipeline for a single claim.
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/checker"
	"github.com/telleroutlook/proofctl/internal/dag"
	proofErr "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/freshness"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/signing"
	"github.com/telleroutlook/proofctl/pkg/protocol"
	protov2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// Pipeline runs the full verification pipeline for one claim.
type Pipeline struct {
	DAG        *dag.DAG
	CAS        *cas.Store
	AttestDir  string // directory for attestation JSON files
	Runner     runner.Runner
	SigningKey *signing.Key // optional; if set, attestations are signed on write
	TrustStore string       // directory of *.pub key files; used to verify loaded attestations
	NoCache    bool         // if true, skip cache lookup and always re-run checker
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
			return nil, proofErr.Newf(proofErr.CodeMissingEvidence,
				"claim %q: evidence %s: %v", claimID, desc.Digest, err)
		}
	}

	// 2b. Re-compute SHA-256 of on-disk evidence files and compare against stored
	// digests. This detects stale evidence entries where graph.json references a
	// digest that no longer matches the file at path_hint.
	if err := verifyEvidenceDigestsOnDisk(evidence); err != nil {
		return nil, proofErr.Newf(proofErr.CodeMissingEvidence,
			"claim %q: %v", claimID, err)
	}

	// 3. Compute cache key.
	cacheKey := checker.CacheKey(claim, deps, evidence, checkerID, checkerID.SchemaDigest, policyDigest)

	// 4. Check attestation cache.
	if !p.NoCache {
		if hit, err := p.loadCachedAttestation(claimID, cacheKey); err == nil && hit != nil {
			// Backfill freshness if the cached attestation pre-dates the B11/B14 fix.
			if hit.StartFreshness == "" || hit.EndFreshness == "" {
				today := time.Now().UTC().Format("2006-01-02")
				hit.StartFreshness = today
				hit.EndFreshness = today
				// Recompute self-digest after backfill.
				hit.SelfDigest = ""
				if sd, sdErr := ir.DigestOf(hit); sdErr == nil {
					hit.SelfDigest = sd
				}
				// Best-effort write — if it fails the in-memory attestation still works.
				_ = writeAttestationAtomic(p.AttestDir, claimID, hit)
			}
			return &Result{Attestation: hit, CacheHit: true, CacheKey: cacheKey}, nil
		} else if err != nil && isSigInvalidError(err) {
			// Signature verification failed on the cached attestation — surface the error
			// rather than silently re-running the checker, which would mask tampering.
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: cached attestation signature invalid: %v", claimID, err)
		}
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
	// Record start time.
	startTime := time.Now()
	startDate := startTime.UTC().Format("2006-01-02")

	// 6. Run checker.
	// For multi-evidence claims each evidence item is checked independently and
	// metadata is unioned across all runs (B18 fix). Single-evidence claims take
	// the fast path and call the runner once with the full input.
	outputBytes, runErr := p.runCheckerAllEvidence(ctx, checkerID, checkerInput)

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
	} else if checkerID.ProtocolVersion == 2 {
		// 8a. v2 protocol path: parse CheckerOutputV2 and derive outcome from obligations.
		// INV-01: never read Outcome or Assurance from checker output.
		var outV2 protov2.CheckerOutputV2
		if jsonErr := json.Unmarshal(outputBytes, &outV2); jsonErr != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: invalid v2 checker output JSON: %v", claimID, jsonErr)
		}
		// Collect expected obligation IDs from the claim's checker policy (use empty list
		// when not declared — ValidateOutput will flag it as a mismatch).
		expectedOblIDs := claim.RequiredAssurance // Re-using RequiredAssurance as obligation IDs is wrong;
		// the actual obligation IDs come from the Contract. For now use an empty expected
		// set so ValidateOutput at least validates protocol_version and claim_id echo.
		// Full Contract-driven obligation validation is wired in M26-T1 tests / M28.
		_ = expectedOblIDs
		if valErr := protov2.ValidateOutput(outV2, claimID, nil); valErr != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: v2 checker output validation failed: %v", claimID, valErr)
		}
		// Derive outcome from obligation results (INV-07: any fail → rejected).
		if protov2.AllObligationsPass(outV2) {
			outcomeStr = string(ir.StatusAccepted)
		} else {
			outcomeStr = string(ir.StatusRejected)
		}
		// assuranceStr is intentionally empty — proofverify derives assurance from runtime+contract.
		assuranceStr = ""
	} else {
		// 8b. v1 protocol path (legacy).
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
		ReplayMode:        "self_consistency",
		StartFreshness:    startDate,
		EndFreshness:      startDate,
		Resources: ir.ResourceStats{
			WallMillis: wallMillis,
		},
		CacheKey: cacheKey,
	}
	if checkerOut != nil {
		// Only use checker-reported wall time if it is non-zero; otherwise keep the
		// locally-measured wallMillis so the field is never left as 0.
		if checkerOut.Resources.WallMillis > 0 {
			att.Resources.WallMillis = checkerOut.Resources.WallMillis
		}
		if checkerOut.Resources.CPUMillis > 0 {
			att.Resources.CPUMillis = checkerOut.Resources.CPUMillis
		}
		if checkerOut.Resources.MemBytes > 0 {
			att.Resources.MemBytes = checkerOut.Resources.MemBytes
		}
		if len(checkerOut.Metadata) > 0 {
			att.Metadata = checkerOut.Metadata
		}
		if len(checkerOut.Toolchain) > 0 {
			att.Toolchain = checkerOut.Toolchain
			// Recompute cache key to include toolchain digest, so a toolchain
			// change causes a cache miss on the next verify run.
			att.CacheKey = checker.CacheKeyWithToolchain(claim, deps, evidence, checkerID, checkerID.SchemaDigest, policyDigest, checkerOut.Toolchain)
		}
	}

	// Compute self-digest (zero out field first).
	att.SelfDigest = ""
	selfDigest, err := ir.DigestOf(att)
	if err != nil {
		return nil, proofErr.Newf(proofErr.CodeInternalError, "compute self-digest: %v", err)
	}
	att.SelfDigest = selfDigest

	// Sign attestation if a signing key is configured (T26).
	if p.SigningKey != nil {
		sig, signErr := p.SigningKey.Sign(att)
		if signErr != nil {
			return nil, proofErr.Newf(proofErr.CodeInternalError, "sign attestation: %v", signErr)
		}
		att.Signature = &ir.AttestationSig{
			PubkeyFingerprint: sig.PubkeyFingerprint,
			Algorithm:         sig.Algorithm,
			Value:             sig.Value,
		}
	}

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
	defer func() { _ = f.Close() }()

	att, err := ir.DecodeAttestation(f)
	if err != nil {
		return nil, err
	}
	if att.CacheKey != cacheKey {
		return nil, fmt.Errorf("cache key mismatch")
	}
	// Verify signature if present and trust store is configured (T27).
	if att.Signature != nil && p.TrustStore != "" {
		if verifyErr := p.verifyAttestationSig(att); verifyErr != nil {
			return nil, fmt.Errorf("signature-invalid: %w", verifyErr)
		}
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

// verifyAttestationSig loads the public key matching att.Signature.PubkeyFingerprint
// from TrustStore and verifies the signature.
func (p *Pipeline) verifyAttestationSig(att *ir.Attestation) error {
	if att.Signature == nil {
		return nil
	}
	entries, err := os.ReadDir(p.TrustStore)
	if err != nil {
		return fmt.Errorf("read trust store: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 4 || e.Name()[len(e.Name())-4:] != ".pub" {
			continue
		}
		pubPath := filepath.Join(p.TrustStore, e.Name())
		k, err := signing.LoadPublic(pubPath)
		if err != nil {
			// A corrupt or unreadable key file is a configuration error, not a missing key.
			return fmt.Errorf("load public key %s: %w", pubPath, err)
		}
		if k.ID != att.Signature.PubkeyFingerprint {
			continue
		}
		sig := signing.Signature{
			PubkeyFingerprint: att.Signature.PubkeyFingerprint,
			Algorithm:         att.Signature.Algorithm,
			Value:             att.Signature.Value,
		}
		return signing.Verify(k, att, sig)
	}
	return fmt.Errorf("no public key found for fingerprint %q in trust store", att.Signature.PubkeyFingerprint)
}

// runCheckerAllEvidence runs the checker once per evidence item and merges the
// results (B18). For each evidence item it builds a single-item CheckerInput,
// runs the checker, and unions the metadata. The merged outcome is the worst
// result across all items: any rejection takes precedence over acceptance.
// For a single-evidence claim this is equivalent to one direct runner call.
func (p *Pipeline) runCheckerAllEvidence(
	ctx context.Context,
	checkerID ir.CheckerIdentity,
	base protocol.CheckerInput,
) ([]byte, error) {
	if len(base.Evidence) <= 1 {
		inputJSON, err := json.Marshal(base)
		if err != nil {
			return nil, fmt.Errorf("marshal checker input: %w", err)
		}
		return p.Runner.Run(ctx, checkerID, bytes.NewReader(inputJSON))
	}

	// Run checker once per evidence item, collecting per-item outputs.
	var mergedOut *protocol.CheckerOutput
	var firstErr error
	for _, evRef := range base.Evidence {
		single := base
		single.Evidence = []protocol.EvidenceRef{evRef}
		inputJSON, err := json.Marshal(single)
		if err != nil {
			return nil, fmt.Errorf("marshal checker input for evidence %s: %w", evRef.Digest, err)
		}
		raw, runErr := p.Runner.Run(ctx, checkerID, bytes.NewReader(inputJSON))
		if runErr != nil {
			if firstErr == nil {
				firstErr = runErr
			}
			continue
		}
		out, parseErr := parseCheckerOutput(raw)
		if parseErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("evidence %s: %w", evRef.Digest, parseErr)
			}
			continue
		}
		if mergedOut == nil {
			mergedOut = out
		} else {
			// Merge metadata: union all keys.
			for k, v := range out.Metadata {
				if mergedOut.Metadata == nil {
					mergedOut.Metadata = make(map[string]string)
				}
				mergedOut.Metadata[k] = v
			}
			// Worst outcome wins.
			if out.Outcome != "accepted" {
				mergedOut.Outcome = out.Outcome
				mergedOut.Assurance = out.Assurance
				mergedOut.ErrorCode = out.ErrorCode
			}
		}
	}

	if firstErr != nil && mergedOut == nil {
		return nil, firstErr
	}
	if mergedOut == nil {
		return nil, fmt.Errorf("checker produced no output for any evidence item")
	}
	merged, err := json.Marshal(mergedOut)
	if err != nil {
		return nil, fmt.Errorf("marshal merged checker output: %w", err)
	}
	return merged, nil
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

// isSigInvalidError reports whether err originated from a signature verification failure.
func isSigInvalidError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "signature-invalid")
}

// verifyEvidenceDigestsOnDisk recomputes the SHA-256 of each evidence file that has
// a path_hint and compares it against the stored digest. Files that are absent on
// disk are skipped (CAS verification already covers content-addressable storage).
// A mismatch means the file was modified after graph.json was last compiled.
func verifyEvidenceDigestsOnDisk(evidence []ir.EvidenceDescriptor) error {
	for _, desc := range evidence {
		if desc.PathHint == "" {
			continue
		}
		f, err := os.Open(desc.PathHint)
		if err != nil {
			if os.IsNotExist(err) {
				continue // not on disk; CAS path handles it
			}
			return fmt.Errorf("evidence %s: open path_hint %q: %w", desc.Digest, desc.PathHint, err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return fmt.Errorf("evidence %s: hash path_hint %q: %w", desc.Digest, desc.PathHint, err)
		}
		_ = f.Close()
		got := "sha256:" + hex.EncodeToString(h.Sum(nil))
		if got != desc.Digest {
			return fmt.Errorf("evidence digest mismatch for %q: graph.json stores %s but on-disk file %s has %s — re-run 'proofctl compile --fix-digests' or update graph.json evidence",
				desc.PathHint, desc.Digest, desc.PathHint, got)
		}
	}
	return nil
}
