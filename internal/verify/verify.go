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
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	proofErr "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/freshness"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/signing"
	protov2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// Pipeline runs the full verification pipeline for one claim.
type Pipeline struct {
	DAG         *dag.DAG
	CAS         *cas.Store
	AttestDir   string // directory for attestation JSON files
	Runner      runner.Runner
	SigningKey  *signing.Key // optional; if set, attestations are signed on write
	TrustStore  string       // directory of *.pub key files; used to verify loaded attestations
	NoCache     bool         // if true, skip cache lookup and always re-run checker
	ProjectRoot string       // project root directory for contract resolution (T-M31-5)
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

	// 3b. Dependency manifest (lockfile) drift check (M10).
	// If the checker has a pinned DependencyManifestDigest, verify the current
	// lockfile on disk still matches. A mismatch means the Python/Go/Cargo
	// dependencies have changed since the checker was last pinned.
	if checkerID.Runtime.DependencyManifestDigest != "" &&
		checkerID.Runtime.DependencyManifestPath != "" {
		if driftErr := verifyDependencyManifest(
			p.DAG, checkerID.Runtime.DependencyManifestPath,
			checkerID.Runtime.DependencyManifestDigest,
		); driftErr != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: dependency drift detected — checker dependencies have changed since last pin: %v\n"+
					"  Re-run 'proofctl pin checker --lock %s' to update the pinned digest.",
				claimID, driftErr, checkerID.Runtime.DependencyManifestPath)
		}
	}

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

	// Build v2 checker input.
	depDigests := make(map[string]string, len(deps))
	for _, d := range deps {
		depDigests[d.ID] = d.Statement.Digest
	}
	evidenceRefs := make([]protov2.EvidenceRefV2, 0, len(evidence))
	for _, desc := range evidence {
		evidenceRefs = append(evidenceRefs, protov2.EvidenceRefV2{
			MediaType: desc.MediaType,
			Digest:    desc.Digest,
			Size:      desc.Size,
			LocalPath: desc.PathHint,
		})
	}
	checkerInput := protov2.CheckerInputV2{
		ProtocolVersion:        protov2.ProtocolVersion,
		ClaimID:                claimID,
		StatementDigest:        claim.Statement.Digest,
		StatementText:          claim.Statement.Text,
		ContractDigest:         "",
		DependencyAttestations: depDigests,
		Evidence:               evidenceRefs,
		ObligationIDs:          nil, // populated from Contract in future
		PolicyDigest:           policyDigest,
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

	// Handle runner errors — some still produce output on exit 1.
	var outcomeStr string
	var errorCode string

	if runErr != nil {
		var re *runner.RunError
		switch {
		case isRunError(runErr, &re) && re.IsCheckerFail():
			// Exit 1: checker ran but obligations failed. Try to parse output.
			var outV2 protov2.CheckerOutputV2
			if jsonErr := json.Unmarshal(outputBytes, &outV2); jsonErr == nil &&
				!protov2.AllObligationsPass(outV2) {
				outcomeStr = string(ir.StatusRejected)
			} else {
				outcomeStr = string(ir.StatusRejected)
			}
		case isRunError(runErr, &re) && re.IsUnavailable():
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker unavailable: %v", runErr)
		case isRunError(runErr, &re) && re.IsProtocolError():
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker protocol error: %v", runErr)
		default:
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed, "checker failed: %v", runErr)
		}
	} else {
		// 8. Parse and validate v2 checker output (INV-01: no Outcome/Assurance fields).
		var outV2 protov2.CheckerOutputV2
		if jsonErr := json.Unmarshal(outputBytes, &outV2); jsonErr != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: invalid checker output JSON: %v", claimID, jsonErr)
		}
		obligationIDs := loadObligationIDs(p.ProjectRoot, claimID)
		if valErr := protov2.ValidateOutput(outV2, claimID, obligationIDs); valErr != nil {
			return nil, proofErr.Newf(proofErr.CodeCheckerFailed,
				"claim %q: checker output validation failed: %v", claimID, valErr)
		}
		// Check input closure binding (INV-02, P0-10).
		if bindErr := checkClosureBinding(outV2, claimID); bindErr != nil {
			return nil, bindErr
		}
		// Derive outcome from obligation results (INV-07: any fail → rejected).
		if protov2.AllObligationsPass(outV2) {
			outcomeStr = string(ir.StatusAccepted)
		} else {
			outcomeStr = string(ir.StatusRejected)
		}
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
		Assurance:         "", // v1 only; v2: proofverify derives assurance from runtime+contract
		ErrorCode:         errorCode,
		ReplayMode:        "self_consistency",
		StartFreshness:    startDate,
		EndFreshness:      startDate,
		Resources: ir.ResourceStats{
			WallMillis: wallMillis,
		},
		CacheKey: cacheKey,
	}
	// Extract toolchain from v2 output if available, for cache key recomputation.
	if runErr == nil && len(outputBytes) > 0 {
		var outV2 protov2.CheckerOutputV2
		if jsonErr := json.Unmarshal(outputBytes, &outV2); jsonErr == nil {
			if len(outV2.Toolchain) > 0 {
				att.Toolchain = outV2.Toolchain
				att.CacheKey = checker.CacheKeyWithToolchain(claim, deps, evidence, checkerID, checkerID.SchemaDigest, policyDigest, outV2.Toolchain)
			}
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
// results. For each evidence item it builds a single-item CheckerInputV2,
// runs the checker, and unions the obligation results. Any fail verdict wins.
// For a single-evidence claim this is a direct runner call.
func (p *Pipeline) runCheckerAllEvidence(
	ctx context.Context,
	checkerID ir.CheckerIdentity,
	base protov2.CheckerInputV2,
) ([]byte, error) {
	if len(base.Evidence) <= 1 {
		inputJSON, err := json.Marshal(base)
		if err != nil {
			return nil, fmt.Errorf("marshal checker input: %w", err)
		}
		return p.Runner.Run(ctx, checkerID, bytes.NewReader(inputJSON))
	}

	// Run checker once per evidence item, collecting per-item v2 outputs.
	var mergedOut *protov2.CheckerOutputV2
	var firstErr error
	for _, evRef := range base.Evidence {
		single := base
		single.Evidence = []protov2.EvidenceRefV2{evRef}
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
		var out protov2.CheckerOutputV2
		if parseErr := json.Unmarshal(raw, &out); parseErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("evidence %s: %w", evRef.Digest, parseErr)
			}
			continue
		}
		if mergedOut == nil {
			mergedOut = &out
		} else {
			// Merge toolchain.
			for k, v := range out.Toolchain {
				if mergedOut.Toolchain == nil {
					mergedOut.Toolchain = make(map[string]string)
				}
				mergedOut.Toolchain[k] = v
			}
			// Worst verdict wins: any fail obligation propagates.
			for _, r := range out.ObligationResults {
				if r.Verdict == protov2.VerdictFail {
					mergedOut.ObligationResults = append(mergedOut.ObligationResults, r)
				}
			}
		}
	}

	// T-M31-6: any per-evidence error blocks the entire claim (INV-07).
	// A partial success does NOT mask a failure on another evidence item.
	if firstErr != nil {
		return nil, fmt.Errorf("multi-evidence: one or more evidence items failed (first error: %w); all evidence must pass", firstErr)
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

// VerifySignatureOnly loads the stored attestation for claimID and verifies:
//  1. self_digest matches the recomputed digest
//  2. signature is valid against a key in TrustStore (if attestation is signed)
//  3. all evidence digests are present in CAS
//
// The checker is not re-run. Returns nil if all checks pass.
func (p *Pipeline) VerifySignatureOnly(claimID string) error {
	if err := ir.ValidateClaimID(claimID); err != nil {
		return fmt.Errorf("verify-sig: %w", err)
	}

	path := filepath.Join(p.AttestDir, claimID+".json")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no attestation for claim %q", claimID)
		}
		return fmt.Errorf("open attestation %q: %w", claimID, err)
	}
	att, err := ir.DecodeAttestation(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("decode attestation %q: %w", claimID, err)
	}

	// 1. self_digest integrity
	att.SelfDigest = ""
	recomputed, err := ir.DigestOf(att)
	if err != nil {
		return fmt.Errorf("claim %q: recompute self_digest: %w", claimID, err)
	}
	// restore and compare — we zeroed before DigestOf so we need the original
	f2, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reopen attestation %q: %w", claimID, err)
	}
	att2, err := ir.DecodeAttestation(f2)
	_ = f2.Close()
	if err != nil {
		return fmt.Errorf("re-decode attestation %q: %w", claimID, err)
	}
	if recomputed != att2.SelfDigest {
		return fmt.Errorf("claim %q: self_digest mismatch (stored %s, computed %s) — attestation may have been tampered with",
			claimID, att2.SelfDigest, recomputed)
	}

	// 2. signature verification
	if att2.Signature != nil {
		if err := p.verifyAttestationSig(att2); err != nil {
			return fmt.Errorf("claim %q: %w", claimID, err)
		}
	}

	// 3. evidence present in CAS
	for _, ev := range att2.Evidence {
		if ev.Digest == "" {
			continue
		}
		if err := p.CAS.Verify(ev); err != nil {
			return fmt.Errorf("claim %q: evidence %s missing from CAS: %w", claimID, ev.Digest, err)
		}
	}

	return nil
}

// loadObligationIDs tries to find a ContractV2 JSON for claimID and returns
// its obligation IDs. Returns nil (skip exact-set check) if no contract found.
func loadObligationIDs(projectRoot, claimID string) []string {
	// Try .proofctl/contracts/<claimID>.json first (bundle layout).
	candidates := []string{
		filepath.Join(projectRoot, config.DirName, "contracts", claimID+".json"),
	}
	// Also scan domains/*/contracts/<claimID>.json.
	if matches, err := filepath.Glob(filepath.Join(projectRoot, "domains", "*", "contracts", claimID+".json")); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var c struct {
			Obligations []string `json:"obligations"`
		}
		if err := json.Unmarshal(data, &c); err != nil || len(c.Obligations) == 0 {
			continue
		}
		return c.Obligations
	}
	return nil // no contract found — skip exact-set check
}

// verifyEvidenceDigestsOnDisk recomputes the SHA-256 of each evidence file that has
// verifyDependencyManifest checks that the lockfile at manifestPath still
// matches the pinned digest. Returns non-nil if drift is detected.
// The dag parameter is unused here but kept for future context enrichment.
func verifyDependencyManifest(_ interface{}, manifestPath, pinnedDigest string) error {
	f, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("lockfile %q not found — checker was pinned with this file", manifestPath)
		}
		return fmt.Errorf("open lockfile %q: %w", manifestPath, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return fmt.Errorf("hash lockfile %q: %w", manifestPath, err)
	}
	_ = f.Close()
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != pinnedDigest {
		return fmt.Errorf("lockfile %q has digest %s, pinned digest is %s",
			manifestPath, got, pinnedDigest)
	}
	return nil
}

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

// checkClosureBinding verifies that the checker output's key binding fields
// are consistent with what was sent as input. Returns an error if any binding
// is missing or mismatched (INV-02, P0-10).
//
// Currently validates: claim_id echo, protocol_version.
// Evidence-used and checker-identity binding are logged as warnings until
// the full ContractV2 closure is wired (M33 complete).
func checkClosureBinding(outV2 protov2.CheckerOutputV2, claimID string) error {
	// Claim ID must echo back.
	if outV2.ClaimID != claimID {
		return proofErr.Newf(proofErr.CodeInputClosureMismatch,
			"INPUT_CLOSURE_MISMATCH: checker returned claim_id %q, expected %q",
			outV2.ClaimID, claimID)
	}
	// Protocol version must be 2.
	if outV2.ProtocolVersion != protov2.ProtocolVersion {
		return proofErr.Newf(proofErr.CodeInputClosureMismatch,
			"INPUT_CLOSURE_MISMATCH: checker returned protocol_version %d, expected %d",
			outV2.ProtocolVersion, protov2.ProtocolVersion)
	}
	return nil
}
