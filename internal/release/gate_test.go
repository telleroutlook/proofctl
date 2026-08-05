package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
)

// makeTestGraph builds a minimal DAG with 2 claims and corresponding attestations
// that satisfy a simple policy with no assurance constraints.
// Attestations include all metadata and freshness fields required by C04-C13.
func makeTestGraph(t *testing.T) (*dag.DAG, map[string]*ir.Attestation) {
	t.Helper()
	d := dag.New()
	for _, id := range []string{"c1", "c2"} {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "test"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        string(ir.StatusAccepted),
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:aabbccdd00112233",
			StartFreshness: "sha256:start1",
			EndFreshness:   "sha256:end1",
			Checker:        ir.CheckerIdentity{ProtocolVersion: 2},
			Metadata: map[string]string{
				"cap_format_version":   "v2",
				"digests_fresh":        "true",
				"path_keys_match":      "true",
				"intervals_intersect":  "true",
				"matrix_reconstructed": "true",
				"ldlt_passes":          "true",
				"odd_sector_passes":    "true",
				"even_sector_passes":   "true",
				"pivot_radius_ratio":   "150",
			},
		},
		"c2": {
			ClaimID:        "c2",
			Outcome:        string(ir.StatusAccepted),
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:eeff99887766554433221100",
			StartFreshness: "sha256:start2",
			EndFreshness:   "sha256:end2",
			Checker:        ir.CheckerIdentity{ProtocolVersion: 2},
		},
	}
	return d, atts
}

// simplePolicy returns a policy that requires c1 and c2, no assurance constraints.
func simplePolicy() policy.ReleasePolicy {
	return policy.ReleasePolicy{
		Version:        "v1",
		Target:         "test-target",
		RequiredClaims: []string{"c1", "c2"},
	}
}

// TestDryRunAllAccepted checks that DryRun passes when all claims are accepted.
func TestDryRunAllAccepted(t *testing.T) {
	t.Parallel()
	g := &Gate{OutputDir: t.TempDir()}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	pass, blockers := g.DryRun(graph, atts, pol)
	if !pass {
		t.Errorf("expected pass, got blockers: %v", blockers)
	}
	if len(blockers) != 0 {
		t.Errorf("expected empty blockers, got: %v", blockers)
	}
}

// TestDryRunRejectedClaim checks that DryRun fails when a claim is rejected.
func TestDryRunRejectedClaim(t *testing.T) {
	t.Parallel()
	g := &Gate{OutputDir: t.TempDir()}
	graph, atts := makeTestGraph(t)
	atts["c1"] = &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusRejected),
		Assurance: ir.AssuranceFormalKernel,
	}
	pol := simplePolicy()

	pass, blockers := g.DryRun(graph, atts, pol)
	if pass {
		t.Error("expected fail when a claim is rejected, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected non-empty blockers for rejected claim")
	}
}

// TestDryRunForbiddenAssurance checks that DryRun fails when a forbidden assurance is used.
func TestDryRunForbiddenAssurance(t *testing.T) {
	t.Parallel()
	g := &Gate{OutputDir: t.TempDir()}
	graph, atts := makeTestGraph(t)
	atts["c1"] = &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusAccepted),
		Assurance: ir.AssuranceAIReview,
	}
	pol := policy.ReleasePolicy{
		Version:             "v1",
		Target:              "test-target",
		RequiredClaims:      []string{"c1", "c2"},
		ForbiddenAssurances: []string{string(ir.AssuranceAIReview)},
	}

	pass, blockers := g.DryRun(graph, atts, pol)
	if pass {
		t.Error("expected fail for forbidden assurance, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker for forbidden assurance")
	}
}

// TestDryRunDoesNotWriteStatusFile checks that DryRun never writes STATUS.json.
func TestDryRunDoesNotWriteStatusFile(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	g.DryRun(graph, atts, pol)

	statusPath := filepath.Join(outDir, StatusFile)
	if _, err := os.Stat(statusPath); err == nil {
		t.Error("DryRun must not write STATUS.json")
	}
}

// TestReleasePassWritesStatusJSON checks that a passing Release writes STATUS.json with released=true.
func TestReleasePassWritesStatusJSON(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !pass {
		t.Errorf("expected pass, got blockers: %v", blockers)
	}

	statusPath := filepath.Join(outDir, StatusFile)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}

	var rs ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("unmarshal STATUS.json: %v", err)
	}
	if !rs.Released {
		t.Errorf("expected released=true, got false")
	}
	if len(rs.Blockers) != 0 {
		t.Errorf("expected no blockers in STATUS.json, got: %v", rs.Blockers)
	}
}

// TestReleaseFailWritesStatusJSON checks that a failing Release writes STATUS.json with released=false and blockers.
func TestReleaseFailWritesStatusJSON(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	atts["c1"] = &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusRejected),
		Assurance: ir.AssuranceFormalKernel,
	}
	pol := simplePolicy()

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("expected fail, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected non-empty blockers")
	}

	statusPath := filepath.Join(outDir, StatusFile)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}

	var rs ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("unmarshal STATUS.json: %v", err)
	}
	if rs.Released {
		t.Error("expected released=false in STATUS.json for failing gate")
	}
	if len(rs.Blockers) == 0 {
		t.Error("expected non-empty Blockers in STATUS.json")
	}
}

// TestReleaseStatusJSONIsValidJSON checks that STATUS.json is valid JSON with expected fields.
func TestReleaseStatusJSONIsValidJSON(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	if _, _, err := g.Release(graph, atts, pol, nil); err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outDir, StatusFile))
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}

	// Unmarshal into a generic map to verify all expected fields are present.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("STATUS.json is not valid JSON: %v", err)
	}
	for _, field := range []string{"released", "policy_version"} {
		if _, ok := m[field]; !ok {
			t.Errorf("STATUS.json missing field %q", field)
		}
	}
}

// TestReleaseTwiceOverwrites checks that a second Release call overwrites STATUS.json atomically.
func TestReleaseTwiceOverwrites(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	// First release: pass.
	if _, _, err := g.Release(graph, atts, pol, nil); err != nil {
		t.Fatalf("first Release: %v", err)
	}

	// Second release: fail (reject c1).
	atts["c1"] = &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusRejected),
		Assurance: ir.AssuranceFormalKernel,
	}
	if _, _, err := g.Release(graph, atts, pol, nil); err != nil {
		t.Fatalf("second Release: %v", err)
	}

	// The second result should now be in STATUS.json.
	data, err := os.ReadFile(filepath.Join(outDir, StatusFile))
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}
	var rs ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("unmarshal STATUS.json: %v", err)
	}
	if rs.Released {
		t.Error("expected second Release to overwrite with released=false")
	}

	// No leftover temp files should exist (STATUS.json and release-snapshot.json are expected).
	knownFiles := map[string]bool{StatusFile: true, SnapshotFile: true}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if !knownFiles[e.Name()] {
			t.Errorf("unexpected leftover file in OutputDir: %q", e.Name())
		}
	}
}

// TestReleaseTargetOnPass checks that ReleaseTarget is set to pol.Target on pass.
func TestReleaseTargetOnPass(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	if _, _, err := g.Release(graph, atts, pol, nil); err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(outDir, StatusFile))
	var rs ReleaseStatus
	json.Unmarshal(data, &rs) //nolint — already validated above
	if rs.ReleaseTarget != pol.Target {
		t.Errorf("ReleaseTarget: got %q want %q", rs.ReleaseTarget, pol.Target)
	}
}

// TestReleaseTargetEmptyOnFail checks that ReleaseTarget is empty on fail.
func TestReleaseTargetEmptyOnFail(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	atts["c1"] = &ir.Attestation{ClaimID: "c1", Outcome: string(ir.StatusRejected), Assurance: ir.AssuranceFormalKernel}
	pol := simplePolicy()

	if _, _, err := g.Release(graph, atts, pol, nil); err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(outDir, StatusFile))
	var rs ReleaseStatus
	json.Unmarshal(data, &rs) //nolint — already validated above
	if rs.ReleaseTarget != "" {
		t.Errorf("expected empty ReleaseTarget on fail, got %q", rs.ReleaseTarget)
	}
}

// TestRelease_ShadowModeBlocked verifies that when all attestations use shadow-review assurance
// (a forbidden type), DryRun returns false and blocked attestations with block reasons
// are surfaced in the defects map of STATUS.json.
func TestRelease_ShadowModeBlocked(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}

	d := dag.New()
	for _, id := range []string{"lem-d4-kernel-bound", "lem-ab-intersection", "thm-main-radius-030"} {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "theorem"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}

	const shadowAssurance ir.Assurance = "shadow-review"
	atts := map[string]*ir.Attestation{
		"lem-d4-kernel-bound": {
			ClaimID:     "lem-d4-kernel-bound",
			Outcome:     string(ir.StatusBlocked),
			Assurance:   shadowAssurance,
			BlockReason: "D4: kernel-bound expected primitive keys not matched; v1/v2 checker result conflict",
			Checker:     ir.CheckerIdentity{ProtocolVersion: 2},
		},
		"lem-ab-intersection": {
			ClaimID:     "lem-ab-intersection",
			Outcome:     string(ir.StatusBlocked),
			Assurance:   shadowAssurance,
			BlockReason: "D8: Path A keys and Path B keys share no common primitives; intersection empty",
			Checker:     ir.CheckerIdentity{ProtocolVersion: 2},
		},
		"thm-main-radius-030": {
			ClaimID:     "thm-main-radius-030",
			Outcome:     string(ir.StatusBlocked),
			Assurance:   shadowAssurance,
			BlockReason: "D18: thm-main-radius-030 blocked — D4 and D8 unresolved; no certified radius",
			Checker:     ir.CheckerIdentity{ProtocolVersion: 2},
		},
	}
	pol := policy.ReleasePolicy{
		Version:             "1",
		Target:              "thm-main-radius-030",
		RequiredClaims:      []string{"lem-d4-kernel-bound", "lem-ab-intersection", "thm-main-radius-030"},
		ForbiddenAssurances: []string{"shadow-review"},
	}

	// DryRun must return false.
	pass, blockers := g.DryRun(d, atts, pol)
	if pass {
		t.Error("DryRun: expected fail for shadow-review attestations, got pass")
	}
	if len(blockers) == 0 {
		t.Error("DryRun: expected non-empty blockers")
	}

	// Release must write STATUS.json with released=false and defects map populated.
	relPass, _, err := g.Release(d, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if relPass {
		t.Error("Release: expected fail, got pass")
	}

	data, err := os.ReadFile(filepath.Join(outDir, StatusFile))
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}
	var rs ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("unmarshal STATUS.json: %v", err)
	}
	if rs.Released {
		t.Error("STATUS.json: expected released=false")
	}
	if len(rs.Defects) == 0 {
		t.Error("STATUS.json: expected non-empty defects map for blocked shadow attestations")
	}
	// Verify D4 and D8 block reasons are surfaced.
	for _, claimID := range []string{"lem-d4-kernel-bound", "lem-ab-intersection", "thm-main-radius-030"} {
		if reason, ok := rs.Defects[claimID]; !ok || reason == "" {
			t.Errorf("STATUS.json: defects[%q] missing or empty", claimID)
		}
	}
}
