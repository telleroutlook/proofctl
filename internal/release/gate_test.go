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
			ClaimID:   "c1",
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceFormalKernel,
		},
		"c2": {
			ClaimID:   "c2",
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceFormalKernel,
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

	pass, blockers, err := g.Release(graph, atts, pol)
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

	pass, blockers, err := g.Release(graph, atts, pol)
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

	if _, _, err := g.Release(graph, atts, pol); err != nil {
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
	if _, _, err := g.Release(graph, atts, pol); err != nil {
		t.Fatalf("first Release: %v", err)
	}

	// Second release: fail (reject c1).
	atts["c1"] = &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusRejected),
		Assurance: ir.AssuranceFormalKernel,
	}
	if _, _, err := g.Release(graph, atts, pol); err != nil {
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

	// No leftover temp files should exist.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != StatusFile {
			t.Errorf("unexpected leftover file in OutputDir: %q", e.Name())
		}
	}
}

// TestReleaseCertifiedRadiusOnPass checks that CertifiedRadius is set to Target on pass.
func TestReleaseCertifiedRadiusOnPass(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	pol := simplePolicy()

	if _, _, err := g.Release(graph, atts, pol); err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(outDir, StatusFile))
	var rs ReleaseStatus
	json.Unmarshal(data, &rs) //nolint — already validated above
	if rs.CertifiedRadius != pol.Target {
		t.Errorf("CertifiedRadius: got %q want %q", rs.CertifiedRadius, pol.Target)
	}
}

// TestReleaseCertifiedRadiusEmptyOnFail checks that CertifiedRadius is empty on fail.
func TestReleaseCertifiedRadiusEmptyOnFail(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &Gate{OutputDir: outDir}
	graph, atts := makeTestGraph(t)
	atts["c1"] = &ir.Attestation{ClaimID: "c1", Outcome: string(ir.StatusRejected), Assurance: ir.AssuranceFormalKernel}
	pol := simplePolicy()

	if _, _, err := g.Release(graph, atts, pol); err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(outDir, StatusFile))
	var rs ReleaseStatus
	json.Unmarshal(data, &rs) //nolint — already validated above
	if rs.CertifiedRadius != "" {
		t.Errorf("expected empty CertifiedRadius on fail, got %q", rs.CertifiedRadius)
	}
}
