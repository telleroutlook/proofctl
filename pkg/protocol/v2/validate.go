// Package v2 — validate.go implements strict output validation for checker protocol v2.
//
// ValidateOutput enforces the exact-set obligation rule (INV-06) and ensures that
// a checker cannot smuggle acceptance by returning unexpected fields or extra IDs.
package v2

import (
	"fmt"
	"sort"
	"strings"
)

// ValidateOutput validates a CheckerOutputV2 against the expected contract.
//
// Parameters:
//   - out: the checker output to validate
//   - claimID: the claim ID that was passed to the checker (for echo check)
//   - expectedObligationIDs: the exact set of obligation IDs declared in the Contract
//
// Errors returned use code prefixes matching the Canvas §8.3 strict rejection rules:
//   - PROTOCOL_VERSION: version mismatch
//   - CLAIM_ID_MISMATCH: claim_id not echoed correctly
//   - OBLIGATION_MISSING: one or more expected IDs absent from results
//   - OBLIGATION_EXTRA: one or more unexpected IDs present in results
//   - OBLIGATION_DUPLICATE: same ID appears more than once
//   - VERDICT_INVALID: verdict is not "pass" or "fail"
func ValidateOutput(out CheckerOutputV2, claimID string, expectedObligationIDs []string) error {
	// Protocol version check.
	if out.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("PROTOCOL_VERSION: got %d, want %d", out.ProtocolVersion, ProtocolVersion)
	}

	// Claim ID echo check.
	if out.ClaimID != claimID {
		return fmt.Errorf("CLAIM_ID_MISMATCH: checker returned claim_id %q, expected %q", out.ClaimID, claimID)
	}

	// Validate each verdict value.
	for i, r := range out.ObligationResults {
		if r.Verdict != VerdictPass && r.Verdict != VerdictFail {
			return fmt.Errorf("VERDICT_INVALID: obligation[%d] id=%q has verdict %q (must be %q or %q)",
				i, r.ID, r.Verdict, VerdictPass, VerdictFail)
		}
	}

	// Build expected set. If nil, obligation set check is skipped (used when
	// Contract-driven obligation IDs are not yet wired in — only protocol/claim
	// validation runs).
	if expectedObligationIDs == nil {
		return nil
	}
	expected := make(map[string]struct{}, len(expectedObligationIDs))
	for _, id := range expectedObligationIDs {
		expected[id] = struct{}{}
	}

	// Build returned set and check for duplicates.
	returned := make(map[string]int, len(out.ObligationResults))
	for _, r := range out.ObligationResults {
		returned[r.ID]++
	}

	// Check for duplicates.
	var duplicates []string
	for id, count := range returned {
		if count > 1 {
			duplicates = append(duplicates, id)
		}
	}
	if len(duplicates) > 0 {
		sort.Strings(duplicates)
		return fmt.Errorf("OBLIGATION_DUPLICATE: duplicate obligation IDs: %s", strings.Join(duplicates, ", "))
	}

	// Check for missing IDs (in expected but not in returned).
	var missing []string
	for id := range expected {
		if _, ok := returned[id]; !ok {
			missing = append(missing, id)
		}
	}

	// Check for extra IDs (in returned but not in expected).
	var extra []string
	for id := range returned {
		if _, ok := expected[id]; !ok {
			extra = append(extra, id)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("OBLIGATION_MISSING: expected obligation IDs not returned: %s", strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("OBLIGATION_EXTRA: unexpected obligation IDs in result: %s (INV-06: must be exact set)", strings.Join(extra, ", "))
	}

	return nil
}

// AllObligationsPass returns true iff every ObligationResult has verdict "pass".
// Callers must first call ValidateOutput to ensure the set is valid.
func AllObligationsPass(out CheckerOutputV2) bool {
	if len(out.ObligationResults) == 0 {
		return false // OBLIGATION_EMPTY: empty results cannot constitute a pass
	}
	for _, r := range out.ObligationResults {
		if r.Verdict != VerdictPass {
			return false
		}
	}
	return true
}
