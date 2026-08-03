package protocol_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/pkg/protocol"
)

func TestIsBatchOutput_True(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		[]byte(`{"claims":[{"claim_id":"x","ok":true}]}`),
		[]byte(`{"claims":[],"resources":{}}`),
	}
	for _, c := range cases {
		if !protocol.IsBatchOutput(c) {
			t.Errorf("IsBatchOutput(%q) = false, want true", c)
		}
	}
}

func TestIsBatchOutput_False(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		[]byte(`{"outcome":"accepted","claim_id":"x"}`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`not json`),
	}
	for _, c := range cases {
		if protocol.IsBatchOutput(c) {
			t.Errorf("IsBatchOutput(%q) = true, want false", c)
		}
	}
}

func TestBatchResult_ClaimResult_Fields(t *testing.T) {
	t.Parallel()
	cr := protocol.ClaimResult{
		ClaimID:   "thm-main",
		OK:        true,
		Assurance: "formal-kernel",
		Metadata:  map[string]string{"lean_version": "4.14.0"},
	}
	if cr.ClaimID != "thm-main" || !cr.OK || cr.Assurance != "formal-kernel" {
		t.Errorf("unexpected ClaimResult fields: %+v", cr)
	}
}
