package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/status"
)

func cmdStatus(_ []string, useJSON bool) {
	_, _, g, attestations := loadProjectGraph(useJSON)

	statuses := status.Compute(g, attestations)

	topoOrder, topoErr := topoSort(g)
	if topoErr != nil {
		topoOrder = make([]string, 0, len(statuses))
		for id := range statuses {
			topoOrder = append(topoOrder, id)
		}
		sort.Strings(topoOrder)
	}

	if useJSON {
		type claimStatusEntry struct {
			Status      string `json:"status"`
			BlockReason string `json:"block_reason,omitempty"`
		}
		claimsMap := make(map[string]claimStatusEntry, len(statuses))
		for id, s := range statuses {
			entry := claimStatusEntry{Status: string(s)}
			if att, ok := attestations[id]; ok && att.BlockReason != "" {
				entry.BlockReason = att.BlockReason
			}
			claimsMap[id] = entry
		}
		type summaryEntry struct {
			Accepted int `json:"accepted"`
			Blocked  int `json:"blocked"`
			Open     int `json:"open"`
			Rejected int `json:"rejected"`
		}
		var summ summaryEntry
		for _, s := range statuses {
			switch s {
			case ir.StatusAccepted:
				summ.Accepted++
			case ir.StatusBlocked:
				summ.Blocked++
			case ir.StatusOpen:
				summ.Open++
			case ir.StatusRejected:
				summ.Rejected++
			}
		}
		type statusOutput struct {
			Claims        map[string]claimStatusEntry `json:"claims"`
			Summary       summaryEntry                `json:"summary"`
			ReleaseTarget interface{}                 `json:"release_target"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(statusOutput{Claims: claimsMap, Summary: summ, ReleaseTarget: nil})
		return
	}

	fmt.Println("Proof Graph Status")
	fmt.Println("==================")

	var accepted, open, blocked, rejected int
	for _, id := range topoOrder {
		s := statuses[id]
		switch s {
		case ir.StatusAccepted:
			accepted++
		case ir.StatusOpen:
			open++
		case ir.StatusBlocked:
			blocked++
		case ir.StatusRejected:
			rejected++
		}
		reason := ""
		if att, ok := attestations[id]; ok && att.BlockReason != "" {
			reason = "  " + att.BlockReason
		} else if s == ir.StatusOpen {
			reason = "  (no attestation)"
		}
		fmt.Printf("%-40s %-10s%s\n", id, strings.ToUpper(string(s)), reason)
	}
	fmt.Printf("\nSummary: %d accepted, %d blocked, %d open, %d rejected\n",
		accepted, blocked, open, rejected)
	fmt.Println("release_target: null")
}
