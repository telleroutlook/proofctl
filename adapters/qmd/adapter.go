// Package qmd implements the QMD/Pandoc claim graph adapter.
// It extracts mathematical claims from a Pandoc JSON document and
// compiles them into ProofGraph IR. This adapter is a frontend only —
// it never produces certification conclusions.
package qmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// AdapterIdentity records the adapter version and Pandoc API version
// for cache-key computation. Any change here invalidates the IR cache.
type AdapterIdentity struct {
	AdapterVersion   string `json:"adapter_version"`
	PandocAPIVersion []int  `json:"pandoc_api_version"`
}

// Digest returns the sha256 digest of the adapter identity for cache keys.
func (a *AdapterIdentity) Digest() string {
	data, _ := json.Marshal(a)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Adapter extracts ProofGraph IR from Pandoc JSON documents.
type Adapter struct {
	Identity AdapterIdentity
}

// DefaultAdapter returns an Adapter with the current version.
func DefaultAdapter() *Adapter {
	return &Adapter{
		Identity: AdapterIdentity{
			AdapterVersion: "1",
		},
	}
}

// pandocDoc is the minimal Pandoc JSON top-level structure we parse.
type pandocDoc struct {
	PandocAPIVersion []int          `json:"pandoc-api-version"`
	Meta             map[string]any `json:"meta"`
	Blocks           []pandocBlock  `json:"blocks"`
}

// pandocBlock represents any Pandoc block element.
// The type tag is in T, content in C (raw JSON for flexible parsing).
type pandocBlock struct {
	T string          `json:"t"`
	C json.RawMessage `json:"c"`
}

// pandocInline represents any Pandoc inline element.
type pandocInline struct {
	T string          `json:"t"`
	C json.RawMessage `json:"c"`
}

// Compile parses a Pandoc JSON document and returns a ProofGraph.
// The same input always produces the same output (deterministic).
// Pandoc version is extracted from the document and stored in a.Identity.PandocAPIVersion.
func (a *Adapter) Compile(pandocJSON []byte) (*ir.ProofGraph, error) {
	var doc pandocDoc
	if err := json.Unmarshal(pandocJSON, &doc); err != nil {
		return nil, fmt.Errorf("qmd: cannot parse pandoc JSON: %w", err)
	}

	// Store Pandoc API version in the adapter identity.
	a.Identity.PandocAPIVersion = doc.PandocAPIVersion

	var claims []ir.Claim
	if err := walkBlocks(doc.Blocks, &claims); err != nil {
		return nil, err
	}

	return &ir.ProofGraph{Claims: claims}, nil
}

// VerifyDeterminism compiles src twice and returns an error if the IR differs.
func (a *Adapter) VerifyDeterminism(src []byte) error {
	g1, err := a.Compile(src)
	if err != nil {
		return err
	}
	g2, err := a.Compile(src)
	if err != nil {
		return err
	}
	d1, _ := json.Marshal(g1)
	d2, _ := json.Marshal(g2)
	if !bytes.Equal(d1, d2) {
		return fmt.Errorf("qmd: non-deterministic output detected")
	}
	return nil
}

// walkBlocks recursively walks a slice of Pandoc blocks and appends any
// claims found in Div blocks with class "claim" to claims.
func walkBlocks(blocks []pandocBlock, claims *[]ir.Claim) error {
	for _, b := range blocks {
		switch b.T {
		case "Div":
			claim, inner, err := parseDivBlock(b.C)
			if err != nil {
				return err
			}
			if claim != nil {
				// claim with empty ID is skipped silently.
				if claim.ID != "" {
					*claims = append(*claims, *claim)
				}
			}
			// Recurse into inner blocks regardless (a Div may contain more Divs).
			if inner != nil {
				if err := walkBlocks(inner, claims); err != nil {
					return err
				}
			}
		case "Header":
			// Headers may contain nested blocks in their content; no claims directly.
		default:
			// Other block types (Para, BulletList, etc.) are not claim containers.
		}
	}
	return nil
}

// divAttr holds the attributes extracted from a Div's attr triple.
type divAttr struct {
	id      string
	classes []string
	kvs     map[string]string
}

// parseDivAttrs parses the Pandoc Attr triple: [id, [classes], [[k,v], ...]].
func parseDivAttrs(raw json.RawMessage) (divAttr, error) {
	// Pandoc Attr is a 3-element array: [id, classes, kvpairs]
	var triple [3]json.RawMessage
	if err := json.Unmarshal(raw, &triple); err != nil {
		return divAttr{}, fmt.Errorf("qmd: cannot parse div attr triple: %w", err)
	}

	var id string
	if err := json.Unmarshal(triple[0], &id); err != nil {
		return divAttr{}, fmt.Errorf("qmd: cannot parse div id: %w", err)
	}

	var classes []string
	if err := json.Unmarshal(triple[1], &classes); err != nil {
		return divAttr{}, fmt.Errorf("qmd: cannot parse div classes: %w", err)
	}

	var kvRaw [][]string
	if err := json.Unmarshal(triple[2], &kvRaw); err != nil {
		return divAttr{}, fmt.Errorf("qmd: cannot parse div kv pairs: %w", err)
	}
	kvs := make(map[string]string, len(kvRaw))
	for _, pair := range kvRaw {
		if len(pair) == 2 {
			kvs[pair[0]] = pair[1]
		}
	}

	return divAttr{id: id, classes: classes, kvs: kvs}, nil
}

// parseDivBlock parses the content of a Div block.
// Returns the extracted claim (nil if not a "claim" div), the inner blocks, and any error.
// A claim with an empty ID is returned as a non-nil claim with empty ID so the caller
// can decide to skip it.
func parseDivBlock(rawC json.RawMessage) (*ir.Claim, []pandocBlock, error) {
	// Pandoc Div content is [Attr, [Block]]
	var divContent [2]json.RawMessage
	if err := json.Unmarshal(rawC, &divContent); err != nil {
		return nil, nil, fmt.Errorf("qmd: cannot parse div content: %w", err)
	}

	attr, err := parseDivAttrs(divContent[0])
	if err != nil {
		return nil, nil, err
	}

	var innerBlocks []pandocBlock
	if err := json.Unmarshal(divContent[1], &innerBlocks); err != nil {
		return nil, nil, fmt.Errorf("qmd: cannot parse div inner blocks: %w", err)
	}

	// Only process divs with "claim" class.
	isClaim := false
	for _, cls := range attr.classes {
		if cls == "claim" {
			isClaim = true
			break
		}
	}
	if !isClaim {
		return nil, innerBlocks, nil
	}

	// Extract claim fields.
	kind := attr.kvs["kind"]
	if kind == "" {
		kind = "lemma"
	}

	var dependsOn []string
	if raw, ok := attr.kvs["depends-on"]; ok && raw != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				dependsOn = append(dependsOn, part)
			}
		}
	}

	var requiredAssurance []string
	if raw, ok := attr.kvs["required-assurance"]; ok && raw != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				requiredAssurance = append(requiredAssurance, part)
			}
		}
	}

	checkerPolicy := attr.kvs["checker-policy"]

	// Extract statement text from first Para block.
	text := extractFirstParaText(innerBlocks)
	digest := ir.StatementDigest(text)

	claim := &ir.Claim{
		ID:   attr.id,
		Kind: kind,
		Statement: ir.Statement{
			Text:   text,
			Digest: digest,
		},
		DependsOn:         dependsOn,
		RequiredAssurance: requiredAssurance,
		CheckerPolicy:     checkerPolicy,
	}

	return claim, innerBlocks, nil
}

// extractFirstParaText returns the plain text of the first Para block in blocks.
func extractFirstParaText(blocks []pandocBlock) string {
	for _, b := range blocks {
		if b.T == "Para" {
			var inlines []pandocInline
			if err := json.Unmarshal(b.C, &inlines); err != nil {
				return ""
			}
			return extractInlineText(inlines)
		}
	}
	return ""
}

// extractInlineText concatenates text from Pandoc inline nodes.
// Handles: Str, Space, SoftBreak, LineBreak, Code, Math.
func extractInlineText(inlines []pandocInline) string {
	var sb strings.Builder
	for _, node := range inlines {
		switch node.T {
		case "Str":
			var s string
			if err := json.Unmarshal(node.C, &s); err == nil {
				sb.WriteString(s)
			}
		case "Space":
			sb.WriteString(" ")
		case "SoftBreak", "LineBreak":
			sb.WriteString(" ")
		case "Code":
			// Code is [Attr, String]; we want the string.
			var codeContent [2]json.RawMessage
			if err := json.Unmarshal(node.C, &codeContent); err == nil {
				var s string
				if err := json.Unmarshal(codeContent[1], &s); err == nil {
					sb.WriteString(s)
				}
			}
		case "Math":
			// Math is [MathType, String]; we want the string.
			var mathContent [2]json.RawMessage
			if err := json.Unmarshal(node.C, &mathContent); err == nil {
				var s string
				if err := json.Unmarshal(mathContent[1], &s); err == nil {
					sb.WriteString(s)
				}
			}
		}
	}
	return sb.String()
}
