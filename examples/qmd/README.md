# QMD Adapter Example

This directory contains an example Pandoc JSON document that demonstrates
the QMD adapter for the ProofGraph Engine.

## File

- `example.pandoc.json` — a minimal Pandoc JSON document with three claims:

| Claim ID | Kind | Depends On |
|---|---|---|
| `def-example-frozen` | definition | (none) |
| `lem-example-step1` | computational-lemma | `def-example-frozen` |
| `thm-example-main` | theorem | `lem-example-step1` |

## Usage

Compile this document to ProofGraph IR:

```
proofctl compile --adapter qmd examples/qmd/example.pandoc.json
```

## Format Notes

The Pandoc JSON format used here follows Pandoc API version 1.23.1.
Each claim is represented as a `Div` block with the `claim` class.
Claim metadata is stored as key-value attributes on the `Div`.

The QMD adapter reads this format and extracts claims into the ProofGraph IR.
It does not write status back to the source file — status is tracked separately
in the `.proofctl/` directory.
