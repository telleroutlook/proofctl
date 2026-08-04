#!/usr/bin/env sh
# Minimal toy checker for examples/minimal.
# Accepts any certificate file and always returns "accepted".
# Real checkers would read $1 (the certificate path) and validate it.
#
# proofctl calls: sh checker/check.sh <cert-file>
# stdin: JSON containing at least {"claim_id": "<id>", ...}
# Output: JSON matching the proofctl checker protocol v2.

CERT="${1:-}"

CLAIM_ID=$(python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('claim_id',''))" 2>/dev/null || true)

printf '{"protocol_version":2,"claim_id":"%s","input_closure_digest":"","checker_identity_digest":"","runtime_identity_digest":"","evidence_used":[],"obligation_results":[{"id":"cap.checker-pass","verdict":"pass"}]}\n' "$CLAIM_ID"
exit 0
