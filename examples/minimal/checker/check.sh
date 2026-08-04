#!/usr/bin/env sh
# Minimal toy checker for examples/minimal.
# Accepts any certificate file and always returns "accepted".
# Real checkers would read $1 (the certificate path) and validate it.
#
# proofctl calls: sh checker/check.sh <cert-file>
# Output: JSON matching the proofctl checker protocol.

CERT="${1:-}"

printf '{"protocol_version":1,"claim_id":"","outcome":"accepted","assurance":"exact-replay","metadata":{"checker_name":"echo-checker-v1","cert_path":"%s"}}\n' "$CERT"
exit 0
