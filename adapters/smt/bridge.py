#!/usr/bin/env python3
"""
SMT checker bridge for proofctl.

Supports two proof formats:
  --format alethe   Alethe proof format (cvc5 / veriT output)
  --format drat     DRAT/LRAT-adjacent SAT refutation proof

Usage:
    bridge.py [--format alethe|drat] <cert-file>

The cert-file is a JSON object with fields:
    smt_file    - path to the SMT-LIB2 problem file (.smt2)
    proof_file  - path to the proof certificate
    format      - "alethe" or "drat" (overrides --format flag)

Exit codes:
    0  proof verified
    1  proof rejected or verification failed
    2  checker unavailable (required tool not in PATH)
    3  protocol error (bad cert-file format)
"""
import argparse
import json
import os
import subprocess
import sys

# Supported formats and their verifier commands.
_VERIFIERS = {
    "alethe": ["verit-checker"],
    "drat":   ["drat-trim"],
}


def _checker_version(tool: str) -> str:
    """Return the version of a tool, or 'unknown'."""
    try:
        result = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, timeout=10
        )
        first_line = (result.stdout + result.stderr).splitlines()
        return first_line[0].strip() if first_line else "unknown"
    except Exception:
        return "unknown"


def _output(outcome: str, claim_id: str, metadata: dict) -> None:
    print(json.dumps({
        "protocol_version": 1,
        "claim_id": claim_id,
        "outcome": outcome,
        "assurance": "formal-kernel",
        "metadata": metadata,
    }))


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--format", default="alethe", choices=["alethe", "drat"])
    parser.add_argument("cert_file", nargs="?", default="")
    args, _ = parser.parse_known_args()

    cert_path = args.cert_file
    if not cert_path and len(sys.argv) > 1:
        # Fallback: last positional arg.
        cert_path = sys.argv[-1]

    if not cert_path:
        _output("error", "", {"error": "usage: bridge.py [--format alethe|drat] <cert-file>"})
        return 3

    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _output("error", "", {"error": f"cannot read cert-file: {exc}"})
        return 3

    smt_file = cert.get("smt_file", "")
    proof_file = cert.get("proof_file", "")
    fmt = cert.get("format", args.format)
    claim_id = cert.get("claim_id", "")

    if not smt_file or not proof_file:
        _output("error", claim_id, {"error": "cert-file must contain 'smt_file' and 'proof_file'"})
        return 3

    for path, name in [(smt_file, "smt_file"), (proof_file, "proof_file")]:
        if not os.path.isfile(path):
            _output("error", claim_id, {"error": f"{name} not found: {path}"})
            return 3

    if fmt not in _VERIFIERS:
        _output("error", claim_id, {"error": f"unsupported format: {fmt}"})
        return 3

    tool = _VERIFIERS[fmt][0]

    # Check tool availability.
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=10, check=False)
    except FileNotFoundError:
        _output("error", claim_id, {"error": f"{tool} not found in PATH (required for {fmt} format)"})
        return 2

    version = _checker_version(tool)

    # Run verifier.
    if fmt == "alethe":
        cmd = [tool, smt_file, proof_file]
    else:  # drat
        cmd = [tool, smt_file, proof_file]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        _output("rejected", claim_id, {
            "format": fmt,
            "smt_file": smt_file,
            "proof_file": proof_file,
            "error": f"{tool} timed out",
        })
        return 1
    except Exception as exc:
        _output("error", claim_id, {"error": f"{tool} execution error: {exc}"})
        return 2

    # Interpret exit code: 0 = verified, non-zero = rejected.
    if result.returncode == 0:
        _output("accepted", claim_id, {
            f"{fmt}_checker_version": version,
            "format": fmt,
            "smt_file": smt_file,
            "proof_file": proof_file,
        })
        return 0
    else:
        error_lines = (result.stdout + result.stderr).splitlines()
        _output("rejected", claim_id, {
            f"{fmt}_checker_version": version,
            "format": fmt,
            "smt_file": smt_file,
            "proof_file": proof_file,
            "error": "; ".join(error_lines[:3]),
        })
        return 1


if __name__ == "__main__":
    sys.exit(main())
