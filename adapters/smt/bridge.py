#!/usr/bin/env python3
"""
SMT checker bridge — proofctl wire protocol v2 adapter.

Reads CheckerInputV2 JSON from stdin; writes CheckerOutputV2 JSON to stdout.

Supports two proof formats:
  alethe   Alethe proof format (cvc5 / veriT output)
  drat     DRAT/LRAT-adjacent SAT refutation proof

The cert-file (first evidence item with a valid local_path) is a JSON object:
    smt_file      - path to the SMT-LIB2 problem file (.smt2)
    proof_file    - path to the proof certificate (required unless formula_only)
    format        - "alethe" or "drat" (default: "alethe")
    formula_only  - true to check formula well-formedness only (no proof)

Obligations produced:
    formula_only=true   smt.formula-well-formed
    otherwise           smt.proof-checker-accepts, smt.unsat-witness-valid

Exit codes:
    0  obligation results written (pass or fail)
    2  checker tool not available (CheckerErrorV2)
    3  protocol error / bad input (CheckerErrorV2)

BRIDGE_CHECKER env var overrides the default tool selection.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PROTOCOL_VERSION = 2

_VERIFIERS = {
    "alethe": "verit-checker",
    "drat":   "drat-trim",
}

_FORMULA_OBLIGATIONS = ["smt.formula-well-formed"]
_PROOF_OBLIGATIONS   = ["smt.proof-checker-accepts", "smt.unsat-witness-valid"]


def _checker_identity() -> str:
    """Return sha256 digest of this script file."""
    try:
        data = Path(__file__).read_bytes()
        return "sha256:" + hashlib.sha256(data).hexdigest()
    except Exception:
        return ""


def _input_closure_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _checker_version(tool: str) -> str:
    try:
        r = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, timeout=10
        )
        lines = (r.stdout + r.stderr).splitlines()
        return lines[0].strip() if lines else "unknown"
    except Exception:
        return "unknown"


def _error_out(claim_id: str, code: str, message: str) -> None:
    """Write CheckerErrorV2 to stdout."""
    print(json.dumps({
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "code": code,
        "message": message,
    }))


def _find_cert(evidence: list) -> "Path | None":
    """Return the path of the first evidence item with a valid local_path."""
    for item in evidence:
        lp = item.get("local_path", "")
        if lp and Path(lp).exists():
            return Path(lp)
    return None


def _write_output(
    claim_id: str,
    closure_digest: str,
    obl_results: list,
    toolchain: dict,
    evidence: list,
) -> None:
    evidence_used = [
        item["digest"]
        for item in evidence
        if item.get("digest") and item.get("local_path")
        and Path(item["local_path"]).exists()
    ]
    print(json.dumps({
        "protocol_version":        PROTOCOL_VERSION,
        "claim_id":                claim_id,
        "input_closure_digest":    closure_digest,
        "checker_identity_digest": _checker_identity(),
        "runtime_identity_digest": "",
        "evidence_used":           evidence_used,
        "obligation_results":      obl_results,
        "toolchain":               toolchain,
    }))


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        inp = json.loads(raw)
    except json.JSONDecodeError as e:
        _error_out("", "MALFORMED_INPUT", f"cannot parse CheckerInputV2 JSON: {e}")
        return 3

    claim_id       = inp.get("claim_id", "")
    evidence       = inp.get("evidence", [])
    obligation_ids = inp.get("obligation_ids", [])
    closure_digest = _input_closure_digest(raw)

    # Locate cert file from evidence.
    cert_path = _find_cert(evidence)
    if cert_path is None:
        _error_out(claim_id, "EVIDENCE_NOT_FOUND",
                   "no evidence item has a valid local_path")
        return 3

    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as e:
        _error_out(claim_id, "CERT_READ_ERROR",
                   f"cannot read cert file {cert_path}: {e}")
        return 3

    smt_file     = cert.get("smt_file", "")
    proof_file   = cert.get("proof_file", "")
    fmt          = cert.get("format", "alethe")
    formula_only = bool(cert.get("formula_only", False))

    # Validate required fields.
    if not smt_file:
        _error_out(claim_id, "MISSING_SMT_FILE",
                   "cert must contain 'smt_file'")
        return 3

    if not os.path.isfile(smt_file):
        _error_out(claim_id, "SMT_FILE_NOT_FOUND",
                   f"smt_file not found: {smt_file}")
        return 3

    if not formula_only:
        if not proof_file:
            _error_out(claim_id, "MISSING_PROOF_FILE",
                       "cert must contain 'proof_file' when formula_only is not set")
            return 3
        if not os.path.isfile(proof_file):
            _error_out(claim_id, "PROOF_FILE_NOT_FOUND",
                       f"proof_file not found: {proof_file}")
            return 3

    # Resolve verifier tool: BRIDGE_CHECKER overrides format-based default.
    tool = os.environ.get("BRIDGE_CHECKER", "") or _VERIFIERS.get(fmt, "")
    if not tool:
        _error_out(claim_id, "UNSUPPORTED_FORMAT",
                   f"no verifier known for format '{fmt}' and BRIDGE_CHECKER is not set")
        return 3

    # Check tool availability.
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=10, check=False)
    except FileNotFoundError:
        _error_out(claim_id, "CHECKER_NOT_FOUND",
                   f"verifier '{tool}' not found in PATH (required for {fmt} format)")
        return 2

    version  = _checker_version(tool)
    toolchain = {"smt_checker_version": version, "format": fmt}

    # Build verifier command.
    # formula_only: verify the SMT2 file alone (well-formedness check).
    # full proof:   verify smt_file against proof_file.
    cmd = [tool, smt_file] if formula_only else [tool, smt_file, proof_file]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        obl_results = [
            {"id": oid, "verdict": "fail", "method": f"{fmt}-timeout"}
            for oid in obligation_ids
        ]
        _write_output(claim_id, closure_digest, obl_results, toolchain, evidence)
        return 0
    except Exception as e:
        _error_out(claim_id, "CHECKER_EXEC_ERROR",
                   f"verifier '{tool}' execution error: {e}")
        return 2

    # Map verifier exit code to obligation verdicts.
    # exit 0 = all obligations pass; non-zero = all obligations fail.
    method  = f"{fmt}-verify"
    verdict = "pass" if proc.returncode == 0 else "fail"
    obl_results = [
        {"id": oid, "verdict": verdict, "method": method}
        for oid in obligation_ids
    ]

    _write_output(claim_id, closure_digest, obl_results, toolchain, evidence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
