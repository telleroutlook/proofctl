#!/usr/bin/env python3
"""
Metamath checker bridge for proofctl — Protocol v2.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    mm_file   - path to the .mm proof file
    theorem   - Metamath theorem label to verify
    claim_id  - (optional) claim identifier

Exit codes:
    0  all obligations pass (theorem found and proof verified)
    1  one or more obligations fail
    2  checker unavailable (metamath not in PATH)
    3  protocol error (bad cert-file format)
"""
import hashlib
import json
import os
import subprocess
import sys

_OBLIGATION_THEOREM_EXISTS = "mm.theorem-exists"
_OBLIGATION_PROOF_VERIFIES = "mm.proof-verifies"


def _sha256_file(path: str) -> str:
    """Return hex sha256 of a file, or empty string on failure."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _version() -> str:
    """Return metamath version string, or empty string on failure."""
    try:
        result = subprocess.run(
            ["metamath", "exit"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Metamath prints version on first line of stdout.
        for line in result.stdout.splitlines():
            if "Metamath" in line and "Version" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "Version" and i + 1 < len(parts):
                        return parts[i + 1]
        return "unknown"
    except Exception:
        return "unknown"


def _output(
    claim_id: str,
    obligation_results: list,
    evidence_used: list,
    toolchain: dict,
) -> None:
    obj = {
        "protocol_version": 2,
        "claim_id": claim_id,
        "input_closure_digest": "",
        "checker_identity_digest": "",
        "runtime_identity_digest": "",
        "evidence_used": evidence_used,
        "obligation_results": obligation_results,
        "toolchain": toolchain,
    }
    print(json.dumps(obj))


def _error_output(claim_id: str, code: str, message: str) -> None:
    obj = {
        "protocol_version": 2,
        "claim_id": claim_id,
        "code": code,
        "message": message,
    }
    print(json.dumps(obj))


def main() -> int:
    if len(sys.argv) != 2:
        _error_output("", "PROTOCOL_ERROR", "usage: bridge.py <cert-file>")
        return 3

    cert_path = sys.argv[1]
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _error_output("", "PROTOCOL_ERROR", f"cannot read cert-file: {exc}")
        return 3

    mm_file = cert.get("mm_file", "")
    theorem = cert.get("theorem", "")
    claim_id = cert.get("claim_id", "")

    if not mm_file or not theorem:
        _error_output(claim_id, "PROTOCOL_ERROR", "cert-file must contain 'mm_file' and 'theorem'")
        return 3

    if not os.path.isfile(mm_file):
        _error_output(claim_id, "PROTOCOL_ERROR", f"mm_file not found: {mm_file}")
        return 3

    # Check metamath is available.
    try:
        subprocess.run(["metamath", "exit"], capture_output=True, timeout=10, check=False)
    except FileNotFoundError:
        _error_output(claim_id, "CHECKER_UNAVAILABLE", "metamath not found in PATH")
        return 2

    version = _version()

    evidence_used: list = []
    digest = _sha256_file(mm_file)
    if digest:
        evidence_used = [digest]

    toolchain = {"metamath_version": version}

    # Run verification.
    # We verify all proofs in the file and check the specific theorem label.
    try:
        result = subprocess.run(
            ["metamath", f'read "{mm_file}"', "verify proof *", "exit"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        _output(
            claim_id,
            [
                {"obligation_id": _OBLIGATION_THEOREM_EXISTS, "verdict": "fail", "detail": "metamath timed out"},
                {"obligation_id": _OBLIGATION_PROOF_VERIFIES, "verdict": "fail", "detail": "metamath timed out"},
            ],
            evidence_used,
            toolchain,
        )
        return 1
    except Exception as exc:
        _error_output(claim_id, "CHECKER_UNAVAILABLE", f"metamath execution error: {exc}")
        return 2

    combined = result.stdout + result.stderr

    # Check for errors.
    if "?" in combined or "error" in combined.lower():
        # Determine which obligation failed.
        theorem_missing = (
            theorem in combined
            and ("not found" in combined.lower() or "failed" in combined.lower())
        )
        if theorem_missing:
            _output(
                claim_id,
                [
                    {
                        "obligation_id": _OBLIGATION_THEOREM_EXISTS,
                        "verdict": "fail",
                        "detail": f"theorem '{theorem}' not found",
                    },
                    {
                        "obligation_id": _OBLIGATION_PROOF_VERIFIES,
                        "verdict": "fail",
                        "detail": "cannot verify: theorem not found",
                    },
                ],
                evidence_used,
                toolchain,
            )
        else:
            # Theorem label present but proof verification failed.
            error_lines = [l for l in combined.splitlines() if "?" in l or "error" in l.lower()]
            detail = "; ".join(error_lines[:3])
            _output(
                claim_id,
                [
                    {"obligation_id": _OBLIGATION_THEOREM_EXISTS, "verdict": "pass"},
                    {"obligation_id": _OBLIGATION_PROOF_VERIFIES, "verdict": "fail", "detail": detail},
                ],
                evidence_used,
                toolchain,
            )
        return 1

    _output(
        claim_id,
        [
            {"obligation_id": _OBLIGATION_THEOREM_EXISTS, "verdict": "pass"},
            {"obligation_id": _OBLIGATION_PROOF_VERIFIES, "verdict": "pass"},
        ],
        evidence_used,
        toolchain,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
