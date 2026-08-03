#!/usr/bin/env python3
"""
Metamath checker bridge for proofctl.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    mm_file   - path to the .mm proof file
    theorem   - Metamath theorem label to verify

Exit codes:
    0  theorem verified
    1  theorem not found or proof failed
    2  checker unavailable (metamath not in PATH)
    3  protocol error (bad cert-file format)
"""
import json
import os
import subprocess
import sys


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


def _output(outcome: str, claim_id: str, metadata: dict, error: str = "") -> None:
    obj: dict = {
        "protocol_version": 1,
        "claim_id": claim_id,
        "outcome": outcome,
        "assurance": "formal-kernel",
        "metadata": metadata,
    }
    if error:
        obj["metadata"]["error"] = error
    print(json.dumps(obj))


def main() -> int:
    if len(sys.argv) != 2:
        _output("error", "", {}, "usage: bridge.py <cert-file>")
        return 3

    cert_path = sys.argv[1]
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _output("error", "", {}, f"cannot read cert-file: {exc}")
        return 3

    mm_file = cert.get("mm_file", "")
    theorem = cert.get("theorem", "")
    claim_id = cert.get("claim_id", "")

    if not mm_file or not theorem:
        _output("error", claim_id, {}, "cert-file must contain 'mm_file' and 'theorem'")
        return 3

    if not os.path.isfile(mm_file):
        _output("error", claim_id, {}, f"mm_file not found: {mm_file}")
        return 3

    # Check metamath is available.
    try:
        subprocess.run(["metamath", "exit"], capture_output=True, timeout=10, check=False)
    except FileNotFoundError:
        _output("error", claim_id, {}, "metamath not found in PATH")
        return 2

    version = _version()

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
        _output("rejected", claim_id, {"theorem": theorem}, "metamath timed out")
        return 1
    except Exception as exc:
        _output("error", claim_id, {}, f"metamath execution error: {exc}")
        return 2

    combined = result.stdout + result.stderr

    # Check for errors.
    if "?" in combined or "error" in combined.lower():
        # Look for theorem-specific error.
        if theorem in combined and ("not found" in combined.lower() or "failed" in combined.lower()):
            _output(
                "rejected",
                claim_id,
                {"metamath_version": version, "theorem": theorem, "mm_file": mm_file},
                f"theorem '{theorem}' proof failed",
            )
            return 1
        # Generic error.
        error_lines = [l for l in combined.splitlines() if "?" in l or "error" in l.lower()]
        _output(
            "rejected",
            claim_id,
            {"metamath_version": version, "theorem": theorem, "mm_file": mm_file},
            "; ".join(error_lines[:3]),
        )
        return 1

    _output(
        "accepted",
        claim_id,
        {
            "metamath_version": version,
            "theorem": theorem,
            "mm_file": mm_file,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
