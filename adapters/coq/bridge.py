#!/usr/bin/env python3
"""
Coq/Rocq checker bridge for proofctl.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    vo_files    - list of .vo compiled object files to verify (or omit for all)
    coq_root    - project root where _CoqProject lives; defaults to "."

The bridge runs 'coqchk -silent <vo_files>' and captures toolchain info
(coq_version, opam_hash) for the M14 ToolchainDigest mechanism.

All theorems in a Coq project share batch_group "coq-env" (M13 BatchRunner).

Exit codes:
    0  coqchk succeeded — all proofs accepted
    1  coqchk failed — proof rejected
    2  coqchk not found in PATH
    3  protocol error (bad cert-file format)
"""
import json
import os
import subprocess
import sys


def _run(cmd: list, cwd: str, timeout: int = 600) -> tuple:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"{cmd[0]} timed out"
    except FileNotFoundError:
        return -2, "", f"{cmd[0]} not found in PATH"


def _coq_version(cwd: str) -> str:
    code, out, _ = _run(["coqchk", "--version"], cwd, timeout=15)
    if code not in (0, 1):
        return "unknown"
    for line in out.splitlines():
        if "The Coq Proof Assistant" in line or "version" in line.lower():
            parts = line.split()
            for i, p in enumerate(parts):
                if p.lower() == "version" and i + 1 < len(parts):
                    return parts[i + 1]
            # Last token fallback.
            return parts[-1] if parts else "unknown"
    return "unknown"


def _opam_hash(cwd: str) -> str:
    """Return a stable identifier for the current opam switch state."""
    code, out, _ = _run(["opam", "switch", "show"], cwd, timeout=15)
    if code != 0:
        return "unknown"
    switch_name = out.strip()
    # Hash the installed package list for a more stable identifier.
    code2, out2, _ = _run(["opam", "list", "--installed", "--short"], cwd, timeout=30)
    if code2 != 0:
        return switch_name
    import hashlib
    return hashlib.sha256(out2.encode()).hexdigest()[:16]


def _find_vo_files(coq_root: str) -> list:
    """Find all .vo files under coq_root."""
    vo_files = []
    for dirpath, _, filenames in os.walk(coq_root):
        for fn in filenames:
            if fn.endswith(".vo"):
                vo_files.append(os.path.join(dirpath, fn))
    return vo_files


def _output(outcome: str, claim_id: str, metadata: dict, toolchain: dict = None) -> None:
    obj: dict = {
        "protocol_version": 1,
        "claim_id": claim_id,
        "outcome": outcome,
        "assurance": "formal-kernel",
        "metadata": metadata,
    }
    if toolchain:
        obj["toolchain"] = toolchain
    print(json.dumps(obj))


def main() -> int:
    if len(sys.argv) != 2:
        _output("error", "", {"error": "usage: bridge.py <cert-file>"})
        return 3

    cert_path = sys.argv[1]
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _output("error", "", {"error": f"cannot read cert-file: {exc}"})
        return 3

    coq_root = cert.get("coq_root", ".")
    claim_id = cert.get("claim_id", "")
    vo_files = cert.get("vo_files", [])

    if not os.path.isabs(coq_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        coq_root = os.path.normpath(os.path.join(base, coq_root))

    # Check coqchk is available.
    code, _, _ = _run(["coqchk", "--version"], coq_root, timeout=15)
    if code == -2:
        _output("error", claim_id, {"error": "coqchk not found in PATH"})
        return 2

    # If no vo_files specified, discover all .vo under coq_root.
    if not vo_files:
        vo_files = _find_vo_files(coq_root)
        if not vo_files:
            _output("error", claim_id, {
                "error": f"no .vo files found under {coq_root} — run 'coqc' first"
            })
            return 3

    coq_ver = _coq_version(coq_root)
    opam_h = _opam_hash(coq_root)
    toolchain = {
        "coq_version": coq_ver,
        "opam_hash": opam_h,
    }

    # Run coqchk on all .vo files.
    cmd = ["coqchk", "-silent"] + vo_files
    code, stdout, stderr = _run(cmd, coq_root)

    if code == -1:
        _output("rejected", claim_id, {
            "coq_root": coq_root,
            "error": "coqchk timed out",
        }, toolchain)
        return 1

    if code == -2:
        _output("error", claim_id, {"error": "coqchk not found in PATH"})
        return 2

    if code != 0:
        error_lines = (stdout + stderr).splitlines()
        _output("rejected", claim_id, {
            "coq_root": coq_root,
            "vo_count": str(len(vo_files)),
            "error": "; ".join(error_lines[:5]),
        }, toolchain)
        return 1

    _output("accepted", claim_id, {
        "coq_root": coq_root,
        "vo_count": str(len(vo_files)),
    }, toolchain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
