#!/usr/bin/env python3
"""
Isabelle/HOL checker bridge for proofctl.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    session_name  - Isabelle session name (matches ROOT entry)
    isabelle_root - project root containing ROOT and ROOTS files; defaults to "."

The bridge runs 'isabelle build -c -D <isabelle_root>' to build and check
the session, then extracts the isabelle_version and afp_commit for M14
ToolchainDigest.

All theorems in an Isabelle session share batch_group "isabelle-env"
(M13 BatchRunner).

Exit codes:
    0  isabelle build succeeded
    1  build failed (proof rejected)
    2  isabelle not found in PATH
    3  protocol error (bad cert-file format)
"""
import json
import os
import subprocess
import sys


def _run(cmd: list, cwd: str, timeout: int = 1800) -> tuple:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"{cmd[0]} timed out after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"{cmd[0]} not found in PATH"


def _isabelle_version(cwd: str) -> str:
    code, out, _ = _run(["isabelle", "version"], cwd, timeout=30)
    if code not in (0, 1):
        return "unknown"
    line = out.strip().splitlines()[0] if out.strip() else ""
    # "Isabelle2024: December 2024" → extract "Isabelle2024"
    return line.split(":")[0].strip() if line else "unknown"


def _afp_commit(isabelle_root: str) -> str:
    """Return the AFP git commit from afp/ submodule or ROOTS reference."""
    # Common layouts: afp/ subdirectory or AFP_BASE env var.
    afp_base = os.environ.get("AFP_BASE", os.path.join(isabelle_root, "afp"))
    git_dir = os.path.join(afp_base, ".git")
    if os.path.isdir(afp_base) and (os.path.isdir(git_dir) or os.path.isfile(git_dir)):
        code, out, _ = _run(
            ["git", "rev-parse", "--short=8", "HEAD"], afp_base, timeout=15
        )
        if code == 0:
            return out.strip()
    return "unknown"


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

    session_name = cert.get("session_name", "")
    isabelle_root = cert.get("isabelle_root", ".")
    claim_id = cert.get("claim_id", "")

    if not isabelle_root:
        isabelle_root = "."

    if not os.path.isabs(isabelle_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        isabelle_root = os.path.normpath(os.path.join(base, isabelle_root))

    # Check isabelle is available.
    code, _, _ = _run(["isabelle", "version"], isabelle_root, timeout=30)
    if code == -2:
        _output("error", claim_id, {"error": "isabelle not found in PATH"})
        return 2

    isabelle_ver = _isabelle_version(isabelle_root)
    afp_commit = _afp_commit(isabelle_root)
    toolchain = {
        "isabelle_version": isabelle_ver,
        "afp_commit": afp_commit,
    }

    # Build command: isabelle build -c -D <isabelle_root> [<session_name>]
    cmd = ["isabelle", "build", "-c", "-D", isabelle_root]
    if session_name:
        cmd.append(session_name)

    code, stdout, stderr = _run(cmd, isabelle_root)

    if code == -1:
        _output("rejected", claim_id, {
            "isabelle_root": isabelle_root,
            "session_name": session_name,
            "error": "isabelle build timed out",
        }, toolchain)
        return 1

    if code == -2:
        _output("error", claim_id, {"error": "isabelle not found in PATH"})
        return 2

    combined = stdout + stderr

    # Parse session log for theory count.
    theory_count = sum(1 for line in combined.splitlines() if "theory" in line.lower())

    if code != 0:
        error_lines = combined.splitlines()
        _output("rejected", claim_id, {
            "isabelle_root": isabelle_root,
            "session_name": session_name or "(all)",
            "error": "; ".join(line for line in error_lines[:5] if line.strip()),
        }, toolchain)
        return 1

    _output("accepted", claim_id, {
        "isabelle_root": isabelle_root,
        "session_name": session_name or "(all)",
        "theory_count": str(theory_count),
    }, toolchain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
