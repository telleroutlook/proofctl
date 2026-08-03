#!/usr/bin/env python3
"""
Lean 4 checker bridge for proofctl.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    lean_file   - path to the .lean file containing the theorem
    theorem     - fully qualified Lean 4 theorem name
    lake_root   - project root (where lakefile.lean lives); defaults to "."

The bridge runs 'lake build' in lake_root and checks for errors.
It captures lean_version, mathlib_commit (from lake-manifest.json),
and lake_version for the toolchain field.

Exit codes:
    0  lake build succeeded
    1  lake build failed (proof rejected)
    2  lake or lean not found in PATH
    3  protocol error (bad cert-file format)
"""
import json
import os
import subprocess
import sys


def _run(cmd: list, cwd: str, timeout: int = 600) -> tuple:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"{cmd[0]} timed out"
    except FileNotFoundError:
        return -2, "", f"{cmd[0]} not found in PATH"


def _lean_version(cwd: str) -> str:
    code, out, _ = _run(["lean", "--version"], cwd, timeout=30)
    if code != 0:
        return "unknown"
    for line in out.splitlines():
        if "Lean" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p.lower() in ("version", "lean") and i + 1 < len(parts):
                    return parts[i + 1].lstrip("v")
    return out.strip().split()[-1] if out.strip() else "unknown"


def _lake_version(cwd: str) -> str:
    code, out, _ = _run(["lake", "--version"], cwd, timeout=30)
    if code != 0:
        return "unknown"
    line = out.strip().splitlines()[0] if out.strip() else ""
    return line.split()[-1].lstrip("v") if line else "unknown"


def _mathlib_commit(lake_root: str) -> str:
    """Extract the Mathlib git revision from lake-manifest.json."""
    manifest_path = os.path.join(lake_root, "lake-manifest.json")
    if not os.path.isfile(manifest_path):
        return "unknown"
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        packages = manifest.get("packages", [])
        for pkg in packages:
            name = pkg.get("name", "") or pkg.get("url", "")
            if "mathlib" in name.lower():
                return pkg.get("rev", "unknown")[:8]
    except Exception:
        pass
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

    lean_file = cert.get("lean_file", "")
    theorem = cert.get("theorem", "")
    lake_root = cert.get("lake_root", ".")
    claim_id = cert.get("claim_id", "")

    if not lean_file or not theorem:
        _output("error", claim_id, {"error": "cert-file must contain 'lean_file' and 'theorem'"})
        return 3

    # Resolve lake_root relative to cert_file's directory if relative.
    if not os.path.isabs(lake_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        lake_root = os.path.normpath(os.path.join(base, lake_root))

    # Check lake is available.
    code, _, err = _run(["lake", "--version"], lake_root, timeout=10)
    if code == -2:
        _output("error", claim_id, {"error": "lake not found in PATH"})
        return 2

    # Run lake build.
    code, stdout, stderr = _run(["lake", "build"], lake_root)

    if code == -1:
        _output("rejected", claim_id, {
            "lean_file": lean_file,
            "theorem": theorem,
            "error": "lake build timed out",
        })
        return 1

    if code == -2:
        _output("error", claim_id, {"error": "lake not found in PATH"})
        return 2

    # Capture toolchain info regardless of outcome.
    lean_ver = _lean_version(lake_root)
    lake_ver = _lake_version(lake_root)
    mathlib_commit = _mathlib_commit(lake_root)
    toolchain = {
        "lean_version": lean_ver,
        "lake_version": lake_ver,
        "mathlib_commit": mathlib_commit,
    }

    if code != 0:
        error_lines = (stdout + stderr).splitlines()
        _output("rejected", claim_id, {
            "lean_file": lean_file,
            "theorem": theorem,
            "error": "; ".join(error_lines[:5]),
        }, toolchain)
        return 1

    _output("accepted", claim_id, {
        "lean_file": lean_file,
        "theorem": theorem,
    }, toolchain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
