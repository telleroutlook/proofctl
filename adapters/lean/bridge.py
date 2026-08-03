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


def _check_cross_domain_imports(lake_root: str, attest_dir: str) -> str:
    """
    Scan lake_root for ProofCtlImport_*.lean files.
    For each, parse the '-- Attestation digest: <digest>' comment and verify
    that the matching attestation in attest_dir has the same self_digest.
    Returns an error string if any mismatch is found, or "" if all match.
    """
    import glob
    import re

    pattern = os.path.join(lake_root, "**", "ProofCtlImport_*.lean")
    import_files = glob.glob(pattern, recursive=True)

    if not import_files:
        return ""  # no cross-domain imports — nothing to verify

    digest_re = re.compile(r"^--\s*Attestation digest:\s*(\S+)")
    claim_re = re.compile(r"^--\s*Source claim:\s*(\S+)")

    for import_file in import_files:
        try:
            with open(import_file, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as exc:
            return f"cannot read {import_file}: {exc}"

        expected_digest = ""
        claim_id = ""
        for line in lines[:20]:  # header is always in the first 20 lines
            if m := digest_re.match(line):
                expected_digest = m.group(1)
            if m := claim_re.match(line):
                claim_id = m.group(1)

        if not expected_digest or not claim_id:
            # Not a proofctl-generated import file — skip.
            continue

        # Find the matching attestation file.
        att_path = os.path.join(attest_dir, claim_id + ".json")
        if not os.path.isfile(att_path):
            # Also try <claim-id>-replay.json.
            att_path = os.path.join(attest_dir, claim_id + "-replay.json")

        if not os.path.isfile(att_path):
            return (
                f"cross-domain claim mismatch: no attestation found for {claim_id!r}"
                f" (expected from {os.path.basename(import_file)})"
            )

        try:
            with open(att_path, encoding="utf-8") as f:
                att = json.load(f)
        except Exception as exc:
            return f"cross-domain claim mismatch: cannot read attestation for {claim_id!r}: {exc}"

        actual_digest = att.get("self_digest", "")
        if actual_digest != expected_digest:
            return (
                f"cross-domain claim mismatch: {claim_id!r} — "
                f"import file has digest {expected_digest!r} but "
                f"attestation has {actual_digest!r}"
            )

    return ""


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

    # Check cross-domain claim integrity BEFORE lake build.
    # ProofCtlImport_*.lean files must match the attestations in .proofctl/attestations/.
    attest_dir = cert.get("attest_dir", os.path.join(lake_root, ".proofctl", "attestations"))
    xd_error = _check_cross_domain_imports(lake_root, attest_dir)
    if xd_error:
        _output("rejected", claim_id, {
            "lean_file": lean_file,
            "theorem": theorem,
            "error": xd_error,
        })
        return 1

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
