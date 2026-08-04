#!/usr/bin/env python3
"""
Lean 4 checker bridge for proofctl (protocol v2).

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    lean_file   - path to the .lean file containing the theorem
    theorem     - fully qualified Lean 4 theorem name
    lake_root   - project root (where lakefile.lean lives); defaults to "."

The bridge runs 'lake build' in lake_root and verifies the theorem is
reachable via 'lake env lean --stdin'.

Obligations emitted:
    lean.lake-build-succeeds   - pass if lake build exits 0
    lean.theorem-type-checks   - pass if build passes AND lean can #check the theorem

Exit codes:
    0  all obligations pass
    1  one or more obligations fail (proof uncertified)
    2  lean or lake not found in PATH (checker unavailable)
    3  protocol error (bad cert-file format)
"""
import json
import os
import subprocess
import sys


OBLIGATIONS = [
    "lean.lake-build-succeeds",
    "lean.theorem-type-checks",
]


def _run(cmd: list, cwd: str, timeout: int = 600, input_data: str = None) -> tuple:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
            input=input_data,
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


def _theorem_exists(theorem: str, lake_root: str) -> bool:
    """Check if the theorem is reachable via 'lake env lean --stdin'."""
    code, _, _ = _run(
        ["lake", "env", "lean", "--stdin"],
        cwd=lake_root,
        timeout=60,
        input_data=f"#check @{theorem}\n",
    )
    return code == 0


def _make_obligations(lake_pass: bool, theorem_pass: bool) -> list:
    return [
        {
            "obligation": "lean.lake-build-succeeds",
            "verdict": "pass" if lake_pass else "fail",
        },
        {
            "obligation": "lean.theorem-type-checks",
            "verdict": "pass" if (lake_pass and theorem_pass) else "fail",
        },
    ]


def _output_v2(claim_id: str, obligation_results: list, toolchain: dict = None) -> None:
    obj: dict = {
        "protocol_version": 2,
        "claim_id": claim_id,
        "input_closure_digest": "",
        "checker_identity_digest": "",
        "runtime_identity_digest": "",
        "evidence_used": [],
        "obligation_results": obligation_results,
    }
    if toolchain:
        obj["toolchain"] = toolchain
    print(json.dumps(obj))


def _error_v2(claim_id: str, error: str) -> None:
    print(json.dumps({
        "protocol_version": 2,
        "claim_id": claim_id,
        "error": error,
    }))


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
        _error_v2("", "usage: bridge.py <cert-file>")
        return 3

    cert_path = sys.argv[1]
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _error_v2("", f"cannot read cert-file: {exc}")
        return 3

    lean_file = cert.get("lean_file", "")
    theorem = cert.get("theorem", "")
    lake_root = cert.get("lake_root", ".")
    claim_id = cert.get("claim_id", "")

    if not lean_file or not theorem:
        _error_v2(claim_id, "cert-file must contain 'lean_file' and 'theorem'")
        return 3

    # Resolve lake_root relative to cert_file's directory if relative.
    if not os.path.isabs(lake_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        lake_root = os.path.normpath(os.path.join(base, lake_root))

    # Check lake is available.
    code, _, _ = _run(["lake", "--version"], lake_root, timeout=10)
    if code == -2:
        _error_v2(claim_id, "lake not found in PATH")
        return 2

    # Check cross-domain claim integrity BEFORE lake build.
    # ProofCtlImport_*.lean files must match the attestations in .proofctl/attestations/.
    attest_dir = cert.get("attest_dir", os.path.join(lake_root, ".proofctl", "attestations"))
    xd_error = _check_cross_domain_imports(lake_root, attest_dir)
    if xd_error:
        toolchain = {
            "lean_version": _lean_version(lake_root),
            "lake_version": _lake_version(lake_root),
            "mathlib_commit": _mathlib_commit(lake_root),
        }
        _output_v2(claim_id, _make_obligations(False, False), toolchain)
        return 1

    # Run lake build.
    build_code, build_stdout, build_stderr = _run(["lake", "build"], lake_root)

    if build_code == -1:
        # Timed out — treat as build failure.
        toolchain = {
            "lean_version": _lean_version(lake_root),
            "lake_version": _lake_version(lake_root),
            "mathlib_commit": _mathlib_commit(lake_root),
        }
        _output_v2(claim_id, _make_obligations(False, False), toolchain)
        return 1

    if build_code == -2:
        _error_v2(claim_id, "lake not found in PATH")
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

    if build_code != 0:
        # lake build failed — both obligations fail.
        _output_v2(claim_id, _make_obligations(False, False), toolchain)
        return 1

    # Build succeeded — verify the theorem is reachable.
    theorem_ok = _theorem_exists(theorem, lake_root)
    _output_v2(claim_id, _make_obligations(True, theorem_ok), toolchain)
    return 0 if theorem_ok else 1


if __name__ == "__main__":
    sys.exit(main())
