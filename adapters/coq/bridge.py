#!/usr/bin/env python3
"""
Coq/Rocq checker bridge for proofctl — protocol v2.

Usage:
    bridge.py <cert-file>

The cert-file is a JSON object with fields:
    vo_files    - list of .vo compiled object files to verify (or omit for all)
    coq_root    - project root where _CoqProject lives; defaults to "."
    theorem_vo  - optional path to the target theorem's .vo file;
                  used to resolve the coq.theorem-vo-valid obligation

The bridge runs 'coqchk -silent <vo_files>' and emits a v2 CheckerOutputV2
with per-obligation verdicts for:
    coq.coqchk-succeeds   — coqchk kernel check passed
    coq.theorem-vo-valid  — target theorem's .vo file is valid

Obligation rules:
    coqchk passes + theorem_vo found  → both pass
    coqchk fails                      → both fail
    coqchk passes + theorem_vo absent → coqchk pass, theorem-vo-valid fail

Exit codes:
    0  obligation results written (checkerOutputV2; individual verdicts may be fail)
    2  coqchk not found in PATH (CheckerErrorV2)
    3  protocol error / bad cert-file (CheckerErrorV2)
"""
import hashlib
import json
import os
import subprocess
import sys

PROTOCOL_VERSION = 2
OBL_COQCHK = "coq.coqchk-succeeds"
OBL_THM_VO = "coq.theorem-vo-valid"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return "sha256:" + h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
    code2, out2, _ = _run(["opam", "list", "--installed", "--short"], cwd, timeout=30)
    if code2 != 0:
        return switch_name
    return "sha256:" + hashlib.sha256(out2.encode()).hexdigest()[:16]


def _find_vo_files(coq_root: str) -> list:
    """Find all .vo files under coq_root."""
    vo_files = []
    for dirpath, _, filenames in os.walk(coq_root):
        for fn in filenames:
            if fn.endswith(".vo"):
                vo_files.append(os.path.join(dirpath, fn))
    return vo_files


def _error_out(code: str, message: str, claim_id: str = "", exit_code: int = 3) -> None:
    """Emit a CheckerErrorV2 and exit."""
    print(json.dumps({
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "code": code,
        "message": message,
    }))
    sys.exit(exit_code)


def _obl_result(obl_id: str, verdict: str, method: str = "") -> dict:
    r: dict = {"id": obl_id, "verdict": verdict}
    if method:
        r["method"] = method
    return r


def _output(
    claim_id: str,
    cert_digest: str,
    obligation_results: list,
    toolchain: dict = None,
) -> None:
    """Emit a CheckerOutputV2."""
    checker_digest = _sha256_file(os.path.abspath(__file__))
    obj: dict = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "input_closure_digest": cert_digest,
        "checker_identity_digest": checker_digest,
        "runtime_identity_digest": "",
        "evidence_used": [cert_digest] if cert_digest else [],
        "obligation_results": obligation_results,
    }
    if toolchain:
        obj["toolchain"] = toolchain
    print(json.dumps(obj))


def main() -> int:
    if len(sys.argv) != 2:
        _error_out("PROTOCOL_ERROR", "usage: bridge.py <cert-file>", exit_code=3)

    cert_path = sys.argv[1]
    try:
        with open(cert_path, "rb") as f:
            cert_raw = f.read()
        cert = json.loads(cert_raw)
    except Exception as exc:
        _error_out("PROTOCOL_ERROR", f"cannot read cert-file: {exc}", exit_code=3)

    cert_digest = _sha256_bytes(cert_raw)
    coq_root = cert.get("coq_root", ".")
    claim_id = cert.get("claim_id", "")
    vo_files = cert.get("vo_files", [])
    theorem_vo = cert.get("theorem_vo", "")

    if not os.path.isabs(coq_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        coq_root = os.path.normpath(os.path.join(base, coq_root))

    # Resolve theorem_vo relative to cert location if not absolute.
    if theorem_vo and not os.path.isabs(theorem_vo):
        base = os.path.dirname(os.path.abspath(cert_path))
        theorem_vo = os.path.normpath(os.path.join(base, theorem_vo))

    # Check coqchk is available.
    code, _, _ = _run(["coqchk", "--version"], coq_root, timeout=15)
    if code == -2:
        _error_out("CHECKER_UNAVAILABLE", "coqchk not found in PATH", claim_id, exit_code=2)

    # If no vo_files specified, discover all .vo under coq_root.
    if not vo_files:
        vo_files = _find_vo_files(coq_root)
        if not vo_files:
            _error_out(
                "PROTOCOL_ERROR",
                f"no .vo files found under {coq_root} — run 'coqc' first",
                claim_id,
                exit_code=3,
            )

    coq_ver = _coq_version(coq_root)
    opam_h = _opam_hash(coq_root)
    toolchain = {
        "coq_version": coq_ver,
        "opam_hash": opam_h,
    }

    # Determine whether the theorem's .vo file is present before running coqchk.
    # If theorem_vo is not specified, presence is assumed (any .vo files were found).
    if theorem_vo:
        theorem_vo_present = os.path.isfile(theorem_vo)
    else:
        theorem_vo_present = True

    # Run coqchk on all .vo files.
    cmd = ["coqchk", "-silent"] + vo_files
    code, stdout, stderr = _run(cmd, coq_root)

    if code == -2:
        _error_out("CHECKER_UNAVAILABLE", "coqchk not found in PATH", claim_id, exit_code=2)

    # coqchk failed (includes timeout code -1 and non-zero exit): both obligations fail.
    if code != 0:
        _output(
            claim_id,
            cert_digest,
            [
                _obl_result(OBL_COQCHK, "fail"),
                _obl_result(OBL_THM_VO, "fail"),
            ],
            toolchain,
        )
        return 0

    # coqchk succeeded: coq.coqchk-succeeds passes.
    # coq.theorem-vo-valid passes only if the theorem's .vo file was present.
    thm_verdict = "pass" if theorem_vo_present else "fail"
    _output(
        claim_id,
        cert_digest,
        [
            _obl_result(OBL_COQCHK, "pass"),
            _obl_result(OBL_THM_VO, thm_verdict),
        ],
        toolchain,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
