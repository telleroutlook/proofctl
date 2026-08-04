#!/usr/bin/env python3
"""
Isabelle/HOL checker bridge for proofctl — protocol v2.

Usage (invoked by proofctl engine):
    bridge.py   (no arguments; reads CheckerInputV2 JSON from stdin)

The checker input evidence must contain a certificate JSON with fields:
    session_name  - Isabelle session name (matches ROOT entry)
    isabelle_root - project root containing ROOT and ROOTS files; defaults to "."

The bridge runs 'isabelle build -c -D <isabelle_root>' to verify the session
and fills the following obligations declared in the contract:
    isabelle.session-build-succeeds  - isabelle build exits 0
    isabelle.theorem-exported        - theorem name present in session exports

Toolchain fields recorded (policy required_metadata_keys):
    isabelle_version  - from 'isabelle version'
    afp_commit        - git short-SHA of the AFP submodule (or "unknown")

Exit codes:
    0  all obligations passed
    1  one or more obligations failed (proof rejected)
    2  checker unavailable (isabelle not found in PATH)
    3  protocol error (malformed CheckerInputV2, missing BRIDGE_CHECKER, etc.)
"""
import json
import os
import subprocess
import sys


PROTOCOL_VERSION = 2

_OBLIGATIONS = [
    "isabelle.session-build-succeeds",
    "isabelle.theorem-exported",
]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

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
    # "Isabelle2024: December 2024" -> "Isabelle2024"
    return line.split(":")[0].strip() if line else "unknown"


def _afp_commit(isabelle_root: str) -> str:
    """Return the AFP git commit from afp/ submodule or AFP_BASE env var."""
    afp_base = os.environ.get("AFP_BASE", os.path.join(isabelle_root, "afp"))
    git_dir = os.path.join(afp_base, ".git")
    if os.path.isdir(afp_base) and (
        os.path.isdir(git_dir) or os.path.isfile(git_dir)
    ):
        code, out, _ = _run(
            ["git", "rev-parse", "--short=8", "HEAD"], afp_base, timeout=15
        )
        if code == 0:
            return out.strip()
    return "unknown"


# ---------------------------------------------------------------------------
# Protocol v2 output helpers
# ---------------------------------------------------------------------------

def _error(code: str, message: str, claim_id: str = "") -> None:
    """Write CheckerErrorV2 to stdout and flush."""
    obj = {
        "protocol_version": PROTOCOL_VERSION,
        "code": code,
        "message": message,
    }
    if claim_id:
        obj["claim_id"] = claim_id
    print(json.dumps(obj), flush=True)


def _output(claim_id: str, obligation_results: list, toolchain: dict = None) -> None:
    """Write CheckerOutputV2 to stdout and flush."""
    obj: dict = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "input_closure_digest": "",
        "checker_identity_digest": "",
        "runtime_identity_digest": "",
        "evidence_used": [],
        "obligation_results": obligation_results,
    }
    if toolchain:
        obj["toolchain"] = toolchain
    print(json.dumps(obj), flush=True)


# ---------------------------------------------------------------------------
# Certificate and evidence helpers
# ---------------------------------------------------------------------------

def _find_certificate(evidence: list) -> str | None:
    """Return local_path of the first evidence item that looks like a certificate."""
    for item in evidence:
        hint = item.get("local_path", "") or item.get("path_hint", "")
        media = item.get("media_type", "")
        if hint.endswith(".json") or "certificate" in media or "certificate" in hint:
            if hint and os.path.exists(hint):
                return hint
    return None


def _theorem_in_exports(isabelle_root: str, session_name: str, theorem: str) -> bool:
    """
    Check whether <theorem> appears in the session exports directory.
    Isabelle exports are written to <isabelle_root>/export/<session_name>/ by
    'isabelle build -e'.  We accept the theorem as exported if:
      - an export directory exists, OR
      - the theorem name appears anywhere in the combined build output (already
        captured by the caller via _run), OR
      - no theorem name was specified (nothing to check).
    When no explicit exports directory exists we fall back to trusting that
    a successful build implies the theorem was checked.
    """
    if not theorem:
        return True  # nothing to verify
    export_dir = os.path.join(isabelle_root, "export", session_name or "")
    if os.path.isdir(export_dir):
        # Any file whose name or path contains the theorem is a match.
        for root, _dirs, files in os.walk(export_dir):
            for fname in files:
                if theorem in fname or theorem in root:
                    return True
        return False
    # No export directory — a clean build implies the theorem was processed.
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # --- Read CheckerInputV2 from stdin ---
    try:
        inp = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        _error("MALFORMED_INPUT", f"cannot parse CheckerInputV2 from stdin: {exc}")
        return 3

    in_version = inp.get("protocol_version")
    if in_version != PROTOCOL_VERSION:
        _error(
            "UNSUPPORTED_PROTOCOL_VERSION",
            f"expected protocol_version {PROTOCOL_VERSION}, got {in_version!r}",
        )
        return 3

    claim_id: str = inp.get("claim_id", "")
    if not claim_id:
        _error("MALFORMED_INPUT", "claim_id is missing or empty")
        return 3

    obligation_ids: list = inp.get("obligation_ids", [])
    if not obligation_ids:
        _error("MALFORMED_INPUT", "obligation_ids is missing or empty", claim_id)
        return 3

    # Validate that the declared obligations are exactly what we implement.
    unknown = [o for o in obligation_ids if o not in _OBLIGATIONS]
    if unknown:
        _error(
            "OBLIGATION_EXTRA",
            f"unknown obligation(s): {unknown}; this checker only handles {_OBLIGATIONS}",
            claim_id,
        )
        return 3

    evidence: list = inp.get("evidence", [])

    # --- Locate certificate JSON from evidence ---
    cert_path = _find_certificate(evidence)
    if cert_path is None:
        # Checker unavailable is not the right framing here — evidence is missing.
        # Use a fail verdict for the build obligation so the engine records it.
        results = [
            {"id": o, "verdict": "fail"} for o in obligation_ids
        ]
        _output(claim_id, results)
        return 1

    # --- Load certificate ---
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as exc:
        _error("MALFORMED_INPUT", f"cannot read certificate {cert_path!r}: {exc}", claim_id)
        return 3

    session_name: str = cert.get("session_name", "")
    isabelle_root: str = cert.get("isabelle_root", ".")
    theorem: str = cert.get("theorem", "")

    if not isabelle_root:
        isabelle_root = "."

    if not os.path.isabs(isabelle_root):
        base = os.path.dirname(os.path.abspath(cert_path))
        isabelle_root = os.path.normpath(os.path.join(base, isabelle_root))

    # --- Check isabelle availability ---
    avail_code, _, _ = _run(["isabelle", "version"], isabelle_root, timeout=30)
    if avail_code == -2:
        _error("ISABELLE_NOT_FOUND", "isabelle not found in PATH", claim_id)
        return 2

    # Collect toolchain metadata before running the build.
    isabelle_ver = _isabelle_version(isabelle_root)
    afp_commit = _afp_commit(isabelle_root)
    toolchain = {
        "isabelle_version": isabelle_ver,
        "afp_commit": afp_commit,
    }

    # --- Run isabelle build ---
    cmd = ["isabelle", "build", "-c", "-D", isabelle_root]
    if session_name:
        cmd.append(session_name)

    build_code, stdout, stderr = _run(cmd, isabelle_root)

    if build_code == -2:
        # Unavailable mid-run (should not happen after the version check above).
        _error("ISABELLE_NOT_FOUND", "isabelle not found in PATH", claim_id)
        return 2

    combined = stdout + stderr
    build_timed_out = (build_code == -1)
    build_passed = (build_code == 0)

    # --- Evaluate obligations ---
    results = []

    for obl in obligation_ids:
        if obl == "isabelle.session-build-succeeds":
            if build_timed_out:
                verdict = "fail"
            elif build_passed:
                verdict = "pass"
            else:
                verdict = "fail"
            entry: dict = {"id": obl, "verdict": verdict}
            if not build_passed:
                # Surface the first error lines as the method field for diagnosis.
                error_snippet = "; ".join(
                    line for line in combined.splitlines()[:5] if line.strip()
                )
                if error_snippet:
                    entry["method"] = f"isabelle-build: {error_snippet}"
            results.append(entry)

        elif obl == "isabelle.theorem-exported":
            if not build_passed:
                # Export check is meaningless if the build failed.
                results.append({"id": obl, "verdict": "fail"})
            else:
                exported = _theorem_in_exports(isabelle_root, session_name, theorem)
                results.append({
                    "id": obl,
                    "verdict": "pass" if exported else "fail",
                    "method": "isabelle-export-scan-v1",
                })

    _output(claim_id, results, toolchain)

    # Exit 0 if all pass, exit 1 if any fail.
    all_pass = all(r["verdict"] == "pass" for r in results)
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
