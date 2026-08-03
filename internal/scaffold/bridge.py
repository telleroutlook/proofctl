"""
CAP checker bridge — proofctl wire protocol v1 adapter.

Translates between proofctl's CheckerInput/CheckerOutput JSON protocol
(stdin/stdout) and a domain checker that takes a certificate JSON file path
as its sole argument and communicates via exit code.

Usage (in a ProofGraph checker_policy or CheckerIdentity runtime):
    python adapters/cap/bridge.py

The bridge reads CheckerInput JSON from stdin, locates the certificate file
from the evidence list, invokes the domain checker subprocess, and writes
CheckerOutput JSON to stdout.

Domain checker contract:
    exit 0  — CERTIFIED
    exit 1  — UNCERTIFIED (proof failed)
    exit 2  — malformed certificate (schema / resource violation)

The domain checker path is supplied via the BRIDGE_CHECKER env var, e.g.:
    BRIDGE_CHECKER="python checker/check_certificate.py"

Metadata keys populated on exit 0 (checker passes):
    cap_format_version   — from certificate top-level "format_version" field
    digests_fresh        — "true" (proofctl freshness layer guarantees this)
    path_keys_match      — "true" (checker verified A/B key bijection)
    intervals_intersect  — "true" (checker verified Path B crosscheck)
    matrix_reconstructed — "true" (checker verified matrix reconstruction)
    ldlt_passes          — "true" (checker verified interval LDL^T)
    odd_sector_passes    — "true" if certificate "sector" field is "odd"
    even_sector_passes   — "true" if certificate "sector" field is "even"
    pivot_radius_ratio   — from certificate "margin_ratio" field if present,
                           or parsed from checker stdout (key=value or JSON)
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROTOCOL_VERSION = 1

_EMPTY_RESOURCES = {"wall_millis": 0, "cpu_millis": 0, "mem_bytes": 0}


def _read_input() -> dict:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        _die(2, f"malformed CheckerInput JSON: {e}")


def _out(claim_id: str, outcome: str, assurance: str = "",
         explanation: str = "", error_code: str = "",
         metadata: dict = None) -> dict:
    """Build a protocol-compliant CheckerOutput dict."""
    o = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "outcome": outcome,
        "assurance": assurance,
        "resources": _EMPTY_RESOURCES,
    }
    if explanation:
        o["explanation"] = explanation
    if error_code:
        o["error_code"] = error_code
    if metadata:
        o["metadata"] = metadata
    return o


def _die(exit_code: int, message: str) -> None:
    out = _out("", "error", error_code="malformed_input", explanation=message)
    json.dump(out, sys.stdout)
    sys.exit(exit_code)


def _find_certificate(evidence: list) -> Path | None:
    """Return the path of the first evidence item that looks like a certificate."""
    for item in evidence:
        hint = item.get("local_path", "") or item.get("path_hint", "")
        media = item.get("media_type", "")
        if hint.endswith(".json") or "certificate" in media or "certificate" in hint:
            p = Path(hint)
            if p.exists():
                return p
    return None


def _read_cert_field(cert_path: Path, field: str) -> str:
    try:
        with open(cert_path) as f:
            data = json.load(f)
        v = data.get(field, "")
        return str(v) if v else ""
    except Exception:
        return ""


def _extract_margin_from_stdout(stdout: str) -> str:
    """Extract margin_ratio / pivot_radius_ratio from checker stdout.

    Tries two formats:
      1. JSON object with a "margin_ratio" or "pivot_radius_ratio" key.
      2. Plain-text lines with key=value pairs (e.g. "margin_ratio=3.3e8").
    Returns the value as a string, or "" if not found.
    """
    text = stdout.strip()
    if not text:
        return ""
    # Try JSON first.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for key in ("margin_ratio", "pivot_radius_ratio"):
                v = obj.get(key, "")
                if v:
                    return str(v)
    except (json.JSONDecodeError, ValueError):
        pass
    # Fall back to key=value scan.
    for key in ("margin_ratio", "pivot_radius_ratio"):
        m = re.search(rf"(?:^|[\s,;])(?:pivot_radius_ratio|margin_ratio)\s*=\s*([^\s,;]+)", text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1)
    return ""


def main() -> None:
    checker_cmd = os.environ.get("BRIDGE_CHECKER", "")
    if not checker_cmd:
        _die(3, "BRIDGE_CHECKER environment variable not set")

    inp = _read_input()
    claim_id: str = inp.get("claim_id", "")
    evidence: list = inp.get("evidence", [])

    cert_path = _find_certificate(evidence)
    if cert_path is None:
        json.dump(_out(claim_id, "rejected", "deterministic-cap",
                       error_code="evidence_not_found",
                       explanation="no certificate JSON found in evidence paths"),
                  sys.stdout)
        sys.exit(0)

    # Invoke domain checker.
    cmd = checker_cmd.split() + [str(cert_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as e:
        _die(2, f"checker not found: {e}")
    except Exception as e:
        _die(2, f"checker subprocess error: {e}")

    checker_exit = result.returncode

    if checker_exit == 2:
        json.dump(_out(claim_id, "error",
                       error_code="malformed_certificate",
                       explanation=result.stderr.strip() or "certificate schema violation (exit 2)"),
                  sys.stdout)
        sys.exit(0)

    if checker_exit != 0:
        json.dump(_out(claim_id, "rejected", "deterministic-cap",
                       error_code="proof_rejected",
                       explanation=result.stderr.strip() or f"checker exit {checker_exit}"),
                  sys.stdout)
        sys.exit(0)

    # exit 0 — CERTIFIED. Build metadata.
    metadata: dict = {
        "digests_fresh": "true",
        "path_keys_match": "true",
        "intervals_intersect": "true",
        "matrix_reconstructed": "true",
        "ldlt_passes": "true",
    }

    fmt_ver = _read_cert_field(cert_path, "format_version")
    if fmt_ver:
        metadata["cap_format_version"] = fmt_ver

    # pivot_radius_ratio: prefer cert top-level field, fall back to checker stdout.
    margin = _read_cert_field(cert_path, "margin_ratio")
    if not margin:
        margin = _extract_margin_from_stdout(result.stdout)
    if margin:
        metadata["pivot_radius_ratio"] = margin

    sector = _read_cert_field(cert_path, "sector")
    if sector == "odd":
        metadata["odd_sector_passes"] = "true"
    elif sector == "even":
        metadata["even_sector_passes"] = "true"

    json.dump(_out(claim_id, "accepted", "deterministic-cap", metadata=metadata),
              sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()


PROTOCOL_VERSION = 1

_EMPTY_RESOURCES = {"wall_millis": 0, "cpu_millis": 0, "mem_bytes": 0}


def _read_input() -> dict:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        _die(2, f"malformed CheckerInput JSON: {e}")


def _out(claim_id: str, outcome: str, assurance: str = "",
         explanation: str = "", error_code: str = "",
         metadata: dict = None) -> dict:
    """Build a protocol-compliant CheckerOutput dict."""
    o = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "outcome": outcome,
        "assurance": assurance,
        "resources": _EMPTY_RESOURCES,
    }
    if explanation:
        o["explanation"] = explanation
    if error_code:
        o["error_code"] = error_code
    if metadata:
        o["metadata"] = metadata
    return o


def _die(exit_code: int, message: str) -> None:
    out = _out("", "error", error_code="malformed_input", explanation=message)
    json.dump(out, sys.stdout)
    sys.exit(exit_code)


def _find_certificate(evidence: list) -> Path | None:
    """Return the path of the first evidence item that looks like a certificate."""
    for item in evidence:
        hint = item.get("local_path", "") or item.get("path_hint", "")
        media = item.get("media_type", "")
        if hint.endswith(".json") or "certificate" in media or "certificate" in hint:
            p = Path(hint)
            if p.exists():
                return p
    return None


def _read_cert_field(cert_path: Path, field: str) -> str:
    try:
        with open(cert_path) as f:
            data = json.load(f)
        v = data.get(field, "")
        return str(v) if v else ""
    except Exception:
        return ""


def main() -> None:
    checker_cmd = os.environ.get("BRIDGE_CHECKER", "")
    if not checker_cmd:
        _die(3, "BRIDGE_CHECKER environment variable not set")

    inp = _read_input()
    claim_id: str = inp.get("claim_id", "")
    evidence: list = inp.get("evidence", [])

    cert_path = _find_certificate(evidence)
    if cert_path is None:
        json.dump(_out(claim_id, "rejected", "deterministic-cap",
                       error_code="evidence_not_found",
                       explanation="no certificate JSON found in evidence paths"),
                  sys.stdout)
        sys.exit(0)

    # Invoke domain checker.
    cmd = checker_cmd.split() + [str(cert_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as e:
        _die(2, f"checker not found: {e}")
    except Exception as e:
        _die(2, f"checker subprocess error: {e}")

    checker_exit = result.returncode

    if checker_exit == 2:
        json.dump(_out(claim_id, "error",
                       error_code="malformed_certificate",
                       explanation=result.stderr.strip() or "certificate schema violation (exit 2)"),
                  sys.stdout)
        sys.exit(0)

    if checker_exit != 0:
        json.dump(_out(claim_id, "rejected", "deterministic-cap",
                       error_code="proof_rejected",
                       explanation=result.stderr.strip() or f"checker exit {checker_exit}"),
                  sys.stdout)
        sys.exit(0)

    # exit 0 — CERTIFIED. Build metadata.
    metadata: dict = {
        "digests_fresh": "true",
        "path_keys_match": "true",
        "intervals_intersect": "true",
        "matrix_reconstructed": "true",
        "ldlt_passes": "true",
    }

    fmt_ver = _read_cert_field(cert_path, "format_version")
    if fmt_ver:
        metadata["cap_format_version"] = fmt_ver

    margin = _read_cert_field(cert_path, "margin_ratio")
    if margin:
        metadata["pivot_radius_ratio"] = margin

    sector = _read_cert_field(cert_path, "sector")
    if sector == "odd":
        metadata["odd_sector_passes"] = "true"
    elif sector == "even":
        metadata["even_sector_passes"] = "true"

    json.dump(_out(claim_id, "accepted", "deterministic-cap", metadata=metadata),
              sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
