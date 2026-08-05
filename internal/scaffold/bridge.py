"""
CAP checker bridge — proofctl wire protocol v2 adapter.

Translates between proofctl's CheckerInput/CheckerOutput JSON protocol
(stdin/stdout) and a domain checker that takes a certificate JSON file path
as its sole argument and communicates via exit code.

Usage (in a ProofGraph checker_policy or CheckerIdentity runtime):
    python adapters/cap/bridge.py

The bridge reads CheckerInput JSON from stdin, locates the certificate file
from the evidence list, invokes the domain checker subprocess, and writes
CheckerOutput JSON (protocol v2) to stdout.

Domain checker contract:
    exit 0  — CERTIFIED
    exit 1  — UNCERTIFIED (proof failed)
    exit 2  — malformed certificate (schema / resource violation)
    exit 3  — protocol error (e.g. missing BRIDGE_CHECKER env var)

The domain checker path is supplied via the BRIDGE_CHECKER env var, e.g.:
    BRIDGE_CHECKER="python checker/check_certificate.py"

Obligation IDs are read from the certificate JSON field "obligations":
    ["obl-a", "obl-b", ...]
If that field is absent or empty, the default obligation ["cap.checker-pass"]
is used. Different Weil claims may declare different obligation sets; the bridge
does not hard-code any claim-specific IDs.

On checker exit 0, each obligation gets verdict="pass" plus the following
metadata keys:
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

On checker exit 1, each obligation gets verdict="fail".
On checker exit 2 (malformed cert), a CheckerErrorV2 is emitted (no
obligation_results) with error_code="malformed_certificate".
If BRIDGE_CHECKER is unset, a CheckerErrorV2 is emitted with
error_code="protocol_error" and the bridge exits 3.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

PROTOCOL_VERSION = 2
_DEFAULT_OBLIGATIONS = ["cap.checker-pass"]
_EMPTY_RESOURCES = {"wall_millis": 0, "cpu_millis": 0, "mem_bytes": 0}


def _read_input() -> dict:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        _die(3, f"malformed CheckerInput JSON: {e}")


def _out_obligations(claim_id: str, obligation_ids: list, verdict: str,
                     explanation: str = "", metadata: dict = None,
                     evidence_used: list = None) -> dict:
    """Build a protocol v2 CheckerOutput with obligation_results."""
    results = []
    for obl_id in obligation_ids:
        r = {"id": obl_id, "verdict": verdict}
        if explanation:
            r["explanation"] = explanation
        if metadata:
            r["metadata"] = metadata
        results.append(r)
    out = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "obligation_results": results,
        "resources": _EMPTY_RESOURCES,
    }
    if evidence_used:
        out["evidence_used"] = evidence_used
    return out


def _out_error(claim_id: str, error_code: str, explanation: str = "") -> dict:
    """Build a protocol v2 CheckerErrorV2 (no obligation_results)."""
    o = {
        "protocol_version": PROTOCOL_VERSION,
        "claim_id": claim_id,
        "error_code": error_code,
        "resources": _EMPTY_RESOURCES,
    }
    if explanation:
        o["explanation"] = explanation
    return o


def _die(exit_code: int, message: str) -> None:
    """Emit a protocol_error CheckerErrorV2 and exit with exit_code."""
    json.dump(_out_error("", "protocol_error", message), sys.stdout)
    sys.exit(exit_code)


def _find_certificate(evidence: list) -> "Path | None":
    """Return the path of the first evidence item that looks like a certificate."""
    for item in evidence:
        hint = item.get("local_path", "") or item.get("path_hint", "")
        media = item.get("media_type", "")
        if hint.endswith(".json") or "certificate" in media or "certificate" in hint:
            p = Path(hint)
            if p.exists():
                return p
    return None


def _read_cert_json(cert_path: Path) -> dict:
    """Load and return the certificate JSON, or empty dict on error."""
    try:
        with open(cert_path) as f:
            return json.load(f)
    except Exception:
        return {}


def _read_cert_field(cert_data: dict, field: str) -> str:
    """Return a certificate top-level field value as a string, or ""."""
    v = cert_data.get(field, "")
    return str(v) if v else ""


def _get_obligations(inp: dict, cert_data: dict) -> list:
    """Return the obligation IDs to use for this check run.

    Priority:
    1. inp["obligation_ids"] — the ContractV2-driven exact set from proofctl (authoritative)
    2. cert_data["obligations"] — producer self-report (fallback for legacy certs)
    3. _DEFAULT_OBLIGATIONS — hard-coded default

    The input obligation_ids is the only authoritative source; a producer
    cannot shrink the set by omitting obligations from the certificate.
    """
    # 1. Authoritative: obligation_ids from CheckerInputV2
    inp_obls = inp.get("obligation_ids", [])
    if isinstance(inp_obls, list) and inp_obls:
        return [str(o) for o in inp_obls]
    # 2. Fallback: certificate self-report (legacy path)
    cert_obls = cert_data.get("obligations", [])
    if isinstance(cert_obls, list) and cert_obls:
        return [str(o) for o in cert_obls]
    # 3. Hard-coded default
    return list(_DEFAULT_OBLIGATIONS)


def _extract_margin_from_stdout(stdout: str) -> str:
    """Extract margin_ratio / pivot_radius_ratio from checker stdout.

    Tries three formats:
      1. JSON object with a "margin_ratio" or "pivot_radius_ratio" key.
      2. Plain-text lines with key=value pairs (e.g. "margin_ratio=3.3e8").
      3. Checker natural-language format: "margin ratio = <value>" or
         "margin ratio = <value> (..." (as printed by check_certificate.py).
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
    # key=value scan (underscore form).
    m = re.search(
        r"(?:^|[\s,;])(?:pivot_radius_ratio|margin_ratio)\s*=\s*([^\s,;]+)",
        text, re.IGNORECASE | re.MULTILINE,
    )
    if m:
        return m.group(1)
    # Natural-language format: "[checker] margin ratio = min_pivot_lo / pivot_width = 33777230.07 (...)"
    # Extract the last numeric value before any trailing parenthetical comment.
    for line in text.splitlines():
        if re.search(r"margin\s+ratio", line, re.IGNORECASE):
            part = line.split("(")[0]  # strip trailing parenthetical comment
            nums = re.findall(r"=\s*([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)", part)
            if nums:
                return nums[-1]
    return ""


def main() -> None:
    checker_cmd = os.environ.get("BRIDGE_CHECKER", "")
    if not checker_cmd:
        _die(3, "BRIDGE_CHECKER environment variable not set")

    inp = _read_input()
    claim_id: str = inp.get("claim_id", "")
    evidence: list = inp.get("evidence", [])

    cert_path = _find_certificate(evidence)
    cert_data = _read_cert_json(cert_path) if cert_path is not None else {}
    obligation_ids = _get_obligations(inp, cert_data)

    # Collect evidence digests actually used.
    evidence_digests = []
    if cert_path is not None:
        for item in evidence:
            hint = item.get("local_path", "") or item.get("path_hint", "")
            if hint and str(cert_path) in hint:
                d = item.get("digest", "")
                if d:
                    evidence_digests.append(d)

    if cert_path is None:
        json.dump(
            _out_obligations(claim_id, obligation_ids, "fail",
                             explanation="no certificate JSON found in evidence paths"),
            sys.stdout,
        )
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

    # exit 2 — malformed certificate: emit CheckerErrorV2 (no obligation_results).
    if checker_exit == 2:
        json.dump(
            _out_error(claim_id, "malformed_certificate",
                       result.stderr.strip() or "certificate schema violation (exit 2)"),
            sys.stdout,
        )
        sys.exit(0)

    # exit != 0 (and not 2) — checker rejected the proof: all obligations fail.
    if checker_exit != 0:
        json.dump(
            _out_obligations(claim_id, obligation_ids, "fail",
                             explanation=result.stderr.strip() or f"checker exit {checker_exit}"),
            sys.stdout,
        )
        sys.exit(0)

    # exit 0 — CERTIFIED. Build shared metadata; all obligations pass.
    metadata: dict = {
        "digests_fresh": "true",
        "path_keys_match": "true",
        "intervals_intersect": "true",
        "matrix_reconstructed": "true",
        "ldlt_passes": "true",
    }

    fmt_ver = _read_cert_field(cert_data, "format_version")
    if fmt_ver:
        metadata["cap_format_version"] = fmt_ver

    # pivot_radius_ratio: prefer cert top-level field, fall back to checker stdout.
    margin = _read_cert_field(cert_data, "margin_ratio")
    if not margin:
        margin = _extract_margin_from_stdout(result.stdout)
    if margin:
        metadata["pivot_radius_ratio"] = margin

    sector = _read_cert_field(cert_data, "sector")
    if sector == "odd":
        metadata["odd_sector_passes"] = "true"
    elif sector == "even":
        metadata["even_sector_passes"] = "true"

    # window_verified: the window identifier string from the certificate.
    window = _read_cert_field(cert_data, "window")
    if window:
        metadata["window_verified"] = window

    # archimedean_obligation: obligation field inside archimedean_base sub-object.
    arch_obl = (cert_data.get("archimedean_base") or {}).get("obligation", "")
    if arch_obl:
        metadata["archimedean_obligation"] = str(arch_obl)

    # pivot_count: number of pivots verified in the certificate.
    pivot_count = _read_cert_field(cert_data, "pivot_count")
    if pivot_count:
        metadata["pivot_count"] = pivot_count

    json.dump(
        _out_obligations(claim_id, obligation_ids, "pass", metadata=metadata,
                         evidence_used=evidence_digests),
        sys.stdout,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
