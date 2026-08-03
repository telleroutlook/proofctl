"""
test_tamper_basic.py — generic tamper tests for any CAP certificate checker.

These tests verify that the checker correctly REJECTS malformed or tampered
certificates. Every test must produce exit code != 0.

To run:
    pytest tests/negative/test_tamper_basic.py

To point at a different certificate directory:
    CERT_DIR=certificates/033/primary pytest tests/negative/

To use a different checker:
    CHECKER_CMD="python3 checker/check_certificate.py" pytest tests/negative/
"""
import copy
import json
import subprocess
import tempfile
import pathlib
import pytest


def _run_checker(checker_cmd: list[str], cert: dict) -> int:
    """Write cert to a temp file, run checker, return exit code."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(cert, f)
        tmp = f.name
    result = subprocess.run(checker_cmd + [tmp], capture_output=True)
    pathlib.Path(tmp).unlink(missing_ok=True)
    return result.returncode


# ---------------------------------------------------------------------------
# T1: wrong conclusion
# ---------------------------------------------------------------------------
def test_tamper_conclusion_uncertified(cert_data, checker_cmd):
    """Checker must reject a certificate whose conclusion is UNCERTIFIED."""
    cert = copy.deepcopy(cert_data)
    cert["conclusion"] = "UNCERTIFIED"
    assert _run_checker(checker_cmd, cert) != 0, (
        "checker accepted certificate with conclusion=UNCERTIFIED"
    )


# ---------------------------------------------------------------------------
# T2: unknown top-level field
# ---------------------------------------------------------------------------
def test_tamper_unknown_field(cert_data, checker_cmd):
    """Checker must reject a certificate with an unknown top-level field."""
    cert = copy.deepcopy(cert_data)
    cert["__injected_field__"] = "malicious"
    assert _run_checker(checker_cmd, cert) != 0, (
        "checker accepted certificate with unknown top-level field"
    )


# ---------------------------------------------------------------------------
# T3: wrong format_version
# ---------------------------------------------------------------------------
def test_tamper_wrong_version(cert_data, checker_cmd):
    """Checker must reject a certificate with an unsupported format_version."""
    cert = copy.deepcopy(cert_data)
    cert["format_version"] = "0.0"
    assert _run_checker(checker_cmd, cert) != 0, (
        "checker accepted certificate with format_version=0.0"
    )


# ---------------------------------------------------------------------------
# T4: empty witnesses_a
# ---------------------------------------------------------------------------
def test_tamper_empty_witnesses_a(cert_data, checker_cmd):
    """Checker must reject a certificate with an empty witnesses_a set."""
    cert = copy.deepcopy(cert_data)
    if "witnesses_a" in cert:
        cert["witnesses_a"] = {}
        assert _run_checker(checker_cmd, cert) != 0, (
            "checker accepted certificate with empty witnesses_a"
        )
    else:
        pytest.skip("certificate has no witnesses_a field")


# ---------------------------------------------------------------------------
# T5: kappa_upper set to zero
# ---------------------------------------------------------------------------
def test_tamper_kappa_zero(cert_data, checker_cmd):
    """Checker must reject a certificate with kappa_upper = 0."""
    cert = copy.deepcopy(cert_data)
    if "kappa_upper" in cert:
        cert["kappa_upper"] = "0"
        assert _run_checker(checker_cmd, cert) != 0, (
            "checker accepted certificate with kappa_upper=0"
        )
    else:
        pytest.skip("certificate has no kappa_upper field")
