"""
conftest.py — pytest fixtures for negative (tamper) tests.

Place certificate files under certificates/ in the project root.
The CERT_DIR environment variable overrides the default path.
"""
import json
import os
import pathlib
import copy
import pytest

_DEFAULT_CERT_DIR = pathlib.Path(__file__).parent.parent.parent / "certificates"


def _cert_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get("CERT_DIR", _DEFAULT_CERT_DIR))


def _find_certs() -> list[pathlib.Path]:
    d = _cert_dir()
    if not d.exists():
        return []
    return sorted(d.rglob("*.json"))


@pytest.fixture(params=_find_certs(), ids=lambda p: p.name)
def cert_path(request) -> pathlib.Path:
    """Yields the path to each certificate found under certificates/."""
    return request.param


@pytest.fixture()
def cert_data(cert_path) -> dict:
    """Yields a deep-copied parsed certificate dict (safe to mutate)."""
    with open(cert_path) as f:
        return json.load(f)


@pytest.fixture()
def checker_cmd() -> list[str]:
    """Returns the checker command as a list.
    Override with CHECKER_CMD environment variable (space-separated).
    Default: python3 checker/check_certificate.py
    """
    cmd = os.environ.get("CHECKER_CMD", "python3 checker/check_certificate.py")
    return cmd.split()
