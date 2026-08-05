#!/usr/bin/env python3
"""Conformance tests for CAP bridge protocol v2 output format.

Tests that:
1. obligation results use "id" field (not "obligation_id") — P1-01 fix
2. obligation IDs come from input, not certificate self-report — P1-02 fix
3. evidence_used is populated from actual evidence digests
4. claim_id is echoed back
5. protocol_version is 2
"""
import json
import subprocess
import sys
import tempfile
import os
import unittest


def run_bridge(stdin_data: dict, env: dict = None) -> dict:
    """Run bridge.py with the given stdin and return parsed stdout."""
    bridge_path = os.path.join(os.path.dirname(__file__), "bridge.py")
    env_full = os.environ.copy()
    if env:
        env_full.update(env)
    result = subprocess.run(
        [sys.executable, bridge_path],
        input=json.dumps(stdin_data),
        capture_output=True,
        text=True,
        env=env_full,
        timeout=10,
    )
    if not result.stdout.strip():
        raise ValueError(f"bridge produced no stdout (stderr: {result.stderr!r})")
    return json.loads(result.stdout)


class TestObligationIDField(unittest.TestCase):
    """P1-01: obligation results must use 'id' field, not 'obligation_id'."""

    def setUp(self):
        # Create a minimal certificate file and a fake checker.
        self.tmp = tempfile.mkdtemp()
        cert = {"result": "ok"}
        self.cert_path = os.path.join(self.tmp, "cert.json")
        with open(self.cert_path, "w") as f:
            json.dump(cert, f)
        # Fake checker: always exits 0, prints nothing to stdout.
        checker_path = os.path.join(self.tmp, "checker.sh")
        with open(checker_path, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(checker_path, 0o755)
        self.env = {"BRIDGE_CHECKER": f"sh {checker_path}"}

    def test_obligation_results_use_id_field(self):
        inp = {
            "claim_id": "thm-test",
            "evidence": [{"local_path": self.cert_path, "digest": "sha256:abcd"}],
            "obligation_ids": ["obl.A", "obl.B"],
        }
        out = run_bridge(inp, self.env)
        self.assertEqual(out.get("protocol_version"), 2)
        self.assertEqual(out.get("claim_id"), "thm-test")
        results = out.get("obligation_results", [])
        self.assertTrue(len(results) > 0, "obligation_results must be non-empty")
        for r in results:
            self.assertIn("id", r, f"obligation result must have 'id' field, got: {r}")
            self.assertNotIn("obligation_id", r,
                             f"'obligation_id' field must not appear in result: {r}")

    def test_obligation_ids_from_input_not_certificate(self):
        """P1-02: obligation IDs must come from input, not certificate."""
        # Certificate declares its own obligations — bridge must ignore them.
        cert = {"obligations": ["cert.fake-obl-1", "cert.fake-obl-2"]}
        cert_path = os.path.join(self.tmp, "cert_with_obls.json")
        with open(cert_path, "w") as f:
            json.dump(cert, f)
        inp = {
            "claim_id": "thm-test",
            "evidence": [{"local_path": cert_path, "digest": "sha256:efgh"}],
            "obligation_ids": ["input.obl-A", "input.obl-B"],
        }
        out = run_bridge(inp, self.env)
        results = out.get("obligation_results", [])
        ids = [r.get("id") for r in results]
        self.assertIn("input.obl-A", ids, "input obligation IDs must appear in results")
        self.assertIn("input.obl-B", ids, "input obligation IDs must appear in results")
        self.assertNotIn("cert.fake-obl-1", ids,
                         "certificate obligation IDs must NOT appear when input IDs provided")

    def test_evidence_used_populated(self):
        """evidence_used must be populated with actual evidence digest."""
        inp = {
            "claim_id": "thm-test",
            "evidence": [{"local_path": self.cert_path, "digest": "sha256:abcd1234"}],
            "obligation_ids": ["obl.A"],
        }
        out = run_bridge(inp, self.env)
        evidence_used = out.get("evidence_used", [])
        self.assertTrue(len(evidence_used) > 0,
                        "evidence_used must be populated on success")

    def test_claim_id_echoed(self):
        inp = {
            "claim_id": "thm-echo-test",
            "evidence": [{"local_path": self.cert_path, "digest": "sha256:abcd"}],
            "obligation_ids": ["obl.A"],
        }
        out = run_bridge(inp, self.env)
        self.assertEqual(out.get("claim_id"), "thm-echo-test")

    def test_no_bridge_checker_exits_3(self):
        """Missing BRIDGE_CHECKER must exit 3 (protocol error)."""
        inp = {"claim_id": "thm-test", "evidence": [], "obligation_ids": []}
        # Remove BRIDGE_CHECKER from env.
        bridge_env = os.environ.copy()
        bridge_env.pop("BRIDGE_CHECKER", None)
        bridge_path = os.path.join(os.path.dirname(__file__), "bridge.py")
        result = subprocess.run(
            [sys.executable, bridge_path],
            input=json.dumps(inp),
            capture_output=True,
            text=True,
            env=bridge_env,
            timeout=10,
        )
        self.assertEqual(result.returncode, 3, f"expected exit 3, got {result.returncode}")


if __name__ == "__main__":
    unittest.main()
