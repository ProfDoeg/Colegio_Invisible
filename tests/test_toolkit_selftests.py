"""Run the toolkit-level test scripts (root of the repo) under pytest.

These are standalone offline suites that predate the pytest harness:
    test_quipu_crypto.py   23 crypto tests (ECIES combining, AES, key-drop)
    quipu_centinela.py     HTLC lock construction, claim/refund scriptSigs
    quipu_tags.py          7-stage tag lifecycle (engine -> reader -> sale)
Each runs in a subprocess exactly as a human would run it; the pass
banner is the contract.
"""
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(script):
    r = subprocess.run([sys.executable, os.path.join(REPO, script)],
                       capture_output=True, text=True, timeout=300, cwd=REPO)
    assert r.returncode == 0, f"{script} exited {r.returncode}:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def test_quipu_crypto_suite():
    out = _run("test_quipu_crypto.py")
    assert "23/23 passed" in out


def test_centinela_offline():
    out = _run("quipu_centinela.py")
    assert "ALL OFFLINE CHECKS PASSED" in out


def test_tags_offline():
    out = _run("quipu_tags.py")
    assert "ALL OFFLINE CHECKS PASSED" in out


@pytest.mark.rpc
@pytest.mark.skipif(os.environ.get("QUIPU_RPC_TESTS") != "1",
                    reason="needs a reachable Dogecoin node; set QUIPU_RPC_TESTS=1")
def test_smoke_against_node():
    _run("smoke_test.py")
