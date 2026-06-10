"""Pre-broadcast controls — the gate the Dantean Cosmos phantom proved missing.

Byte round-trips were always checked and always passed; the phantom WAS
the bytes. These tests pin the new semantic gates: undeclared 64-hex
tokens fail the BUILD, tampered artifacts fail the FLIGHT, signed-tx
payloads are judged (not the build's memory), and the legitimate
non-txid cases (declared hashes, 0xab alias left-hands) pass only by
explicit declaration or type-aware exemption — default-deny everywhere.
"""
import hashlib
import os

import pytest

import cryptos

from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
from quipu_preflight import (PreflightError, alias_lhs_tokens,
                             check_refs_resolve, extract_refs, preflight)

PH_A = "a" * 64                                   # declared placeholder, piece A


@pytest.fixture(scope="module")
def funder():
    priv = cryptos.random_key()
    return priv, cryptos.Doge().privtoaddr(priv)


def _build(funder, body_b_text, declared_ok=None):
    """Two text pieces; B's body is caller-controlled (citations, smuggled
    tokens). A is cited by placeholder and must backfill cleanly."""
    from text import build_text_quipu
    priv, addr = funder
    ha, ba = build_text_quipu("pieza A", "the cited work, " + "x" * 200)
    hb, bb = build_text_quipu("pieza B", body_b_text)
    pieces = [("A", ha + ba), ("B", hb + bb)]
    return build_consolidated_diamond(
        pieces, lambda pid: PH_A if pid == "A" else "b" * 64,
        {"output": "%064x:0" % 0xF1, "value": 60 * 10**8},
        priv, addr, FeePolicy(), declared_ok=declared_ok,
        log=lambda *a: None)


def test_healthy_diamond_flies(funder, tmp_path):
    art = _build(funder, "this cites <<%s>> and nothing else, %s" % (PH_A, "y" * 150))
    write_artifacts(art, str(tmp_path))
    summary = preflight(str(tmp_path), log=lambda *a: None)
    assert summary["pieces"] == 2
    assert summary["refs_checked"] >= 1            # the backfilled citation


def test_undeclared_standin_fails_the_build(funder):
    sneaky = hashlib.sha256(b"a stand-in nobody mapped").hexdigest()
    with pytest.raises(ValueError, match="unresolved references"):
        _build(funder, "refs a phantom <<%s>> like the orrery did, %s"
               % (sneaky, "y" * 140))


def test_declared_hash_passes_build_and_flight(funder, tmp_path):
    payload_hash = hashlib.sha256(b"an off-chain payload").hexdigest()
    art = _build(funder, "carries a legitimate hash %s (not a txid), %s"
                 % (payload_hash, "y" * 130), declared_ok=[payload_hash])
    write_artifacts(art, str(tmp_path))
    preflight(str(tmp_path), declared_ok=[payload_hash], log=lambda *a: None)
    with pytest.raises(PreflightError, match="unresolved 64-hex"):
        preflight(str(tmp_path), log=lambda *a: None)   # undeclared at the gate


def test_tampered_body_fails_the_flight(funder, tmp_path):
    art = _build(funder, "honest body citing <<%s>>, %s" % (PH_A, "y" * 150))
    write_artifacts(art, str(tmp_path))
    bin_path = tmp_path / "B.bin"
    blob = bin_path.read_bytes()
    bin_path.write_bytes(blob[:-8] + b"TAMPERED")
    with pytest.raises(PreflightError, match="signed-tx payloads != body file"):
        preflight(str(tmp_path), log=lambda *a: None)


def test_alias_lhs_exempt_rhs_must_resolve():
    """The healing-binding shape: the left-hand name dangles BY DESIGN;
    only the chain's final target must be real."""
    from bindings import build_binding_quipu
    phantom = hashlib.sha256(b"the dangling name being bound").hexdigest()
    real = "f" * 64
    h, b = build_binding_quipu("<<%s>>=<<%s>>\n" % (phantom, real), tone=0x00)
    blob = h + b
    assert phantom in {t for t in extract_refs(blob)}
    assert phantom in alias_lhs_tokens(blob)
    # rhs known -> clean; rhs unknown -> exactly one failure naming it
    assert check_refs_resolve({"heal": blob}, [], known_txids={real}) == []
    fails = check_refs_resolve({"heal": blob}, [], known_txids=set())
    assert len(fails) == 1 and real[:16] in fails[0]


def test_extract_refs_sees_ascii_hex_everywhere():
    blob = (b"\xc1\xdd\x00\x01\x00\x00|t|" +
            b"json {\"quipu_ref\": \"" + b"c" * 64 + b"\"} and <<" + b"d" * 64 + b">>")
    assert extract_refs(blob) == {"c" * 64, "d" * 64}
