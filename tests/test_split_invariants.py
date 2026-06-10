"""Invariants of the splitting and accounting code — the places where a
silent mistake becomes a permanently mis-inscribed quipu.

The Jeremy lesson: a round-robin strand distribution reads as garbage
through the canonical reader (contiguous concatenation). These tests pin
the contract so it cannot regress quietly.
"""
import math
import random

import pytest

import cryptos
from cryptos import deserialize as cs_deserialize

from quipu_diamond import (FeePolicy, build_consolidated_diamond, knot_count,
                           split_body, split_quipu)


# ---------------------------------------------------------------------------
#  split_body — contiguity is the law
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size,n", [
    (1, 1), (79, 1), (80, 1), (81, 2), (160, 2), (4000, 5),
    (4001, 5), (12345, 7), (80 * 24 * 3, 3), (999, 13),
])
def test_split_body_reconcatenates(size, n):
    rng = random.Random(size * 1000 + n)
    body = bytes(rng.getrandbits(8) for _ in range(size))
    strands = split_body(body, n)
    assert b"".join(strands) == body, "contiguous concatenation broken"
    assert len(strands) == max(1, n) if n > 1 else len(strands) == 1


def test_split_body_knot_aligned():
    """Every strand but the last must be a whole number of 80-byte knots —
    a partial knot mid-stream would shift every later byte on read-back."""
    body = bytes(range(256)) * 40                       # 10240 B
    for n in (2, 3, 5, 8):
        strands = split_body(body, n)
        for s in strands[:-1]:
            assert len(s) % 80 == 0, "mid-stream strand not knot-aligned"


def test_split_body_is_not_round_robin():
    """The exact Jeremy failure shape: knots[i::N] interleaving. A marker
    body whose knots are distinguishable must come out in original order."""
    knots = [bytes([i]) * 80 for i in range(12)]
    body = b"".join(knots)
    strands = split_body(body, 3)
    flat = b"".join(strands)
    for i in range(12):
        assert flat[i * 80] == i, "knot order permuted — round-robin regression"


def test_split_quipu_header_is_strand_zero():
    from text import build_text_quipu
    h, b = build_text_quipu("invariante", "z" * 500)
    strands = split_quipu(h + b)
    assert strands[0] == h, "strand 0 must be exactly the header (cabeza)"
    assert b"".join(strands[1:]) == b, "cuerpos must reconcatenate to the body"


@pytest.mark.parametrize("nbytes,expect", [(0, 1), (1, 1), (80, 1), (81, 2), (160, 2)])
def test_knot_count(nbytes, expect):
    assert knot_count(b"x" * nbytes) == expect


# ---------------------------------------------------------------------------
#  diamond accounting — every koinu must be conserved
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def funder():
    priv = cryptos.random_key()
    return priv, cryptos.Doge().privtoaddr(priv)


def _build(funder, tags_of=None, funding=60 * 10**8, sizes=(400, 900)):
    from text import build_text_quipu
    priv, addr = funder
    pieces = []
    for i, s in enumerate(sizes):
        h, b = build_text_quipu(f"pieza{i}", "x" * s)
        pieces.append((f"p{i}", h + b))
    return pieces, build_consolidated_diamond(
        pieces, lambda pid: "f" * 64,
        {"output": "%064x:0" % 0xA1, "value": funding},
        priv, addr, FeePolicy(), tags_of=tags_of, log=lambda *a: None)


def test_diamond_conserves_value(funder):
    _, art = _build(funder)
    f = art["fees"]
    assert f["total_sat"] + f["residual_sat"] == 60 * 10**8, "koinu leaked"


def test_diamond_with_tags_conserves_value(funder):
    _, addr = funder
    tags = {"p1": [{"value": 10_000_000, "address": addr}]}
    _, art = _build(funder, tags_of=tags)
    f = art["fees"]
    assert f["total_sat"] + f["tag_sat"] + f["residual_sat"] == 60 * 10**8
    # the tag rides the root, after the seeds, and the join ignores it
    root = cs_deserialize(art["roots"]["p1"][0])
    n_strands = len(art["strands"]["p1"])
    assert len(root["outs"]) == n_strands + 1
    join = cs_deserialize(art["join"][0])
    assert len(join["ins"]) == art["totals"]["strands"]


def test_diamond_roundtrips_bodies(funder):
    pieces, art = _build(funder)
    for pid, blob in pieces:
        assert art["bodies"][pid] == blob, f"{pid}: inscribed bytes != source"


def test_diamond_insufficient_funds_raises(funder):
    with pytest.raises(ValueError, match="insufficient"):
        _build(funder, funding=10**7)               # 0.1 DOGE can't cover fees


def test_diamond_rejects_dust_tag(funder):
    _, addr = funder
    with pytest.raises(AssertionError, match="dust"):
        _build(funder, tags_of={"p0": [{"value": 10_000, "address": addr}]})
