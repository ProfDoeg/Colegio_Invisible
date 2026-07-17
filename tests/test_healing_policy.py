"""The healing policy, mechanically (docs/design/healing.md).

Heal the map, never the territory: content errata are same-version
additions that supersede at the leaf while every historical leaf keeps
its original statement; format changes bump the version and may never
regress. These tests prove the resolver enforces the assertable half of
that policy and that an erratum behaves as an addition, not a rewrite.
"""
import pytest

from constitution import build_constitution
from registry_v1 import build_registry_v1, v1_type_entry
from estandarte import (
    build_estandarte_quipu, resolve_estandarte_chain, TYPE_ESTANDARTE,
)

V0, V1, V1E = "aa" * 32, "bb" * 32, "cc" * 32


def _blobs():
    h0, b0 = build_constitution()
    h1, b1 = build_registry_v1(parent_txid=V0)
    return {V0: h0 + b0, V1: h1 + b1}


def test_version_may_only_grow_toward_the_leaf():
    # Grain 2 enforced: an amendment claiming an OLDER version than its
    # parent is a later law rewriting an earlier standard's past — refused.
    blobs = _blobs()
    h_bad, b_bad = build_estandarte_quipu([], [], version=0, parent_txid=V1)
    blobs[V1E] = h_bad + b_bad
    with pytest.raises(ValueError, match="version regression"):
        resolve_estandarte_chain(V1E, blobs.__getitem__)


def test_version_growth_and_plateau_are_lawful():
    # Both lawful shapes in one chain: a same-version plateau link (a
    # grain-1 erratum at v0 — the constitution's CONTENT may heal
    # in-version) and a growth link (v0 -> v1).
    h0, b0 = build_constitution()
    h0e, b0e = build_estandarte_quipu([], [], version=0, parent_txid=V0)
    h1, b1 = build_registry_v1(parent_txid=V1E)
    blobs = {V0: h0 + b0, V1E: h0e + b0e, V1: h1 + b1}
    merged = resolve_estandarte_chain(V1, blobs.__getitem__)
    assert [est["version"] for est in merged["chain"]] == [0, 0, 1]


def test_erratum_is_an_addition_not_a_rewrite():
    # Grain 1 end-to-end: a same-version erratum corrects one entry's
    # description. At the new leaf the correction wins; at the OLD leaf the
    # original statement is still exactly what it was — additions, never
    # rewrites; originals stay, silent.
    blobs = _blobs()
    original = v1_type_entry(0x00)
    corrected = dict(original, desc=original["desc"] + " (erratum: clarified)")
    h_e, b_e = build_estandarte_quipu([corrected], [], version=1, parent_txid=V1)
    blobs[V1E] = h_e + b_e

    at_erratum = resolve_estandarte_chain(V1E, blobs.__getitem__)
    at_old_leaf = resolve_estandarte_chain(V1, blobs.__getitem__)

    # the correction wins at the new leaf, and is attributed to the erratum
    assert at_erratum["types"][0x00]["desc"].endswith("(erratum: clarified)")
    assert at_erratum["types"][0x00]["_source_txid"] == V1E
    # the historical leaf still reads exactly as it always did
    assert at_old_leaf["types"][0x00]["desc"] == original["desc"]
    assert at_old_leaf["types"][0x00]["_source_txid"] == V1
    # and the erratum touched nothing else: every other entry identical
    for byte, entry in at_old_leaf["types"].items():
        if byte != 0x00:
            new = dict(at_erratum["types"][byte]); new.pop("_source_txid")
            old = dict(entry); old.pop("_source_txid")
            assert new == old, hex(byte)


def test_the_constitution_still_arrives_through_an_erratum_leaf():
    # Chain depth does not erode inheritance: 0xee + conventions still
    # come from the constitution at a 3-link leaf.
    blobs = _blobs()
    h_e, b_e = build_estandarte_quipu(
        [dict(v1_type_entry(0x00), desc="x")], [], version=1, parent_txid=V1)
    blobs[V1E] = h_e + b_e
    merged = resolve_estandarte_chain(V1E, blobs.__getitem__)
    assert merged["types"][TYPE_ESTANDARTE]["_source_txid"] == V0
    assert merged["conventions"]["magic"]["_source_txid"] == V0
    assert merged["chain_length"] == 3
