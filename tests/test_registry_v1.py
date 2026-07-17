"""Freeze the v1 registry (c1dd0001ee) and prove it lawfully composes.

The constitution says how registries are read; v1 says which types exist.
These tests pin three things:

  1. the delta discipline — v1 carries only its legislation (15 type
     entries, no 0xee, no conventions); everything else inherits from the
     constitution via the parent chain, nothing re-declared;
  2. the frozen bytes — tests/golden/registry_v1_c1dd0001ee.hex, same
     contract as the constitution's golden: changing it is a deliberate,
     reviewed act;
  3. coverage — the composed registry (v0 <- v1) declares every type byte
     that exists in the on-chain corpus, with honest statuses. The registry
     that cannot name the corpus would be legislation that forgot its
     country.
"""
import os

import pytest

from envelope import parse_envelope, VERSION_CONSTITUTION, VERSION_V1
from constitution import build_constitution
from registry_v1 import build_registry_v1, v1_types, v1_type_entry
from estandarte import (
    read_estandarte_quipu, resolve_estandarte_chain, _example_registry,
    TYPE_ESTANDARTE, STATUS_CANONICAL, STATUS_DRAFT, STATUS_DEPRECATED,
)

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "golden", "registry_v1_c1dd0001ee.hex")

V0_TXID, V1_TXID = "aa" * 32, "bb" * 32


def _composed():
    """Resolve the two-link chain v0 <- v1 with an in-memory fetcher."""
    h0, b0 = build_constitution()
    h1, b1 = build_registry_v1(parent_txid=V0_TXID)
    blobs = {V0_TXID: h0 + b0, V1_TXID: h1 + b1}
    return resolve_estandarte_chain(V1_TXID, blobs.__getitem__)


# ---------------------------------------------------------------------------
# 1. Delta discipline
# ---------------------------------------------------------------------------

def test_v1_is_version_one_ordinary():
    header, body = build_registry_v1()
    version, type_byte, tone = parse_envelope(header)
    assert version == VERSION_V1 == 0x0001
    assert type_byte == 0xee
    assert tone == 0x00   # ordinary — the working declaration, not the freeze


def test_v1_carries_only_its_legislation():
    parsed = read_estandarte_quipu(*build_registry_v1())
    # no 0xee re-declaration (constitutional, inherited), no conventions
    assert all(t["byte"] != TYPE_ESTANDARTE for t in parsed["types"])
    assert parsed["conventions"] == []
    # exactly the non-0xee entries of the single source, same order
    expected = [t["byte"] for t in _example_registry()[0]
                if t["byte"] != TYPE_ESTANDARTE]
    assert [t["byte"] for t in parsed["types"]] == expected
    assert len(parsed["types"]) == 15


def test_amendment_form_differs_only_by_parent_prefix():
    # The golden freezes the root form (no txid exists pre-inscription);
    # the inscribed form must differ ONLY by the 33-byte parent prefix.
    root_h, root_b = build_registry_v1()
    amend_h, amend_b = build_registry_v1(parent_txid="cc" * 32)
    assert amend_h == root_h
    assert root_b[0] == 0x00 and amend_b[0] == 0x01
    assert amend_b[1:33] == bytes.fromhex("cc" * 32)
    assert amend_b[33:] == root_b[1:]


# ---------------------------------------------------------------------------
# 2. The freeze
# ---------------------------------------------------------------------------

def test_v1_bytes_are_frozen():
    header, body = build_registry_v1()
    with open(GOLDEN) as f:
        frozen = f.read().strip()
    assert (header + body).hex() == frozen, (
        "the v1 registry bytes changed vs tests/golden/registry_v1_c1dd0001ee.hex. "
        "Regenerating the golden is a deliberate, reviewed act — the registry is "
        "legislation, and legislation is diffed, not drifted.")


def test_v1_work_does_not_move_the_constitution():
    # Legislation must never move the founding bytes.
    c_golden = os.path.join(os.path.dirname(GOLDEN), "constitution_c1dd0000ee.hex")
    h, b = build_constitution()
    with open(c_golden) as f:
        assert (h + b).hex() == f.read().strip()


# ---------------------------------------------------------------------------
# 3. Composition and coverage
# ---------------------------------------------------------------------------

def test_composes_to_the_full_registry():
    merged = _composed()
    assert merged["chain_length"] == 2
    assert merged["root_txid"] == V0_TXID
    all_types, all_conv = _example_registry()
    assert sorted(merged["types"]) == sorted(t["byte"] for t in all_types)
    assert sorted(merged["conventions"]) == sorted(c["name"] for c in all_conv)
    # provenance: 0xee and conventions come from the constitution, the
    # legislation from v1 — nothing double-declared
    assert merged["types"][TYPE_ESTANDARTE]["_source_txid"] == V0_TXID
    for byte, entry in merged["types"].items():
        if byte != TYPE_ESTANDARTE:
            assert entry["_source_txid"] == V1_TXID
    for conv in merged["conventions"].values():
        assert conv["_source_txid"] == V0_TXID


def test_composed_registry_covers_the_corpus(corpus):
    # Every type byte actually inscribed on chain must be declared in the
    # composed registry. A registry that cannot name the corpus is
    # legislation that forgot its country.
    merged = _composed()
    declared = set(merged["types"])
    on_chain = {int(str(tb), 16) for tb in corpus["type_byte"].unique()}
    missing = sorted(b for b in on_chain if b not in declared)
    assert not missing, \
        f"corpus type bytes not declared in v1 registry: {[hex(b) for b in missing]}"


def test_declared_celestial_kinds_cover_canonical_corpus(corpus):
    # Dimension-VALUE coverage (the check that would have caught a missing
    # kind enum value): every kind byte on a canonical_v1 celestial row
    # must be a declared value. Pre-canonical rows are excused by the
    # pre-canonical convention (kind=3 genealogy pair, kind=129 prototype).
    import json as _json
    merged = _composed()
    kind_dim = next(d for d in merged["types"][0xce]["dimensions"]
                    if d["name"] == "kind")
    declared = {v["value"] for v in kind_dim["values"]}
    checked = 0
    for _, r in corpus.iterrows():
        if str(r.type_byte) != "0xce" or r.canonical_status != "canonical_v1":
            continue
        dims = _json.loads(r.dimensions_json) if isinstance(r.dimensions_json, str) else {}
        k = dims.get("kind")
        assert k in declared, \
            f"{str(r.root_txid)[:8]}: on-chain kind {k} not declared in the registry"
        checked += 1
    assert checked > 0, "no canonical_v1 celestial rows checked — dataset moved?"


def test_statuses_are_honest():
    entries = {t["byte"]: t for t in v1_types()}
    assert entries[0x0c]["status"] == STATUS_DEPRECATED   # cert-precursor
    assert entries[0x1d]["status"] == STATUS_DRAFT        # identity
    for byte in (0x00, 0x01, 0x03, 0x07, 0x09, 0x0e, 0x0f,
                 0x3d, 0x5c, 0xab, 0xcc, 0xce, 0xda):
        assert entries[byte]["status"] == STATUS_CANONICAL, hex(byte)


def test_entries_are_independently_addressable():
    # The unit of a future per-type peel: one entry, by its byte.
    celestial = v1_type_entry(0xce)
    assert celestial["name"] == "celestial"
    assert [d["name"] for d in celestial["dimensions"]] == \
           ["kind", "grouped", "meta"]
    with pytest.raises(KeyError):
        v1_type_entry(TYPE_ESTANDARTE)   # constitutional, not v1's to give
    with pytest.raises(KeyError):
        v1_type_entry(0x42)              # unlegislated
