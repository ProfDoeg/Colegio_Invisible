"""Freeze the v2 registry (c1dd0002ee) and prove it lawfully composes.

The constitution says how registries are read; v1 says which types exist;
v2 says only what the second standard changes. These tests pin four things:

  1. the delta discipline — v2 carries exactly its delta (the celestial
     entry + the atoms/date/strings conventions); everything untouched
     inherits over the three-link chain v0 <- v1 <- v2, nothing
     re-declared;
  2. the frozen bytes — tests/golden/registry_v2_c1dd0002ee.hex, same
     contract as the v0/v1 goldens: changing it is a deliberate,
     reviewed act — and v2 work moves neither ancestor's bytes;
  3. composition — leaf-wins gives celestial v2's voice while every
     other key keeps its source, and the composed registry still covers
     the on-chain corpus;
  4. the resolutions of c1dd0002 §10 (settled with Anthony 2026-07-17) —
     the v2 entry is canonical outright, one date mechanism (no meta
     value 0x01), and NTYPE_UNCERTAIN is not in network's v2 grammar.
"""
import json
import os

import pytest

from envelope import parse_envelope, VERSION_V2
from constitution import build_constitution
from registry_v1 import build_registry_v1
from registry_v2 import (
    build_registry_v2, v2_types, v2_conventions, v2_type_entry,
    preflight_inscription_form, TYPE_CELESTIAL,
)
from estandarte import (
    read_estandarte_quipu, resolve_estandarte_chain, _example_registry,
    TYPE_ESTANDARTE, STATUS_CANONICAL,
)
from atoms import ATOM_NAMES, DATE_PRECISION_NAMES

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")
GOLDEN = os.path.join(GOLDEN_DIR, "registry_v2_c1dd0002ee.hex")

V0_TXID, V1_TXID, V2_TXID = "aa" * 32, "bb" * 32, "cc" * 32


def _composed():
    """Resolve the three-link chain v0 <- v1 <- v2 with an in-memory fetcher."""
    h0, b0 = build_constitution()
    h1, b1 = build_registry_v1(parent_txid=V0_TXID)
    h2, b2 = build_registry_v2(parent_txid=V1_TXID)
    blobs = {V0_TXID: h0 + b0, V1_TXID: h1 + b1, V2_TXID: h2 + b2}
    return resolve_estandarte_chain(V2_TXID, blobs.__getitem__)


# ---------------------------------------------------------------------------
# 1. Delta discipline
# ---------------------------------------------------------------------------

def test_v2_is_version_two_ordinary():
    header, body = build_registry_v2()
    version, type_byte, tone = parse_envelope(header)
    assert version == VERSION_V2 == 0x0002
    assert type_byte == 0xee
    assert tone == 0x00   # ordinary — the working declaration, not the freeze


def test_v2_carries_only_its_delta():
    parsed = read_estandarte_quipu(*build_registry_v2())
    # one type entry: the celestial override; no 0xee re-declaration
    assert [t["byte"] for t in parsed["types"]] == [TYPE_CELESTIAL]
    # three new conventions; none of the constitution's re-declared
    assert [c["name"] for c in parsed["conventions"]] == \
           ["atoms", "date", "strings"]
    founding = {c["name"] for c in _example_registry()[1]}
    assert founding.isdisjoint({c["name"] for c in parsed["conventions"]})


def test_amendment_form_differs_only_by_parent_prefix():
    # The golden freezes the root form (no txid exists pre-inscription);
    # the inscribed form must differ ONLY by the 33-byte parent prefix.
    root_h, root_b = build_registry_v2()
    amend_h, amend_b = build_registry_v2(parent_txid="dd" * 32)
    assert amend_h == root_h
    assert root_b[0] == 0x00 and amend_b[0] == 0x01
    assert amend_b[1:33] == bytes.fromhex("dd" * 32)
    assert amend_b[33:] == root_b[1:]


def test_preflight_refuses_rootless_legislation():
    with pytest.raises(ValueError, match="constitution"):
        preflight_inscription_form(*build_registry_v2())
    parsed = preflight_inscription_form(*build_registry_v2(parent_txid="ee" * 32))
    assert parsed["parent_txid"] == "ee" * 32


# ---------------------------------------------------------------------------
# 2. The freeze
# ---------------------------------------------------------------------------

def test_v2_bytes_are_frozen():
    header, body = build_registry_v2()
    with open(GOLDEN) as f:
        frozen = f.read().strip()
    assert (header + body).hex() == frozen, (
        "the v2 registry bytes changed vs tests/golden/registry_v2_c1dd0002ee.hex. "
        "Regenerating the golden is a deliberate, reviewed act — the registry is "
        "legislation, and legislation is diffed, not drifted.")


def test_v2_work_does_not_move_the_ancestors():
    # The second standard must move neither the founding bytes nor v1's.
    for builder, name in ((build_constitution, "constitution_c1dd0000ee.hex"),
                          (build_registry_v1, "registry_v1_c1dd0001ee.hex")):
        h, b = builder()
        with open(os.path.join(GOLDEN_DIR, name)) as f:
            assert (h + b).hex() == f.read().strip(), name


# ---------------------------------------------------------------------------
# 3. Composition and coverage
# ---------------------------------------------------------------------------

def test_composes_to_the_full_registry():
    merged = _composed()
    assert merged["chain_length"] == 3
    assert merged["root_txid"] == V0_TXID
    # same key set as v0 <- v1 (v2 overrides, never adds a type byte)
    all_types, all_conv = _example_registry()
    assert sorted(merged["types"]) == sorted(t["byte"] for t in all_types)
    assert sorted(merged["conventions"]) == \
           sorted([c["name"] for c in all_conv] +
                  [c["name"] for c in v2_conventions()])
    # provenance: celestial speaks with v2's voice; every other type keeps
    # its v1 source; 0xee and the founding conventions stay constitutional
    assert merged["types"][TYPE_CELESTIAL]["_source_txid"] == V2_TXID
    assert merged["types"][TYPE_ESTANDARTE]["_source_txid"] == V0_TXID
    for byte, entry in merged["types"].items():
        if byte not in (TYPE_ESTANDARTE, TYPE_CELESTIAL):
            assert entry["_source_txid"] == V1_TXID, hex(byte)
    for name, conv in merged["conventions"].items():
        want = V2_TXID if name in ("atoms", "date", "strings") else V0_TXID
        assert conv["_source_txid"] == want, name


def test_composed_registry_covers_the_corpus(corpus):
    # Every type byte actually inscribed on chain must be declared in the
    # composed registry — the override must not orphan anything.
    merged = _composed()
    declared = set(merged["types"])
    on_chain = {int(str(tb), 16) for tb in corpus["type_byte"].unique()}
    missing = sorted(b for b in on_chain if b not in declared)
    assert not missing, \
        f"corpus type bytes not declared through v2: {[hex(b) for b in missing]}"


def test_v2_declares_celestial_kinds_for_canonical_corpus(corpus):
    # The v2 kind enum must still cover every canonical_v1 celestial row —
    # and now also declares the node-edge kinds (genealogy entered the
    # chain pre-canonically; v2 is where 0x03-0x05 enter the law).
    merged = _composed()
    kind_dim = next(d for d in merged["types"][TYPE_CELESTIAL]["dimensions"]
                    if d["name"] == "kind")
    declared = {v["value"] for v in kind_dim["values"]}
    assert {0x03, 0x04, 0x05} <= declared
    checked = 0
    for _, r in corpus.iterrows():
        if str(r.type_byte) != "0xce" or r.canonical_status != "canonical_v1":
            continue
        dims = json.loads(r.dimensions_json) if isinstance(r.dimensions_json, str) else {}
        k = dims.get("kind")
        assert k in declared, \
            f"{str(r.root_txid)[:8]}: on-chain kind {k} not declared in v2"
        checked += 1
    assert checked > 0, "no canonical_v1 celestial rows checked — dataset moved?"


# ---------------------------------------------------------------------------
# 4. The §10 resolutions, pinned
# ---------------------------------------------------------------------------

def test_celestial_v2_is_canonical_outright():
    # Resolved 2026-07-17: statuses describe reality, not choreography.
    assert v2_type_entry(TYPE_CELESTIAL)["status"] == STATUS_CANONICAL
    with pytest.raises(KeyError):
        v2_type_entry(0x00)   # untouched types keep their v1 wire and entry


def test_one_date_mechanism():
    # v1's meta value 0x01 "time" is not in the v2 grammar — the typed
    # date var (9-byte precision+jd, earth-only) is the only mechanism.
    meta = next(d for d in v2_type_entry(TYPE_CELESTIAL)["dimensions"]
                if d["name"] == "meta")
    assert [v["value"] for v in meta["values"]] == [0x00, 0x02]
    assert all(v["name"] != "time" for v in meta["values"])


def test_ntype_uncertain_is_gone():
    # Resolved 2026-07-17: the last certainty-flavored byte goes; v2
    # network nodes are place/agent/relay/resource, a closed enum.
    kind = next(d for d in v2_type_entry(TYPE_CELESTIAL)["dimensions"]
                if d["name"] == "kind")
    net = next(v for v in kind["values"] if v["name"] == "network")
    assert "uncertain" not in net["desc"]
    for want in ("place", "agent", "relay", "resource"):
        assert want in net["desc"]


def test_declaration_matches_atoms_py():
    # The on-chain atom statement is drift-checked against the single
    # source: every atom and every precision value, named byte-for-byte.
    conv = {c["name"]: c for c in v2_conventions()}
    for byte, name in ATOM_NAMES.items():
        assert f"0x{byte:02x} {name}" in conv["atoms"]["syntax"]
    for byte, name in DATE_PRECISION_NAMES.items():
        assert f"0x{byte:02x} {name}" in conv["date"]["syntax"]
