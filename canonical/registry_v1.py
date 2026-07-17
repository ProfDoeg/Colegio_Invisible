"""
registry_v1.py — c1dd0001ee, the v1 registry: legislation under the constitution.

The constitution (c1dd0000ee, constitution.py) declares how any registry is
read; the v1 registry declares WHICH TYPES EXIST — the working vocabulary of
the c1dd0001 corpus. Constitution : legislation :: how : what.

Inherit + delta (c1dd0002 §2). The v1 estandarte is an AMENDMENT riding on
the constitution: at inscription time its parent_txid points at the
constitution's root, and it carries only what v1 adds —

    carries:   the type entries for every byte EXCEPT 0xee
               (text, essay, image, sound, book, cert-precursor, encrypted,
                file, identity, scene, latex, binding, cert, celestial,
                dancer — statuses honest: 0x0c deprecated, 0x1d draft)
    inherits:  the 0xee self-entry and all thirteen cross-cutting
               conventions (incl. tag, ripcord, genesis, despot, amend,
               commentary), unchanged from the constitution (leaf-wins
               composition brings them through; nothing is ever
               re-declared)

A resolver walking leaf(v1) -> root(v0) therefore composes the full
registry: 16 types + 13 conventions. Each type entry is keyed by its type
byte — the same key a future per-type peel would amend on — so the monolith
is one inscription, not one lump: any entry can later be superseded
individually by a keyed amendment without touching its neighbors.

Tone is ordinary (0x00): this is the working protocol declaration, not the
commemorative freeze (docs/quipu-types/estandarte.md tone table).

NOT INSCRIBED. The constitution has no txid yet, so build_registry_v1's
parent_txid defaults to None (root form) — that form is what the golden
vector freezes, since content must be reviewable before any txid exists.
At inscription the ceremony passes the constitution's root txid and the
bytes change ONLY by the 33-byte parent prefix (0x01 + txid replacing
0x00); tests pin exactly that.

INVARIANT — the version's locus (c1dd0002 §8). This registry is a
MONOLITH because the envelope's version field tracks registry currency:
the version IS the snapshot, so one registry declares it. If you are
about to split this into per-type registries, registry currency must move
into a manifest (the curated-set quipu) in the same change — bytes 2-3
are constitutional and never vacate; they freeze at the split's
era-version while the manifest takes over "the protocol is at vN". Never
per-type chains AND a global-currency version stamp at once. The trigger
for the split is the grammar fold's schema pin: the split ships with the
first inscription that pins its grammar. Not before.
"""

from __future__ import annotations

from envelope import VERSION_V1
from estandarte import (
    build_estandarte_quipu, read_estandarte_quipu, _example_registry,
    TYPE_ESTANDARTE,
)
from tone import TONE_ORDINARY


def v1_types():
    """The v1 legislation: every type entry except the 0xee self-entry
    (which is constitutional and inherits from c1dd0000ee). Derived from
    the single source so nothing here can drift."""
    all_types, _conv = _example_registry()
    return [t for t in all_types if t["byte"] != TYPE_ESTANDARTE]


def v1_type_entry(type_byte):
    """The v1 entry for one type byte — the unit a future per-type peel
    would amend on. Raises KeyError for bytes v1 does not legislate."""
    for t in v1_types():
        if t["byte"] == type_byte:
            return t
    raise KeyError(f"type {type_byte:#04x} not legislated in v1")


def build_registry_v1(parent_txid=None):
    """Build c1dd0001ee — the v1 registry — and return (header, body).

    parent_txid: the constitution's root txid (64-hex). None builds the
    root form (what the golden vector freezes, pre-inscription); the
    inscription ceremony passes the real txid, changing only the parent
    prefix bytes.
    """
    return build_estandarte_quipu(
        v1_types(), [],                 # conventions inherit from v0
        tone=TONE_ORDINARY,
        version=VERSION_V1,
        parent_txid=parent_txid,
    )


def preflight_inscription_form(header_bytes, body_bytes):
    """Refuse the one wrong ceremony: inscribing legislation without its
    constitution. Any estandarte of version >= 1 must be an AMENDMENT
    (parent_kind 0x01, parent -> ultimately the c1dd0000ee root); only the
    constitution itself (version 0) may be a root. The golden vector is the
    parentless form — content review, not inscription bytes — so a ceremony
    that lifts golden bytes verbatim must fail here, rebuild with
    parent_txid, and re-run. Returns the parsed registry on success."""
    parsed = read_estandarte_quipu(header_bytes, body_bytes)
    if parsed["version"] >= 1 and parsed["parent_txid"] is None:
        raise ValueError(
            f"estandarte v{parsed['version']} has no parent_txid: legislation "
            f"must ride the constitution (rebuild with parent_txid = the "
            f"c1dd0000ee root before inscribing; the golden's root form is "
            f"for content review only)")
    return parsed


# ---------------------------------------------------------------------------
# Self-tests (collected by tests/test_canonical_selftests.py)
# ---------------------------------------------------------------------------

def _selftest_is_v1_ordinary_delta():
    h, b = build_registry_v1()
    parsed = read_estandarte_quipu(h, b)
    assert parsed["version"] == VERSION_V1 == 0x0001
    assert parsed["tone"] == TONE_ORDINARY
    assert parsed["parent_txid"] is None          # root form pre-inscription
    # pure delta: no 0xee re-declaration, no conventions
    assert all(t["byte"] != TYPE_ESTANDARTE for t in parsed["types"])
    assert parsed["conventions"] == []


def _selftest_composes_with_constitution():
    from constitution import build_constitution
    from estandarte import resolve_estandarte_chain
    V0_TXID, V1_TXID = "aa" * 32, "bb" * 32
    h0, b0 = build_constitution()
    h1, b1 = build_registry_v1(parent_txid=V0_TXID)
    blobs = {V0_TXID: h0 + b0, V1_TXID: h1 + b1}
    merged = resolve_estandarte_chain(V1_TXID, blobs.__getitem__)
    assert merged["chain_length"] == 2
    assert merged["root_txid"] == V0_TXID
    # full registry: v1's legislation + v0's 0xee self-entry and conventions
    all_types, all_conv = _example_registry()
    assert sorted(merged["types"]) == sorted(t["byte"] for t in all_types)
    assert sorted(merged["conventions"]) == sorted(c["name"] for c in all_conv)
    # the 0xee entry arrives from the CONSTITUTION, not from v1
    assert merged["types"][TYPE_ESTANDARTE]["_source_txid"] == V0_TXID


def _selftest_amendment_form_differs_only_by_parent_prefix():
    root_h, root_b = build_registry_v1()
    amend_h, amend_b = build_registry_v1(parent_txid="cc" * 32)
    assert amend_h == root_h
    assert root_b[0] == 0x00 and amend_b[0] == 0x01
    assert amend_b[1:33] == bytes.fromhex("cc" * 32)
    assert amend_b[33:] == root_b[1:]             # content bytes identical


def _selftest_preflight_refuses_rootless_legislation():
    from constitution import build_constitution
    # the root-form v1 (golden bytes) must be refused for inscription...
    try:
        preflight_inscription_form(*build_registry_v1())
    except ValueError as e:
        assert "constitution" in str(e)
    else:
        raise AssertionError("parentless v1 passed inscription preflight")
    # ...the amendment form and the constitution itself must pass
    parsed = preflight_inscription_form(*build_registry_v1(parent_txid="dd" * 32))
    assert parsed["parent_txid"] == "dd" * 32
    parsed0 = preflight_inscription_form(*build_constitution())
    assert parsed0["version"] == 0 and parsed0["parent_txid"] is None


if __name__ == "__main__":
    _selftest_is_v1_ordinary_delta()
    _selftest_composes_with_constitution()
    _selftest_amendment_form_differs_only_by_parent_prefix()
    _selftest_preflight_refuses_rootless_legislation()
    h, b = build_registry_v1()
    n = len(v1_types())
    print("c1dd0001ee v1 registry — working-tree freeze (NOT inscribed)")
    print(f"  header: {h.hex()}")
    print(f"  body:   {len(b)} bytes, {n} type entries, 0 conventions (inherited)")
