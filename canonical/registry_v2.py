"""
registry_v2.py — c1dd0002ee, the v2 registry: the second standard's delta.

The constitution (c1dd0000ee) declares how any registry is read; the v1
registry (c1dd0001ee) declares which types exist; v2 declares the second
standard — and, per the re-engineering criterion (c1dd0002 §2), it states
ONLY its delta. Every type v0.2 does not touch keeps its v1 wire and its
v1 entry; a mixed-version corpus is correct by construction.

Inherit + delta, one more link. At inscription time this estandarte's
parent_txid points at the v1 registry's leaf, which rides the
constitution — a three-link chain v0 <- v1 <- v2, leaf-wins. It carries:

    types:        the celestial (0xce) v2 entry — a keyed override of
                  v1's. The v2 grammar: kinds grown to the node-edge
                  family (genealogy 0x03, etymology 0x04, network 0x05 —
                  on chain and in code since birth, now in the law); ONE
                  date mechanism (the typed date var, 9-byte
                  precision+jd, earth points only — v1's meta value 0x01
                  "time" is not in the v2 grammar, so the meta enum
                  declares 0x00/0x02 only and a v2 blob carrying 0x01 is
                  malformed); f32 coordinates ratified with their
                  quantization stated honestly (~2.4 m on the ground,
                  ~0.08 arcsec on the sky — lossy by decision).
                  Status: canonical outright (resolved 2026-07-17 —
                  statuses describe reality, not choreography; the
                  empirical gates run before inscription and the journey
                  fleet is born under v0.2).

    conventions:  atoms   — the type-atom table (atoms.py, 0x00-0x08).
                            This declaration IS the variable-union
                            statement (c1dd0002 §7.1): one namespace,
                            operational in every more-block, descriptive
                            in every dimension's vkind.
                  date    — atom 0x02's v2 wire (precision:u8 · jd:f64-BE)
                            and the precision vocabulary. Precision is
                            structural granularity; no certainty
                            vocabulary exists anywhere in the standard
                            (§7.3, ratified 2026-07-17).
                  strings — the strings-are-atoms convention (§7.7):
                            v2-authored formats carry their strings as
                            text atoms (u16-BE length), each untouched
                            type adopting at its own future bump.

    inherits:     everything else — the 0xee self-entry and the thirteen
                  founding conventions from the constitution, the fifteen
                  v1 type entries (fourteen untouched + celestial, which
                  v2 overrides leaf-wins).

Resolved at authoring (c1dd0002 §10, with Anthony 2026-07-17): the v2
celestial entry is canonical outright, and NTYPE_UNCERTAIN (0x04) is NOT
in network's v2 grammar — the one remaining certainty-flavored byte goes
the way of the rest; v2 network nodes are place/agent/relay/resource, a
closed enum.

Tone is ordinary (0x00): working protocol declaration, not the freeze.

NOT INSCRIBED. Neither parent has a txid yet, so build_registry_v2's
parent_txid defaults to None (root form) — that form is what the golden
vector freezes, since content must be reviewable before any txid exists.
At the ceremony the v1 leaf's root txid is passed and the bytes change
ONLY by the 33-byte parent prefix (0x01 + txid replacing 0x00); the
tests pin exactly that, and preflight_inscription_form (registry_v1's,
reused — the rule is the same law) refuses the parentless form.
"""

from __future__ import annotations

from atoms import ATOM_NAMES, DATE_PRECISION_NAMES
from envelope import VERSION_V2
from estandarte import (
    build_estandarte_quipu, read_estandarte_quipu,
    TYPE_ESTANDARTE, STATUS_CANONICAL,
)
from registry_v1 import preflight_inscription_form  # same law, re-exported
from tone import TONE_ORDINARY

TYPE_CELESTIAL = 0xCE

__all__ = [
    "build_registry_v2", "v2_types", "v2_conventions", "v2_type_entry",
    "preflight_inscription_form", "TYPE_CELESTIAL",
]


def v2_types():
    """The v2 legislation: the one type entry the second standard touches.
    A keyed override — leaf-wins replaces v1's 0xce entry whole."""
    return [
        {
            'byte': TYPE_CELESTIAL, 'name': 'celestial',
            'status': STATUS_CANONICAL,
            'desc': 'point figures (earth/star/mixed) and node-edge figures '
                    '(genealogy/etymology/network); f32 coords, lossy by '
                    'decision: ~2.4 m on the ground, ~0.08 arcsec on the sky; '
                    'one date mechanism: the typed date var, earth points only',
            'dimensions': [
                {'name': 'kind',
                 'desc': 'figure grammar; 0x02 = per-point frame byte opens '
                         'each record; 0x03-0x05 route to the node-edge codecs',
                 'values': [
                    {'value': 0x00, 'name': 'earth',
                     'desc': 'lng/lat geographic coordinates'},
                    {'value': 0x01, 'name': 'star',
                     'desc': 'RA/Dec celestial-sphere coordinates'},
                    {'value': 0x02, 'name': 'mixed',
                     'desc': 'earth and star points in one figure; each point '
                             'record opens with its own kind byte'},
                    {'value': 0x03, 'name': 'genealogy',
                     'desc': 'node-edge family tree: person nodes with '
                             'born/died f32 years (NaN = unknown) + '
                             'parent-child edges, 4-byte stride'},
                    {'value': 0x04, 'name': 'etymology',
                     'desc': 'node-edge word lineage: lexeme nodes + typed '
                             'descent edges, 5-byte stride (per-edge relation '
                             'byte)'},
                    {'value': 0x05, 'name': 'network',
                     'desc': 'node-edge network: typed nodes '
                             '(place/agent/relay/resource, closed enum) + '
                             'typed direction-capable edges (per-edge medium '
                             'byte)'},
                 ]},
                {'name': 'grouped',
                 'desc': 'whether points are partitioned into named groups; '
                         'reserved MUST-be-0 for the node-edge kinds '
                         '(0x03-0x05)',
                 'values': [
                    {'value': 0x00, 'name': 'no',  'desc': 'flat point list'},
                    {'value': 0x01, 'name': 'yes',
                     'desc': 'points partitioned into named groups with lines'},
                 ]},
                {'name': 'meta',
                 'desc': 'per-point metadata shape; v2 has one date mechanism '
                         '(the typed date var), so v1\'s 0x01 time value is '
                         'not in the v2 grammar — a v2 blob carrying it is '
                         'malformed; reserved MUST-be-0 for kinds 0x03-0x05',
                 'values': [
                    {'value': 0x00, 'name': 'no',
                     'desc': 'points have name + coords only'},
                    {'value': 0x02, 'name': 'more',
                     'desc': 'points may carry typed variables from the atom '
                             'namespace; a date var is legal on earth points '
                             'only'},
                 ]},
            ],
            'flags': [],
        },
    ]


def v2_conventions():
    """The v2 cross-cutting declarations. `atoms` is the variable-union
    statement (c1dd0002 §7.1); `date` is atom 0x02's v2 layout and the
    certainty abolition (§7.3); `strings` is the strings-are-atoms
    convention (§7.7). Keyed by name — individually amendable leaf-wins."""
    return [
        {
            'name':   'atoms',
            'syntax': '0x00 text (u16-BE len + UTF-8) · 0x01 ref (32 B txid) · '
                      '0x02 date (9 B, see date) · 0x03 u8 · 0x04 u16 · '
                      '0x05 u32 · 0x06 f32 · 0x07 f64 · 0x08 bytes '
                      '(u16-BE len + raw); fixed widths big-endian',
            'desc':   'the type-atoms, one namespace, two uses: operational '
                      '(a more-block tags each value: Nvar:u8, then '
                      'keylen:u8 key atom:u8 value) and descriptive (a '
                      'dimension\'s vkind states its width as data); it is '
                      'the variable union; future atoms ride version bumps',
        },
        {
            'name':   'date',
            'syntax': 'atom 0x02 v2: precision:u8 · jd:f64-BE (9 B); '
                      'precision 0x00 unspecified · 0x01 exact · 0x02 day · '
                      '0x03 month · 0x04 year',
            'desc':   'precision is structural: the granularity the datum '
                      'has, never how sure anyone is (no certainty vocabulary '
                      'exists in the standard); jd is noon-convention Julian '
                      'Day, BCE-safe; renderers widen the marker to the '
                      'precision instead of fabricating specificity',
        },
        {
            'name':   'strings',
            'syntax': 'v2-authored formats carry strings as text atoms '
                      '(u16-BE length + UTF-8)',
            'desc':   'strings are atoms: types authored or re-formatted '
                      'under v2 use the text atom for titles, names and '
                      'descriptions, retiring u8 length caps and delimiter '
                      'collisions; untouched types keep their v1 wire and '
                      'adopt at their own future bump',
        },
    ]


def v2_type_entry(type_byte):
    """The v2 entry for one type byte — the unit a future per-type peel
    would amend on. Raises KeyError for bytes v2 does not touch (they are
    v1's or the constitution's to give)."""
    for t in v2_types():
        if t['byte'] == type_byte:
            return t
    raise KeyError(f"type {type_byte:#04x} not legislated in v2")


def build_registry_v2(parent_txid=None):
    """Build c1dd0002ee — the v2 registry — and return (header, body).

    parent_txid: the v1 registry's root txid (64-hex). None builds the
    root form (what the golden vector freezes, pre-inscription); the
    inscription ceremony passes the real txid, changing only the parent
    prefix bytes.
    """
    return build_estandarte_quipu(
        v2_types(), v2_conventions(),
        tone=TONE_ORDINARY,
        version=VERSION_V2,
        parent_txid=parent_txid,
    )


# ---------------------------------------------------------------------------
# Self-tests (collected by tests/test_canonical_selftests.py)
# ---------------------------------------------------------------------------

def _selftest_is_v2_ordinary_delta():
    h, b = build_registry_v2()
    parsed = read_estandarte_quipu(h, b)
    assert parsed["version"] == VERSION_V2 == 0x0002
    assert parsed["tone"] == TONE_ORDINARY
    assert parsed["parent_txid"] is None          # root form pre-inscription
    # pure delta: one type entry (celestial), three new conventions
    assert [t["byte"] for t in parsed["types"]] == [TYPE_CELESTIAL]
    assert [c["name"] for c in parsed["conventions"]] == \
           ["atoms", "date", "strings"]


def _selftest_v2_celestial_grammar():
    cel = v2_type_entry(TYPE_CELESTIAL)
    assert cel["status"] == STATUS_CANONICAL       # outright — resolved §10.1
    kind, grouped, meta = cel["dimensions"]
    assert [v["value"] for v in kind["values"]] == [0, 1, 2, 3, 4, 5]
    # one date mechanism: v1's meta value 0x01 "time" is not in the grammar
    assert [v["value"] for v in meta["values"]] == [0x00, 0x02]
    assert all(v["name"] != "time" for v in meta["values"])
    # NTYPE_UNCERTAIN is gone: network's node enum is closed at four
    net = next(v for v in kind["values"] if v["name"] == "network")
    assert "uncertain" not in net["desc"]


def _selftest_declaration_matches_atoms_py():
    # The on-chain statement must name every atom the code implements —
    # crafted prose, drift-checked against the single source (atoms.py).
    conv = {c["name"]: c for c in v2_conventions()}
    for byte, name in ATOM_NAMES.items():
        assert f"0x{byte:02x} {name}" in conv["atoms"]["syntax"], \
            f"atom {name} (0x{byte:02x}) missing from the atoms declaration"
    for byte, name in DATE_PRECISION_NAMES.items():
        assert f"0x{byte:02x} {name}" in conv["date"]["syntax"], \
            f"precision {name} (0x{byte:02x}) missing from the date declaration"


def _selftest_composes_three_link_chain():
    from constitution import build_constitution
    from registry_v1 import build_registry_v1
    from estandarte import resolve_estandarte_chain, _example_registry
    V0, V1, V2 = "aa" * 32, "bb" * 32, "cc" * 32
    h0, b0 = build_constitution()
    h1, b1 = build_registry_v1(parent_txid=V0)
    h2, b2 = build_registry_v2(parent_txid=V1)
    blobs = {V0: h0 + b0, V1: h1 + b1, V2: h2 + b2}
    merged = resolve_estandarte_chain(V2, blobs.__getitem__)
    assert merged["chain_length"] == 3
    assert merged["root_txid"] == V0
    # every v0/v1 key survives; celestial now speaks with v2's voice
    all_types, _ = _example_registry()
    assert sorted(merged["types"]) == sorted(t["byte"] for t in all_types)
    assert merged["types"][TYPE_CELESTIAL]["_source_txid"] == V2
    assert merged["conventions"]["atoms"]["_source_txid"] == V2
    assert merged["conventions"]["diamond"]["_source_txid"] == V0


def _selftest_amendment_form_differs_only_by_parent_prefix():
    root_h, root_b = build_registry_v2()
    amend_h, amend_b = build_registry_v2(parent_txid="dd" * 32)
    assert amend_h == root_h
    assert root_b[0] == 0x00 and amend_b[0] == 0x01
    assert amend_b[1:33] == bytes.fromhex("dd" * 32)
    assert amend_b[33:] == root_b[1:]             # content bytes identical


def _selftest_preflight_refuses_rootless_legislation():
    try:
        preflight_inscription_form(*build_registry_v2())
    except ValueError as e:
        assert "constitution" in str(e)
    else:
        raise AssertionError("parentless v2 passed inscription preflight")
    parsed = preflight_inscription_form(*build_registry_v2(parent_txid="ee" * 32))
    assert parsed["parent_txid"] == "ee" * 32


if __name__ == "__main__":
    _selftest_is_v2_ordinary_delta()
    _selftest_v2_celestial_grammar()
    _selftest_declaration_matches_atoms_py()
    _selftest_composes_three_link_chain()
    _selftest_amendment_form_differs_only_by_parent_prefix()
    _selftest_preflight_refuses_rootless_legislation()
    h, b = build_registry_v2()
    print("c1dd0002ee v2 registry — working-tree freeze (NOT inscribed)")
    print(f"  header: {h.hex()}")
    print(f"  body:   {len(b)} bytes, {len(v2_types())} type entry, "
          f"{len(v2_conventions())} conventions")
