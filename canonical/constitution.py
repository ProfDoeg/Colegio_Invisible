"""
constitution.py — c1dd0000ee, the founding standard.

Version 0 is the constitution: the standard that declares *how any registry
is read*, prior to and presupposed by every later version. It is the seed
(c1dd0002 design, §3) made explicit and pinned in the working tree so it can
be reviewed and tested. It is NOT inscribed here; inscription waits for a
real protocol freeze under the ACH anchor.

WHAT THE CONSTITUTION FIXES (frozen):
    1. the envelope grammar        — envelope.py (magic c1dd, u16-BE version,
                                      type, tone; six bytes, forever)
    2. the estandarte body format  — documented on chain by the metacircular
                                      0xee self-entry; hardcoded by readers
    3. the trust anchor            — the ACH 3-of-3; the slot is empty and
                                      waiting until the root is inscribed
    4. the tip rule                — how a reader finds the authoritative leaf
    + the cross-cutting protocol conventions (magic, tone, diamond, assembly,
      tag, ripcord, genesis, despot, amend, commentary, citation, forest,
      pre-canonical).

WHAT IT DELIBERATELY DEFERS: grammar-as-data. The constitution freezes how a
registry is *read* structurally. Per-(version, type) field grammars — the
fold that lets a seed-only reader parse a body it has no code for — are a
later standard, proven against text (0x00) first (c1dd0002 §8). Freezing the
descriptor language before that proof would freeze an expressive ceiling we
are only guessing at, and the constitution is the one thing no amendment can
reach (reading the amendment needs the capability being changed).

CONSTITUTION vs. LEGISLATION. The type *vocabulary* is not here. The
constitution says how registries are read; the v1 estandarte (legislation,
version 1) says which types exist. So the constitution carries exactly one
type entry — the 0xee self-entry, i.e. "how to read an estandarte" — plus
the cross-cutting conventions. Both are DERIVED from the single source
(estandarte._example_registry) so the constitution can never drift from the
registry it founds.
"""

from __future__ import annotations

from envelope import build_envelope, parse_envelope, VERSION_CONSTITUTION
from estandarte import (
    build_estandarte_quipu, read_estandarte_quipu, _example_registry,
    TYPE_ESTANDARTE,
)
from tone import TONE_SOVEREIGN


# --- Seed element 3: the trust anchor (empty slot, waiting for inscription) --
# The ACH 3-of-3 certificate authority. Keys and root txid are not fixed until
# the constitution is inscribed under the ACH anchor; the seed carries the
# slot empty and waiting (c1dd0002 §3.3). A reader follows only the chain ACH
# certifies — another party's c1dd..ee chain is a different authority's fork,
# not a forgery, and this reader does not follow it.
ACH_ANCHOR = {
    "authority": "ACH 3-of-3",
    "members":   ("Anthony", "Christophia", "Hayagriva"),
    "quorum":    3,
    "pubkeys":   None,   # empty until the signing ceremony
    "root_txid": None,   # empty until c1dd0000ee is inscribed
}

# --- Seed element 4: the tip rule (an algorithm a reader runs, documented) ---
TIP_RULE = (
    "From the anchored constitution root, find the GENESIS TAG (the root's "
    "single non-strand output) and its fan-out: despot, amend, commentary. "
    "(1) THE DESPOT CHECK, first: latent (unspent — the ordinary rules hold), "
    "exercised (spent with declarations and a re-offered successor — the "
    "declarations bind, in chain order, over any ordinary rule), or burned "
    "(no successor — the rules are absolute forever). (2) THE CONSTITUTION'S "
    "TEXT: walk the amend thread — constitutional additions, chain order. "
    "(3) LEGISLATION: find the c1dd0001ee whose parent_txid names the "
    "constitution root, ACH-signed (the constitution's tag is claimed by "
    "genesis, so this one hop is text-anchored). From v1 walk the RIPCORD: "
    "each registry root's first non-strand output is its cord, and the cord's "
    "spending transaction (no OP_RETURN: an act, not writing) IS the "
    "successor's root. At most one spend of a cord can ever confirm, so "
    "succession is unique by the ledger's own double-spend rule. At each hop "
    "verify thread and text agree: the successor's parent_txid names the root "
    "whose cord it spent. The terminal intact cord marks the current leaf. "
    "(4) FALLBACK on a dead or absent cord: scan the version bucket for 0xee "
    "envelopes, walk each candidate leaf's parent_txid chain to its root, "
    "keep only the chain rooted at the ACH anchor AND signed at every link "
    "by the then-current authority — pointer continuity is not enough. "
    "Authority is transferable: the reader follows the succession. The "
    "commentary thread is never consulted for law."
)

# --- The genesis tag: the constitution's one instrument, at inception ---
# An output cannot be added to a transaction that already exists, so the
# constitution's root either carries its genesis tag from birth or no thread
# can ever begin there. Scripts/addresses are empty and waiting like
# ACH_ANCHOR — the 3-of-3 P2SH is computed from the ACH pubkeys at the
# signing ceremony. Legislation roots (v1+) carry ordinary ripcords; the
# genesis fan-out exists once, on the constitution alone.
GENESIS = {
    "rule":     "the constitution root's single tag (last output; N+2 anatomy)",
    "seed_sat": 100_000_000,   # 1 DOGE — spent once, by the fan-out
    "script":   None,          # P2SH(3-of-3 ACH CHECKMULTISIG) — awaits the ceremony
    "address":  None,          # derived from the script at the ceremony
}
FANOUT = {
    "rule":     "genesis spend: exactly three outputs, no OP_RETURN "
                "(a speaking act would read as strand continuation)",
    "outputs":  ("despot", "amend", "commentary"),
    "seed_sat": 100_000_000,   # per output
    "scripts":  None,          # three P2SH(3-of-3 ACH) — await the ceremony
}


def _constitution_content():
    """Return (types, conventions) for the constitution, derived from the
    single source so it cannot drift from the v1 registry it founds.

    types       = [the 0xee self-entry only] — how an estandarte is read.
    conventions = the full cross-cutting convention block, byte-identical to
                  v1's, so constitution and legislation never disagree on a
                  convention.
    """
    all_types, conventions = _example_registry()
    self_entry = next(t for t in all_types if t["byte"] == TYPE_ESTANDARTE)
    # Skeleton only: the self-entry declares no field grammar (dimensions []).
    return [self_entry], conventions


def build_constitution():
    """Build c1dd0000ee — the founding standard — and return (header, body).

    Version 0, sovereign tone (c1dd0000·ee·ee — tone and type share the
    byte; the registry speaking in its own name). Not inscribed; this is
    the working-tree freeze.
    """
    types, conventions = _constitution_content()
    return build_estandarte_quipu(
        types, conventions,
        tone=TONE_SOVEREIGN,
        version=VERSION_CONSTITUTION,
    )


# ---------------------------------------------------------------------------
# Self-tests (collected by tests/test_canonical_selftests.py)
# ---------------------------------------------------------------------------

def _selftest_is_version_zero_sovereign():
    header, body = build_constitution()
    version, type_byte, tone = parse_envelope(header)
    assert version == VERSION_CONSTITUTION == 0x0000, version
    assert type_byte == TYPE_ESTANDARTE, type_byte
    assert tone == 0xee, tone   # sovereign — tone and type share the byte


def _selftest_roundtrips_and_is_metacircular():
    header, body = build_constitution()
    parsed = read_estandarte_quipu(header, body)
    assert parsed["version"] == 0x0000
    # exactly one type entry: the 0xee self-entry (constitution, not legislation)
    assert len(parsed["types"]) == 1, [t["byte"] for t in parsed["types"]]
    ee = parsed["types"][0]
    assert ee["byte"] == TYPE_ESTANDARTE and ee["name"] == "estandarte"
    # skeleton only — no grammar folded in
    assert ee["dimensions"] == [], ee["dimensions"]
    # carries the cross-cutting conventions
    assert len(parsed["conventions"]) >= 1


def _selftest_conventions_match_v1_no_drift():
    _all, v1_conv = _example_registry()
    header, body = build_constitution()
    parsed = read_estandarte_quipu(header, body)
    assert [c["name"] for c in parsed["conventions"]] == \
           [c["name"] for c in v1_conv]


def _selftest_anchor_slot_empty_and_waiting():
    assert ACH_ANCHOR["root_txid"] is None
    assert ACH_ANCHOR["pubkeys"] is None
    assert ACH_ANCHOR["quorum"] == 3
    assert len(ACH_ANCHOR["members"]) == 3


if __name__ == "__main__":
    _selftest_is_version_zero_sovereign()
    _selftest_roundtrips_and_is_metacircular()
    _selftest_conventions_match_v1_no_drift()
    _selftest_anchor_slot_empty_and_waiting()
    h, b = build_constitution()
    print("c1dd0000ee constitution — working-tree freeze (NOT inscribed)")
    print(f"  header: {h.hex()}")
    print(f"  body:   {len(b)} bytes")
    print(f"  full:   {(h + b).hex()}")
