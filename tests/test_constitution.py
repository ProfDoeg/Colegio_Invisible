"""Freeze the constitution: the six-byte envelope and c1dd0000ee.

This is the seed (c1dd0002 design, §3) — the kernel every reader carries as
code, and the one part of the wire no estandarte can describe, because a
reader needs it to find and trust the estandarte in the first place. It is
NOT on chain; these tests ARE the working-tree freeze.

A change to the envelope grammar or to the constitution's bytes must fail
here, loudly and on purpose. Growing the type vocabulary (v1 legislation)
must NOT change the frozen vector — the constitution carries only the 0xee
self-entry plus the cross-cutting conventions, not the type list.

The byte freeze compares against a committed golden file
(tests/golden/constitution_c1dd0000ee.hex). Regenerating that file is a
deliberate, reviewed constitutional amendment — it shows up as a diff.
"""
import os

import pytest

from envelope import (
    build_envelope, parse_envelope, MAGIC, ENVELOPE_LEN,
    VERSION_CONSTITUTION, VERSION_V1, VERSION_V2,
)
from constitution import build_constitution, ACH_ANCHOR, TIP_RULE
from estandarte import read_estandarte_quipu, _example_registry

GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "golden", "constitution_c1dd0000ee.hex")


def _frozen_hex():
    with open(GOLDEN) as f:
        return f.read().strip()


# ---------------------------------------------------------------------------
# Seed element 1 — the envelope grammar
# ---------------------------------------------------------------------------

def test_envelope_roundtrip_all_versions():
    for version in (0x0000, 0x0001, 0x0002, 0x00ff, 0xabcd, 0xffff):
        for type_byte in (0x00, 0x03, 0xee, 0xff):
            for tone in (0x00, 0xff):
                env = build_envelope(version, type_byte, tone)
                assert len(env) == ENVELOPE_LEN
                assert parse_envelope(env) == (version, type_byte, tone)


def test_magic_is_two_bytes():
    assert MAGIC == b"\xc1\xdd"
    assert ENVELOPE_LEN == 6


def test_v1_envelope_is_byte_identical_to_legacy_literal():
    # The historic 4-byte "magic" was really magic(2) + version(2)=0001.
    assert build_envelope(VERSION_V1, 0xee, 0x00)[:4] == b"\xc1\xdd\x00\x01"


def test_version_is_u16_be_at_bytes_2_3():
    assert build_envelope(VERSION_V2, 0xee, 0x00)[:4] == b"\xc1\xdd\x00\x02"
    assert parse_envelope(b"\xc1\xdd\x00\x02\xee\x00")[0] == 2
    assert parse_envelope(b"\xc1\xdd\xab\xcd\xee\x00")[0] == 0xabcd
    # every version parses; the version value is never a gate
    for v in (0x0000, 0x0001, 0x0002, 0x1234, 0xffff):
        assert parse_envelope(build_envelope(v, 0xee, 0x00))[0] == v


def test_bad_magic_rejected():
    for bad in (b"\xc0\xdd\x00\x01\xee\x00",   # wrong byte 0
                b"\xc1\xde\x00\x01\xee\x00",   # wrong byte 1
                b"\x00\x00\x00\x00\xee\x00"):
        with pytest.raises(ValueError):
            parse_envelope(bad)


def test_short_header_raises_valueerror_not_indexerror():
    # c1dd0002 §3 footnote: the length guard must precede any indexing.
    for n in range(0, ENVELOPE_LEN):
        with pytest.raises(ValueError):
            parse_envelope(b"\xc1\xdd\x00\x01\xee"[:n])
    # the exact case that bit the old reader: valid magic, header truncated
    # before type/tone. Old code indexed header[4] and raised IndexError.
    with pytest.raises(ValueError):
        parse_envelope(b"\xc1\xdd\x00\x01")   # 4 bytes: magic + version only


def test_build_envelope_validation():
    with pytest.raises(ValueError):
        build_envelope(0x10000, 0xee, 0x00)   # version > u16
    with pytest.raises(ValueError):
        build_envelope(0x0001, 0x100, 0x00)   # type > u8
    with pytest.raises(ValueError):
        build_envelope(0x0001, 0xee, 0x100)   # tone > u8


# ---------------------------------------------------------------------------
# The estandarte reader now speaks the envelope (version-tolerant, guarded)
# ---------------------------------------------------------------------------

def test_reader_accepts_known_versions_and_refuses_unknown():
    # Known versions read and carry their version for a dispatcher to act on.
    from estandarte import build_estandarte_quipu, KNOWN_ESTANDARTE_VERSIONS
    assert KNOWN_ESTANDARTE_VERSIONS == \
        frozenset({VERSION_CONSTITUTION, VERSION_V1, VERSION_V2})
    for v in (VERSION_CONSTITUTION, VERSION_V1, VERSION_V2):
        h, b = build_estandarte_quipu([], [], version=v)
        assert read_estandarte_quipu(h, b)["version"] == v
    # Honest failure (c1dd0002 §5): an unknown version is refused, not parsed
    # as this shape — the builder can stamp v3 bytes, the reader must not guess.
    for v in (0x0003, 0xffff):
        h, b = build_estandarte_quipu([], [], version=v)
        with pytest.raises(ValueError):
            read_estandarte_quipu(h, b)


def test_reader_rejects_short_header_with_valueerror():
    with pytest.raises(ValueError):
        read_estandarte_quipu(b"\xc1\xdd\x00\x00\xee", b"")   # 5 bytes


# ---------------------------------------------------------------------------
# Seed elements 2-4 — the constitution itself (c1dd0000ee)
# ---------------------------------------------------------------------------

def test_constitution_is_version_zero_sovereign():
    header, body = build_constitution()
    version, type_byte, tone = parse_envelope(header)
    assert version == VERSION_CONSTITUTION == 0x0000
    assert type_byte == 0xee
    assert tone == 0xee   # sovereign — tone and type share the byte


def test_constitution_bytes_are_frozen():
    header, body = build_constitution()
    got = (header + body).hex()
    assert got == _frozen_hex(), (
        "the constitution bytes changed vs tests/golden/constitution_c1dd0000ee.hex. "
        "This is the founding standard — a change here must be a deliberate, "
        "reviewed constitutional amendment, not an incidental edit. If intended, "
        "regenerate the golden file.")


def test_constitution_is_metacircular_skeleton_only():
    header, body = build_constitution()
    parsed = read_estandarte_quipu(header, body)
    assert parsed["version"] == 0x0000
    # constitution, not legislation: exactly one type entry, the 0xee self-entry
    assert len(parsed["types"]) == 1
    ee = parsed["types"][0]
    assert ee["byte"] == 0xee and ee["name"] == "estandarte"
    # skeleton only — NO field grammar folded in
    assert ee["dimensions"] == []
    assert ee["flags"] == []


def test_constitution_conventions_derive_from_single_source_no_drift():
    _all, v1_conv = _example_registry()
    header, body = build_constitution()
    parsed = read_estandarte_quipu(header, body)
    assert [c["name"] for c in parsed["conventions"]] == \
           [c["name"] for c in v1_conv]
    assert len(parsed["conventions"]) >= 1


def test_magic_convention_describes_the_true_envelope():
    # Audit MAJOR-1 guard: the constitution's own 'magic' convention must not
    # re-teach the c1dd0001-is-magic defect it exists to fix. It must state the
    # 2-byte magic and that the version is data — and be true of the
    # constitution's own c1dd0000 header.
    header, body = build_constitution()
    magic = next(c for c in read_estandarte_quipu(header, body)["conventions"]
                 if c["name"] == "magic")
    blob = (magic["syntax"] + " " + magic["desc"]).lower()
    assert "c1 dd" in blob and "version" in blob
    assert "c1 dd 00 01 at offset 0" not in magic["syntax"]   # the old falsehood


def test_tone_convention_covers_the_registered_set():
    # Audit MAJOR-2 guard: every registered tone (tone.py, the single source)
    # must be named in the constitution's tone convention, so it can never
    # under-declare the vocabulary or mis-describe an on-chain tone (0xe5 is
    # live). The affective family 0x01-0x07 is described as a range.
    from tone import TONES
    header, body = build_constitution()
    tone_conv = next(c for c in read_estandarte_quipu(header, body)["conventions"]
                     if c["name"] == "tone")
    desc = tone_conv["desc"]
    for b, name in TONES.items():
        if 0x01 <= b <= 0x07:
            continue   # covered by the "0x01-0x07" family range
        assert f"0x{b:02x}" in desc, \
            f"tone 0x{b:02x} ({name}) missing from the constitution tone convention"


def test_growing_the_type_vocabulary_does_not_move_the_constitution():
    # The constitution takes only the 0xee entry + conventions, so adding a
    # type to the registry must not change its bytes. Simulate a v1 addition.
    from estandarte import build_estandarte_quipu, STATUS_DRAFT
    all_types, conv = _example_registry()
    all_types.append({'byte': 0x42, 'name': 'hypothetical', 'status': STATUS_DRAFT,
                      'desc': 'a future type', 'dimensions': [], 'flags': []})
    ee = next(t for t in all_types if t['byte'] == 0xee)
    h, b = build_estandarte_quipu([ee], conv, tone=0xee, version=VERSION_CONSTITUTION)
    assert (h + b).hex() == _frozen_hex()


def test_anchor_slot_is_empty_and_waiting():
    assert ACH_ANCHOR["root_txid"] is None      # not inscribed yet
    assert ACH_ANCHOR["pubkeys"] is None        # ceremony not held
    assert ACH_ANCHOR["quorum"] == 3
    assert len(ACH_ANCHOR["members"]) == 3


def test_tip_rule_is_documented():
    assert "signed" in TIP_RULE.lower()
    assert "parent_txid" in TIP_RULE


def test_tag_ripcord_and_genesis_conventions_are_law():
    # The amendment machinery is written in at inception: the tag primitive,
    # the ripcord (legislation succession, Article V), and the genesis
    # fan-out with its three powers (Articles V-VII) are founding conventions.
    header, body = build_constitution()
    conv = {c["name"]: c for c in read_estandarte_quipu(header, body)["conventions"]}
    assert list(conv) == ["magic", "tone", "diamond", "assembly", "tag",
                          "ripcord", "genesis", "despot", "amend", "commentary",
                          "citation", "forest", "pre-canonical"]
    tag = conv["tag"]
    assert "no OP_RETURN" in tag["syntax"]
    assert "spend IS the event" in tag["desc"]
    rip = conv["ripcord"]
    assert "first non-strand output" in rip["syntax"]
    for phrase in ("input 0", "double-spend", "parent_txid", "falls back"):
        assert phrase in rip["desc"], f"ripcord law missing {phrase!r}"
    # v1's anchor hop is text, not thread — the constitution's tag is genesis
    assert "anchors to the constitution" in rip["desc"]
    gen = conv["genesis"]
    assert "no OP_RETURN" in gen["syntax"]
    for phrase in ("despot", "amend", "commentary", "mute", "once"):
        assert phrase in gen["desc"], f"genesis law missing {phrase!r}"
    des = conv["despot"]
    assert "burn" in des["syntax"]
    for phrase in ("general power", "chain order", "successor-less", "first to burn"):
        assert phrase in des["desc"], f"despot law missing {phrase!r}"
    amd = conv["amend"]
    assert "c1dd0000ee" in amd["syntax"]
    for phrase in ("additions only", "not legislation", "second to burn",
                   "legislation lives on"):
        assert phrase in amd["desc"], f"amend law missing {phrase!r}"
    com = conv["commentary"]
    for phrase in ("without power", "never consulted for law", "outlives both burns"):
        assert phrase in com["desc"], f"commentary law missing {phrase!r}"


def test_genesis_slots_are_armed_but_unkeyed():
    from constitution import GENESIS, FANOUT
    assert "single tag" in GENESIS["rule"]
    assert GENESIS["seed_sat"] >= 100_000       # engine dust floor for tags
    assert GENESIS["script"] is None            # awaits the ceremony keys
    assert GENESIS["address"] is None
    assert FANOUT["outputs"] == ("despot", "amend", "commentary")
    assert "no OP_RETURN" in FANOUT["rule"]
    assert FANOUT["scripts"] is None            # await the ceremony keys


def test_reader_refuses_in_body_duplicate_keys():
    # The builder refuses duplicate keys; a crafted blob must not slip
    # past the reader into silent last-wins (leaf-wins composition is
    # defined ACROSS amendments only, never within one body).
    entry = bytes([0x00, 1, ord("a"), 0, 0, 0, 0])   # byte·name'a'·desc''·status·0 dims·0 flags
    body = bytes([0x00, 0x02]) + entry + entry + bytes([0x00])
    with pytest.raises(ValueError, match="duplicate type byte"):
        read_estandarte_quipu(build_envelope(VERSION_V1, 0xee, 0x00), body)


def test_seed_modules_are_numpy_free():
    # The seed must stay dependency-light. Checked hermetically in a fresh
    # interpreter (the shared selftest harness can't — numpy is already
    # imported by celestial/image/scene by the time it runs).
    import subprocess
    import sys
    canon = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "canonical")
    code = ("import sys; sys.path.insert(0, %r); import constitution, envelope; "
            "assert 'numpy' not in sys.modules, sorted(sys.modules)" % canon)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, f"seed pulled numpy:\n{r.stdout}\n{r.stderr}"
