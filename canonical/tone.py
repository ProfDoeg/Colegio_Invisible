"""canonical/tone.py — the tone byte spec, single source of truth.

Every Colegio Invisible quipu carries a tone byte at header offset 5,
recording the emotional / classificatory register of the inscribed
content. Thirteen values are recognized in v1:

  0x00  ordinary           descriptive, neutral, the default

  --- the affective family (0x01–0x07) ---
  Jaak Panksepp's seven primal, subcortical emotional systems shared
  across all mammals — distinct neurological drives, not cognitive
  thoughts. Each tone marks content carrying that drive's register:

  0x01  affection/care      the nurturing, protective bond (panksepp CARE)
  0x02  seeking/wandering   enthusiastic foraging, curiosity, anticipation (SEEKING)
  0x03  play/interaction    rough-and-tumble social joy, the "laughter" register (PLAY)
  0x04  lust/wanting        the reproductive drive, desire, courtship (LUST)
  0x05  rage/anger          frustration when goals are blocked or movement restrained (RAGE)
  0x06  fear/dread          anxiety, the freeze-or-flee alarm (FEAR)
  0x07  grief/panic         separation distress, the isolation call, loss (PANIC/GRIEF)

  --- classificatory registers (a separate axis) ---
  0x0d  demonic    content that documents harm: dictators, founding
                   instruments of state terror, surveillance documents
  0x6e  nature     naturaleza ("n"). The non-human living world and the
                   elements — water, stone, birdsong, weather; field
                   recordings and content of/about the natural world.
  0xa1  ai         authored by, or fully attributable to, a non-human
                   model. Marks inscriptions that emerged from machine
                   composition rather than human hand.
  0xe5  hope       esperanza ("E5" ≈ ES). Content written TOWARD the
                   future reader, trusting it will be followed:
                   corrections, healings, editions, invitations.
                   Coined 2026-06-10 for the first correction catalog.
  0xff  reverence  the dead, ancestors, formal commemoration

Every canonical/* type module imports TONES + validate_tone from this
module instead of redeclaring its own TONE_* constants and _VALID_TONES
tuple, so adding a tone byte is a single-file change here rather than a
20-file edit across the protocol.

See docs/quipu-types/tone.md for the full spec + semantic guidance per
value.
"""

# ---------------------------------------------------------------------------
# Per-tone constants (re-exported by every type module for backward compat
# with `from text import TONE_REVERENCE` style imports).
# ---------------------------------------------------------------------------
TONE_ORDINARY  = 0x00
TONE_AFFECTION = 0x01      # care
TONE_SEEKING   = 0x02
TONE_PLAY      = 0x03
TONE_LUST      = 0x04
TONE_RAGE      = 0x05
TONE_FEAR      = 0x06
TONE_GRIEF     = 0x07
TONE_DEMONIC   = 0x0D
TONE_NATURE    = 0x6E      # naturaleza ('n')
TONE_AI        = 0xA1
TONE_HOPE      = 0xE5      # esperanza
TONE_REVERENCE = 0xFF

# Canonical value → name map. This is THE dictionary; everything else
# is derived from it.
TONES = {
    TONE_ORDINARY:  "ordinary",
    TONE_AFFECTION: "affection/care",
    TONE_SEEKING:   "seeking/wandering",
    TONE_PLAY:      "play/interaction",
    TONE_LUST:      "lust/wanting",
    TONE_RAGE:      "rage/anger",
    TONE_FEAR:      "fear/dread",
    TONE_GRIEF:     "grief/panic",
    TONE_DEMONIC:   "demonic",
    TONE_NATURE:    "nature",
    TONE_AI:        "ai",
    TONE_HOPE:      "hope",
    TONE_REVERENCE: "reverence",
}

# Set of accepted bytes, immutable. Public (no leading underscore) — callers
# may use it directly for `tone in VALID_TONES` checks.
VALID_TONES = frozenset(TONES.keys())

# Reverse lookup for convenience (build_text_quipu(..., tone=TONE_BY_NAME["reverence"]))
TONE_BY_NAME = {v: k for k, v in TONES.items()}

# The seven primal emotional systems (panksepp), 0x01–0x07. Affection/care
# anchors the family at 0x01; the rest follow. Useful for "is this an
# affective tone?" checks and for renderers that want to colour the family.
AFFECTIVE_TONES = frozenset({TONE_AFFECTION, TONE_SEEKING, TONE_PLAY,
                             TONE_LUST, TONE_RAGE, TONE_FEAR, TONE_GRIEF})

# Pre-formatted human-readable list, used in error messages so every
# module produces the same wording.
_TONE_LIST_STR = ", ".join(
    f"0x{b:02x} ({n})" for b, n in sorted(TONES.items())
)


def validate_tone(tone):
    """Raise ValueError if tone is not a recognized v1 byte.

    Builders call this once at the top of every build_*_quipu function
    instead of carrying their own per-module validation logic.
    """
    if tone not in VALID_TONES:
        raise ValueError(
            f"tone must be one of {_TONE_LIST_STR}; got {tone:#04x}"
        )


def name(tone):
    """Return the canonical name string for a tone byte, or
    'unknown_0xNN' for an unrecognized value (readers can pass-through
    unknown tones without failing — only builders reject them).
    """
    return TONES.get(tone, f"unknown_0x{tone:02x}")


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest():
    # Constants exist and have expected byte values
    assert TONE_ORDINARY  == 0x00
    assert TONE_AFFECTION == 0x01
    assert TONE_SEEKING   == 0x02
    assert TONE_PLAY      == 0x03
    assert TONE_LUST      == 0x04
    assert TONE_RAGE      == 0x05
    assert TONE_FEAR      == 0x06
    assert TONE_GRIEF     == 0x07
    assert TONE_DEMONIC   == 0x0D
    assert TONE_NATURE    == 0x6E
    assert TONE_AI        == 0xA1
    assert TONE_REVERENCE == 0xFF

    # Forward map
    assert TONES[0x00] == "ordinary"
    assert TONES[0x01] == "affection/care"
    assert TONES[0x02] == "seeking/wandering"
    assert TONES[0x03] == "play/interaction"
    assert TONES[0x04] == "lust/wanting"
    assert TONES[0x05] == "rage/anger"
    assert TONES[0x06] == "fear/dread"
    assert TONES[0x07] == "grief/panic"
    assert TONES[0x0d] == "demonic"
    assert TONES[0x6e] == "nature"
    assert TONES[0xa1] == "ai"
    assert TONES[0xe5] == "hope"
    assert TONES[0xff] == "reverence"
    assert len(TONES) == 13

    # VALID_TONES contains the right bytes
    assert VALID_TONES == frozenset({0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                     0x06, 0x07, 0x0d, 0x6e, 0xa1, 0xe5, 0xff})
    assert 0x42 not in VALID_TONES

    # The affective family is exactly 0x01–0x07
    assert AFFECTIVE_TONES == frozenset(range(0x01, 0x08))

    # Reverse lookup
    assert TONE_BY_NAME["ordinary"]          == 0x00
    assert TONE_BY_NAME["affection/care"]    == 0x01
    assert TONE_BY_NAME["seeking/wandering"] == 0x02
    assert TONE_BY_NAME["grief/panic"]       == 0x07
    assert TONE_BY_NAME["reverence"]         == 0xff

    # validate_tone accepts all twelve
    for t in VALID_TONES:
        validate_tone(t)

    # validate_tone rejects unknowns (0x08 is just past the affective family)
    for bad in (0x08, 0x42, 0xfe, 0xc3):
        try:
            validate_tone(bad)
            assert False, f"expected ValueError for {bad:#04x}"
        except ValueError as e:
            msg = str(e)
            assert "0x00 (ordinary)" in msg
            assert "0x01 (affection/care)" in msg
            assert "0x04 (lust/wanting)" in msg
            assert "0x07 (grief/panic)" in msg
            assert "0xff (reverence)" in msg
            assert f"{bad:#04x}" in msg

    # name() returns lookup or unknown_0xNN
    assert name(0x00) == "ordinary"
    assert name(0x05) == "rage/anger"
    assert name(0x42) == "unknown_0x42"
    assert name(0xfe) == "unknown_0xfe"

    assert name(0x6e) == "nature"
    print("  ✓ 13 tones, affective family 0x01–0x07, TONES/VALID_TONES/validate/name/reverse")


if __name__ == "__main__":
    print("=== tone.py self-tests ===")
    _selftest()
    print("all tone self-tests passed.")
