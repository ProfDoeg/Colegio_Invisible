"""canonical/tone.py — the tone byte spec, single source of truth.

Every Colegio Invisible quipu carries a tone byte at header offset 5,
recording the emotional / classificatory register of the inscribed
content. Five values are recognized in v1:

  0x00  ordinary   descriptive, neutral, the default
  0x01  affection  paired, intimate, addressed to a specific other
  0x0d  demonic    content that documents harm: dictators, founding
                   instruments of state terror, surveillance documents
  0xa1  ai         authored by, or fully attributable to, a non-human
                   model. Marks inscriptions that emerged from machine
                   composition rather than human hand. See tone.md for
                   guidance on partial vs total AI attribution.
  0xff  reverence  the dead, ancestors, formal commemoration

Every canonical/* type module imports TONES + validate_tone from this
module instead of redeclaring its own TONE_* constants and _VALID_TONES
tuple, so adding a sixth tone byte someday is a single-file change here
rather than a 20-file edit across the protocol.

See docs/quipu-types/tone.md for the full spec + semantic guidance per
value.
"""

# ---------------------------------------------------------------------------
# Per-tone constants (re-exported by every type module for backward compat
# with `from text import TONE_REVERENCE` style imports).
# ---------------------------------------------------------------------------
TONE_ORDINARY  = 0x00
TONE_AFFECTION = 0x01
TONE_DEMONIC   = 0x0D
TONE_AI        = 0xA1
TONE_REVERENCE = 0xFF

# Canonical value → name map. This is THE dictionary; everything else
# is derived from it.
TONES = {
    TONE_ORDINARY:  "ordinary",
    TONE_AFFECTION: "affection",
    TONE_DEMONIC:   "demonic",
    TONE_AI:        "ai",
    TONE_REVERENCE: "reverence",
}

# Set of accepted bytes, immutable. Public (no leading underscore) — callers
# may use it directly for `tone in VALID_TONES` checks.
VALID_TONES = frozenset(TONES.keys())

# Reverse lookup for convenience (build_text_quipu(..., tone=TONE_BY_NAME["reverence"]))
TONE_BY_NAME = {v: k for k, v in TONES.items()}

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
    assert TONE_DEMONIC   == 0x0D
    assert TONE_AI        == 0xA1
    assert TONE_REVERENCE == 0xFF

    # Forward map
    assert TONES[0x00] == "ordinary"
    assert TONES[0x01] == "affection"
    assert TONES[0x0d] == "demonic"
    assert TONES[0xa1] == "ai"
    assert TONES[0xff] == "reverence"
    assert len(TONES) == 5

    # VALID_TONES contains the right bytes
    assert VALID_TONES == frozenset({0x00, 0x01, 0x0d, 0xa1, 0xff})
    assert 0x42 not in VALID_TONES

    # Reverse lookup
    assert TONE_BY_NAME["ordinary"]  == 0x00
    assert TONE_BY_NAME["affection"] == 0x01
    assert TONE_BY_NAME["demonic"]   == 0x0d
    assert TONE_BY_NAME["ai"]        == 0xa1
    assert TONE_BY_NAME["reverence"] == 0xff

    # validate_tone accepts all five
    for t in VALID_TONES:
        validate_tone(t)

    # validate_tone rejects unknowns
    for bad in (0x02, 0x42, 0xfe, 0xc3):
        try:
            validate_tone(bad)
            assert False, f"expected ValueError for {bad:#04x}"
        except ValueError as e:
            # Error message must list all canonical tones
            msg = str(e)
            assert "0x00 (ordinary)" in msg
            assert "0x01 (affection)" in msg
            assert "0x0d (demonic)" in msg
            assert "0xa1 (ai)" in msg
            assert "0xff (reverence)" in msg
            assert f"{bad:#04x}" in msg

    # name() returns lookup or unknown_0xNN
    assert name(0x00) == "ordinary"
    assert name(0x0d) == "demonic"
    assert name(0x42) == "unknown_0x42"
    assert name(0xfe) == "unknown_0xfe"

    print("  ✓ constants, TONES dict, VALID_TONES, validate_tone, name, reverse map")


if __name__ == "__main__":
    print("=== tone.py self-tests ===")
    _selftest()
    print("all tone self-tests passed.")
