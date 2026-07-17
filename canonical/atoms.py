"""
atoms.py — the protocol's type-atoms: one namespace, two uses.

The atom set is the single vocabulary of wire shapes (c1dd0002 §7.1). The
first three bytes were born operational — the more-block's VAR_TEXT /
VAR_REF / VAR_DATE, byte-identical across celestial, etymology, and
network — and are promoted here to the protocol level, completed with the
fixed-width primitives the corpus already uses. One namespace, two uses:

  operational  — a more-block tags each value with its atom byte
  descriptive  — the registry cites an atom to state a field's shape
                 (a dimension's vkind, estandarte.py)

Width is width(atom) — a total function, never prose. A grammar-fold
reader computes offsets instead of guessing them.

  byte  atom   wire form
  0x00  text   u16-BE len + UTF-8
  0x01  ref    32-byte txid
  0x02  date   v1: jd f64-BE (8 B) · v2: precision u8 + jd f64-BE (9 B)
  0x03  u8     1 byte
  0x04  u16    2 bytes BE
  0x05  u32    4 bytes BE
  0x06  f32    4 bytes BE
  0x07  f64    8 bytes BE
  0x08  bytes  u16-BE len + raw

Future atoms ride future version bumps — vocabulary, not
descriptor-language, so no hard fork (c1dd0000, three tiers).

Keyless, pure stdlib. Part of the seed's reference implementation.
"""

from __future__ import annotations

import struct

ATOM_TEXT  = 0x00
ATOM_REF   = 0x01
ATOM_DATE  = 0x02
ATOM_U8    = 0x03
ATOM_U16   = 0x04
ATOM_U32   = 0x05
ATOM_F32   = 0x06
ATOM_F64   = 0x07
ATOM_BYTES = 0x08

ATOM_NAMES = {
    ATOM_TEXT:  "text",
    ATOM_REF:   "ref",
    ATOM_DATE:  "date",
    ATOM_U8:    "u8",
    ATOM_U16:   "u16",
    ATOM_U32:   "u32",
    ATOM_F32:   "f32",
    ATOM_F64:   "f64",
    ATOM_BYTES: "bytes",
}
VALID_ATOMS = frozenset(ATOM_NAMES)

# The unsigned-int atoms — the only atoms legal as a dimension's vkind
# (an enum ranges over an unsigned field; text/ref/date/float enums are
# not a thing the registry declares).
UINT_ATOMS = frozenset({ATOM_U8, ATOM_U16, ATOM_U32})

# --- date precision (v2) — promoted from the stranded PMETA_TIME_* values ---
DATE_UNSPECIFIED = 0x00
DATE_EXACT       = 0x01
DATE_DAY         = 0x02
DATE_MONTH       = 0x03
DATE_YEAR        = 0x04
DATE_PRECISION_NAMES = {
    DATE_UNSPECIFIED: "unspecified",
    DATE_EXACT:       "exact",
    DATE_DAY:         "day",
    DATE_MONTH:       "month",
    DATE_YEAR:        "year",
}

_UINT_WIDTH = {ATOM_U8: 1, ATOM_U16: 2, ATOM_U32: 4}


def atom_name(atom):
    """Canonical name for an atom byte, or 'unknown_0xNN' (naming only —
    parsing an unknown atom always raises; see fixed_width)."""
    return ATOM_NAMES.get(atom, f"unknown_0x{atom:02x}")


def fixed_width(atom, version=2):
    """Byte width of an atom's value on the wire.

    Returns None for the variable-width atoms (text, bytes — u16-BE length
    prefix + payload). Raises on an unknown atom: width unknown means
    nothing after the value can be read, so guessing is never honest
    (c1dd0002 §5).
    """
    if atom in (ATOM_TEXT, ATOM_BYTES):
        return None
    if atom == ATOM_REF:
        return 32
    if atom == ATOM_DATE:
        return 8 if version < 2 else 9
    w = _UINT_WIDTH.get(atom)
    if w is not None:
        return w
    if atom == ATOM_F32:
        return 4
    if atom == ATOM_F64:
        return 8
    raise ValueError(f"unknown atom {atom:#04x} — width unknown, refusing to guess")


def encode_uint(atom, value):
    """Encode an unsigned int at its atom's width, big-endian."""
    w = _UINT_WIDTH.get(atom)
    if w is None:
        raise ValueError(f"atom {atom_name(atom)} is not an unsigned-int atom")
    if not (0 <= value < 1 << (8 * w)):
        raise ValueError(
            f"value {value!r} out of range for {atom_name(atom)} (0..{(1 << (8 * w)) - 1})")
    return value.to_bytes(w, "big")


def decode_uint(atom, blob, offset=0):
    """Decode an unsigned int at its atom's width. Returns (value, new_offset)."""
    w = _UINT_WIDTH.get(atom)
    if w is None:
        raise ValueError(f"atom {atom_name(atom)} is not an unsigned-int atom")
    if offset + w > len(blob):
        raise ValueError(f"truncated {atom_name(atom)} value at offset {offset}")
    return int.from_bytes(blob[offset:offset + w], "big"), offset + w


# ---------------------------------------------------------------------------
# Self-tests (collected by tests/test_canonical_selftests.py)
# ---------------------------------------------------------------------------

def _selftest_widths():
    assert fixed_width(ATOM_REF) == 32
    assert fixed_width(ATOM_U8) == 1 and fixed_width(ATOM_U16) == 2
    assert fixed_width(ATOM_U32) == 4
    assert fixed_width(ATOM_F32) == 4 and fixed_width(ATOM_F64) == 8
    assert fixed_width(ATOM_TEXT) is None and fixed_width(ATOM_BYTES) is None
    # the date atom is version-dispatched: v1 8 B, v2 9 B
    assert fixed_width(ATOM_DATE, version=1) == 8
    assert fixed_width(ATOM_DATE, version=2) == 9
    try:
        fixed_width(0x42)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown atom did not raise")


def _selftest_uint_roundtrip():
    for atom, hi in ((ATOM_U8, 0xFF), (ATOM_U16, 0xFFFF), (ATOM_U32, 0xFFFFFFFF)):
        for v in (0, 1, hi):
            enc = encode_uint(atom, v)
            assert len(enc) == fixed_width(atom)
            got, off = decode_uint(atom, enc)
            assert got == v and off == len(enc)
        try:
            encode_uint(atom, hi + 1)
        except ValueError:
            pass
        else:
            raise AssertionError("overflow did not raise")


def _selftest_legacy_byte_compat():
    # The promoted namespace must not move the on-wire VAR_* bytes.
    assert ATOM_TEXT == 0x00 and ATOM_REF == 0x01 and ATOM_DATE == 0x02


if __name__ == "__main__":
    _selftest_widths()
    _selftest_uint_roundtrip()
    _selftest_legacy_byte_compat()
    print("atoms.py self-tests OK")
