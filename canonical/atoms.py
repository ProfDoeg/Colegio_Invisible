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
# The shared more-block codec — the one typed-var implementation
# (replaces the four byte-identical clones: celestial, etymology, network,
#  and the client's decode.py copy — c1dd0002 §7.5)
# ---------------------------------------------------------------------------
#
# Wire (unchanged from v1's more-block, byte-compatible for text/ref/date):
#   Nvar:u8 · Nvar × [ keylen:u8 · key · atom:u8 · value ]
#   text  = vlen:u16-BE + UTF-8
#   ref   = 32 raw bytes
#   date  = v1: jd:f64-BE · v2: precision:u8 + jd:f64-BE
#   u8/u16/u32/f32/f64 = fixed-width BE (v2+ only)
#   bytes = vlen:u16-BE + raw            (v2+ only)
#
# STRICT, uniformly: an unknown or version-illegal atom raises — its width
# is unknown, so nothing after it could be read; silence would present a
# partial record as whole (c1dd0002 §5). UTF-8 decodes strictly: mojibake
# is never silently minted.

_NAME_TO_ATOM = {v: k for k, v in ATOM_NAMES.items()}
_V1_MORE_ATOMS = frozenset({ATOM_TEXT, ATOM_REF, ATOM_DATE})


def legal_more_atoms(version):
    """The atoms legal inside a more-block at a given blob version."""
    return VALID_ATOMS if version >= 2 else _V1_MORE_ATOMS


def _coerce_atom(kind):
    if isinstance(kind, str):
        try:
            return _NAME_TO_ATOM[kind]
        except KeyError:
            raise ValueError(f"unknown atom name {kind!r}")
    return kind


def _coerce_precision(precision):
    if isinstance(precision, str):
        for byte, name_ in DATE_PRECISION_NAMES.items():
            if name_ == precision:
                return byte
        raise ValueError(f"unknown date precision {precision!r}")
    if precision not in DATE_PRECISION_NAMES:
        raise ValueError(f"date precision {precision!r} not in 0x00..0x04")
    return precision


def emit_more_block(more, version=1, label="record"):
    """Serialize a typed-var list [(key, atom-or-name, value)] to the bytes
    AFTER the morelen prefix (the caller frames with its own morelen:u16).

    Date values: v1 takes a bare float jd. v2 takes a float (precision
    unspecified) or a dict {'jd': float, 'precision': name-or-byte}.
    """
    legal = legal_more_atoms(version)
    out = bytearray([len(more)])
    for key, kind, value in more:
        atom = _coerce_atom(kind)
        if atom not in legal:
            raise ValueError(
                f"{label}: atom {atom_name(atom)} not legal in a v{version} more-block")
        kb = key.encode("utf-8")
        if len(kb) > 255:
            raise ValueError(f"{label}: variable key encodes to {len(kb)} bytes; max 255")
        out += bytes([len(kb)]) + kb + bytes([atom])
        if atom == ATOM_TEXT:
            vb = str(value).encode("utf-8")
            if len(vb) > 0xFFFF:
                raise ValueError(f"{label}: text variable {key!r} exceeds u16 length")
            out += struct.pack(">H", len(vb)) + vb
        elif atom == ATOM_REF:
            if len(value) != 32:
                raise ValueError(f"{label}: ref variable {key!r} must be a 32-byte txid")
            out += bytes(value)
        elif atom == ATOM_DATE:
            if version >= 2:
                if isinstance(value, dict):
                    prec = _coerce_precision(value.get("precision", DATE_UNSPECIFIED))
                    jd = float(value["jd"])
                else:
                    prec, jd = DATE_UNSPECIFIED, float(value)
                out += bytes([prec]) + struct.pack(">d", jd)
            else:
                if isinstance(value, dict):
                    raise ValueError(
                        f"{label}: v1 dates carry no precision on the wire "
                        f"(a dict date value is a v2 form)")
                out += struct.pack(">d", float(value))
        elif atom in _UINT_WIDTH:
            out += encode_uint(atom, int(value))
        elif atom == ATOM_F32:
            out += struct.pack(">f", float(value))
        elif atom == ATOM_F64:
            out += struct.pack(">d", float(value))
        elif atom == ATOM_BYTES:
            vb = bytes(value)
            if len(vb) > 0xFFFF:
                raise ValueError(f"{label}: bytes variable {key!r} exceeds u16 length")
            out += struct.pack(">H", len(vb)) + vb
        else:  # unreachable while VALID_ATOMS is the gate, kept for honesty
            raise ValueError(f"{label}: unknown atom {atom:#04x}")
    return bytes(out)


def read_more_block(mo, version=1, label="record"):
    """Parse a full more block (the bytes AFTER morelen) into a list of
    (key, atom_name, value). STRICT per §5. Refs are raw bytes; v2 dates
    are {'jd': float, 'precision': name} dicts; v1 dates are bare floats.
    """
    legal = legal_more_atoms(version)
    q, more = 0, []
    if not mo:
        raise ValueError(f"{label}: empty more block (missing Nvar)")
    nvar = mo[q]; q += 1
    for _ in range(nvar):
        if q >= len(mo):
            raise ValueError(f"{label}: more block truncated reading key length")
        kl = mo[q]; q += 1
        key = mo[q:q + kl].decode("utf-8"); q += kl
        if q >= len(mo):
            raise ValueError(f"{label}: more block truncated reading atom for {key!r}")
        atom = mo[q]; q += 1
        if atom not in legal:
            raise ValueError(
                f"{label}: variable {key!r} atom {atom:#04x} not legal in a "
                f"v{version} more-block — width unknown, refusing to guess")
        if atom == ATOM_TEXT:
            vl = struct.unpack(">H", mo[q:q + 2])[0]; q += 2
            more.append((key, "text", mo[q:q + vl].decode("utf-8"))); q += vl
        elif atom == ATOM_REF:
            if q + 32 > len(mo):
                raise ValueError(f"{label}: more block truncated reading ref {key!r}")
            more.append((key, "ref", bytes(mo[q:q + 32]))); q += 32
        elif atom == ATOM_DATE:
            if version >= 2:
                if q + 9 > len(mo):
                    raise ValueError(f"{label}: more block truncated reading date {key!r}")
                prec = mo[q]; q += 1
                if prec not in DATE_PRECISION_NAMES:
                    raise ValueError(
                        f"{label}: date {key!r} precision {prec:#04x} not in 0x00..0x04")
                jd = struct.unpack(">d", mo[q:q + 8])[0]; q += 8
                more.append((key, "date",
                             {"jd": jd, "precision": DATE_PRECISION_NAMES[prec]}))
            else:
                if q + 8 > len(mo):
                    raise ValueError(f"{label}: more block truncated reading date {key!r}")
                more.append((key, "date", struct.unpack(">d", mo[q:q + 8])[0])); q += 8
        elif atom in _UINT_WIDTH:
            v, q = decode_uint(atom, mo, q)
            more.append((key, ATOM_NAMES[atom], v))
        elif atom == ATOM_F32:
            more.append((key, "f32", struct.unpack(">f", mo[q:q + 4])[0])); q += 4
        elif atom == ATOM_F64:
            more.append((key, "f64", struct.unpack(">d", mo[q:q + 8])[0])); q += 8
        elif atom == ATOM_BYTES:
            vl = struct.unpack(">H", mo[q:q + 2])[0]; q += 2
            more.append((key, "bytes", bytes(mo[q:q + vl]))); q += vl
    if q != len(mo):
        raise ValueError(
            f"{label}: more block has {len(mo) - q} trailing bytes after "
            f"{nvar} variables — malformed, refusing to drop them")
    return more


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


def _selftest_more_block_v1_wire_compat():
    # v1 wire: the shared codec must be byte-identical to the historical
    # clones for text/ref/date, and refuse the v2-only atoms.
    more = [("gloss", "text", "sol invicto"), ("cita", "ref", b"\xab" * 32),
            ("dia", "date", 2456789.5)]
    blob = emit_more_block(more, version=1)
    # hand-check the frame: Nvar, then keylen·key·atom per var
    assert blob[0] == 3 and blob[1] == 5 and blob[2:7] == b"gloss" and blob[7] == 0x00
    got = read_more_block(blob, version=1)
    assert got == more
    try:
        emit_more_block([("n", "u16", 7)], version=1)
    except ValueError:
        pass
    else:
        raise AssertionError("v2-only atom accepted in a v1 block")
    try:
        read_more_block(bytes([1, 1, ord("x"), 0x04, 0, 7]), version=1)
    except ValueError:
        pass
    else:
        raise AssertionError("v2-only atom read in a v1 block did not raise")


def _selftest_more_block_v2_date_and_atoms():
    more = [("dia", "date", {"jd": 2456789.5, "precision": "year"}),
            ("n", "u16", 7), ("peso", "f64", 1.5), ("raw", "bytes", b"\x01\x02")]
    blob = emit_more_block(more, version=2)
    got = read_more_block(blob, version=2)
    assert got[0] == ("dia", "date", {"jd": 2456789.5, "precision": "year"})
    assert got[1:] == more[1:]
    # bare float date in v2 = precision unspecified (9 bytes on wire)
    b2 = emit_more_block([("d", "date", 2400000.5)], version=2)
    assert read_more_block(b2, version=2)[0][2] == {"jd": 2400000.5,
                                                   "precision": "unspecified"}
    # trailing garbage is malformed, never dropped
    try:
        read_more_block(blob + b"\x00", version=2)
    except ValueError:
        pass
    else:
        raise AssertionError("trailing bytes silently dropped")


if __name__ == "__main__":
    _selftest_widths()
    _selftest_uint_roundtrip()
    _selftest_legacy_byte_compat()
    _selftest_more_block_v1_wire_compat()
    _selftest_more_block_v2_date_and_atoms()
    print("atoms.py self-tests OK")
