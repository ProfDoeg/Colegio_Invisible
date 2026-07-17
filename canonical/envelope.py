"""
envelope.py — the six-byte quipu envelope: the seed's first element.

Every quipu on chain, of every type and every protocol version, opens with
the same six bytes. This is the one grammar no estandarte can describe,
because a reader needs it to *find and trust* the estandarte in the first
place (c1dd0002 design, §3). It is hardcoded forever:

    offset  bytes    meaning
    0..1    c1 dd    magic — Colegio Invisible / DD
    2..3    u16-BE   protocol version   (0x0000 = the constitution)
    4       u8       type byte
    5       u8       tone byte

The version lives at bytes 2..3 as a big-endian u16. A reader selects the
governing standard from the version *before* it parses a body; the type
byte (0xee) is what marks the registry apart from data inside a version
bucket — the version value is never a sentinel.

Historic code compared the whole literal ``b"\\xc1\\xdd\\x00\\x01"`` and so
rejected every non-v1 version as bad magic (c1dd0002 §3 audit, A2). It also
indexed ``header[4]`` before guarding ``len < 6`` (§3 footnote), turning a
short header into an IndexError. This module is the version-aware
replacement: the true magic is two bytes, version is data, and the length
guard runs before any indexing.

Frozen. This file is part of the constitution (version 0); changing the
envelope grammar is a hard fork of every reader, not an amendment.
"""

from __future__ import annotations

MAGIC = b"\xc1\xdd"          # bytes 0..1 — the real magic, two bytes
ENVELOPE_LEN = 6             # magic(2) + version(2) + type(1) + tone(1)

# Protocol versions live at bytes 2..3 (u16-BE). Version 0 is the
# constitution: the founding standard that declares how any registry is
# read, prior to and presupposed by every later version.
VERSION_CONSTITUTION = 0x0000
VERSION_V1           = 0x0001
VERSION_V2           = 0x0002


def build_envelope(version, type_byte, tone):
    """Return the frozen 6-byte envelope for (version, type_byte, tone).

    version is a u16 (0..0xffff); type_byte and tone are u8 (0..0xff).
    """
    if not (0 <= version <= 0xFFFF):
        raise ValueError(f"version {version!r} out of u16 range (0..0xffff)")
    if not (0 <= type_byte <= 0xFF):
        raise ValueError(f"type byte {type_byte!r} out of u8 range (0..0xff)")
    if not (0 <= tone <= 0xFF):
        raise ValueError(f"tone {tone!r} out of u8 range (0..0xff)")
    return MAGIC + bytes([(version >> 8) & 0xFF, version & 0xFF, type_byte, tone])


def parse_envelope(header_bytes):
    """Parse the six-byte envelope. Returns (version, type_byte, tone).

    The length guard runs BEFORE any indexing, so a short or empty header
    raises ValueError, never IndexError (c1dd0002 §3 footnote). Only the
    two-byte magic gates; every version parses, and it is a later layer's
    job to decide which versions it is willing to dispatch.
    """
    if len(header_bytes) < ENVELOPE_LEN:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need >= {ENVELOPE_LEN})")
    if bytes(header_bytes[:2]) != MAGIC:
        raise ValueError(
            f"not a quipu (magic c1dd missing; got {bytes(header_bytes[:2]).hex()})")
    version = (header_bytes[2] << 8) | header_bytes[3]
    type_byte = header_bytes[4]
    tone = header_bytes[5]
    return version, type_byte, tone


# ---------------------------------------------------------------------------
# Self-tests (run under tests/test_canonical_selftests.py alongside the rest)
# ---------------------------------------------------------------------------

def _selftest_roundtrip():
    for version in (0x0000, 0x0001, 0x0002, 0x00ff, 0xabcd, 0xffff):
        for type_byte in (0x00, 0x03, 0xee, 0xff):
            for tone in (0x00, 0xff):
                env = build_envelope(version, type_byte, tone)
                assert len(env) == ENVELOPE_LEN
                assert parse_envelope(env) == (version, type_byte, tone)


def _selftest_v1_byte_identical():
    # The historic 4-byte "magic" was really magic(2) + version(2)=0001.
    assert build_envelope(VERSION_V1, 0xee, 0x00)[:4] == b"\xc1\xdd\x00\x01"
    assert build_envelope(VERSION_V2, 0xee, 0x00)[:4] == b"\xc1\xdd\x00\x02"


def _selftest_short_header_valueerror():
    # §3 footnote: guard length before indexing.
    for n in range(0, ENVELOPE_LEN):
        try:
            parse_envelope(b"\xc1\xdd\x00\x01\xee"[:n])
        except ValueError:
            pass
        else:
            raise AssertionError(f"{n}-byte header did not raise ValueError")


if __name__ == "__main__":
    _selftest_roundtrip()
    _selftest_v1_byte_identical()
    _selftest_short_header_valueerror()
    print("envelope.py self-tests OK")
