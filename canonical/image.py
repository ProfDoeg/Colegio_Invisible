"""
image.py — 0x03 image quipu type (canonical).

Pixel data inscribed as bit-packed bytes after a 12-byte structural
header carrying width, height, color mode, and bit-depth. Pipe-bracketed
title follows the structural fields.

Spec
----
HEADER (12 + variable title bytes):

    c1dd 0001                       magic + protocol version 0.1
    03                              type byte = image
    <tone:1>                        00 ordinary, 01 affection, 0d demonic, ff reverence
    <color:1>                       00 grayscale (1 channel)
                                    01 RGB       (3 channels)
                                    02 grayscale + alpha (2 channels: G, A)
                                    03 RGBA      (4 channels: R, G, B, A)
    <W_hi W_lo>                     width  in pixels, uint16 big-endian
    <H_hi H_lo>                     height in pixels, uint16 big-endian
    <bit_depth:1>                   bits per channel per pixel (1..8)
    <pipe-bracketed title>          | TITLE | (UTF-8 between pipe sentinels)

The dimension convention is **(width, height)** — width first then height
in the header bytes. The pixel array in memory is row-major (H, W).
(A single historical inscription, Sabina, transposed this; that's
documented as a one-off, not the convention.)

BODY:

    Bit-packed pixel values, MSB-first within each byte, no padding
    between pixels except trailing zero bits in the final byte if the
    total bit count is not a multiple of 8.

    Pixel order is row-major: top-left first, scanning each row left-to-
    right, then moving down to the next row.

    Channel order within each pixel is the natural order for the color
    mode:
        grayscale:        one value per pixel
        RGB:              R, then G, then B
        grayscale+alpha:  G, then A
        RGBA:             R, then G, then B, then A

    Total bit count: width * height * channels * bit_depth
    Total byte count: ceil(total_bit_count / 8)

Tone vocabulary
    Same as text.py — 0x00 ordinary, 0x01 affection, 0x0d demonic, 0xff reverence.

Example on chain
    Domremy bordado image: root b92bbbf974ad7d1b…, 160 × 240 RGB at 5
    bits/channel, tone 0xff, title "| Domremy: Campo de Bourlemont |".
    Header is 44 bytes; body is 72000 bytes (= 160*240*3*5/8).
"""

from __future__ import annotations

import math
import struct


TYPE_IMAGE      = 0x03

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

COLOR_GRAY       = 0x00   # 1 channel
COLOR_RGB        = 0x01   # 3 channels
COLOR_GRAY_ALPHA = 0x02   # 2 channels: G, A
COLOR_RGBA       = 0x03   # 4 channels: R, G, B, A
_CHANNELS = {
    COLOR_GRAY:       1,
    COLOR_RGB:        3,
    COLOR_GRAY_ALPHA: 2,
    COLOR_RGBA:       4,
}
_COLOR_NAMES = {
    COLOR_GRAY:       "gray",
    COLOR_RGB:        "RGB",
    COLOR_GRAY_ALPHA: "gray+alpha",
    COLOR_RGBA:       "RGBA",
}


def expected_body_bytes(width, height, color, bit_depth):
    """Bytes needed for a (width, height, color, bit_depth) image body."""
    chans = _CHANNELS[color]
    total_bits = width * height * chans * bit_depth
    return math.ceil(total_bits / 8)


def build_image_quipu(width, height, color, bit_depth, title, body,
                      tone=TONE_ORDINARY):
    """Build a 0x03 image quipu's (header_bytes, body_bytes) pair.

    Args:
        width, height: pixel dimensions, each in [1, 65535].
        color:         COLOR_GRAY (0x00), COLOR_RGB (0x01),
                       COLOR_GRAY_ALPHA (0x02), or COLOR_RGBA (0x03).
        bit_depth:     bits per channel, in [1, 8].
        title:         UTF-8 string. May be empty. MUST NOT contain '|'.
        body:          raw bit-packed pixel bytes. Length must equal
                       expected_body_bytes(width, height, color, bit_depth).
        tone:          TONE_ORDINARY / TONE_AFFECTION / TONE_DEMONIC /
                       TONE_REVERENCE.

    Returns:
        (header_bytes, body_bytes) — body returned unchanged.
    """
    validate_tone(tone)
    if color not in _CHANNELS:
        raise ValueError(
            f"color must be 0x00 (gray), 0x01 (RGB), 0x02 (gray+alpha), "
            f"or 0x03 (RGBA); got {color:#04x}"
        )
    if not (1 <= width  <= 0xFFFF):
        raise ValueError(f"width must be in [1, 65535]; got {width}")
    if not (1 <= height <= 0xFFFF):
        raise ValueError(f"height must be in [1, 65535]; got {height}")
    if not (1 <= bit_depth <= 8):
        raise ValueError(f"bit_depth must be in [1, 8]; got {bit_depth}")

    if not isinstance(title, str):
        raise TypeError(f"title must be str, got {type(title).__name__}")
    if "|" in title:
        raise ValueError(
            "title contains '|' which is the field-separator byte"
        )

    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(f"body must be bytes, got {type(body).__name__}")
    body_bytes = bytes(body)
    expected = expected_body_bytes(width, height, color, bit_depth)
    if len(body_bytes) != expected:
        raise ValueError(
            f"body length {len(body_bytes)} != expected {expected} bytes "
            f"for {width}x{height} {_COLOR_NAMES[color]} @ {bit_depth} bpc"
        )

    header = (
        b"\xc1\xdd\x00\x01"
        + bytes([TYPE_IMAGE, tone, color])
        + struct.pack(">H", width)
        + struct.pack(">H", height)
        + bytes([bit_depth])
    )
    if title:
        header += b"|" + title.encode("utf-8") + b"|"

    return header, body_bytes


def read_image_quipu(header_bytes, body_bytes):
    """Parse a 0x03 image quipu.

    Returns:
        {
          'tone':       int (0x00 / 0x01 / 0x0d / 0xff),
          'color':      int (0x00 gray / 0x01 RGB / 0x02 gray+alpha / 0x03 RGBA),
          'channels':   int (1, 2, 3, or 4),
          'width':      int,
          'height':     int,
          'bit_depth':  int,
          'title':      str,
          'fields':     [str, ...],
          'body':       bytes (raw bit-packed pixel data),
          'body_bits':  int (expected total bits of pixel data),
        }
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 12:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need ≥ 12)"
        )
    if header_bytes[4] != TYPE_IMAGE:
        raise ValueError(
            f"not an image quipu (type byte = {header_bytes[4]:#04x}, "
            f"expected 0x03)"
        )

    tone      = header_bytes[5]
    color     = header_bytes[6]
    width     = struct.unpack(">H", header_bytes[7:9])[0]
    height    = struct.unpack(">H", header_bytes[9:11])[0]
    bit_depth = header_bytes[11]

    if color not in _CHANNELS:
        raise ValueError(
            f"unknown color byte {color:#04x} "
            f"(expected 0x00 gray, 0x01 RGB, 0x02 gray+alpha, or 0x03 RGBA)"
        )
    channels = _CHANNELS[color]

    # Lenient title extraction (v1, May 2026 — see image.md "Title region"):
    #   pipe form  → title = first non-empty pipe-delimited field after
    #                whitespace strip. Handles |T|, |T|<padding>, and
    #                | |T| | double-wrap (whitespace-pipes collapse).
    #   no-pipe    → title = whole cabeza decoded UTF-8, truncated at the
    #                first decode-replacement char (padding bytes), stripped.
    tail = header_bytes[12:]
    text = tail.decode("utf-8", errors="replace")
    if "|" in text:
        parts  = [p.strip() for p in text.split("|")]
        fields = [p for p in parts if p]
        title  = fields[0] if fields else ""
    elif not tail:
        title  = ""
        fields = []
    else:
        cut = text.find("�")
        if cut >= 0:
            text = text[:cut]
        title  = text.strip()
        fields = [title] if title else []

    return {
        "tone":      tone,
        "color":     color,
        "channels":  channels,
        "width":     width,
        "height":    height,
        "bit_depth": bit_depth,
        "title":     title,
        "fields":    fields,
        "body":      bytes(body_bytes),
        "body_bits": width * height * channels * bit_depth,
    }


# ---------------------------------------------------------------------------
# Reference pixel pack / unpack
# ---------------------------------------------------------------------------

def pack_pixels(values, bit_depth):
    """Pack a flat sequence of pixel-channel values into bytes.

    `values` is an iterable of integers in [0, 2**bit_depth - 1], in
    row-major order (top-left first), channels-interleaved per pixel
    (e.g. for RGB: r0, g0, b0, r1, g1, b1, …).

    Bits are packed MSB-first within each byte. The final byte is
    zero-padded if the total bit count is not a multiple of 8.

    Returns: bytes.
    """
    if not (1 <= bit_depth <= 8):
        raise ValueError(f"bit_depth must be in [1, 8]; got {bit_depth}")
    max_val = (1 << bit_depth) - 1
    out = bytearray()
    bit_buf = 0
    bits_in_buf = 0
    for v in values:
        if not (0 <= v <= max_val):
            raise ValueError(
                f"value {v} out of range [0, {max_val}] for bit_depth={bit_depth}"
            )
        bit_buf = (bit_buf << bit_depth) | v
        bits_in_buf += bit_depth
        while bits_in_buf >= 8:
            bits_in_buf -= 8
            out.append((bit_buf >> bits_in_buf) & 0xFF)
            bit_buf &= (1 << bits_in_buf) - 1
    if bits_in_buf:
        out.append((bit_buf << (8 - bits_in_buf)) & 0xFF)
    return bytes(out)


def unpack_pixels(body_bytes, count, bit_depth):
    """Unpack `count` channel values of bit_depth bits each from body_bytes.

    `count` = width * height * channels.

    Returns: list of ints in [0, 2**bit_depth - 1].
    """
    if not (1 <= bit_depth <= 8):
        raise ValueError(f"bit_depth must be in [1, 8]; got {bit_depth}")
    values = []
    bit_buf = 0
    bits_in_buf = 0
    byte_idx = 0
    mask = (1 << bit_depth) - 1
    while len(values) < count:
        while bits_in_buf < bit_depth and byte_idx < len(body_bytes):
            bit_buf = (bit_buf << 8) | body_bytes[byte_idx]
            bits_in_buf += 8
            byte_idx += 1
        if bits_in_buf < bit_depth:
            raise ValueError(
                f"body truncated: needed {count} values at bit_depth={bit_depth}, "
                f"got {len(values)}"
            )
        bits_in_buf -= bit_depth
        values.append((bit_buf >> bits_in_buf) & mask)
        bit_buf &= (1 << bits_in_buf) - 1
    return values


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_header_roundtrip():
    # Synthetic 4x3 RGB 8-bit image, 12 pixels = 36 channel values = 36 bytes
    width, height, bit_depth = 4, 3, 8
    values = list(range(36))  # 0..35
    body = pack_pixels(values, bit_depth)
    assert len(body) == 36
    h, b = build_image_quipu(width, height, COLOR_RGB, bit_depth,
                             "Tiny RGB", body, tone=TONE_ORDINARY)
    print(f"=== 4x3 RGB 8-bit header round-trip ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    print(f"  body   ({len(b)} B)")
    assert h[:4] == b"\xc1\xdd\x00\x01"
    assert h[4] == TYPE_IMAGE
    assert h[5] == TONE_ORDINARY
    assert h[6] == COLOR_RGB
    assert struct.unpack(">H", h[7:9])[0]  == width
    assert struct.unpack(">H", h[9:11])[0] == height
    assert h[11] == bit_depth

    parsed = read_image_quipu(h, b)
    assert parsed["width"]     == width
    assert parsed["height"]    == height
    assert parsed["bit_depth"] == bit_depth
    assert parsed["color"]     == COLOR_RGB
    assert parsed["channels"]  == 3
    assert parsed["title"]     == "Tiny RGB"
    assert parsed["body"]      == body

    unpacked = unpack_pixels(parsed["body"], 36, bit_depth)
    assert unpacked == values
    print(f"  ✓ round-trip OK; 36 values recovered byte-identical")
    print()


def _selftest_5bit_packing():
    # 5-bit RGB packing — matches Domremy / Sabina bit-depth
    width, height, bit_depth = 2, 2, 5
    values = [0, 1, 2, 3,    # pixel 0: R, G, B  (then pixel 1.R because 4 chans...)
              4, 5, 6, 7,    # pixel 1 mostly
              8, 9, 10, 11]  # 12 values = 4 pixels × 3 channels = 60 bits = 8 bytes
    body = pack_pixels(values, bit_depth)
    assert len(body) == math.ceil(12 * 5 / 8) == 8
    unpacked = unpack_pixels(body, 12, bit_depth)
    assert unpacked == values
    print(f"=== 5-bit pack/unpack ===")
    print(f"  12 values @ 5 bpc -> {len(body)} bytes -> 12 values recovered")
    print(f"  ✓ bit-packing matches Domremy/Sabina depth")
    print()


def _selftest_domremy_header_shape():
    # Verify the Domremy image header bytes (from chain) parse to the
    # spec'd values: 160x240 RGB at 5 bits/channel.
    h = bytes.fromhex("c1dd000103ff0100a000f0057c20446f6d72656d793a2043616d706f20"
                      "646520426f75726c656d6f6e74207c")
    # body is 72000 B on chain; we don't have it here, but the header is
    # what matters for the canonical spec check. Use a dummy zero body of
    # the correct length to exercise the reader.
    body = bytes(expected_body_bytes(160, 240, COLOR_RGB, 5))
    parsed = read_image_quipu(h, body)
    print(f"=== Domremy image header (from chain bytes) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    print(f"  parsed:")
    print(f"    tone:      0x{parsed['tone']:02x} ({'reverence' if parsed['tone']==0xff else '?'})")
    print(f"    color:     0x{parsed['color']:02x} (RGB, {parsed['channels']} channels)")
    print(f"    width:     {parsed['width']}")
    print(f"    height:    {parsed['height']}")
    print(f"    bit_depth: {parsed['bit_depth']}")
    print(f"    title:     {parsed['title']!r}")
    assert parsed["width"]     == 160
    assert parsed["height"]    == 240
    assert parsed["color"]     == COLOR_RGB
    assert parsed["bit_depth"] == 5
    assert parsed["title"]     == "Domremy: Campo de Bourlemont"
    assert parsed["tone"]      == TONE_REVERENCE
    assert parsed["body_bits"] == 160 * 240 * 3 * 5  # = 576000
    assert expected_body_bytes(160, 240, COLOR_RGB, 5) == 72000
    print(f"  ✓ matches on-chain inscription shape (body would be 72000 B)")
    print()


def _selftest_alpha_modes():
    """Round-trip for the two alpha-channel color modes (0x02 gray+alpha,
    0x03 RGBA), at 4-bit and 8-bit depths."""
    print(f"=== alpha-mode round-trips ===")

    # --- gray + alpha, 4-bit -------------------------------------------------
    width, height, bit_depth = 3, 2, 4
    # 6 pixels × 2 channels (G, A) = 12 values, each 0..15
    values = [
        15, 15,   8, 12,   3, 0,    # row 0: bright opaque, mid semi, dim transparent
         0,  0,  15,  4,  10, 8,    # row 1: hidden, bright semi-transparent, mid
    ]
    body = pack_pixels(values, bit_depth)
    expected_n_bytes = math.ceil(width * height * 2 * bit_depth / 8)
    assert len(body) == expected_n_bytes, f"GA pack: {len(body)} vs {expected_n_bytes}"
    h, b = build_image_quipu(width, height, COLOR_GRAY_ALPHA, bit_depth,
                             "Tiny GA", body, tone=TONE_AFFECTION)
    parsed = read_image_quipu(h, b)
    assert parsed["color"]    == COLOR_GRAY_ALPHA
    assert parsed["channels"] == 2
    assert parsed["width"]    == width
    assert parsed["height"]   == height
    assert parsed["title"]    == "Tiny GA"
    assert parsed["body"]     == body
    recovered = unpack_pixels(parsed["body"], width * height * 2, bit_depth)
    assert recovered == values
    print(f"  gray+alpha {width}×{height} @ {bit_depth}-bit: "
          f"{len(values)} values → {len(body)} B → round-trip OK")

    # --- RGBA, 8-bit ---------------------------------------------------------
    width, height, bit_depth = 2, 2, 8
    # 4 pixels × 4 channels (R, G, B, A) = 16 values
    values = [
        255,   0,   0, 255,     # pixel 0: opaque red
          0, 255,   0, 128,     # pixel 1: half-transparent green
          0,   0, 255,   0,     # pixel 2: fully transparent blue
        255, 255, 255, 200,     # pixel 3: mostly-opaque white
    ]
    body = pack_pixels(values, bit_depth)
    assert len(body) == 16
    h, b = build_image_quipu(width, height, COLOR_RGBA, bit_depth,
                             "Tiny RGBA", body, tone=TONE_ORDINARY)
    parsed = read_image_quipu(h, b)
    assert parsed["color"]    == COLOR_RGBA
    assert parsed["channels"] == 4
    assert parsed["body"]     == body
    recovered = unpack_pixels(parsed["body"], width * height * 4, bit_depth)
    assert recovered == values
    print(f"  RGBA       {width}×{height} @ {bit_depth}-bit: "
          f"{len(values)} values → {len(body)} B → round-trip OK")

    # --- RGBA, 4-bit (compact format likely for dancer sprites) -------------
    width, height, bit_depth = 4, 4, 4
    values = []
    for i in range(width * height):
        values.extend([i % 16, (i*3) % 16, (i*5) % 16, 15])  # opaque
    body = pack_pixels(values, bit_depth)
    expected_n_bytes = math.ceil(width * height * 4 * bit_depth / 8)
    assert len(body) == expected_n_bytes
    h, b = build_image_quipu(width, height, COLOR_RGBA, bit_depth,
                             "Tiny RGBA 4bit", body)
    parsed = read_image_quipu(h, b)
    assert parsed["color"] == COLOR_RGBA
    assert parsed["channels"] == 4
    recovered = unpack_pixels(parsed["body"], width * height * 4, bit_depth)
    assert recovered == values
    print(f"  RGBA       {width}×{height} @ {bit_depth}-bit: "
          f"{len(values)} values → {len(body)} B → round-trip OK")

    # --- expected_body_bytes sanity for all four modes -----------------------
    assert expected_body_bytes(100, 100, COLOR_GRAY,       8) == 10000
    assert expected_body_bytes(100, 100, COLOR_RGB,        8) == 30000
    assert expected_body_bytes(100, 100, COLOR_GRAY_ALPHA, 8) == 20000
    assert expected_body_bytes(100, 100, COLOR_RGBA,       8) == 40000
    assert expected_body_bytes(100, 100, COLOR_RGBA,       4) == 20000
    print(f"  expected_body_bytes() consistent across all four color modes")
    print()


def _selftest_validation():
    cases = [
        ("body length mismatch",
         lambda: build_image_quipu(4, 3, COLOR_RGB, 8, "x", b"\x00" * 35),
         "body length"),
        ("bit_depth out of range",
         lambda: build_image_quipu(4, 3, COLOR_RGB, 9, "x", b""),
         "bit_depth"),
        ("color invalid",
         lambda: build_image_quipu(4, 3, 0x05, 8, "x", b""),
         "color"),
        ("width zero",
         lambda: build_image_quipu(0, 3, COLOR_RGB, 8, "x", b""),
         "width"),
        ("title with pipe",
         lambda: build_image_quipu(1, 1, COLOR_GRAY, 8, "a|b", b"\x00"),
         "field-separator"),
        ("pixel value over range",
         lambda: pack_pixels([100], 5),
         "out of range"),
    ]
    print(f"=== validation tests ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:30s} -> {status}: {e}")
        else:
            print(f"  {desc:30s} -> DID NOT RAISE (bug)")
    print()


if __name__ == "__main__":
    _selftest_header_roundtrip()
    _selftest_5bit_packing()
    _selftest_domremy_header_shape()
    _selftest_alpha_modes()
    _selftest_validation()
