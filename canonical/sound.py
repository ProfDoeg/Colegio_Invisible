"""
sound.py — 0x07 sound quipu type (canonical).

A general AUDIO CONTAINER. The body is opaque encoded audio; what the
bytes mean is decided entirely by the codec byte in the header. The
container is codec-agnostic: it carries enough metadata (sample rate,
channel count, duration, a small codec-specific blob) to describe and
route the audio, but it never decodes it. Speech vocoders (STFT / LPC /
Codec2) and opaque standard formats (opus / mp3 / wav / flac) all share
this one type byte; the codec enum selects between them.

This canonicalizes the old 0x07 slot. The earlier "voice" sketch in
`voice_codec.py` was never inscribed; its wire format has been redesigned
freely into this container. The numpy DSP that produces/consumes the
STFT and LPC bodies lives in `voice_codec.py` and imports numpy lazily;
THIS module is pure stdlib (`struct` + `hashlib`) and MUST NOT import
numpy, so the container builds and reads on a machine with no numpy.

Spec
----
HEADER (16 + cmlen + titlelen bytes):

    offset  field                bytes  meaning
    0..3    c1dd 0001             4B  magic + protocol version 0.1
    4       07                    1B  type byte = sound
    5       <tone:1>              1B  tone — see tone.md for the vocabulary
    6       <codec:1>             1B  codec / format byte (enum below)
    7..8    <sample_rate:u16 BE>  2B  Hz; 0 = unknown / embedded in bitstream
    9       <channels:1>          1B  channel count; 0 = unknown
    10..13  <duration_ms:u32 BE>  4B  total duration in ms; 0 = unknown
    14      <cmlen:1>             1B  codec-meta length, 0..255
    15..    <codec_meta:cmlen>    ..  codec-specific bytes, opaque
    .       <titlelen:1>          1B  length of title, 0..255
    .       <title:titlelen>      ..  UTF-8 human title; may be length 0

All multi-byte integers are BIG-ENDIAN. The fixed structural prefix is
15 bytes (offsets 0..14), with the codec-meta length byte at offset 14.
The codec_meta region begins at offset 15; the title-length byte sits at
offset 15 + cmlen, and the title at 16 + cmlen. Total header length =
16 + cmlen + titlelen — recoverable from the header bytes alone (the two
length-prefixed regions are self-delimiting), so a reader never needs the
total blob length to split header from body.

BODY:

    Encoded audio bytes, opaque. The container neither parses nor
    transforms them. `size` reported by the reader is `len(body)`.

CODEC enum
    0x00 stft   quipu STFT-magnitude vocoder (speech)
                codec_meta = n_frames:u16 + g_min:f32 + g_max:f32   (10 B)
    0x01 lpc    quipu LPC-10 vocoder (speech)
                codec_meta = n_frames:u16                            (2 B)
    0x02 codec2 Codec2-700C (speech, needs libcodec2)
                codec_meta = n_frames:u16                            (2 B)
    0x10 opus   opaque ogg/opus bytes                  codec_meta = b''
    0x11 mp3    opaque                                 codec_meta = b''
    0x12 wav    opaque WAV/PCM                          codec_meta = b''
    0x13 flac   opaque                                 codec_meta = b''

    Any codec byte parses fine — an unknown value surfaces as
    'unknown_0xNN' via codec_name(), for forward compatibility. The
    builder accepts ANY byte 0..255 in the codec field for the same
    reason.

Tone vocabulary
    Same as every type — see tone.md. Validated by the tone module.

Purity
    The container build/read use only stdlib `struct` (and `hashlib` is
    imported but unused by the container — kept for parity with the other
    envelope types; no numpy, no third-party imports). Keyless: reading
    requires no key.

Example on chain (shape)
    A 5-second STFT vocoder utterance: codec 0x00, sample_rate 8000,
    channels 1, duration_ms 5000, codec_meta = 10 bytes
    (n_frames:u16 + g_min:f32 + g_max:f32), title "| Ephemeris |".
    Body is n_frames * 32 bytes of 8-bit log-magnitude bins.
"""

from __future__ import annotations

import struct


TYPE_SOUND = 0x07

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

_MAGIC = b"\xc1\xdd\x00\x01"

# ---------------------------------------------------------------------------
# Codec enum
# ---------------------------------------------------------------------------
# Speech vocoders (quipu-native bodies, decoded by the numpy DSP in
# voice_codec.py):
CODEC_STFT   = 0x00   # band-limited 8-bit STFT-magnitude vocoder
CODEC_LPC    = 0x01   # LPC-10-style vocoder
CODEC_CODEC2 = 0x02   # Codec2-700C (needs libcodec2)
# Opaque standard formats (the body is a real container/bitstream a
# browser or audio library decodes directly; codec_meta is empty):
CODEC_OPUS   = 0x10   # ogg/opus
CODEC_MP3    = 0x11   # mp3
CODEC_WAV    = 0x12   # WAV / PCM
CODEC_FLAC   = 0x13   # flac

# Canonical byte -> name map. THE dictionary; everything else is derived.
CODEC_NAMES = {
    CODEC_STFT:   "stft",
    CODEC_LPC:    "lpc",
    CODEC_CODEC2: "codec2",
    CODEC_OPUS:   "opus",
    CODEC_MP3:    "mp3",
    CODEC_WAV:    "wav",
    CODEC_FLAC:   "flac",
}

# Reverse lookup: name -> byte.
CODEC_BY_NAME = {v: k for k, v in CODEC_NAMES.items()}

# The three speech vocoders whose bodies need the numpy DSP to decode.
# (Renderers use this to decide "browser can't play this — show a card".)
VOCODER_CODECS = frozenset({CODEC_STFT, CODEC_LPC, CODEC_CODEC2})

# Opaque standard codecs -> a MIME type, for renderers emitting <audio>.
CODEC_MIME = {
    CODEC_OPUS: "audio/ogg",
    CODEC_MP3:  "audio/mpeg",
    CODEC_WAV:  "audio/wav",
    CODEC_FLAC: "audio/flac",
}


def codec_name(codec):
    """Return the canonical name for a codec byte, or 'unknown_0xNN' for
    an unrecognized value (readers pass unknown codecs through without
    failing — only out-of-range bytes are ever rejected, and the byte
    field is a single octet so nothing is)."""
    return CODEC_NAMES.get(codec, f"unknown_0x{codec:02x}")


# ---------------------------------------------------------------------------
# Vocoder codec_meta (un)packers
# ---------------------------------------------------------------------------
# These pack the small codec-specific metadata blob that rides in the
# header. They are pure-stdlib (struct only) so the container module can
# build/read vocoder headers without numpy; the DSP in voice_codec.py
# calls these to assemble its codec_meta.

def pack_stft_meta(n_frames, g_min, g_max):
    """Pack the STFT vocoder's codec_meta: n_frames:u16 + g_min:f32 +
    g_max:f32 = 10 bytes, big-endian ('>Hff')."""
    if not (0 <= int(n_frames) <= 0xFFFF):
        raise ValueError(f"n_frames must fit in u16 [0, 65535]; got {n_frames}")
    return struct.pack(">Hff", int(n_frames), float(g_min), float(g_max))


def unpack_stft_meta(codec_meta):
    """Unpack STFT codec_meta -> (n_frames, g_min, g_max). Expects exactly
    10 bytes ('>Hff')."""
    codec_meta = bytes(codec_meta)
    if len(codec_meta) < 10:
        raise ValueError(
            f"stft codec_meta must be >= 10 bytes; got {len(codec_meta)}"
        )
    n_frames, g_min, g_max = struct.unpack(">Hff", codec_meta[:10])
    return n_frames, g_min, g_max


def pack_frames_meta(n_frames):
    """Pack the LPC / Codec2 codec_meta: just n_frames:u16 = 2 bytes,
    big-endian ('>H')."""
    if not (0 <= int(n_frames) <= 0xFFFF):
        raise ValueError(f"n_frames must fit in u16 [0, 65535]; got {n_frames}")
    return struct.pack(">H", int(n_frames))


def unpack_frames_meta(codec_meta):
    """Unpack LPC / Codec2 codec_meta -> n_frames (int). Expects >= 2
    bytes ('>H')."""
    codec_meta = bytes(codec_meta)
    if len(codec_meta) < 2:
        raise ValueError(
            f"frames codec_meta must be >= 2 bytes; got {len(codec_meta)}"
        )
    return struct.unpack(">H", codec_meta[:2])[0]


# ---------------------------------------------------------------------------
# Build / read
# ---------------------------------------------------------------------------

def build_sound_quipu(codec, body, *, sample_rate=0, channels=0,
                      duration_ms=0, codec_meta=b"", title="",
                      tone=TONE_ORDINARY):
    """Build a 0x07 sound quipu's (header_bytes, body_bytes) pair.

    Args:
        codec:        codec/format byte. ANY value in [0, 255] is accepted
                      (forward-compat); see the CODEC_* constants for the
                      known ones.
        body:         encoded audio bytes (bytes/bytearray), opaque,
                      returned unchanged.
        sample_rate:  Hz, in [0, 65535]. 0 = unknown / embedded in the
                      bitstream.
        channels:     channel count, in [0, 255]. 0 = unknown.
        duration_ms:  total duration in ms, in [0, 0xFFFFFFFF]. 0 = unknown.
        codec_meta:   codec-specific bytes, <= 255 bytes, opaque to the
                      container. Use pack_stft_meta / pack_frames_meta for
                      the vocoder codecs; b'' for the opaque formats.
        title:        optional human title, UTF-8. May be empty.
                      <= 255 UTF-8 bytes.
        tone:         a valid tone byte (see tone.md).

    Returns:
        (header_bytes, body_bytes) — body returned unchanged.
    """
    validate_tone(tone)

    if not isinstance(codec, int) or not (0 <= codec <= 0xFF):
        raise ValueError(f"codec must be a byte in [0, 255]; got {codec!r}")
    if not (0 <= sample_rate <= 0xFFFF):
        raise ValueError(f"sample_rate must be in [0, 65535]; got {sample_rate}")
    if not (0 <= channels <= 0xFF):
        raise ValueError(f"channels must be in [0, 255]; got {channels}")
    if not (0 <= duration_ms <= 0xFFFFFFFF):
        raise ValueError(
            f"duration_ms must be in [0, {0xFFFFFFFF}]; got {duration_ms}"
        )

    if not isinstance(codec_meta, (bytes, bytearray)):
        raise TypeError(
            f"codec_meta must be bytes, got {type(codec_meta).__name__}"
        )
    codec_meta = bytes(codec_meta)
    if len(codec_meta) > 255:
        raise ValueError(
            f"codec_meta is {len(codec_meta)} bytes; max is 255"
        )

    if not isinstance(title, str):
        raise TypeError(f"title must be str, got {type(title).__name__}")
    title_raw = title.encode("utf-8")
    if len(title_raw) > 255:
        raise ValueError(
            f"title encodes to {len(title_raw)} UTF-8 bytes; max is 255"
        )

    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(f"body must be bytes, got {type(body).__name__}")
    body_bytes = bytes(body)

    header = (
        _MAGIC
        + bytes([TYPE_SOUND, tone, codec])
        + struct.pack(">H", sample_rate)
        + bytes([channels])
        + struct.pack(">I", duration_ms)
        + bytes([len(codec_meta)]) + codec_meta
        + bytes([len(title_raw)]) + title_raw
    )
    return header, body_bytes


def read_sound_quipu(header_bytes, body_bytes):
    """Parse a 0x07 sound quipu. Keyless.

    Args:
        header_bytes: the header strand (bytes).
        body_bytes:   the body strand (encoded audio bytes).

    Returns:
        {
          'type':        'sound',
          'tone':        int,
          'codec':       int,
          'codec_name':  str ('stft' / ... / 'unknown_0xNN'),
          'sample_rate': int (Hz; 0 = unknown),
          'channels':    int (0 = unknown),
          'duration_ms': int (0 = unknown),
          'codec_meta':  bytes (opaque codec-specific blob),
          'title':       str,
          'body':        bytes,
          'size':        int (len(body)),
        }

    Raises:
        ValueError on bad magic, wrong type byte, or a truncated header.
    """
    header_bytes = bytes(header_bytes)
    body_bytes = bytes(body_bytes)

    if header_bytes[:4] != _MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 16:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need >= 16)"
        )
    if header_bytes[4] != TYPE_SOUND:
        raise ValueError(
            f"not a sound quipu (type byte = {header_bytes[4]:#04x}, "
            f"expected 0x07)"
        )

    tone        = header_bytes[5]
    codec       = header_bytes[6]
    sample_rate = struct.unpack(">H", header_bytes[7:9])[0]
    channels    = header_bytes[9]
    duration_ms = struct.unpack(">I", header_bytes[10:14])[0]
    cmlen       = header_bytes[14]

    cm_start = 15
    cm_end = cm_start + cmlen
    if cm_end > len(header_bytes):
        raise ValueError(
            f"header truncated: codec_meta claims {cmlen} bytes but only "
            f"{len(header_bytes) - cm_start} remain"
        )
    codec_meta = header_bytes[cm_start:cm_end]

    if cm_end >= len(header_bytes):
        raise ValueError("header truncated: missing title length byte")
    titlelen = header_bytes[cm_end]
    title_start = cm_end + 1
    title_end = title_start + titlelen
    if title_end > len(header_bytes):
        raise ValueError(
            f"header truncated: title claims {titlelen} bytes but only "
            f"{len(header_bytes) - title_start} remain"
        )
    title = header_bytes[title_start:title_end].decode("utf-8", errors="replace")

    return {
        "type":        "sound",
        "tone":        tone,
        "codec":       codec,
        "codec_name":  codec_name(codec),
        "sample_rate": sample_rate,
        "channels":    channels,
        "duration_ms": duration_ms,
        "codec_meta":  codec_meta,
        "title":       title,
        "body":        body_bytes,
        "size":        len(body_bytes),
    }


def sound_header_len(header_bytes):
    """Return the total header length computed purely from header fields:
    17 + cmlen + titlelen. Used by split_blob-style helpers to separate
    the header strand from the body strand without relying on the joined
    blob length."""
    header_bytes = bytes(header_bytes)
    if len(header_bytes) < 16:
        raise ValueError("header too short to measure")
    cmlen = header_bytes[14]
    titlelen = header_bytes[15 + cmlen]
    return 16 + cmlen + titlelen


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_opaque_wav():
    # 0x12 wav with synthetic opaque bytes — exercises the empty-codec_meta
    # path and the opaque-format branch.
    body = bytes(range(256)) * 8  # 2048 bytes of fake "WAV" payload
    h, b = build_sound_quipu(
        CODEC_WAV, body,
        sample_rate=44100, channels=2, duration_ms=12000,
        codec_meta=b"", title="Synthetic WAV",
        tone=TONE_REVERENCE,
    )
    assert h[:4] == _MAGIC
    assert h[4] == TYPE_SOUND
    assert h[5] == TONE_REVERENCE
    assert h[6] == CODEC_WAV
    assert struct.unpack(">H", h[7:9])[0] == 44100
    assert h[9] == 2
    assert struct.unpack(">I", h[10:14])[0] == 12000
    assert h[14] == 0  # cmlen

    r = read_sound_quipu(h, b)
    assert r["type"] == "sound"
    assert r["codec"] == CODEC_WAV
    assert r["codec_name"] == "wav"
    assert r["sample_rate"] == 44100
    assert r["channels"] == 2
    assert r["duration_ms"] == 12000
    assert r["codec_meta"] == b""
    assert r["title"] == "Synthetic WAV"
    assert r["tone"] == TONE_REVERENCE
    assert r["body"] == body
    assert r["size"] == len(body)
    assert sound_header_len(h) == len(h)
    print("=== opaque 0x12 wav ===")
    print(f"  header {len(h)} B, body {len(b)} B; "
          f"codec={r['codec_name']} sr={r['sample_rate']} ch={r['channels']} "
          f"dur={r['duration_ms']}ms")
    print("  OK: round-trip byte-identical")
    print()


def _selftest_stft_meta():
    # 0x00 stft with a 10-byte codec_meta — exercises pack/unpack_stft_meta
    # and the vocoder branch. (No numpy: we feed a synthetic body.)
    n_frames, g_min, g_max = 313, -7.5, 3.25
    meta = pack_stft_meta(n_frames, g_min, g_max)
    assert len(meta) == 10
    body = bytes((i * 7) & 0xFF for i in range(n_frames * 32))  # K_BINS=32
    h, b = build_sound_quipu(
        CODEC_STFT, body,
        sample_rate=8000, channels=1, duration_ms=5008,
        codec_meta=meta, title="Ephemeris",
        tone=TONE_ORDINARY,
    )
    r = read_sound_quipu(h, b)
    assert r["codec"] == CODEC_STFT
    assert r["codec_name"] == "stft"
    assert r["sample_rate"] == 8000
    assert r["channels"] == 1
    assert r["duration_ms"] == 5008
    assert r["codec_meta"] == meta
    nf2, gmin2, gmax2 = unpack_stft_meta(r["codec_meta"])
    assert nf2 == n_frames
    assert abs(gmin2 - g_min) < 1e-5
    assert abs(gmax2 - g_max) < 1e-5
    assert r["body"] == body
    print("=== vocoder 0x00 stft (synthetic body, no numpy) ===")
    print(f"  header {len(h)} B, body {len(b)} B; codec_meta {len(meta)} B")
    print(f"  unpacked: n_frames={nf2} g_min={gmin2:.3f} g_max={gmax2:.3f}")
    print("  OK: codec_meta pack/unpack + round-trip")
    print()


def _selftest_frames_meta():
    # 0x01 lpc / 0x02 codec2 with a 2-byte codec_meta.
    for codec, name in ((CODEC_LPC, "lpc"), (CODEC_CODEC2, "codec2")):
        n_frames = 200
        meta = pack_frames_meta(n_frames)
        assert len(meta) == 2
        body = bytes(n_frames * 12)  # arbitrary opaque body
        h, b = build_sound_quipu(
            codec, body,
            sample_rate=8000, channels=1, duration_ms=5000,
            codec_meta=meta, title=name,
        )
        r = read_sound_quipu(h, b)
        assert r["codec"] == codec
        assert r["codec_name"] == name
        assert unpack_frames_meta(r["codec_meta"]) == n_frames
        assert r["body"] == body
    print("=== vocoder 0x01 lpc / 0x02 codec2 (2-byte meta) ===")
    print("  OK: pack/unpack_frames_meta round-trip for both")
    print()


def _selftest_unknown_and_empty():
    # Unknown codec byte parses as unknown_0xNN; empty title round-trips.
    h, b = build_sound_quipu(0x7F, b"abc", title="")
    r = read_sound_quipu(h, b)
    assert r["codec"] == 0x7F
    assert r["codec_name"] == "unknown_0x7f"
    assert r["title"] == ""
    assert r["sample_rate"] == 0
    assert r["channels"] == 0
    assert r["duration_ms"] == 0
    assert r["codec_meta"] == b""

    # codec_name() helper + reverse map sanity
    assert codec_name(CODEC_OPUS) == "opus"
    assert CODEC_BY_NAME["mp3"] == CODEC_MP3
    assert CODEC_MIME[CODEC_FLAC] == "audio/flac"
    assert CODEC_STFT in VOCODER_CODECS and CODEC_WAV not in VOCODER_CODECS
    print("=== unknown codec / empty title / name maps ===")
    print(f"  codec 0x7f -> {r['codec_name']!r}; empty title OK")
    print("  OK: forward-compat unknown byte + name maps")
    print()


def _selftest_validation():
    cases = [
        ("bad tone",
         lambda: build_sound_quipu(CODEC_WAV, b"", tone=0x42), "tone"),
        ("sample_rate over range",
         lambda: build_sound_quipu(CODEC_WAV, b"", sample_rate=70000),
         "sample_rate"),
        ("channels over range",
         lambda: build_sound_quipu(CODEC_WAV, b"", channels=300), "channels"),
        ("duration_ms over range",
         lambda: build_sound_quipu(CODEC_WAV, b"", duration_ms=0x1_0000_0000),
         "duration_ms"),
        ("codec_meta too long",
         lambda: build_sound_quipu(CODEC_WAV, b"", codec_meta=b"x" * 256),
         "255"),
        ("title too long",
         lambda: build_sound_quipu(CODEC_WAV, b"", title="t" * 256), "255"),
        ("codec out of range",
         lambda: build_sound_quipu(300, b""), "codec"),
        ("stft meta n_frames over u16",
         lambda: pack_stft_meta(70000, 0.0, 1.0), "u16"),
    ]
    print("=== validation tests ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:28s} -> {status}: {e}")
        else:
            print(f"  {desc:28s} -> DID NOT RAISE (bug)")

    # reader rejects a wrong type byte
    h, b = build_sound_quipu(CODEC_WAV, b"hi")
    bad = bytearray(h)
    bad[4] = 0x03
    try:
        read_sound_quipu(bytes(bad), b)
    except ValueError as e:
        print(f"  {'wrong type byte':28s} -> OK: {e}")
    else:
        print(f"  {'wrong type byte':28s} -> DID NOT RAISE (bug)")
    print()


def _selftest_purity():
    import sys
    # The container module must not pull numpy in transitively.
    assert "numpy" not in sys.modules, "sound.py must not import numpy"
    print("=== container purity ===")
    print("  OK: stdlib only (struct); numpy not imported")
    print()


if __name__ == "__main__":
    _selftest_opaque_wav()
    _selftest_stft_meta()
    _selftest_frames_meta()
    _selftest_unknown_and_empty()
    _selftest_validation()
    _selftest_purity()
    print("all sound.py self-tests passed.")
