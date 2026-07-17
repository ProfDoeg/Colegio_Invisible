"""
file.py — 0x0F file quipu type (canonical).

A generic BINARY CONTAINER. The body is raw, opaque file bytes; the
header carries an optional sha256 digest of the body (flag-gated),
a mimetype, a filename, and an optional human-readable title. Nothing
in here interprets the body — that is the point. Any blob of bytes can
be inscribed as a named, typed file with optional integrity protection.

Spec
----
HEADER (variable):

    c1dd 0001             4B  magic + protocol version 0.1
    0f                    1B  type byte = file
    <tone:1>              1B  tone — see tone.md for the vocabulary
    <flags:1>             1B  bit0 (0x01) = sha256 present;
                              bits 1-7 reserved (MUST be 0)
    [<sha256:32>]         32B present IFF flags bit0 set
                              (raw sha256 digest of the body)
    <mimelen:1>           1B  length of mimetype, 0..255
    <mimetype:mimelen>    ..  UTF-8 (e.g. 'application/pdf'); may be empty
    <namelen:1>           1B  length of filename, 0..255
    <filename:namelen>    ..  UTF-8 (e.g. 'report.pdf')
    <titlelen:1>          1B  length of title, 0..255
    <title:titlelen>      ..  UTF-8 human title; may be empty

All multi-byte integers are BIG-ENDIAN. The structural prefix up to and
including the flags byte is 7 bytes (offsets 0..6). The digest, when
present, occupies offsets 7..38. The three length-prefixed UTF-8 fields
follow, each self-delimiting, so the header length is recoverable from
the header bytes alone (no reliance on the total blob length).

BODY:

    Raw file bytes, opaque. The container neither parses nor transforms
    them. `size` reported by the reader is simply `len(body)`.

sha256 tri-state (load-bearing)
    An ABSENT digest must NEVER read as "tampered". The reader derives
    `has_sha256` purely from `flags & 0x01`, never from the header
    length. `sha256_ok` is three-valued:

        None   no digest present — no integrity claim made
        True   digest present and matches sha256(body)
        False  digest present and does NOT match — genuine tamper

    A header whose `flags` has any reserved bit (1..7) set is REJECTED
    (raises), rather than being silently reinterpreted.

Tone vocabulary
    Same as every type — see tone.md. Validated by the tone module.

Purity
    The container build/read use only stdlib `struct` and `hashlib`.
    NO numpy, no third-party imports. Keyless: reading requires no key.
"""

from __future__ import annotations

import hashlib
import struct


TYPE_FILE = 0x0F

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

_MAGIC = b"\xc1\xdd\x00\x01"

# flags byte bits
FLAG_SHA256   = 0x01   # bit0: a 32-byte sha256 digest follows the flags byte
FLAG_RESERVED = 0xFE   # bits 1-7: reserved, must be zero


def _enc_field(value, label):
    """Encode a str/bytes field to UTF-8 bytes, enforcing the 0..255 cap."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise TypeError(f"{label} must be str (or bytes), got {type(value).__name__}")
    if len(raw) > 255:
        raise ValueError(
            f"{label} encodes to {len(raw)} UTF-8 bytes; max is 255"
        )
    return raw


def build_file_quipu(filename, body, *, mimetype="", sha256=None,
                     title="", tone=TONE_ORDINARY):
    """Build a 0x0F file quipu's (header_bytes, body_bytes) pair.

    Args:
        filename:  UTF-8 string, e.g. 'report.pdf'. <= 255 UTF-8 bytes.
        body:      raw file bytes (bytes/bytearray), returned unchanged.
        mimetype:  UTF-8 string, e.g. 'application/pdf'. May be empty.
                   <= 255 UTF-8 bytes.
        sha256:    integrity digest control —
                     None or False    -> omit digest; flags bit0 clear
                     True             -> digest = sha256(body); flags bit0 set
                     bytes (len == 32) -> used verbatim; flags bit0 set
                     anything else (incl. wrong-length bytes) -> ValueError
        title:     optional human title, UTF-8. May be empty. <= 255 bytes.
        tone:      a valid tone byte (see tone.md).

    Returns:
        (header_bytes, body_bytes) — body returned unchanged.
    """
    validate_tone(tone)

    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(f"body must be bytes, got {type(body).__name__}")
    body_bytes = bytes(body)

    mime_raw = _enc_field(mimetype, "mimetype")
    name_raw = _enc_field(filename, "filename")
    title_raw = _enc_field(title, "title")

    # --- resolve the sha256 tri-state into (flags, digest_bytes) -----------
    if sha256 is None or sha256 is False:
        flags = 0x00
        digest = b""
    elif sha256 is True:
        flags = FLAG_SHA256
        digest = hashlib.sha256(body_bytes).digest()
    elif isinstance(sha256, (bytes, bytearray)):
        digest = bytes(sha256)
        if len(digest) != 32:
            raise ValueError(
                f"sha256 bytes must be exactly 32 bytes; got {len(digest)}"
            )
        flags = FLAG_SHA256
    else:
        raise ValueError(
            "sha256 must be None/False (omit), True (compute), or 32 raw "
            f"bytes; got {type(sha256).__name__}"
        )

    # reserved bits are never set by the builder, but assert the invariant
    if flags & FLAG_RESERVED:
        raise ValueError("reserved flag bits (1-7) must remain 0")

    header = (
        _MAGIC
        + bytes([TYPE_FILE, tone, flags])
        + digest
        + bytes([len(mime_raw)]) + mime_raw
        + bytes([len(name_raw)]) + name_raw
        + bytes([len(title_raw)]) + title_raw
    )
    return header, body_bytes


def read_file_quipu(header_bytes, body_bytes):
    """Parse a 0x0F file quipu. Keyless.

    Args:
        header_bytes: the header strand (bytes).
        body_bytes:   the body strand (raw file bytes).

    Returns:
        {
          'type':       'file',
          'tone':       int,
          'flags':      int,
          'has_sha256': bool,
          'sha256':     str | None  (64-char lowercase hex, or None),
          'sha256_ok':  None | True | False  (tri-state, see module docstring),
          'mimetype':   str,
          'filename':   str,
          'title':      str,
          'body':       bytes,
          'size':       int (len(body)),
        }

    Raises:
        ValueError on bad magic, wrong type byte, reserved flag bits set,
        or a truncated header.
    """
    header_bytes = bytes(header_bytes)
    body_bytes = bytes(body_bytes)

    if header_bytes[:4] != _MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 7:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need >= 7)"
        )
    if header_bytes[4] != TYPE_FILE:
        raise ValueError(
            f"not a file quipu (type byte = {header_bytes[4]:#04x}, "
            f"expected 0x0f)"
        )

    tone = header_bytes[5]
    flags = header_bytes[6]

    if flags & FLAG_RESERVED:
        raise ValueError(
            f"reserved flag bits set in flags byte {flags:#04x}; "
            f"only bit0 (0x01, sha256-present) is defined"
        )

    has_sha256 = bool(flags & FLAG_SHA256)

    off = 7
    if has_sha256:
        if len(header_bytes) < off + 32:
            raise ValueError("header truncated: sha256 flag set but digest missing")
        stored_digest = header_bytes[off:off + 32]
        off += 32
    else:
        stored_digest = None

    def _read_field(off, label):
        if off >= len(header_bytes):
            raise ValueError(f"header truncated: missing {label} length byte")
        length = header_bytes[off]
        off += 1
        end = off + length
        if end > len(header_bytes):
            raise ValueError(
                f"header truncated: {label} claims {length} bytes "
                f"but only {len(header_bytes) - off} remain"
            )
        text = header_bytes[off:end].decode("utf-8", errors="replace")
        return text, end

    mimetype, off = _read_field(off, "mimetype")
    filename, off = _read_field(off, "filename")
    title, off = _read_field(off, "title")

    # --- sha256 tri-state ---------------------------------------------------
    if not has_sha256:
        sha256_hex = None
        sha256_ok = None
    else:
        sha256_hex = stored_digest.hex()
        sha256_ok = (hashlib.sha256(body_bytes).digest() == stored_digest)

    return {
        "type":       "file",
        "tone":       tone,
        "flags":      flags,
        "has_sha256": has_sha256,
        "sha256":     sha256_hex,
        "sha256_ok":  sha256_ok,
        "mimetype":   mimetype,
        "filename":   filename,
        "title":      title,
        "body":       body_bytes,
        "size":       len(body_bytes),
    }


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_with_sha256():
    body = b"%PDF-1.7\nfake pdf bytes for the round trip\n" * 4
    h, b = build_file_quipu(
        "report.pdf", body,
        mimetype="application/pdf",
        sha256=True,
        title="Quarterly Report",
        tone=TONE_REVERENCE,
    )
    assert h[:4] == _MAGIC
    assert h[4] == TYPE_FILE
    assert h[5] == TONE_REVERENCE
    assert h[6] == FLAG_SHA256

    r = read_file_quipu(h, b)
    assert r["type"] == "file"
    assert r["has_sha256"] is True
    assert r["sha256_ok"] is True
    assert r["sha256"] == hashlib.sha256(body).hexdigest()
    assert r["mimetype"] == "application/pdf"
    assert r["filename"] == "report.pdf"
    assert r["title"] == "Quarterly Report"
    assert r["tone"] == TONE_REVERENCE
    assert r["body"] == body
    assert r["size"] == len(body)

    # Tamper one body byte -> a FRESH read must report sha256_ok False.
    tampered = bytearray(b)
    tampered[0] ^= 0x01
    r2 = read_file_quipu(h, bytes(tampered))
    assert r2["has_sha256"] is True
    assert r2["sha256_ok"] is False, "flipping a body byte must fail integrity"
    print("=== file WITH sha256 ===")
    print(f"  header {len(h)} B, body {len(b)} B")
    print(f"  sha256_ok (clean)    = {r['sha256_ok']}")
    print(f"  sha256_ok (tampered) = {r2['sha256_ok']}")
    print("  OK: verified True; one-bit body flip -> False")
    print()


def _selftest_without_sha256():
    body = b"plain bytes, no integrity claim"
    h, b = build_file_quipu(
        "notes.txt", body,
        mimetype="text/plain",
        sha256=None,
        title="",
    )
    assert h[6] == 0x00  # flags clear

    r = read_file_quipu(h, b)
    assert r["has_sha256"] is False
    assert r["sha256"] is None
    assert r["sha256_ok"] is None, "absent digest must read as None, never False"

    # Even with a different body, an unhashed file is NEVER 'tampered'.
    r2 = read_file_quipu(h, b"totally different bytes")
    assert r2["has_sha256"] is False
    assert r2["sha256_ok"] is None, "unhashed file must never read as tampered"
    print("=== file WITHOUT sha256 ===")
    print(f"  has_sha256 = {r['has_sha256']}, sha256 = {r['sha256']}, "
          f"sha256_ok = {r['sha256_ok']}")
    print("  OK: no integrity claim; never a false tamper")
    print()


def _selftest_field_roundtrip():
    body = b"\x00\x01\x02\x03\xff\xfe"
    # explicit 32-byte digest passed verbatim
    digest = hashlib.sha256(body).digest()
    h, b = build_file_quipu(
        "imágen-ñ.bin", body,
        mimetype="application/octet-stream",
        sha256=digest,
        title="Tóno y título — UTF-8 ✓",
        tone=TONE_AFFECTION,
    )
    r = read_file_quipu(h, b)
    assert r["filename"] == "imágen-ñ.bin"
    assert r["mimetype"] == "application/octet-stream"
    assert r["title"] == "Tóno y título — UTF-8 ✓"
    assert r["tone"] == TONE_AFFECTION
    assert r["sha256_ok"] is True
    assert r["sha256"] == digest.hex()

    # empty mimetype / empty title round-trip
    h2, b2 = build_file_quipu("x", b"hi", mimetype="", title="")
    r2 = read_file_quipu(h2, b2)
    assert r2["mimetype"] == ""
    assert r2["title"] == ""
    assert r2["filename"] == "x"
    print("=== mimetype / filename / title / tone round-trip ===")
    print(f"  filename={r['filename']!r} mimetype={r['mimetype']!r}")
    print(f"  title={r['title']!r} tone=0x{r['tone']:02x}")
    print("  OK: UTF-8 fields + verbatim 32-byte digest + empty fields")
    print()


def _selftest_validation():
    cases = [
        ("filename too long",
         lambda: build_file_quipu("x" * 256, b""), "255"),
        ("mimetype too long",
         lambda: build_file_quipu("x", b"", mimetype="m" * 256), "255"),
        ("title too long",
         lambda: build_file_quipu("x", b"", title="t" * 256), "255"),
        ("bad tone",
         lambda: build_file_quipu("x", b"", tone=0x42), "tone"),
        ("wrong-length digest",
         lambda: build_file_quipu("x", b"", sha256=b"\x00" * 31), "32 bytes"),
        ("bad sha256 type",
         lambda: build_file_quipu("x", b"", sha256=123), "sha256 must"),
    ]
    print("=== validation tests ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:24s} -> {status}: {e}")
        else:
            print(f"  {desc:24s} -> DID NOT RAISE (bug)")

    # reader rejects reserved flag bits
    h, b = build_file_quipu("x", b"hi")
    bad = bytearray(h)
    bad[6] = 0x02  # set a reserved bit
    try:
        read_file_quipu(bytes(bad), b)
    except ValueError as e:
        print(f"  {'reserved flag bit set':24s} -> OK: {e}")
    else:
        print(f"  {'reserved flag bit set':24s} -> DID NOT RAISE (bug)")
    print()


def _selftest_purity():
    # Hermetic check in a FRESH interpreter: asserting on this process's
    # sys.modules was a false positive under shared pytest (any neighbor's
    # pandas import trips it regardless of what file.py does).
    import os
    import subprocess
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    code = ("import sys; sys.path.insert(0, %r); import file; "
            "assert 'numpy' not in sys.modules, 'pulled numpy'" % here)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"file.py pulled numpy:\n{r.stderr}"
    print("=== container purity (hermetic) ===")
    print("  OK: stdlib only (struct/hashlib); numpy not imported in a fresh interpreter")
    print()


if __name__ == "__main__":
    _selftest_with_sha256()
    _selftest_without_sha256()
    _selftest_field_roundtrip()
    _selftest_validation()
    _selftest_purity()
    print("all file.py self-tests passed.")
