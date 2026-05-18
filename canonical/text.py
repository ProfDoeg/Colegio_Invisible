"""
text.py — 0x00 text quipu type (canonical).

The simplest quipu type. Body is plain UTF-8 text. Header carries a
pipe-bracketed title after the magic + type + tone bytes; nothing else
structural.

Spec
----
HEADER (6 + variable title bytes):

    c1dd 0001                       magic + protocol version 0.1
    00                              type byte = text
    <tone:1>                        00 ordinary, ff reverence
    <pipe-bracketed title>          | TITLE | (UTF-8, between pipe sentinels)

BODY:

    UTF-8 text, arbitrary length, no structural constraints.

    Bodies MAY contain citation references of the form:
        <<txid>><<name>>           — sub-object inside another quipu
        <<txid>>                   — whole inscription
        <<alias>> = <<txid>>       — inline binding (alias for use later)

    Bodies MAY contain `Field: value\\n` lines (the essay convention,
    consumed by essay_renderer.py).

    These are all *body conventions* — the protocol-level definition of
    type 0x00 is just "UTF-8 in, UTF-8 out."

Title-field convention
----------------------
The title is enclosed by literal `|` (0x7C) bytes. Runs of `|` (one, two,
or more) are equivalent — the parser splits on `|` and takes non-empty
parts. So `|TITLE|`, `||TITLE||`, `|TITLE|EXTRA|` all parse with TITLE
as the first non-empty field.

Empty title (no pipes at all) is permitted — the entire header tail
after byte 5 is treated as the single first field.

Examples on chain
-----------------
    | Mi Perrito |              text quipu, ordinary tone
    | Mi Caballo |              text quipu, ordinary tone

(The actual UTF-8 bytes between the pipes vary; the structural shape is
fixed.)
"""

from __future__ import annotations


TYPE_TEXT       = 0x00

# Tone vocabulary — observed on chain across the existing text corpus.
# Three named values; any other byte is rejected by the builder but
# accepted (passed through) by the reader.
TONE_ORDINARY   = 0x00   # default; descriptive, academic, neutral,
                         #           or literary content about the living
TONE_AFFECTION  = 0x01   # paired / intimate / addressed to a specific other
                         #   (e.g. Mi Perrito at pair_CA, Mi Caballo at pair_HA)
TONE_REVERENCE  = 0xFF   # the dead, ancestors, formal commemoration

_VALID_TONES = (TONE_ORDINARY, TONE_AFFECTION, TONE_REVERENCE)

PIPE            = ord("|")  # 0x7C


def build_text_quipu(title, body, tone=TONE_ORDINARY):
    """Build a 0x00 text quipu's (header_bytes, body_bytes) pair.

    Args:
        title: figure title. Encoded as UTF-8 between `|` sentinels.
               May be empty (`""`) — header then carries no pipes.
               MUST NOT contain `|` (would split into multiple fields
               and confuse the reader).
        body:  body text (str) or raw bytes. str is UTF-8 encoded.
        tone:  TONE_ORDINARY (0x00, default) or TONE_REVERENCE (0xff).

    Returns:
        (header_bytes, body_bytes)
    """
    if tone not in _VALID_TONES:
        raise ValueError(
            f"tone must be 0x00 (ordinary), 0x01 (affection), or 0xff "
            f"(reverence); got {tone:#04x}"
        )
    if not isinstance(title, str):
        raise TypeError(f"title must be str, got {type(title).__name__}")
    if "|" in title:
        raise ValueError(
            f"title contains '|' which is the field-separator byte; "
            f"would parse as multiple fields"
        )

    header = b"\xc1\xdd\x00\x01" + bytes([TYPE_TEXT]) + bytes([tone])
    if title:
        header += b"|" + title.encode("utf-8") + b"|"

    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = bytes(body)
    else:
        raise TypeError(f"body must be str or bytes, got {type(body).__name__}")

    return header, body_bytes


def read_text_quipu(header_bytes, body_bytes):
    """Parse a 0x00 text quipu.

    Returns:
        {
          'title':  str,                # first non-empty pipe-field, or '' if no pipes
          'tone':   int (0x00 or 0xff),
          'fields': [str, ...],         # all non-empty pipe-fields (may be []), or
                                          ['<tail>'] if the header had no pipes
          'body':   str,                # body decoded as UTF-8
        }

    Raises:
        ValueError on bad magic / wrong type / non-UTF-8 body.
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing from header)")
    if len(header_bytes) < 6:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need ≥ 6)"
        )
    if header_bytes[4] != TYPE_TEXT:
        raise ValueError(
            f"not a text quipu (type byte = {header_bytes[4]:#04x}, expected 0x00)"
        )

    tone = header_bytes[5]
    tail = header_bytes[6:].rstrip(b"\x00 ")

    if not tail:
        title  = ""
        fields = []
    elif b"|" in tail:
        text   = tail.decode("utf-8", errors="replace")
        fields = [p for p in text.split("|") if p != ""]
        title  = fields[0] if fields else ""
    else:
        # No pipes — the whole tail is treated as one field (also the title)
        text   = tail.decode("utf-8", errors="replace")
        fields = [text]
        title  = text

    try:
        body = body_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"body is not valid UTF-8: {e}")

    return {
        "title":  title,
        "tone":   tone,
        "fields": fields,
        "body":   body,
    }


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_basic():
    h, b = build_text_quipu("Mi Perrito", "A short note about my dog.")
    print(f"=== basic text quipu ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    assert h == b"\xc1\xdd\x00\x01\x00\x00|Mi Perrito|"
    assert b == b"A short note about my dog."

    parsed = read_text_quipu(h, b)
    assert parsed["title"]  == "Mi Perrito"
    assert parsed["tone"]   == TONE_ORDINARY
    assert parsed["fields"] == ["Mi Perrito"]
    assert parsed["body"]   == "A short note about my dog."
    print(f"  ✓ round-trip OK")
    print()


def _selftest_reverence_unicode():
    h, b = build_text_quipu("Domrémy", "L’enfance de la pucelle.", tone=TONE_REVERENCE)
    print(f"=== reverence + unicode title ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    parsed = read_text_quipu(h, b)
    assert parsed["title"] == "Domrémy"
    assert parsed["tone"]  == TONE_REVERENCE
    assert parsed["body"]  == "L’enfance de la pucelle."
    print(f"  ✓ round-trip OK; é and ’ preserved")
    print()


def _selftest_empty_title():
    h, b = build_text_quipu("", "untitled fragment")
    print(f"=== empty title ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    assert h == b"\xc1\xdd\x00\x01\x00\x00"
    parsed = read_text_quipu(h, b)
    assert parsed["title"]  == ""
    assert parsed["fields"] == []
    assert parsed["body"]   == "untitled fragment"
    print(f"  ✓ round-trip OK (no pipes when title is empty)")
    print()


def _selftest_multifield():
    # Title plus an extra field — the parser keeps both
    h = b"\xc1\xdd\x00\x01\x00\xff|Title|EXTRA|"
    b = b"body content"
    print(f"=== multiple pipe fields ===")
    parsed = read_text_quipu(h, b)
    assert parsed["title"]  == "Title"
    assert parsed["fields"] == ["Title", "EXTRA"]
    print(f"  fields: {parsed['fields']!r}")
    print(f"  ✓ extra fields surfaced")
    print()


def _selftest_affection():
    # Round-trip a Mi-Perrito-style affection-toned inscription
    h, b = build_text_quipu("Mi Perrito", "mi perrito\nque bravo es el cuerpo",
                            tone=TONE_AFFECTION)
    print(f"=== affection tone (0x01) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    assert h == b"\xc1\xdd\x00\x01\x00\x01|Mi Perrito|"
    parsed = read_text_quipu(h, b)
    assert parsed["tone"] == TONE_AFFECTION
    print(f"  ✓ round-trip OK; byte-identical to the on-chain pair inscriptions")
    print()


def _selftest_validation():
    cases = [
        ("title with pipe",
         lambda: build_text_quipu("a|b", "body"),
         "field-separator"),
        ("invalid tone",
         lambda: build_text_quipu("t", "body", tone=0x42),
         "tone"),
        ("body not str/bytes",
         lambda: build_text_quipu("t", 12345),
         "body must be"),
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
    _selftest_basic()
    _selftest_reverence_unicode()
    _selftest_affection()
    _selftest_empty_title()
    _selftest_multifield()
    _selftest_validation()
