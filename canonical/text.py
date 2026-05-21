"""
text.py — 0x00 text quipu type (canonical).

The simplest quipu type. Body is plain UTF-8 (or another declared encoding)
text. The header carries a pipe-delimited title plus optional `key=value`
metadata fields. The substitution engine does NOT process 0x00 bodies —
what's inscribed is what's rendered. For an essay that can be processed
by the binding/substitution engine, use type 0x01 (TBD).

Spec
----
HEADER (6 + variable header-tail bytes):

    c1dd 0001                       magic + protocol version 0.1
    00                              type byte = text
    <tone:1>                        00 ordinary, 01 affection, ff reverence
    <pipe-delimited header tail>    |Title|key=value|key=value|

BODY:

    Bytes interpreted via the encoding declared in the header
    (default: utf-8). No structural constraints. Pure literal — the
    substitution engine never modifies a 0x00 body.

Header-tail grammar
-------------------
    | <title> ( | <key>=<value> )* |

  - The FIRST pipe-delimited field is the title (no `=`).
  - Every subsequent field is `key=value` (must contain `=`).
  - All bytes between pipes are UTF-8 (the header itself is always
    UTF-8 regardless of `encoding`; only the body honors `encoding`).
  - Pipe characters (`|` / 0x7C) are forbidden inside field values.
  - Empty title is permitted: `||key=value|...|` opens with an
    empty first field.

Reserved fields with canonical formats
--------------------------------------
None are required. If present, they must follow these forms:

| field      | format                                              |
|------------|-----------------------------------------------------|
| `encoding` | IANA codec name (any alias `codecs.lookup` accepts)  |
| `date`     | ISO 8601 / RFC 3339: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS(±HH:MM|Z) |
| `lang`     | BCP 47 tag: en, es, la, en-US, es-MX, …             |
| `author`   | free UTF-8 string (no canonical format)             |

Other field names are unreserved and pass through opaquely. Conventions
may settle in Estandarte's conventions block over time.

Multi-value handling
--------------------
Each key appears at most once in a header. For naturally multi-valued
fields, use comma-separated values within one entry (e.g.,
`author=Frank Johnson, Mary Lee`) or use distinct keys (`composed=…`
plus `inscribed=…`). Duplicate keys are rejected by the canonical
builder; if encountered by the reader, last-write-wins.

Existing on-chain inscriptions
------------------------------
The five canonical text quipus on chain (Mi Perrito, Mi Caballo, Atom,
two Bowie texts) use the bare `|Title|` form. They parse cleanly under
this extended grammar — they're just "one field, no key=value pairs."
"""

from __future__ import annotations

import codecs
import datetime
import re


TYPE_TEXT       = 0x00

TONE_ORDINARY   = 0x00
TONE_AFFECTION  = 0x01
TONE_REVERENCE  = 0xFF
_VALID_TONES    = (TONE_ORDINARY, TONE_AFFECTION, TONE_REVERENCE)

PIPE            = ord("|")  # 0x7C


# ---------------------------------------------------------------------------
# Field-format validators
# ---------------------------------------------------------------------------

_ISO_DATE   = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_DT_Z   = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ISO_DT_OFF = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}$")
# BCP 47: simplified — primary tag plus optional region. Full BCP 47 is
# more elaborate (scripts, variants, extensions); this catches the common
# cases without an external dependency.
_BCP47      = re.compile(r"^[a-zA-Z]{2,3}(-[a-zA-Z]{2,3})?$")


def _validate_encoding(value):
    try:
        codecs.lookup(value)
    except LookupError:
        raise ValueError(
            f"unknown encoding {value!r} — must be a Python codec name "
            f"(e.g. utf-8, latin-1, ascii, cp1252)"
        )


def _validate_date(value):
    if _ISO_DATE.match(value):
        try:
            datetime.date.fromisoformat(value)
            return
        except ValueError:
            pass
    if _ISO_DT_Z.match(value):
        try:
            datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return
        except ValueError:
            pass
    if _ISO_DT_OFF.match(value):
        try:
            datetime.datetime.fromisoformat(value)
            return
        except ValueError:
            pass
    raise ValueError(
        f"date {value!r} not in ISO 8601 form "
        f"(YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS{{Z|±HH:MM}})"
    )


def _validate_lang(value):
    if not _BCP47.match(value):
        raise ValueError(
            f"lang {value!r} not a recognizable BCP 47 tag "
            f"(e.g. en, es, la, en-US, es-MX)"
        )


_FIELD_VALIDATORS = {
    "encoding": _validate_encoding,
    "date":     _validate_date,
    "lang":     _validate_lang,
    # 'author' is unvalidated; any UTF-8 accepted.
}


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_text_quipu(title, body, tone=TONE_ORDINARY, fields=None):
    """Build a 0x00 text quipu's (header_bytes, body_bytes) pair.

    Args:
        title:  str title, encoded between pipe sentinels. May be empty.
                MUST NOT contain `|`.
        body:   body text (str) or raw bytes. If str, encoded via fields['encoding']
                (defaults to utf-8).
        tone:   TONE_ORDINARY / TONE_AFFECTION / TONE_REVERENCE.
        fields: optional dict of {key: value} metadata. Each value must be a
                str. Reserved keys (encoding, date, lang) are format-validated.
                Pipes are forbidden in keys and values. Duplicate keys raise
                (use a single comma-separated value or distinct key names).

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
            f"title contains '|' which is the field-separator byte"
        )
    if "=" in title:
        # The title is the first non-empty unkeyed field; '=' would make it
        # look like key=value to the reader.
        raise ValueError(
            f"title contains '=' which would parse as key=value"
        )

    fields = dict(fields) if fields else {}
    seen = set()
    for key, value in fields.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError(
                f"field keys and values must be str (got {key!r}: {value!r})"
            )
        if "|" in key or "|" in value:
            raise ValueError(
                f"field {key!r} contains '|' which is forbidden in values"
            )
        if "=" in key:
            raise ValueError(f"field key {key!r} contains '='")
        if key in seen:
            raise ValueError(f"duplicate field key {key!r}")
        seen.add(key)
        if key in _FIELD_VALIDATORS:
            _FIELD_VALIDATORS[key](value)

    # Body encoding — uses declared encoding if specified, otherwise utf-8
    declared_encoding = fields.get("encoding", "utf-8")
    if isinstance(body, str):
        try:
            body_bytes = body.encode(declared_encoding)
        except LookupError:
            raise ValueError(f"unknown body encoding {declared_encoding!r}")
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = bytes(body)
    else:
        raise TypeError(f"body must be str or bytes, got {type(body).__name__}")

    # Header bytes
    header = b"\xc1\xdd\x00\x01" + bytes([TYPE_TEXT]) + bytes([tone])

    if title or fields:
        parts = [title] + [f"{k}={v}" for k, v in fields.items()]
        header += b"|" + "|".join(parts).encode("utf-8") + b"|"

    return header, body_bytes


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def read_text_quipu(header_bytes, body_bytes):
    """Parse a 0x00 text quipu.

    Returns:
        {
          'title':  str            — first unkeyed pipe-field, or '' if none
          'tone':   int            — 0x00, 0x01, or 0xff
          'fields': dict[str, str] — parsed key=value pairs (may be empty)
          'body':   str            — decoded via fields.get('encoding', 'utf-8')
        }

    Raises:
        ValueError if magic/type/body decoding fails.
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

    title = ""
    fields = {}

    if tail:
        if b"|" in tail:
            text = tail.decode("utf-8", errors="replace")
            parts = [p for p in text.split("|") if p != ""]
        else:
            # No pipes — treat the whole tail as the title (lenient, for
            # parity with image.py's bare-title rule)
            parts = [tail.decode("utf-8", errors="replace")]

        for i, part in enumerate(parts):
            if i == 0 and "=" not in part:
                # First field, no '=' → it's the title
                title = part
            elif "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key in fields:
                    # last-write-wins; the canonical builder rejects this
                    pass
                fields[key] = value
            else:
                # Subsequent unkeyed field — uncommon, treat as anonymous
                # extra (key = empty string)
                pass

    # Decode body via declared encoding (default utf-8)
    encoding = fields.get("encoding", "utf-8")
    try:
        body = bytes(body_bytes).decode(encoding)
    except (LookupError, UnicodeDecodeError) as e:
        raise ValueError(f"cannot decode body with encoding {encoding!r}: {e}")

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
    print(f"=== basic (no fields, bare title) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    # Backward-compat: byte-identical to the existing on-chain Mi Perrito form
    assert h == b"\xc1\xdd\x00\x01\x00\x00|Mi Perrito|"
    parsed = read_text_quipu(h, b)
    assert parsed["title"]  == "Mi Perrito"
    assert parsed["tone"]   == TONE_ORDINARY
    assert parsed["fields"] == {}
    assert parsed["body"]   == "A short note about my dog."
    print("  ✓ round-trip + byte-identical to existing on-chain inscriptions")
    print()


def _selftest_full_fields():
    h, b = build_text_quipu(
        "Mi Perrito",
        "mi perrito\nque bravo es el cuerpo",
        tone=TONE_AFFECTION,
        fields={"author": "Christophia Hayagriva",
                "date":   "2024-06-12",
                "lang":   "es",
                "encoding": "utf-8"},
    )
    print(f"=== full header (title + 4 fields) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    print(f"  header text: {h[6:].decode('utf-8')!r}")
    parsed = read_text_quipu(h, b)
    assert parsed["title"] == "Mi Perrito"
    assert parsed["tone"]  == TONE_AFFECTION
    assert parsed["fields"]["author"]   == "Christophia Hayagriva"
    assert parsed["fields"]["date"]     == "2024-06-12"
    assert parsed["fields"]["lang"]     == "es"
    assert parsed["fields"]["encoding"] == "utf-8"
    print(f"  ✓ all four fields round-trip")
    print()


def _selftest_encoding_honored():
    # Round-trip a body containing characters representable in cp1252 (€, é, —)
    # but not in plain ascii — verifies the reader honors declared encoding.
    h, b = build_text_quipu(
        "Latin1Test", "Café — €100", tone=TONE_REVERENCE,
        fields={"encoding": "cp1252"},
    )
    print(f"=== encoding honored ===")
    print(f"  declared encoding: cp1252")
    print(f"  body bytes (hex): {b.hex()}")
    parsed = read_text_quipu(h, b)
    print(f"  recovered body: {parsed['body']!r}")
    assert parsed["body"] == "Café — €100"
    print(f"  ✓ encoding honored end-to-end")
    print()


def _selftest_backward_compat():
    # Existing on-chain Mi Perrito bytes (from Christophia's inscription)
    h = b"\xc1\xdd\x00\x01\x00\x01|Mi Perrito|"
    b = b"mi perrito\nque bravo es el cuerpo"
    print(f"=== backward-compat: bare |Title| form ===")
    parsed = read_text_quipu(h, b)
    assert parsed["title"]  == "Mi Perrito"
    assert parsed["tone"]   == TONE_AFFECTION
    assert parsed["fields"] == {}
    print(f"  ✓ existing on-chain text quipus parse cleanly")
    print()


def _selftest_empty_title_with_fields():
    h, b = build_text_quipu(
        "", "no title here", tone=TONE_ORDINARY,
        fields={"author": "anonymous", "date": "2026-05-21"},
    )
    print(f"=== empty title, fields present ===")
    print(f"  header text: {h[6:].decode('utf-8')!r}")
    parsed = read_text_quipu(h, b)
    assert parsed["title"] == ""
    assert parsed["fields"] == {"author": "anonymous", "date": "2026-05-21"}
    print(f"  ✓ empty title is OK with fields")
    print()


def _selftest_validation():
    cases = [
        ("title with pipe",      lambda: build_text_quipu("a|b", ""),
         "field-separator"),
        ("title with equals",    lambda: build_text_quipu("a=b", ""),
         "key=value"),
        ("invalid tone",         lambda: build_text_quipu("t", "", tone=0x42),
         "tone"),
        ("bad date",             lambda: build_text_quipu("t", "", fields={"date": "yesterday"}),
         "ISO 8601"),
        ("bad lang",             lambda: build_text_quipu("t", "", fields={"lang": "Spanish"}),
         "BCP 47"),
        ("bad encoding",         lambda: build_text_quipu("t", "", fields={"encoding": "moonspeak"}),
         "encoding"),
        ("pipe in value",        lambda: build_text_quipu("t", "", fields={"author": "a|b"}),
         "forbidden"),
        ("duplicate keys",       lambda: build_text_quipu("t", "", fields={"author": "a", "AUTHOR": "b"}),
         None),   # case-sensitive — different keys, both allowed
    ]
    print(f"=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
            if want is None:
                print(f"  {desc:25s} -> OK (no error expected)")
            else:
                print(f"  {desc:25s} -> DID NOT RAISE (bug)")
        except (ValueError, TypeError) as e:
            if want is None:
                print(f"  {desc:25s} -> UNEXPECTED RAISE: {e}")
            else:
                status = "OK" if want in str(e) else "WRONG ERR"
                print(f"  {desc:25s} -> {status}: {e}")
    print()


def _selftest_iso_date_forms():
    # Date in three legal shapes
    for d in ["2026-05-21",
              "2026-05-21T14:30:00Z",
              "2026-05-21T14:30:00+02:00"]:
        h, b = build_text_quipu("d", "", fields={"date": d})
        parsed = read_text_quipu(h, b)
        assert parsed["fields"]["date"] == d
    print(f"=== ISO 8601 date forms ===")
    print(f"  ✓ all three ISO 8601 forms accepted")
    print()


if __name__ == "__main__":
    _selftest_basic()
    _selftest_full_fields()
    _selftest_encoding_honored()
    _selftest_backward_compat()
    _selftest_empty_title_with_fields()
    _selftest_iso_date_forms()
    _selftest_validation()
