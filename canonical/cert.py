"""
cert.py — 0xcc certificate quipu type (canonical).

A certificate quipu carries either a cryptographic attestation (hash cert)
or a self-contained attestation document (all-in-one cert). Both share
the same 8-byte structural header; the 2-byte subtype field at offsets
6..7 picks the body shape.

Spec
----
HEADER (8 structural bytes):

    c1dd 0001                       magic + protocol version 0.1
    cc                              type byte = certificate
    <tone:1>                        00 ordinary, 01 affection, ff reverence
    <subtype_hi subtype_lo>         uint16 BE: 0x0001 hash, 0x0002 all-in-one

BODY (varies by subtype):

  Subtype 0x0001 — Hash cert:
    | HASH_ALGO | <hash_hex>          pipe-delimited algorithm name + hash
    Field:value\\n …                  the data being attested to

  Subtype 0x0002 — All-in-one cert:
    | TITLE |                         pipe-delimited title
    Field: value\\n …                 structured attestation content

The body convention is **lenient on `Field:value` separator** — both
`Field:value` (no space) and `Field: value` (with space) appear on chain.
The reader accepts either.

Body conventions
----------------
Hash cert (0x0001) typically declares:
    HASH_ALGO is the hash function name (`SHA256` on chain to date).
    Hash value is the lowercase hex of HASH_ALGO over the canonical
    serialization of the attested content.
    Field/value section carries identifying metadata about the parties
    or content being attested.

All-in-one cert (0x0002) typically declares:
    Title           — short attestation title
    Artist          — creator / signer / responsible party
    Image           — citation to the attested image quipu (<<txid>>)
    CertificateAuthority — citation to an 0x0001 hash cert (<<txid>>)
    Text            — descriptive prose, may span paragraphs

These field names are the prevailing convention. The protocol-level
definition of `0xcc` is just the structural prefix + the pipe-delimited
preamble + UTF-8 body; the field vocabulary is a convention layer that
`essay_renderer.py` and other readers consume.

Examples on chain
-----------------
Maier 3-key declaration (hash cert):
    root: 1ec0ee9b27d6ab91…
    header: c1dd0001 cc ff 00 01
    body:   |SHA256|337095…1ba0  Hayagriva_Public:0x…  Christophia_Public:0x…
            Anthony_Public:0x…   Artist:Laura_Renee_Maier

Domremy bordado certificate (all-in-one cert):
    root: 6da7a9a9d8d651c4…
    header: c1dd0001 cc ff 00 02
    body:   |Domrémy Bordado Certificate|
            Title: Domrémy
            Artist: Ekaterina Sirichinova
            Image: <<b92bbbf974ad7d1b…>>
            CertificateAuthority: <<1ec0ee9b27d6ab91…>>
            Text: Joffrey Bourlémont, French nobleman turned Crusader…
"""

from __future__ import annotations

import re
import struct


TYPE_CERT          = 0xCC

TONE_ORDINARY      = 0x00
TONE_AFFECTION     = 0x01
TONE_REVERENCE     = 0xFF
_VALID_TONES = (TONE_ORDINARY, TONE_AFFECTION, TONE_REVERENCE)

SUBTYPE_HASH       = 0x0001   # |HASH_ALGO|<hash_hex>  +  Field:value body
SUBTYPE_ALLINONE   = 0x0002   # |TITLE|  +  Field: value body
_VALID_SUBTYPES = (SUBTYPE_HASH, SUBTYPE_ALLINONE)

# Tolerant Field/Value line matcher: optional whitespace around the colon
_FIELD_LINE_RE = re.compile(r"^([^:\s][^:]*?)\s*:\s*(.*)$", re.MULTILINE)


def _build_structural_header(tone, subtype):
    if tone not in _VALID_TONES:
        raise ValueError(
            f"tone must be 0x00, 0x01, or 0xff (got {tone:#04x})"
        )
    if subtype not in _VALID_SUBTYPES:
        raise ValueError(
            f"subtype must be 0x0001 (hash) or 0x0002 (all-in-one); "
            f"got {subtype:#06x}"
        )
    return (
        b"\xc1\xdd\x00\x01"
        + bytes([TYPE_CERT, tone])
        + struct.pack(">H", subtype)
    )


def _serialize_fields(fields, separator):
    """Encode an ordered list of (name, value) pairs as UTF-8 Field<sep>value\\n lines."""
    if isinstance(fields, dict):
        items = list(fields.items())
    else:
        items = list(fields)
    out = bytearray()
    for i, (name, value) in enumerate(items):
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError(
                f"field {i}: name and value must be str, "
                f"got {type(name).__name__}/{type(value).__name__}"
            )
        if "\n" in name or ":" in name:
            raise ValueError(f"field name {name!r} cannot contain newline or colon")
        if "\n" in value:
            raise ValueError(f"field {name!r} value contains newline")
        out += (name + separator + value).encode("utf-8")
        if i < len(items) - 1:
            out += b"\n"
    return bytes(out)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_hash_cert(hash_algo, hash_hex, fields=None, tone=TONE_REVERENCE,
                    field_separator=":"):
    """Build a 0xcc subtype 0x0001 hash certificate.

    Args:
        hash_algo:        name of the hash function (e.g. 'SHA256').
        hash_hex:         lowercase hex digest of HASH_ALGO over the canonical
                          serialization of the attested content.
        fields:           ordered list of (name, value) tuples or a dict;
                          identifying metadata about parties / content.
                          May be empty / None.
        tone:             tone byte (default reverence — matches Maier on chain).
        field_separator:  ':' (default, no space — matches Maier on chain) or
                          ': ' (with space — matches Domremy all-in-one convention).

    Returns:
        (header_bytes, body_bytes) where header_bytes is the 8-byte structural
        prefix and body_bytes is `|HASH_ALGO|<hash_hex>` plus optional
        Field<sep>value lines.
    """
    if "|" in hash_algo:
        raise ValueError("hash_algo cannot contain '|'")
    if not re.fullmatch(r"[0-9a-fA-F]+", hash_hex):
        raise ValueError(f"hash_hex must be hex digits; got {hash_hex!r}")

    header = _build_structural_header(tone, SUBTYPE_HASH)

    body = b"|" + hash_algo.encode("utf-8") + b"|" + hash_hex.lower().encode("utf-8")
    if fields:
        body += b"\n" + _serialize_fields(fields, field_separator)
    return header, body


def build_allinone_cert(title, fields, tone=TONE_REVERENCE, field_separator=": "):
    """Build a 0xcc subtype 0x0002 all-in-one certificate.

    Args:
        title:            short attestation title, no '|' allowed.
        fields:           ordered list of (name, value) tuples or a dict;
                          the structured attestation content.
                          Recommended fields: Title, Artist, Image,
                          CertificateAuthority, Text.
        tone:             tone byte (default reverence — matches Domremy on chain).
        field_separator:  ': ' (default, with space — matches Domremy on chain) or
                          ':' (no space).

    Returns:
        (header_bytes, body_bytes) where header_bytes is the 8-byte structural
        prefix and body_bytes is `|TITLE|` plus Field<sep>value lines.
    """
    if "|" in title:
        raise ValueError("title cannot contain '|'")

    header = _build_structural_header(tone, SUBTYPE_ALLINONE)
    body = b"|" + title.encode("utf-8") + b"|"
    if fields:
        body += b"\n" + _serialize_fields(fields, field_separator)
    return header, body


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_cert(header_bytes, body_bytes):
    """Parse a 0xcc certificate quipu.

    Dispatches on the subtype field. Returns a dict shaped to the subtype:

    Common keys (always present):
        'tone':         int (0x00 / 0x01 / 0xff)
        'subtype':      int (0x0001 or 0x0002)
        'subtype_name': str ('hash' or 'allinone')
        'pipe_fields':  list of non-empty pipe-delimited UTF-8 fields at the
                        start of the body, in order
        'fields':       OrderedDict of Field -> value extracted from the rest
                        of the body (parses both 'Field:value' and 'Field: value')
        'raw_body':     full body bytes as given

    Subtype-specific convenience keys:
        hash    (0x0001): 'hash_algo', 'hash_hex'
        allinone(0x0002): 'title'
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 8:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need ≥ 8)"
        )
    if header_bytes[4] != TYPE_CERT:
        raise ValueError(
            f"not a certificate quipu (type byte = {header_bytes[4]:#04x}, "
            f"expected 0xcc)"
        )

    tone    = header_bytes[5]
    subtype = struct.unpack(">H", header_bytes[6:8])[0]
    if subtype not in _VALID_SUBTYPES:
        raise ValueError(
            f"subtype 0x{subtype:04x} not defined in v1 "
            f"(known: 0x0001 hash, 0x0002 allinone)"
        )
    subtype_name = {SUBTYPE_HASH: "hash", SUBTYPE_ALLINONE: "allinone"}[subtype]

    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"body is not valid UTF-8: {e}")

    parsed = {
        "tone":         tone,
        "subtype":      subtype,
        "subtype_name": subtype_name,
        "raw_body":     bytes(body_bytes),
    }

    # Subtype-specific preamble parsing
    if subtype == SUBTYPE_HASH:
        # body starts with |HASH_ALGO|<hash_hex>  (hash_hex is greedy hex,
        # no closing pipe — runs until any non-hex character).
        m = re.match(r"^\|([^|]+)\|([0-9a-fA-F]+)", body_text)
        if not m:
            raise ValueError(
                "hash cert body doesn't start with |HASH_ALGO|<hash_hex>"
            )
        parsed["hash_algo"]   = m.group(1).strip()
        parsed["hash_hex"]    = m.group(2)
        parsed["pipe_fields"] = [parsed["hash_algo"], parsed["hash_hex"]]
        rest = body_text[m.end():]

    elif subtype == SUBTYPE_ALLINONE:
        # body starts with |TITLE| (then optional padding spaces from cabeza
        # filling, then a newline, then Field: value lines).
        m = re.match(r"^\|([^|]*)\|", body_text)
        if not m:
            raise ValueError(
                "all-in-one cert body doesn't start with |TITLE|"
            )
        parsed["title"]       = m.group(1).strip()
        parsed["pipe_fields"] = [parsed["title"]]
        rest = body_text[m.end():]

    else:
        rest = body_text  # unreachable given subtype validation above

    # Strip leading whitespace (cabeza padding, leading newlines) and scan
    # Field:value lines. Tolerates both Field:value and Field: value spacing.
    fields_dict = {}
    rest_stripped = rest.lstrip()
    for m in _FIELD_LINE_RE.finditer(rest_stripped):
        name, value = m.group(1).strip(), m.group(2).strip()
        if name:
            fields_dict[name] = value
    parsed["fields"] = fields_dict

    return parsed


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _selftest_build_hash_cert():
    h, b = build_hash_cert(
        "SHA256",
        "337095adb739572e5566416637a4e8905f0fda28a804999a3e472b024c5a1ba0",
        fields=[
            ("Hayagriva_Public",   "0xabc"),
            ("Christophia_Public", "0xdef"),
            ("Anthony_Public",     "0x123"),
            ("Artist",             "Laura_Renee_Maier"),
        ],
        tone=TONE_REVERENCE,
        field_separator=":",   # matches Maier on chain
    )
    print(f"=== build hash cert (Maier-shaped) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    assert h == bytes.fromhex("c1dd0001ccff0001")
    parsed = read_cert(h, b)
    assert parsed["subtype"]      == SUBTYPE_HASH
    assert parsed["subtype_name"] == "hash"
    assert parsed["hash_algo"]    == "SHA256"
    assert parsed["hash_hex"]     == "337095adb739572e5566416637a4e8905f0fda28a804999a3e472b024c5a1ba0"
    assert parsed["fields"]["Artist"] == "Laura_Renee_Maier"
    print(f"  ✓ round-trip OK")
    print()


def _selftest_build_allinone_cert():
    h, b = build_allinone_cert(
        "Domrémy Bordado Certificate",
        fields=[
            ("Title",  "Domrémy"),
            ("Artist", "Ekaterina Sirichinova"),
            ("Image",  "<<b92bbbf974ad7d1ba035d03b34ee455dadf4e85c365d841beb4443e55da0b66c>>"),
            ("CertificateAuthority",
             "<<1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c>>"),
            ("Text",   "A short prose body."),
        ],
        tone=TONE_REVERENCE,
        field_separator=": ",   # matches Domremy on chain
    )
    print(f"=== build all-in-one cert (Domremy-shaped) ===")
    print(f"  header ({len(h)} B): {h.hex()}")
    assert h == bytes.fromhex("c1dd0001ccff0002")
    parsed = read_cert(h, b)
    assert parsed["subtype"]      == SUBTYPE_ALLINONE
    assert parsed["subtype_name"] == "allinone"
    assert parsed["title"]        == "Domrémy Bordado Certificate"
    assert parsed["fields"]["Title"]                == "Domrémy"
    assert parsed["fields"]["CertificateAuthority"].startswith("<<1ec0")
    print(f"  ✓ round-trip OK")
    print()


def _selftest_parse_maier_onchain():
    # Bytes copied from the on-chain Maier inscription (root 1ec0ee9b…)
    # cabeza walk = 80 B, but per the canonical spec the structural header
    # is the first 8 bytes; everything else is body.
    full_hex = (
        "c1dd0001ccff0001"
        "7c5348413235367c"   # |SHA256|
        "33333730393561646237333935373265353536363431363633376134653839303566"
        "306664613238613830343939396133653437326230323463356131626130"        # 64-hex hash
    )
    body_extra = (
        "\nHayagriva_Public:0x505d743671977487913280812271df3e8b27126788d03b5dd"
        "84430280b710b20584a8c442082960a67214fba8f45e97c7aeca15a6a59ba98f830dfe"
        "9e487d8cd"
        "\nChristophia_Public:0x6bb329760057768325b73b3420650c0d077790ce78a54a5f"
        "40630a5342d11310b24308716b30b3e86539964f701e4e570ce497b6073c652ab153db"
        "e676b57970"
        "\nAnthony_Public:0xcd477d18b1ed8549fd6d9d576c8378deed4df4a926f0fe8ea9d"
        "bde07a72bb5911bf9a1f380ea24adabff0b91eb5525e4526f22d9ed1e3bcbebe97093d"
        "4871f53"
        "\nArtist:Laura_Renee_Maier"
    ).encode("utf-8")
    full_bytes = bytes.fromhex(full_hex) + body_extra
    header = full_bytes[:8]
    body   = full_bytes[8:]
    parsed = read_cert(header, body)
    print(f"=== parse Maier on-chain hash cert ===")
    print(f"  subtype:      0x{parsed['subtype']:04x} ({parsed['subtype_name']})")
    print(f"  tone:         0x{parsed['tone']:02x}")
    print(f"  hash_algo:    {parsed['hash_algo']}")
    print(f"  hash_hex:     {parsed['hash_hex'][:20]}…")
    print(f"  fields:")
    for k, v in parsed['fields'].items():
        print(f"    {k:22s} = {v[:50]}{'…' if len(v) > 50 else ''}")
    assert parsed["subtype"]   == SUBTYPE_HASH
    assert parsed["tone"]      == TONE_REVERENCE
    assert parsed["hash_algo"] == "SHA256"
    assert parsed["hash_hex"]  == "337095adb739572e5566416637a4e8905f0fda28a804999a3e472b024c5a1ba0"
    assert "Hayagriva_Public"   in parsed["fields"]
    assert "Christophia_Public" in parsed["fields"]
    assert "Anthony_Public"     in parsed["fields"]
    assert parsed["fields"]["Artist"] == "Laura_Renee_Maier"
    print(f"  ✓ on-chain Maier bytes parse correctly")
    print()


def _selftest_parse_domremy_onchain():
    # Domremy cabeza had |TITLE| then padding spaces; body then has Field: value lines.
    # The reader must strip the padding gracefully.
    cabeza_with_padding = (
        bytes.fromhex("c1dd0001ccff0002")
        + b"|Domr\xc3\xa9my Bordado Certificate|"
        + b" " * 42   # padding to fill the 80-byte cabeza OP_RETURN
    )
    body_extra = (
        b"Title: Domr\xc3\xa9my\n"
        b"Artist: Ekaterina Sirichinova\n"
        b"Image: <<b92bbbf974ad7d1ba035d03b34ee455dadf4e85c365d841beb4443e55da0b66c>>\n"
        b"CertificateAuthority: <<1ec0ee9b27d6ab91169b28f3acdada51cab8eb03af8c2a7e128d122a2dba7d0c>>\n"
        b"Text: A short prose body."
    )
    full = cabeza_with_padding + body_extra
    header = full[:8]
    body   = full[8:]
    parsed = read_cert(header, body)
    print(f"=== parse Domremy on-chain all-in-one cert (with cabeza padding) ===")
    print(f"  subtype:    0x{parsed['subtype']:04x} ({parsed['subtype_name']})")
    print(f"  title:      {parsed['title']!r}")
    print(f"  fields:")
    for k, v in parsed['fields'].items():
        print(f"    {k:22s} = {v[:60]}{'…' if len(v) > 60 else ''}")
    assert parsed["subtype"] == SUBTYPE_ALLINONE
    assert parsed["title"]   == "Domrémy Bordado Certificate"
    assert parsed["fields"]["Title"]                == "Domrémy"
    assert parsed["fields"]["Artist"]               == "Ekaterina Sirichinova"
    assert parsed["fields"]["Image"].startswith("<<b92bbbf9")
    assert parsed["fields"]["CertificateAuthority"].startswith("<<1ec0ee9b")
    print(f"  ✓ on-chain Domremy bytes parse correctly (padding tolerated)")
    print()


def _selftest_validation():
    cases = [
        ("invalid tone",
         lambda: build_hash_cert("SHA256", "abc", tone=0x42),
         "tone"),
        ("hash_algo with pipe",
         lambda: build_hash_cert("S|HA", "abc"),
         "hash_algo"),
        ("hash_hex non-hex",
         lambda: build_hash_cert("SHA256", "xyz"),
         "hash_hex"),
        ("title with pipe",
         lambda: build_allinone_cert("a|b", []),
         "title"),
        ("read unknown subtype",
         lambda: read_cert(b"\xc1\xdd\x00\x01\xcc\xff\x00\x09", b""),
         "subtype"),
        ("read wrong type byte",
         lambda: read_cert(b"\xc1\xdd\x00\x01\x03\xff\x00\x01", b""),
         "expected 0xcc"),
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
    _selftest_build_hash_cert()
    _selftest_build_allinone_cert()
    _selftest_parse_maier_onchain()
    _selftest_parse_domremy_onchain()
    _selftest_validation()
