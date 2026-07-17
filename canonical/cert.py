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
    <tone:1>                        00 ordinary, 01 affection, 0d demonic, ff reverence
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

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

SUBTYPE_HASH       = 0x0001   # |HASH_ALGO|<hash_hex>  +  Field:value body
SUBTYPE_ALLINONE   = 0x0002   # |TITLE|  +  Field: value body
SUBTYPE_SALE_OFFER = 0x0003   # |TITLE| + attestation fields + Signers: + Signatures:
_VALID_SUBTYPES = (SUBTYPE_HASH, SUBTYPE_ALLINONE, SUBTYPE_SALE_OFFER)

# Tolerant Field/Value line matcher: optional whitespace around the colon
_FIELD_LINE_RE = re.compile(r"^([^:\s][^:]*?)\s*:\s*(.*)$", re.MULTILINE)


def _build_structural_header(tone, subtype):
    validate_tone(tone)
    if subtype not in _VALID_SUBTYPES:
        raise ValueError(
            f"subtype must be 0x0001 (hash), 0x0002 (all-in-one), or "
            f"0x0003 (sale offer); got {subtype:#06x}"
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
# Sale-offer cert (subtype 0x0003) — verified-key sale construction
# ---------------------------------------------------------------------------
# Body shape:
#
#     |Title|
#     Box: <<txid>>
#     SessionPubkey: <hex>
#     BondAddress: <P2SH>
#     RedeemScript: <hex>
#     Price: <satoshi int>
#     RefundHeight: <block height int>
#     RefundPubkey: <hex>
#     SellerPubkey: <hex>
#     ClaimTxSighash: <hex>             ← the message the adaptor signs
#     AdaptorR:    <33B hex>            ← R = k·G
#     AdaptorRa:   <33B hex>            ← R_a = k·T
#     AdaptorSa:   <hex>                ← s_a = k⁻¹(H(m) + r·d)
#     AdaptorDleqC: <hex>               ← DLEQ challenge
#     AdaptorDleqZ: <hex>               ← DLEQ response
#     [PlaintextHash: <hex>]            ← optional belt-and-suspenders
#
#     Signers:
#     seller | <hex pubkey>
#     [<role> | <hex pubkey>]*
#
#     Signatures:
#     seller | <hex sig>
#     [<role> | <hex sig>]*
#
# The canonical hash range (what the seller signs) is:
#     SHA256(body_bytes from byte 0 through the byte immediately preceding
#            the b"Signatures:\n" sentinel, LF-normalized line endings).
#
# The Signers block IS inside the hashed range — so adding/removing/reordering
# signers invalidates every signature. The Signatures block is NOT inside.

_SALE_REQUIRED_FIELDS = (
    "Box", "SessionPubkey", "BondAddress", "RedeemScript",
    "Price", "RefundHeight", "RefundPubkey", "SellerPubkey",
    "ClaimTxSighash",
    "AdaptorR", "AdaptorRa", "AdaptorSa", "AdaptorDleqC", "AdaptorDleqZ",
)

_SIGNATURES_SENTINEL = "Signatures:"
_SIGNERS_HEADER      = "Signers:"


def _serialize_signer_block(rows):
    """Encode [(role, hexstr), ...] as `role | hexstr` lines."""
    lines = []
    for role, value in rows:
        if not isinstance(role, str) or not isinstance(value, str):
            raise TypeError(f"signer row: role and value must be str, got {role!r}/{value!r}")
        if "|" in role or "|" in value:
            raise ValueError(f"signer row {role!r}: '|' is the column separator, forbidden in values")
        if "\n" in role or "\n" in value:
            raise ValueError(f"signer row {role!r}: newline forbidden in values")
        lines.append(f"{role} | {value}")
    return "\n".join(lines)


def build_sale_offer_cert(title, *, box_txid, session_pubkey_hex,
                          bond_address, redeem_script_hex,
                          price_sats, refund_height, refund_pubkey_hex,
                          seller_pubkey_hex,
                          claim_tx_sighash_hex,
                          adaptor_presig,
                          signers, signatures=None,
                          plaintext_hash_hex=None,
                          tone=TONE_ORDINARY):
    """Build a 0xcc subtype 0x0003 sale-offer cert.

    Args:
        title:                short offer title (no '|')
        box_txid:             64-hex root txid of the 0x0e 0xcb box being sold
        session_pubkey_hex:   33B compressed hex of the box's session pubkey T
        bond_address:         P2SH address holding the HTLC bond
        redeem_script_hex:    full redeem script bytes, hex
        price_sats:           integer satoshi amount the buyer pays
        refund_height:        block height after which buyer may refund
        refund_pubkey_hex:    33B compressed hex of the refund-leg pubkey
        seller_pubkey_hex:    33B compressed hex of the seller's identity pubkey
        claim_tx_sighash_hex: 64-hex of the sighash the adaptor signs over
        adaptor_presig:       dict from canonical.adaptor.pre_sign — must
                              contain 'R', 'R_a', 's_a', 'dleq_c', 'dleq_z'
        signers:              list of (role_str, pubkey_hex_str) tuples;
                              MUST include ('seller', seller_pubkey_hex);
                              role names must be unique within the cert
        signatures:           optional list of (role_str, sig_hex_str) tuples.
                              May be empty/None — the cert can be inscribed
                              with no signatures and amended later.
        plaintext_hash_hex:   optional 64-hex SHA256(inner plaintext) for
                              belt-and-suspenders post-hoc plaintext binding
        tone:                 outer tone byte

    Returns:
        (header_bytes, body_bytes)
    """
    if "|" in title:
        raise ValueError("title cannot contain '|'")
    if not isinstance(price_sats, int) or price_sats < 0:
        raise ValueError(f"price_sats must be a non-negative int, got {price_sats!r}")
    if not isinstance(refund_height, int) or refund_height < 0:
        raise ValueError(f"refund_height must be a non-negative int, got {refund_height!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", box_txid):
        raise ValueError(f"box_txid must be 64 hex chars, got {box_txid!r}")
    for name, val in (("session_pubkey_hex", session_pubkey_hex),
                      ("refund_pubkey_hex", refund_pubkey_hex),
                      ("seller_pubkey_hex", seller_pubkey_hex)):
        if not re.fullmatch(r"[0-9a-fA-F]{66}", val):
            raise ValueError(f"{name} must be 66 hex chars (33B compressed), got {val!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", claim_tx_sighash_hex):
        raise ValueError(f"claim_tx_sighash_hex must be 64 hex chars, got {claim_tx_sighash_hex!r}")
    if not re.fullmatch(r"[0-9a-fA-F]+", redeem_script_hex):
        raise ValueError("redeem_script_hex must be hex")
    for k in ("R", "R_a", "s_a", "dleq_c", "dleq_z"):
        if k not in adaptor_presig:
            raise ValueError(f"adaptor_presig missing field {k!r}")
    if plaintext_hash_hex is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", plaintext_hash_hex):
            raise ValueError("plaintext_hash_hex must be 64 hex chars")

    # Signer roles must be unique; 'seller' is mandatory; its pubkey must
    # match the SellerPubkey field
    seen_roles = set()
    seller_signer_pub = None
    for role, pub in signers:
        if role in seen_roles:
            raise ValueError(f"duplicate signer role {role!r}")
        seen_roles.add(role)
        if role == "seller":
            seller_signer_pub = pub
    if seller_signer_pub is None:
        raise ValueError("signers must include ('seller', <SellerPubkey>)")
    if seller_signer_pub.lower() != seller_pubkey_hex.lower():
        raise ValueError("Signers.seller pubkey does not match SellerPubkey field")

    if signatures:
        sig_roles = set()
        for role, _ in signatures:
            if role in sig_roles:
                raise ValueError(f"duplicate signature role {role!r}")
            sig_roles.add(role)
            if role not in seen_roles:
                raise ValueError(f"signature role {role!r} is not in the Signers block")

    # Build body
    header = _build_structural_header(tone, SUBTYPE_SALE_OFFER)
    lines = [f"|{title}|"]
    lines.append(f"Box: <<{box_txid.lower()}>>")
    lines.append(f"SessionPubkey: {session_pubkey_hex.lower()}")
    lines.append(f"BondAddress: {bond_address}")
    lines.append(f"RedeemScript: {redeem_script_hex.lower()}")
    lines.append(f"Price: {price_sats}")
    lines.append(f"RefundHeight: {refund_height}")
    lines.append(f"RefundPubkey: {refund_pubkey_hex.lower()}")
    lines.append(f"SellerPubkey: {seller_pubkey_hex.lower()}")
    lines.append(f"ClaimTxSighash: {claim_tx_sighash_hex.lower()}")
    lines.append(f"AdaptorR: {adaptor_presig['R'].lower()}")
    lines.append(f"AdaptorRa: {adaptor_presig['R_a'].lower()}")
    # s_a / dleq values are hex strings possibly prefixed with '0x'; normalize
    def _strip0x(s):
        s = s.lower()
        return s[2:] if s.startswith("0x") else s
    lines.append(f"AdaptorSa: {_strip0x(adaptor_presig['s_a'])}")
    lines.append(f"AdaptorDleqC: {_strip0x(adaptor_presig['dleq_c'])}")
    lines.append(f"AdaptorDleqZ: {_strip0x(adaptor_presig['dleq_z'])}")
    if plaintext_hash_hex is not None:
        lines.append(f"PlaintextHash: {plaintext_hash_hex.lower()}")
    lines.append("")
    lines.append(_SIGNERS_HEADER)
    lines.append(_serialize_signer_block(signers))
    lines.append("")
    lines.append(_SIGNATURES_SENTINEL)
    if signatures:
        lines.append(_serialize_signer_block(signatures))

    body = ("\n".join(lines)).encode("utf-8")
    return header, body


def canonical_hash_of_sale_offer(body_bytes):
    """Compute SHA256 of the offer's body up to (but NOT including) the
    `Signatures:\\n` sentinel line, with LF-normalized line endings.

    This is the hash each signer signs. Callers compute it both at build
    time (to produce signatures) and at read time (to verify signatures).
    """
    import hashlib
    text = bytes(body_bytes).decode("utf-8", errors="replace").replace("\r\n", "\n")
    sentinel = _SIGNATURES_SENTINEL + "\n"
    idx = text.find(sentinel)
    if idx < 0:
        # End-of-body sentinel (no trailing newline)
        idx_eof = text.rfind(_SIGNATURES_SENTINEL)
        if idx_eof < 0:
            raise ValueError("sale-offer body has no `Signatures:` sentinel")
        idx = idx_eof
    canonical_bytes = text[:idx].encode("utf-8")
    return hashlib.sha256(canonical_bytes).digest()


def read_sale_offer_cert(header_bytes, body_bytes):
    """Parse a 0xcc subtype 0x0003 sale-offer cert into a structured dict.

    Returns:
        dict with keys:
          'title', 'tone',
          'box_txid', 'session_pubkey', 'bond_address', 'redeem_script',
          'price_sats', 'refund_height', 'refund_pubkey', 'seller_pubkey',
          'claim_tx_sighash',
          'adaptor_presig'  : dict with R, R_a, s_a, dleq_c, dleq_z
          'plaintext_hash'  : str or None
          'signers'         : list of (role, pubkey_hex) tuples (insertion order)
          'signatures'      : list of (role, sig_hex) tuples (insertion order)
          'canonical_hash'  : 32-byte SHA256 the signatures sign over
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 8:
        raise ValueError(f"header too short: {len(header_bytes)}")
    if header_bytes[4] != TYPE_CERT:
        raise ValueError(f"not a cert (type 0x{header_bytes[4]:02x})")
    subtype = struct.unpack(">H", header_bytes[6:8])[0]
    if subtype != SUBTYPE_SALE_OFFER:
        raise ValueError(f"not a sale-offer cert (subtype 0x{subtype:04x})")

    tone = header_bytes[5]
    text = bytes(body_bytes).decode("utf-8").replace("\r\n", "\n")

    # Parse title
    m = re.match(r"^\|([^|]*)\|", text)
    if not m:
        raise ValueError("body does not start with |TITLE|")
    title = m.group(1).strip()
    cursor = m.end()

    # Split the body into three sections: fields, signers, signatures
    signers_idx = text.find("\n" + _SIGNERS_HEADER, cursor)
    sigs_idx    = text.find("\n" + _SIGNATURES_SENTINEL, cursor)
    if signers_idx < 0:
        raise ValueError("body missing `Signers:` block")
    if sigs_idx < 0 or sigs_idx < signers_idx:
        raise ValueError("body missing or misplaced `Signatures:` block")

    fields_section  = text[cursor:signers_idx]
    signers_section = text[signers_idx + len("\n" + _SIGNERS_HEADER):sigs_idx]
    sigs_section    = text[sigs_idx + len("\n" + _SIGNATURES_SENTINEL):]

    # Extract Field: value pairs from fields_section
    fields = {}
    for m in _FIELD_LINE_RE.finditer(fields_section.lstrip()):
        name = m.group(1).strip()
        value = m.group(2).strip()
        fields[name] = value

    # Required fields
    for k in _SALE_REQUIRED_FIELDS:
        if k not in fields:
            raise ValueError(f"required field {k!r} missing")

    # Box: extract txid from <<txid>>
    box_match = re.match(r"^<<([0-9a-fA-F]{64})>>$", fields["Box"])
    if not box_match:
        raise ValueError(f"Box field malformed: {fields['Box']!r}")
    box_txid = box_match.group(1).lower()

    adaptor = {
        "R":      fields["AdaptorR"].lower(),
        "R_a":    fields["AdaptorRa"].lower(),
        "s_a":    fields["AdaptorSa"].lower(),
        "dleq_c": fields["AdaptorDleqC"].lower(),
        "dleq_z": fields["AdaptorDleqZ"].lower(),
    }

    # Parse signers / signatures rows (role | value)
    def _parse_rows(section):
        rows = []
        for line in section.strip("\n").split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                raise ValueError(f"malformed row (expected `role | value`): {line!r}")
            role = parts[0].strip()
            val  = parts[1].strip()
            rows.append((role, val))
        return rows

    signers    = _parse_rows(signers_section)
    signatures = _parse_rows(sigs_section)

    canonical_hash = canonical_hash_of_sale_offer(body_bytes)

    return {
        "title":            title,
        "tone":             tone,
        "subtype":          SUBTYPE_SALE_OFFER,
        "subtype_name":     "sale_offer",
        "box_txid":         box_txid,
        "session_pubkey":   fields["SessionPubkey"].lower(),
        "bond_address":     fields["BondAddress"],
        "redeem_script":    fields["RedeemScript"].lower(),
        "price_sats":       int(fields["Price"]),
        "refund_height":    int(fields["RefundHeight"]),
        "refund_pubkey":    fields["RefundPubkey"].lower(),
        "seller_pubkey":    fields["SellerPubkey"].lower(),
        "claim_tx_sighash": fields["ClaimTxSighash"].lower(),
        "adaptor_presig":   adaptor,
        "plaintext_hash":   fields.get("PlaintextHash", "").lower() or None,
        "signers":          signers,
        "signatures":       signatures,
        "canonical_hash":   canonical_hash,
    }


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_cert(header_bytes, body_bytes):
    """Parse a 0xcc certificate quipu.

    Dispatches on the subtype field. Returns a dict shaped to the subtype:

    Common keys (always present):
        'tone':         int (0x00 / 0x01 / 0x0d / 0xff)
        'subtype':      int (0x0001, 0x0002, or 0x0003)
        'subtype_name': str ('hash', 'allinone', or 'saleoffer')
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
            f"(known: 0x0001 hash, 0x0002 allinone, 0x0003 sale_offer)"
        )

    # Sale-offer (0x0003) has a structured body that doesn't fit the
    # pipe-fields + Field:value shape of 0x0001/0x0002. Delegate.
    if subtype == SUBTYPE_SALE_OFFER:
        return read_sale_offer_cert(header_bytes, body_bytes)

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
        # the first pipe field doubles as the title slot — AUGURY reads the
        # 1ec0… node as 'the header title reads |SHA256|3370…1ba0'
        parsed["title"]       = parsed["hash_algo"]
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


def _selftest_sale_offer():
    """0xcc 0x0003 sale-offer cert: build, parse, verify canonical-hash stability."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import hashlib
    import adaptor
    from coincurve import PrivateKey

    # Fake but well-formed inputs
    seller = PrivateKey(b"\x11" * 32)
    session = PrivateKey(b"\x22" * 32)
    refund_pub = PrivateKey(b"\x33" * 32).public_key.format(compressed=True).hex()

    # Build a realistic sighash and adaptor pre-sig
    claim_sighash = hashlib.sha256(b"claim tx sighash bytes go here").digest()
    presig = adaptor.pre_sign(
        seller.secret, claim_sighash,
        session.public_key.format(compressed=True),
    )

    box_txid = "7f3e2a91" + "00" * 28
    h, b = build_sale_offer_cert(
        title="On Custody — Preview Sale",
        box_txid=box_txid,
        session_pubkey_hex=session.public_key.format(compressed=True).hex(),
        bond_address="A5K2gVPlaceholderBondAddress",
        redeem_script_hex="63a8200" + "0" * 63 + "88",
        price_sats=500_000_000,
        refund_height=6_213_157,
        refund_pubkey_hex=refund_pub,
        seller_pubkey_hex=seller.public_key.format(compressed=True).hex(),
        claim_tx_sighash_hex=claim_sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller.public_key.format(compressed=True).hex())],
        signatures=None,  # to be added after computing canonical hash
        plaintext_hash_hex="a" * 64,
        tone=TONE_ORDINARY,
    )
    print("=== sale-offer cert (subtype 0x0003) ===")
    print(f"  header bytes ({len(h)} B): {h.hex()}")
    print(f"  body length: {len(b)} B")
    assert h[4] == TYPE_CERT
    assert struct.unpack(">H", h[6:8])[0] == SUBTYPE_SALE_OFFER
    print(f"  ✓ structural header has subtype 0x0003")

    # Compute canonical hash; should match a re-build with same inputs
    canonical = canonical_hash_of_sale_offer(b)
    assert len(canonical) == 32
    print(f"  canonical hash: {canonical.hex()[:20]}...")

    # Parse
    parsed = read_sale_offer_cert(h, b)
    assert parsed["title"] == "On Custody — Preview Sale"
    assert parsed["box_txid"] == box_txid
    assert parsed["price_sats"] == 500_000_000
    assert parsed["refund_height"] == 6_213_157
    assert parsed["adaptor_presig"]["R"] == presig["R"].lower()
    assert parsed["plaintext_hash"] == "a" * 64
    assert parsed["signers"] == [("seller", seller.public_key.format(compressed=True).hex())]
    assert parsed["signatures"] == []
    assert parsed["canonical_hash"] == canonical
    print(f"  ✓ roundtrip preserves all fields; adaptor pre-sig recovered")

    # Adaptor pre-sig from the parsed cert should verify
    assert adaptor.pre_verify(
        bytes.fromhex(parsed["seller_pubkey"]),
        bytes.fromhex(parsed["claim_tx_sighash"]),
        bytes.fromhex(parsed["session_pubkey"]),
        parsed["adaptor_presig"],
    )
    print(f"  ✓ adaptor pre-sig recovered from cert verifies against signer's pubkey")

    # Now produce a signature over canonical_hash, rebuild with signatures, re-parse
    sig = seller.sign(canonical, hasher=None).hex()
    h2, b2 = build_sale_offer_cert(
        title="On Custody — Preview Sale",
        box_txid=box_txid,
        session_pubkey_hex=session.public_key.format(compressed=True).hex(),
        bond_address="A5K2gVPlaceholderBondAddress",
        redeem_script_hex="63a8200" + "0" * 63 + "88",
        price_sats=500_000_000,
        refund_height=6_213_157,
        refund_pubkey_hex=refund_pub,
        seller_pubkey_hex=seller.public_key.format(compressed=True).hex(),
        claim_tx_sighash_hex=claim_sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller.public_key.format(compressed=True).hex())],
        signatures=[("seller", sig)],
        plaintext_hash_hex="a" * 64,
        tone=TONE_ORDINARY,
    )
    canonical_2 = canonical_hash_of_sale_offer(b2)
    assert canonical_2 == canonical, \
        "canonical hash CHANGED after adding signatures (adding sigs MUST NOT change the hashed range)"
    print(f"  ✓ canonical hash is stable: signature block addition does not change it")

    parsed_2 = read_sale_offer_cert(h2, b2)
    assert parsed_2["signatures"] == [("seller", sig)]
    print(f"  ✓ signature recovered after re-parse")

    # Verify the signature against the canonical hash
    assert seller.public_key.verify(bytes.fromhex(sig), canonical, hasher=None)
    print(f"  ✓ seller's signature verifies under SellerPubkey over canonical hash")

    # Tamper check: changing a field in the Signers block invalidates the hash
    tampered_body = b2.replace(b"seller |", b"buyer  |", 1)
    if tampered_body != b2:
        canonical_tampered = canonical_hash_of_sale_offer(tampered_body)
        assert canonical_tampered != canonical, \
            "tampering Signers block did not change canonical hash"
        print(f"  ✓ tampering the Signers block produces a different canonical hash")
    print()


if __name__ == "__main__":
    _selftest_build_hash_cert()
    _selftest_build_allinone_cert()
    _selftest_parse_maier_onchain()
    _selftest_parse_domremy_onchain()
    _selftest_sale_offer()
    _selftest_validation()
