"""
encrypted.py — 0x0e encrypted family (canonical v1, May 2026).

Three sub-families under type byte 0x0e, distinguished by byte 6:

    0e <tone> ae <key_access>     AES wrapper        — key supplied as raw 32-byte
                                                       (key_access=0x00) or password
                                                       (0x01, key = SHA256(passphrase))
    0e <tone> ec 0x00              ECIES broadcast   — N per-recipient ECDH-wrapped
                                                       envelopes around a session key
    0e <tone> 0d 0x00              key drop          — releases an AES/session key
                                                       for a previously sealed target

Header layout (uniform across sub-families):

    offset  bytes        meaning
    0..3    c1 dd 00 01  magic + protocol version 0.1
    4       0e           type byte = encrypted family
    5       <tone>       00 ordinary / 01 affection / 0d demonic / ff reverence
                         (default 00 — opt-in disclosure)
    6       <sub_family> ae | ec | 0d
    7       <variant>    sub-family-specific qualifier
    8..     body         sub-family-specific

Body shapes:

    ae (AES wrapper):
        [|TITLE|]               optional outer-public-facing title
        <ciphertext>            AES-CBC(key, framed_inner)

    ec (ECIES broadcast):
        [|TITLE|]
        <Nrec:1>                number of recipient envelopes (max 255)
        N × <envelope:64>       16 IV + 48 AES-CBC ciphertext of 32-byte session key
        <ciphertext>            AES-CBC(session_key, framed_inner)

    0d (key drop):
        <ref_txid:32>           txid of the target encrypted quipu
        <key:32>                the 256-bit key (AES key or ECIES session key)
        [|TITLE|]               optional outer label

Framed inner (inside ciphertext for ae and ec):

    <header_len:2 uint16 BE>    length of the inner quipu's header
    <inner_header:header_len>   the full inner quipu header (magic c1dd0001 + type + ...)
    <inner_body:rest>           the full inner quipu body

The length prefix replaces the strand-boundary framing that separates header
from body in unencrypted quipus.

Multisig sender (N-of-N): aggregate-key ECDH.
    aggregate_pubkey  = sum of N component pubkeys (point addition on secp256k1)
    aggregate_privkey = sum of N component privkeys mod curve order
    ECDH against the aggregate is the canonical "I am this multisig" operation.

Multisig recipient (N-of-N): per-component envelopes — one envelope per
component pubkey, any cosigner can decrypt with their own privkey.
"""

from __future__ import annotations

import hashlib
import struct
import ecies as _ecies
from coincurve import PrivateKey as CCPriv, PublicKey as CCPub
from coincurve.utils import get_valid_secret
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_ENCRYPTED = 0x0e

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

# Sub-family byte at offset 6
SUB_AES   = 0xAE
SUB_ECIES = 0xEC
SUB_DROP  = 0x0D
_VALID_SUBS = (SUB_AES, SUB_ECIES, SUB_DROP)

# Variant byte at offset 7
KEY_RAW       = 0x00   # for SUB_AES: raw 32-byte key
KEY_PASSWORD  = 0x01   # for SUB_AES: key = SHA256(passphrase)
ECIES_BROADCAST = 0x00 # for SUB_ECIES
DROP_RELEASE  = 0x00   # for SUB_DROP

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
AES_KEY_BYTES_LEN = 32


# ---------------------------------------------------------------------------
# Multisig key aggregation helpers (N-of-N)
# ---------------------------------------------------------------------------

def aggregate_pubkey(component_pubkeys):
    """Sum N component pubkeys (point addition) → single aggregate pubkey.

    Accepts a list of coincurve.PublicKey OR 33/65-byte serialized pubkey bytes.
    Returns a coincurve.PublicKey.
    """
    pubs = []
    for p in component_pubkeys:
        if isinstance(p, CCPub):
            pubs.append(p)
        elif isinstance(p, (bytes, bytearray)):
            pubs.append(CCPub(bytes(p)))
        else:
            raise TypeError(f"unsupported pubkey type {type(p).__name__}")
    return CCPub.combine_keys(pubs)


def aggregate_privkey(component_privkeys):
    """Sum N component privkeys mod curve order → single aggregate privkey.

    Accepts a list of coincurve.PrivateKey OR 32-byte secret bytes.
    Returns a coincurve.PrivateKey.
    """
    s = 0
    for p in component_privkeys:
        if isinstance(p, CCPriv):
            s += int.from_bytes(p.secret, "big")
        elif isinstance(p, (bytes, bytearray)):
            if len(p) != 32:
                raise ValueError(f"privkey bytes must be 32 (got {len(p)})")
            s += int.from_bytes(bytes(p), "big")
        else:
            raise TypeError(f"unsupported privkey type {type(p).__name__}")
    s %= SECP256K1_N
    if s == 0:
        raise ValueError("aggregate privkey is zero (degenerate sum)")
    return CCPriv(s.to_bytes(32, "big"))


def _shared_key(privkey, pubkey):
    """HKDF-derived 32-byte shared secret from ECDH(priv, pub).

    Mirrors colegio_tools.shared_key — same KDF, same output, so v2 envelopes
    interop with the existing ECIES helpers.
    """
    if not isinstance(privkey, CCPriv):
        raise TypeError("privkey must be coincurve.PrivateKey")
    if not isinstance(pubkey, CCPub):
        raise TypeError("pubkey must be coincurve.PublicKey")
    raw = pubkey.multiply(privkey.secret).format()
    return HKDF(raw, AES_KEY_BYTES_LEN, b"", SHA256)


# ---------------------------------------------------------------------------
# Common header/body framing
# ---------------------------------------------------------------------------

def _build_header_prefix(tone, sub_family, variant):
    validate_tone(tone)
    if sub_family not in _VALID_SUBS:
        raise ValueError(f"sub_family must be 0x{SUB_AES:02x}/0x{SUB_ECIES:02x}/0x{SUB_DROP:02x} (got {sub_family:#04x})")
    return MAGIC + bytes([TYPE_ENCRYPTED, tone, sub_family, variant])


def _append_title(prefix, title):
    if title:
        if "|" in title:
            raise ValueError("title cannot contain '|' (field separator)")
        return prefix + b"|" + title.encode("utf-8") + b"|"
    return prefix


def _frame_inner(inner_header, inner_body):
    """Prefix the inner with its 2-byte BE header length."""
    if not isinstance(inner_header, (bytes, bytearray)):
        raise TypeError("inner_header must be bytes")
    if not isinstance(inner_body, (bytes, bytearray)):
        raise TypeError("inner_body must be bytes")
    if inner_header[:4] != MAGIC:
        raise ValueError("inner_header must start with c1dd 0001 magic")
    if len(inner_header) > 0xFFFF:
        raise ValueError(f"inner_header too large ({len(inner_header)} > 65535)")
    return struct.pack(">H", len(inner_header)) + bytes(inner_header) + bytes(inner_body)


def _unframe_inner(framed):
    """Inverse of _frame_inner. Returns (inner_header, inner_body)."""
    if len(framed) < 2:
        raise ValueError("framed inner too short for length prefix")
    hlen = struct.unpack(">H", framed[:2])[0]
    if 2 + hlen > len(framed):
        raise ValueError(f"length prefix says {hlen} but only {len(framed)-2} bytes follow")
    return framed[2:2 + hlen], framed[2 + hlen:]


# ---------------------------------------------------------------------------
# AES wrapper (sub-family 0xae)
# ---------------------------------------------------------------------------

def _aes_key_from(key_or_password):
    """Coerce key_or_password into (key_bytes_32, variant_byte)."""
    if isinstance(key_or_password, (bytes, bytearray)):
        if len(key_or_password) != 32:
            raise ValueError(f"raw AES key must be 32 bytes (got {len(key_or_password)})")
        return bytes(key_or_password), KEY_RAW
    if isinstance(key_or_password, str):
        return hashlib.sha256(key_or_password.encode("utf-8")).digest(), KEY_PASSWORD
    raise TypeError("key must be 32 bytes or a passphrase string")


def build_aes_quipu(inner_header, inner_body, key, *, title="", tone=TONE_ORDINARY):
    """Build a 0e ae AES-wrapped encrypted quipu.

    Args:
        inner_header, inner_body: the bytes of the plaintext inner quipu
        key: 32-byte raw key, or a passphrase string (key = SHA256(passphrase))
        title: optional outer-facing public title
        tone: outer tone byte (default 0x00 ordinary — opt-in disclosure)

    Returns:
        (header_bytes, body_bytes)
    """
    key_bytes, variant = _aes_key_from(key)
    header = _build_header_prefix(tone, SUB_AES, variant)
    header = _append_title(header, title)
    framed = _frame_inner(inner_header, inner_body)
    ciphertext = _ecies.sym_encrypt(key_bytes, framed)
    return header, ciphertext


def build_ecies_quipu(inner_header, inner_body, sender_privkey, recipient_pubkeys, *,
                     title="", tone=TONE_ORDINARY):
    """Build a 0e ec ECIES-broadcast encrypted quipu.

    Args:
        inner_header, inner_body: bytes of the plaintext inner quipu
        sender_privkey: coincurve.PrivateKey of the sender.
                        For an N-of-N multisig sender, pass `aggregate_privkey(N_privs)`.
        recipient_pubkeys: list of coincurve.PublicKey of recipients. Each one
                           gets its own envelope.
                           For a multisig recipient, pass the component pubkeys
                           individually so each cosigner can decrypt.
        title: optional outer-facing public title
        tone: outer tone byte (default 0x00 ordinary)

    Returns:
        (header_bytes, body_bytes)
    """
    if not isinstance(sender_privkey, CCPriv):
        raise TypeError("sender_privkey must be coincurve.PrivateKey")
    if not recipient_pubkeys:
        raise ValueError("at least one recipient_pubkey required")
    if len(recipient_pubkeys) > 255:
        raise ValueError(f"max 255 recipients (got {len(recipient_pubkeys)})")

    header = _build_header_prefix(tone, SUB_ECIES, ECIES_BROADCAST)
    header = _append_title(header, title)

    session_key = get_valid_secret()
    envelopes = b""
    for pub in recipient_pubkeys:
        if not isinstance(pub, CCPub):
            pub = CCPub(bytes(pub))
        sk = _shared_key(sender_privkey, pub)
        env = _ecies.sym_encrypt(sk, session_key)
        if len(env) != 64:
            raise RuntimeError(f"envelope size {len(env)} != 64 (AES-CBC of 32B)")
        envelopes += env

    framed = _frame_inner(inner_header, inner_body)
    ciphertext = _ecies.sym_encrypt(session_key, framed)

    body = bytes([len(recipient_pubkeys)]) + envelopes + ciphertext
    return header, body


def build_keydrop_quipu(drops, *, title="", tone=TONE_ORDINARY):
    """Build a 0e 0d named-multi keydrop quipu releasing N keys.

    Args:
        drops: list of drops, each as either
                 (name, ref_txid_hex, key_bytes)  — 3-tuple
               or
                 {'name': str, 'ref_txid': str, 'key': bytes}  — dict
               `name` may be empty string for anonymous drops (not citeable
               by name, but still released). Names within one keydrop SHOULD
               be unique; duplicates resolve to the first match.
        title: optional outer public-facing batch label
        tone:  TONE_ORDINARY / TONE_AFFECTION / TONE_DEMONIC / TONE_REVERENCE
               (the tone reflects the act of disclosure, not per-drop)

    Returns:
        (header_bytes, body_bytes)

    Body layout (variant 0x00 — the only defined keydrop variant):
        <count:2 uint16 BE>
        for each drop:
            <namelen:1>  <name:namelen UTF-8>
            <ref_txid:32 raw bytes>
            <key:32>
        [|TITLE|]                  optional outer label

    A single-drop keydrop is just count=1.
    """
    if not drops:
        raise ValueError("drops list cannot be empty")
    if len(drops) > 0xFFFF:
        raise ValueError(f"max 65535 drops per keydrop (got {len(drops)})")

    normalized = []   # list of (name_bytes, ref_txid_raw, key_bytes)
    for i, d in enumerate(drops):
        if isinstance(d, dict):
            name = d.get('name', '')
            ref_txid_hex = d['ref_txid']
            key = d['key']
        elif isinstance(d, (tuple, list)) and len(d) == 3:
            name, ref_txid_hex, key = d
        else:
            raise TypeError(
                f"drop {i}: expected (name, ref_txid_hex, key) tuple or dict "
                f"with those keys; got {type(d).__name__}"
            )
        if not isinstance(name, str):
            raise TypeError(f"drop {i}: name must be str (got {type(name).__name__})")
        if len(ref_txid_hex) != 64:
            raise ValueError(
                f"drop {i}: ref_txid_hex must be 64 hex chars (got {len(ref_txid_hex)})"
            )
        try:
            ref_txid_raw = bytes.fromhex(ref_txid_hex)
        except ValueError:
            raise ValueError(f"drop {i}: ref_txid_hex is not valid hex")
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError(f"drop {i}: key must be 32 bytes")
        name_bytes = name.encode("utf-8")
        if len(name_bytes) > 255:
            raise ValueError(
                f"drop {i}: name encodes to {len(name_bytes)} UTF-8 bytes; max 255"
            )
        normalized.append((name_bytes, ref_txid_raw, bytes(key)))

    header = _build_header_prefix(tone, SUB_DROP, DROP_RELEASE)
    body = struct.pack(">H", len(normalized))
    for name_bytes, ref_txid_raw, key in normalized:
        body += bytes([len(name_bytes)]) + name_bytes + ref_txid_raw + key
    if title:
        if "|" in title:
            raise ValueError("title cannot contain '|'")
        body += b"|" + title.encode("utf-8") + b"|"
    return header, body


# ---------------------------------------------------------------------------
# Reader (dispatches on sub-family)
# ---------------------------------------------------------------------------

def _split_outer_title(rest):
    """If `rest` starts with `|TITLE|`, peel off the title and return (title, remainder)."""
    if not rest or rest[0:1] != b"|":
        return "", rest
    # Find closing pipe
    close = rest.find(b"|", 1)
    if close < 0:
        return "", rest
    title = rest[1:close].decode("utf-8", errors="replace")
    return title, rest[close + 1:]


def read_encrypted_quipu(header_bytes, body_bytes, *,
                          key=None, my_privkey=None, author_pubkey=None,
                          session_key=None):
    """Parse a 0x0e encrypted quipu and (if keys are supplied) decrypt.

    Args:
        header_bytes, body_bytes: the (header, body) pair returned by the diamond walker
        key: for SUB_AES — 32-byte raw key, or a passphrase string
        my_privkey: for SUB_ECIES — coincurve.PrivateKey of the recipient
                     (or aggregate priv for a multisig recipient)
        author_pubkey: for SUB_ECIES — coincurve.PublicKey of the sender
                     (or aggregate pub for a multisig sender)
        session_key: for SUB_ECIES — the 32-byte session key released via a
                     keydrop. If supplied, bypasses envelope unwrapping
                     entirely; lets a non-envelope-recipient decrypt the body
                     using a dropped session key.

    Returns:
        dict with:
            'tone':         int
            'sub_family':   int
            'sub_name':     'aes' | 'ecies' | 'drop'
            'variant':      int
            'title':        str (outer-facing public label, may be '')
            For 'aes' and 'ecies' after successful decrypt:
                'inner_header': bytes
                'inner_body':   bytes
                'magic_ok':     bool (True if inner_header[:4] == c1dd 0001)
            For 'drop':
                'ref_txid':     str (64-hex)
                'key':          bytes (32)
    """
    if header_bytes[:4] != MAGIC:
        raise ValueError("not a quipu (c1dd0001 magic missing)")
    if len(header_bytes) < 8:
        raise ValueError(f"header too short: {len(header_bytes)} bytes (need >= 8)")
    if header_bytes[4] != TYPE_ENCRYPTED:
        raise ValueError(f"not an encrypted quipu (type 0x{header_bytes[4]:02x}, expected 0x0e)")

    tone = header_bytes[5]
    sub  = header_bytes[6]
    var  = header_bytes[7]
    rest = header_bytes[8:]
    title, _trail = _split_outer_title(rest)

    out = {
        "tone": tone, "sub_family": sub, "variant": var, "title": title,
        "sub_name": {SUB_AES: "aes", SUB_ECIES: "ecies", SUB_DROP: "drop"}.get(sub, f"unknown_{sub:02x}"),
    }

    if sub == SUB_AES:
        if key is None:
            return out  # parse-only
        if var == KEY_PASSWORD:
            if not isinstance(key, str):
                raise ValueError("for password-AES (variant 0x01), pass key as a passphrase string")
            key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
        elif var == KEY_RAW:
            if not (isinstance(key, (bytes, bytearray)) and len(key) == 32):
                raise ValueError("for raw-AES (variant 0x00), pass 32-byte key")
            key_bytes = bytes(key)
        else:
            raise ValueError(f"unknown AES variant byte 0x{var:02x}")
        framed = _ecies.sym_decrypt(key_bytes, body_bytes)
        inner_header, inner_body = _unframe_inner(framed)
        out["inner_header"] = inner_header
        out["inner_body"] = inner_body
        out["magic_ok"] = (inner_header[:4] == MAGIC)
        return out

    if sub == SUB_ECIES:
        if session_key is not None:
            if not (isinstance(session_key, (bytes, bytearray)) and len(session_key) == 32):
                raise ValueError("session_key must be 32 bytes")
            n = body_bytes[0]
            ciphertext = body_bytes[1 + n*64:]
            framed = _ecies.sym_decrypt(bytes(session_key), ciphertext)
            inner_header, inner_body = _unframe_inner(framed)
            out["inner_header"] = inner_header
            out["inner_body"] = inner_body
            out["magic_ok"] = (inner_header[:4] == MAGIC)
            return out
        if my_privkey is None or author_pubkey is None:
            return out  # parse-only
        if not isinstance(my_privkey, CCPriv):
            raise TypeError("my_privkey must be coincurve.PrivateKey")
        if not isinstance(author_pubkey, CCPub):
            author_pubkey = CCPub(bytes(author_pubkey))
        n = body_bytes[0]
        envelopes = [body_bytes[1 + i*64 : 1 + (i+1)*64] for i in range(n)]
        ciphertext = body_bytes[1 + n*64:]
        sk = _shared_key(my_privkey, author_pubkey)
        for env in envelopes:
            try:
                session = _ecies.sym_decrypt(sk, env)
                framed  = _ecies.sym_decrypt(session, ciphertext)
                inner_header, inner_body = _unframe_inner(framed)
                out["inner_header"] = inner_header
                out["inner_body"] = inner_body
                out["magic_ok"] = (inner_header[:4] == MAGIC)
                return out
            except Exception:
                continue
        raise ValueError("no envelope decrypted with the given (my_privkey, author_pubkey)")

    if sub == SUB_DROP:
        # Body: <count:2 BE> + N × (<namelen:1><name><txid:32><key:32>) + optional |TITLE|
        if len(body_bytes) < 2:
            raise ValueError("keydrop body too short for count field")
        count = struct.unpack(">H", body_bytes[:2])[0]
        p = 2
        drops = []
        for i in range(count):
            if p >= len(body_bytes):
                raise ValueError(f"keydrop body truncated reading drop {i} namelen")
            namelen = body_bytes[p]; p += 1
            if p + namelen > len(body_bytes):
                raise ValueError(f"keydrop body truncated reading drop {i} name")
            name = body_bytes[p:p + namelen].decode("utf-8", errors="replace")
            p += namelen
            if p + 64 > len(body_bytes):
                raise ValueError(f"keydrop body truncated reading drop {i} ref_txid + key")
            ref_txid = body_bytes[p:p + 32].hex()
            key = bytes(body_bytes[p + 32:p + 64])
            p += 64
            drops.append({'name': name, 'ref_txid': ref_txid, 'key': key})
        out['drops'] = drops
        # Remaining bytes (if any) are an optional outer |TITLE|
        if p < len(body_bytes):
            tail_title, _ = _split_outer_title(body_bytes[p:])
            if tail_title:
                out["title"] = tail_title
        return out

    raise ValueError(f"unknown sub-family 0x{sub:02x}")


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _build_inner_text():
    """Build a tiny inner text quipu for testing."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from text import build_text_quipu, TONE_REVERENCE
    return build_text_quipu("Inner text",
                             "the encrypted body holds these words",
                             tone=TONE_REVERENCE)


def _selftest_aes_raw():
    h, b = _build_inner_text()
    key = b"\x42" * 32
    oh, ob = build_aes_quipu(h, b, key, title="public hint", tone=TONE_ORDINARY)
    print(f"=== AES raw key ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()}")
    assert oh[:4] == MAGIC
    assert oh[4] == TYPE_ENCRYPTED
    assert oh[5] == TONE_ORDINARY
    assert oh[6] == SUB_AES
    assert oh[7] == KEY_RAW

    parsed = read_encrypted_quipu(oh, ob, key=key)
    assert parsed["sub_name"] == "aes"
    assert parsed["title"] == "public hint"
    assert parsed["inner_header"] == h
    assert parsed["inner_body"] == b
    assert parsed["magic_ok"]
    print(f"  ✓ round-trip OK; inner magic check passes")

    try:
        read_encrypted_quipu(oh, ob, key=b"\x00"*32)
        print(f"  ✗ wrong key should have failed")
    except Exception as e:
        print(f"  ✓ wrong key rejected: {type(e).__name__}")
    print()


def _selftest_aes_password():
    h, b = _build_inner_text()
    passphrase = "el rio de la noche"
    oh, ob = build_aes_quipu(h, b, passphrase, title="amor", tone=TONE_AFFECTION)
    print(f"=== AES password ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()}")
    assert oh[5] == TONE_AFFECTION
    assert oh[7] == KEY_PASSWORD
    parsed = read_encrypted_quipu(oh, ob, key=passphrase)
    assert parsed["inner_header"] == h and parsed["inner_body"] == b
    print(f"  ✓ round-trip OK")
    try:
        read_encrypted_quipu(oh, ob, key="wrong")
        print(f"  ✗ wrong passphrase should have failed")
    except Exception as e:
        print(f"  ✓ wrong passphrase rejected: {type(e).__name__}")
    print()


def _selftest_ecies_single():
    h, b = _build_inner_text()
    sender   = CCPriv(b"\x11" * 32)
    recipient = CCPriv(b"\x22" * 32)
    oh, ob = build_ecies_quipu(h, b, sender, [recipient.public_key],
                                title="ecies 1-recipient", tone=TONE_REVERENCE)
    print(f"=== ECIES single-recipient ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()[:80]}…")
    assert oh[5] == TONE_REVERENCE
    assert oh[6] == SUB_ECIES
    n = ob[0]
    assert n == 1
    parsed = read_encrypted_quipu(oh, ob,
                                    my_privkey=recipient,
                                    author_pubkey=sender.public_key)
    assert parsed["inner_header"] == h and parsed["inner_body"] == b
    print(f"  ✓ round-trip OK (1 envelope, 64 B)")
    # Outsider rejection
    outsider = CCPriv(b"\x99" * 32)
    try:
        read_encrypted_quipu(oh, ob,
                              my_privkey=outsider,
                              author_pubkey=sender.public_key)
        print(f"  ✗ outsider should have failed")
    except Exception as e:
        print(f"  ✓ outsider rejected: {type(e).__name__}")
    print()


def _selftest_ecies_multi():
    h, b = _build_inner_text()
    sender = CCPriv(b"\x11" * 32)
    recipients = [CCPriv(bytes([i + 33]) * 32) for i in range(3)]
    pubs = [r.public_key for r in recipients]
    oh, ob = build_ecies_quipu(h, b, sender, pubs, title="to 3 friends")
    print(f"=== ECIES 3-recipient broadcast ===")
    n = ob[0]
    assert n == 3
    for i, r in enumerate(recipients):
        parsed = read_encrypted_quipu(oh, ob, my_privkey=r, author_pubkey=sender.public_key)
        assert parsed["inner_header"] == h and parsed["inner_body"] == b
        print(f"  ✓ recipient {i} decrypted")
    print()


def _selftest_ecies_multisig_sender():
    h, b = _build_inner_text()
    # 3-of-3 multisig sender (Hayagriva + Christophia + Anthony pattern)
    member_privs = [CCPriv(bytes([i + 10]) * 32) for i in range(3)]
    agg_priv = aggregate_privkey(member_privs)
    agg_pub  = aggregate_pubkey([p.public_key for p in member_privs])
    # Recipient: single key
    recipient = CCPriv(b"\x77" * 32)
    oh, ob = build_ecies_quipu(h, b, agg_priv, [recipient.public_key],
                                title="from the multisig")
    print(f"=== ECIES multisig sender (3-of-3 aggregate) ===")
    parsed = read_encrypted_quipu(oh, ob,
                                    my_privkey=recipient,
                                    author_pubkey=agg_pub)
    assert parsed["inner_header"] == h and parsed["inner_body"] == b
    print(f"  ✓ recipient decrypts using aggregate sender pubkey")
    # Verify aggregate identity
    assert agg_priv.public_key.format() == agg_pub.format()
    print(f"  ✓ aggregate identity holds: agg_priv·G == sum(member_pubs)")
    print()


def _selftest_keydrop_single():
    """Variant 0x00 with count=1 — the simplest keydrop."""
    ref = "2ae7fe909e19c0e4646f7981d0feffc96f4a3b286539f3da8caf19aebcf93bb2"
    k   = b"\xab" * 32
    oh, ob = build_keydrop_quipu(
        [("Sky of al-Jawza key", ref, k)],
        title="release the sky key",
        tone=TONE_REVERENCE,
    )
    print(f"=== Key drop — single named entry ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()}")
    assert oh[5] == TONE_REVERENCE
    assert oh[6] == SUB_DROP
    parsed = read_encrypted_quipu(oh, ob)
    assert parsed["sub_name"] == "drop"
    assert len(parsed["drops"]) == 1
    assert parsed["drops"][0]["name"] == "Sky of al-Jawza key"
    assert parsed["drops"][0]["ref_txid"] == ref
    assert parsed["drops"][0]["key"] == k
    assert parsed["title"] == "release the sky key"
    print(f"  ✓ round-trip OK: 1 named drop preserved")
    print()


def _selftest_keydrop_multi():
    """Variant 0x00 with count=3 — named multi-drop."""
    drops = [
        ("AES message",      "1" * 64, b"\x01" * 32),
        ("ECIES letter",     "2" * 64, b"\x02" * 32),
        ("",                 "3" * 64, b"\x03" * 32),  # anonymous drop OK
    ]
    oh, ob = build_keydrop_quipu(
        drops,
        title="Posthumous batch",
        tone=TONE_REVERENCE,
    )
    print(f"=== Key drop — named multi (3 drops) ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()}")
    print(f"  body length: {len(ob)} B")
    parsed = read_encrypted_quipu(oh, ob)
    assert len(parsed["drops"]) == 3
    assert parsed["drops"][0]["name"] == "AES message"
    assert parsed["drops"][1]["name"] == "ECIES letter"
    assert parsed["drops"][2]["name"] == ""   # anonymous
    assert parsed["drops"][0]["ref_txid"] == "1" * 64
    assert parsed["drops"][1]["key"] == b"\x02" * 32
    assert parsed["title"] == "Posthumous batch"
    print(f"  ✓ round-trip OK; all 3 drops + their names preserved")
    print()


def _selftest_nested():
    """AES wrap of an AES wrap of a text quipu."""
    h, b = _build_inner_text()
    mid_h, mid_b = build_aes_quipu(h, b, b"\x01"*32, title="inner layer")
    out_h, out_b = build_aes_quipu(mid_h, mid_b, b"\x02"*32, title="outer layer")
    print(f"=== Nested AES-in-AES ===")
    p1 = read_encrypted_quipu(out_h, out_b, key=b"\x02"*32)
    assert p1["inner_header"] == mid_h and p1["inner_body"] == mid_b
    p2 = read_encrypted_quipu(p1["inner_header"], p1["inner_body"], key=b"\x01"*32)
    assert p2["inner_header"] == h and p2["inner_body"] == b
    print(f"  ✓ peel outer + peel inner → original text quipu recovered byte-identical")
    print()


def _selftest_validation():
    cases = [
        ("invalid tone",
         lambda: build_aes_quipu(MAGIC + b"\x00\x00", b"", b"\x00"*32, tone=0x42),
         "tone"),
        ("title with pipe",
         lambda: build_aes_quipu(MAGIC + b"\x00\x00", b"", b"\x00"*32, title="a|b"),
         "title cannot contain"),
        ("non-32-byte key",
         lambda: build_aes_quipu(MAGIC + b"\x00\x00", b"", b"\x00"*16),
         "32 bytes"),
        ("non-magic inner header",
         lambda: build_aes_quipu(b"\x00"*16, b"", b"\x00"*32),
         "c1dd"),
        ("empty keydrop list",
         lambda: build_keydrop_quipu([]),
         "cannot be empty"),
        ("invalid keydrop txid length",
         lambda: build_keydrop_quipu([("x", "ab", b"\x00"*32)]),
         "64 hex"),
        ("invalid keydrop key length",
         lambda: build_keydrop_quipu([("x", "0"*64, b"\x00"*16)]),
         "32 bytes"),
        ("keydrop drop entry wrong shape",
         lambda: build_keydrop_quipu([("just_two_fields", "0"*64)]),
         "expected"),
    ]
    print(f"=== validation ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:35s} -> {status}: {e}")
        else:
            print(f"  {desc:35s} -> DID NOT RAISE (bug)")
    print()


if __name__ == "__main__":
    _selftest_aes_raw()
    _selftest_aes_password()
    _selftest_ecies_single()
    _selftest_ecies_multi()
    _selftest_ecies_multisig_sender()
    _selftest_keydrop_single()
    _selftest_keydrop_multi()
    _selftest_nested()
    _selftest_validation()
