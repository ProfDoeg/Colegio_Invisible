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
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

MAGIC = b"\xc1\xdd\x00\x01"
TYPE_ENCRYPTED = 0x0e

from tone import (
    TONES, VALID_TONES, validate_tone,
    TONE_ORDINARY, TONE_AFFECTION, TONE_DEMONIC, TONE_AI, TONE_REVERENCE,
)
_VALID_TONES = VALID_TONES  # backward-compat alias

# Sub-family byte at offset 6
SUB_AES   = 0xAE
SUB_ECIES = 0xEC
SUB_DROP  = 0x0D
SUB_CENTINELA = 0xCA   # canary: public lock descriptor (header) + AES-sealed claim secret (body)
SUB_CB        = 0xCB   # committed-binding sale box (verified-key sale construction)
SUB_SHAMIR    = 0x55   # Shamir share: one K-of-N share of a 32-byte key (reads "SS")
_VALID_SUBS = (SUB_AES, SUB_ECIES, SUB_DROP, SUB_CENTINELA, SUB_CB, SUB_SHAMIR)

# Variant byte at offset 7
KEY_RAW       = 0x00   # for SUB_AES: raw 32-byte key
KEY_PASSWORD  = 0x01   # for SUB_AES: key = SHA256(passphrase)
ECIES_BROADCAST = 0x00 # for SUB_ECIES
DROP_RELEASE  = 0x00   # for SUB_DROP: bare body
DROP_SOURCED  = 0x01   # for SUB_DROP: body preceded by |claim=...|... header descriptor
CB_SALE_V1    = 0x00   # for SUB_CB: v1 single-key sale (only variant defined)
SHAMIR_GF256  = 0x00   # for SUB_SHAMIR: byte-wise Shamir over GF(2^8)  (single share)
SHAMIR_VAULT  = 0x01   # for SUB_SHAMIR: self-contained vault (dump + N shares)

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


# centinela (sub-family 0xca) — a canary container: public lock descriptor in the
# header (pipe fields), the claim secret AES-sealed in the body (same sealing as
# 0xae). The descriptor lets anyone watch the bait outpoint + verify the lock; the
# sealed body yields {preimage, claim key} only to whoever holds the AES key.
_CENTINELA_FIELDS = ("mode", "outpoint", "p2sh", "redeem", "refund")


def build_centinela_quipu(inner_header, inner_body, key, *, descriptor, title="",
                          tone=TONE_ORDINARY):
    """Build a 0e ca centinela. `descriptor` is a dict over _CENTINELA_FIELDS
    (cleartext, public). `inner_header`/`inner_body` are the secret inner quipu
    (e.g. a 0x00 text holding {P, D_priv}); it is AES-sealed exactly like 0xae.
    `key` = 32-byte raw key or a passphrase string."""
    key_bytes, variant = _aes_key_from(key)
    header = _build_header_prefix(tone, SUB_CENTINELA, variant)
    fields = []
    if title:
        if "|" in title:
            raise ValueError("title cannot contain '|'")
        fields.append(title)
    for k in _CENTINELA_FIELDS:
        if descriptor.get(k) is not None:
            v = str(descriptor[k])
            if "|" in v:
                raise ValueError(f"descriptor field {k} cannot contain '|'")
            fields.append(f"{k}={v}")
    if fields:
        header += b"|" + "|".join(fields).encode("utf-8") + b"|"
    framed = _frame_inner(inner_header, inner_body)
    return header, _ecies.sym_encrypt(key_bytes, framed)


def parse_centinela_header(header_bytes):
    """(title, descriptor_dict, variant) from a 0e ca header — public, no key."""
    if header_bytes[4] != TYPE_ENCRYPTED or header_bytes[6] != SUB_CENTINELA:
        raise ValueError("not a 0e ca centinela header")
    variant = header_bytes[7]
    title, desc = "", {}
    rest = header_bytes[8:]
    if rest[:1] == b"|":
        for seg in rest.split(b"|")[1:-1]:
            txt = seg.decode("utf-8", "replace")
            if "=" in txt:
                k, v = txt.split("=", 1); desc[k] = v
            elif not title:
                title = txt
    return title, desc, variant


# ---------------------------------------------------------------------------
# Shamir share (sub-family 0x55) — one K-of-N share of a key.
# Byte-wise Shamir Secret Sharing over GF(2^8) (the AES field). Each 0e 55 quipu
# carries ONE share; any K shares reconstruct the key, which then opens its
# target 0e ae / 0e ec — a *threshold* keydrop. Pure arithmetic, no opcodes.
# ---------------------------------------------------------------------------
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
def _xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else ((a << 1) & 0xFF)
def _gf_build():
    a = 1
    for i in range(255):
        _GF_EXP[i] = a; _GF_LOG[a] = i
        a ^= _xtime(a)                      # a *= 3 (a primitive element of GF(2^8))
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]
_gf_build()
def _gf_mul(a, b):
    return 0 if (a == 0 or b == 0) else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]
def _gf_div(a, b):
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    return _GF_EXP[_GF_LOG[a] - _GF_LOG[b] + 255]


def shamir_split(secret, k, n):
    """Split bytes `secret` into n shares, any k of which reconstruct it.
    Returns {x: share_bytes} for x in 1..n. Uses os.urandom for the coefficients."""
    import os
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    shares = {x: bytearray(len(secret)) for x in range(1, n + 1)}
    for bi, sb in enumerate(secret):
        coeffs = [sb] + list(os.urandom(k - 1))      # f(0) = secret byte; random higher terms
        for x in range(1, n + 1):
            y, xp = 0, 1
            for c in coeffs:
                y ^= _gf_mul(c, xp); xp = _gf_mul(xp, x)
            shares[x][bi] = y
    return {x: bytes(b) for x, b in shares.items()}


def shamir_combine(parts):
    """parts: list of (x, share_bytes), at least k of them. Lagrange-interpolate at
    x=0 over GF(2^8) and return the secret bytes."""
    L = len(parts[0][1])
    xs = [p[0] for p in parts]
    out = bytearray(L)
    for bi in range(L):
        s = 0
        for j, (xj, sbj) in enumerate(parts):
            num = den = 1
            for m, xm in enumerate(xs):
                if m == j:
                    continue
                num = _gf_mul(num, xm)        # at x=0: basis_j = prod x_m / prod (x_j ^ x_m)
                den = _gf_mul(den, xj ^ xm)
            s ^= _gf_mul(sbj[bi], _gf_div(num, den))
        out[bi] = s
    return bytes(out)


def build_shamir_share_quipu(x, k, n, share, *, commitment, ref_txid=b"\x00" * 32,
                             title="", tone=TONE_ORDINARY):
    """One 0e 55 share quipu. `commitment` = SHA256(secret) (lets a reconstruction be
    verified); `ref_txid` = the target sealed quipu this key opens (zeros if none).
    To keep a share private until release, wrap this in a 0e ec to the keeper."""
    if not (1 <= x <= n and 1 <= k <= n <= 255):
        raise ValueError("require 1 <= x <= n and 1 <= k <= n <= 255")
    if len(commitment) != 32 or len(ref_txid) != 32:
        raise ValueError("commitment and ref_txid must be 32 bytes")
    header = _append_title(_build_header_prefix(tone, SUB_SHAMIR, SHAMIR_GF256), title)
    body = bytes([k, n, x]) + bytes(commitment) + bytes(ref_txid) + struct.pack(">H", len(share)) + bytes(share)
    return header, body


def read_shamir_share_quipu(header_bytes, body_bytes):
    """Parse a 0e 55 share quipu -> dict (k, n, x, commitment, ref_txid, share, title)."""
    if header_bytes[4] != TYPE_ENCRYPTED or header_bytes[6] != SUB_SHAMIR:
        raise ValueError("not a 0e 55 Shamir share")
    k, n, x = body_bytes[0], body_bytes[1], body_bytes[2]
    commitment = bytes(body_bytes[3:35]); ref = bytes(body_bytes[35:67])
    slen = struct.unpack(">H", body_bytes[67:69])[0]
    share = bytes(body_bytes[69:69 + slen])
    title, _ = _split_outer_title(header_bytes[8:])
    return {"k": k, "n": n, "x": x, "commitment": commitment,
            "ref_txid": ref.hex(), "share": share, "title": title}


def shamir_seal_key(secret, k, n, *, ref_txid=b"\x00" * 32, names=None, tone=TONE_ORDINARY):
    """Split `secret` (e.g. a 32-byte AES key) k-of-n into n 0e 55 share quipus.
    Returns (list[(header, body)], commitment_hex). `names` optionally titles each."""
    commit = hashlib.sha256(bytes(secret)).digest()
    shares = shamir_split(bytes(secret), k, n)
    out = []
    for i, (x, sb) in enumerate(sorted(shares.items())):
        t = names[i] if (names and i < len(names)) else ""
        out.append(build_shamir_share_quipu(x, k, n, sb, commitment=commit,
                                            ref_txid=ref_txid, title=t, tone=tone))
    return out, commit.hex()


def shamir_reconstruct_key(share_quipus):
    """share_quipus: list of (header, body) 0e 55 quipus (>= k). Reconstructs and
    VERIFIES the key against the shares' commitment. Raises on too-few / mismatch."""
    parsed = [read_shamir_share_quipu(h, b) for h, b in share_quipus]
    k = parsed[0]["k"]
    by_x = {}
    for p in parsed:
        by_x.setdefault(p["x"], p["share"])          # dedup by index
    if len(by_x) < k:
        raise ValueError(f"need >= {k} distinct shares, got {len(by_x)}")
    secret = shamir_combine(list(by_x.items())[:k])
    if hashlib.sha256(secret).digest() != parsed[0]["commitment"]:
        raise ValueError("reconstruction failed: commitment mismatch (wrong or corrupt shares)")
    return secret


# ---------------------------------------------------------------------------
# Shamir vault (sub-family 0x55, variant 0x01) — SELF-CONTAINED K-of-N vault.
# One quipu carries: the sealed dump (0e ae under key K — inline or by-ref) and N
# share records (each a 0e 55 share, optionally ECIES-sealed to a chosen keeper
# key). Reconstruct K shares -> K -> open the dump. Composes 0e ae + 0e 55 + 0e ec.
# ---------------------------------------------------------------------------
def build_shamir_vault(secret_key, k, n, *, dump=None, dump_ref=None,
                       recipients=None, sender_privkey=None,
                       ref_txid=b"\x00" * 32, title="", tone=TONE_ORDINARY):
    """Self-contained K-of-N Shamir vault (0e 55 variant 0x01).

    secret_key : the key that opens the dump (32 B); this is what gets split.
    dump       : (header, body) of the sealed 0e ae payload -> embedded INLINE.
    dump_ref   : 32-byte txid of the dump -> stored BY REFERENCE (lean). Exactly
                 one of dump / dump_ref is required.
    recipients : list of n pubkeys (coincurve.PublicKey) -> each share is
                 ECIES-sealed to its keeper (needs sender_privkey). None -> the
                 shares are PUBLIC (in the clear).
    Returns (header, body)."""
    secret_key = bytes(secret_key)
    inline = dump is not None
    sealed = recipients is not None
    if inline == (dump_ref is not None):
        raise ValueError("provide exactly one of dump / dump_ref")
    if sealed and (sender_privkey is None or len(recipients) != n):
        raise ValueError("sealed vault needs sender_privkey and exactly n recipients")
    commit = hashlib.sha256(secret_key).digest()
    shares = shamir_split(secret_key, k, n)
    sender_pub = sender_privkey.public_key.format() if sealed else b"\x00" * 33
    flags = (1 if inline else 0) | (2 if sealed else 0)
    body = bytes([k, n, flags]) + bytes(sender_pub) + commit
    if inline:
        framed = _frame_inner(dump[0], dump[1])
        body += struct.pack(">I", len(framed)) + framed
    else:
        if len(dump_ref) != 32:
            raise ValueError("dump_ref must be 32 bytes")
        body += bytes(dump_ref)
    for i, (x, sb) in enumerate(sorted(shares.items())):
        sh = build_shamir_share_quipu(x, k, n, sb, commitment=commit, ref_txid=ref_txid)
        rec = build_ecies_quipu(sh[0], sh[1], sender_privkey, [recipients[i]]) if sealed else sh
        framed = _frame_inner(rec[0], rec[1])
        body += struct.pack(">I", len(framed)) + framed
    header = _append_title(_build_header_prefix(tone, SUB_SHAMIR, SHAMIR_VAULT), title)
    return header, body


def read_shamir_vault(header_bytes, body_bytes):
    """Parse a 0e 55 vault -> dict(k, n, sealed, inline, sender_pub, commit,
    dump_blob=(h,b)|None, dump_ref=hex|None, records=[(h,b),…])."""
    if (header_bytes[4] != TYPE_ENCRYPTED or header_bytes[6] != SUB_SHAMIR
            or header_bytes[7] != SHAMIR_VAULT):
        raise ValueError("not a 0e 55 vault (variant 0x01)")
    k, n, flags = body_bytes[0], body_bytes[1], body_bytes[2]
    sender_pub = bytes(body_bytes[3:36]); commit = bytes(body_bytes[36:68])
    inline, sealed = bool(flags & 1), bool(flags & 2)
    pos = 68; dump_blob = dump_ref = None
    if inline:
        dlen = struct.unpack(">I", body_bytes[pos:pos + 4])[0]; pos += 4
        dump_blob = _unframe_inner(bytes(body_bytes[pos:pos + dlen])); pos += dlen
    else:
        dump_ref = bytes(body_bytes[pos:pos + 32]).hex(); pos += 32
    records = []
    for _ in range(n):
        rl = struct.unpack(">I", body_bytes[pos:pos + 4])[0]; pos += 4
        records.append(_unframe_inner(bytes(body_bytes[pos:pos + rl]))); pos += rl
    return {"k": k, "n": n, "sealed": sealed, "inline": inline, "sender_pub": sender_pub,
            "commit": commit, "dump_blob": dump_blob, "dump_ref": dump_ref, "records": records}


def _as_vault(vault):
    return read_shamir_vault(*vault) if isinstance(vault, tuple) else vault


def vault_public_shares(vault):
    """[(x, share)] for a PUBLIC vault (shares in the clear)."""
    v = _as_vault(vault)
    if v["sealed"]:
        raise ValueError("shares are ECIES-sealed; use vault_open_share per keeper")
    out = []
    for (h, b) in v["records"]:
        p = read_shamir_share_quipu(h, b); out.append((p["x"], p["share"]))
    return out


def vault_open_share(vault, my_privkey):
    """SEALED vault: return (x, share) for the record `my_privkey` can decrypt."""
    v = _as_vault(vault)
    if not v["sealed"]:
        raise ValueError("public vault — use vault_public_shares()")
    import coincurve
    author = coincurve.PublicKey(v["sender_pub"])
    for (h, b) in v["records"]:
        try:
            dec = read_encrypted_quipu(h, b, my_privkey=my_privkey, author_pubkey=author)
        except Exception:
            continue
        if dec.get("magic_ok"):
            p = read_shamir_share_quipu(dec["inner_header"], dec["inner_body"])
            return (p["x"], p["share"])
    raise ValueError("no record decryptable by this key")


def vault_reconstruct_key(vault, shares):
    """shares: list of (x, share_bytes), >= k. Reconstruct + verify against commit."""
    v = _as_vault(vault)
    if len(shares) < v["k"]:
        raise ValueError(f"need >= {v['k']} shares, got {len(shares)}")
    key = shamir_combine(list(shares)[:v["k"]])
    if hashlib.sha256(key).digest() != v["commit"]:
        raise ValueError("reconstruction failed: commitment mismatch")
    return key


def vault_open(vault, keeper_privkeys=None):
    """One-shot for an INLINE vault: gather shares (per-keeper if sealed, else
    public), reconstruct the key, decrypt the inline dump, return its inner
    {inner_header, inner_body, magic_ok, …}. keeper_privkeys needed iff sealed."""
    v = _as_vault(vault)
    shares = []
    if v["sealed"]:
        for kp in (keeper_privkeys or []):
            try:
                shares.append(vault_open_share(v, kp))
            except Exception:
                pass
    else:
        shares = vault_public_shares(v)
    key = vault_reconstruct_key(v, shares)
    if not v["inline"]:
        raise ValueError("dump is by-reference; fetch v['dump_ref'] and decrypt with the key")
    dh, db = v["dump_blob"]
    return read_encrypted_quipu(dh, db, key=key)


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


# ---------------------------------------------------------------------------
# Committed-binding sale box (sub-family 0xcb)
# ---------------------------------------------------------------------------
# A 0xcb box is ECIES-sealed to a fresh **session** keypair generated for one
# sale only. The seller's identity key is the sender. The session_pub is
# embedded in the body so anyone parsing the bytes can identify the box's
# recipient pubkey without needing to know who sent it. Pairing: an offer
# cert (0xcc 0x0003) references this box's join txid and carries an ECDSA
# adaptor signature that binds revealing session_priv to claiming the offer's
# bond UTXO. See docs/quipu-syntax/verified-key-sale.md.

def build_cb_box_quipu(inner_header, inner_body, sender_privkey,
                      session_pubkey, *, title="", tone=TONE_ORDINARY):
    """Build a 0e cb committed-binding sale box.

    Args:
        inner_header, inner_body: bytes of the plaintext inner quipu (what's
            being sold)
        sender_privkey: coincurve.PrivateKey — the seller's identity key.
            Sender_pub is recoverable from the box's funding tx scriptSig
            inputs; the buyer uses it (with session_priv) to derive the
            shared_key for decryption.
        session_pubkey: coincurve.PublicKey — the fresh session keypair's
            pubkey. MUST NOT be the sender's identity key (tooling refuses).
            The corresponding session_priv is what gets sold via the offer's
            HTLC bond.
        title: optional outer-facing public title
        tone: outer tone byte

    Returns:
        (header_bytes, body_bytes)

    Body layout:
        <session_pub:33>           compressed secp256k1 pubkey, T = session_pub
        <envelope:64>              16 IV + 48 AES-CBC ciphertext of session_key
        <ciphertext>               AES-CBC(session_key, framed_inner)
    """
    if not isinstance(sender_privkey, CCPriv):
        raise TypeError("sender_privkey must be coincurve.PrivateKey")
    if not isinstance(session_pubkey, CCPub):
        session_pubkey = CCPub(bytes(session_pubkey))
    if sender_privkey.public_key.format() == session_pubkey.format():
        raise ValueError(
            "session_pubkey must NOT equal the sender's identity pubkey "
            "(revealing session_priv would catastrophically compromise the seller)"
        )

    header = _build_header_prefix(tone, SUB_CB, CB_SALE_V1)
    header = _append_title(header, title)

    # Derive shared_key for the envelope (same KDF as 0x0e 0xec)
    shared_key = _shared_key(sender_privkey, session_pubkey)
    session_key = get_valid_secret()
    envelope = _ecies.sym_encrypt(shared_key, session_key)
    if len(envelope) != 64:
        raise RuntimeError(f"envelope size {len(envelope)} != 64")

    framed = _frame_inner(inner_header, inner_body)
    ciphertext = _ecies.sym_encrypt(session_key, framed)

    body = session_pubkey.format(compressed=True) + envelope + ciphertext
    return header, body


def read_cb_box_quipu(header_bytes, body_bytes, *, session_privkey=None,
                     sender_pubkey=None):
    """Parse and (with the right keys) decrypt a 0e cb sale box.

    Args:
        header_bytes, body_bytes: from the diamond walker
        session_privkey: coincurve.PrivateKey, the buyer's recovered session_priv
        sender_pubkey:   coincurve.PublicKey of the seller's identity (recovered
                         from the box's funding tx scriptSig). Required for
                         decryption since the box's body doesn't carry sender_pub.

    Returns:
        dict:
            'tone', 'sub_family', 'variant', 'title' — always
            'session_pub' — 33-byte hex of the box's recipient pubkey
            If session_privkey AND sender_pubkey supplied AND decryption works:
                'inner_header', 'inner_body', 'magic_ok'
    """
    if header_bytes[:4] != MAGIC:
        raise ValueError("not a quipu (c1dd0001 missing)")
    if len(header_bytes) < 8:
        raise ValueError(f"header too short: {len(header_bytes)}")
    if header_bytes[4] != TYPE_ENCRYPTED:
        raise ValueError(f"not encrypted family (type 0x{header_bytes[4]:02x})")
    if header_bytes[6] != SUB_CB:
        raise ValueError(f"not a 0e cb sale box (sub-family 0x{header_bytes[6]:02x})")

    tone = header_bytes[5]
    var = header_bytes[7]
    title, _ = _split_outer_title(header_bytes[8:])

    if len(body_bytes) < 33 + 64:
        raise ValueError(f"body too short ({len(body_bytes)}): need >= 33 + 64")
    session_pub_bytes = bytes(body_bytes[:33])
    envelope = bytes(body_bytes[33:97])
    ciphertext = bytes(body_bytes[97:])

    out = {
        "tone":         tone,
        "sub_family":   SUB_CB,
        "sub_name":     "cb",
        "variant":      var,
        "title":        title,
        "session_pub":  session_pub_bytes.hex(),
    }

    if session_privkey is None or sender_pubkey is None:
        return out  # parse-only

    if not isinstance(session_privkey, CCPriv):
        raise TypeError("session_privkey must be coincurve.PrivateKey")
    if not isinstance(sender_pubkey, CCPub):
        sender_pubkey = CCPub(bytes(sender_pubkey))

    # Verify the supplied session_privkey actually corresponds to the box's session_pub
    derived = session_privkey.public_key.format(compressed=True)
    if derived != session_pub_bytes:
        raise ValueError(
            "session_privkey does not derive to the box's session_pub — "
            "wrong key, or wrong box"
        )

    shared_key = _shared_key(session_privkey, sender_pubkey)
    session_key = _ecies.sym_decrypt(shared_key, envelope)
    framed = _ecies.sym_decrypt(session_key, ciphertext)
    inner_header, inner_body = _unframe_inner(framed)
    out["inner_header"] = inner_header
    out["inner_body"]   = inner_body
    out["magic_ok"]     = (inner_header[:4] == MAGIC)
    return out


_KEYDROP_HEADER_FIELDS = ("claim", "source", "centinela", "supersedes")


def build_keydrop_quipu(drops, *, title="", tone=TONE_ORDINARY,
                         header_fields=None):
    """Build a 0e 0d named-multi keydrop quipu releasing N keys.

    Args:
        drops: list of drops, each as either
                 (name, ref_txid_hex, key_bytes)  — 3-tuple
               or
                 {'name': str, 'ref_txid': str, 'key': bytes}  — dict
               `name` may be empty string for anonymous drops (not citeable
               by name, but still released). Names within one keydrop SHOULD
               be unique; duplicates resolve to the first match.
        title: optional outer public-facing batch label (lives at end of body)
        tone:  TONE_ORDINARY / TONE_AFFECTION / TONE_DEMONIC / TONE_REVERENCE
               (the tone reflects the act of disclosure, not per-drop)
        header_fields: optional dict of header descriptor fields. If supplied,
               builds the SOURCED variant (`0x01`) — the header gets a
               pipe-delimited `|name=value|...` tail right after the 8
               structural bytes, and the body's count+drops+optional-|TITLE|
               layout is unchanged. Reserved field names:
                   claim       — the claim tx that revealed this key in its
                                 scriptSig (verified-key sale)
                   source      — generic source reference (any txid)
                   centinela   — the centinela whose tripwire revealed the key
                   supersedes  — a prior keydrop this one replaces
               Other names pass through opaquely. Values must be strings with
               no '|' character.

    Returns:
        (header_bytes, body_bytes)

    Body layout (both variants):
        <count:2 uint16 BE>
        for each drop:
            <namelen:1>  <name:namelen UTF-8>
            <ref_txid:32 raw bytes>
            <key:32>
        [|TITLE|]                  optional outer label

    Header layout:
        variant 0x00 (bare):    c1dd0001 0e <tone> 0d 00
        variant 0x01 (sourced): c1dd0001 0e <tone> 0d 01 |name=value|...|
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

    # Choose variant by whether header_fields was supplied
    if header_fields:
        if not isinstance(header_fields, dict):
            raise TypeError("header_fields must be a dict[str, str]")
        for k, v in header_fields.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError(f"header_fields {k!r}={v!r}: keys and values must be str")
            if "|" in k or "|" in v:
                raise ValueError(f"header_fields {k!r}: '|' forbidden")
            if "=" in k:
                raise ValueError(f"header_fields {k!r}: '=' forbidden in keys")
        header = _build_header_prefix(tone, SUB_DROP, DROP_SOURCED)
        tail = "|".join(f"{k}={v}" for k, v in header_fields.items())
        header += b"|" + tail.encode("utf-8") + b"|"
    else:
        header = _build_header_prefix(tone, SUB_DROP, DROP_RELEASE)

    body = struct.pack(">H", len(normalized))
    for name_bytes, ref_txid_raw, key in normalized:
        body += bytes([len(name_bytes)]) + name_bytes + ref_txid_raw + key
    if title:
        if "|" in title:
            raise ValueError("title cannot contain '|'")
        body += b"|" + title.encode("utf-8") + b"|"
    return header, body


def parse_keydrop_header_fields(header_bytes):
    """Parse the variant-0x01 keydrop header tail (descriptor fields).
    Returns a dict[str,str], possibly empty. Variant 0x00 returns {}."""
    if len(header_bytes) < 8:
        return {}
    if header_bytes[4] != TYPE_ENCRYPTED or header_bytes[6] != SUB_DROP:
        return {}
    if header_bytes[7] != DROP_SOURCED:
        return {}
    rest = header_bytes[8:]
    if not rest or rest[0:1] != b"|":
        return {}
    out = {}
    text = rest.decode("utf-8", errors="replace")
    for seg in text.split("|"):
        if not seg or "=" not in seg:
            continue
        k, _, v = seg.partition("=")
        out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------------------
# Legacy (pre-canonical, 2022) wire layouts — READ SIDE ONLY.
#
# Before the May-2026 canonical v1 redesign, colegio_tools.py wrote three
# 0x0e layouts (nb17/nb18 era). Four such quipus are inscribed on mainnet
# (blocks 4.25M–4.27M) and must stay legible forever:
#
#   legacy broadcast   c1dd0001 0e <inner_type> <color> <LL:2> <WW:2> <B> <N> |title|
#                      body: N × 64-byte envelopes + AES(session, inner_body)
#                      (on chain: d68175…, d0209a… — inner_type 0x03 image;
#                       tone was dropped at write time)
#   legacy keydrop     c1dd0001 0e 0e 0d |title|
#                      body: <target_txid:32> <key:32>
#                      (on chain: 89b51b…, f278e4…)
#   legacy AES splice  c1dd0001 0e ae + inner_header[4:]
#                      body: AES(key, inner_body) — the inner header stayed
#                      in CLEARTEXT, only the body was sealed. None inscribed;
#                      supported for local files built by the old tooling.
#
# Detection is unambiguous: canonical always has a registered tone at byte 5
# and a registered sub-family at byte 6. Legacy keydrop has 0x0e at byte 5
# (not a tone); legacy AES splice has 0xae at byte 5 (not a tone); legacy
# broadcast has a non-sub-family byte (the color, 0x00/0x01) at byte 6.
#
# NEVER build these layouts for new inscriptions — all writers emit
# canonical. See tests/test_encrypted_wire.py for the corpus gates.
# ---------------------------------------------------------------------------

LEGACY_DROP_PREFIX = b"\x0e\x0e\x0d"   # bytes 4..6 of a legacy keydrop header


def classify_encrypted(header_bytes):
    """Classify a 0x0e header's wire era.

    Returns 'canonical' | 'legacy_drop' | 'legacy_aes' | 'legacy_broadcast'
    | 'unknown' | 'not_encrypted'.
    """
    hb = bytes(header_bytes)
    if len(hb) < 7 or hb[:4] != MAGIC or hb[4] != TYPE_ENCRYPTED:
        return "not_encrypted"
    if len(hb) >= 8 and hb[5] in VALID_TONES and hb[6] in _VALID_SUBS:
        return "canonical"
    if hb[4:7] == LEGACY_DROP_PREFIX:
        return "legacy_drop"
    if hb[5] == 0xAE:
        return "legacy_aes"
    # Legacy broadcast: byte 5 is the INNER type (0x03 image on chain — which
    # collides with TONE_PLAY, so it can't discriminate); byte 6 is the color
    # byte (0x00 grayscale / 0x01 RGB), which is never a canonical sub-family.
    if len(hb) >= 13 and hb[6] in (0x00, 0x01):
        return "legacy_broadcast"
    return "unknown"


def parse_legacy_keydrop(header_bytes, body_bytes):
    """Parse a legacy 0e 0e 0d keydrop. Returns (target_txid_hex, key32, title).

    The txid is display-endian (bytes.fromhex of the displayed txid), per nb18.
    """
    if bytes(header_bytes[4:7]) != LEGACY_DROP_PREFIX:
        raise ValueError("not a legacy keydrop (c1dd0001 0e 0e 0d expected)")
    if len(body_bytes) < 64:
        raise ValueError(f"legacy keydrop body too short ({len(body_bytes)} < 64)")
    title, _ = _split_outer_title(bytes(header_bytes[7:]))
    return bytes(body_bytes[:32]).hex(), bytes(body_bytes[32:64]), title


def _legacy_broadcast_fields(header_bytes):
    """Structural fields of a legacy broadcast header (13 bytes + |title|)."""
    hb = bytes(header_bytes)
    if len(hb) < 13:
        raise ValueError(f"legacy broadcast header too short ({len(hb)} < 13)")
    title, _ = _split_outer_title(hb[13:])
    return {
        "inner_type":   hb[5],
        "color":        hb[6],
        "W":            (hb[7] << 8) | hb[8],
        "H":            (hb[9] << 8) | hb[10],
        "bit_depth":    hb[11],
        "n_recipients": hb[12],
        "title":        title,
    }


def synthesize_legacy_inner_header(header_bytes):
    """Reconstruct the plaintext-shaped inner header a legacy broadcast
    implies: magic + inner_type + placeholder tone 0x00 + the six
    color/L/W/B bytes + the |title| tail (tone was dropped at write time)."""
    hb = bytes(header_bytes)
    return MAGIC + hb[5:6] + b"\x00" + hb[6:12] + hb[13:]


def read_legacy_broadcast_quipu(header_bytes, body_bytes, *,
                                my_privkey=None, author_pubkey=None,
                                session_key=None):
    """Parse (and with keys, decrypt) a legacy 0e <type> broadcast quipu.

    Args mirror the canonical reader: my_privkey/author_pubkey are coincurve
    keys for envelope unwrapping; session_key is a released 32-byte key (from
    a keydrop) that bypasses the envelopes.

    Returns a canonical-reader-shaped dict with legacy=True; on successful
    decrypt adds inner_header (synthesized, magic_ok True by construction)
    and inner_body.
    """
    out = _legacy_broadcast_fields(header_bytes)
    out.update({"legacy": True, "sub_name": "legacy_broadcast",
                "sub_family": None, "variant": None, "tone": None})
    n = out["n_recipients"]
    if len(body_bytes) < n * 64:
        raise ValueError(f"legacy broadcast body too short for {n} envelopes")
    ciphertext = bytes(body_bytes[n * 64:])

    session = None
    if session_key is not None:
        if not (isinstance(session_key, (bytes, bytearray)) and len(session_key) == 32):
            raise ValueError("session_key must be 32 bytes")
        session = bytes(session_key)
    elif my_privkey is not None and author_pubkey is not None:
        if not isinstance(my_privkey, CCPriv):
            raise TypeError("my_privkey must be coincurve.PrivateKey")
        if not isinstance(author_pubkey, CCPub):
            author_pubkey = CCPub(bytes(author_pubkey))
        sk = _shared_key(my_privkey, author_pubkey)
        for i in range(n):
            env = bytes(body_bytes[i * 64:(i + 1) * 64])
            try:
                session = _ecies.sym_decrypt(sk, env)
                break
            except Exception:
                continue
        if session is None:
            raise ValueError("no envelope decrypted with the given (my_privkey, author_pubkey)")
    else:
        return out  # parse-only

    out["inner_body"] = _ecies.sym_decrypt(session, ciphertext)
    out["inner_header"] = synthesize_legacy_inner_header(header_bytes)
    out["magic_ok"] = True
    return out


def read_legacy_aes_sealed(header_bytes, body_bytes, key):
    """Unwrap a legacy 0e ae splice. `key` is a 32-byte key or a passphrase
    string (SHA-256 KDF, same as the old tooling). Returns
    (inner_header, inner_body) — the inner header was never encrypted."""
    hb = bytes(header_bytes)
    if hb[:6] != MAGIC + b"\x0e\xae":
        raise ValueError("not a legacy AES splice (c1dd0001 0e ae prefix expected)")
    if isinstance(key, str):
        key = hashlib.sha256(key.encode("utf-8")).digest()
    if not (isinstance(key, (bytes, bytearray)) and len(key) == 32):
        raise ValueError("key must be 32 bytes or a passphrase string")
    inner_header = MAGIC + hb[6:]
    inner_body = _ecies.sym_decrypt(bytes(key), bytes(body_bytes))
    return inner_header, inner_body


def open_with_key(header_bytes, body_bytes, key):
    """Apply a released 32-byte key (or passphrase string) to any sealed
    0x0e quipu of either era. Returns (inner_header, inner_body).

    canonical ae/ca -> AES key · canonical ec -> session key ·
    legacy broadcast -> session key · legacy AES splice -> AES key.
    """
    cls = classify_encrypted(header_bytes)
    if cls == "canonical":
        sub = header_bytes[6]
        if sub in (SUB_AES, SUB_CENTINELA):
            parsed = read_encrypted_quipu(header_bytes, body_bytes, key=key)
        elif sub == SUB_ECIES:
            if isinstance(key, str):
                raise ValueError("an ECIES broadcast needs the 32-byte session key, not a passphrase")
            parsed = read_encrypted_quipu(header_bytes, body_bytes, session_key=key)
        else:
            raise ValueError(f"sub-family 0x{sub:02x} is not key-openable")
        return parsed["inner_header"], parsed["inner_body"]
    if cls == "legacy_aes":
        return read_legacy_aes_sealed(header_bytes, body_bytes, key)
    if cls == "legacy_broadcast":
        if isinstance(key, str):
            raise ValueError("a legacy broadcast needs the 32-byte session key, not a passphrase")
        parsed = read_legacy_broadcast_quipu(header_bytes, body_bytes, session_key=key)
        return parsed["inner_header"], parsed["inner_body"]
    raise ValueError(f"cannot key-open a {cls} quipu")


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
    if len(header_bytes) < 7:
        raise ValueError(f"header too short: {len(header_bytes)} bytes (need >= 7)")
    if header_bytes[4] != TYPE_ENCRYPTED:
        raise ValueError(f"not an encrypted quipu (type 0x{header_bytes[4]:02x}, expected 0x0e)")

    # Pre-canonical (2022) layouts dispatch to the legacy readers; they
    # return canonical-shaped dicts with legacy=True.
    cls = classify_encrypted(header_bytes)
    if cls == "legacy_drop":
        target_txid, k, title = parse_legacy_keydrop(header_bytes, body_bytes)
        return {
            "legacy": True, "sub_name": "legacy_drop", "sub_family": SUB_DROP,
            "variant": None, "tone": None, "title": title,
            "drops": [{"name": "", "ref_txid": target_txid, "key": k}],
        }
    if cls == "legacy_broadcast":
        return read_legacy_broadcast_quipu(
            header_bytes, body_bytes,
            my_privkey=my_privkey, author_pubkey=author_pubkey,
            session_key=session_key)
    if cls == "legacy_aes":
        out = {"legacy": True, "sub_name": "legacy_aes", "sub_family": SUB_AES,
               "variant": None, "tone": None, "title": ""}
        if key is not None:
            ih, ib = read_legacy_aes_sealed(header_bytes, body_bytes, key)
            out.update({"inner_header": ih, "inner_body": ib, "magic_ok": True})
        return out
    if len(header_bytes) < 8:
        raise ValueError(f"header too short: {len(header_bytes)} bytes (need >= 8)")

    tone = header_bytes[5]
    sub  = header_bytes[6]
    var  = header_bytes[7]
    rest = header_bytes[8:]
    title, _trail = _split_outer_title(rest)

    out = {
        "tone": tone, "sub_family": sub, "variant": var, "title": title,
        "sub_name": {SUB_AES: "aes", SUB_ECIES: "ecies", SUB_DROP: "drop",
                     SUB_CENTINELA: "centinela", SUB_CB: "cb",
                     SUB_SHAMIR: "shamir"}.get(sub, f"unknown_{sub:02x}"),
    }
    if sub == SUB_CENTINELA:
        out["title"], out["descriptor"], _ = parse_centinela_header(header_bytes)
    if sub == SUB_SHAMIR:
        if var == SHAMIR_VAULT:
            v = read_shamir_vault(header_bytes, body_bytes)
            out.update({"vault": True, "k": v["k"], "n": v["n"], "sealed": v["sealed"],
                        "inline": v["inline"], "n_records": len(v["records"]),
                        "dump_ref": v["dump_ref"]})
            return out
        p = read_shamir_share_quipu(header_bytes, body_bytes)
        out.update({k: p[k] for k in ("k", "n", "x", "commitment", "ref_txid", "share")})
        return out

    if sub in (SUB_AES, SUB_CENTINELA):
        if key is None:
            return out  # parse-only
        # The variant byte records how the key was DERIVED at build time
        # (0x00 raw, 0x01 = SHA256(passphrase)); either input form opens
        # either variant — a keydrop releases the derived 32-byte key, which
        # must open a password-variant quipu too.
        if isinstance(key, str):
            key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
        elif isinstance(key, (bytes, bytearray)) and len(key) == 32:
            key_bytes = bytes(key)
        else:
            raise ValueError("key must be 32 bytes or a passphrase string")
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

    if sub == SUB_CB:
        # Delegate to the dedicated reader, mapping the unified-reader's
        # kwargs to its interface:
        #   my_privkey   → session_privkey  (the buyer's recovered key)
        #   author_pubkey → sender_pubkey   (the seller's identity)
        cb_out = read_cb_box_quipu(
            header_bytes, body_bytes,
            session_privkey=my_privkey,
            sender_pubkey=author_pubkey,
        )
        out["session_pub"] = cb_out["session_pub"]
        if "inner_header" in cb_out:
            out["inner_header"] = cb_out["inner_header"]
            out["inner_body"]   = cb_out["inner_body"]
            out["magic_ok"]     = cb_out["magic_ok"]
        return out

    if sub == SUB_DROP:
        # Body: <count:2 BE> + N × (<namelen:1><name><txid:32><key:32>) + optional |TITLE|
        # If variant == DROP_SOURCED (0x01), the header also carries a
        # pipe-delimited descriptor tail right after the 8 structural bytes.
        if var == DROP_SOURCED:
            out["header_fields"] = parse_keydrop_header_fields(header_bytes)
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


def _selftest_cb_sale_box():
    """0x0e 0xcb committed-binding sale box: seal to a fresh session pubkey,
    decrypt with the session privkey + recovered sender pubkey."""
    h, b = _build_inner_text()
    seller_priv = CCPriv(b"\x01" * 32)        # seller's identity key
    session_priv = CCPriv(b"\x02" * 32)        # fresh per-sale session key
    oh, ob = build_cb_box_quipu(h, b, seller_priv,
                                session_priv.public_key,
                                title="On Custody — Preview",
                                tone=TONE_REVERENCE)
    print(f"=== 0x0e 0xcb sale box (single-session-recipient) ===")
    print(f"  outer header ({len(oh)} B): {oh.hex()[:80]}…")
    assert oh[5] == TONE_REVERENCE
    assert oh[6] == SUB_CB
    assert oh[7] == CB_SALE_V1
    # session_pub appears in body
    assert bytes(ob[:33]) == session_priv.public_key.format(compressed=True)
    print(f"  ✓ header bytes correct; session_pub embedded in body")

    # Parse-only (no keys): get title + session_pub
    parse_only = read_cb_box_quipu(oh, ob)
    assert parse_only["title"] == "On Custody — Preview"
    assert parse_only["session_pub"] == session_priv.public_key.format(compressed=True).hex()
    assert "inner_header" not in parse_only
    print(f"  ✓ parse-only yields title + session_pub")

    # Full decrypt with session_priv + sender_pub
    parsed = read_cb_box_quipu(oh, ob,
                                session_privkey=session_priv,
                                sender_pubkey=seller_priv.public_key)
    assert parsed["inner_header"] == h
    assert parsed["inner_body"] == b
    assert parsed["magic_ok"]
    print(f"  ✓ full decrypt OK with (session_priv, sender_pub)")

    # Wrong session_priv rejected
    wrong = CCPriv(b"\x99" * 32)
    try:
        read_cb_box_quipu(oh, ob,
                          session_privkey=wrong,
                          sender_pubkey=seller_priv.public_key)
        print(f"  ✗ wrong session_priv should have failed")
    except ValueError as e:
        print(f"  ✓ wrong session_priv rejected: {e}")

    # Unified reader dispatches to cb path
    via_unified = read_encrypted_quipu(oh, ob,
                                       my_privkey=session_priv,
                                       author_pubkey=seller_priv.public_key)
    assert via_unified["sub_name"] == "cb"
    assert via_unified["inner_header"] == h
    print(f"  ✓ read_encrypted_quipu dispatches to 0xcb path")

    # Refuse to seal to seller's own identity key (would be catastrophic)
    try:
        build_cb_box_quipu(h, b, seller_priv, seller_priv.public_key)
        print(f"  ✗ should have refused sealing to seller's identity")
    except ValueError as e:
        print(f"  ✓ refuses to seal to seller's identity: {e}")
    print()


def _selftest_keydrop_sourced():
    """Variant 0x01 — keydrop with header descriptor fields naming the
    claim tx that revealed the key in its scriptSig."""
    box_txid = "f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d"
    claim_txid = "dd57dbc9bcb1d3cb17a1d48ee3ae28e238d46726ec16a711d75ca1be4c75d882"
    key = bytes.fromhex("d7004970988f022000b4837a451555dc" + "00" * 16)
    oh, ob = build_keydrop_quipu(
        [("session", box_txid, key)],
        title="On Custody — session_priv",
        tone=TONE_AI,
        header_fields={"claim": claim_txid},
    )
    print(f"=== keydrop variant 0x01 (sourced — header fields) ===")
    print(f"  header ({len(oh)} B): {oh.hex()}")
    assert oh[6] == SUB_DROP
    assert oh[7] == DROP_SOURCED
    # Body shape unchanged
    assert struct.unpack(">H", ob[:2])[0] == 1
    print(f"  ✓ variant byte 0x01; body's count+drops layout unchanged")

    parsed = read_encrypted_quipu(oh, ob)
    assert parsed["sub_name"] == "drop"
    assert parsed["variant"] == DROP_SOURCED
    assert parsed["header_fields"]["claim"] == claim_txid
    assert parsed["drops"][0]["name"] == "session"
    assert parsed["drops"][0]["ref_txid"] == box_txid
    assert parsed["drops"][0]["key"] == key
    assert parsed["title"] == "On Custody — session_priv"
    print(f"  ✓ header_fields[claim] = {parsed['header_fields']['claim'][:24]}…")
    print(f"  ✓ drop name + ref + key round-trip")
    print(f"  ✓ title round-trips at end of body")

    # Variant 0x00 still works (backward compatible)
    oh0, ob0 = build_keydrop_quipu(
        [("session", box_txid, key)],
        title="On Custody — session_priv",
        tone=TONE_AI,
    )
    assert oh0[7] == DROP_RELEASE
    parsed0 = read_encrypted_quipu(oh0, ob0)
    assert parsed0["variant"] == DROP_RELEASE
    assert "header_fields" not in parsed0
    print(f"  ✓ variant 0x00 unchanged; no header_fields key in parsed output")
    print()


if __name__ == "__main__":
    _selftest_aes_raw()
    _selftest_aes_password()
    _selftest_ecies_single()
    _selftest_ecies_multi()
    _selftest_ecies_multisig_sender()
    _selftest_cb_sale_box()
    _selftest_keydrop_single()
    _selftest_keydrop_multi()
    _selftest_keydrop_sourced()
    _selftest_nested()
    _selftest_validation()
