"""Nostr publishing primitives for Colegio Invisible quipus.

Uses the SAME secp256k1 privkeys as the project's Doge addresses —
apocrypha, multiman, ha, ca, bordado, and the other personas already
have keys; this module lets them publish Schnorr-signed Nostr events
under their npub equivalents without new key management.

Design intent (see docs/guides/nostr-integration.md for the full spec):
    chain = monument            permanent inscriptions, paid in DOGE
    nostr = doorbell + transient real-time announcements, free, replaceable

The chain is always the source of truth. Nostr is the discovery /
notification / transient-commentary layer.

Conventions:
    - Authors keep the same persona across substrates. El Ermitaño's
      Nostr identity is derived from apocrypha's privkey; El Gólem's
      from multiman's; etc.
    - Quipu announcements carry an ["i", "quipu:<txid>"] tag (NIP-73
      external content reference) so Nostr clients can index and link
      back to the canonical on-chain inscription.

Requires:
    coincurve >= 16   (Schnorr signing — already in env at 21.0.0)
    websockets        (only for publish_event(); not needed to build/sign)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

import coincurve


# ---------------------------------------------------------------------------
# House relays + standard event kinds
# ---------------------------------------------------------------------------

# Canonical Colegio relay set. Authors are free to publish elsewhere; these
# are the defaults chosen for breadth (relay.damus.io, nos.lol) plus a
# searchable archive (relay.nostr.band).
DEFAULT_RELAYS = (
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
)

# Standard Nostr event kinds we use (per NIP-01 + NIPs referenced).
KIND_TEXT_NOTE     = 1       # short note — default for quipu announcements
KIND_LONG_FORM     = 30023   # NIP-23 article — mirrors of 0x01 essays
KIND_FILE_METADATA = 1063    # NIP-94 — mirrors of 0x03 image quipus


# ---------------------------------------------------------------------------
# Key derivation — same secp256k1 privkey, x-only pubkey for Nostr
# ---------------------------------------------------------------------------

def privkey_to_xonly_pubkey(privkey_hex):
    """Return the 32-byte x-only pubkey (64 hex chars) for a Nostr identity.

    This is the BIP-340 x-only encoding that Nostr inherited. The same
    secp256k1 privkey signs ECDSA for Doge and Schnorr for Nostr.
    """
    if isinstance(privkey_hex, bytes):
        privkey_hex = privkey_hex.hex()
    if len(privkey_hex) != 64:
        raise ValueError(f"privkey hex must be 64 chars, got {len(privkey_hex)}")
    priv = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    return priv.public_key_xonly.format().hex()


# ---------------------------------------------------------------------------
# Bech32 encoding (NIP-19 — npub1…, nsec1…, note1…, nevent1…)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN     = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]


def _bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits = 0, 0
    ret, maxv = [], (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value in bech32 conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, data_bytes):
    """Encode raw bytes as a bech32 string with the given HRP prefix."""
    data = _convertbits(list(data_bytes), 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def to_bech32_npub(xonly_pubkey_hex):
    """Format an x-only pubkey as 'npub1…' for human display."""
    if len(xonly_pubkey_hex) != 64:
        raise ValueError("x-only pubkey hex must be 64 chars")
    return bech32_encode("npub", bytes.fromhex(xonly_pubkey_hex))


def to_bech32_note(event_id_hex):
    """Format an event id as 'note1…' (NIP-19 short form)."""
    if len(event_id_hex) != 64:
        raise ValueError("event id hex must be 64 chars")
    return bech32_encode("note", bytes.fromhex(event_id_hex))


# ---------------------------------------------------------------------------
# Event construction — canonical serialization, id, Schnorr signature
# ---------------------------------------------------------------------------

def _canonical_serialize(pubkey, created_at, kind, tags, content):
    """The exact byte serialization Nostr uses to compute event ids.

    Per NIP-01: JSON array [0, pubkey, created_at, kind, tags, content]
    with the tightest separators and no escaping of non-ASCII.
    """
    return json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_event(privkey_hex, kind, content, tags=None, created_at=None):
    """Construct, hash, and Schnorr-sign a Nostr event.

    Args:
        privkey_hex: 64-char hex secp256k1 privkey (same key used to sign
                     Doge transactions for this persona).
        kind:        Integer event kind. See module constants.
        content:     str — the event content (markdown OK, plain text OK).
        tags:        list[list[str]] — NIP-01 tags. Default [].
        created_at:  Unix seconds. Default: now.

    Returns:
        dict with id, pubkey, created_at, kind, tags, content, sig.
        Ready to wrap as ["EVENT", event] and send to a relay.
    """
    tags = tags or []
    if created_at is None:
        created_at = int(time.time())
    if not isinstance(content, str):
        raise TypeError("content must be a str")

    pubkey = privkey_to_xonly_pubkey(privkey_hex)
    serial = _canonical_serialize(pubkey, created_at, kind, tags, content)
    event_id = hashlib.sha256(serial).hexdigest()

    priv = coincurve.PrivateKey(bytes.fromhex(privkey_hex))
    sig = priv.sign_schnorr(bytes.fromhex(event_id))

    return {
        "id":         event_id,
        "pubkey":     pubkey,
        "created_at": created_at,
        "kind":       kind,
        "tags":       tags,
        "content":    content,
        "sig":        sig.hex(),
    }


def verify_event(event):
    """Verify a received event's id and Schnorr signature.

    Returns True on success, False on any failure (bad id, bad sig).
    Useful for validating events read back from relays.
    """
    try:
        serial = _canonical_serialize(
            event["pubkey"], event["created_at"], event["kind"],
            event["tags"], event["content"])
        if hashlib.sha256(serial).hexdigest() != event["id"]:
            return False
        pub = coincurve.PublicKeyXOnly(bytes.fromhex(event["pubkey"]))
        return pub.verify(bytes.fromhex(event["sig"]),
                          bytes.fromhex(event["id"]))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Async publication to relays
# ---------------------------------------------------------------------------

async def _publish_one(relay_url, event, timeout):
    """Publish to a single relay; return (url, parsed_reply).

    Reply on success: ["OK", <event_id>, true, ""]
    Reply on rejection: ["OK", <event_id>, false, "reason: ..."]
    """
    import websockets  # imported lazily so building events doesn't require it
    msg = json.dumps(["EVENT", event])
    try:
        async with websockets.connect(relay_url, open_timeout=timeout) as ws:
            await ws.send(msg)
            reply = await asyncio.wait_for(ws.recv(), timeout=timeout)
            return relay_url, json.loads(reply)
    except Exception as e:
        return relay_url, ["ERROR", type(e).__name__, str(e)]


async def publish_event_async(event, relays=DEFAULT_RELAYS, timeout=10):
    """Publish a signed event to multiple relays concurrently.

    Returns:
        list of (relay_url, parsed_reply) tuples.
    """
    return list(await asyncio.gather(
        *[_publish_one(r, event, timeout) for r in relays]))


def publish_event(event, relays=DEFAULT_RELAYS, timeout=10):
    """Sync wrapper around publish_event_async()."""
    return asyncio.run(publish_event_async(event, relays, timeout))


# ---------------------------------------------------------------------------
# Quipu-specific conventions — the announcement event shape
# ---------------------------------------------------------------------------

def quipu_announcement(privkey_hex, root_txid, title, type_byte_hex,
                       author=None, body=None, kind=KIND_TEXT_NOTE,
                       extra_tags=None, created_at=None):
    """Build (don't publish) an announcement event for an inscribed quipu.

    Tag convention:
        ["i",     f"quipu:{root_txid}"]   NIP-73 external content ref
        ["t",     "quipu"]                discovery tag
        ["type",  type_byte_hex]          e.g. "0x3d"
        ["title", title]
        ["author", author]                if provided

    Args:
        privkey_hex:    the persona's secp256k1 privkey (Doge + Nostr).
        root_txid:      the quipu's root txid (the canonical identifier).
        title:          the quipu's title.
        type_byte_hex:  e.g. "0x3d", "0x01", "0x09".
        author:         e.g. "El Ermitaño". Optional.
        body:           content text. Default: "{title}\\n\\nquipu:{txid}".
        kind:           default KIND_TEXT_NOTE (1). Use KIND_LONG_FORM
                        (30023) when mirroring full essay bodies.
        extra_tags:     extra tag rows to append.
        created_at:     unix seconds, default now.

    Returns:
        a signed event dict, ready for publish_event().
    """
    if len(root_txid) != 64:
        raise ValueError("root_txid must be 64 hex chars")

    tags = [
        ["i",     "quipu:" + root_txid],
        ["t",     "quipu"],
        ["type",  type_byte_hex],
        ["title", title],
    ]
    if author:
        tags.append(["author", author])
    if extra_tags:
        tags.extend(extra_tags)

    if body is None:
        body = title + "\n\nquipu:" + root_txid

    return build_event(privkey_hex, kind, body,
                       tags=tags, created_at=created_at)


# ---------------------------------------------------------------------------
# Self-tests (no network — use a known test-vector key)
# ---------------------------------------------------------------------------

# secp256k1 privkey = 1 (BIP-340 test vector 0). Known-good x-only pubkey:
_TEST_PRIVKEY = "0000000000000000000000000000000000000000000000000000000000000001"
_TEST_XONLY   = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _selftest_pubkey_derivation():
    """privkey=1 derives the canonical secp256k1 generator's x-coordinate."""
    got = privkey_to_xonly_pubkey(_TEST_PRIVKEY)
    assert got == _TEST_XONLY, (
        "x-only pubkey derivation mismatch:\n"
        "  got:      " + got + "\n"
        "  expected: " + _TEST_XONLY)
    print("  derivation OK — privkey=1 -> " + got[:16] + "...")


def _selftest_bech32_npub():
    """Round-trip a known x-only pubkey to npub1... NIP-19 form."""
    npub = to_bech32_npub(_TEST_XONLY)
    assert npub.startswith("npub1"), "wrong prefix: " + npub
    assert len(npub) == 63, "wrong length: " + str(len(npub))
    print("  bech32 OK    — " + npub)


def _selftest_event_id_deterministic():
    """Build an event with fixed inputs; verify the id matches a
    re-computed canonical serialization."""
    ev = build_event(_TEST_PRIVKEY, kind=1, content="hello world",
                     tags=[["t", "test"]], created_at=1000000000)
    expected_serial = _canonical_serialize(
        ev["pubkey"], 1000000000, 1, [["t", "test"]], "hello world")
    expected_id = hashlib.sha256(expected_serial).hexdigest()
    assert ev["id"] == expected_id, "id mismatch"
    print("  id OK        — " + ev["id"][:16] + "...")


def _selftest_signature_verifies():
    """Build, then verify with the verify_event helper."""
    ev = build_event(_TEST_PRIVKEY, kind=1, content="verify me",
                     tags=[], created_at=1000000000)
    assert verify_event(ev), "self-built event failed verification"

    # Tampering with content invalidates the id check:
    tampered = dict(ev); tampered["content"] = "modified"
    assert not verify_event(tampered), "tampered event passed verification"
    print("  signature OK — verify_event accepts good, rejects tampered")


def _selftest_announcement_shape():
    """Verify the quipu_announcement() helper builds the conventional tags."""
    ev = quipu_announcement(
        _TEST_PRIVKEY,
        root_txid="1f63558b" + "0" * 56,
        title="Cementerio de los Animales",
        type_byte_hex="0x3d",
        author="El Ermitaño")
    keys = [t[0] for t in ev["tags"]]
    for required in ("i", "t", "type", "title", "author"):
        assert required in keys, "missing tag " + required
    i_tag = next(t for t in ev["tags"] if t[0] == "i")
    assert i_tag[1].startswith("quipu:"), "i tag wrong: " + str(i_tag)
    assert verify_event(ev), "announcement signature failed"
    print("  announcement OK — tags " + str(keys))


if __name__ == "__main__":
    print("canonical/nostr.py self-tests:")
    _selftest_pubkey_derivation()
    _selftest_bech32_npub()
    _selftest_event_id_deterministic()
    _selftest_signature_verifies()
    _selftest_announcement_shape()
    print("all nostr self-tests passed.")
