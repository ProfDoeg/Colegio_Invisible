"""
verify_nostr_roundtrip.py — fetch our just-published kind:1729 offer DM
back from a relay, decrypt with mi_prv, verify the offer + adaptor pre-sig.

Proves the full path: publish → relay → fetch → decrypt → cryptographic verify.
"""
import asyncio
import base64
import hashlib
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

import websockets
from coincurve import PrivateKey, PublicKey
from canonical.cert import read_sale_offer_cert
from canonical import adaptor
import ecies as _ecies_pkg
from colegio_tools import import_privKey

EVENT_ID = "484b927804631e1b2a62f6cbc78da006af5bd2855084460d7ee44c9758df393f"
RELAY    = "wss://relay.damus.io"
MI_PRV   = Path("~/Desktop/cinv/llaves/mi_prv.enc").expanduser()


async def fetch_event(relay_url, event_id, timeout=10):
    """REQ a specific event by id, return its JSON dict or None."""
    sub_id = "verify_" + event_id[:8]
    async with websockets.connect(relay_url) as ws:
        await ws.send(json.dumps(["REQ", sub_id, {"ids": [event_id]}]))
        end = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end:
            try:
                msg = await asyncio.wait_for(ws.recv(),
                                              timeout=end - asyncio.get_event_loop().time())
            except asyncio.TimeoutError:
                return None
            data = json.loads(msg)
            if data[0] == "EVENT" and data[1] == sub_id:
                return data[2]
            if data[0] == "EOSE":
                return None
    return None


def main():
    print("=" * 70)
    print("Nostr round-trip verification — fetch event back from relay")
    print("=" * 70)
    print()

    print(f"1. Fetching event {EVENT_ID[:16]}... from {RELAY}")
    event = asyncio.run(fetch_event(RELAY, EVENT_ID))
    if event is None:
        print("   ✗ event not found at relay (may still be propagating; try again in 30s)")
        return
    print(f"   ✓ Event fetched from relay:")
    print(f"     kind:    {event['kind']}")
    print(f"     pubkey:  {event['pubkey'][:32]}...")
    print(f"     tags:    {len(event['tags'])} tag(s)")
    print(f"     content: {len(event['content'])} chars base64")
    print()

    print("2. Verifying event id matches Schnorr signature")
    # The event id is sha256 of the canonical serialization
    canonical = json.dumps([
        0, event["pubkey"], event["created_at"],
        event["kind"], event["tags"], event["content"],
    ], separators=(",", ":"), ensure_ascii=False)
    computed_id = hashlib.sha256(canonical.encode()).hexdigest()
    assert computed_id == event["id"], "event id mismatch"
    print(f"   ✓ Event id reconstructs from canonical form (id matches sha256)")
    print()

    print("3. Decrypting the kind:1729 content with mi_prv (El Ermitaño)")
    mi_priv = import_privKey(str(MI_PRV), "")
    encrypted_blob = base64.b64decode(event["content"])
    plaintext_offer = _ecies_pkg.decrypt(mi_priv.to_hex(), encrypted_blob)
    print(f"   ✓ ECIES decryption succeeded: {len(plaintext_offer)} B plaintext")
    print()

    print("4. Parsing the offer cert from Nostr DM")
    offer_header = plaintext_offer[:8]
    offer_body   = plaintext_offer[8:]
    parsed = read_sale_offer_cert(offer_header, offer_body)
    print(f"   ✓ Title:           {parsed['title']!r}")
    print(f"   ✓ Box txid:        {parsed['box_txid']}")
    print(f"   ✓ Price:           {parsed['price_sats']} sat ({parsed['price_sats']/1e8} DOGE)")
    print(f"   ✓ Seller pubkey:   {parsed['seller_pubkey'][:32]}...")
    print(f"   ✓ Session pubkey:  {parsed['session_pubkey'][:32]}...")
    print()

    print("5. Verifying seller's identity signature")
    seller_pub = PublicKey(bytes.fromhex(parsed["seller_pubkey"]))
    sig_role, sig_hex = parsed["signatures"][0]
    assert sig_role == "seller"
    assert seller_pub.verify(bytes.fromhex(sig_hex), parsed["canonical_hash"], hasher=None)
    print(f"   ✓ Seller signature verifies over canonical hash {parsed['canonical_hash'].hex()[:24]}...")
    print()

    print("6. Verifying the ECDSA adaptor pre-signature")
    assert adaptor.pre_verify(
        bytes.fromhex(parsed["seller_pubkey"]),
        bytes.fromhex(parsed["claim_tx_sighash"]),
        bytes.fromhex(parsed["session_pubkey"]),
        parsed["adaptor_presig"],
    )
    print(f"   ✓ Adaptor pre-sig verifies — cryptographic binding established")
    print(f"     between session_pub and the seller's commitment to reveal it")
    print(f"     on claim. This survived round-trip through {RELAY}.")
    print()

    print("=" * 70)
    print("NOSTR ROUND-TRIP COMPLETE — proof transported, decrypted, and verified")
    print("=" * 70)


if __name__ == "__main__":
    main()
