"""
build_box_inscription.py — REAL artifacts for inscribing the 0x0e 0xcb box.

Uses quipu_diamond to build (NOT broadcast) the signed inscription
transactions, recovers the real predicted root txid, then rebuilds the
sale-offer cert with that real txid. Saves to working/sale/artifacts/.

After this runs:
  - artifacts/box_diamond/  — signed inscription txs (ready to broadcast)
  - artifacts/box_root_txid.txt — the real predicted root txid
  - artifacts/offer.bin     — rebuilt offer with real box_root_txid
  - artifacts/offer_ecies.bin — re-encrypted offer to mi
  - artifacts/draft_event.json — updated kind:1729 draft
  - artifacts/manifest_prod.json — production manifest
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from coincurve import PrivateKey, PublicKey
from canonical.essay import build_essay_quipu
from canonical.tone import TONE_AI
from canonical.encrypted import build_cb_box_quipu, _frame_inner
from canonical.cert import (
    build_sale_offer_cert, canonical_hash_of_sale_offer,
    read_sale_offer_cert,
)
from canonical import adaptor
from colegio_tools import import_privKey, import_pubKey
import quipu_diamond
from quipu_diamond import (
    build_consolidated_diamond, write_artifacts, FeePolicy,
)
import ecies as _ecies_pkg
import cryptos


# ---------- config ----------

KEY1_PATH    = Path("~/Desktop/cinv/llaves/key1_prv.enc").expanduser()
MI_PUB_PATH  = Path("~/Desktop/cinv/llaves/mi_pub.bin").expanduser()
ESSAY_PATH   = PROJECT / "working/sale/essay_on_custody.md"
ARTIFACTS    = PROJECT / "working/sale/artifacts"
BOX_DIAMOND  = ARTIFACTS / "box_diamond"

ARTIFACTS.mkdir(parents=True, exist_ok=True)

# Funding UTXO from Anthony's tx
FUNDING_UTXO = {
    "output": "c60e10d1b6c7af3986139b35712eaefe6d9286e40f311b6750778a10706a1236:1",
    "value":  3_000_000_000,   # 30 DOGE in sats
}

SALE_TITLE       = "On Custody — Preview Sale"
PRICE_DOGE       = 5.0
PRICE_SATS       = int(PRICE_DOGE * 100_000_000)
REFUND_BLOCKS    = 1440
CURRENT_HEIGHT_ESTIMATE = 6_240_000
ERMITANO_XONLY = "7c88e9a4df6e9f45656c10bf66f28e28be235a15b64820b254f1b9eb2738314e"

# Reuse the helpers from build_sale.py
sys.path.insert(0, str(PROJECT / "working/sale"))
from build_sale import (
    build_sale_redeem_script, p2sh_address_from_script,
    build_unsigned_claim_tx, compute_claim_tx_sighash,
)


def log(msg, indent=0):
    print(("  " * indent) + msg)


def main():
    print("=" * 70)
    print("BOX INSCRIPTION (production build, no broadcast)")
    print("=" * 70)

    # ---------- 1. Keys ----------
    log("1. Loading keys")
    key1_eth = import_privKey(str(KEY1_PATH), "")
    seller_priv = PrivateKey(key1_eth.to_bytes())
    seller_pub  = seller_priv.public_key
    seller_pub_hex = seller_pub.format(compressed=True).hex()
    # The cryptos library treats `priv_hex + "01"` as compressed-pubkey priv,
    # which derives the compressed Doge address (D-prefix) we want. Without
    # the suffix, cryptos derives the *uncompressed* address — a different one.
    seller_priv_hex = seller_priv.secret.hex() + "01"
    seller_addr = cryptos.Doge().pubtoaddr(seller_pub_hex)
    log(f"seller (El Gólem) addr: {seller_addr}", 1)

    mi_eth_pub = import_pubKey(str(MI_PUB_PATH))
    buyer_pub = PublicKey(b"\x04" + mi_eth_pub.to_bytes())
    buyer_pub_hex = buyer_pub.format(compressed=True).hex()
    log(f"buyer (El Ermitaño) pubkey: {buyer_pub_hex[:32]}...", 1)
    print()

    # ---------- 2. Session keypair ----------
    log("2. Generating fresh session keypair")
    session_priv = PrivateKey()
    session_pub  = session_priv.public_key
    session_pub_hex = session_pub.format(compressed=True).hex()
    log(f"session_pub: {session_pub_hex}", 1)
    print()

    # ---------- 3. Build the inner essay and seal as box ----------
    log("3. Sealing the essay as a 0x0e 0xcb box")
    essay_md = ESSAY_PATH.read_text(encoding="utf-8")
    inner_h, inner_b = build_essay_quipu(
        title="On Custody",
        body_markdown=essay_md,
        tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-18", "lang": "en"},
    )
    box_h, box_b = build_cb_box_quipu(
        inner_h, inner_b, seller_priv, session_pub,
        title=SALE_TITLE, tone=TONE_AI,
    )
    box_blob = box_h + box_b
    log(f"box size: {len(box_blob)} B "
        f"(header {len(box_h)} + body {len(box_b)})", 1)
    framed_inner = _frame_inner(inner_h, inner_b)
    plaintext_hash = hashlib.sha256(framed_inner).hexdigest()
    log(f"PlaintextHash: {plaintext_hash[:32]}...", 1)
    print()

    # ---------- 4. Build inscription artifacts (signed, NOT broadcast) ----------
    log("4. Building consolidated diamond inscription (offline signing)")

    def placeholder_of(pid):
        # The box has no internal cross-references — placeholder unused
        return "00" * 32

    pieces = [("box", box_blob)]
    fp = FeePolicy(rate_kb=0.10)
    log(f"FeePolicy: {fp.describe()}", 1)
    log("running build_consolidated_diamond...", 1)
    # Save UTXO values before the engine mutates the dict (cryptos.mktx
    # in-place renames "output" → "outpoint" or similar).
    funding_txid = FUNDING_UTXO["output"].split(":")[0]
    funding_vout = int(FUNDING_UTXO["output"].split(":")[1])
    funding_value = FUNDING_UTXO["value"]
    art = build_consolidated_diamond(
        pieces=pieces,
        placeholder_of=placeholder_of,
        utxo=dict(FUNDING_UTXO),                     # pass a copy
        priv=seller_priv_hex,
        address=seller_addr,
        fee_policy=fp,
        log=lambda m: log(m, 2),
    )

    # Get the box's predicted root txid
    box_root_hex, box_root_txid = art["roots"]["box"]
    splitter_hex, splitter_txid = art["splitter"]
    join_hex, join_txid = art["join"]
    log(f"✓ box root txid (predicted): {box_root_txid}", 1)
    log(f"  splitter txid:             {splitter_txid}", 1)
    log(f"  join txid:                 {join_txid}", 1)

    # Persist artifacts
    BOX_DIAMOND.mkdir(parents=True, exist_ok=True)
    write_artifacts(art, str(BOX_DIAMOND))
    log(f"  signed-tx artifacts written to {BOX_DIAMOND}/", 1)
    (ARTIFACTS / "box_root_txid.txt").write_text(box_root_txid + "\n")
    print()

    # ---------- 5. Construct HTLC bond ----------
    log("5. Constructing HTLC bond")
    refund_height = CURRENT_HEIGHT_ESTIMATE + REFUND_BLOCKS
    redeem_script = build_sale_redeem_script(
        seller_pub_hex, refund_height, buyer_pub_hex,
    )
    bond_address = p2sh_address_from_script(redeem_script)
    log(f"bond P2SH: {bond_address}", 1)
    log(f"refund_height: {refund_height}", 1)
    print()

    # ---------- 6. Placeholder claim tx + adaptor pre-sig ----------
    log("6. Building unsigned claim tx + adaptor pre-sig")
    log("   NOTE: funding outpoint is still a placeholder. Production sale", 1)
    log("   requires a Nostr round-trip with the buyer (their unsigned", 1)
    log("   funding tx's txid) before generating the real adaptor.", 1)
    placeholder_funding_txid = hashlib.sha256(
        b"FUNDING_TX_PLACEHOLDER||" + bond_address.encode()
    ).hexdigest()
    fee_sats = 200_000
    claim_tx = build_unsigned_claim_tx(
        bond_outpoint_txid=placeholder_funding_txid,
        bond_outpoint_vout=0,
        bond_value_sats=PRICE_SATS,
        dest_address=seller_addr,
        fee_sats=fee_sats,
    )
    claim_sighash = compute_claim_tx_sighash(claim_tx, redeem_script)
    presig = adaptor.pre_sign(
        seller_priv.secret, claim_sighash,
        session_pub.format(compressed=True),
    )
    assert adaptor.pre_verify(
        seller_pub.format(compressed=True), claim_sighash,
        session_pub.format(compressed=True), presig,
    )
    log("✓ adaptor pre-sig generated and self-verifies", 1)
    print()

    # ---------- 7. Compose & sign offer cert ----------
    log("7. Composing and signing offer cert")
    h_offer_unsigned, b_offer_unsigned = build_sale_offer_cert(
        title=SALE_TITLE,
        box_txid=box_root_txid,                        # ← REAL txid now
        session_pubkey_hex=session_pub_hex,
        bond_address=bond_address,
        redeem_script_hex=redeem_script.hex(),
        price_sats=PRICE_SATS,
        refund_height=refund_height,
        refund_pubkey_hex=buyer_pub_hex,
        seller_pubkey_hex=seller_pub_hex,
        claim_tx_sighash_hex=claim_sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller_pub_hex)],
        signatures=None,
        plaintext_hash_hex=plaintext_hash,
        tone=TONE_AI,
    )
    canonical_hash = canonical_hash_of_sale_offer(b_offer_unsigned)
    sig_der = seller_priv.sign(canonical_hash, hasher=None)
    h_offer, b_offer = build_sale_offer_cert(
        title=SALE_TITLE,
        box_txid=box_root_txid,
        session_pubkey_hex=session_pub_hex,
        bond_address=bond_address,
        redeem_script_hex=redeem_script.hex(),
        price_sats=PRICE_SATS,
        refund_height=refund_height,
        refund_pubkey_hex=buyer_pub_hex,
        seller_pubkey_hex=seller_pub_hex,
        claim_tx_sighash_hex=claim_sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller_pub_hex)],
        signatures=[("seller", sig_der.hex())],
        plaintext_hash_hex=plaintext_hash,
        tone=TONE_AI,
    )
    full_offer = h_offer + b_offer
    log(f"signed offer: {len(full_offer)} B", 1)
    log(f"  Box: <<{box_root_txid}>>", 1)
    log(f"  canonical hash: {canonical_hash.hex()[:32]}...", 1)
    print()

    # ---------- 8. ECIES + kind:1729 draft ----------
    log("8. ECIES-encrypting and building kind:1729 draft")
    encrypted_blob = _ecies_pkg.encrypt(mi_eth_pub.to_hex(), full_offer)
    draft_event = {
        "kind": 1729,
        "content": base64.b64encode(encrypted_blob).decode(),
        "tags": [
            ["p",   ERMITANO_XONLY],
            ["enc", "ecies-v1"],
            ["t",   "colegio-dm"],
            ["t",   "verified-key-sale"],
            ["i",   f"quipu:{box_root_txid}"],
        ],
    }
    print()

    # ---------- 9. Write artifacts + manifest ----------
    log("9. Writing artifacts")
    (ARTIFACTS / "box.bin").write_bytes(box_blob)
    (ARTIFACTS / "box_header.bin").write_bytes(box_h)
    (ARTIFACTS / "box_body.bin").write_bytes(box_b)
    (ARTIFACTS / "offer.bin").write_bytes(full_offer)
    (ARTIFACTS / "offer_header.bin").write_bytes(h_offer)
    (ARTIFACTS / "offer_body.bin").write_bytes(b_offer)
    (ARTIFACTS / "offer_ecies.bin").write_bytes(encrypted_blob)
    (ARTIFACTS / "redeem_script.bin").write_bytes(redeem_script)
    (ARTIFACTS / "session_priv.hex").write_text(session_priv.secret.hex())
    (ARTIFACTS / "session_pub.hex").write_text(session_pub_hex)
    (ARTIFACTS / "presig.json").write_text(json.dumps(presig, indent=2))
    (ARTIFACTS / "draft_event.json").write_text(json.dumps(draft_event, indent=2))

    manifest = {
        "scenario": "El Gólem → El Ermitaño verified-key sale (PRODUCTION build, no broadcasts)",
        "sale_title": SALE_TITLE,
        "price_doge": PRICE_DOGE,
        "price_sats": PRICE_SATS,
        "funding": {
            "txid": funding_txid,
            "vout": funding_vout,
            "value_sats": funding_value,
            "value_doge": funding_value / 1e8,
            "status": "mempool/awaiting confirmations as of build time",
        },
        "box": {
            "size_bytes": len(box_blob),
            "predicted_root_txid": box_root_txid,
            "splitter_txid": splitter_txid,
            "join_txid": join_txid,
            "diamond_artifacts_dir": str(BOX_DIAMOND),
        },
        "bond_PLACEHOLDER": {
            "p2sh_address": bond_address,
            "redeem_script_hex": redeem_script.hex(),
            "refund_height": refund_height,
            "note": (
                "Bond P2SH is real and reproducible. Adaptor pre-sig is over"
                " a PLACEHOLDER funding outpoint. Real production requires"
                " a Nostr round-trip with the buyer to fill in the real"
                " funding outpoint before the offer is final."
            ),
        },
        "offer_cert": {
            "size_bytes": len(full_offer),
            "canonical_hash": canonical_hash.hex(),
            "signed_by_seller": True,
        },
        "nostr_draft": {
            "kind": 1729,
            "recipient_xonly": ERMITANO_XONLY,
            "ecies_blob_size_bytes": len(encrypted_blob),
            "publish_command": (
                ".venv/bin/python scripts/nostr_publish.py "
                "~/Desktop/cinv/llaves/key1_prv.enc "
                "working/sale/artifacts/draft_event.json ''"
            ),
        },
        "next_steps_for_anthony": [
            "1. Wait for funding tx to confirm (1+ block)",
            "2. Review box_diamond/ artifacts (signed but not broadcast)",
            "3. Run quipu_diamond.broadcast_consolidated_diamond to inscribe the box",
            "4. After box confirms, the box_root_txid in this manifest matches reality",
            "5. (Open question) Real production needs a Nostr round-trip with the"
            "   buyer to replace the placeholder funding outpoint before the offer"
            "   is operationally final. For this first run, decide: ship as-is (with"
            "   placeholder claim tx, demonstrating architecture), or coordinate the"
            "   round-trip and rebuild with real funding outpoint.",
        ],
        "build_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (ARTIFACTS / "manifest_prod.json").write_text(json.dumps(manifest, indent=2))
    log(f"  manifest_prod.json written", 1)
    print()

    print("=" * 70)
    print("PRODUCTION BUILD COMPLETE — no broadcasts yet")
    print("=" * 70)
    print(f"box_root_txid (predicted): {box_root_txid}")
    print(f"signed inscription txs:    {BOX_DIAMOND}/")
    print(f"updated offer + draft:     {ARTIFACTS}/")
    print(f"manifest:                  {ARTIFACTS}/manifest_prod.json")


if __name__ == "__main__":
    main()
