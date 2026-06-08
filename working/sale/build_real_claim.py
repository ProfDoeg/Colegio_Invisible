"""
build_real_claim.py — given the buyer's actual funding outpoint, regenerate
the adaptor pre-sig over the REAL claim tx sighash, sign the claim tx,
and produce ready-to-broadcast artifacts.

Usage:
    .venv/bin/python working/sale/build_real_claim.py <funding_txid> <vout>

Example:
    .venv/bin/python working/sale/build_real_claim.py abc123...def 0

Produces:
    artifacts/claim_tx_signed.hex      — ready to broadcast
    artifacts/claim_tx_signed.txid     — its txid
    artifacts/offer_real.bin           — updated offer with real sighash
    artifacts/offer_real_ecies.bin     — re-encrypted offer to mi
    artifacts/draft_event_real.json    — updated kind:1729 draft
    artifacts/sale_manifest_real.json  — final manifest with real outpoints
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))
sys.path.insert(0, str(PROJECT / "working/sale"))

from coincurve import PrivateKey, PublicKey
from canonical.cert import build_sale_offer_cert, canonical_hash_of_sale_offer
from canonical import adaptor
from colegio_tools import import_privKey, import_pubKey
import ecies as _ecies_pkg
import cryptos

from build_sale import (
    build_sale_redeem_script, p2sh_address_from_script,
    compute_claim_tx_sighash, build_unsigned_claim_tx,
)

ARTIFACTS = PROJECT / "working/sale/artifacts"
KEY1_PATH = Path("~/Desktop/cinv/llaves/key1_prv.enc").expanduser()
MI_PUB    = Path("~/Desktop/cinv/llaves/mi_pub.bin").expanduser()
ERMITANO_XONLY = "7c88e9a4df6e9f45656c10bf66f28e28be235a15b64820b254f1b9eb2738314e"
SALE_TITLE  = "On Custody — Preview Sale"
PRICE_SATS  = 500_000_000
CURRENT_HEIGHT_ESTIMATE = 6_240_000
REFUND_BLOCKS = 1440


def sign_claim_tx_p2sh(unsigned_struct: dict, redeem_script: bytes,
                       seller_priv: PrivateKey,
                       session_priv: PrivateKey,
                       sighash: bytes) -> tuple:
    """Produce the fully-signed claim tx using the ADAPTOR-COMPLETED signature.

    The seller's signature is generated via adaptor completion (not standard
    ECDSA sign), so that publishing the claim tx publicly reveals session_priv.

    Returns (signed_tx_hex, signed_txid).
    """
    # 1. Generate adaptor pre-sig (we need it for completion)
    presig = adaptor.pre_sign(
        seller_priv.secret, sighash,
        session_priv.public_key.format(compressed=True),
    )
    # 2. Complete with session_priv
    r, s = adaptor.complete(presig, session_priv.secret)
    # 3. Encode as DER signature with SIGHASH_ALL appended
    der_sig = _encode_der_sig(r, s) + b"\x01"   # SIGHASH_ALL

    # 4. Build scriptSig: <sig> <OP_1 (claim branch)> <redeemScript>
    OP_1 = b"\x51"
    script_sig = (
        bytes([len(der_sig)]) + der_sig
        + OP_1
        + _push(redeem_script)
    )

    # 5. Assemble the signed tx
    version = bytes.fromhex(unsigned_struct["version"])
    prev_txid = bytes.fromhex(unsigned_struct["input"]["prev_txid"])[::-1]
    vout = unsigned_struct["input"]["vout"].to_bytes(4, "little")
    sequence = bytes.fromhex(unsigned_struct["input"]["sequence"])
    out_value = unsigned_struct["output"]["value_sats"].to_bytes(8, "little")
    out_spk = bytes.fromhex(cryptos.Doge().addrtoscript(unsigned_struct["output"]["address"]))
    out_spk_with_len = bytes([len(out_spk)]) + out_spk
    nlocktime = bytes.fromhex(unsigned_struct["nlocktime"])

    script_sig_len = len(script_sig)
    if script_sig_len < 0xfd:
        script_sig_len_bytes = bytes([script_sig_len])
    else:
        script_sig_len_bytes = b"\xfd" + script_sig_len.to_bytes(2, "little")

    signed_tx = (
        version
        + b"\x01" + prev_txid + vout + script_sig_len_bytes + script_sig + sequence
        + b"\x01" + out_value + out_spk_with_len
        + nlocktime
    )
    txid = hashlib.sha256(hashlib.sha256(signed_tx).digest()).digest()[::-1].hex()
    return signed_tx.hex(), txid, presig


def _push(data: bytes) -> bytes:
    L = len(data)
    if L < 0x4c:
        return bytes([L]) + data
    if L < 0x100:
        return bytes([0x4c, L]) + data
    if L < 0x10000:
        return bytes([0x4d]) + L.to_bytes(2, "little") + data
    raise ValueError("push data too large")


def _encode_der_sig(r: int, s: int) -> bytes:
    """Encode (r, s) as a DER ECDSA signature."""
    def _enc_int(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    r_enc = _enc_int(r)
    s_enc = _enc_int(s)
    body = r_enc + s_enc
    return b"\x30" + bytes([len(body)]) + body


def main():
    if len(sys.argv) != 3:
        print("Usage: build_real_claim.py <funding_txid> <vout>", file=sys.stderr)
        sys.exit(1)
    funding_txid = sys.argv[1]
    funding_vout = int(sys.argv[2])

    print("=" * 70)
    print(f"BUILDING REAL CLAIM TX")
    print(f"  funding outpoint: {funding_txid}:{funding_vout}")
    print("=" * 70)
    print()

    # Load keys
    key1_eth = import_privKey(str(KEY1_PATH), "")
    seller_priv = PrivateKey(key1_eth.to_bytes())
    seller_pub_hex = seller_priv.public_key.format(compressed=True).hex()
    seller_addr = cryptos.Doge().pubtoaddr(seller_pub_hex)

    mi_eth_pub = import_pubKey(str(MI_PUB))
    buyer_pub = PublicKey(b"\x04" + mi_eth_pub.to_bytes())
    buyer_pub_hex = buyer_pub.format(compressed=True).hex()

    # Load session key from artifacts (dry-run produced it)
    session_priv = PrivateKey(bytes.fromhex((ARTIFACTS / "session_priv.hex").read_text()))
    session_pub_hex = session_priv.public_key.format(compressed=True).hex()
    print(f"seller (El Gólem):  {seller_addr}")
    print(f"session_pub:        {session_pub_hex}")

    # Load box txid from artifacts
    box_root_txid = (ARTIFACTS / "box_root_txid.txt").read_text().strip()
    print(f"box_root_txid:      {box_root_txid}")
    print()

    # Reconstruct bond
    refund_height = CURRENT_HEIGHT_ESTIMATE + REFUND_BLOCKS
    redeem_script = build_sale_redeem_script(
        seller_pub_hex, refund_height, buyer_pub_hex,
    )
    bond_address = p2sh_address_from_script(redeem_script)
    print(f"bond P2SH:          {bond_address}")
    print()

    # Build the REAL unsigned claim tx
    fee_sats = 200_000
    claim_tx = build_unsigned_claim_tx(
        bond_outpoint_txid=funding_txid,
        bond_outpoint_vout=funding_vout,
        bond_value_sats=PRICE_SATS,
        dest_address=seller_addr,
        fee_sats=fee_sats,
    )
    sighash = compute_claim_tx_sighash(claim_tx, redeem_script)
    print(f"REAL claim tx sighash: {sighash.hex()}")
    print(f"claim output: {PRICE_SATS - fee_sats} sat → {seller_addr}")
    print()

    # Generate the adaptor pre-sig and complete it to produce the claim sig
    print("Building signed claim tx with adaptor-completed signature...")
    signed_hex, signed_txid, presig = sign_claim_tx_p2sh(
        claim_tx, redeem_script, seller_priv, session_priv, sighash,
    )
    print(f"signed claim tx ({len(signed_hex)//2} B)")
    print(f"signed claim txid: {signed_txid}")
    print()

    # Self-check: extract session_priv from the (completed) signature
    # by reading the scriptSig of the just-signed tx
    print("Self-verifying: can session_priv be extracted from the signed tx?")
    # Locate the signature in the scriptSig and reconstruct (r, s)
    # The scriptSig is <sig><01> OP_1 <push_redeem>
    # The signature is DER-encoded with SIGHASH_ALL byte appended
    # We can also just use the (r, s) tuple we got from complete()
    r_extracted = adaptor.extract_with_T(
        presig,
        (int.from_bytes(_extract_r_from_signed_tx(signed_hex), "big"),
         int.from_bytes(_extract_s_from_signed_tx(signed_hex), "big")),
        session_priv.public_key.format(compressed=True),
    )
    assert r_extracted == session_priv.secret, "extraction failed!"
    print(f"   ✓ session_priv extractable from signed tx: {r_extracted.hex()[:32]}...")
    print()

    # Rebuild the offer cert with the REAL sighash + presig
    print("Rebuilding offer cert with real sighash + adaptor pre-sig...")
    plaintext_hash = hashlib.sha256(
        # Recompute from box
        (ARTIFACTS / "box_body.bin").read_bytes()[-((ARTIFACTS / "box_body.bin").stat().st_size - 33 - 64):]
    ).hexdigest()  # Note: this is approximate; the dry-run already wrote the correct PlaintextHash
    # Read PlaintextHash from the previously-built offer to keep it canonical
    from canonical.cert import read_sale_offer_cert
    old_offer = read_sale_offer_cert(
        (ARTIFACTS / "offer_header.bin").read_bytes(),
        (ARTIFACTS / "offer_body.bin").read_bytes(),
    )
    plaintext_hash = old_offer["plaintext_hash"]

    h_unsigned, b_unsigned = build_sale_offer_cert(
        title=SALE_TITLE,
        box_txid=box_root_txid,
        session_pubkey_hex=session_pub_hex,
        bond_address=bond_address,
        redeem_script_hex=redeem_script.hex(),
        price_sats=PRICE_SATS,
        refund_height=refund_height,
        refund_pubkey_hex=buyer_pub_hex,
        seller_pubkey_hex=seller_pub_hex,
        claim_tx_sighash_hex=sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller_pub_hex)],
        signatures=None,
        plaintext_hash_hex=plaintext_hash,
        tone=0xa1,
    )
    canonical_hash = canonical_hash_of_sale_offer(b_unsigned)
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
        claim_tx_sighash_hex=sighash.hex(),
        adaptor_presig=presig,
        signers=[("seller", seller_pub_hex)],
        signatures=[("seller", sig_der.hex())],
        plaintext_hash_hex=plaintext_hash,
        tone=0xa1,
    )
    full_offer = h_offer + b_offer
    print(f"offer_real size: {len(full_offer)} B")
    print()

    # ECIES + draft event
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

    # Save artifacts
    (ARTIFACTS / "claim_tx_signed.hex").write_text(signed_hex)
    (ARTIFACTS / "claim_tx_signed.txid").write_text(signed_txid)
    (ARTIFACTS / "offer_real.bin").write_bytes(full_offer)
    (ARTIFACTS / "offer_real_ecies.bin").write_bytes(encrypted_blob)
    (ARTIFACTS / "draft_event_real.json").write_text(json.dumps(draft_event, indent=2))

    manifest = {
        "funding_outpoint": f"{funding_txid}:{funding_vout}",
        "bond_address": bond_address,
        "box_root_txid": box_root_txid,
        "claim_tx_signed_txid": signed_txid,
        "claim_tx_dest": seller_addr,
        "claim_payout_sats": PRICE_SATS - fee_sats,
        "session_pub": session_pub_hex,
        "offer_size_bytes": len(full_offer),
        "canonical_hash": canonical_hash.hex(),
        "ecies_blob_size": len(encrypted_blob),
        "build_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "next_steps": [
            "1. (Optional) Re-publish updated offer DM via scripts/nostr_publish.py "
            "with draft_event_real.json",
            f"2. Broadcast the signed claim tx — reveals session_priv publicly:\n"
            f"   dogecoin-cli sendrawtransaction $(cat {ARTIFACTS}/claim_tx_signed.hex)",
            "3. After claim confirms, run verify_claim_extraction.py to demonstrate "
            "session_priv extraction from the on-chain scriptSig and decrypt the box",
        ],
    }
    (ARTIFACTS / "sale_manifest_real.json").write_text(json.dumps(manifest, indent=2))

    print("=" * 70)
    print("REAL CLAIM TX READY")
    print("=" * 70)
    print(f"signed tx:    {ARTIFACTS}/claim_tx_signed.hex")
    print(f"its txid:     {signed_txid}")
    print(f"manifest:     {ARTIFACTS}/sale_manifest_real.json")
    print()
    print("To broadcast:")
    print(f"  /Users/anthonyschultz/Desktop/dogecoin/src/dogecoin-cli "
          f"sendrawtransaction $(cat {ARTIFACTS}/claim_tx_signed.hex)")


def _extract_r_from_signed_tx(signed_hex):
    """Pull the r bytes out of the DER sig in the signed tx's scriptSig."""
    # Find the start of the DER signature in the tx.
    # scriptSig starts after the input outpoint+sequence prefix.
    # Easier: just parse known offsets.
    tx = bytes.fromhex(signed_hex)
    # version(4) + input_count(1) + prev_txid(32) + vout(4) = 41
    cursor = 41
    # script_sig_len (varint) + script_sig
    sl = tx[cursor]
    if sl < 0xfd:
        cursor += 1
        script_sig_len = sl
    else:
        cursor += 3
        script_sig_len = int.from_bytes(tx[cursor-2:cursor], "little")
    # First push: the DER-encoded signature
    sig_push_len = tx[cursor]; cursor += 1
    # Skip the SIGHASH byte at the end
    der_sig = tx[cursor:cursor + sig_push_len - 1]
    # Parse DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    assert der_sig[0] == 0x30
    r_len = der_sig[3]
    r_bytes = der_sig[4:4 + r_len]
    if r_bytes[0] == 0x00:
        r_bytes = r_bytes[1:]
    return r_bytes


def _extract_s_from_signed_tx(signed_hex):
    tx = bytes.fromhex(signed_hex)
    cursor = 41
    sl = tx[cursor]
    if sl < 0xfd:
        cursor += 1
    else:
        cursor += 3
    sig_push_len = tx[cursor]; cursor += 1
    der_sig = tx[cursor:cursor + sig_push_len - 1]
    r_len = der_sig[3]
    s_start = 4 + r_len + 2  # skip r, then 0x02 + s_len
    s_len = der_sig[4 + r_len + 1]
    s_bytes = der_sig[s_start:s_start + s_len]
    if s_bytes[0] == 0x00:
        s_bytes = s_bytes[1:]
    return s_bytes


if __name__ == "__main__":
    main()
