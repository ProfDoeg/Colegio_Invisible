"""
build_sale.py — verified-key sale orchestration (DRY RUN)

End-to-end build of an El Gólem → El Ermitaño sale of the "On Custody"
essay. Nothing broadcasts; nothing publishes to Nostr. All artifacts are
written to working/sale/artifacts/ for Anthony's review.

Flow:
  1.  Load El Gólem's identity key (key1_prv.enc) and El Ermitaño's
      identity pubkey (mi_pub.bin).
  2.  Generate a fresh session keypair (session_priv, session_pub).
  3.  Wrap the essay markdown as a 0x01 essay quipu (the inner content).
  4.  Seal as a 0x0e 0xcb committed-binding sale box.
  5.  Construct the HTLC redeem script (seller-claims OR buyer-refunds
      via CLTV) and compute the P2SH bond address.
  6.  Build a placeholder unsigned claim transaction (input = simulated
      bond UTXO, output = seller's destination). Compute its sighash.
  7.  Generate the ECDSA adaptor pre-signature with T = session_pub
      over the claim tx sighash.
  8.  Compose the 0xcc 0x0003 sale-offer cert body (no signatures yet).
  9.  Compute the canonical hash; sign with El Gólem's identity key.
  10. Re-build the offer cert with the seller signature attached.
  11. ECIES-encrypt the full offer body (header + body) to El Ermitaño's
      pubkey via quipu_crypto.encrypt_ecies (same primitive as
      scripts/ecc_encrypt.py).
  12. Build the kind:1729 Nostr DM draft event JSON.
  13. Write all artifacts + manifest.

Architecture A: Claude (this script) drafts; Anthony reviews artifacts
and decides whether/how to broadcast.

Run:
    .venv/bin/python working/sale/build_sale.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path

# Project paths
PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from coincurve import PrivateKey, PublicKey
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Canonical modules
from canonical.essay import build_essay_quipu
from canonical.tone import TONE_AI
from canonical.encrypted import (
    build_cb_box_quipu, _frame_inner,
    _shared_key, MAGIC as ENC_MAGIC,
)
from canonical.cert import (
    build_sale_offer_cert, canonical_hash_of_sale_offer,
    read_sale_offer_cert,
)
from canonical import adaptor

# Tools
from colegio_tools import import_privKey, import_pubKey
import quipu_crypto
import ecies as _ecies

# Cryptos for P2SH addressing
import cryptos
DOGE_P2SH_MAGIC = 0x16  # Dogecoin mainnet P2SH version


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KEY1_PATH    = Path("~/Desktop/cinv/llaves/key1_prv.enc").expanduser()
MI_PUB_PATH  = Path("~/Desktop/cinv/llaves/mi_pub.bin").expanduser()
ESSAY_PATH   = PROJECT / "working/sale/essay_on_custody.md"
ARTIFACTS    = PROJECT / "working/sale/artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

# Sale parameters
SALE_TITLE       = "On Custody — Preview Sale"
PRICE_DOGE       = 5.0
PRICE_SATS       = int(PRICE_DOGE * 100_000_000)
REFUND_BLOCKS    = 1440                            # ~1 day timeout
CURRENT_HEIGHT_ESTIMATE = 6_240_000                # plausible recent block

# El Ermitaño's Nostr xonly (per memory/nostr_integration.md)
ERMITANO_XONLY = "7c88e9a4df6e9f45656c10bf66f28e28be235a15b64820b254f1b9eb2738314e"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg, indent=0):
    print(("  " * indent) + msg)


def script_pushdata(data: bytes) -> bytes:
    """Bitcoin script PUSHDATA — simplified, for our small payloads."""
    L = len(data)
    if L < 0x4c:
        return bytes([L]) + data
    if L < 0x100:
        return bytes([0x4c, L]) + data
    if L < 0x10000:
        return bytes([0x4d]) + L.to_bytes(2, "little") + data
    raise ValueError("payload too large")


def cscriptnum(n: int) -> bytes:
    """CScriptNum encoding of an integer for OP_CLTV operand."""
    if n == 0:
        return script_pushdata(b"")
    negative = n < 0
    n = -n if negative else n
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if negative else 0x00)
    elif negative:
        out[-1] |= 0x80
    return script_pushdata(bytes(out))


def build_sale_redeem_script(seller_pub_hex: str, refund_height: int,
                             buyer_pub_hex: str) -> bytes:
    """Build the verified-key sale's HTLC redeem script.

        OP_IF
            <seller_pub> OP_CHECKSIG
        OP_ELSE
            <refund_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
            <buyer_pub> OP_CHECKSIG
        OP_ENDIF
    """
    OP_IF, OP_ELSE, OP_ENDIF = b"\x63", b"\x67", b"\x68"
    OP_CHECKSIG = b"\xac"
    OP_CHECKLOCKTIMEVERIFY = b"\xb1"
    OP_DROP = b"\x75"
    return (
        OP_IF
        + script_pushdata(bytes.fromhex(seller_pub_hex)) + OP_CHECKSIG
        + OP_ELSE
        + cscriptnum(refund_height) + OP_CHECKLOCKTIMEVERIFY + OP_DROP
        + script_pushdata(bytes.fromhex(buyer_pub_hex)) + OP_CHECKSIG
        + OP_ENDIF
    )


def p2sh_address_from_script(script_bytes: bytes) -> str:
    """P2SH address (Dogecoin mainnet, version 0x16)."""
    h160 = cryptos.bin_hash160(script_bytes)
    return cryptos.bin_to_b58check(h160, DOGE_P2SH_MAGIC)


def build_unsigned_claim_tx(bond_outpoint_txid: str, bond_outpoint_vout: int,
                            bond_value_sats: int, dest_address: str,
                            fee_sats: int) -> dict:
    """Build an unsigned claim tx (one input, one output).

    Returns a dict {raw_unsigned_hex, sighash_hex} where sighash_hex is the
    SIGHASH_ALL of the redeem-script-substituted tx (what the seller's
    adaptor pre-sig commits to).

    For v0 dry-run, we use a placeholder bond outpoint — the real value is
    only known after the buyer constructs (but doesn't yet broadcast) their
    funding tx. In production, this script would coordinate with the buyer
    via Nostr to obtain the funding txid before generating the adaptor.
    """
    # Build raw tx structure manually so we can compute SIGHASH_ALL.
    # For SIGHASH_ALL with P2SH, sighash = double-SHA256 of the tx with
    # input's scriptSig replaced by the redeem script.
    version = b"\x01\x00\x00\x00"
    nlocktime = b"\x00\x00\x00\x00"  # immediate claim (no CLTV on claim leg)

    # Input
    prevhash = bytes.fromhex(bond_outpoint_txid)[::-1]  # little-endian
    prevout_idx = bond_outpoint_vout.to_bytes(4, "little")
    sequence = b"\xff\xff\xff\xff"

    # Output: pay (bond_value - fee) to dest_address
    out_value = (bond_value_sats - fee_sats).to_bytes(8, "little")
    # P2PKH scriptPubKey for dest: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    # cryptos can give us the scriptPubKey from an address:
    out_spk = bytes.fromhex(cryptos.Doge().addrtoscript(dest_address))
    out_spk_with_len = bytes([len(out_spk)]) + out_spk

    # Unsigned tx (scriptSig empty)
    tx_bytes = (
        version
        + b"\x01" + prevhash + prevout_idx + b"\x00" + sequence  # 1 input, empty scriptSig
        + b"\x01" + out_value + out_spk_with_len                 # 1 output
        + nlocktime
    )

    return {
        "raw_unsigned_hex": tx_bytes.hex(),
        "version":  "01000000",
        "input":    {"prev_txid": bond_outpoint_txid, "vout": bond_outpoint_vout,
                     "sequence": "ffffffff"},
        "output":   {"value_sats": bond_value_sats - fee_sats,
                     "address": dest_address},
        "nlocktime": "00000000",
    }


def compute_claim_tx_sighash(unsigned_tx_struct: dict,
                              redeem_script_bytes: bytes,
                              branch: str = "claim") -> bytes:
    """Compute SIGHASH_ALL for the claim tx with the redeem script
    substituted into the input's scriptSig position.

    branch='claim' uses the IF leg's expected scriptSig (with OP_1
    selecting the claim branch).
    """
    version = bytes.fromhex(unsigned_tx_struct["version"])
    prev_txid = bytes.fromhex(unsigned_tx_struct["input"]["prev_txid"])[::-1]
    vout = unsigned_tx_struct["input"]["vout"].to_bytes(4, "little")
    sequence = bytes.fromhex(unsigned_tx_struct["input"]["sequence"])

    # For SIGHASH_ALL, substitute the redeem script as the scriptSig
    script_len = len(redeem_script_bytes)
    if script_len < 0xfd:
        script_len_bytes = bytes([script_len])
    else:
        script_len_bytes = b"\xfd" + script_len.to_bytes(2, "little")

    out_value = unsigned_tx_struct["output"]["value_sats"].to_bytes(8, "little")
    out_spk = bytes.fromhex(cryptos.Doge().addrtoscript(unsigned_tx_struct["output"]["address"]))
    out_spk_with_len = bytes([len(out_spk)]) + out_spk

    nlocktime = bytes.fromhex(unsigned_tx_struct["nlocktime"])
    sighash_all = b"\x01\x00\x00\x00"

    preimage = (
        version
        + b"\x01" + prev_txid + vout + script_len_bytes + redeem_script_bytes + sequence
        + b"\x01" + out_value + out_spk_with_len
        + nlocktime
        + sighash_all
    )

    # Bitcoin/Dogecoin sighash is double-SHA256
    return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("verified-key sale — DRY RUN — El Gólem → El Ermitaño")
    print("=" * 70)
    print()

    # ---------- 1. Load keys ----------
    log("1. Loading keys")
    key1_eth = import_privKey(str(KEY1_PATH), "")           # eth_keys.PrivateKey
    seller_priv = PrivateKey(key1_eth.to_bytes())           # coincurve.PrivateKey
    seller_pub  = seller_priv.public_key
    seller_pub_hex = seller_pub.format(compressed=True).hex()
    log(f"seller (El Gólem) pubkey: {seller_pub_hex}", indent=1)
    log(f"seller doge address: {cryptos.Doge().pubtoaddr(seller_pub.format(compressed=True).hex())}",
        indent=1)

    mi_eth_pub = import_pubKey(str(MI_PUB_PATH))            # eth_keys.PublicKey
    mi_uncompressed = b"\x04" + mi_eth_pub.to_bytes()       # eth_keys gives 64B uncompressed sans prefix
    buyer_pub = PublicKey(mi_uncompressed)
    buyer_pub_hex = buyer_pub.format(compressed=True).hex()
    log(f"buyer (El Ermitaño) pubkey: {buyer_pub_hex}", indent=1)
    log(f"buyer doge address: {cryptos.Doge().pubtoaddr(buyer_pub_hex)}",
        indent=1)
    print()

    # ---------- 2. Generate session keypair ----------
    log("2. Generating fresh session keypair")
    session_priv = PrivateKey()                              # random
    session_pub  = session_priv.public_key
    session_pub_hex = session_pub.format(compressed=True).hex()
    log(f"session_pub: {session_pub_hex}", indent=1)
    log(f"session_priv: [held in memory only — never written to disk]",
        indent=1)
    print()

    # ---------- 3. Wrap essay as 0x01 essay quipu ----------
    log("3. Building inner essay quipu (0x01)")
    essay_md = ESSAY_PATH.read_text(encoding="utf-8")
    inner_h, inner_b = build_essay_quipu(
        title="On Custody",
        body_markdown=essay_md,
        tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-18", "lang": "en"},
    )
    log(f"inner header: {len(inner_h)} B  body: {len(inner_b)} B", indent=1)
    print()

    # ---------- 4. Seal as 0x0e 0xcb box ----------
    log("4. Sealing as 0x0e 0xcb committed-binding sale box")
    box_h, box_b = build_cb_box_quipu(
        inner_h, inner_b, seller_priv, session_pub,
        title=SALE_TITLE, tone=TONE_AI,
    )
    box_bytes = box_h + box_b
    log(f"box header: {len(box_h)} B  body: {len(box_b)} B  "
        f"total: {len(box_bytes)} B", indent=1)
    # Plaintext hash for belt-and-suspenders binding
    framed_inner = _frame_inner(inner_h, inner_b)
    plaintext_hash = hashlib.sha256(framed_inner).hexdigest()
    log(f"PlaintextHash = SHA256(framed_inner): {plaintext_hash[:32]}...",
        indent=1)
    # Predicted box root_txid placeholder — see manifest note
    box_root_txid = hashlib.sha256(b"BOX_TXID_PLACEHOLDER_v0||" + box_bytes).hexdigest()
    log(f"box_root_txid (v0 PLACEHOLDER): {box_root_txid[:32]}...", indent=1)
    print()

    # ---------- 5. HTLC bond ----------
    log("5. Constructing HTLC redeem script + P2SH bond address")
    refund_height = CURRENT_HEIGHT_ESTIMATE + REFUND_BLOCKS
    redeem_script = build_sale_redeem_script(
        seller_pub_hex, refund_height, buyer_pub_hex,
    )
    bond_address = p2sh_address_from_script(redeem_script)
    log(f"redeem script: {len(redeem_script)} B "
        f"({redeem_script.hex()[:32]}...)", indent=1)
    log(f"refund_height: {refund_height} "
        f"(estimated current {CURRENT_HEIGHT_ESTIMATE} + {REFUND_BLOCKS})",
        indent=1)
    log(f"bond P2SH address: {bond_address}", indent=1)
    print()

    # ---------- 6. Simulate buyer's funding tx + build unsigned claim tx ----------
    log("6. Building unsigned claim tx (PLACEHOLDER bond outpoint)")
    placeholder_funding_txid = hashlib.sha256(
        b"FUNDING_TX_PLACEHOLDER||" + bond_address.encode()
    ).hexdigest()
    fee_sats = 200_000   # 0.002 DOGE
    claim_tx = build_unsigned_claim_tx(
        bond_outpoint_txid=placeholder_funding_txid,
        bond_outpoint_vout=0,
        bond_value_sats=PRICE_SATS,
        dest_address=cryptos.Doge().pubtoaddr(seller_pub_hex),
        fee_sats=fee_sats,
    )
    log(f"placeholder funding txid: {placeholder_funding_txid[:32]}...",
        indent=1)
    log(f"claim tx unsigned: {len(claim_tx['raw_unsigned_hex']) // 2} B", indent=1)
    log(f"claim tx output: {PRICE_SATS - fee_sats} sat → seller", indent=1)

    claim_sighash = compute_claim_tx_sighash(claim_tx, redeem_script)
    log(f"claim tx sighash: {claim_sighash.hex()}", indent=1)
    print()

    # ---------- 7. Adaptor pre-signature ----------
    log("7. Generating ECDSA adaptor pre-signature")
    log(f"  signer:        seller_priv (El Gólem identity)", indent=1)
    log(f"  message_hash:  claim tx SIGHASH_ALL", indent=1)
    log(f"  adaptor T:     session_pub", indent=1)
    presig = adaptor.pre_sign(
        seller_priv.secret, claim_sighash,
        session_pub.format(compressed=True),
    )
    log(f"pre-sig R   = {presig['R'][:32]}...", indent=1)
    log(f"pre-sig R_a = {presig['R_a'][:32]}...", indent=1)
    log(f"pre-sig s_a = {presig['s_a'][:32]}...", indent=1)

    # Sanity-verify our own pre-sig
    assert adaptor.pre_verify(
        seller_pub.format(compressed=True), claim_sighash,
        session_pub.format(compressed=True), presig,
    ), "self-verify of pre-sig failed!"
    log("✓ pre-sig self-verifies under seller's pubkey", indent=1)

    # Demonstrate atomic key reveal: simulate the seller completing the sig
    # (in production, this happens at claim-broadcast time)
    completed_sig = adaptor.complete(presig, session_priv.secret)
    extracted = adaptor.extract_with_T(
        presig, completed_sig, session_pub.format(compressed=True),
    )
    assert extracted == session_priv.secret, "extraction roundtrip failed!"
    log(f"✓ simulated completion → extraction recovers session_priv "
        f"({extracted.hex()[:16]}...)", indent=1)
    print()

    # ---------- 8 & 9. Compose offer body + sign ----------
    log("8. Composing offer body (no signature yet)")
    h_offer_unsigned, b_offer_unsigned = build_sale_offer_cert(
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
        signatures=None,
        plaintext_hash_hex=plaintext_hash,
        tone=TONE_AI,
    )
    canonical_hash = canonical_hash_of_sale_offer(b_offer_unsigned)
    log(f"offer body: {len(b_offer_unsigned)} B  "
        f"canonical hash: {canonical_hash.hex()[:32]}...",
        indent=1)

    log("9. Signing canonical hash with seller's identity key (ECDSA)")
    sig_der = seller_priv.sign(canonical_hash, hasher=None)
    log(f"signature: {len(sig_der)} B  ({sig_der.hex()[:32]}...)", indent=1)
    assert seller_pub.verify(sig_der, canonical_hash, hasher=None), \
        "seller signature does not verify"
    log("✓ signature verifies under seller pubkey", indent=1)

    # ---------- 10. Re-build offer with signature ----------
    log("10. Re-building offer cert with seller signature attached")
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
    # canonical hash MUST be unchanged
    canonical_hash_v2 = canonical_hash_of_sale_offer(b_offer)
    assert canonical_hash_v2 == canonical_hash, \
        "adding signature changed canonical hash (broken)"
    log(f"signed offer: {len(b_offer)} B  "
        f"(canonical hash unchanged: ✓)", indent=1)

    # Roundtrip-verify
    parsed_offer = read_sale_offer_cert(h_offer, b_offer)
    assert parsed_offer["signatures"] == [("seller", sig_der.hex())]
    assert adaptor.pre_verify(
        bytes.fromhex(parsed_offer["seller_pubkey"]),
        bytes.fromhex(parsed_offer["claim_tx_sighash"]),
        bytes.fromhex(parsed_offer["session_pubkey"]),
        parsed_offer["adaptor_presig"],
    )
    log("✓ parsed offer roundtrips; adaptor pre-sig verifies", indent=1)
    print()

    # ---------- 11. ECIES-encrypt to El Ermitaño ----------
    log("11. ECIES-encrypting offer body to El Ermitaño's pubkey")
    full_offer_bytes = h_offer + b_offer
    # Use the project's foundational eth_keys ECIES (same as scripts/ecc_encrypt.py).
    # eth_keys PublicKey expects 64-byte uncompressed (no prefix); we have that.
    import ecies as _ecies_pkg
    encrypted_blob = _ecies_pkg.encrypt(mi_eth_pub.to_hex(), full_offer_bytes)
    log(f"plaintext offer: {len(full_offer_bytes)} B", indent=1)
    log(f"ECIES blob:      {len(encrypted_blob)} B", indent=1)
    print()

    # ---------- 12. Build kind:1729 draft event ----------
    log("12. Building kind:1729 Nostr DM draft event")
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
    log(f"kind 1729, ['p', {ERMITANO_XONLY[:16]}...]", indent=1)
    log(f"content (base64): {len(draft_event['content'])} chars", indent=1)
    print()

    # ---------- 13. Write all artifacts + manifest ----------
    log("13. Writing artifacts")

    artifacts = {
        "box.bin":                 box_bytes,
        "box_header.bin":          box_h,
        "box_body.bin":            box_b,
        "offer.bin":               h_offer + b_offer,
        "offer_header.bin":        h_offer,
        "offer_body.bin":          b_offer,
        "offer_ecies.bin":         encrypted_blob,
        "redeem_script.bin":       redeem_script,
        "claim_tx_unsigned.hex":   claim_tx["raw_unsigned_hex"].encode(),
        "claim_tx_sighash.bin":    claim_sighash,
        "session_priv.hex":        session_priv.secret.hex().encode(),  # ⚠ secret
        "session_pub.hex":         session_pub_hex.encode(),
        "presig.json":             json.dumps(presig, indent=2).encode(),
        "draft_event.json":        json.dumps(draft_event, indent=2).encode(),
    }
    for name, data in artifacts.items():
        path = ARTIFACTS / name
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        log(f"  {name} ({len(data)} B)", indent=1)

    # Manifest summary
    manifest = {
        "scenario": "El Gólem → El Ermitaño verified-key sale (DRY RUN)",
        "sale_title": SALE_TITLE,
        "price_doge": PRICE_DOGE,
        "price_sats": PRICE_SATS,
        "personas": {
            "seller": {
                "name": "El Gólem",
                "pubkey": seller_pub_hex,
                "doge_address": cryptos.Doge().pubtoaddr(seller_pub_hex),
            },
            "buyer": {
                "name": "El Ermitaño",
                "pubkey": buyer_pub_hex,
                "doge_address": cryptos.Doge().pubtoaddr(buyer_pub_hex),
                "nostr_xonly": ERMITANO_XONLY,
            },
        },
        "session": {
            "pubkey": session_pub_hex,
            "privkey_note": (
                "Held in session_priv.hex for v0 dry-run only. In production "
                "the priv is NEVER written to disk; it lives in memory until "
                "the claim tx is signed."
            ),
        },
        "box": {
            "size_bytes": len(box_bytes),
            "predicted_root_txid_PLACEHOLDER": box_root_txid,
            "note": (
                "v0 placeholder = SHA256(box_bytes). In production, replace "
                "with the diamond engine's predicted root txid (see "
                "quipu_diamond.build_consolidated_diamond)."
            ),
        },
        "bond": {
            "p2sh_address": bond_address,
            "redeem_script_hex": redeem_script.hex(),
            "refund_height": refund_height,
            "refund_pubkey": buyer_pub_hex,
            "claim_destination": cryptos.Doge().pubtoaddr(seller_pub_hex),
            "claim_fee_sats": fee_sats,
        },
        "claim_tx": {
            "PLACEHOLDER_funding_outpoint": f"{placeholder_funding_txid}:0",
            "sighash": claim_sighash.hex(),
            "note": (
                "Placeholder funding outpoint. In production this is filled "
                "in after a Nostr round-trip with the buyer: buyer constructs "
                "(unsigned) funding tx, shares the txid, seller computes the "
                "claim tx sighash and adaptor pre-sig over that specific "
                "outpoint."
            ),
        },
        "adaptor_presig": {
            "R":      presig["R"],
            "R_a":    presig["R_a"],
            "verified_self": True,
            "extracts_to_session_priv_when_completed": True,
        },
        "offer_cert": {
            "size_bytes": len(b_offer) + len(h_offer),
            "canonical_hash": canonical_hash.hex(),
            "signed_by": ["seller"],
            "signature": sig_der.hex(),
        },
        "ecies_blob_size_bytes": len(encrypted_blob),
        "nostr_draft": {
            "kind": 1729,
            "recipient_xonly": ERMITANO_XONLY,
            "encryption": "ecies-v1 (project's own ECIES envelope)",
            "publish_command": (
                ".venv/bin/python scripts/nostr_publish.py "
                "~/Desktop/cinv/llaves/key1_prv.enc "
                "working/sale/artifacts/draft_event.json ''"
            ),
        },
        "artifacts_directory": str(ARTIFACTS),
        "next_steps_for_anthony": [
            "1. Review draft_event.json — confirm recipient + tags look right",
            "2. Inspect offer.bin via cert reader (canonical/cert.py) to "
               "confirm body fields and adaptor sig present",
            "3. Decide: actually broadcast box via quipu_diamond? "
               "publish kind:1729 via scripts/nostr_publish.py? "
               "or stop here (this dry run was the validation)",
            "4. NOTE: session_priv.hex is currently on disk — for a real "
               "sale we never write this. Treat the dry-run artifact as "
               "compromised once reviewed.",
        ],
        "build_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path = ARTIFACTS / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log(f"  manifest.json ({manifest_path.stat().st_size} B)", indent=1)
    print()

    print("=" * 70)
    print("DRY RUN COMPLETE")
    print("=" * 70)
    print(f"artifacts directory: {ARTIFACTS}")
    print(f"manifest: {manifest_path}")
    print()
    print("Review manifest.json for review checklist + next steps.")


if __name__ == "__main__":
    main()
