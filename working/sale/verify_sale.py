"""
verify_sale.py — read back the dry-run artifacts and simulate the
buyer-side flow end-to-end. NO broadcasts, NO network. Just confirms
every cryptographic check passes.

Steps:
  1. Decrypt the ECIES blob with mi_prv (as El Ermitaño would on receipt)
  2. Parse the offer cert
  3. Verify the seller's identity signature over the canonical hash
  4. Parse the box (parse-only, no keys)
  5. Verify session_pub in offer matches session_pub in box
  6. Verify the adaptor pre-signature against (seller_pub, sighash, session_pub)
  7. Reconstruct the bond P2SH from the offer's redeem script; verify it
     matches the BondAddress
  8. Simulate the seller's claim: complete the adaptor pre-sig with
     session_priv (which we read from session_priv.hex for the dry run)
  9. Verify the completed signature is a valid standard ECDSA sig
 10. Simulate the buyer extracting session_priv from (presig, completed_sig)
 11. Decrypt the box using extracted session_priv + recovered seller pubkey
 12. Verify decrypted plaintext SHA256 matches PlaintextHash in offer
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from coincurve import PrivateKey, PublicKey
from canonical.encrypted import read_cb_box_quipu, _frame_inner
from canonical.cert import read_sale_offer_cert, canonical_hash_of_sale_offer
from canonical import adaptor
from canonical.essay import read_essay_quipu
import ecies as _ecies_pkg
from colegio_tools import import_privKey
import cryptos

ARTIFACTS = PROJECT / "working/sale/artifacts"
MI_PRV = Path("~/Desktop/cinv/llaves/mi_prv.enc").expanduser()


def main():
    print("=" * 70)
    print("verify_sale.py — buyer-side simulated verification")
    print("=" * 70)
    print()

    # ---------- 1. Decrypt the ECIES blob ----------
    print("1. Decrypting the ECIES blob with mi_prv (El Ermitaño)")
    encrypted_blob = (ARTIFACTS / "offer_ecies.bin").read_bytes()
    mi_eth_priv = import_privKey(str(MI_PRV), "")
    plaintext_offer = _ecies_pkg.decrypt(mi_eth_priv.to_hex(), encrypted_blob)
    print(f"   ✓ ECIES blob ({len(encrypted_blob)} B) → plaintext ({len(plaintext_offer)} B)")
    print()

    # ---------- 2. Parse the offer cert ----------
    print("2. Parsing the offer cert")
    # plaintext_offer = header (8B) + body
    offer_header = plaintext_offer[:8]
    offer_body = plaintext_offer[8:]
    parsed = read_sale_offer_cert(offer_header, offer_body)
    print(f"   ✓ Title: {parsed['title']!r}")
    print(f"   ✓ Box txid: {parsed['box_txid'][:32]}...")
    print(f"   ✓ Price: {parsed['price_sats']} sat ({parsed['price_sats']/1e8} DOGE)")
    print(f"   ✓ Refund height: {parsed['refund_height']}")
    print(f"   ✓ Signers: {parsed['signers']}")
    print()

    # ---------- 3. Verify seller's identity signature ----------
    print("3. Verifying seller's identity signature over canonical hash")
    canonical_hash = parsed["canonical_hash"]
    seller_pub_bytes = bytes.fromhex(parsed["seller_pubkey"])
    seller_pub = PublicKey(seller_pub_bytes)
    sig_role, sig_hex = parsed["signatures"][0]
    assert sig_role == "seller", "first signature must be from seller"
    sig_bytes = bytes.fromhex(sig_hex)
    assert seller_pub.verify(sig_bytes, canonical_hash, hasher=None), \
        "seller's signature does NOT verify"
    print(f"   ✓ Seller's ECDSA signature verifies under SellerPubkey "
          f"over canonical hash {canonical_hash.hex()[:24]}...")
    print()

    # ---------- 4. Parse the box (parse-only) ----------
    print("4. Parsing the box (parse-only, no keys)")
    box_bytes = (ARTIFACTS / "box.bin").read_bytes()
    # Split into header + body via box_header.bin
    box_header = (ARTIFACTS / "box_header.bin").read_bytes()
    box_body = box_bytes[len(box_header):]
    box_parsed = read_cb_box_quipu(box_header, box_body)
    print(f"   ✓ Box title: {box_parsed['title']!r}")
    print(f"   ✓ Box session_pub: {box_parsed['session_pub'][:32]}...")
    print()

    # ---------- 5. session_pub matches between box and offer ----------
    print("5. Verifying session_pub matches between box and offer")
    assert box_parsed["session_pub"] == parsed["session_pubkey"], \
        f"session_pub mismatch: box={box_parsed['session_pub']} offer={parsed['session_pubkey']}"
    print(f"   ✓ session_pub is consistent across box and offer")
    print()

    # ---------- 6. Verify adaptor pre-signature ----------
    print("6. Verifying adaptor pre-signature")
    presig = parsed["adaptor_presig"]
    sighash = bytes.fromhex(parsed["claim_tx_sighash"])
    session_pub_bytes = bytes.fromhex(parsed["session_pubkey"])
    assert adaptor.pre_verify(
        seller_pub_bytes, sighash, session_pub_bytes, presig,
    ), "adaptor pre-sig does NOT verify"
    print(f"   ✓ Adaptor pre-sig verifies — binding established between")
    print(f"     session_pub and the claim-tx signature commitment")
    print()

    # ---------- 7. Verify P2SH bond address ----------
    print("7. Verifying P2SH bond address from redeem script")
    redeem = bytes.fromhex(parsed["redeem_script"])
    h160 = cryptos.bin_hash160(redeem)
    reconstructed = cryptos.bin_to_b58check(h160, 0x16)
    assert reconstructed == parsed["bond_address"], \
        f"BondAddress mismatch: offer={parsed['bond_address']} computed={reconstructed}"
    print(f"   ✓ P2SH({{redeem_script}}) = {reconstructed}")
    print(f"     matches BondAddress field in offer")
    print()

    # ---------- 8 & 9. Simulate seller's claim ----------
    print("8. Simulating seller's claim (using session_priv from dry-run artifact)")
    session_priv_bytes = bytes.fromhex(
        (ARTIFACTS / "session_priv.hex").read_text()
    )
    completed_sig = adaptor.complete(presig, session_priv_bytes)
    print(f"   ✓ Completion: (r, s) = "
          f"({hex(completed_sig[0])[:20]}.., {hex(completed_sig[1])[:20]}..)")

    print("9. Confirming completed sig is a valid standard ECDSA signature")
    valid = adaptor._ecdsa_verify(
        completed_sig[0], completed_sig[1], sighash, seller_pub_bytes,
    )
    assert valid, "completed signature does NOT verify as ECDSA"
    print(f"   ✓ Completed (r, s) verifies as standard ECDSA under seller's pubkey")
    print(f"     — the chain would accept this as OP_CHECKSIG")
    print()

    # ---------- 10. Buyer extracts session_priv ----------
    print("10. Buyer extracts session_priv from (pre-sig, completed sig)")
    extracted = adaptor.extract_with_T(presig, completed_sig, session_pub_bytes)
    assert extracted == session_priv_bytes, \
        f"extracted ≠ original: {extracted.hex()} vs {session_priv_bytes.hex()}"
    print(f"   ✓ Extracted session_priv: {extracted.hex()[:32]}...")
    print(f"     matches the seller's actual session_priv — atomicity proven")
    print()

    # ---------- 11. Decrypt the box ----------
    print("11. Decrypting the box with extracted session_priv")
    session_priv_obj = PrivateKey(extracted)
    decrypted = read_cb_box_quipu(
        box_header, box_body,
        session_privkey=session_priv_obj,
        sender_pubkey=seller_pub,
    )
    assert decrypted["magic_ok"], "decrypted inner has bad magic"
    inner_h = decrypted["inner_header"]
    inner_b = decrypted["inner_body"]
    print(f"   ✓ Box decrypted: inner header {len(inner_h)} B, body {len(inner_b)} B")
    print()

    # ---------- 12. PlaintextHash verification ----------
    print("12. Verifying PlaintextHash binding")
    framed_inner = _frame_inner(inner_h, inner_b)
    computed = hashlib.sha256(framed_inner).hexdigest()
    expected = parsed["plaintext_hash"]
    assert computed == expected, \
        f"PlaintextHash mismatch:\n  expected: {expected}\n  computed: {computed}"
    print(f"   ✓ SHA256(framed inner) = {computed[:32]}...")
    print(f"     matches PlaintextHash in offer — content authenticity confirmed")
    print()

    # ---------- Done: show the essay ----------
    print("13. Reading the inner essay (proof we got the content)")
    essay_parsed = read_essay_quipu(inner_h, inner_b)
    print(f"   ✓ Essay title: {essay_parsed['title']!r}")
    print(f"   ✓ Essay author: {essay_parsed['fields'].get('author')!r}")
    print(f"   ✓ Essay date: {essay_parsed['fields'].get('date')!r}")
    print()
    print("   --- first 3 lines of the essay body ---")
    for line in essay_parsed['body'].split("\n")[:6]:
        print(f"     {line}")
    print()

    print("=" * 70)
    print("ALL CHECKS PASS — verified-key sale construction works end-to-end")
    print("=" * 70)


if __name__ == "__main__":
    main()
