"""
extract_and_decrypt.py — the buyer's final step.

After the seller broadcasts the claim tx, anyone watching the bond P2SH
can extract session_priv by:
  1. Reading the claim tx from chain (or mempool)
  2. Parsing the scriptSig to recover (r, s) of the adaptor-completed sig
  3. Combining with the adaptor pre-sig from the offer to extract session_priv
  4. Fetching the box from chain via its root txid
  5. Decrypting with session_priv + recovered seller pubkey

This script does all five steps and reads back the essay El Gólem sold.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from coincurve import PrivateKey, PublicKey
from canonical.encrypted import read_cb_box_quipu
from canonical.essay import read_essay_quipu
from canonical.cert import read_sale_offer_cert
from canonical import adaptor

CLAIM_TXID = "dd57dbc9bcb1d3cb17a1d48ee3ae28e238d46726ec16a711d75ca1be4c75d882"
BOX_ROOT_TXID = "f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d"
ARTIFACTS = PROJECT / "working/sale/artifacts"
DOGE_CLI = "/Users/anthonyschultz/Desktop/dogecoin/src/dogecoin-cli"


def cli(*args):
    return subprocess.check_output([DOGE_CLI, *args]).decode()


def parse_claim_scriptSig(signed_hex):
    """Pull (r, s) out of the DER-encoded sig in the claim tx's scriptSig."""
    tx = bytes.fromhex(signed_hex)
    # version(4) + input_count(1) + prev_txid(32) + vout(4) = 41
    cursor = 41
    sl = tx[cursor]
    if sl < 0xfd:
        cursor += 1
    else:
        cursor += 3
    sig_push_len = tx[cursor]
    cursor += 1
    # Last byte of the push is SIGHASH; DER sig is everything before it
    der_sig = tx[cursor:cursor + sig_push_len - 1]
    # DER: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    assert der_sig[0] == 0x30
    r_len = der_sig[3]
    r_bytes = der_sig[4:4 + r_len]
    s_start = 4 + r_len + 2
    s_len = der_sig[4 + r_len + 1]
    s_bytes = der_sig[s_start:s_start + s_len]
    # Strip leading zero (DER positivity padding)
    if r_bytes[0] == 0:
        r_bytes = r_bytes[1:]
    if s_bytes[0] == 0:
        s_bytes = s_bytes[1:]
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    return r, s


def main():
    print("=" * 70)
    print("Buyer-side: extract session_priv from claim, decrypt the box")
    print("=" * 70)
    print()

    # ---------- 1. Read claim tx from chain ----------
    print(f"1. Reading claim tx from chain: {CLAIM_TXID[:20]}...")
    raw = cli("getrawtransaction", CLAIM_TXID).strip()
    print(f"   ✓ Got {len(raw)//2} B raw tx")
    print()

    # ---------- 2. Extract (r, s) from scriptSig ----------
    print("2. Parsing scriptSig to recover the adaptor-completed signature")
    r, s = parse_claim_scriptSig(raw)
    print(f"   ✓ r = {hex(r)[:32]}...")
    print(f"   ✓ s = {hex(s)[:32]}...")
    print()

    # ---------- 3. Load the offer's adaptor pre-sig ----------
    print("3. Loading the offer's adaptor pre-signature")
    offer_h = (ARTIFACTS / "offer_header.bin").read_bytes()
    offer_b = (ARTIFACTS / "offer_real.bin").read_bytes()[len(offer_h):] \
        if (ARTIFACTS / "offer_real.bin").exists() \
        else (ARTIFACTS / "offer_body.bin").read_bytes()
    # Try real offer first, fall back to dry-run
    if (ARTIFACTS / "offer_real.bin").exists():
        offer_full = (ARTIFACTS / "offer_real.bin").read_bytes()
        offer_h = offer_full[:8]
        offer_b = offer_full[8:]
        print("   (using offer_real.bin with real claim sighash)")
    else:
        offer_h = (ARTIFACTS / "offer_header.bin").read_bytes()
        offer_b = (ARTIFACTS / "offer_body.bin").read_bytes()
        print("   (using dry-run offer)")
    parsed = read_sale_offer_cert(offer_h, offer_b)
    presig = parsed["adaptor_presig"]
    session_pub_hex = parsed["session_pubkey"]
    print(f"   ✓ session_pub (committed in offer): {session_pub_hex[:32]}...")
    print()

    # ---------- 4. Extract session_priv ----------
    print("4. Extracting session_priv from (presig, on-chain sig)")
    session_priv_bytes = adaptor.extract_with_T(
        presig, (r, s), bytes.fromhex(session_pub_hex),
    )
    print(f"   ✓ session_priv = {session_priv_bytes.hex()}")
    print()

    # ---------- 5. Fetch box from chain ----------
    print(f"5. Fetching box from chain: {BOX_ROOT_TXID[:20]}...")
    sys.path.insert(0, str(PROJECT))
    from colegio_tools import fetch_quipu_bytes
    box_bytes = fetch_quipu_bytes(BOX_ROOT_TXID)
    print(f"   ✓ Got {len(box_bytes)} B from chain walker")
    print()

    # ---------- 6. Recover seller pubkey from box's funding tx ----------
    print("6. Recovering seller's identity pubkey from box's funding scriptSig")
    seller_pub_hex = parsed["seller_pubkey"]
    seller_pub = PublicKey(bytes.fromhex(seller_pub_hex))
    print(f"   ✓ Seller pubkey (from offer): {seller_pub_hex[:32]}...")
    print()

    # ---------- 7. Decrypt the box ----------
    print("7. Decrypting the box with extracted session_priv")
    # Split box bytes into header + body. The box header is 37 B for our title.
    # Easier: parse via read_cb_box_quipu in parse-only mode to find the
    # header boundary, then re-decrypt.
    # The 0x0e 0xcb header is: c1dd0001 0e tone cb 00 |TITLE|
    # Find the closing pipe after byte 8 to locate end of header.
    # For our box, header is 37 B from the dry-run; let's reuse.
    # Safer: detect by scanning for the end of |TITLE|.
    if box_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise SystemExit("Box bytes don't start with magic")
    if box_bytes[4] != 0x0e or box_bytes[6] != 0xcb:
        raise SystemExit("Not a 0x0e 0xcb box")
    # Header tail starts at offset 8 with '|TITLE|'
    end_title = box_bytes.find(b"|", 9)
    if end_title < 0:
        raise SystemExit("No closing | in title")
    header_end = end_title + 1
    box_h = box_bytes[:header_end]
    box_b = box_bytes[header_end:]
    print(f"   header: {len(box_h)} B  body: {len(box_b)} B")
    decrypted = read_cb_box_quipu(
        box_h, box_b,
        session_privkey=PrivateKey(session_priv_bytes),
        sender_pubkey=seller_pub,
    )
    assert decrypted["magic_ok"]
    inner_h = decrypted["inner_header"]
    inner_b = decrypted["inner_body"]
    print(f"   ✓ Decrypted: inner header {len(inner_h)} B  body {len(inner_b)} B")
    print()

    # ---------- 8. Read the essay ----------
    print("8. Reading the essay")
    essay = read_essay_quipu(inner_h, inner_b)
    print(f"   ✓ Title:  {essay['title']!r}")
    print(f"   ✓ Author: {essay['fields'].get('author')!r}")
    print(f"   ✓ Date:   {essay['fields'].get('date')!r}")
    print()

    # ---------- 9. The essay itself ----------
    print("=" * 70)
    print("THE SOLD CONTENT — extracted from chain via cryptographic atomicity")
    print("=" * 70)
    print()
    print(essay["body"])
    print()
    print("=" * 70)
    print("SALE COMPLETE — verified-key construction proven end-to-end on Dogecoin")
    print("=" * 70)


if __name__ == "__main__":
    main()
