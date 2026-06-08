"""
build_bond_funding.py — build + sign a tx from apocrypha (mi) funding the
bond P2SH with 5 DOGE. Saves the signed hex; does NOT broadcast.
"""
from __future__ import annotations

import json
import sys
import hashlib
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from colegio_tools import import_privKey
import cryptos

ARTIFACTS = PROJECT / "working/sale/artifacts"
MI_PRV  = Path("~/Desktop/cinv/llaves/mi_prv.enc").expanduser()

BOND_P2SH = "A8AFPT17pSjcs17DURmyxnRH3UEztUCLwU"
BOND_VALUE_SATS = 500_000_000     # 5 DOGE
FEE_SATS = 200_000                 # 0.002 DOGE

# Use this specific UTXO at apocrypha (D6zKNn...)
UTXO_TXID = "06b3cb115472d62651a458ff81d46e01dddbe7a34253874210ddfabb8882e152"
UTXO_VOUT = 3
UTXO_VALUE_SATS = int(19.63511799 * 100_000_000)   # 1963511799


def main():
    print("=" * 70)
    print("Building bond funding tx (apocrypha → bond P2SH)")
    print("=" * 70)
    print()

    # Load mi
    mi_eth = import_privKey(str(MI_PRV), "")
    # Apocrypha mi uses UNCOMPRESSED form — derives D6zKNn… not D5ivhw…
    mi_priv_hex = mi_eth.to_bytes().hex()
    d = cryptos.Doge()
    mi_addr = d.privtoaddr(mi_priv_hex)
    print(f"funding from: {mi_addr} (apocrypha / El Ermitaño)")
    print(f"  UTXO: {UTXO_TXID}:{UTXO_VOUT}  ({UTXO_VALUE_SATS/1e8} DOGE)")
    print(f"  → {BOND_P2SH}: {BOND_VALUE_SATS/1e8} DOGE  (bond)")
    change_sats = UTXO_VALUE_SATS - BOND_VALUE_SATS - FEE_SATS
    print(f"  → {mi_addr}: {change_sats/1e8} DOGE  (change)")
    print(f"  fee: {FEE_SATS/1e8} DOGE")
    print()

    # Construct the tx
    tx = d.mktx(
        [{"output": f"{UTXO_TXID}:{UTXO_VOUT}", "value": UTXO_VALUE_SATS}],
        [
            {"address": BOND_P2SH, "value": BOND_VALUE_SATS},
            {"address": mi_addr,   "value": change_sats},
        ],
    )

    # Sign
    signed = d.signall(tx, mi_priv_hex)
    signed_hex = cryptos.serialize(signed)

    # Compute txid
    raw = bytes.fromhex(signed_hex)
    txid = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()

    print(f"signed tx ({len(signed_hex)//2} B)")
    print(f"funding txid: {txid}")
    print()

    # Save
    (ARTIFACTS / "funding_tx_signed.hex").write_text(signed_hex)
    (ARTIFACTS / "funding_tx_signed.txid").write_text(txid)

    print(f"artifacts:")
    print(f"  {ARTIFACTS}/funding_tx_signed.hex   ({len(signed_hex)} chars)")
    print(f"  {ARTIFACTS}/funding_tx_signed.txid  ({txid})")
    print()
    print("Vout 0 (the bond output) will be the bond UTXO once broadcast.")
    print()
    print("To broadcast:")
    print(f"  /Users/anthonyschultz/Desktop/dogecoin/src/dogecoin-cli "
          f"sendrawtransaction {signed_hex[:32]}...")


if __name__ == "__main__":
    main()
