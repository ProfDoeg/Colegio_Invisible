"""
build_keydrop_inscription.py — build + broadcast a sourced keydrop quipu
(0x0e 0x0d variant 0x01) releasing the On Custody session_priv with a
header reference to the claim tx that revealed it in scriptSig.
"""
import os
import sys
import json
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

from coincurve import PrivateKey
from canonical.encrypted import build_keydrop_quipu, DROP_SOURCED
from canonical.tone import TONE_AI
from colegio_tools import import_privKey
import quipu_diamond
from quipu_diamond import build_consolidated_diamond, write_artifacts, FeePolicy
import cryptos

ARTIFACTS = PROJECT / "working/sale/artifacts"
KD_DIAMOND = ARTIFACTS / "keydrop_diamond"
KD_DIAMOND.mkdir(parents=True, exist_ok=True)

KEY1_PATH = Path("~/Desktop/cinv/llaves/key1_prv.enc").expanduser()

BOX_TXID   = "f74a53b76bb2b6dfc9e26e7218525cfcb1f440cd3becbf4e38b31fbaf7b71d6d"
CLAIM_TXID = "dd57dbc9bcb1d3cb17a1d48ee3ae28e238d46726ec16a711d75ca1be4c75d882"


def main():
    print("=" * 70)
    print("Building keydrop inscription — On Custody session_priv")
    print("=" * 70)

    # session_priv was extracted in the dry-run; re-read from the artifacts
    session_priv_hex = (ARTIFACTS / "session_priv.hex").read_text().strip()
    session_priv_bytes = bytes.fromhex(session_priv_hex)
    assert len(session_priv_bytes) == 32
    print(f"session_priv: {session_priv_hex}")
    print(f"box (ref):    {BOX_TXID}")
    print(f"claim (src):  {CLAIM_TXID}")
    print()

    # Build the keydrop quipu
    h, b = build_keydrop_quipu(
        drops=[("session", BOX_TXID, session_priv_bytes)],
        title="On Custody — session_priv",
        tone=TONE_AI,
        header_fields={"claim": CLAIM_TXID},
    )
    blob = h + b
    print(f"keydrop quipu: header {len(h)} B + body {len(b)} B = {len(blob)} B")
    print(f"  variant: 0x{h[7]:02x} (DROP_SOURCED)")
    print()

    # Find funding UTXO at El Gólem's address
    key1_eth = import_privKey(str(KEY1_PATH), "")
    seller_priv = PrivateKey(key1_eth.to_bytes())
    seller_priv_hex = seller_priv.secret.hex() + "01"
    seller_addr = cryptos.Doge().pubtoaddr(
        seller_priv.public_key.format(compressed=True).hex()
    )
    print(f"funding from: {seller_addr}")

    # Find UTXOs at this address
    import subprocess
    out = subprocess.check_output(
        ["/Users/anthonyschultz/Desktop/dogecoin/src/dogecoin-cli",
         "listunspent", "1", "9999999", json.dumps([seller_addr])]
    ).decode()
    utxos = json.loads(out)
    if not utxos:
        raise SystemExit("no UTXOs at El Gólem's address")
    # Pick the smallest UTXO above 1 DOGE
    utxos = [u for u in utxos if u["amount"] >= 1.0]
    utxos.sort(key=lambda u: u["amount"])
    utxo = utxos[0]
    print(f"using utxo: {utxo['txid'][:24]}…:{utxo['vout']} = {utxo['amount']} DOGE")
    funding_utxo = {
        "output": f"{utxo['txid']}:{utxo['vout']}",
        "value": int(round(utxo["amount"] * 100_000_000)),
    }
    print()

    # Build consolidated diamond (single piece)
    pieces = [("keydrop", blob)]
    fp = FeePolicy(rate_kb=0.10)
    art = build_consolidated_diamond(
        pieces=pieces,
        placeholder_of=lambda pid: "00" * 32,
        utxo=dict(funding_utxo),
        priv=seller_priv_hex,
        address=seller_addr,
        fee_policy=fp,
        log=lambda m: print(f"  {m}"),
    )

    keydrop_root_hex, keydrop_root_txid = art["roots"]["keydrop"]
    print()
    print(f"✓ keydrop root txid (predicted): {keydrop_root_txid}")

    # Persist signed artifacts
    write_artifacts(art, str(KD_DIAMOND))
    print(f"  signed-tx artifacts: {KD_DIAMOND}/")

    # Broadcast
    print()
    print("Broadcasting…")
    quipu_diamond.broadcast_consolidated_diamond(str(KD_DIAMOND))
    print()
    print("=" * 70)
    print(f"KEYDROP INSCRIBED: {keydrop_root_txid}")
    print("=" * 70)

    # Also cache the bytes for the local fetcher
    (PROJECT / "data" / "bodies" / f"{keydrop_root_txid}.bin").write_bytes(blob)
    print(f"cached to data/bodies/{keydrop_root_txid}.bin")


if __name__ == "__main__":
    main()
