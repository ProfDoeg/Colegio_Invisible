"""Claim the test centinela (IF branch: preimage + D's sig) — validates the HTLC
spend on the real node. Reads the secret from bundle.json (in production this
comes from decrypting seal.0e_ae.bin with the AES key). Finds the funding UTXO,
builds a size-priced claim back to DEST, prints the signed hex.

  .venv/bin/python working/centinela/run_claim.py            # build + show (no broadcast)
  BROADCAST=1 .venv/bin/python working/centinela/run_claim.py # build + send
"""
import os, sys, json
from pathlib import Path

THIS = Path(__file__).parent; REPO = THIS.parent.parent
sys.path.insert(0, str(REPO))
import warnings; warnings.filterwarnings("ignore")

import quipu_centinela as C
from quipu_diamond import FeePolicy
from colegio_tools import rpc_request

DEST = os.environ.get("DEST", "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX")   # back to apocrypha
TEST = THIS / "test"
bundle = json.load(open(TEST / "bundle.json"))
addr = bundle["p2sh_addr"]

# find the funding UTXO at the P2SH address
scan = rpc_request("scantxoutset", ["start", [{"desc": "addr(%s)" % addr}]])
utxos = scan.get("unspents", []) if scan else []
if not utxos:
    raise SystemExit("no UTXO at %s yet — fund it first (~1 DOGE) and wait 1 conf" % addr)
u = max(utxos, key=lambda x: x["amount"])
outpoint = "%s:%d" % (u["txid"], u["vout"]); value = int(round(u["amount"] * 1e8))
print("funding UTXO:", outpoint, "=", u["amount"], "DOGE")

# size-price the claim: build once with a provisional fee, measure, reprice, rebuild
fp = FeePolicy()
prov, _ = C.build_claim_tx(outpoint, value, DEST, bundle, fee_sat=2_000_000)
size = len(prov) // 2
fee = fp.fee_for_bytes(size)
hexs, txid = C.build_claim_tx(outpoint, value, DEST, bundle, fee_sat=fee)
print("claim tx %d B, fee %.4f DOGE (%.4f/KB), -> %s" % (size, fee/1e8, fee/size*1000/1e8, DEST))
print("txid:", txid)

if os.environ.get("BROADCAST") == "1":
    print("broadcasting...")
    print("sent:", rpc_request("sendrawtransaction", [hexs]))
else:
    print("\n(dry: set BROADCAST=1 to send. hex below)\n" + hexs)
