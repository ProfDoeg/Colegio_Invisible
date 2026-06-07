"""Funding tx for the 3-mode centinela test: apocrypha -> 3.3 DOGE to each of the
A/B/C test locks + change back to apocrypha, size-priced fee.

  python              working/centinela/fund.py    # BUILD only — print the unsigned tx to review
  SIGN=1              .../fund.py                   # YOU run: getpass apocrypha key, sign, write hex
  SIGN=1 BROADCAST=1  .../fund.py                   # ...and broadcast

Build-only touches nothing spendable. Signing needs your key (getpass) — that's
the step you run.
"""
import os, sys, json
from pathlib import Path

THIS = Path(__file__).parent; REPO = THIS.parent.parent
sys.path.insert(0, str(REPO))
import warnings; warnings.filterwarnings("ignore")

import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import unspent, import_privKey, _txid_of_serial, rpc_request
from quipu_diamond import FeePolicy

APO = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEY = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"
AMT = 330_000_000                                   # 3.3 DOGE per lock
targets = json.load(open(THIS / "test3" / "targets.json"))
d = cryptos.Doge()

us = sorted(unspent(APO), key=lambda u: -u["value"])
if not us:
    raise SystemExit("apocrypha has no spendable utxo in the wallet")
utxo = us[0]; op = utxo["output"]; total = utxo["value"]   # snapshot (mktx mutates the dict)
addrs = list(targets.values())
outs = [{"address": a, "value": AMT} for a in addrs]

def build(fee):
    change = total - AMT * len(addrs) - fee
    return d.mktx([{"output": op, "value": total}], outs + [{"address": APO, "value": change}]), change

# size-price on the SIGNED size (unsigned + ~108 B for the one P2PKH input)
prov, _ = build(2_000_000)
signed_size = len(cs_serialize(prov)) // 2 + 108
fee = FeePolicy().fee_for_bytes(signed_size)
tx, change = build(fee)
if change < 1_000_000:
    raise SystemExit("insufficient apocrypha funds for 3x3.3 + fee")
unsigned = cs_serialize(tx)

print("=== FUNDING TX (unsigned) ===")
print("input : %s  %.4f DOGE" % (op, total / 1e8))
for m, a in targets.items():
    print("  out : 3.3000 DOGE -> %s  (%s)" % (a, m))
print("  change: %.4f DOGE -> %s" % (change / 1e8, APO))
print("  fee   : %.4f DOGE (~%d B signed)" % (fee / 1e8, signed_size))
print("\nunsigned hex:\n" + unsigned)

if os.environ.get("SIGN") == "1":
    pk = import_privKey(KEY)                         # getpass — your key, in memory only
    raw = pk.to_hex(); priv = raw[2:] if raw.startswith("0x") else raw
    assert d.privtoaddr(priv) == APO, "key does not derive apocrypha"
    signed = cs_serialize(d.signall(tx, priv)); txid = _txid_of_serial(signed)
    open(THIS / "funding.signed.hex", "w").write(signed)
    open(THIS / "funding.txid", "w").write(txid)
    print("\n=== SIGNED ===\ntxid: %s\n%s" % (txid, signed))
    if os.environ.get("BROADCAST") == "1":
        print("\nbroadcast:", rpc_request("sendrawtransaction", [signed]))
    else:
        print("\nnot broadcast. send with: BROADCAST=1, or dogecoin-cli sendrawtransaction <hex>")
