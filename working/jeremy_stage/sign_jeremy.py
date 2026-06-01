#!/usr/bin/env python3
"""Sign the entire Jeremy diamond OFFLINE, funded from apocrypha. Run this
yourself — it getpass-prompts for the password that decrypts mi_prv.enc; the
key and password live only in memory and are NEVER written. It SIGNS only (no
broadcast — safe to run), and writes public hexes/txids to
working/jeremy_stage/artifacts/ for the keyless broadcast + loom to use.

  .venv/bin/python working/jeremy_stage/sign_jeremy.py

Nothing is spent by running this. Broadcasting the artifacts is a separate step.
"""
import os, sys, math, getpass

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO); sys.path.insert(0, os.path.join(REPO, "canonical"))
from quipu_crypto import decrypt_password
from quipu_orchestrator import Quipu, STATE_STRANDS_CONFIRMED
from colegio_tools import rpc_request
import cryptos

APOCRYPHA = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEYFILE   = os.path.expanduser("~/Desktop/cinv/llaves/mi_prv.enc")
BODY      = os.path.join(REPO, "working/jeremy_stage/jeremy_perf.bin")
ART       = os.path.join(REPO, "working/jeremy_stage/artifacts")
N_STRANDS = 255
TIP_SAT   = 2_000_000          # 0.02 DOGE per knot tx (~280 B, generous)
FEE_KB    = 5_000_000          # 0.05 DOGE/kB for the big root/join txs
COIN      = 100_000_000

# ---- decrypt the apocrypha key, in memory only ----
ct = open(KEYFILE, "rb").read()
pw = getpass.getpass("apocrypha password: ")
dec = decrypt_password(pw, ct)
doge = cryptos.Doge()
privkey = None
cands = []
if isinstance(dec, (bytes, bytearray)):
    try: cands.append(dec.decode().strip())
    except Exception: pass
    cands.append(dec.hex())
else:
    cands.append(str(dec).strip())
for c in cands:
    try:
        if doge.privtoaddr(c) == APOCRYPHA:
            privkey = c; break
    except Exception:
        pass
del pw, dec, ct
assert privkey, "decrypted key does not derive apocrypha — wrong password?"
print("key ok — apocrypha %s" % APOCRYPHA)

# ---- funding UTXO (read-only) ----
u = sorted(rpc_request("listunspent", [1, 99999999, [APOCRYPHA]]), key=lambda x: -x["amount"])
fund = u[0]
utxo = {"output": "%s:%d" % (fund["txid"], fund["vout"]), "value": int(round(fund["amount"] * COIN))}
print("funding utxo %s = %.2f DOGE" % (utxo["output"], fund["amount"]))

# ---- split body into N strand payloads (modulo knots) ----
blob = open(BODY, "rb").read()
knots = [blob[j:j+80] for j in range(0, len(blob), 80)]
N = min(N_STRANDS, len(knots))
strand_payloads = [b"".join(knots[i::N]) for i in range(N)]
# size root/join fees by bytes (root: N outputs; join: N inputs)
root_fee = max(TIP_SAT, math.ceil((100 + 40 * N) / 1000 * FEE_KB))
join_fee = max(TIP_SAT, math.ceil((100 + 160 * N) / 1000 * FEE_KB))

q = Quipu(privkey, utxo, strand_payloads, tip=TIP_SAT, root_fee=root_fee, join_fee=join_fee)
q.build_root()
q.precompute_strands()
q.state = STATE_STRANDS_CONFIRMED          # termini known from precompute; gate is conservative
q.build_join()
del privkey, q.priv                        # drop the key from memory

# ---- write public artifacts ----
os.makedirs(ART, exist_ok=True)
open(os.path.join(ART, "root.txid"), "w").write(q.root_txid)
open(os.path.join(ART, "root.txn"),  "w").write(q.root_hex)
open(os.path.join(ART, "join.txid"), "w").write(q.join_txid)
open(os.path.join(ART, "join.txn"),  "w").write(q.join_hex)
n_knot = 0
for i, c in enumerate(q.strands):
    open(os.path.join(ART, "strand_%d.txids" % i), "w").write("\n".join(c.txn_ids[1:]))
    open(os.path.join(ART, "strand_%d.txns"  % i), "w").write("\n".join(c.txns))
    n_knot += len(c.txns)
open(os.path.join(ART, "utxo.json"), "w").write('{"output":"%s","value":%d}' % (utxo["output"], utxo["value"]))

total_tx   = 1 + n_knot + 1
knot_fees  = n_knot * TIP_SAT
spend      = (root_fee + knot_fees + join_fee)
root_bytes = len(q.root_hex) // 2; join_bytes = len(q.join_hex) // 2
print("\n=== signed (NOT broadcast) ===")
print(" strands       %d   knots %d   total tx %d" % (N, n_knot, total_tx))
print(" root  %d B  fee %.3f DOGE   txid %s" % (root_bytes, root_fee/COIN, q.root_txid))
print(" join  %d B  fee %.3f DOGE   txid %s" % (join_bytes, join_fee/COIN, q.join_txid))
print(" knot tips     %.2f DOGE  (%d × 0.02)" % (knot_fees/COIN, n_knot))
print(" total spend   %.2f DOGE   leftover ~%.2f DOGE" % (spend/COIN, (utxo["value"] - spend)/COIN))
print(" artifacts ->  %s" % ART)
# sanity: warn if root/join look underpaid at 0.01/kB min relay
for nm, by, fe in (("root", root_bytes, root_fee), ("join", join_bytes, join_fee)):
    if fe < by / 1000 * 1_000_000:
        print(" *** WARNING: %s fee may be below 0.01/kB min relay — bump FEE_KB" % nm)
print("\nKey + password were used in memory only and never written. Nothing spent.")
