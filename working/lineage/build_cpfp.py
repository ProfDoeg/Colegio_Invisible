"""Optional child-pays-for-parent nudge for the mega-join, in case its low fee
rate (~0.0084 DOGE/KB) keeps it out of full blocks. Spends the mega-join's single
residual output (megajoin:0, at apocrypha) with one small high-fee child, so the
(parent+child) package fee rate is high enough that any mempool-filling miner
includes both. Spends nothing extra beyond the CPFP fee; the rest returns to
apocrypha. Touches the key (getpass) — YOU run it. Keyless broadcast afterwards.

  .venv/bin/python working/lineage/build_cpfp.py
"""
import os, sys, json
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT)); sys.path.insert(0, str(THIS_DIR))

import warnings; warnings.filterwarnings("ignore")
import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import import_privKey, _txid_of_serial

APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEY_PATH       = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"
ARTIFACTS      = THIS_DIR / "artifacts"
CPFP_FEE_SAT   = int(os.environ.get("CPFP_FEE_SAT", "200000000"))   # 2 DOGE -> package ~0.07 DOGE/KB

idx = json.load(open(ARTIFACTS / "index.json"))
mj_txid  = idx["megajoin"]
residual = idx["residual_sat"]                     # 3,156,480,000 sat = 31.5648 DOGE
out_val  = residual - CPFP_FEE_SAT
assert out_val > 100_000_000, "CPFP fee too large"

priv = import_privKey(KEY_PATH)                     # getpass — YOU run this
raw  = priv.to_hex(); PRIV = raw[2:] if raw.startswith("0x") else raw
doge = cryptos.Doge()
assert doge.privtoaddr(PRIV) == APOCRYPHA_ADDR, "wrong key"

child = doge.mktx([{"output": f"{mj_txid}:0", "value": residual}],
                  [{"value": out_val, "address": APOCRYPHA_ADDR}])
signed = doge.signall(child, PRIV)
hexs   = cs_serialize(signed)
txid   = _txid_of_serial(hexs)
(ARTIFACTS / "cpfp.hex").write_text(hexs)
(ARTIFACTS / "cpfp.txid").write_text(txid)
print(f"CPFP child {txid}")
print(f"  spends megajoin:0 ({residual/1e8:.4f} DOGE) -> {out_val/1e8:.4f} DOGE to apocrypha")
print(f"  CPFP fee {CPFP_FEE_SAT/1e8:.4f} DOGE on a ~{len(hexs)//2} B child")
print(f"  -> artifacts/cpfp.hex  (broadcast it keyless to pull the mega-join into a block)")
