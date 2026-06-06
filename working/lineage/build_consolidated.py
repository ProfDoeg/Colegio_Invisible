"""SIGN the Gana forest — the per-stage reference for a consolidated-diamond
inscription. Thin wrapper over the canonical engine (quipu_diamond.py); all the
real logic (header=strand0 split, placeholder->root backfill, size-priced fees,
mega-join) lives there. Copy this file for the next forest and edit the manifest
+ placeholders.

  DRY_RUN=1 [RATE_KB=0.10] .venv/bin/python working/lineage/build_consolidated.py   # validate, throwaway key
  [RATE_KB=0.10]            .venv/bin/python working/lineage/build_consolidated.py   # YOU run; getpass for key

Fees: every tx pays RATE_KB DOGE per KB of its actual size (default 0.10; ~5x the
observed miner floor — see docs/guides/consolidated-diamond.md). NOTE the Gana
forest already shipped (block 6237154) at a flat 0.025/knot; this canonical
rebuild is the reference path, not a re-inscription.
"""
import os, sys, hashlib
from pathlib import Path

THIS = Path(__file__).parent
REPO = THIS.parent.parent
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(THIS))

import warnings; warnings.filterwarnings("ignore")
import cryptos
from colegio_tools import import_privKey, unspent
from quipu_diamond import FeePolicy, build_consolidated_diamond, write_artifacts
from forest_manifest import PIECES

APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEY_PATH       = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"

# placeholder txids embedded in the bodies (must match render_from_quipus.py)
KNOWN = {
 "journey":    "bb26882451630ae9aba5ffe4c06c8508cddc69d1e9cc36c05fac07a019f9ebea",
 "jung_quote": "92a7ac8bd9604b9d26be23bd08067501b626c15eb816c91edcf89071da49c4e4",
 "jung_gen":   "5d8c04bc51a93253a225681998d72e161601c8475ef0b05c1df009f0990300ee",
 "goethe_gen": "fa1c118a5a029c7f7f321fb241af0fd318e4f40dc033555cd4a6a372dabe7121",
 "tower":      "8b1b73eed4919e0b49d03f8d393664bc6343c91b8df88f48064c4124140888a1",
}
GOETHE_XREF = "34fc10f09d8cdd83dd2f7825d37a95b13c136d0d5b8f2e7ee80de556f66549e8"  # jung_gen -> goethe_gen
def placeholder_of(pid):
    return KNOWN.get(pid) or hashlib.sha256(pid.encode()).hexdigest()

RATE_KB = float(os.environ.get("RATE_KB", "0.10"))
DRY = os.environ.get("DRY_RUN") == "1"
ARTIFACTS = THIS / ("artifacts_dry" if DRY else "artifacts")

pieces = [(pid, (REPO / path).read_bytes()) for pid, _, _, _, path in PIECES]

if DRY:
    priv = hashlib.sha256(b"gana-forest-dry-run").hexdigest()
    address = cryptos.Doge().privtoaddr(priv)
    utxo = {"output": "de" * 32 + ":0", "value": 12_558_480_000}
    print("DRY RUN — throwaway key", address)
else:
    pk = import_privKey(KEY_PATH)                       # getpass — YOU run this
    raw = pk.to_hex(); priv = raw[2:] if raw.startswith("0x") else raw
    address = cryptos.Doge().privtoaddr(priv)
    assert address == APOCRYPHA_ADDR, "key derives %s, expected funder" % address
    us = sorted(unspent(APOCRYPHA_ADDR), key=lambda u: -u["value"])
    if not us:
        raise SystemExit("apocrypha has no utxos")
    utxo = us[0]
    print("funder", address, "utxo", utxo["output"], utxo["value"] / 1e8, "DOGE")

art = build_consolidated_diamond(
    pieces, placeholder_of, utxo, priv, address,
    fee_policy=FeePolicy(rate_kb=RATE_KB), extra_placeholders={GOETHE_XREF: "goethe_gen"})
write_artifacts(art, str(ARTIFACTS))
print("\nartifacts ->", ARTIFACTS)
print("DRY OK — structure validated, nothing spendable." if DRY else "READY TO BROADCAST.")
