"""Build the Dos ensayos inscription (deterministic, no broadcast).

Single quipu — a 0x09 book with two entries:
  [0] essay/01  El yiddish del joven Goethe       -> 84fbbb17… (already on chain)
  [1] essay/02  Cementerio de los Animales        -> 449e67f4… (already on chain)

No separate 0xab binding inscription. The Goethe essay's historical title
("El hebreo del joven Goethe") is corrected at the book level by setting
the entry's `name` field directly to the corrected form.

Standalone diamond: splitter → root → strands → join. Mirrors the
working/cemetery/ pattern but with one quipu instead of three.
"""
import math
import os
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import (
    rpc_request, unspent, import_privKey, _txid_of_serial, CadenaAtom,
)

from canonical.book import build_book_quipu
from canonical.tone import TONE_ORDINARY

# =============================================================================
#                              CONFIGURATION
# =============================================================================

APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"

# On-chain root_txids of the two essays
GOETHE_ROOT_TXID    = "84fbbb17718523edf373630e68239fa9abda85297ba2aca8a69ace04f0ad5fb5"
CEMENTERIO_V2_ROOT  = "449e67f4a2e948f044e1a32662b58ccedad3cf8e85a742cc45b6b6541e47b5d7"

BOOK_BODY_STRANDS = 1   # body is ~150 B, one strand of ~2 knots

TIP_SAT          = 5_000_000
ROOT_FEE_SAT     = 5_000_000
SPLITTER_FEE_SAT = 5_000_000
JOIN_FEE_MIN     = 5_000_000

KEY_PATH = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"
ARTIFACTS = THIS_DIR / "artifacts"

# =============================================================================
#                              HELPERS
# =============================================================================

def doge(sat):
    return f"{sat/100_000_000:.8f} DOGE"

def knot_count(payload_bytes):
    return math.ceil(len(payload_bytes) / 80) if payload_bytes else 1

def split_body(body, n_strands, knot_size=80):
    if n_strands <= 1:
        return [body]
    total_knots = math.ceil(len(body) / knot_size)
    base = total_knots // n_strands
    extra = total_knots - base * n_strands
    strands = []
    knot_idx = 0
    for i in range(n_strands):
        k = base + (1 if i < extra else 0)
        start = knot_idx * knot_size
        end_knot = knot_idx + k
        end = end_knot * knot_size if i < n_strands - 1 else len(body)
        strands.append(body[start:end])
        knot_idx = end_knot
    assert b"".join(strands) == body
    return strands


# =============================================================================
#                       1. BUILD BOOK PAYLOAD
# =============================================================================
print("=" * 72)
print("PHASE 1 — building book payload")
print("=" * 72)

book_entries = [
    {
        "ref_txid": GOETHE_ROOT_TXID,
        "tag":      "essay/01",
        "name":     "El yiddish del joven Goethe",
    },
    {
        "ref_txid": CEMENTERIO_V2_ROOT,
        "tag":      "essay/02",
        "name":     "Cementerio de los Animales",
    },
]

book_header, book_body = build_book_quipu(
    "Dos ensayos",
    book_entries,
    tone=TONE_ORDINARY,
    fields={
        "author": "El Ermitaño",
        "date":   "2026-05-22",
        "lang":   "es",
    },
)
print(f"  BOOK  header={len(book_header):>3}B  body={len(book_body):>4}B  (0x09 book, 2 entries)")

# =============================================================================
#                       2. STRAND LAYOUT + FEE CALC
# =============================================================================
print()
print("=" * 72)
print("PHASE 2 — strand layout + funding")
print("=" * 72)

strands       = [book_header] + split_body(book_body, BOOK_BODY_STRANDS)
knots         = [knot_count(p) for p in strands]
total_strands = len(strands)
total_knots   = sum(knots)
print(f"  strands={total_strands}  knots={total_knots}  (header strand + {len(strands)-1} body strand)")

print()
print("  querying apocrypha utxos...")
import warnings; warnings.filterwarnings("ignore")
all_utxos = sorted(unspent(APOCRYPHA_ADDR), key=lambda u: -u["value"])
print(f"  apocrypha has {len(all_utxos)} utxo(s):")
for u in all_utxos:
    print(f"    {u['output']}  {doge(u['value'])}")
if not all_utxos:
    raise SystemExit("FATAL: apocrypha has no utxos")

# Pick the smallest utxo that still covers the inscription budget. Leaves
# the large residual untouched for future inscriptions. (Required budget
# computed below; using a safe upper bound here.)
_MIN_BUDGET_GUESS = 50_000_000   # 0.50 DOGE — comfortably above ~0.30 DOGE need
candidates = sorted(
    (u for u in all_utxos if u["value"] >= _MIN_BUDGET_GUESS),
    key=lambda u: u["value"],
)
if not candidates:
    raise SystemExit(f"FATAL: no utxo ≥ {doge(_MIN_BUDGET_GUESS)}")
utxos = [candidates[0]]
total_in = utxos[0]["value"]
print(f"  using smallest-sufficient: {utxos[0]['output']}  {doge(total_in)}")

strand_fees    = total_knots * TIP_SAT
mandatory_fees = SPLITTER_FEE_SAT + ROOT_FEE_SAT + strand_fees + JOIN_FEE_MIN
print(f"  required fees: {doge(mandatory_fees)}  "
      f"(splitter + root + {total_knots} knots + min join)")
if total_in < mandatory_fees:
    raise SystemExit(f"\nFATAL: insufficient funds. {doge(total_in)} < {doge(mandatory_fees)}\n")

join_fee_sat  = JOIN_FEE_MIN
final_out_sat = total_in - SPLITTER_FEE_SAT - ROOT_FEE_SAT - strand_fees - join_fee_sat
assert final_out_sat > 100_000, f"final_out below safe dust threshold: {final_out_sat}"

total_terminals_sat = join_fee_sat + final_out_sat
base_terminal = total_terminals_sat // total_strands
remainder     = total_terminals_sat - base_terminal * total_strands

seeds = []
for i, k in enumerate(knots):
    terminal = base_terminal + (remainder if i == 0 else 0)
    seeds.append(k * TIP_SAT + terminal)
root_input = sum(seeds) + ROOT_FEE_SAT

splitter_outputs = [root_input]
splitter_fee     = total_in - root_input
assert splitter_fee == SPLITTER_FEE_SAT, f"splitter_fee {splitter_fee} != {SPLITTER_FEE_SAT}"

print()
print(f"  splitter input:           {doge(total_in)}")
print(f"  splitter outputs sum:     {doge(root_input)}")
print(f"  splitter fee:             {doge(splitter_fee)}")
print(f"  predicted join fee:       {doge(join_fee_sat)}")
print(f"  predicted final residual: {doge(final_out_sat)}")

# =============================================================================
#                       3. BUILD SPLITTER + ROOT
# =============================================================================
print()
print("=" * 72)
print("PHASE 3 — splitter + root txs")
print("=" * 72)

priv_obj = import_privKey(KEY_PATH, "")
priv_hex_raw = priv_obj.to_hex()
PRIV = priv_hex_raw[2:] if priv_hex_raw.startswith("0x") else priv_hex_raw
doge_cs = cryptos.Doge()
addr = doge_cs.privtoaddr(PRIV)
assert addr == APOCRYPHA_ADDR

splitter_tx = doge_cs.mktx(
    utxos,
    [{"value": v, "address": APOCRYPHA_ADDR} for v in splitter_outputs],
)
splitter_signed = doge_cs.signall(splitter_tx, PRIV)
splitter_hex    = cs_serialize(splitter_signed)
splitter_txid   = _txid_of_serial(splitter_hex)
print(f"  splitter txid: {splitter_txid}")

root_input_ref = {"output": f"{splitter_txid}:0", "value": root_input}
root_outputs   = [{"value": s, "address": APOCRYPHA_ADDR} for s in seeds]
root_tx = doge_cs.mktx([root_input_ref], root_outputs)
root_signed = doge_cs.signall(root_tx, PRIV)
root_hex    = cs_serialize(root_signed)
root_txid   = _txid_of_serial(root_hex)
print(f"  book root_txid: {root_txid}")

# =============================================================================
#                       4. PRECOMPUTE STRANDS
# =============================================================================
print()
print("=" * 72)
print("PHASE 4 — precompute Cadena strands")
print("=" * 72)

cadenas = []
for i, payload in enumerate(strands):
    seed_utxo = {"output": f"{root_txid}:{i}", "value": seeds[i]}
    cad = CadenaAtom(PRIV, payload, seed_utxo, TIP_SAT)
    cad.precompute()
    cadenas.append(cad)
actual_total_knots = sum(len(c.txns) for c in cadenas)
assert actual_total_knots == total_knots
print(f"  precomputed {actual_total_knots} knot txs across {len(cadenas)} strands")

# =============================================================================
#                       5. BUILD JOIN
# =============================================================================
print()
print("=" * 72)
print(f"PHASE 5 — join ({total_strands} inputs → 1 output)")
print("=" * 72)

join_inputs = []
for i, cad in enumerate(cadenas):
    terminus_value = seeds[i] - TIP_SAT * len(cad.txns)
    join_inputs.append({"output": f"{cad.txn_ids[-1]}:0", "value": terminus_value})
actual_total_in = sum(inp["value"] for inp in join_inputs)
actual_join_fee = actual_total_in - final_out_sat
print(f"  total terminus value: {doge(actual_total_in)}")
print(f"  final output:         {doge(final_out_sat)}")
print(f"  join fee:             {doge(actual_join_fee)}")
if actual_join_fee < 0:
    raise SystemExit(f"FATAL: join fee negative")

join_tx = doge_cs.mktx(join_inputs, [{"value": final_out_sat, "address": APOCRYPHA_ADDR}])
join_signed = doge_cs.signall(join_tx, PRIV)
join_hex    = cs_serialize(join_signed)
join_txid   = _txid_of_serial(join_hex)
print(f"  join txid: {join_txid}")

# =============================================================================
#                       6. VERIFICATION + ARTIFACTS
# =============================================================================
print()
print("=" * 72)
print("PHASE 6 — verification report")
print("=" * 72)

total_strand_fees = actual_total_knots * TIP_SAT
total_fees        = splitter_fee + ROOT_FEE_SAT + total_strand_fees + actual_join_fee
print(f"  splitter fee:        {doge(splitter_fee):>16}")
print(f"  root fee:            {doge(ROOT_FEE_SAT):>16}")
print(f"  strand fees:         {doge(total_strand_fees):>16}  ({actual_total_knots} × {doge(TIP_SAT)})")
print(f"  join fee:            {doge(actual_join_fee):>16}")
print(f"  ──────────────────   ─────────────────")
print(f"  TOTAL FEES:          {doge(total_fees):>16}")
print(f"  apocrypha input:     {doge(total_in):>16}")
print(f"  final residual:      {doge(final_out_sat):>16}")
assert total_fees == total_in - final_out_sat

print()
print("  TX HEX SIZES")
print(f"    splitter:  {len(splitter_hex)//2:>6} B")
print(f"    root:      {len(root_hex)//2:>6} B")
print(f"    join:      {len(join_hex)//2:>6} B")

ARTIFACTS.mkdir(exist_ok=True)
(ARTIFACTS / "splitter.hex").write_text(splitter_hex)
(ARTIFACTS / "splitter.txid").write_text(splitter_txid)
(ARTIFACTS / "root_book.hex").write_text(root_hex)
(ARTIFACTS / "root_book.txid").write_text(root_txid)
for i, cad in enumerate(cadenas):
    (ARTIFACTS / f"strand_book_{i}.txns").write_text("\n".join(cad.txns))
    (ARTIFACTS / f"strand_book_{i}.txids").write_text("\n".join(cad.txn_ids))
(ARTIFACTS / "book_header.bin").write_bytes(book_header)
(ARTIFACTS / "book_body.bin").write_bytes(book_body)
(ARTIFACTS / "join.hex").write_text(join_hex)
(ARTIFACTS / "join.txid").write_text(join_txid)

print()
print(f"  artifacts written to {ARTIFACTS}")
print("  READY TO BROADCAST.")
