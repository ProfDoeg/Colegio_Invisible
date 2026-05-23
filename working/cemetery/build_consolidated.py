"""Build the consolidated 3-quipu inscription (deterministic, no broadcast).

Architecture (mirrors working/goethe_hebrew/build_consolidated.py):

    apocrypha utxo(s) (~80 DOGE expected)
        -> mega-splitter        (M inputs, 3 outputs)
        -> 3 per-quipu roots    (each with N strand outputs)
        -> all strands          (parallel CadenaAtom chains)
        -> mega-join            (Σ inputs, 1 output)
        -> residual at apocrypha

Three quipus:
  1. Pinochet portrait              0x03 image, tone 0x0d demonic, 320×400 3-bit gray
  2. Condor invitation letter scan  0x03 image, tone 0x0d demonic, 320×420 3-bit gray
  3. Cementerio de los Animales     0x01 essay, tone 0x00 ordinary

The essay's body contains two 64-char placeholder hex strings as quipu: refs to
the two new images. After computing the per-quipu root_txids, this script
substitutes the real txids back into the essay body (same length, so knot
counts are preserved), re-builds the essay, and re-precomputes its strands.

After this script runs cleanly with PRIV set, broadcast in order:
    1. splitter
    2. all 3 per-quipu roots (parallel)
    3. all strands (parallel waves, mempool-ancestor-limit-aware)
    4. mega-join
"""
import math
import os
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from PIL import Image
import numpy as np
import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import (
    rpc_request, unspent, import_privKey, _txid_of_serial, CadenaAtom,
)

from canonical.image import (
    build_image_quipu, pack_pixels, COLOR_GRAY, TONE_DEMONIC,
)
from canonical.essay import build_essay_quipu, TONE_ORDINARY

# =============================================================================
#                              CONFIGURATION
# =============================================================================

APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"

# Image specs — must match the local PNGs in figures/
PINOCHET_PNG  = THIS_DIR / "figures" / "pinochet_320x400_3bit.png"
PINOCHET_W, PINOCHET_H, PINOCHET_BITS = 320, 400, 3
PINOCHET_TITLE = "Augusto Pinochet Ugarte"

CONDOR_PNG    = THIS_DIR / "figures" / "condor_invite_320x420_3bit.png"
CONDOR_W, CONDOR_H, CONDOR_BITS = 320, 420, 3
CONDOR_TITLE = "DINA, Invitación, Santiago, octubre 1975"

ESSAY_MD      = THIS_DIR / "cementerio_de_los_animales.md"

# Strand distribution — split each large body into N parallel strands.
# Each strand is one CadenaAtom chain of OP_RETURN-bearing transactions.
# Strand counts chosen so each strand's knot count fits under Doge's
# mempool-ancestor-chain limit (25), so every strand confirms in one
# wave (= one block). Knot allocation across strands follows balanced
# modulo arithmetic: total_knots // N base, with the first
# (total_knots % N) strands getting one extra knot. Strands therefore
# differ in length by at most one knot. Reader walks each strand to its
# terminus and concatenates contents in strand order; no interleaving.
PINOCHET_BODY_STRANDS = 26   # 600 body knots → 26 × ~23 (2 × 24)
CONDOR_BODY_STRANDS   = 26   # 630 body knots → 26 × ~24 (6 × 25)
ESSAY_BODY_STRANDS    = 11   # 263 body knots → 11 × ~24 (10 × 24, 1 × 23)

# Placeholder hex strings in the essay body — replaced with real root_txids
# after computing them deterministically. Both 64-char hex (= 1 txid worth).
PINOCHET_PLACEHOLDER = "de" * 32
CONDOR_PLACEHOLDER   = "c0" * 32

# Fee constants — fixed by project convention
TIP_SAT         = 5_000_000      # 0.05 DOGE per strand-tx (knot)
ROOT_FEE_SAT    = 5_000_000      # 0.05 DOGE per per-quipu root
SPLITTER_FEE_SAT= 5_000_000      # 0.05 DOGE for the splitter tx
JOIN_FEE_MIN    = 5_000_000      # 0.05 DOGE minimum for mega-join

# Private key — loaded from the encrypted apocrypha keyfile (empty password,
# matches the cemetery scene inscription pattern).
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
    """Split body into n_strands contiguous knot ranges, modulo-balanced.

    Total body knots = ceil(len(body)/knot_size). Each strand gets
    base = total_knots // n_strands knots; the first (total_knots %
    n_strands) strands get one extra knot. Strands therefore differ
    in length by at most one knot, and the last strand may have a
    partial trailing knot if len(body) % knot_size != 0. Strands are
    contiguous slices of the body so reader-side naive concatenation
    in strand-index order reconstructs the original body bytes."""
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
    assert b"".join(strands) == body, "balanced split lost or duplicated bytes"
    return strands

def quantize_image_body(png_path, W, H, bits):
    """Load PNG, convert to L, resize, quantize to `bits` bits, pack."""
    img = Image.open(png_path).convert("L").resize((W, H), Image.LANCZOS)
    arr = np.array(img, dtype=np.uint8)
    shift = 8 - bits
    arr_q = (arr >> shift).astype(np.uint8)
    pixels = arr_q.flatten().tolist()
    return pack_pixels(pixels, bits)

# =============================================================================
#                       1. BUILD PAYLOADS (header, body)
# =============================================================================
print("=" * 72)
print("PHASE 1 — building the 3 quipus' (header, body) tuples")
print("=" * 72)

# --- 1a. Pinochet image -----------------------------------------------------
pinochet_body = quantize_image_body(PINOCHET_PNG, PINOCHET_W, PINOCHET_H, PINOCHET_BITS)
pinochet_header, _ = build_image_quipu(
    PINOCHET_W, PINOCHET_H, COLOR_GRAY, PINOCHET_BITS,
    PINOCHET_TITLE, pinochet_body, tone=TONE_DEMONIC,
)
print(f"  PINOCHET   header={len(pinochet_header):>4}B  body={len(pinochet_body):>6}B  "
      f"({PINOCHET_W}×{PINOCHET_H} grey {PINOCHET_BITS}-bit · tone=demonic)")

# --- 1b. Condor invitation image --------------------------------------------
condor_body = quantize_image_body(CONDOR_PNG, CONDOR_W, CONDOR_H, CONDOR_BITS)
condor_header, _ = build_image_quipu(
    CONDOR_W, CONDOR_H, COLOR_GRAY, CONDOR_BITS,
    CONDOR_TITLE, condor_body, tone=TONE_DEMONIC,
)
print(f"  CONDOR     header={len(condor_header):>4}B  body={len(condor_body):>6}B  "
      f"({CONDOR_W}×{CONDOR_H} grey {CONDOR_BITS}-bit · tone=demonic)")

# --- 1c. Essay (with placeholder txids; substituted real ones in Phase 4) ----
essay_md = ESSAY_MD.read_text(encoding="utf-8")
assert PINOCHET_PLACEHOLDER in essay_md, f"Pinochet placeholder not found in essay"
assert CONDOR_PLACEHOLDER   in essay_md, f"Condor placeholder not found in essay"

essay_header, essay_body = build_essay_quipu(
    title="Cementerio de los Animales",
    body_markdown=essay_md,
    tone=TONE_ORDINARY,
    fields={
        "author": "El Ermitaño",
        "date":   "2026-05-22",
        "lang":   "en",
        "place":  "Cazón, Provincia de Buenos Aires, Argentina",
    },
)
print(f"  ESSAY      header={len(essay_header):>4}B  body={len(essay_body):>6}B  "
      f"(0x01 essay · tone=ordinary)")

# =============================================================================
#                       2. STRAND LAYOUT + FEE CALC
# =============================================================================
print()
print("=" * 72)
print("PHASE 2 — strand layout per quipu")
print("=" * 72)

quipus = {
    "pinochet": {
        "label":   "Pinochet Portrait",
        "strands": [pinochet_header] + split_body(pinochet_body, PINOCHET_BODY_STRANDS),
    },
    "condor": {
        "label":   "Condor Invitation",
        "strands": [condor_header] + split_body(condor_body, CONDOR_BODY_STRANDS),
    },
    "essay": {
        "label":   "Cementerio de los Animales",
        "strands": [essay_header] + split_body(essay_body, ESSAY_BODY_STRANDS),
    },
}

total_knots = 0
total_strands = 0
for key, q in quipus.items():
    q["knots"] = [knot_count(p) for p in q["strands"]]
    total_knots += sum(q["knots"])
    total_strands += len(q["strands"])
    print(f"  {q['label']:<32} strands={len(q['strands']):>2}  knots={sum(q['knots']):>4}")

print()
print(f"  TOTAL strands: {total_strands}")
print(f"  TOTAL knots:   {total_knots}")

# Query apocrypha UTXOs at runtime. Pick the single largest one as the
# splitter input; leave any smaller UTXOs alone (e.g. the cemetery
# inscription's join terminus residual).
print()
print("  querying apocrypha utxos...")
import warnings; warnings.filterwarnings("ignore")
all_utxos = sorted(unspent(APOCRYPHA_ADDR), key=lambda u: -u["value"])
print(f"  apocrypha has {len(all_utxos)} utxo(s):")
for u in all_utxos:
    print(f"    {u['output']}  {doge(u['value'])}")
if not all_utxos:
    raise SystemExit("FATAL: apocrypha has no utxos")
utxos = [all_utxos[0]]   # consume only the largest
total_in = utxos[0]["value"]
print(f"  using only the largest: {utxos[0]['output']}  {doge(total_in)}")

# Cost calc
strand_fees      = total_knots * TIP_SAT
total_root_fees  = len(quipus) * ROOT_FEE_SAT
mandatory_fees   = SPLITTER_FEE_SAT + total_root_fees + strand_fees + JOIN_FEE_MIN
print(f"  required fees: {doge(mandatory_fees)}  (splitter {doge(SPLITTER_FEE_SAT)} + "
      f"{len(quipus)} roots × {doge(ROOT_FEE_SAT)} + {total_knots} knots × {doge(TIP_SAT)} + "
      f"min join {doge(JOIN_FEE_MIN)})")
if total_in < mandatory_fees:
    raise SystemExit(
        f"\nFATAL: insufficient funds. apocrypha has {doge(total_in)} but need "
        f"at least {doge(mandatory_fees)}. Top up the address and re-run.\n"
    )

# Solve for distribution. Mirror Goethe's approach:
#   total_in - final_out = splitter_fee + 3*root_fee + total_knots*tip + join_fee
# We pick FINAL_OUT_SAT = whatever is left after a clean 0.05 join fee.
join_fee_sat  = JOIN_FEE_MIN
final_out_sat = total_in - SPLITTER_FEE_SAT - total_root_fees - strand_fees - join_fee_sat
assert final_out_sat > 100_000, f"final_out below safe dust threshold: {final_out_sat}"

# Sum of all strand terminals = join_fee + final_out
total_terminals_sat = join_fee_sat + final_out_sat
base_terminal = total_terminals_sat // total_strands
remainder     = total_terminals_sat - base_terminal * total_strands

# Assign per-strand seeds
strand_index = 0
for key, q in quipus.items():
    q["seeds"] = []
    for i, k in enumerate(q["knots"]):
        terminal = base_terminal + (remainder if strand_index == 0 else 0)
        q["seeds"].append(k * TIP_SAT + terminal)
        strand_index += 1
    q["root_input"] = sum(q["seeds"]) + ROOT_FEE_SAT

splitter_outputs = [q["root_input"] for q in quipus.values()]
splitter_out_sum = sum(splitter_outputs)
splitter_fee     = total_in - splitter_out_sum
assert splitter_fee == SPLITTER_FEE_SAT, f"splitter_fee {splitter_fee} != {SPLITTER_FEE_SAT}"

print()
print(f"  splitter input:           {doge(total_in)}")
print(f"  splitter outputs sum:     {doge(splitter_out_sum)}")
print(f"  splitter fee:             {doge(splitter_fee)}")
print(f"  predicted mega-join fee:  {doge(join_fee_sat)}")
print(f"  predicted final residual: {doge(final_out_sat)}")

# =============================================================================
#                       3. BUILD SPLITTER + PER-QUIPU ROOTS
# =============================================================================
print()
print("=" * 72)
print("PHASE 3 — splitter + per-quipu root txs (deterministic, signed)")
print("=" * 72)

priv_obj = import_privKey(KEY_PATH, "")
priv_hex_raw = priv_obj.to_hex()
PRIV = priv_hex_raw[2:] if priv_hex_raw.startswith("0x") else priv_hex_raw
doge_cs = cryptos.Doge()
addr = doge_cs.privtoaddr(PRIV)
assert addr == APOCRYPHA_ADDR, f"key derives {addr}, expected {APOCRYPHA_ADDR}"

# Splitter: consume ALL apocrypha utxos → N outputs (one per per-quipu root)
splitter_tx = doge_cs.mktx(
    utxos,
    [{"value": v, "address": APOCRYPHA_ADDR} for v in splitter_outputs],
)
splitter_signed = doge_cs.signall(splitter_tx, PRIV)
splitter_hex    = cs_serialize(splitter_signed)
splitter_txid   = _txid_of_serial(splitter_hex)
print(f"  splitter txid: {splitter_txid}")

# Per-quipu root txs
root_txids = {}
root_hexes = {}
for i, (key, q) in enumerate(quipus.items()):
    root_input = {
        "output": f"{splitter_txid}:{i}",
        "value":  q["root_input"],
    }
    root_outputs = [{"value": s, "address": APOCRYPHA_ADDR} for s in q["seeds"]]
    root_tx = doge_cs.mktx([root_input], root_outputs)
    root_signed = doge_cs.signall(root_tx, PRIV)
    root_hex    = cs_serialize(root_signed)
    root_txid   = _txid_of_serial(root_hex)
    root_txids[key] = root_txid
    root_hexes[key] = root_hex
    q["root_txid"] = root_txid
    print(f"  {key:<8} root_txid: {root_txid}")

# =============================================================================
#                4. SUBSTITUTE REAL TXIDS INTO ESSAY BODY
# =============================================================================
print()
print("=" * 72)
print("PHASE 4 — substitute real root_txids into essay body")
print("=" * 72)

substitutions = {
    PINOCHET_PLACEHOLDER: root_txids["pinochet"],
    CONDOR_PLACEHOLDER:   root_txids["condor"],
}
new_essay_md = essay_md
for placeholder, real in substitutions.items():
    assert placeholder in new_essay_md, f"placeholder {placeholder[:16]}… not found"
    assert len(placeholder) == len(real), \
        f"length mismatch: placeholder {len(placeholder)} vs real {len(real)}"
    new_essay_md = new_essay_md.replace(placeholder, real)
    print(f"  {placeholder[:16]}… -> {real}")

new_essay_header, new_essay_body = build_essay_quipu(
    title="Cementerio de los Animales",
    body_markdown=new_essay_md,
    tone=TONE_ORDINARY,
    fields={
        "author": "El Ermitaño",
        "date":   "2026-05-22",
        "lang":   "en",
        "place":  "Cazón, Provincia de Buenos Aires, Argentina",
    },
)
assert len(new_essay_header) == len(essay_header), "essay header length changed!"
assert len(new_essay_body)   == len(essay_body),   "essay body length changed!"
print(f"  essay body length invariant: {len(essay_body)} B ✓")

# Replace the essay's strand payloads with the txid-substituted versions
quipus["essay"]["strands"] = [new_essay_header] + split_body(new_essay_body, ESSAY_BODY_STRANDS)

# =============================================================================
#                5. PRECOMPUTE ALL CADENA STRANDS
# =============================================================================
print()
print("=" * 72)
print("PHASE 5 — precompute all Cadena strands")
print("=" * 72)

all_cadenas = []  # list of (quipu_key, strand_index, cadena)
for key, q in quipus.items():
    q_cads = []
    for i, payload in enumerate(q["strands"]):
        seed_utxo = {
            "output": f"{q['root_txid']}:{i}",
            "value":  q["seeds"][i],
        }
        cad = CadenaAtom(PRIV, payload, seed_utxo, TIP_SAT)
        cad.precompute()
        q_cads.append(cad)
        all_cadenas.append((key, i, cad))
    q["cadenas"] = q_cads
    n_knots = sum(len(c.txns) for c in q_cads)
    print(f"  {key:<8} {len(q_cads)} strands  knots={n_knots}")

actual_total_knots = sum(len(c.txns) for _, _, c in all_cadenas)
assert actual_total_knots == total_knots, \
    f"knot mismatch: {actual_total_knots} vs predicted {total_knots}"
print(f"  total knot txs precomputed: {actual_total_knots}")

# =============================================================================
#                6. BUILD MEGA-JOIN
# =============================================================================
print()
print("=" * 72)
print(f"PHASE 6 — mega-join ({total_strands} inputs → 1 output)")
print("=" * 72)

join_inputs = []
for key, i, cad in all_cadenas:
    terminus_value = quipus[key]["seeds"][i] - TIP_SAT * len(cad.txns)
    join_inputs.append({
        "output": f"{cad.txn_ids[-1]}:0",
        "value":  terminus_value,
    })

actual_total_in = sum(inp["value"] for inp in join_inputs)
actual_join_fee = actual_total_in - final_out_sat
print(f"  total terminus value: {doge(actual_total_in)}")
print(f"  final output:         {doge(final_out_sat)}")
print(f"  mega-join fee:        {doge(actual_join_fee)}")
if actual_join_fee < 0:
    raise SystemExit(
        f"FATAL: terminus values too small to leave {doge(final_out_sat)} after join_fee"
    )

join_tx = doge_cs.mktx(
    join_inputs,
    [{"value": final_out_sat, "address": APOCRYPHA_ADDR}],
)
join_signed = doge_cs.signall(join_tx, PRIV)
join_hex    = cs_serialize(join_signed)
join_txid   = _txid_of_serial(join_hex)
print(f"  mega-join txid: {join_txid}")

# =============================================================================
#                7. VERIFICATION + ARTIFACTS
# =============================================================================
print()
print("=" * 72)
print("PHASE 7 — verification report")
print("=" * 72)

total_strand_fees = actual_total_knots * TIP_SAT
total_fees        = splitter_fee + total_root_fees + total_strand_fees + actual_join_fee

print(f"  splitter fee:              {doge(splitter_fee):>16}")
print(f"  per-quipu root fees (×{len(quipus)}):  {doge(total_root_fees):>16}")
print(f"  strand fees:               {doge(total_strand_fees):>16}  ({actual_total_knots} × {doge(TIP_SAT)})")
print(f"  mega-join fee:             {doge(actual_join_fee):>16}")
print(f"  ─────────────────────────  ─────────────────")
print(f"  TOTAL FEES:                {doge(total_fees):>16}")
print(f"  apocrypha input:           {doge(total_in):>16}")
print(f"  final output (residual):   {doge(final_out_sat):>16}")

assert total_fees == total_in - final_out_sat, "fee accounting broken"

print()
print("  TX HEX SIZES")
print(f"    splitter:  {len(splitter_hex)//2:>6} B")
for key in quipus:
    print(f"    root[{key:<8}] {len(root_hexes[key])//2:>6} B")
print(f"    mega-join: {len(join_hex)//2:>6} B")

# Write artifacts
ARTIFACTS.mkdir(exist_ok=True)
(ARTIFACTS / "splitter.hex").write_text(splitter_hex)
(ARTIFACTS / "splitter.txid").write_text(splitter_txid)
for key, q in quipus.items():
    (ARTIFACTS / f"root_{key}.hex").write_text(root_hexes[key])
    (ARTIFACTS / f"root_{key}.txid").write_text(q["root_txid"])
    for i, cad in enumerate(q["cadenas"]):
        (ARTIFACTS / f"strand_{key}_{i}.txns").write_text("\n".join(cad.txns))
        (ARTIFACTS / f"strand_{key}_{i}.txids").write_text("\n".join(cad.txn_ids))
    # Post-substitution (header, body) for the dataset update step
    header_bytes = q["strands"][0]
    body_bytes   = b"".join(q["strands"][1:])
    (ARTIFACTS / f"{key}_header.bin").write_bytes(header_bytes)
    (ARTIFACTS / f"{key}_body.bin").write_bytes(body_bytes)
(ARTIFACTS / "megajoin.hex").write_text(join_hex)
(ARTIFACTS / "megajoin.txid").write_text(join_txid)

print()
print(f"  artifacts written to {ARTIFACTS}")
print("  READY TO BROADCAST.")
