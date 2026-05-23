"""Build the 2-quipu corrections inscription (deterministic, no broadcast).

  binding (0xab) — 8 string-substitution rules mapping each hardcoded
                   https://dogechain.info/tx/<txid> URL in the v1
                   essay body to its in-protocol <<txid>> citation form.

  essay v2 (0x01) — corrected republication of the v1 essay
                    (d442073b…), using <<txid>> form throughout and a
                    closing paragraph that cites the broken v1 + the
                    corrections binding by their root_txids.

Same architecture as working/cemetery/build_consolidated.py:

    apocrypha utxo
        -> splitter   (1 in, 2 out)
        -> 2 per-quipu roots
        -> all strands  (parallel CadenaAtom chains, ≤25 knots each)
        -> mega-join  (Σ in, 1 out → residual at apocrypha)

The essay body contains an "abab…64" placeholder (64-hex) where the
binding's root_txid belongs. After computing the binding's root_txid
deterministically in Phase 3, the placeholder is substituted into the
essay body (length-invariant) and the essay is re-built.
"""
import math
import os
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import (
    rpc_request, unspent, import_privKey, _txid_of_serial, CadenaAtom,
)

from canonical.bindings import build_binding_quipu, TONE_ORDINARY as BIND_ORDINARY
from canonical.essay    import build_essay_quipu, TONE_ORDINARY

# =============================================================================
#                              CONFIGURATION
# =============================================================================
APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
KEY_PATH       = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"

BINDING_AB = THIS_DIR / "corrections.ab"
ESSAY_MD   = THIS_DIR / "cementerio_v2.md"

# Strand layout — each strand ≤25 knots so it fits one mempool wave.
# binding is small (~1.2 KB → 15 knots) — 1 strand suffices.
# essay v2 is ~21 KB → 263 knots → 11 strands × ~24 knots.
BINDING_BODY_STRANDS = 1
ESSAY_BODY_STRANDS   = 1

# Placeholder for the binding's root_txid in the v2 essay body —
# replaced with the real txid after Phase 3 (length invariant: 64 hex).
BINDING_PLACEHOLDER = "ab" * 32

# Fee constants
TIP_SAT          = 5_000_000   # 0.05 DOGE per knot
ROOT_FEE_SAT     = 5_000_000
SPLITTER_FEE_SAT = 5_000_000
JOIN_FEE_MIN     = 5_000_000

ARTIFACTS = THIS_DIR / "corrections_artifacts"

# =============================================================================
#                              HELPERS
# =============================================================================
def doge(sat):
    return f"{sat/100_000_000:.8f} DOGE"

def knot_count(payload_bytes):
    return math.ceil(len(payload_bytes) / 80) if payload_bytes else 1

def split_body(body, n_strands, knot_size=80):
    """Split body into n_strands contiguous knot ranges, modulo-balanced.
    Same shape as build_consolidated.split_body: each strand gets
    (total_knots // N) + (1 if i < total_knots % N else 0) knots; the
    last strand may have a partial trailing knot. Strands are contiguous
    so reader-side naive concatenation reconstructs the body."""
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


# =============================================================================
#                       1. BUILD PAYLOADS
# =============================================================================
print("=" * 72)
print("PHASE 1 — building the 2 quipus' (header, body) tuples")
print("=" * 72)

# 1a. Binding
binding_text = BINDING_AB.read_text(encoding="utf-8")
binding_header, binding_body = build_binding_quipu(binding_text, tone=BIND_ORDINARY)
print(f"  BINDING  header={len(binding_header):>4}B  body={len(binding_body):>6}B  "
      f"(0xab binding · tone=ordinary)")

# 1b. Essay v2 — minimal two-citation body. The binding txid is a
# 64-char placeholder, substituted with the real value in Phase 4.
essay_md = ESSAY_MD.read_text(encoding="utf-8")
assert BINDING_PLACEHOLDER in essay_md, "binding placeholder missing in v2 essay"
essay_header, essay_body = build_essay_quipu(
    title="Cementerio de los Animales",
    body_markdown=essay_md,
    tone=TONE_ORDINARY,
    fields={
        "author":   "El Ermitaño",
        "date":     "2026-05-22",
        "lang":     "en",
        "place":    "Cazón, Provincia de Buenos Aires, Argentina",
        "previous": "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985",
    },
)
print(f"  ESSAY    header={len(essay_header):>4}B  body={len(essay_body):>6}B  "
      f"(0x01 essay · tone=ordinary · v2 of d442073b…)")

# =============================================================================
#                       2. STRAND LAYOUT + FEE CALC
# =============================================================================
print()
print("=" * 72)
print("PHASE 2 — strand layout per quipu")
print("=" * 72)

quipus = {
    "binding": {
        "label":   "Corrections binding (0xab)",
        "strands": [binding_header] + split_body(binding_body, BINDING_BODY_STRANDS),
    },
    "essay": {
        "label":   "Cementerio v2 (0x01)",
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

# Query apocrypha UTXOs at runtime; pick the single largest one
print()
print("  querying apocrypha utxos...")
import warnings; warnings.filterwarnings("ignore")
all_utxos = sorted(unspent(APOCRYPHA_ADDR), key=lambda u: -u["value"])
print(f"  apocrypha has {len(all_utxos)} utxo(s):")
for u in all_utxos:
    print(f"    {u['output']}  {doge(u['value'])}")
if not all_utxos:
    raise SystemExit("FATAL: apocrypha has no utxos")
utxos = [all_utxos[0]]
total_in = utxos[0]["value"]
print(f"  using only the largest: {utxos[0]['output']}  {doge(total_in)}")

# Fee calc
strand_fees     = total_knots * TIP_SAT
total_root_fees = len(quipus) * ROOT_FEE_SAT
mandatory_fees  = SPLITTER_FEE_SAT + total_root_fees + strand_fees + JOIN_FEE_MIN
print(f"  required fees: {doge(mandatory_fees)}")
if total_in < mandatory_fees:
    raise SystemExit(
        f"\nFATAL: insufficient funds. apocrypha has {doge(total_in)} but need "
        f"at least {doge(mandatory_fees)}.\n"
    )

join_fee_sat  = JOIN_FEE_MIN
final_out_sat = total_in - SPLITTER_FEE_SAT - total_root_fees - strand_fees - join_fee_sat
total_terminals_sat = join_fee_sat + final_out_sat
base_terminal = total_terminals_sat // total_strands
remainder     = total_terminals_sat - base_terminal * total_strands

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
assert splitter_fee == SPLITTER_FEE_SAT

print()
print(f"  splitter input:           {doge(total_in)}")
print(f"  splitter fee:             {doge(splitter_fee)}")
print(f"  predicted mega-join fee:  {doge(join_fee_sat)}")
print(f"  predicted final residual: {doge(final_out_sat)}")

# =============================================================================
#                       3. BUILD SPLITTER + PER-QUIPU ROOTS
# =============================================================================
print()
print("=" * 72)
print("PHASE 3 — splitter + per-quipu root txs")
print("=" * 72)

priv_obj = import_privKey(KEY_PATH, "")
priv_hex_raw = priv_obj.to_hex()
PRIV = priv_hex_raw[2:] if priv_hex_raw.startswith("0x") else priv_hex_raw
doge_cs = cryptos.Doge()
addr = doge_cs.privtoaddr(PRIV)
assert addr == APOCRYPHA_ADDR, f"key derives {addr}, expected {APOCRYPHA_ADDR}"

splitter_tx = doge_cs.mktx(
    utxos,
    [{"value": v, "address": APOCRYPHA_ADDR} for v in splitter_outputs],
)
splitter_signed = doge_cs.signall(splitter_tx, PRIV)
splitter_hex    = cs_serialize(splitter_signed)
splitter_txid   = _txid_of_serial(splitter_hex)
print(f"  splitter txid: {splitter_txid}")

root_txids = {}
root_hexes = {}
for i, (key, q) in enumerate(quipus.items()):
    root_input = {"output": f"{splitter_txid}:{i}", "value": q["root_input"]}
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
#                4. SUBSTITUTE BINDING TXID INTO ESSAY BODY
# =============================================================================
print()
print("=" * 72)
print("PHASE 4 — substitute binding's root_txid into essay body")
print("=" * 72)

real_binding_txid = root_txids["binding"]
assert len(real_binding_txid) == len(BINDING_PLACEHOLDER) == 64
new_essay_md = essay_md.replace(BINDING_PLACEHOLDER, real_binding_txid)
print(f"  {BINDING_PLACEHOLDER[:16]}… -> {real_binding_txid}")

new_essay_header, new_essay_body = build_essay_quipu(
    title="Cementerio de los Animales",
    body_markdown=new_essay_md,
    tone=TONE_ORDINARY,
    fields={
        "author":   "El Ermitaño",
        "date":     "2026-05-22",
        "lang":     "en",
        "place":    "Cazón, Provincia de Buenos Aires, Argentina",
        "previous": "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985",
    },
)
assert len(new_essay_header) == len(essay_header), "essay header length changed!"
assert len(new_essay_body)   == len(essay_body),   "essay body length changed!"
print(f"  essay body length invariant: {len(essay_body)} B ✓")

quipus["essay"]["strands"] = [new_essay_header] + split_body(new_essay_body, ESSAY_BODY_STRANDS)

# =============================================================================
#                5. PRECOMPUTE ALL CADENA STRANDS
# =============================================================================
print()
print("=" * 72)
print("PHASE 5 — precompute all Cadena strands")
print("=" * 72)

all_cadenas = []
for key, q in quipus.items():
    q_cads = []
    for i, payload in enumerate(q["strands"]):
        seed_utxo = {"output": f"{q['root_txid']}:{i}", "value": q["seeds"][i]}
        cad = CadenaAtom(PRIV, payload, seed_utxo, TIP_SAT)
        cad.precompute()
        q_cads.append(cad)
        all_cadenas.append((key, i, cad))
    q["cadenas"] = q_cads
    n_knots = sum(len(c.txns) for c in q_cads)
    print(f"  {key:<8} {len(q_cads)} strands  knots={n_knots}")

actual_total_knots = sum(len(c.txns) for _, _, c in all_cadenas)
assert actual_total_knots == total_knots

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
    join_inputs.append({"output": f"{cad.txn_ids[-1]}:0", "value": terminus_value})

actual_total_in = sum(inp["value"] for inp in join_inputs)
actual_join_fee = actual_total_in - final_out_sat
print(f"  total terminus value: {doge(actual_total_in)}")
print(f"  final output:         {doge(final_out_sat)}")
print(f"  mega-join fee:        {doge(actual_join_fee)}")

join_tx = doge_cs.mktx(
    join_inputs, [{"value": final_out_sat, "address": APOCRYPHA_ADDR}],
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
total_fees = splitter_fee + total_root_fees + total_strand_fees + actual_join_fee

print(f"  splitter fee:              {doge(splitter_fee):>16}")
print(f"  per-quipu root fees (×2):  {doge(total_root_fees):>16}")
print(f"  strand fees:               {doge(total_strand_fees):>16}  ({actual_total_knots} × {doge(TIP_SAT)})")
print(f"  mega-join fee:             {doge(actual_join_fee):>16}")
print(f"  ─────────────────────────  ─────────────────")
print(f"  TOTAL FEES:                {doge(total_fees):>16}")
print(f"  apocrypha input:           {doge(total_in):>16}")
print(f"  final output (residual):   {doge(final_out_sat):>16}")

ARTIFACTS.mkdir(exist_ok=True)
(ARTIFACTS / "splitter.hex").write_text(splitter_hex)
(ARTIFACTS / "splitter.txid").write_text(splitter_txid)
for key, q in quipus.items():
    (ARTIFACTS / f"root_{key}.hex").write_text(root_hexes[key])
    (ARTIFACTS / f"root_{key}.txid").write_text(q["root_txid"])
    for i, cad in enumerate(q["cadenas"]):
        (ARTIFACTS / f"strand_{key}_{i}.txns").write_text("\n".join(cad.txns))
        (ARTIFACTS / f"strand_{key}_{i}.txids").write_text("\n".join(cad.txn_ids))
    header_bytes = q["strands"][0]
    body_bytes   = b"".join(q["strands"][1:])
    (ARTIFACTS / f"{key}_header.bin").write_bytes(header_bytes)
    (ARTIFACTS / f"{key}_body.bin").write_bytes(body_bytes)
(ARTIFACTS / "megajoin.hex").write_text(join_hex)
(ARTIFACTS / "megajoin.txid").write_text(join_txid)

print()
print(f"  artifacts written to {ARTIFACTS}")
print("  READY TO BROADCAST.")
