"""Build the consolidated El Libro del Gólem inscription (deterministic, no broadcast).

Twelve quipus, single mega-diamond, signed by the 2-of-2 multiman multisig:

  binding        commentary.ab      (0xab, tone 0xa1 ai)
  forward        forward.md          (0x01 essay, ordinary)
  essay/01       tone.md             (0x01 essay, ordinary)
  essay/02       mythology.md        (0x01 essay, ordinary)
  essay/03       diamonds.md         (0x01 essay, ordinary)
  essay/04       weaving.md          (0x01 essay, ordinary)
  essay/05       multisig.md         (0x01 essay, ordinary)
  art/01         01_cord.tex         (0x5c latex, ai)
  art/02         02_diamond.tex      (0x5c latex, ai)
  art/03         03_page.tex         (0x5c latex, ai)
  art/04         04_tone.tex         (0x5c latex, ai)
  book           (the book itself)   (0x09 book, ordinary)

The book body lists every other quipu by ref_txid + tag + name, plus
references to the embedded Dos ensayos / Goethe / Cementerio quipus
already on chain. Because the book body must contain the freshly-
computed root_txids of the other 11 quipus, we use deterministic
placeholders during the initial build and substitute the real txids
back into the body in Phase 4 (same length, no strand layout change).
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
    rpc_request, unspent, import_privKey, _txid_of_serial,
    CadenaMultiAtom, mk_opreturn,
)

from canonical.essay   import build_essay_quipu
from canonical.bindings import build_binding_quipu
from canonical.latex   import build_latex_quipu
from canonical.book    import build_book_quipu
from canonical.tone    import TONE_ORDINARY, TONE_AI

# =============================================================================
#                              CONFIGURATION
# =============================================================================

MULTIMAN_ADDR = "A3ShjwjsAE4ysM66EZJM3A28tPnL2jNDgC"

# On-chain root_txids of pre-existing quipus referenced in the book
GOETHE_TXID    = "84fbbb17718523edf373630e68239fa9abda85297ba2aca8a69ace04f0ad5fb5"
CEMENTERIO_TXID = "449e67f4a2e948f044e1a32662b58ccedad3cf8e85a742cc45b6b6541e47b5d7"
DOS_ENSAYOS_TXID = "26671514416913719c560a4ac1246e333e410d2503e298a8a6852031c3285888"

# Source files
ART_DIR = THIS_DIR / "art"
SOURCES = {
    "binding":  (THIS_DIR / "commentary.ab",   "binding",   "Comentario del Gólem", TONE_AI),
    "forward":  (THIS_DIR / "forward.md",       "forward",  "The Glossator's Forward",        TONE_ORDINARY),
    "essay1":   (THIS_DIR / "tone.md",          "essay/01", "On the Tone Byte",               TONE_ORDINARY),
    "essay2":   (THIS_DIR / "mythology.md",     "essay/02", "On Mythology and Identity",      TONE_ORDINARY),
    "essay3":   (THIS_DIR / "diamonds.md",      "essay/03", "On Diamonds and Capital",        TONE_ORDINARY),
    "essay4":   (THIS_DIR / "weaving.md",       "essay/04", "On Weaving",                     TONE_ORDINARY),
    "essay5":   (THIS_DIR / "multisig.md",      "essay/05", "On the Multisig and the AI",     TONE_ORDINARY),
    "cover":    (THIS_DIR / "cover.tex",         "cover",    "El Libro del Gólem — Cover", TONE_AI),
    "art1":     (ART_DIR  / "01_cord.tex",      "art/01",   "Composition I — Cord",      TONE_AI),
    "art2":     (ART_DIR  / "02_diamond.tex",   "art/02",   "Composition II — Diamond",  TONE_AI),
    "art3":     (ART_DIR  / "03_page.tex",      "art/03",   "Composition III — Page",    TONE_AI),
    "art4":     (ART_DIR  / "04_tone.tex",      "art/04",   "Composition IV — Tone",     TONE_AI),
}

# Fee constants
TIP_SAT          = 5_000_000
ROOT_FEE_SAT     = 5_000_000
SPLITTER_FEE_SAT = 5_000_000
JOIN_FEE_MIN     =30_000_000   # 0.30 DOGE — multisig megajoin is large

KEY1_PATH = "/Users/anthonyschultz/Desktop/cinv/llaves/key1_prv.enc"
MI_PATH   = "/Users/anthonyschultz/Desktop/cinv/llaves/mi_prv.enc"
ARTIFACTS = THIS_DIR / "artifacts"

# =============================================================================
#                              HELPERS
# =============================================================================

def doge(sat):
    return f"{sat/100_000_000:.8f} DOGE"

def knot_count(payload_bytes):
    return math.ceil(len(payload_bytes) / 80) if payload_bytes else 1

def split_body(body, n_strands, knot_size=80):
    """Balanced split: total_knots // n base, first (rem) get one extra."""
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

def choose_n_strands(body_len, max_per_strand_knots=24):
    """Pick smallest N so each body strand has <= max_per_strand_knots knots."""
    total_knots = math.ceil(body_len / 80) if body_len else 1
    return max(1, math.ceil(total_knots / max_per_strand_knots))

# =============================================================================
#                       1. BUILD INDIVIDUAL QUIPUS
# =============================================================================
print("=" * 72)
print("PHASE 1 — building 12 inner quipus (binding + 6 essays + cover + 4 art)")
print("=" * 72)

# Per-quipu builders, keyed by SOURCES key
builders = {
    "binding": lambda src: build_binding_quipu(src, tone=TONE_AI),
    "forward": lambda src: build_essay_quipu(
        "The Glossator's Forward", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "essay1":  lambda src: build_essay_quipu(
        "On the Tone Byte", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "essay2":  lambda src: build_essay_quipu(
        "On Mythology and Identity", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "essay3":  lambda src: build_essay_quipu(
        "On Diamonds and Capital", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "essay4":  lambda src: build_essay_quipu(
        "On Weaving", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "essay5":  lambda src: build_essay_quipu(
        "On the Multisig and the AI", src, tone=TONE_ORDINARY,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "en"},
    ),
    "cover":   lambda src: build_latex_quipu(
        "El Libro del Gólem — Cover", src, tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "es", "engine": "pdflatex"},
    ),
    "art1":    lambda src: build_latex_quipu(
        "Composition I — Cord", src, tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "es", "engine": "pdflatex"},
    ),
    "art2":    lambda src: build_latex_quipu(
        "Composition II — Diamond", src, tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "es", "engine": "pdflatex"},
    ),
    "art3":    lambda src: build_latex_quipu(
        "Composition III — Page", src, tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "es", "engine": "pdflatex"},
    ),
    "art4":    lambda src: build_latex_quipu(
        "Composition IV — Tone", src, tone=TONE_AI,
        fields={"author": "El Gólem", "date": "2026-05-23", "lang": "es", "engine": "pdflatex"},
    ),
}

quipus = {}   # key -> dict with header, body, strands, knots, etc.
for key, (path, tag, name, tone) in SOURCES.items():
    src_text = path.read_text(encoding="utf-8")
    if key == "binding":
        # binding builder takes the body text directly
        header, body = builders[key](src_text)
    else:
        header, body = builders[key](src_text)
    n_body_strands = choose_n_strands(len(body))
    strands = [header] + split_body(body, n_body_strands)
    knots = [knot_count(p) for p in strands]
    quipus[key] = {
        "tag":       tag,
        "name":      name,
        "tone":      tone,
        "header":    header,
        "body":      body,
        "strands":   strands,
        "knots":     knots,
        "n_strands": len(strands),
    }
    print(f"  {key:<8} {tag:<10} header={len(header):>3}B body={len(body):>6}B "
          f"strands={len(strands):>2} knots={sum(knots):>4} tone=0x{tone:02x}")

# =============================================================================
#                  2. BUILD BOOK BODY WITH PLACEHOLDER TXIDS
# =============================================================================
print()
print("=" * 72)
print("PHASE 2 — book body with placeholder txids (substituted in Phase 4)")
print("=" * 72)

# Order matters: book entries are listed in this order. Placeholder txid is
# 32 raw bytes that we'll substitute back later. Each placeholder is unique
# so the substitution is unambiguous.
PLACEHOLDER_KEYS = [
    "binding", "cover", "forward", "essay1", "essay2", "essay3", "essay4", "essay5",
    "art1", "art2", "art3", "art4",
]
def placeholder_bytes(i):
    # 32-byte pattern: 0xfe followed by a unique single-byte tag, then 30 bytes of 0xfe
    return bytes([0xfe, i] + [0xfe] * 30)

# Build book entries in order: binding first, then forward, essays, art,
# then the embedded Goethe/Cementerio essays, then Dos ensayos subbook.
book_entries = []
for i, key in enumerate(PLACEHOLDER_KEYS):
    book_entries.append({
        "ref_txid": placeholder_bytes(i),
        "tag":      quipus[key]["tag"],
        "name":     quipus[key]["name"],
    })
# Pre-existing on-chain entries
book_entries.extend([
    {"ref_txid": GOETHE_TXID,     "tag": "essay/06",   "name": "El yiddish del joven Goethe"},
    {"ref_txid": CEMENTERIO_TXID, "tag": "essay/07",   "name": "Cementerio de los Animales"},
    {"ref_txid": DOS_ENSAYOS_TXID,"tag": "subbook/01", "name": "Dos ensayos"},
])

book_header, book_body = build_book_quipu(
    "El Libro del Gólem",
    book_entries,
    tone=TONE_ORDINARY,
    fields={
        "author":    "El Gólem",
        "date":      "2026-05-23",
        "lang":      "es",
        "series":    "Colegio Invisible",
        "publisher": "multiman",
    },
)
n_book_body_strands = choose_n_strands(len(book_body))
book_strands = [book_header] + split_body(book_body, n_book_body_strands)
book_knots = [knot_count(p) for p in book_strands]
quipus["book"] = {
    "tag":       "book",
    "name":      "El Libro del Gólem",
    "tone":      TONE_ORDINARY,
    "header":    book_header,
    "body":      book_body,
    "strands":   book_strands,
    "knots":     book_knots,
    "n_strands": len(book_strands),
}
print(f"  book     book       header={len(book_header):>3}B body={len(book_body):>6}B "
      f"strands={len(book_strands):>2} knots={sum(book_knots):>4} tone=0x00")
print(f"  (entries: {len(book_entries)} = {len(PLACEHOLDER_KEYS)} new + 3 pre-existing)")

# =============================================================================
#                       3. LAYOUT + FUNDING
# =============================================================================
print()
print("=" * 72)
print("PHASE 3 — strand layout + funding analysis")
print("=" * 72)

QUIPU_ORDER = PLACEHOLDER_KEYS + ["book"]
total_strands = sum(quipus[k]["n_strands"] for k in QUIPU_ORDER)
total_knots   = sum(sum(quipus[k]["knots"]) for k in QUIPU_ORDER)
print(f"  total quipus:  {len(QUIPU_ORDER)}")
print(f"  total strands: {total_strands}")
print(f"  total knots:   {total_knots}")

print()
print("  querying multiman utxos...")
import warnings; warnings.filterwarnings("ignore")
all_utxos = sorted(unspent(MULTIMAN_ADDR), key=lambda u: -u["value"])
print(f"  multiman has {len(all_utxos)} utxo(s):")
for u in all_utxos:
    print(f"    {u['output']}  {doge(u['value'])}")
if not all_utxos:
    raise SystemExit("FATAL: multiman has no utxos")

# Use ALL utxos as splitter inputs (we only have 2 anyway, both modest)
utxos = all_utxos
total_in = sum(u["value"] for u in utxos)
print(f"  using {len(utxos)} utxo(s): total in = {doge(total_in)}")

strand_fees      = total_knots * TIP_SAT
total_root_fees  = len(QUIPU_ORDER) * ROOT_FEE_SAT
mandatory_fees   = SPLITTER_FEE_SAT + total_root_fees + strand_fees + JOIN_FEE_MIN
print(f"  required fees: {doge(mandatory_fees)}")
print(f"    splitter     {doge(SPLITTER_FEE_SAT)}")
print(f"    {len(QUIPU_ORDER)} roots      {doge(total_root_fees)}")
print(f"    {total_knots} knots    {doge(strand_fees)}")
print(f"    join         {doge(JOIN_FEE_MIN)} (multisig megajoin)")
if total_in < mandatory_fees:
    raise SystemExit(
        f"\nFATAL: insufficient funds. {doge(total_in)} < {doge(mandatory_fees)}\n"
    )

join_fee_sat  = JOIN_FEE_MIN
final_out_sat = total_in - SPLITTER_FEE_SAT - total_root_fees - strand_fees - join_fee_sat
assert final_out_sat > 100_000, f"final residual under safe dust: {final_out_sat}"

total_terminals_sat = join_fee_sat + final_out_sat
base_terminal = total_terminals_sat // total_strands
remainder     = total_terminals_sat - base_terminal * total_strands

strand_index = 0
for key in QUIPU_ORDER:
    q = quipus[key]
    q["seeds"] = []
    for i, k in enumerate(q["knots"]):
        terminal = base_terminal + (remainder if strand_index == 0 else 0)
        q["seeds"].append(k * TIP_SAT + terminal)
        strand_index += 1
    q["root_input"] = sum(q["seeds"]) + ROOT_FEE_SAT

splitter_outputs = [quipus[k]["root_input"] for k in QUIPU_ORDER]
splitter_out_sum = sum(splitter_outputs)
splitter_fee     = total_in - splitter_out_sum
assert splitter_fee == SPLITTER_FEE_SAT, f"splitter_fee {splitter_fee} != {SPLITTER_FEE_SAT}"

print()
print(f"  splitter input:           {doge(total_in)}")
print(f"  splitter outputs sum:     {doge(splitter_out_sum)}")
print(f"  splitter fee:             {doge(splitter_fee)}")
print(f"  predicted megajoin fee:   {doge(join_fee_sat)}")
print(f"  predicted final residual: {doge(final_out_sat)}")

# =============================================================================
#                       4. LOAD MULTIMAN KEYS
# =============================================================================
print()
print("=" * 72)
print("PHASE 4 — load multiman keys (2-of-2)")
print("=" * 72)

# key1 password from env or interactive prompt; mi has empty password
key1_pw = os.environ.get("KEY1_PW")
if key1_pw is None:
    import getpass
    key1_pw = getpass.getpass("Password for key1_prv.enc: ")
mi_pw = os.environ.get("MI_PW", "")

key1_obj = import_privKey(KEY1_PATH, key1_pw)
mi_obj   = import_privKey(MI_PATH,   mi_pw)

def _hex_strip(k):
    h = k.to_hex()
    return h[2:] if h.startswith("0x") else h

KEY1 = _hex_strip(key1_obj)
MI   = _hex_strip(mi_obj)

doge_cs = cryptos.Doge()
doge_cs.script_magicbyte = CadenaMultiAtom.DOGE_P2SH_MAGIC
script, addr = doge_cs.mk_multisig_address(
    doge_cs.privtopub(KEY1), doge_cs.privtopub(MI), num_required=2,
)
assert addr == MULTIMAN_ADDR, (
    f"keys derive {addr}, expected multiman {MULTIMAN_ADDR}. "
    f"Check key1/mi assignment + label order."
)
print(f"  ✓ keys load; derive correct multiman address")
print(f"    redeem script len = {len(script)//2} bytes")

# =============================================================================
#               5. BUILD SPLITTER (multisig spend → 12 outputs)
# =============================================================================
print()
print("=" * 72)
print("PHASE 5 — splitter (multisig spend → 12 per-quipu root outputs)")
print("=" * 72)

splitter_tx = doge_cs.mktx(
    utxos,
    [{"value": v, "address": MULTIMAN_ADDR} for v in splitter_outputs],
)
# Multisign each input
for i in range(len(utxos)):
    sigs = [doge_cs.multisign(tx=splitter_tx, i=i, script=script, pk=prv)
            for prv in (KEY1, MI)]
    splitter_tx = cryptos.apply_multisignatures(splitter_tx, i, script, *sigs)
splitter_hex  = cs_serialize(splitter_tx)
splitter_txid = _txid_of_serial(splitter_hex)
print(f"  splitter txid: {splitter_txid}")
print(f"  splitter hex size: {len(splitter_hex)//2} B")

# =============================================================================
#               6. BUILD PER-QUIPU ROOT TXS (multisig)
# =============================================================================
print()
print("=" * 72)
print(f"PHASE 6 — {len(QUIPU_ORDER)} per-quipu root txs (each splits into strand seeds)")
print("=" * 72)

root_hexes = {}
for i, key in enumerate(QUIPU_ORDER):
    q = quipus[key]
    root_input = {"output": f"{splitter_txid}:{i}", "value": q["root_input"]}
    root_outputs = [{"value": s, "address": MULTIMAN_ADDR} for s in q["seeds"]]
    root_tx = doge_cs.mktx([root_input], root_outputs)
    sigs = [doge_cs.multisign(tx=root_tx, i=0, script=script, pk=prv)
            for prv in (KEY1, MI)]
    root_tx = cryptos.apply_multisignatures(root_tx, 0, script, *sigs)
    root_hex  = cs_serialize(root_tx)
    root_txid = _txid_of_serial(root_hex)
    root_hexes[key] = root_hex
    q["root_txid"]  = root_txid
    print(f"  {key:<8} root_txid: {root_txid}")

# =============================================================================
#               7. SUBSTITUTE REAL ROOT TXIDS INTO BOOK BODY
# =============================================================================
print()
print("=" * 72)
print("PHASE 7 — substitute real root_txids into book body")
print("=" * 72)

new_book_body = quipus["book"]["body"]
for i, key in enumerate(PLACEHOLDER_KEYS):
    placeholder = placeholder_bytes(i)
    real = bytes.fromhex(quipus[key]["root_txid"])
    assert len(real) == 32
    assert placeholder in new_book_body, f"placeholder {i} not in book body"
    new_book_body = new_book_body.replace(placeholder, real)
assert all(placeholder_bytes(i) not in new_book_body for i in range(len(PLACEHOLDER_KEYS)))
assert len(new_book_body) == len(quipus["book"]["body"])
print(f"  ✓ all {len(PLACEHOLDER_KEYS)} placeholders substituted; body length unchanged")
quipus["book"]["body"]    = new_book_body
quipus["book"]["strands"] = [quipus["book"]["header"]] + split_body(new_book_body, n_book_body_strands)

# =============================================================================
#               8. PRECOMPUTE ALL STRANDS (multisig signed)
# =============================================================================
print()
print("=" * 72)
print(f"PHASE 8 — precompute {total_strands} multisig strands ({total_knots} total knots)")
print("=" * 72)

all_cadenas = []
for key in QUIPU_ORDER:
    q = quipus[key]
    q_cads = []
    for i, payload in enumerate(q["strands"]):
        seed_utxo = {"output": f"{q['root_txid']}:{i}", "value": q["seeds"][i]}
        cad = CadenaMultiAtom([KEY1, MI], payload, seed_utxo, TIP_SAT)
        cad.precompute()
        q_cads.append(cad)
        all_cadenas.append((key, i, cad))
    q["cadenas"] = q_cads
    n = sum(len(c.txns) for c in q_cads)
    print(f"  {key:<8} {len(q_cads)} strands  {n} knots precomputed")

actual_total_knots = sum(len(c.txns) for _, _, c in all_cadenas)
assert actual_total_knots == total_knots
print(f"  ✓ {actual_total_knots} total knot txs precomputed")

# =============================================================================
#               9. BUILD MEGAJOIN
# =============================================================================
print()
print("=" * 72)
print(f"PHASE 9 — megajoin ({total_strands} multisig inputs → 1 output)")
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
print(f"  megajoin fee:         {doge(actual_join_fee)}")

join_tx = doge_cs.mktx(
    join_inputs,
    [{"value": final_out_sat, "address": MULTIMAN_ADDR}],
)
for i in range(len(join_inputs)):
    sigs = [doge_cs.multisign(tx=join_tx, i=i, script=script, pk=prv)
            for prv in (KEY1, MI)]
    join_tx = cryptos.apply_multisignatures(join_tx, i, script, *sigs)
join_hex  = cs_serialize(join_tx)
join_txid = _txid_of_serial(join_hex)
print(f"  megajoin txid: {join_txid}")
print(f"  megajoin hex size: {len(join_hex)//2} B  "
      f"({len(join_hex)/2 / (actual_join_fee/100_000_000 * 100_000_000):.2f} sat/byte ratio)")

# =============================================================================
#               10. VERIFICATION + ARTIFACTS
# =============================================================================
print()
print("=" * 72)
print("PHASE 10 — verification + artifact dump")
print("=" * 72)

total_strand_fees = actual_total_knots * TIP_SAT
total_fees = splitter_fee + total_root_fees + total_strand_fees + actual_join_fee
print(f"  splitter fee:              {doge(splitter_fee)}")
print(f"  {len(QUIPU_ORDER)} root fees:           {doge(total_root_fees)}")
print(f"  {actual_total_knots} strand-knot fees:   {doge(total_strand_fees)}")
print(f"  megajoin fee:              {doge(actual_join_fee)}")
print(f"  ─────────────────────────────────────")
print(f"  TOTAL FEES:                {doge(total_fees)}")
print(f"  multiman input:            {doge(total_in)}")
print(f"  final residual:            {doge(final_out_sat)}")
assert total_fees == total_in - final_out_sat

ARTIFACTS.mkdir(exist_ok=True)
(ARTIFACTS / "splitter.hex").write_text(splitter_hex)
(ARTIFACTS / "splitter.txid").write_text(splitter_txid)
for key in QUIPU_ORDER:
    (ARTIFACTS / f"root_{key}.hex").write_text(root_hexes[key])
    (ARTIFACTS / f"root_{key}.txid").write_text(quipus[key]["root_txid"])
    for i, cad in enumerate(quipus[key]["cadenas"]):
        (ARTIFACTS / f"strand_{key}_{i}.txns").write_text("\n".join(cad.txns))
        (ARTIFACTS / f"strand_{key}_{i}.txids").write_text("\n".join(cad.txn_ids))
    (ARTIFACTS / f"{key}_header.bin").write_bytes(quipus[key]["header"])
    (ARTIFACTS / f"{key}_body.bin").write_bytes(quipus[key]["body"])
(ARTIFACTS / "megajoin.hex").write_text(join_hex)
(ARTIFACTS / "megajoin.txid").write_text(join_txid)
(ARTIFACTS / "quipu_order.txt").write_text("\n".join(QUIPU_ORDER))

print()
print(f"  artifacts written to {ARTIFACTS}")
print("  READY TO BROADCAST.")
