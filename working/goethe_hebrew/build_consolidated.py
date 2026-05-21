"""Build the consolidated 5-quipu inscription (deterministic, no broadcast).

Architecture:
    apocrypha utxo (153 DOGE)
        -> mega-splitter (1 input, 5 outputs)
        -> 5 per-quipu roots (each with N strand outputs)
        -> all strands (parallel Cadena chains)
        -> mega-join (M inputs, 1 output)
        -> 1 DOGE residual at apocrypha

This script computes all txids in dependency order, lets us substitute the
real txids back into the main essay's binding block, precomputes every
signed-but-unbroadcast tx, and prints the full fee verification.

After this script runs cleanly, broadcast in order:
    1. splitter
    2. all 5 per-quipu roots (parallel)
    3. all 17 strands (parallel waves)
    4. mega-join
"""
import math
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))

from PIL import Image
import numpy as np
import cryptos
from cryptos import serialize as cs_serialize
from colegio_tools import rpc_request, _txid_of_serial, CadenaAtom

from canonical.image import build_image_quipu, pack_pixels, COLOR_GRAY
from canonical.text import build_text_quipu, TONE_ORDINARY
from canonical.essay import build_essay_quipu

# =============================================================================
#                              CONFIGURATION
# =============================================================================

APOCRYPHA_UTXO = {
    "output": "a221090ef0d9655060b95083f0222fbf5f728f6019171b0cef0622ad3ddb1478:1",
    "value":  15_300_000_000,   # 153.00 DOGE
}
APOCRYPHA_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"

# Private key — loaded at broadcast time, not here.  This script only computes.
# Pass via env var APOCRYPHA_PRIV when running.
import os
PRIV = os.environ.get("APOCRYPHA_PRIV", "00" * 32)

TIP_SAT       = 5_000_000      # 0.05 DOGE per strand-tx (fixed by convention)
ROOT_FEE_SAT  = 5_000_000      # 0.05 DOGE per per-quipu root (fixed)
FINAL_OUT_SAT = 100_000_000    # 1.00 DOGE residual (user constraint)

# Image setting (tuned to land at 152 DOGE exactly with essay-es at 7287B body)
IMG_W, IMG_H, IMG_BITS = 748, 485, 5
IMG_BODY_STRANDS       = 8     # split image body into 8 parallel strands

# =============================================================================
#                       HELPERS
# =============================================================================

def doge(sat):
    return f"{sat/100_000_000:.8f} DOGE"

def knot_count(payload_bytes):
    return math.ceil(len(payload_bytes) / 80) if payload_bytes else 1

# =============================================================================
#                       1. PREPARE PAYLOADS
# =============================================================================
print("=" * 72)
print("PHASE 1 — building the 5 quipus' (header, body) tuples")
print("=" * 72)

# --- 1a. Image quipu (placeholder, will be re-rendered if image bumps) -------
img_path = THIS_DIR / "preview_664x430_grey5bit.png"
img = Image.open(img_path).convert('L').resize((IMG_W, IMG_H), Image.LANCZOS)
arr = np.array(img, dtype=np.uint8)
# Quantize to IMG_BITS bits
shift = 8 - IMG_BITS
arr_q = (arr >> shift).astype(np.uint8)
pixels = arr_q.flatten().tolist()
img_body = pack_pixels(pixels, IMG_BITS)
img_header, _ = build_image_quipu(
    IMG_W, IMG_H, COLOR_GRAY, IMG_BITS,
    "Página de Práctica Hebrea de Goethe, c. 1760",
    img_body
)
print(f"  IMAGE      header={len(img_header):>6}B  body={len(img_body):>7}B  ({IMG_W}×{IMG_H} grey {IMG_BITS}-bit)")

# --- 1b. Essay-es (Spanish main essay) ---------------------------------------
essay_md = (THIS_DIR / "essay_source.md").read_text(encoding="utf-8")
essay_header, essay_body = build_essay_quipu(
    title="El hebreo del joven Goethe",
    body_markdown=essay_md,
    fields={
        "author": "El Ermitaño",
        "date":   "2026-05-21",
        "lang":   "es",
    },
)
print(f"  ESSAY-ES   header={len(essay_header):>6}B  body={len(essay_body):>7}B")

# --- 1c. Dichtung und Wahrheit IV (bilingual de+en) --------------------------
dichtung_body_md = """\
[DE]

Auf einmal kam mir der Einfall, daß ich es mit einer anderen
Sprache versuchen müsse: dem Hebräischen. Auch die Mutter
billigte mein Vorhaben, und so trat ich, schon als Knabe von
zehn Jahren, bei Herrn Rektor Albrecht in die Lehre, einem
würdigen Greise, der mit eiserner Geduld den ersten Grund mir
einprägte. Bald schritt ich vom Lesen zum Schreiben, und das
Geheimnis der Quadratbuchstaben, jeder mit seinem Namen und
seinem Zahlenwert, faßte mich wie eine Magie. Ich setzte die
Buchstaben aufs Geratewohl nebeneinander und las heraus, was
nicht stehen sollte, und doch stand, sobald die Ziffern es
geboten — eine Vorbereitung, deren Wert ich erst viel später
ermaß.

Da ich aber, neben dem Heiligen Hebräischen, das tägliche
Geräusch der Judengasse hören wollte, dasselbe das durch das
ganze Frankfurter Stadtgewebe rieselte, suchte ich einen Lehrer
in jenem barocken Judendeutsch, das die Märkte sprach. Ich fand
ihn in einem getauften Israeliten namens Christamicus, der mir
das Bisherige neu beibringen mußte — denn das Schöne, das mir
Albrecht eingeschrieben, war hier nur das Skelett, und das
Fleisch sprach anders. Ich bemühte mich, das judendeutsche
Barock zu erwerben, und suchte so gut zu schreiben, als ich
lesen konnte.

Was mir aus diesen Übungen geblieben ist, ist nicht das System,
sondern eine Empfänglichkeit für Schriften, die zugleich Bild
und Zahl sind. Ich glaube nicht zu viel zu sagen, wenn ich
behaupte, daß meine spätere Liebe zur ägyptischen Hieroglyphik
und zur arabischen Kalligraphie, ja zu allem, was sich der
bloßen Mitteilung entzieht und auf das Geheimnis zurückweist,
in jenen ersten Stunden bei Albrecht und Christamicus gepflanzt
worden ist.

[EN]

It came suddenly into my mind that I must try another language:
Hebrew. My mother also approved of my plan, and so, already as
a boy of ten, I entered the school of Rector Albrecht, a worthy
old gentleman who impressed the first foundations on me with
iron patience. Soon I passed from reading to writing, and the
secret of the square letters — each with its name and its
numerical value — seized me like a kind of magic. I set the
letters down at random, side by side, and read out what should
not have stood there at all, and yet did stand, as soon as the
numbers required it — a preparation whose worth I did not
measure until much later.

Yet since, alongside the holy Hebrew, I wished to hear the
daily noise of the Judengasse — that same noise that rippled
through the whole web of Frankfurt — I sought out a teacher in
that baroque Judeo-German which the markets spoke. I found him
in a baptized Israelite by the name of Christamicus, who had
to teach me everything over again, for the beautiful thing
Albrecht had inscribed in me was here only the skeleton, and
the flesh spoke otherwise. I exerted myself to acquire the
Judeo-German baroque, and sought to write as well as I could
read.

What remains to me from those exercises is not the system but
a receptivity to scripts that are at once image and number. I
believe I say no more than the truth when I claim that my later
love of Egyptian hieroglyphics, of Arabic calligraphy, and
indeed of everything that withdraws from mere communication and
points back to the mystery, was planted in those first hours
with Albrecht and Christamicus.
"""
dichtung_header, dichtung_body = build_essay_quipu(
    title="Dichtung und Wahrheit (Libro IV, extracto)",
    body_markdown=dichtung_body_md,
    fields={
        "author":  "El Ermitaño",
        "date":    "2026-05-21",
        "lang":    "mul",
        "primary": "de",
    },
)
print(f"  DICHTUNG   header={len(dichtung_header):>6}B  body={len(dichtung_body):>7}B")

# --- 1d. La Rebelión de Fettmilch (text 0x00, Spanish) -----------------------
fett_body_text = """\
LA REBELIÓN DE FETTMILCH (Frankfurt am Main, 1612–1616)

A comienzos del siglo XVII, Frankfurt era ciudad libre del Sacro
Imperio Romano, sede de coronaciones imperiales y de una de las
ferias más antiguas de Europa. Su barrio judío, la Judengasse
— una sola calle cerrada con tres puertas, fundada en 1462 —
contenía a unas tres mil personas, los acreedores de buena parte
del comercio frankfurtés.

Vincent Fettmilch, pastelero y agitador, líder de los gremios
descontentos con la oligarquía patricia, debía sumas grandes a
prestamistas judíos de la Judengasse. En 1612 encabezó una
revuelta contra el Consejo de la ciudad. Tres años después, el
22 de agosto de 1614, sus seguidores irrumpieron en la Judengasse,
saquearon y demolieron casas, y expulsaron por la fuerza a toda
la comunidad — alrededor de mil cuatrocientas almas — fuera de
las murallas. Las deudas se hicieron humo en una hora.

El emperador Matías declaró a Fettmilch fuera de la ley imperial.
En febrero de 1616 los judíos fueron escoltados de regreso a la
Judengasse bajo guardia armada y trompeta, con un decreto
imperial sellado en la puerta. El 28 de febrero del mismo año
Fettmilch fue decapitado y descuartizado en la Roßmarkt frente
a una multitud silenciosa; su cabeza quedó clavada sobre el
puente, sus deudas, oficialmente nulas, fueron declaradas vivas
de nuevo y pagaderas.

La comunidad de la Judengasse instituyó el ayuno del 20 de Adar
y el Purim Vinz, una fiesta menor que se observó cada año hasta
la abolición del gueto en 1796. Conmemora la salvación, no la
venganza.

Esta es la historia que el joven Goethe escuchó de niño en casa
de su tío Jost Textor, que vivía contiguo a la antigua Judengasse,
y que más tarde recogió en el Libro IV de Dichtung und Wahrheit.
"""
fett_header, fett_body = build_text_quipu(
    title="La Rebelión de Fettmilch (1614)",
    body=fett_body_text,
    fields={
        "author": "El Ermitaño",
        "date":   "2026-05-21",
        "lang":   "es",
    },
)
print(f"  FETTMILCH  header={len(fett_header):>6}B  body={len(fett_body):>7}B")

# --- 1e. Die Judenpredigt (text 0x00, bilingual de+yi) -----------------------
juden_body_text = """\
LA JUDENPREDIGT DE GOETHE (c. 1762)

— Único fragmento auténtico que sobrevive:

   "Do werd äh groser Mann, mit Stiefle und Spore gradaus,
    sporenstrechs gegange komme übers grose grause rothe Meer,
    und werd in der Hand habe äh Horn,
    und was denn ver äh Horn? — äh Düt-Horn."

— Contenido perdido:

El joven Goethe — de dieciséis o diecisiete años — describe una
visión escatológica grotesca. En trescientos mil años el Mesías
vendrá a caballo, montado sobre una yegua pinta, atravesando el
Mar Rojo de un solo trote. Levantará en la mano un cuerno, un
Düt-Horn, cuyo eco congregará a todos los judíos de la tierra;
cada uno hallará sitio sobre los flancos del caballo y pasará el
mar a salvo. Los cristianos, que se habrán sujetado, en son de
burla, al rabo del animal, se ahogarán en las aguas.

— El habla del poema no es auténticamente yidis occidental sino
"jüdelte Frankfurterisch" — una imitación frankfurtesa del
dialecto, con tantas incorrecciones que las clases de Christamicus
parecen pagadas en vano. Es, sin embargo, lo más cerca que un
cristiano de Frankfurt llegó nunca, en verso firmado, a la lengua
de la Judengasse.

— Aparte de la página de práctica del Aleph-Bet, la Judenpredigt
es la única obra existente de Goethe que contiene material en
germano-hebraico. Su sátira no está dirigida contra la fe judía
sino contra las pretensiones exclusivistas del cristianismo
oficial — el caballo del Mesías deja a los burladores en el mar.
"""
juden_header, juden_body = build_text_quipu(
    title="Die Judenpredigt",
    body=juden_body_text,
    fields={
        "author":  "El Ermitaño",
        "date":    "2026-05-21",
        "lang":    "mul",
        "primary": "de",
    },
)
print(f"  JUDENPRED  header={len(juden_header):>6}B  body={len(juden_body):>7}B")

# =============================================================================
#                       2. SPLIT BODIES INTO STRAND PAYLOADS
# =============================================================================
print()
print("=" * 72)
print("PHASE 2 — strand layout per quipu")
print("=" * 72)

def split_body(body, n_strands):
    """Split body bytes into n_strands roughly-equal chunks."""
    if n_strands <= 1:
        return [body]
    chunk = math.ceil(len(body) / n_strands)
    return [body[i*chunk : (i+1)*chunk] for i in range(n_strands)]

# Each quipu's strand_payloads = [cabeza_header] + body_chunks
quipus = {
    "image": {
        "label":   "GoethePracticePage",
        "strands": [img_header] + split_body(img_body, IMG_BODY_STRANDS),
    },
    "essay": {
        "label":   "El hebreo del joven Goethe",
        "strands": [essay_header, essay_body],
    },
    "dichtung": {
        "label":   "Dichtung und Wahrheit IV",
        "strands": [dichtung_header, dichtung_body],
    },
    "fett": {
        "label":   "La Rebelión de Fettmilch",
        "strands": [fett_header, fett_body],
    },
    "juden": {
        "label":   "Die Judenpredigt",
        "strands": [juden_header, juden_body],
    },
}

# Compute knot counts per strand
total_knots = 0
total_strands = 0
for key, q in quipus.items():
    q["knots"] = [knot_count(p) for p in q["strands"]]
    total_knots += sum(q["knots"])
    total_strands += len(q["strands"])

# Solve for splitter_fee, join_fee, and terminal value so total fees = 152 DOGE.
# Constraint: splitter_in - final_out = splitter_fee + 5*root_fee + total_knots*tip + join_fee
# Strategy: fix splitter_fee = 0.05, fix root_fee = 0.05; compute join_fee from balance.
SPLITTER_FEE_SAT = 5_000_000
strand_fees      = total_knots * TIP_SAT
total_root_fees  = 5 * ROOT_FEE_SAT
target_total_fees = APOCRYPHA_UTXO["value"] - FINAL_OUT_SAT  # = 152.00 DOGE
join_fee_sat     = target_total_fees - SPLITTER_FEE_SAT - total_root_fees - strand_fees

if join_fee_sat <= 0:
    # Splitter must absorb the slack instead
    join_fee_sat     = 5_000_000  # nominal 0.05
    SPLITTER_FEE_SAT = target_total_fees - total_root_fees - strand_fees - join_fee_sat
    if SPLITTER_FEE_SAT <= 0:
        raise SystemExit(
            f"FATAL: too many knots ({total_knots}) — cannot fit in {target_total_fees/1e8} DOGE budget. "
            f"Reduce image resolution.")

# Sum of all strand terminals = join_fee + final_out
total_terminals_sat = join_fee_sat + FINAL_OUT_SAT
# Distribute (almost) uniformly across strands, with remainder on strand 0
base_terminal = total_terminals_sat // total_strands
remainder     = total_terminals_sat - base_terminal * total_strands
assert base_terminal > 1_000_000, f"terminal {base_terminal} below safe-dust threshold"

# Assign per-strand seeds
strand_index = 0
for key, q in quipus.items():
    q["seeds"] = []
    for i, k in enumerate(q["knots"]):
        terminal = base_terminal + (remainder if strand_index == 0 else 0)
        q["seeds"].append(k * TIP_SAT + terminal)
        strand_index += 1
    q["root_input"] = sum(q["seeds"]) + ROOT_FEE_SAT
    print(f"  {q['label']:<42} strands={len(q['strands']):>2}  "
          f"knots={sum(q['knots']):>4}  root_in={doge(q['root_input'])}")

splitter_outputs = [q["root_input"] for q in quipus.values()]
splitter_out_sum = sum(splitter_outputs)
splitter_in      = APOCRYPHA_UTXO["value"]
splitter_fee     = splitter_in - splitter_out_sum

print()
print(f"  TOTAL KNOTS:            {total_knots}")
print(f"  total strands:          {total_strands}")
print(f"  base terminal value:    {doge(base_terminal)}  (per strand)")
print(f"  splitter input:         {doge(splitter_in)}")
print(f"  splitter outputs sum:   {doge(splitter_out_sum)}")
print(f"  splitter fee:           {doge(splitter_fee)}")
print(f"  predicted join fee:     {doge(join_fee_sat)}")
assert splitter_fee == SPLITTER_FEE_SAT, f"splitter_fee {splitter_fee} != target {SPLITTER_FEE_SAT}"

# =============================================================================
#                       3. BUILD SPLITTER (NO BROADCAST)
# =============================================================================
print()
print("=" * 72)
print("PHASE 3 — splitter + per-quipu root txs (deterministic, unsigned-stage)")
print("=" * 72)

if PRIV == "00" * 32:
    print()
    print("  *** PRIV not set — skipping tx signing.  Set APOCRYPHA_PRIV env var ***")
    print("  *** to fully build, sign, and report txids.                          ***")
    print()
    # Still compute the rest to verify byte budget
else:
    doge_cs = cryptos.Doge()
    addr = doge_cs.privtoaddr(PRIV)
    assert addr == APOCRYPHA_ADDR, f"key derives {addr}, expected {APOCRYPHA_ADDR}"

    splitter_tx = doge_cs.mktx(
        [APOCRYPHA_UTXO],
        [{"value": v, "address": APOCRYPHA_ADDR} for v in splitter_outputs],
    )
    splitter_signed = doge_cs.signall(splitter_tx, PRIV)
    splitter_hex    = cs_serialize(splitter_signed)
    splitter_txid   = _txid_of_serial(splitter_hex)
    print(f"  splitter txid:  {splitter_txid}")

    # Build per-quipu root txs
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
        print(f"  {key:<10} root_txid: {root_txid}")

    # =========================================================================
    #         4. SUBSTITUTE REAL TXIDS INTO MAIN ESSAY, RE-BUILD ESSAY BODY
    # =========================================================================
    print()
    print("=" * 72)
    print("PHASE 4 — substitute real root_txids into essay binding block")
    print("=" * 72)

    PLACEHOLDERS = {
        "DichtungWahrheit":   "d" * 64,
        "GoethePracticePage": "be" * 32,
        "DieJudenpredigt":    "cd" * 32,
        "FettmilchRebellion": "fa" * 32,
    }
    REAL = {
        "DichtungWahrheit":   root_txids["dichtung"],
        "GoethePracticePage": root_txids["image"],
        "DieJudenpredigt":    root_txids["juden"],
        "FettmilchRebellion": root_txids["fett"],
    }
    new_essay_md = essay_md
    for alias, placeholder in PLACEHOLDERS.items():
        assert placeholder in new_essay_md, f"placeholder {placeholder} for {alias} not found"
        new_essay_md = new_essay_md.replace(placeholder, REAL[alias])
        print(f"  {alias:<22} -> {REAL[alias][:16]}…")

    new_essay_header, new_essay_body = build_essay_quipu(
        title="El hebreo del joven Goethe",
        body_markdown=new_essay_md,
        fields={
            "author": "El Ermitaño",
            "date":   "2026-05-21",
            "lang":   "es",
        },
    )
    # CRITICAL: body length must be invariant (placeholder hex same length as real txid)
    assert len(new_essay_header) == len(essay_header), "header length changed!"
    assert len(new_essay_body)   == len(essay_body),   f"body length changed: {len(essay_body)} -> {len(new_essay_body)}"
    print(f"  body length invariant: {len(essay_body)}B ✓")

    # Replace the essay's strand payloads with the txid-substituted versions
    quipus["essay"]["strands"] = [new_essay_header, new_essay_body]
    # The header and body bytes are unchanged in length, so knot counts/seeds are unchanged.

    # =========================================================================
    #         5. PRECOMPUTE ALL 17 CADENA STRANDS
    # =========================================================================
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
        print(f"  {key:<10} {len(q_cads)} strands  total knots={n_knots}")

    # Sanity check: total knots = sum of all cad.txns
    actual_total_knots = sum(len(c.txns) for _, _, c in all_cadenas)
    assert actual_total_knots == total_knots, f"knot mismatch: {actual_total_knots} vs {total_knots}"
    print(f"  total knot txs precomputed: {actual_total_knots}")

    # =========================================================================
    #         6. BUILD MEGA-JOIN
    # =========================================================================
    print()
    print("=" * 72)
    print("PHASE 6 — mega-join (17 inputs -> 1 output)")
    print("=" * 72)

    join_inputs = []
    for key, i, cad in all_cadenas:
        terminus_value = quipus[key]["seeds"][i] - TIP_SAT * len(cad.txns)
        join_inputs.append({
            "output": f"{cad.txn_ids[-1]}:0",
            "value":  terminus_value,
        })

    total_in   = sum(inp["value"] for inp in join_inputs)
    final_out  = 100_000_000   # 1.00 DOGE
    join_fee   = total_in - final_out

    print(f"  total terminus value:  {doge(total_in)}")
    print(f"  final output:          {doge(final_out)}")
    print(f"  mega-join fee:         {doge(join_fee)}")

    if join_fee < 0:
        raise SystemExit("FATAL: terminus values too small to leave 1 DOGE after join_fee")
    if join_fee > 200_000_000:
        print(f"  *** WARNING: join_fee {doge(join_fee)} unusually high ***")

    join_tx = doge_cs.mktx(
        join_inputs,
        [{"value": final_out, "address": APOCRYPHA_ADDR}],
    )
    join_signed = doge_cs.signall(join_tx, PRIV)
    join_hex    = cs_serialize(join_signed)
    join_txid   = _txid_of_serial(join_hex)
    print(f"  mega-join txid: {join_txid}")

    # =========================================================================
    #         7. VERIFICATION REPORT
    # =========================================================================
    print()
    print("=" * 72)
    print("PHASE 7 — verification report")
    print("=" * 72)

    total_strand_fees = sum(len(c.txns) for _, _, c in all_cadenas) * TIP_SAT
    total_root_fees   = sum(ROOT_FEE_SAT for _ in quipus)
    total_fees        = splitter_fee + total_root_fees + total_strand_fees + join_fee

    print(f"  splitter fee:              {doge(splitter_fee):>16}")
    print(f"  per-quipu root fees (×5):  {doge(total_root_fees):>16}")
    print(f"  strand fees (knots × tip): {doge(total_strand_fees):>16}  ({total_knots} × 0.05)")
    print(f"  mega-join fee:             {doge(join_fee):>16}")
    print(f"  ─────────────────────────  ─────────────────")
    print(f"  TOTAL FEES BURNT:          {doge(total_fees):>16}")
    print(f"  input:                     {doge(APOCRYPHA_UTXO['value']):>16}")
    print(f"  residual (final output):   {doge(APOCRYPHA_UTXO['value'] - total_fees):>16}")

    expected_total_fees = APOCRYPHA_UTXO['value'] - final_out
    assert total_fees == expected_total_fees, f"fee mismatch: {total_fees} vs {expected_total_fees}"

    print()
    print("  TX HEX SIZES")
    print(f"    splitter:  {len(splitter_hex)//2:>6} bytes")
    for key in quipus:
        print(f"    root[{key:<10}] {len(root_hexes[key])//2:>6} bytes")
    print(f"    mega-join: {len(join_hex)//2:>6} bytes")

    # Save artifacts to disk for the broadcast step
    artifacts = THIS_DIR / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "splitter.hex").write_text(splitter_hex)
    (artifacts / "splitter.txid").write_text(splitter_txid)
    for key, q in quipus.items():
        (artifacts / f"root_{key}.hex").write_text(root_hexes[key])
        (artifacts / f"root_{key}.txid").write_text(q["root_txid"])
        for i, cad in enumerate(q["cadenas"]):
            (artifacts / f"strand_{key}_{i}.txns").write_text(
                "\n".join(cad.txns)
            )
            (artifacts / f"strand_{key}_{i}.txids").write_text(
                "\n".join(cad.txn_ids)
            )
        # Post-substitution (header, body) blob — NB 62 reads these directly
        # to populate data/bodies/{root_txid}.bin without re-walking the chain.
        header_bytes = q["strands"][0]
        body_bytes   = b"".join(q["strands"][1:])
        (artifacts / f"{key}_header.bin").write_bytes(header_bytes)
        (artifacts / f"{key}_body.bin").write_bytes(body_bytes)
    (artifacts / "megajoin.hex").write_text(join_hex)
    (artifacts / "megajoin.txid").write_text(join_txid)

    print()
    print(f"  artifacts written to {artifacts}")
    print(f"  READY TO BROADCAST.")
