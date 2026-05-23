"""Post-broadcast: append the 2 corrections quipus (binding + essay v2)
to data/quipu_data.csv, write body files, and add citation edges.

Idempotent: skips rows / files / edges that already exist.
"""
import os, sys, json
from pathlib import Path
import pandas as pd

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

import warnings; warnings.filterwarnings("ignore")
from colegio_tools import rpc_request

ART     = THIS_DIR / "corrections_artifacts"
DATA    = PROJECT / "data"
BODIES  = DATA / "bodies"
APOC    = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"
V1_TXID = "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985"

splitter_txid = (ART / "splitter.txid").read_text().strip()
megajoin_txid = (ART / "megajoin.txid").read_text().strip()
binding_txid  = (ART / "root_binding.txid").read_text().strip()
essay_txid    = (ART / "root_essay.txid").read_text().strip()

QUIPUS = {
    "binding": {
        "root_txid":  binding_txid,
        "type_byte":  "0xab",
        "type_name":  "binding",
        "tone":       "0x00",
        "tone_name":  "ordinary",
        "title":      "",
        "dimensions": {},
        "notes":      "cementerio corrections binding (URL prefix substitution)",
    },
    "essay": {
        "root_txid":  essay_txid,
        "type_byte":  "0x01",
        "type_name":  "essay",
        "tone":       "0x00",
        "tone_name":  "ordinary",
        "title":      "Cementerio de los Animales",
        "dimensions": {},
        "notes":      "v2 republication of d442073b… (corrections via binding)",
    },
}

print(f"splitter:  {splitter_txid}")
print(f"mega-join: {megajoin_txid}")
for k, q in QUIPUS.items():
    print(f"  {k}: {q['root_txid']}")

# ---- 1. Write body files -------------------------------------------------
print()
print("writing data/bodies/ files...")
for key, q in QUIPUS.items():
    header = (ART / f"{key}_header.bin").read_bytes()
    body   = (ART / f"{key}_body.bin").read_bytes()
    blob = header + body
    path = BODIES / f"{q['root_txid']}.bin"
    if path.exists() and path.read_bytes() == blob:
        print(f"  ↺ {key}: {path.name} unchanged ({len(blob)} B)")
    else:
        path.write_bytes(blob)
        print(f"  ✓ {key}: wrote {path.name} ({len(blob)} B)")
    q["total_bytes"] = len(blob)

# ---- 2. Look up blockheights ---------------------------------------------
print()
print("looking up blockheights via getrawtransaction...")
for key, q in QUIPUS.items():
    raw = rpc_request("getrawtransaction", [q["root_txid"], 1])
    bh = raw.get("blockhash")
    if bh:
        blk = rpc_request("getblock", [bh])
        q["blockheight"] = blk["height"]
        q["blocktime"]   = raw.get("blocktime")
    else:
        q["blockheight"] = None
        q["blocktime"]   = raw.get("time")
    print(f"  {key}: block {q['blockheight']}  blocktime {q['blocktime']}")

# ---- 3. Append CSV rows --------------------------------------------------
print()
print("appending rows to data/quipu_data.csv...")
df = pd.read_csv(DATA / "quipu_data.csv")
existing_roots = set(df["root_txid"].astype(str))

new_rows = []
for key, q in QUIPUS.items():
    if q["root_txid"] in existing_roots:
        print(f"  ↺ {key}: row already exists")
        continue
    new_rows.append({
        "root_txid":        q["root_txid"],
        "join_txid":        megajoin_txid,
        "address":          APOC,
        "label":            "apocrypha",
        "type_byte":        q["type_byte"],
        "type_name":        q["type_name"],
        "tone":             q["tone"],
        "tone_name":        q["tone_name"],
        "title":            q["title"],
        "dimensions_json":  json.dumps(q["dimensions"], sort_keys=True),
        "total_bytes":      q["total_bytes"],
        "blockheight":      q["blockheight"],
        "blocktime":        q["blocktime"],
        "body_file":        f"bodies/{q['root_txid']}.bin",
        "notes":            q["notes"],
        "canonical_status": "canonical_v1",
    })
    print(f"  + {key}: {q['root_txid'][:12]}…  {q['type_name']}  \"{q['title'][:40]}\"")

if new_rows:
    df = pd.concat([df, pd.DataFrame(new_rows)], ignore_index=True)
    df.to_csv(DATA / "quipu_data.csv", index=False)
    print(f"  → quipu_data.csv now {len(df)} rows")

# ---- 4. Append edges -----------------------------------------------------
# Edges:
#   essay v2 → binding   kind: binding_import (essay's fenced ```binding block
#                              imports the binding's substitution rules)
#   essay v2 → v1        kind: citation         (essay's body has <<v1_txid>>)
#   essay v2 → v1        kind: previous         (essay header field previous=v1)
print()
print("appending edges to data/quipu_edges.csv...")
df_e = pd.read_csv(DATA / "quipu_edges.csv")
existing = set(
    (str(r.source_quipu).lower(), str(r.consumer_quipu).lower(), r.kind)
    for r in df_e.itertuples()
)

candidate_edges = [
    (essay_txid, binding_txid, "binding_import"),
    (essay_txid, V1_TXID,      "citation"),
    (essay_txid, V1_TXID,      "previous"),
]

new_edges = []
for src, dst, kind in candidate_edges:
    key = (src.lower(), dst.lower(), kind)
    if key in existing:
        print(f"  ↺ {kind}  → {dst[:12]}… exists")
        continue
    new_edges.append({
        "source_quipu":   src,
        "consumer_quipu": dst,
        "hops":           0,
        "kind":           kind,
    })
    print(f"  + {kind:15s}  → {dst[:12]}…")

if new_edges:
    df_e = pd.concat([df_e, pd.DataFrame(new_edges)], ignore_index=True)
    df_e.to_csv(DATA / "quipu_edges.csv", index=False)
    print(f"  → quipu_edges.csv now {len(df_e)} rows")

print()
print("DONE")
