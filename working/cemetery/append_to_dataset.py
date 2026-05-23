"""Post-broadcast: append the 3 new quipus to data/quipu_data.csv,
write data/bodies/{root_txid}.bin for each, and append citation edges.

Run after broadcast_consolidated.py finishes successfully.
Idempotent: skips rows / files / edges that already exist.
"""
import os, sys, json, datetime
from pathlib import Path
import pandas as pd

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

import warnings; warnings.filterwarnings("ignore")
from colegio_tools import rpc_request

ARTIFACTS = THIS_DIR / "artifacts"
DATA_DIR  = PROJECT / "data"
BODIES    = DATA_DIR / "bodies"
APOC_ADDR = "D6zKNnkupqRbkB9p5rwix8QiobQWJazjyX"

# Per-quipu metadata to materialize into the CSV
QUIPUS = {
    "pinochet": {
        "type_byte":  "0x03",
        "type_name":  "image",
        "tone":       "0x0d",
        "tone_name":  "demonic",
        "title":      "Augusto Pinochet Ugarte",
        "dimensions": {"color": 0, "W": 320, "H": 400, "bit_depth": 3},
        "notes":      "demonic; consolidated cementerio inscription",
    },
    "condor": {
        "type_byte":  "0x03",
        "type_name":  "image",
        "tone":       "0x0d",
        "tone_name":  "demonic",
        "title":      "DINA, Invitación, Santiago, octubre 1975",
        "dimensions": {"color": 0, "W": 320, "H": 420, "bit_depth": 3},
        "notes":      "demonic; consolidated cementerio inscription",
    },
    "essay": {
        "type_byte":  "0x01",
        "type_name":  "essay",
        "tone":       "0x00",
        "tone_name":  "ordinary",
        "title":      "Cementerio de los Animales",
        "dimensions": {},
        "notes":      "consolidated cementerio inscription",
    },
}


def get_blockheight(txid):
    raw = rpc_request("gettransaction", [txid])
    bh = raw.get("blockhash")
    if not bh:
        return None, raw.get("blocktime")
    blk = rpc_request("getblock", [bh])
    return blk["height"], raw.get("blocktime")


# ---- 1. Load artifacts + look up join txid (mega-join) -------------------
splitter_txid = (ARTIFACTS / "splitter.txid").read_text().strip()
megajoin_txid = (ARTIFACTS / "megajoin.txid").read_text().strip()
print(f"splitter:  {splitter_txid}")
print(f"mega-join: {megajoin_txid}")

# All three sub-quipus share the same join (the mega-join consolidates
# every sub-quipu's strand termini back to apocrypha).
for key in QUIPUS:
    QUIPUS[key]["root_txid"] = (ARTIFACTS / f"root_{key}.txid").read_text().strip()
    QUIPUS[key]["join_txid"] = megajoin_txid
    print(f"  {key}: root={QUIPUS[key]['root_txid']}")

# ---- 2. Write body files -------------------------------------------------
print()
print("writing data/bodies/ files...")
for key, q in QUIPUS.items():
    header = (ARTIFACTS / f"{key}_header.bin").read_bytes()
    body   = (ARTIFACTS / f"{key}_body.bin").read_bytes()
    blob = header + body
    path = BODIES / f"{q['root_txid']}.bin"
    if path.exists() and path.read_bytes() == blob:
        print(f"  ↺ {key}: {path.name} unchanged ({len(blob)} B)")
    else:
        path.write_bytes(blob)
        print(f"  ✓ {key}: wrote {path.name} ({len(blob)} B)")
    q["total_bytes"] = len(blob)

# ---- 3. Look up blockheights ---------------------------------------------
print()
print("looking up blockheights...")
for key, q in QUIPUS.items():
    bh, bt = get_blockheight(q["root_txid"])
    q["blockheight"] = bh
    q["blocktime"]   = bt
    print(f"  {key}: block {bh}  blocktime {bt}")

# ---- 4. Append CSV rows --------------------------------------------------
print()
print("appending rows to data/quipu_data.csv...")
df = pd.read_csv(DATA_DIR / "quipu_data.csv")
existing_roots = set(df["root_txid"].astype(str))

new_rows = []
for key, q in QUIPUS.items():
    if q["root_txid"] in existing_roots:
        print(f"  ↺ {key}: row already exists")
        continue
    new_rows.append({
        "root_txid":        q["root_txid"],
        "join_txid":        q["join_txid"],
        "address":          APOC_ADDR,
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
    df.to_csv(DATA_DIR / "quipu_data.csv", index=False)
    print(f"  → quipu_data.csv now {len(df)} rows")

# ---- 5. Append citation edges --------------------------------------------
# The essay cites every txid that appears in its body. NB 60's full re-run
# would discover these via canonical/essay.py's substitute_body walker;
# we add the ones we can derive directly from the essay markdown.
print()
print("appending citation edges to data/quipu_edges.csv...")
import re

CITATION_RE = re.compile(r"https://dogechain\.info/tx/([0-9a-fA-F]{64})")
QUIPU_REF_RE = re.compile(r"quipu:([0-9a-fA-F]{64})")

essay_md = (THIS_DIR / "cementerio_de_los_animales.md").read_text(encoding="utf-8")

# Substitute placeholders with real txids (mirrors build_consolidated.py)
essay_md_resolved = (
    essay_md
    .replace("de" * 32, QUIPUS["pinochet"]["root_txid"])
    .replace("c0" * 32, QUIPUS["condor"]["root_txid"])
)

referenced_txids = set()
for rx in (CITATION_RE, QUIPU_REF_RE):
    for m in rx.finditer(essay_md_resolved):
        referenced_txids.add(m.group(1).lower())
referenced_txids.discard(QUIPUS["essay"]["root_txid"].lower())
print(f"  essay references {len(referenced_txids)} distinct txids")

df_e = pd.read_csv(DATA_DIR / "quipu_edges.csv")
existing_edges = set(
    (str(r.source_quipu).lower(), str(r.consumer_quipu).lower(), r.kind)
    for r in df_e.itertuples()
)
all_known_roots = set(df["root_txid"].astype(str).str.lower())

# Pick citation kind based on the referenced quipu's type
def cite_kind(ref_lo):
    row = df[df["root_txid"].astype(str).str.lower() == ref_lo]
    if row.empty:
        return "citation"
    t = row.iloc[0]["type_name"]
    if t == "image":      return "citation_image"
    if t == "celestial":  return "citation"
    if t == "scene":      return "citation"
    return "citation"

new_edges = []
for ref in referenced_txids:
    if ref not in all_known_roots:
        print(f"  skip: {ref[:12]}… not in dataset")
        continue
    kind = cite_kind(ref)
    key = (QUIPUS["essay"]["root_txid"].lower(), ref, kind)
    if key in existing_edges:
        continue
    new_edges.append({
        "source_quipu":   QUIPUS["essay"]["root_txid"],
        "consumer_quipu": ref,
        "hops":           0,
        "kind":           kind,
    })
    target_title = df[df["root_txid"].astype(str).str.lower() == ref].iloc[0]["title"]
    print(f"  + {kind:14s}  → {ref[:12]}…  \"{str(target_title)[:40]}\"")

if new_edges:
    df_e = pd.concat([df_e, pd.DataFrame(new_edges)], ignore_index=True)
    df_e.to_csv(DATA_DIR / "quipu_edges.csv", index=False)
    print(f"  → quipu_edges.csv now {len(df_e)} rows")

print()
print("DONE")
