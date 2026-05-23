"""Verify substitute_body runs cleanly on the v2 two-line essay body
with the corrections binding loaded into the local database.

Steps:
  1. Stage the corrections binding's bytes into data/bodies/{binding_txid}.bin
  2. Stage the v2 essay's bytes into data/bodies/{v2_txid}.bin
  3. Stand up the same fetcher + title_lookup the streamlit viewer uses
  4. Call substitute_body on v2's body markdown
  5. Show rendered output

Cleans up by removing the staged files at the end.
"""
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
PROJECT  = THIS_DIR.parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "canonical"))

import warnings; warnings.filterwarnings("ignore")
from essay import substitute_body, read_essay_quipu

ART  = THIS_DIR / "corrections_artifacts"
BODIES = PROJECT / "data" / "bodies"

# ---- 1. Get the precomputed bytes from build artifacts ------------------
binding_txid = (ART / "root_binding.txid").read_text().strip()
v2_txid      = (ART / "root_essay.txid").read_text().strip()
v1_txid      = "d442073b33f2a4d04292853abb39e171ae593fcc288a1e4fc2518d5d7a7e5985"

binding_header = (ART / "binding_header.bin").read_bytes()
binding_body   = (ART / "binding_body.bin").read_bytes()
v2_header      = (ART / "essay_header.bin").read_bytes()
v2_body        = (ART / "essay_body.bin").read_bytes()
binding_blob   = binding_header + binding_body
v2_blob        = v2_header + v2_body

print(f"binding txid: {binding_txid}")
print(f"v2 txid:      {v2_txid}")
print(f"v1 txid:      {v1_txid}")
print(f"binding blob: {len(binding_blob)} B")
print(f"v2 blob:      {len(v2_blob)} B")

# ---- 2. Stage the binding + v2 into data/bodies/ ------------------------
staged = []
for txid, blob in [(binding_txid, binding_blob), (v2_txid, v2_blob)]:
    path = BODIES / f"{txid}.bin"
    if not path.exists():
        path.write_bytes(blob)
        staged.append(path)
        print(f"  staged: {path.name}")

try:
    # ---- 3. Parse v2's full quipu (header + body) -----------------------
    # Find the body/header split — same trick as the inscribed-bytes
    # reader: walk pipes from byte 6 until we find one followed by body.
    blob = v2_blob
    pos = 7  # past magic+type+tone+|
    last_pipe = 6
    while pos < len(blob):
        nxt = blob.find(b"|", pos)
        if nxt < 0: break
        seg = blob[pos:nxt]
        if b"\n" in seg or b"<" in seg:  # body content (markdown or markup)
            last_pipe = pos - 1
            break
        pos = nxt + 1
        last_pipe = pos - 1
    v2_body_md = blob[last_pipe + 1:].decode("utf-8")
    print()
    print(f"v2 body markdown ({len(v2_body_md)} chars):")
    print("  " + repr(v2_body_md))

    # ---- 4. Build fetcher + title_lookup ----------------------------------
    def fetcher(txid):
        path = BODIES / f"{txid}.bin"
        if path.exists():
            return path.read_bytes()
        raise FileNotFoundError(f"{txid} not in local corpus")

    # title_lookup — for the two citations, what titles do we expect?
    import pandas as pd
    df = pd.read_csv(PROJECT / "data" / "quipu_data.csv")
    title_map = {
        str(r["root_txid"]).lower(): (r["title"] if isinstance(r["title"], str) else "")
        for _, r in df.iterrows() if isinstance(r.get("root_txid"), str)
    }
    title_map[binding_txid.lower()] = "Corrections binding"
    title_map[v2_txid.lower()]      = "Cementerio de los Animales (v2)"
    def title_lookup(txid):
        return title_map.get(txid.lower(), "")

    # ---- 5. Run substitute_body on v2's body ----------------------------
    print()
    print("=" * 60)
    print("substitute_body OUTPUT")
    print("=" * 60)
    resolved = substitute_body(v2_body_md, fetcher=fetcher, title_lookup=title_lookup)
    print(resolved)
    print("=" * 60)

    # ---- 6. Sanity checks ------------------------------------------------
    print()
    print("CHECKS")
    print("-" * 40)
    if binding_txid in resolved:
        print(f"  ✓ binding txid present in resolved output")
    if v1_txid in resolved:
        print(f"  ✓ v1 txid present in resolved output")
    if "quipu:" in resolved:
        n = resolved.count("quipu:")
        print(f"  ✓ {n} quipu: links in output")
    if "dogechain.info" in resolved:
        print(f"  ✗ FAIL: dogechain.info appears in resolved output")
    else:
        print(f"  ✓ no dogechain.info in resolved output")
    print()
    print("substitute_body() ran cleanly on v2's body. No exceptions.")

finally:
    for path in staged:
        path.unlink()
        print(f"\n  cleaned up: {path.name}")
