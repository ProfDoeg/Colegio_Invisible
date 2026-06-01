#!/usr/bin/env python3
"""Build the on-chain body for the Jeremy dancer — a self-contained 0x01
performance: delta-coded footage (16-color, 128px, 30fps) + the motion graph
(footage inline) + a default boltzmann controller. Key-free: this only produces
the public bytes to be inscribed; signing happens separately with the apocrypha
key. Writes working/jeremy_stage/jeremy_perf.bin and prints size + cost.

Run:  .venv/bin/python working/jeremy_stage/build_body.py
"""
import os, sys, json, math, time
import numpy as np
from PIL import Image

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "canonical"))
import dancer as D

FR   = os.path.join(REPO, "working/avatari/_frames_jeremy")
LIVE = os.path.join(REPO, "working/avatari/live")
OUT  = os.path.join(REPO, "working/jeremy_stage")
RH, PALN, ALPHA, FPS, KEYINT = 128, 16, 100, 30, 30
TIP = 0.02

t0 = time.time()
files = sorted(f for f in os.listdir(FR) if f.startswith("f_"))
nF = len(files)
sw0, sh0 = Image.open(os.path.join(FR, files[0])).size
RW = round(RH * sw0 / sh0)
cxs = json.load(open(os.path.join(LIVE, "centroids.json")))

# shared 16-color palette
samp = []
for k in range(0, nF, 30):
    im = Image.open(os.path.join(FR, files[k])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
    a = np.asarray(im)[..., 3]; rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
    if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
master = Image.fromarray(np.concatenate(samp, 0).reshape(-1, 1, 3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)
pf = master.getpalette()[:PALN*3]
palette = [(pf[3*i], pf[3*i+1], pf[3*i+2]) for i in range(PALN)]

frames = []
for i, fn in enumerate(files):
    im = Image.open(os.path.join(FR, fn)).convert("RGBA").resize((RW, RH), Image.LANCZOS)
    a = np.asarray(im)[..., 3]; m = a > ALPHA; ys, xs = np.where(m)
    if len(xs) == 0:
        frames.append({"x": 0, "y": 0, "w": 1, "h": 1, "cx": float(cxs[i]), "cy": 0.5, "facing": 0, "mask": [0], "idx": [0]}); continue
    x0, x1, y0, y1 = int(xs.min()), int(xs.max()+1), int(ys.min()), int(ys.max()+1)
    idx = np.asarray(im.convert("RGB").crop((x0, y0, x1, y1)).quantize(palette=master, dither=Image.Dither.NONE))
    sm = m[y0:y1, x0:x1]
    frames.append({"x": x0, "y": y0, "w": x1-x0, "h": y1-y0, "cx": float(cxs[i]), "cy": float(ys.mean()/RH),
                   "facing": 0, "mask": sm.astype(int).flatten().tolist(), "idx": idx[sm].astype(int).tolist()})
print("frames encoded %.0fs" % (time.time()-t0))
footage = {"palette": palette, "frames": frames, "nw": RW, "nh": RH, "fps": FPS, "keyint": KEYINT}

# graph from player.json (footage inline)
P = json.load(open(os.path.join(LIVE, "player.json")))
nodeFrames = sorted(P["nodeFrames"]); nidx = {f: i for i, f in enumerate(nodeFrames)}
labvocab = sorted(set(P["labels"].values())); lab_i = {n: i for i, n in enumerate(labvocab)}
symmap = {"1": D.SYM_SAME, "2": D.SYM_REFLECTED, "3": D.SYM_SYMMETRIC}
nodes = []
for f in nodeFrames:
    edges = [{"dst": nidx[dst], "time": 0 if t == 1 else 1, "space": 0 if sp == 1 else 1, "ctrl": c}
             for dst, t, sp, w, c in P["edges"][str(f)] if w > 0 and dst in nidx]
    nodes.append({"foot": 0, "ord": f, "label": lab_i.get(P["labels"].get(str(f), ""), 0),
                  "sym": symmap.get(P["variant"].get(str(f)), D.SYM_SYMMETRIC), "edges": edges})
start = nidx.get(P["start"], 0)
graph = {"footage": [("inline", footage)], "nmode": 3, "labels": labvocab, "start": start, "nodes": nodes}

# full control palette in one toggleable controller (default = boltzmann chase)
def quantum(gen): return {"id": D.M_QUANTUM, "generator": gen, "measure_per_step": 1.0,
                          "measure_handedness": 0, "well_depth": 1.5}
ctrl = {"start": start, "mode0": D.CTRL_ALL, "default_method": 1,
        "methods": [
            {"id": D.M_UNIFORM},
            {"id": D.M_BOLTZMANN, "beta": 2.0, "gain_t": 1.0, "axis": 0, "pref": 0},
            quantum(D.GEN_SIMILARITY),   # S — Hermitian, unitary
            quantum(D.GEN_SYMNORM),      # D^-1/2 S D^-1/2
            quantum(D.GEN_FULL),         # full transition matrix
            quantum(D.GEN_SA),           # S + A — chiral / time-arrow
            {"id": D.M_KEYBOARD, "map": 0},
        ],
        "prefs": [],
        "bindings": [{"source": D.SRC_ATTRACTOR_X, "port": D.PORT_TARGET, "scale": 1.0},
                     {"source": D.SRC_KEY_BTN, "port": D.PORT_METHOD_SELECT, "scale": 1.0}]}

h, b = D.build_performance("Jeremy", graph, [ctrl], tone=D.TONE_ORDINARY)
blob = bytes(h) + bytes(b)
open(os.path.join(OUT, "jeremy_perf.bin"), "wb").write(blob)
total = len(blob); knots = math.ceil(total / 80); tx = knots + 2
print("Jeremy 0x01 performance: %.2f MB (%d B) · %d knots · %d tx" % (total/1e6, total, knots, tx))
print("  cost @ %.2f/tx = %.0f DOGE  (apocrypha has 644.35)" % (TIP, tx*TIP))
print("  round-trip check…")
p = D.read_dancer(h, b)
g = p["graph"]
print("  variant=%s · footage frames=%d · nodes=%d · controllers=%d · build %.0fs" %
      (p["variant_name"], len(g["footage"][0][1]["frames"]), len(g["nodes"]), len(p["controllers"]), time.time()-t0))
