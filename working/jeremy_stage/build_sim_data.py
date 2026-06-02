#!/usr/bin/env python3
"""Emit the graph + per-node clip motion-metrics as JSON for the 2-D dynamics
sim (data/bodies/sim/jeremy_sim.json).

Each node carries the metrics of its forward clip (the footage span from its
cut-point to the next), so the sim can drive footage-drift and pick clips by
behaviour (travel / dance / still) exactly as the attractor field will.

  .venv/bin/python working/jeremy_stage/build_sim_data.py [perf.bin]
"""
import os, sys, json
import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "canonical"))
import dancer as D

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "jeremy_perf.bin")
OUT = os.path.join(REPO, "data", "bodies", "sim", "jeremy_sim.json")
blob = open(BIN, "rb").read(); tlen = blob[7]
p = D.read_dancer(blob[:8 + tlen], blob[8 + tlen:])
g = p["graph"]; foot = g["footage"][0][1]
frames = foot["frames"]; nw, nh, fps = foot["nw"], foot["nh"], foot["fps"]
nodes = g["nodes"]; labels = g["labels"]; nF = len(frames)
LUT = np.array([0.299 * r + 0.587 * gg + 0.114 * b for (r, gg, b) in foot["palette"]], np.float32)


def lum_map(f):
    m = np.zeros((nh, nw), np.float32)
    w, hh = f["w"], f["h"]
    if w * hh <= 1:
        return m
    sg = np.zeros((hh, w), np.float32)
    mask = np.array(f["mask"], bool).reshape(hh, w)
    sg[mask] = LUT[np.array(f["idx"], np.int16)]
    y, x = f["y"], f["x"]
    r1, c1 = min(nh, y + hh), min(nw, x + w)
    if y < r1 and x < c1:
        m[y:r1, x:c1] = sg[:r1 - y, :c1 - x]
    return m


cx = np.array([f["cx"] for f in frames]); cy = np.array([f["cy"] for f in frames])
dcx2 = np.zeros(nF); dcy2 = np.zeros(nF); dpix = np.zeros(nF); prev = None
for i, f in enumerate(frames):
    cur = lum_map(f)
    if prev is not None:
        dcx2[i] = (cx[i] - cx[i - 1]) ** 2; dcy2[i] = (cy[i] - cy[i - 1]) ** 2
        dpix[i] = float(np.abs(cur - prev).sum())
    prev = cur

ords = sorted(n["ord"] for n in nodes)
nextord = {o: (ords[k + 1] if k + 1 < len(ords) else nF) for k, o in enumerate(ords)}
cell = nw * nh

def clip_metrics(o):
    b = nextord[o]; sl = slice(o + 1, max(o + 2, b))
    return {"travel": float(abs(cx[b - 1] - cx[o])), "Ex": float(dcx2[sl].mean()),
            "Ey": float(dcy2[sl].mean()), "Epix": float(dpix[sl].mean() / cell),
            "dur": int(b - o)}

out_nodes = []
for n in nodes:
    o = n["ord"]; b = nextord[o]
    m = clip_metrics(o)
    out_nodes.append({"ord": o, "label": labels[n["label"]] if n["label"] < len(labels) else "?",
                      "edges": [{"dst": e["dst"], "time": e["time"], "space": e["space"]} for e in n["edges"]],
                      "cx": [round(float(cx[i]), 4) for i in range(o, b)],   # per-frame centroid x for footage-accurate drift
                      **m})

# classify by percentiles (relative — Jeremy dances throughout)
Ex = np.array([n["Ex"] for n in out_nodes]); Ep = np.array([n["Epix"] for n in out_nodes])
ex_hi = float(np.percentile(Ex, 60)); ep_lo, ep_hi = np.percentile(Ep, [33, 66])
for n in out_nodes:
    n["cls"] = ("travel" if n["Ex"] >= ex_hi else
                "dance" if n["Epix"] >= ep_hi else
                "still" if n["Epix"] <= ep_lo else "moderate")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
json.dump({"title": p["title"], "fps": fps, "nF": nF,
           "thresh": {"ex_hi": ex_hi, "ep_lo": float(ep_lo), "ep_hi": float(ep_hi)},
           "nodes": out_nodes}, open(OUT, "w"))
from collections import Counter
print("wrote %s · %d nodes · classes %s" % (OUT, len(out_nodes), dict(Counter(n["cls"] for n in out_nodes))))
