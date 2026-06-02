#!/usr/bin/env python3
"""Emit data/bodies/sim3d/jeremy3d.json — one self-contained file for the 3-D
field sim: the footage sprites (to render each billboard) + the graph with
per-node clip metrics (to drive the field). The frame cursor indexes frames[]
directly, so the SAME footage motion drives both the displayed pose and the
floor drift.

  .venv/bin/python working/jeremy_stage/build_3d_data.py [perf.bin]
"""
import os, sys, json, base64
import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "canonical"))
import dancer as D

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "jeremy_perf.bin")
OUT = os.path.join(REPO, "data", "bodies", "sim3d", "jeremy3d.json")
blob = open(BIN, "rb").read(); tlen = blob[7]
p = D.read_dancer(blob[:8 + tlen], blob[8 + tlen:])
g = p["graph"]; foot = g["footage"][0][1]
frames = foot["frames"]; nw, nh, fps = foot["nw"], foot["nh"], foot["fps"]
nodes = g["nodes"]; labels = g["labels"]; nF = len(frames)
LUT = np.array([0.299 * r + 0.587 * gg + 0.114 * b for (r, gg, b) in foot["palette"]], np.float32)
cell = nw * nh


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


cx = np.array([f["cx"] for f in frames])
dpix = np.zeros(nF); prev = None
for i, f in enumerate(frames):
    cur = lum_map(f)
    if prev is not None:
        dpix[i] = float(np.abs(cur - prev).sum())
    prev = cur

ords = sorted(n["ord"] for n in nodes)
nextord = {o: (ords[k + 1] if k + 1 < len(ords) else nF) for k, o in enumerate(ords)}


def clip_metrics(o):
    b = nextord[o]; sl = slice(o + 1, max(o + 2, b)); net = float(cx[b - 1] - cx[o])
    return {"travel": abs(net), "net": round(net, 4), "Epix": float(dpix[sl].mean() / cell)}


out_nodes = []
for n in nodes:
    m = clip_metrics(n["ord"])
    out_nodes.append({"ord": n["ord"],
                      "edges": [{"dst": e["dst"], "time": e["time"], "space": e["space"]} for e in n["edges"]],
                      **m})
Ex_unused = None
Ep = np.array([n["Epix"] for n in out_nodes])
trav = np.array([n["travel"] for n in out_nodes])
t_hi = np.percentile(trav, 60); ep_lo, ep_hi = np.percentile(Ep, [33, 66])
for n in out_nodes:
    n["cls"] = ("travel" if n["travel"] >= t_hi else
                "dance" if n["Epix"] >= ep_hi else
                "still" if n["Epix"] <= ep_lo else "moderate")


def b64(bs):
    return base64.b64encode(bytes(bs)).decode()


frames_out = [{"x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"], "cx": round(f["cx"], 4),
               "facing": f["facing"], "mask": b64(bytes(f["mask"])), "idx": b64(bytes(f["idx"]))} for f in frames]

os.makedirs(os.path.dirname(OUT), exist_ok=True)
json.dump({"title": p["title"], "nw": nw, "nh": nh, "fps": fps, "palette": foot["palette"],
           "frames": frames_out, "nodes": out_nodes}, open(OUT, "w"))
from collections import Counter
print("wrote %s (%.1f MB) · %d frames · %d nodes · %s"
      % (OUT, os.path.getsize(OUT) / 1e6, nF, len(out_nodes), dict(Counter(n["cls"] for n in out_nodes))))
