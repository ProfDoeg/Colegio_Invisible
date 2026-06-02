#!/usr/bin/env python3
"""Measure movement energy per clip (the footage span between two breadcrumb
cut-points) of a 0xda dancer, so we know what the attractor field has to work
with. Three standard motion energies, each a per-frame quantity averaged over
the clip's frames:

  E_x   = mean (Δcx)^2          horizontal centroid energy   (sway / travel)
  E_y   = mean (Δcy)^2          vertical centroid energy     (bob / crouch)
  E_pix = mean Σ|frame diff|    raw luminance churn          (everything moving)

Their combination classifies a clip:
  still             low E_pix
  dancing-in-place  high E_pix, low E_x  (limbs move, body stays)
  traveling/sway    high E_x
plus net |Δcx| (directed travel) and mean cy (level) for context.

  .venv/bin/python working/jeremy_stage/measure_clips.py [path/to/perf.bin]
"""
import os, sys
import numpy as np

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "canonical"))
import dancer as D

BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "jeremy_perf.bin")
blob = open(BIN, "rb").read()
tlen = blob[7]
p = D.read_dancer(blob[:8 + tlen], blob[8 + tlen:])
g = p["graph"]; foot = g["footage"][0][1]
frames = foot["frames"]; nw, nh, fps = foot["nw"], foot["nh"], foot["fps"]
nodes = g["nodes"]; labels = g["labels"]; nF = len(frames)
LUT = np.array([0.299 * r + 0.587 * gg + 0.114 * b for (r, gg, b) in foot["palette"]], np.float32)
print("'%s' · %d frames · %dx%d · %d fps · %d cut-points" % (p["title"], nF, nw, nh, fps, len(nodes)))


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
dcx2 = np.zeros(nF); dcy2 = np.zeros(nF); dpix = np.zeros(nF)
prev = None
for i, f in enumerate(frames):
    cur = lum_map(f)
    if prev is not None:
        dcx2[i] = (cx[i] - cx[i - 1]) ** 2
        dcy2[i] = (cy[i] - cy[i - 1]) ** 2
        dpix[i] = float(np.abs(cur - prev).sum())
    prev = cur

ord_label = {n["ord"]: (labels[n["label"]] if n["label"] < len(labels) else "?") for n in nodes}
ords = sorted(ord_label)
clips = []
for a, b in zip(ords, ords[1:]):
    if b <= a + 1:
        continue
    sl = slice(a + 1, b)
    clips.append({
        "label": ord_label[a], "a": a, "b": b, "dur": b - a,
        "Ex": float(dcx2[sl].mean()), "Ey": float(dcy2[sl].mean()), "Epix": float(dpix[sl].mean()),
        "travel": float(abs(cx[b - 1] - cx[a])), "level": float(cy[a:b].mean()),
    })

Ex = np.array([c["Ex"] for c in clips]); Ey = np.array([c["Ey"] for c in clips])
Ep = np.array([c["Epix"] for c in clips])
ex_hi = np.percentile(Ex, 60); ep_lo, ep_hi = np.percentile(Ep, [33, 66])


def klass(c):
    if c["Ex"] >= ex_hi:
        return "traveling/sway"
    if c["Epix"] >= ep_hi:
        return "dancing-in-place"
    if c["Epix"] <= ep_lo:
        return "still"
    return "moderate"


from collections import Counter
cls = Counter(klass(c) for c in clips)
print("\n%d clips · duration %.1f–%.1fs (median %.1fs)" %
      (len(clips), min(c["dur"] for c in clips) / fps, max(c["dur"] for c in clips) / fps,
       float(np.median([c["dur"] for c in clips])) / fps))
print("E_x   (×1e-3):  mean %.3f  60th %.3f  max %.3f" % (Ex.mean()*1e3, ex_hi*1e3, Ex.max()*1e3))
print("E_y   (×1e-3):  mean %.3f  max %.3f" % (Ey.mean()*1e3, Ey.max()*1e3))
print("E_pix (per-cell |Δlum|): mean %.2f  33rd %.2f  66th %.2f  max %.2f" %
      (Ep.mean()/(nw*nh), ep_lo/(nw*nh), ep_hi/(nw*nh), Ep.max()/(nw*nh)))
print("classes:", dict(cls))

row = lambda c: "  %-10s f%4d-%-4d %4.1fs · Epix %5.2f · Ex %6.3f · Ey %6.3f · travel %.3f · level %.2f" % (
    c["label"], c["a"], c["b"], c["dur"]/fps, c["Epix"]/(nw*nh), c["Ex"]*1e3, c["Ey"]*1e3, c["travel"], c["level"])
print("\n— most dance-in-place (high Epix, low Ex) —")
for c in sorted([c for c in clips if c["Ex"] < ex_hi], key=lambda c: -c["Epix"])[:6]: print(row(c))
print("\n— stillest (low Epix) —")
for c in sorted(clips, key=lambda c: c["Epix"])[:6]: print(row(c))
print("\n— most traveling/sway (high Ex) —")
for c in sorted(clips, key=lambda c: -c["Ex"])[:6]: print(row(c))
print("\n(Epix shown as mean |Δlum| per cell, 0–255 scale; Ex,Ey shown ×1e3)")
