#!/usr/bin/env python3
"""Build Caity as a 0xda dancer — SAME pipeline as Jeremy's build_body.py.

The footage is the CONTINUOUS recording (every frame of caity1png.mov across
the breadcrumb span, delta-coded); the breadcrumbs are the graph's CUT-POINTS
(node.ord = a frame ordinal within that footage) and caity_map.txt supplies the
edges. The real recorded motion plays between cuts — exactly Jeremy's model, so
play_jeremy_chain's player plays her with no changes.

  .venv/bin/python working/jeremy_stage/build_caity.py
"""
import os, sys, json, math, time, base64, subprocess, tempfile, glob
import numpy as np
from PIL import Image

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "canonical"))
sys.path.insert(0, os.path.join(REPO, "working", "avatari"))
import dancer as D
import explore as E

MOVIE  = "caity1png.mov"
CRUMBS = "caity_super_pcrumbs.txt"
MAP    = "caity_map.txt"
RH, PALN, ALPHA, FPS, KEYINT = 128, 16, 24, 30, 30      # caity matte threshold = 24
BODIES = os.path.join(REPO, "data", "bodies")
HERE = os.path.dirname(__file__)
t0 = time.time()

crumbs = E.parse_crumbs(os.path.join(E.SRCDIR, CRUMBS))
gmap   = E.parse_map(os.path.join(E.SRCDIR, MAP))
node_abs = sorted(c["frame"] for c in crumbs)
start_f, end_f = node_abs[0], node_abs[-1]
nF = end_f - start_f + 1
labv_map = {c["frame"]: c["label"] for c in crumbs}
var_map  = {c["frame"]: c["variant"] for c in crumbs}
print("breadcrumbs: %d cut-points · frames %d..%d (%d continuous frames) · labels %s"
      % (len(node_abs), start_f, end_f, nF, sorted(set(labv_map.values()))))

# ---- extract the CONTINUOUS frame range from the movie ----
tmp = tempfile.mkdtemp(prefix="caity_")
subprocess.run([E.FFMPEG, "-v", "error", "-i", os.path.join(E.SRCDIR, MOVIE),
                "-vf", "select='between(n\\,%d\\,%d)',format=rgba" % (start_f, end_f),
                "-vsync", "0", os.path.join(tmp, "o_%05d.png")], check=True)
files = sorted(glob.glob(os.path.join(tmp, "o_*.png")))
nF = len(files)
print("extracted %d continuous frames (%.0fs)" % (nF, time.time() - t0))

sw0, sh0 = Image.open(files[0]).size
RW = round(RH * sw0 / sh0)

# ---- shared 16-color palette (sample every 30th frame, like Jeremy) ----
samp = []
for k in range(0, nF, 30):
    im = Image.open(files[k]).convert("RGBA").resize((RW, RH), Image.LANCZOS)
    a = np.asarray(im)[..., 3]; rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
    if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
master = Image.fromarray(np.concatenate(samp, 0).reshape(-1, 1, 3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)
pf = master.getpalette()[:PALN*3]
palette = [(pf[3*i], pf[3*i+1], pf[3*i+2]) for i in range(PALN)]

# ---- per-frame tight sprite + centroid (continuous footage) ----
frames = []
for fn in files:
    im = Image.open(fn).convert("RGBA").resize((RW, RH), Image.LANCZOS)
    a = np.asarray(im)[..., 3]; m = a > ALPHA; ys, xs = np.where(m)
    if len(xs) == 0:
        frames.append({"x": 0, "y": 0, "w": 1, "h": 1, "cx": 0.5, "cy": 0.5,
                       "facing": 0, "mask": [0], "idx": [0]}); continue
    x0, x1, y0, y1 = int(xs.min()), int(xs.max()+1), int(ys.min()), int(ys.max()+1)
    idx = np.asarray(im.convert("RGB").crop((x0, y0, x1, y1)).quantize(palette=master, dither=Image.Dither.NONE))
    sm = m[y0:y1, x0:x1]
    frames.append({"x": x0, "y": y0, "w": x1-x0, "h": y1-y0,
                   "cx": float(xs.mean())/RW, "cy": float(ys.mean())/RH,
                   "facing": 0, "mask": sm.astype(int).flatten().tolist(), "idx": idx[sm].astype(int).tolist()})
footage = {"palette": palette, "frames": frames, "nw": RW, "nh": RH, "fps": FPS, "keyint": KEYINT}
print("footage encoded: %d frames · %dx%d · %d colors (%.0fs)" % (nF, RW, RH, PALN, time.time()-t0))

# ---- graph: DERIVE the map from the breadcrumbs alone (group poses by label) ----
# A pose links to every other pose sharing its LABEL; same variant -> same space,
# different variant -> mirror; each pair gets forward + reverse in time. This is
# exactly what the 2009 auto_map_making.maxpat baked into caity_map.txt — so the
# breadcrumbs are the only input we need (the map file is just a cached copy).
from collections import defaultdict
nidx = {f: i for i, f in enumerate(node_abs)}            # abs frame -> node index
groups = defaultdict(list)
for f in node_abs:
    groups[labv_map[f]].append(f)
labvocab = sorted(groups); lab_i = {n: k for k, n in enumerate(labvocab)}
symmap = {1: D.SYM_SAME, 2: D.SYM_REFLECTED}

# The ONE thing not in the breadcrumbs: the per-edge CONTROL MODE (1..N). Pull it
# from the map, keyed by (src frame, dst frame, time direction). This is what the
# keyboard controller switches between; connectivity/time/space are derived above.
ctrl_lut, modes = {}, set()
for f in node_abs:
    for e in gmap.get(f, []):
        if e["dst"] in nidx and e["weight"] > 0:
            ctrl_lut[(f, e["dst"], 0 if e["time"] == 1 else 1)] = e["control"]
            modes.add(e["control"])
NMODE = max(modes) if modes else 1

def derive_edges(f):
    es = []
    for g in groups[labv_map[f]]:
        space = D.SPACE_SAME if var_map[g] == var_map[f] else D.SPACE_MIRROR
        if g == f:                                          # self-loop = replay this phrase
            es.append({"dst": nidx[g], "time": D.TIME_FWD, "space": D.SPACE_SAME,
                       "ctrl": ctrl_lut.get((f, g, D.TIME_FWD), D.CTRL_ALL)})
        else:
            for t in (D.TIME_FWD, D.TIME_REV):
                es.append({"dst": nidx[g], "time": t, "space": space,
                           "ctrl": ctrl_lut.get((f, g, t), D.CTRL_ALL)})
    return es
nodes = [{"foot": 0, "ord": f - start_f, "label": lab_i[labv_map[f]],
          "sym": symmap.get(var_map[f], D.SYM_SYMMETRIC), "edges": derive_edges(f)} for f in node_abs]
start = min(range(len(node_abs)), key=lambda i: abs(frames[node_abs[i]-start_f]["cx"] - 0.5))
graph = {"footage": [("inline", footage)], "nmode": NMODE, "labels": labvocab, "start": start, "nodes": nodes}

# cross-check: the label derivation reproduces the map's CONNECTIVITY (modes excepted)
matched = sum(1 for f in node_abs
              if {e["dst"] for e in gmap.get(f, []) if e["weight"] > 0 and e["dst"] in nidx}
              == set(groups[labv_map[f]]))
print("graph: %d nodes · %d edges · start %d · %d control modes (from map) · connectivity matches map on %d/%d nodes"
      % (len(nodes), sum(len(n["edges"]) for n in nodes), start, NMODE, matched, len(node_abs)))

# ---- controller: same full palette as Jeremy ----
def q(g): return {"id": D.M_QUANTUM, "generator": g, "measure_per_step": 1.0, "measure_handedness": 0, "well_depth": 1.5}
ctrl = {"start": start, "mode0": D.CTRL_ALL, "default_method": 1,
        "methods": [{"id": D.M_UNIFORM},
                    {"id": D.M_BOLTZMANN, "beta": 2.0, "gain_t": 1.0, "axis": 0, "pref": 0},
                    q(D.GEN_SIMILARITY), q(D.GEN_SYMNORM), q(D.GEN_FULL), q(D.GEN_SA),
                    {"id": D.M_KEYBOARD, "map": 0}],
        "prefs": [],
        "bindings": [{"source": D.SRC_ATTRACTOR_X, "port": D.PORT_TARGET, "scale": 1.0},
                     {"source": D.SRC_KEY_BTN, "port": D.PORT_METHOD_SELECT, "scale": 1.0}]}

h, b = D.build_performance("Caity", graph, [ctrl], tone=D.TONE_ORDINARY)
blob = bytes(h) + bytes(b)
open(os.path.join(HERE, "caity_perf.bin"), "wb").write(blob)
knots = math.ceil(len(blob)/80)
print("Caity 0xda performance: %.2f MB (%d B) · %d knots · %d tx" % (len(blob)/1e6, len(blob), knots, knots+2))

p = D.read_dancer(h, b); g = p["graph"]; foot = g["footage"][0][1]
print("round-trip: %s · %d frames · %dx%d · %d nodes · %d controllers" %
      (p["variant_name"], len(foot["frames"]), foot["nw"], foot["nh"], len(g["nodes"]), len(p["controllers"])))

# ---- player-ready json (same shape as Jeremy's load_from_chain) ----
def b64(bs): return base64.b64encode(bytes(bs)).decode()
fout = [{"x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"], "cx": round(f["cx"], 4),
         "cy": round(f["cy"], 4), "facing": f["facing"], "mask": b64(bytes(f["mask"])),
         "idx": b64(bytes(f["idx"]))} for f in foot["frames"]]
dj = {"title": "Caity", "nw": foot["nw"], "nh": foot["nh"], "fps": foot["fps"], "palette": foot["palette"],
      "frames": fout, "nmode": g["nmode"],
      "graph": {"start": g["start"], "labels": g["labels"],
                "nodes": [{"ord": n["ord"], "sym": n["sym"],
                           "edges": [{"dst": e["dst"], "time": e["time"], "space": e["space"], "ctrl": e["ctrl"]}
                                     for e in n["edges"]]} for n in g["nodes"]]},
      "default_method": ctrl["default_method"]}
os.makedirs(BODIES, exist_ok=True)
json.dump(dj, open(os.path.join(BODIES, "caity.dancer.json"), "w"))
import shutil; shutil.rmtree(tmp, ignore_errors=True)
print("wrote data/bodies/caity.dancer.json (%.1f MB) · build %.0fs"
      % (os.path.getsize(os.path.join(BODIES, "caity.dancer.json"))/1e6, time.time()-t0))
