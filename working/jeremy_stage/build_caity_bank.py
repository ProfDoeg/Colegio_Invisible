#!/usr/bin/env python3
"""Caity as a footage BANK + two breadcrumb graphs — the MODEL C re-skin.

  Type A (0x01 performance) : union pose bank (inline) + SUPER choreography
                              + the 7-method controller.  The citable asset.
  Type C (0x03 graph)       : footage table = FOOT_REF -> Type A, plus the
                              SMALLER lunge/squat breadcrumb wiring.  Re-skins
                              Type A's bank with a new graph, no footage of its
                              own — the cheap overwrite.

The bank is the UNION of every unique pose either breadcrumb file uses, so both
graphs index into one footage. Emits caity_perf.bin (A), caity_typeC.bin (C),
and player-ready data/bodies/caity_A.dancer.json / caity_C.dancer.json (each
carries the shared bank footage + its own graph).

  .venv/bin/python working/jeremy_stage/build_caity_bank.py
"""
import os, sys, json, math, time, base64, hashlib
import numpy as np
from PIL import Image

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AVATARI = os.path.join(REPO, "working", "avatari")
sys.path.insert(0, os.path.join(REPO, "canonical")); sys.path.insert(0, AVATARI)
import dancer as D
import explore as E
import build_caity_demo as BCD

MOVIE = "caity1png.mov"
SUPER = ("caity_super_pcrumbs.txt", "caity_map.txt")     # 50-pose choreography
SMALL = ("caitycrumbs.txt",         "caitymap.txt")      # lunge/squat
RH, PALN, ALPHA, FPS, KEYINT, MARGIN = 128, 16, 24, 8, 8, 8
BODIES = os.path.join(REPO, "data", "bodies")
HERE = os.path.dirname(__file__)

t0 = time.time()
super_cr = E.parse_crumbs(os.path.join(E.SRCDIR, SUPER[0]))
small_cr = E.parse_crumbs(os.path.join(E.SRCDIR, SMALL[0]))
super_map = E.parse_map(os.path.join(E.SRCDIR, SUPER[1]))
small_map = E.parse_map(os.path.join(E.SRCDIR, SMALL[1]))
print("super: %d poses %s" % (len(super_cr), sorted(set(c["label"] for c in super_cr))))
print("small: %d poses %s" % (len(small_cr), sorted(set(c["label"] for c in small_cr))))

# ---- union pose bank (super frames first, then small extras) ----
bank_frames, seen = [], set()
for c in super_cr + small_cr:
    if c["frame"] not in seen:
        seen.add(c["frame"]); bank_frames.append(c["frame"])
bank_ord = {f: i for i, f in enumerate(bank_frames)}
print("bank: %d unique poses (super %d + small %d, overlap %d)"
      % (len(bank_frames), len(super_cr), len(small_cr),
         len(super_cr) + len(small_cr) - len(bank_frames)))

imgs = E.extract_frames(MOVIE, bank_frames)
sw0, sh0 = imgs[bank_frames[0]].size
RW = round(RH * sw0 / sh0)
poses, fcx, vcy = [], [], []
for f in bank_frames:
    im = imgs[f].resize((RW, RH), Image.LANCZOS)
    a = np.asarray(im)[..., 3]; m = a > ALPHA; ys, xs = np.where(m)
    if len(xs) == 0:
        poses.append(im.crop((0, 0, 1, 1))); fcx.append(0.5); vcy.append(0.5); continue
    x0, x1, y0, y1 = int(xs.min()), int(xs.max()+1), int(ys.min()), int(ys.max()+1)
    poses.append(im.crop((x0, y0, x1, y1)))
    fcx.append(float(xs.mean())/RW); vcy.append(float(ys.mean())/RH)
nw = max(p.width for p in poses) + 2*MARGIN; nh = RH

# shared palette over the whole bank
samp = []
for p in poses:
    al = np.asarray(p.convert("RGBA"))[..., 3] > ALPHA
    rgb = np.asarray(p.convert("RGB"))[al]
    if len(rgb): samp.append(rgb[:: max(1, len(rgb)//300)])
master = Image.fromarray(np.concatenate(samp,0).reshape(-1,1,3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)
pf = master.getpalette()[:PALN*3]
palette = [(pf[3*i], pf[3*i+1], pf[3*i+2]) for i in range(PALN)]

bank_fr = []
for i, p in enumerate(poses):
    pw, ph = p.size; x = (nw-pw)//2; y = nh-ph
    idx = np.asarray(p.convert("RGB").quantize(palette=master, dither=Image.Dither.NONE))
    sm = (np.asarray(p.convert("RGBA"))[..., 3] > ALPHA)
    bank_fr.append({"x": x, "y": y, "w": pw, "h": ph, "cx": fcx[i], "cy": vcy[i],
                    "facing": 0, "mask": sm.astype(int).flatten().tolist(),
                    "idx": idx[sm].astype(int).tolist()})
footage = {"palette": palette, "frames": bank_fr, "nw": nw, "nh": nh, "fps": FPS, "keyint": KEYINT}
print("bank footage: %d poses · %dx%d · %d colors (%.0fs)" % (len(bank_fr), nw, nh, PALN, time.time()-t0))


def choreography(crumbs, gmap, name):
    """Build a codec graph (nodes carry bank ordinals) for one breadcrumb file."""
    fr2node = {c["frame"]: i for i, c in enumerate(crumbs)}
    sprites = [poses[bank_ord[c["frame"]]] for c in crumbs]
    nodes_demo = [{"fcx": fcx[bank_ord[c["frame"]]]} for c in crumbs]
    edges_demo = []
    for c in crumbs:
        es = []
        for e in gmap.get(c["frame"], []):
            j = fr2node.get(e["dst"])
            if j is None or e["weight"] <= 0:
                continue
            es.append({"to": j, "dx": 0.0, "time": e["time"], "space": e["space"],
                       "weight": e["weight"], "control": e["control"]})
        edges_demo.append(es)
    rec = sum(len(e) for e in edges_demo)
    tun, br = BCD.add_tunnels(sprites, nodes_demo, edges_demo)
    labv = sorted(set(c["label"] for c in crumbs)); li = {n: k for k, n in enumerate(labv)}
    sym = {1: D.SYM_SAME, 2: D.SYM_REFLECTED}
    nodes = []
    for i, c in enumerate(crumbs):
        edges = [{"dst": e["to"], "time": 0 if e["time"] == 1 else 1,
                  "space": 0 if e["space"] == 1 else 1, "ctrl": e.get("control", 1)}
                 for e in edges_demo[i]]
        nodes.append({"foot": 0, "ord": bank_ord[c["frame"]], "label": li[c["label"]],
                      "sym": sym.get(c["variant"], D.SYM_SYMMETRIC), "edges": edges})
    start = min(range(len(crumbs)), key=lambda i: abs(fcx[bank_ord[crumbs[i]["frame"]]] - 0.5))
    print("  %s graph: %d nodes · recorded %d +tunnels %d +bridges %d" % (name, len(nodes), rec, tun, br))
    return nodes, start, labv


def controller(start):
    def q(g): return {"id": D.M_QUANTUM, "generator": g, "measure_per_step": 1.0,
                      "measure_handedness": 0, "well_depth": 1.5}
    return {"start": start, "mode0": D.CTRL_ALL, "default_method": 1,
            "methods": [{"id": D.M_UNIFORM},
                        {"id": D.M_BOLTZMANN, "beta": 2.0, "gain_t": 1.0, "axis": 0, "pref": 0},
                        q(D.GEN_SIMILARITY), q(D.GEN_SYMNORM), q(D.GEN_FULL), q(D.GEN_SA),
                        {"id": D.M_KEYBOARD, "map": 0}],
            "prefs": [],
            "bindings": [{"source": D.SRC_ATTRACTOR_X, "port": D.PORT_TARGET, "scale": 1.0},
                         {"source": D.SRC_KEY_BTN, "port": D.PORT_METHOD_SELECT, "scale": 1.0}]}


def b64(bs): return base64.b64encode(bytes(bs)).decode()

def dancer_json(title, foot, nodes, start, labels, default_method):
    fout = [{"x": f["x"], "y": f["y"], "w": f["w"], "h": f["h"], "cx": round(f["cx"], 4),
             "cy": round(f["cy"], 4), "facing": f["facing"],
             "mask": b64(bytes(f["mask"])), "idx": b64(bytes(f["idx"]))} for f in foot["frames"]]
    return {"title": title, "nw": foot["nw"], "nh": foot["nh"], "fps": foot["fps"],
            "palette": foot["palette"], "frames": fout,
            "graph": {"start": start, "labels": labels,
                      "nodes": [{"ord": n["ord"], "sym": n["sym"],
                                 "edges": [{"dst": e["dst"], "time": e["time"], "space": e["space"]}
                                           for e in n["edges"]]} for n in nodes]},
            "default_method": default_method}


os.makedirs(BODIES, exist_ok=True)

# ---- Type A — performance: bank inline + SUPER choreography + controller ----
nA, sA, lA = choreography(super_cr, super_map, "Type A (super)")
graphA = {"footage": [("inline", footage)], "nmode": 3, "labels": lA, "start": sA, "nodes": nA}
hA, bA = D.build_performance("Caity", graphA, [controller(sA)], tone=D.TONE_ORDINARY)
blobA = bytes(hA) + bytes(bA)
open(os.path.join(HERE, "caity_perf.bin"), "wb").write(blobA)
refA = hashlib.sha256(blobA).digest()                    # placeholder txid until inscription
print("Type A: %.1f KB · %d knots · footage-ref placeholder %s…" %
      (len(blobA)/1e3, math.ceil(len(blobA)/80), refA.hex()[:16]))

# ---- Type C — graph: FOOT_REF -> Type A + SMALL (lunge/squat) wiring ----
nC, sC, lC = choreography(small_cr, small_map, "Type C (lunge/squat)")
graphC = {"footage": [("ref", refA.hex())], "nmode": 3, "labels": lC, "start": sC, "nodes": nC}
hC, bC = D.build_graph("Caity · lunge/squat (Type C)", graphC, tone=D.TONE_ORDINARY)
blobC = bytes(hC) + bytes(bC)
open(os.path.join(HERE, "caity_typeC.bin"), "wb").write(blobC)
print("Type C: %d B · %d knots (footage by REFERENCE — re-skin only)" % (len(blobC), math.ceil(len(blobC)/80)))

# round-trips
pA = D.read_dancer(hA, bA); pC = D.read_dancer(hC, bC)
assert pA["variant_name"] == "performance" and pC["variant_name"] == "graph"
assert pC["graph"]["footage"][0][0] == "ref" and pC["graph"]["footage"][0][1] == refA.hex()
print("round-trip OK · A=performance(%d nodes) · C=graph(%d nodes, footage=ref %s…)" %
      (len(pA["graph"]["nodes"]), len(pC["graph"]["nodes"]), pC["graph"]["footage"][0][1][:12]))

# player-ready jsons (both carry the shared bank footage + their own graph)
json.dump(dancer_json("Caity · super (Type A)", footage, nA, sA, lA, 1),
          open(os.path.join(BODIES, "caity_A.dancer.json"), "w"))
json.dump(dancer_json("Caity · lunge/squat (Type C re-skin)", footage, nC, sC, lC, 1),
          open(os.path.join(BODIES, "caity_C.dancer.json"), "w"))
print("wrote caity_A.dancer.json + caity_C.dancer.json · build %.0fs" % (time.time()-t0))
