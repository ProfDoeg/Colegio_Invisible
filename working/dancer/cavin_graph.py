#!/usr/bin/env python3
"""Stage 1b — build the motion graph for the Cavin dancer under the V4
transform group {I, M, R, MR}: identity, mirror (flip), reverse (negative
time), and mirror+reverse.

Nodes are key poses (key frames clustered by a centred, scale-normalised
silhouette descriptor so a shared idle collapses to one hub). Each action is
a directed path through its poses; the three non-trivial transforms generate
the mirrored / reversed / mirror-reversed variants. Transition edges appear
wherever a pose matches another (same cluster), so a walk through the graph
is a continuous dance built from a tiny inscribed set.

Outputs (working/dancer/cavin/):
  graph.json    nodes + edges (clip, transform, displacement)
  graph.png     node-link diagram, pose thumbnails as nodes, edges by transform

Run:  .venv/bin/python working/dancer/cavin_graph.py
"""
import os
import json
import math

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "cavin")
FR = os.path.join(WORK, "frames")

PW, PH = 26, 40           # pose-descriptor grid
ATHRESH = 24              # alpha → figure
MATCH = 0.16              # hamming fraction below which two poses are "the same"


def descriptor(path):
    """Centred, scale-normalised silhouette bitmask (PW×PH) of a crop."""
    im = Image.open(path).convert("RGBA")
    a = im.split()[3]
    bb = a.getbbox() or (0, 0, im.width, im.height)
    a = a.crop(bb).resize((PW, PH))
    px = a.load()
    return [1 if px[x, y] > ATHRESH else 0 for y in range(PH) for x in range(PW)]


def mirror(sig):
    out = [0] * (PW * PH)
    for y in range(PH):
        for x in range(PW):
            out[y*PW + (PW-1-x)] = sig[y*PW + x]
    return out


def ham(a, b):
    return sum(1 for p, q in zip(a, b) if p != q) / len(a)


def main():
    track = json.load(open(os.path.join(WORK, "track.json")))

    # --- gather key frames with descriptor + centroid -------------------
    kfs = []   # {clip, k, file, sig, cx, cy}
    for act in track["actions"]:
        for fr in act["frames"]:
            f = "%s_%04d.png" % (act["name"], fr["src_frame"])
            p = os.path.join(FR, f)
            if not os.path.exists(p):
                continue
            kfs.append({"clip": act["name"], "k": fr["src_frame"], "file": f,
                        "sig": descriptor(p), "cx": fr["centroid"][0],
                        "cy": fr["centroid"][1]})

    # --- cluster poses (originals first, then add mirror nodes) ---------
    nodes = []   # {id, sig, rep, cx, mirror_of}

    def find(sig):
        best, bd = None, 1.0
        for nd in nodes:
            d = ham(sig, nd["sig"])
            if d < bd:
                bd, best = d, nd
        return best if bd < MATCH else None

    for kf in kfs:
        nd = find(kf["sig"])
        if nd is None:
            nd = {"id": "p%02d" % len(nodes), "sig": kf["sig"],
                  "rep": kf["file"], "cx": kf["cx"], "mirror_of": None}
            nodes.append(nd)
        kf["node"] = nd["id"]

    # mirror nodes: each pose's mirror is a node too (merge with an existing
    # pose if the mirror matches one — a self-symmetric pose maps to itself).
    mir = {}                                  # node id -> mirror node id
    for nd in list(nodes):
        msig = mirror(nd["sig"])
        match = None
        for other in nodes:
            if ham(msig, other["sig"]) < MATCH:
                match = other; break
        if match is None:
            mnd = {"id": nd["id"] + "m", "sig": msig, "rep": nd["rep"],
                   "cx": 1 - nd["cx"], "mirror_of": nd["id"]}
            nodes.append(mnd)
            mir[nd["id"]] = mnd["id"]
        else:
            mir[nd["id"]] = match["id"]
    # make mirror involutive for the merged ones
    for nd in nodes:
        mir.setdefault(nd["id"], nd["id"])

    nid = {nd["id"]: nd for nd in nodes}

    # --- edges: forward paths, then M / R / MR transforms ----------------
    edges = []

    def add(src, dst, clip, tf, disp):
        edges.append({"src": src, "dst": dst, "clip": clip, "tf": tf,
                      "disp": [round(disp[0], 4), round(disp[1], 4)]})

    for act in track["actions"]:
        seq = [kf for kf in kfs if kf["clip"] == act["name"]]
        seq.sort(key=lambda k: k["k"])
        for u, v in zip(seq, seq[1:]):
            d = [v["cx"]-u["cx"], v["cy"]-u["cy"]]
            # I — forward
            add(u["node"], v["node"], act["name"], "I", d)
            # R — negative time (reverse the step)
            add(v["node"], u["node"], act["name"], "R", [-d[0], -d[1]])
            # M — mirror (flip horizontal motion)
            add(mir[u["node"]], mir[v["node"]], act["name"], "M", [-d[0], d[1]])
            # MR — mirror + reverse
            add(mir[v["node"]], mir[u["node"]], act["name"], "MR", [d[0], -d[1]])

    graph = {
        "source": track["source"], "transform_group": ["I", "M", "R", "MR"],
        "nodes": [{"id": n["id"], "rep": n["rep"], "cx": round(n["cx"], 3),
                   "mirror_of": n["mirror_of"]} for n in nodes],
        "mirror": mir,
        "edges": edges,
    }
    json.dump(graph, open(os.path.join(WORK, "graph.json"), "w"), indent=1)

    # --- visualise -------------------------------------------------------
    _draw(nodes, edges, nid)

    n_orig = sum(1 for n in nodes if n["mirror_of"] is None)
    print(f"key frames: {len(kfs)}")
    print(f"pose nodes: {len(nodes)}  ({n_orig} original + {len(nodes)-n_orig} mirror)")
    by = {}
    for e in edges:
        by[e["tf"]] = by.get(e["tf"], 0) + 1
    print("edges by transform:", by, " total", len(edges))
    print("wrote graph.json, graph.png under", WORK)


def _draw(nodes, edges, nid):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch

    N = len(nodes)
    pos = {}
    for i, nd in enumerate(nodes):
        ang = 2*math.pi*i/N
        pos[nd["id"]] = (math.cos(ang), math.sin(ang))

    fig, ax = plt.subplots(figsize=(13, 13), facecolor="#12161f")
    ax.set_facecolor("#12161f")
    col = {"I": "#7fb8ff", "M": "#73d0a4", "R": "#f0a85a", "MR": "#c08ad1"}
    rad = {"I": 0.08, "M": 0.14, "R": -0.08, "MR": -0.14}
    for e in edges:
        x0, y0 = pos[e["src"]]; x1, y1 = pos[e["dst"]]
        if e["src"] == e["dst"]:
            continue
        ax.add_patch(FancyArrowPatch(
            (x0, y0), (x1, y1), connectionstyle="arc3,rad=%.2f" % rad[e["tf"]],
            arrowstyle="-|>", mutation_scale=8, lw=0.8,
            color=col[e["tf"]], alpha=0.55, zorder=1))
    # node pose thumbnails
    for nd in nodes:
        x, y = pos[nd["id"]]
        im = Image.open(os.path.join(FR, nd["rep"])).convert("RGBA")
        bg = Image.new("RGBA", im.size, (28, 32, 48, 255)); bg.alpha_composite(im)
        th = bg.convert("RGB"); th.thumbnail((58, 84))
        ax.imshow(th, extent=(x-0.06, x+0.06, y-0.085, y+0.085), zorder=3)
        edgecol = "#888" if nd["mirror_of"] is None else "#73d0a4"
        ax.text(x, y-0.10, nd["id"], color=edgecol, fontsize=6,
                ha="center", va="top", zorder=4)
    from matplotlib.lines import Line2D
    leg = [Line2D([0], [0], color=col[t], lw=2,
                  label={"I": "I — forward", "M": "M — mirror",
                         "R": "R — reverse", "MR": "MR — mirror+reverse"}[t])
           for t in ("I", "M", "R", "MR")]
    ax.legend(handles=leg, loc="upper left", facecolor="#12161f",
              edgecolor="#444", labelcolor="#ddd", fontsize=9)
    ax.set_xlim(-1.25, 1.25); ax.set_ylim(-1.25, 1.25)
    ax.set_aspect("equal"); ax.axis("off")
    ax.set_title("Cavin motion graph — V4 transform group {I, M, R, MR}",
                 color="#ddd", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(WORK, "graph.png"), dpi=130, facecolor="#12161f")


if __name__ == "__main__":
    main()
