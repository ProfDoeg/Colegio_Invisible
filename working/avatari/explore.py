#!/usr/bin/env python3
"""Ground the avatar structure in the actual 2009 footage.

Reads a character's crumb tags (nodes = named poses @ frames) and its map
(edges), pulls the tagged frames out of the PNG-alpha movie, and lays them
out labelled — so the NODES are visible as real poses and the frame-numbering
is confirmed against pixels. Also prints each node's alpha-centroid x so the
"displacement is the meaning" claim is checkable (does she cross the stage?).

No inscription here — this is structural verification only.

Run:  .venv/bin/python working/avatari/explore.py
"""
import os
import re
import subprocess
import tempfile
import shutil

import numpy as np
from PIL import Image, ImageDraw

SRCDIR = os.path.expanduser("~/Documents/avatari")
HERE = os.path.dirname(os.path.abspath(__file__))
FFMPEG = "/usr/local/bin/ffmpeg"
ATHRESH = 24

# (character, movie, crumbs file, map file)
CHAR = ("caity", "caity1png.mov", "caity_super_pcrumbs.txt", "caity_map.txt")


def parse_crumbs(path):
    """`id, label variant frame;` -> list of dict (in file order)."""
    out = []
    for line in open(path):
        line = line.strip().rstrip(";").strip()
        if not line:
            continue
        m = re.match(r"(\d+)\s*,\s*(\w+)\s+(\d+)\s+(\d+)", line)
        if m:
            out.append({"id": int(m.group(1)), "label": m.group(2),
                        "variant": int(m.group(3)), "frame": int(m.group(4))})
    return out


def parse_map(path):
    """`F, control ... frames ... time ... space ... weight ...;` -> dict
    keyed by source frame, each a list of edge dicts."""
    g = {}
    for line in open(path):
        line = line.strip().rstrip(";").strip()
        if not line:
            continue
        head, _, rest = line.partition(",")
        src = int(head.strip())
        toks = rest.split()
        cols = {}
        cur = None
        for t in toks:
            if t in ("control", "frames", "time", "space", "weight"):
                cur = t; cols[cur] = []
            else:
                cols[cur].append(int(t))
        edges = []
        n = len(cols.get("frames", []))
        for i in range(n):
            edges.append({"dst": cols["frames"][i], "control": cols["control"][i],
                          "time": cols["time"][i], "space": cols["space"][i],
                          "weight": cols["weight"][i]})
        g[src] = edges
    return g


def extract_frames(movie, frames):
    """Pull the given native frame indices out of the movie as RGBA pngs.
    Returns {frame_index: PIL.Image}."""
    frames = sorted(set(frames))
    sel = "+".join("eq(n\\,%d)" % f for f in frames)
    tmp = tempfile.mkdtemp(prefix="avx_")
    subprocess.run(
        [FFMPEG, "-v", "error", "-i", os.path.join(SRCDIR, movie),
         "-vf", "select='%s',format=rgba" % sel, "-vsync", "0",
         os.path.join(tmp, "o_%04d.png")], check=True)
    outs = sorted(f for f in os.listdir(tmp) if f.startswith("o_"))
    res = {}
    for f, idx in zip(outs, frames):
        res[idx] = Image.open(os.path.join(tmp, f)).convert("RGBA").copy()
    shutil.rmtree(tmp, ignore_errors=True)
    return res


def centroid_x(im):
    a = np.array(im)[:, :, 3].astype(np.float64)
    tot = a.sum()
    if tot == 0:
        return 0.5
    xs = np.arange(a.shape[1])[None, :]
    return float((xs * a).sum() / tot) / a.shape[1]


def main():
    name, movie, crumbf, mapf = CHAR
    crumbs = parse_crumbs(os.path.join(SRCDIR, crumbf))
    graph = parse_map(os.path.join(SRCDIR, mapf))
    print("%s: %d crumb nodes, %d map source-frames" % (name, len(crumbs), len(graph)))
    labels = {}
    for c in crumbs:
        labels.setdefault(c["label"], 0)
        labels[c["label"]] += 1
    print("pose vocabulary:", dict(labels))

    # are the crumb frames exactly the map's source frames?
    cf = {c["frame"] for c in crumbs}
    mf = set(graph)
    print("crumb frames that are map nodes: %d/%d   map nodes not tagged: %d"
          % (len(cf & mf), len(cf), len(mf - cf)))

    imgs = extract_frames(movie, [c["frame"] for c in crumbs])

    # centroid x per node (does she traverse the stage?)
    print("\nnode centroid-x (stage position, 0=left 1=right):")
    for c in crumbs:
        cx = centroid_x(imgs[c["frame"]])
        c["cx"] = cx
    xs = [c["cx"] for c in crumbs]
    print("  range %.2f .. %.2f  (spread %.2f of stage width)"
          % (min(xs), max(xs), max(xs) - min(xs)))

    # labelled pose board
    cols = 8
    cw, ch = 150, 150
    rows = (len(crumbs) + cols - 1) // cols
    board = Image.new("RGB", (cols * cw, rows * (ch + 26)), (14, 16, 24))
    d = ImageDraw.Draw(board)
    for k, c in enumerate(crumbs):
        im = imgs[c["frame"]]
        s = (ch - 8) / im.height
        im = im.resize((max(1, round(im.width * s)), ch - 8), Image.LANCZOS)
        bx = (k % cols) * cw
        by = (k // cols) * (ch + 26)
        cell = Image.new("RGBA", (cw, ch), (26, 30, 44, 255))
        cell.alpha_composite(im, ((cw - im.width) // 2, 20))
        board.paste(cell.convert("RGB"), (bx, by))
        d.text((bx + 4, by + 2), "%d %s.%d" % (c["id"], c["label"], c["variant"]),
               fill=(228, 230, 240))
        d.text((bx + 4, by + ch + 2), "f%d  x=%.2f" % (c["frame"], c["cx"]),
               fill=(150, 200, 160))
    out = os.path.join(HERE, "%s_poseboard.png" % name)
    board.save(out)
    print("\nwrote", os.path.relpath(out, os.path.expanduser("~")))

    # sample one node's outgoing edges to show the graph structure
    sample = crumbs[6]["frame"]            # low_a @836
    print("\noutgoing edges from frame %d (%s):" % (sample, crumbs[6]["label"]))
    for e in graph.get(sample, [])[:10]:
        td = "fwd" if e["time"] == 1 else "rev"
        print("  -> f%-5d  ctrl=%d  %s  space=%d  w=%d"
              % (e["dst"], e["control"], td, e["space"], e["weight"]))


if __name__ == "__main__":
    main()
