#!/usr/bin/env python3
"""Tunnel detection by centroid-aligned, full-character colour difference.

For each pose, register the figure on a fixed canvas by its alpha centroid,
then compare two poses over the whole body using actual RGB — so the colour
blocks (grey sweater, dark trousers, blue boots, skin vs hair at the head)
distinguish front from back, killing the silhouette ambiguity. No velocity
term: the avatar plays discrete pose-to-pose and can reverse time, so smooth-
motion continuity is irrelevant — only appearance match matters for a seamless
cut.

Renders the best matched pairs side by side (with distance) so the matches can
be eyeballed before they go in the graph.

Run:  .venv/bin/python working/dancer/cavin_tunnels.py
"""
import os
import sys

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from cavin_encode import load_frames

CMP_W, CMP_H = 44, 72
ATHRESH = 24
THRESH = 0.16            # tunnel if appearance distance below this


def appearance(im):
    """Centroid-registered RGBA descriptor on a CMP_W×CMP_H canvas."""
    s = CMP_H / im.height
    im = im.resize((max(1, round(im.width*s)), CMP_H), Image.LANCZOS)
    a = np.array(im).astype(np.float32)
    al = a[:, :, 3] > ATHRESH
    ys, xs = np.nonzero(al)
    canvas = np.zeros((CMP_H, CMP_W, 4), np.float32)
    if len(xs) == 0:
        return canvas
    ccx, ccy = xs.mean(), ys.mean()
    ox = int(round(CMP_W/2 - ccx)); oy = int(round(CMP_H/2 - ccy))
    H0, W0 = a.shape[:2]
    sy0, sy1 = max(0, -oy), min(H0, CMP_H-oy)
    sx0, sx1 = max(0, -ox), min(W0, CMP_W-ox)
    if sy1 > sy0 and sx1 > sx0:
        canvas[sy0+oy:sy1+oy, sx0+ox:sx1+ox] = a[sy0:sy1, sx0:sx1]
    return canvas


def dist(A, B):
    """0 = identical appearance, ~1 = wholly different. Colour diff where both
    opaque; full penalty where one is opaque and the other isn't."""
    aA = A[:, :, 3] > ATHRESH; aB = B[:, :, 3] > ATHRESH
    both = aA & aB; either = aA | aB
    n = int(either.sum())
    if n == 0:
        return 1.0
    cd = np.abs(A[:, :, :3][both] - B[:, :, :3][both]).sum() / (255*3)
    mism = int((either & ~both).sum())
    return float((cd + mism) / n)


def main():
    items, actions = load_frames()
    desc = [appearance(it["img"]) for it in items]
    n = len(items)
    # adjacency within an action (the recorded forward steps) — never a tunnel
    adj = set()
    for a in actions:
        for u, v in zip(a["idx"], a["idx"][1:]):
            adj.add((min(u, v), max(u, v)))
    action_of = {i: a["name"] for a in actions for i in a["idx"]}

    # how many key frames are literal duplicates (shared action boundaries)?
    by_src = {}
    for k, it in enumerate(items):
        by_src.setdefault(it["key"], []).append(k)
    dups = sum(len(v)-1 for v in by_src.values() if len(v) > 1)
    print(f"key frames {n}: {len(by_src)} unique source frames, {dups} duplicates "
          f"(shared action boundaries)")

    pairs = []
    for i in range(n):
        for j in range(i+1, n):
            if items[i]["key"] == items[j]["key"]:
                continue                    # SAME source frame — not a tunnel
            if (i, j) in adj:
                continue
            d = dist(desc[i], desc[j])
            pairs.append((d, i, j))
    pairs.sort()

    tunnels = [(d, i, j) for d, i, j in pairs if d < THRESH]
    print(f"poses {n}   cross-action candidate pairs {len(pairs)}")
    print(f"tunnels below {THRESH}: {len(tunnels)}")
    print("distance distribution: best %.3f  median %.3f  @thresh #%d"
          % (pairs[0][0], pairs[len(pairs)//2][0], len(tunnels)))

    # validation strip: best 12 matched pairs, side by side
    show = (tunnels or pairs)[:12]
    cw, ch = 120, 150
    cols = 4
    import math
    rows = math.ceil(len(show)/cols)
    sheet = Image.new("RGB", (cols*(cw*2+16), rows*(ch+22)), (10, 12, 20))
    from PIL import ImageDraw
    d = ImageDraw.Draw(sheet)

    def cell(idx):
        im = items[idx]["img"].convert("RGBA")
        s = (ch-10)/im.height
        im = im.resize((max(1, round(im.width*s)), ch-10), Image.LANCZOS)
        c = Image.new("RGBA", (cw, ch), (22, 26, 40, 255))
        c.alpha_composite(im, ((cw-im.width)//2, 6))
        return c.convert("RGB")

    for k, (dd, i, j) in enumerate(show):
        bx = (k % cols)*(cw*2+16); by = (k//cols)*(ch+22)
        sheet.paste(cell(i), (bx, by+18))
        sheet.paste(cell(j), (bx+cw, by+18))
        d.text((bx+4, by+2), "d=%.3f  %s|%s" % (dd, action_of[i][7:], action_of[j][7:]),
               fill=(225, 227, 238))
    sheet.save(os.path.join(HERE, "cavin", "tunnel_matches.png"))
    print("wrote tunnel_matches.png")


if __name__ == "__main__":
    main()
