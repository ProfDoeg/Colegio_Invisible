#!/usr/bin/env python3
"""Stage 1.5 — clean the key frames and record precise centroids.

For every key frame in track.json: re-extract it at native resolution, keep
only the LARGEST connected alpha component (drops the foot-shadow blob and
fringe specks), compute the centroid from the cleaned full-resolution alpha
(sub-pixel, in original-frame normalised coords), re-crop to the cleaned
bbox, downsample, and overwrite frames/. Then recompute per-action
displacements from the precise centroids and rewrite track.json.

Run:  .venv/bin/python working/dancer/cavin_clean.py
"""
import os
import json
import math
import subprocess

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.expanduser("~/Desktop/cavin_clean_png.mov")
WORK = os.path.join(HERE, "cavin")
FR = os.path.join(WORK, "frames")
NAT = os.path.join(WORK, "native")        # native-res key frames
os.makedirs(NAT, exist_ok=True)

ATHRESH = 24
SPRITE_H = 144


def largest_component(mask):
    """Boolean mask of the largest 4-connected component (flood fill)."""
    H, W = mask.shape
    seen = np.zeros_like(mask, dtype=bool)
    best = None
    best_n = 0
    ys, xs = np.nonzero(mask)
    for sy, sx in zip(ys, xs):
        if seen[sy, sx]:
            continue
        stack = [(sy, sx)]
        seen[sy, sx] = True
        comp = []
        while stack:
            y, x = stack.pop()
            comp.append((y, x))
            for dy, dx in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                ny, nx = y+dy, x+dx
                if 0 <= ny < H and 0 <= nx < W and mask[ny, nx] and not seen[ny, nx]:
                    seen[ny, nx] = True
                    stack.append((ny, nx))
        if len(comp) > best_n:
            best_n = len(comp)
            best = comp
    out = np.zeros_like(mask, dtype=bool)
    if best:
        ys2, xs2 = zip(*best)
        out[list(ys2), list(xs2)] = True
    return out


def extract_native(indices):
    """Extract the given frame indices at native res (RGBA) into NAT/."""
    have = {int(f[2:6]) for f in os.listdir(NAT) if f.startswith("n_")}
    need = [i for i in indices if i not in have]
    if not need:
        return
    sel = "+".join("eq(n\\,%d)" % i for i in need)
    # -vframes via -frames:v after select; output numbered in selection order,
    # so map outputs back to indices afterward.
    tmp = os.path.join(NAT, "_tmp")
    os.makedirs(tmp, exist_ok=True)
    subprocess.run(
        ["/usr/local/bin/ffmpeg", "-v", "error", "-i", SRC,
         "-vf", "select='%s',format=rgba" % sel, "-vsync", "0",
         os.path.join(tmp, "o_%03d.png")], check=True)
    outs = sorted(f for f in os.listdir(tmp) if f.startswith("o_"))
    for f, idx in zip(outs, sorted(need)):
        os.replace(os.path.join(tmp, f), os.path.join(NAT, "n_%04d.png" % idx))
    os.rmdir(tmp)


def clean_frame(idx):
    """Return (cleaned RGBA crop @SPRITE_H, centroid (cx,cy) in frame fracs)."""
    im = Image.open(os.path.join(NAT, "n_%04d.png" % idx)).convert("RGBA")
    arr = np.array(im)
    H, W = arr.shape[:2]
    alpha = arr[:, :, 3]
    op = alpha > ATHRESH
    # Ground-shadow removal: a warm-toned smear connected to the feet at the
    # very bottom. Drop warm, dim, non-blue opaque pixels in the bottom ~14%
    # of the figure's height (the foot band); the boots are blue (B≥R) and
    # survive. Then keep the largest connected component to clear any residue.
    ys = np.nonzero(op.any(1))[0]
    if len(ys):
        top, bot = ys.min(), ys.max()
        band = top + 0.86 * (bot - top)
        r = arr[:, :, 0].astype(int); g = arr[:, :, 1].astype(int)
        b = arr[:, :, 2].astype(int)
        mx = np.maximum(np.maximum(r, g), b)
        rows = np.arange(H)[:, None]
        shadow = op & (rows > band) & (mx < 170) & (r >= b - 5) & (b < r + 40)
        op = op & ~shadow
    keep = largest_component(op)
    arr[~keep, 3] = 0                                   # zero stray alpha
    a = arr[:, :, 3].astype(np.float64)
    tot = a.sum()
    ys, xs = np.mgrid[0:H, 0:W]
    cx = float((xs*a).sum()/tot)/W if tot else 0.5      # precise, alpha-weighted
    cy = float((ys*a).sum()/tot)/H if tot else 0.5
    # crop to cleaned bbox, with HEADROOM above (and a little at the sides) so
    # the crown isn't flush to the top edge and a render-time feather can bloom
    # the rim-lit hair into the margin as a soft halo. The added rows are
    # transparent — ~1 bit/pixel via the mask, negligible on chain.
    yy, xx = np.nonzero(keep)
    x0, y0, x1, y1 = xx.min(), yy.min(), xx.max()+1, yy.max()+1
    bw, bh = x1-x0, y1-y0
    m_top = int(0.16 * bh)
    m_side = int(0.05 * bw)
    bb = (max(0, x0-m_side), max(0, y0-m_top),
          min(W, x1+m_side), min(H, y1))
    cr = Image.fromarray(arr).crop(bb)
    s = SPRITE_H / cr.height
    cr = cr.resize((max(1, round(cr.width*s)), SPRITE_H), Image.LANCZOS)
    return cr, (round(cx, 5), round(cy, 5))


def main():
    track = json.load(open(os.path.join(WORK, "track.json")))
    idxs = sorted({fr["src_frame"] for a in track["actions"] for fr in a["frames"]})
    print(f"key frames to clean: {len(idxs)}  (extracting native res…)")
    extract_native(idxs)

    blob_before = None
    for a in track["actions"]:
        prev = None
        for fr in sorted(a["frames"], key=lambda f: f["src_frame"]):
            k = fr["src_frame"]
            cr, (cx, cy) = clean_frame(k)
            outp = os.path.join(FR, "%s_%04d.png" % (a["name"], k))
            if a["name"] == track["actions"][0]["name"] and prev is None:
                blob_before = outp           # remember the first (blobby) one
            cr.save(outp)
            fr["centroid"] = [cx, cy]
            fr["w"], fr["h"] = cr.width, cr.height
            fr["displacement"] = [0.0, 0.0] if prev is None else \
                [round(cx-prev[0], 5), round(cy-prev[1], 5)]
            prev = (cx, cy)

    track["centroids"] = "precise (native-res alpha-weighted)"
    track["matte"] = "largest-connected-component"
    json.dump(track, open(os.path.join(WORK, "track.json"), "w"), indent=1)

    # before/after montage of the first action's first frame (the blob one)
    if blob_before:
        after = Image.open(blob_before).convert("RGBA")
        comp = Image.new("RGB", (after.width*2+30, after.height), (18, 22, 38))
        bg = Image.new("RGBA", after.size, (18, 22, 38, 255)); bg.alpha_composite(after)
        comp.paste(bg.convert("RGB"), (after.width+30, 0))
        comp.save(os.path.join(WORK, "clean_after.png"))

    print("cleaned + precise centroids written to frames/ and track.json")
    print("sample precise centroids (action_01):")
    for fr in track["actions"][0]["frames"][:5]:
        print("  frame %4d  centroid=%s  disp=%s"
              % (fr["src_frame"], fr["centroid"], fr["displacement"]))


if __name__ == "__main__":
    main()
