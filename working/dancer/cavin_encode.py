#!/usr/bin/env python3
"""Stage 3 prototype — encode the real Cavin dancer as a 0xda performance.

Loads the cleaned key frames + track.json, downsamples to the budget height,
builds a shared palette, sparse-palette-encodes every frame, builds the
control graph in the {stay/forward/backward/tunnel} + features formulation,
and calls build_dancer_performance. Then: inscribe locally, read it back,
reconstruct a frame from the decoded sparse bytes (proving the codec), and
report the on-chain size.

Run:  .venv/bin/python working/dancer/cavin_encode.py
"""
import os
import sys
import json
import math

import numpy as np
from PIL import Image

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import colegio_pipeline as P
from dancer import (build_dancer_performance, read_dancer,
                    FACE_FRONT, OP_FORWARD, OP_BACKWARD, OP_TUNNEL,
                    LABEL_IDLE, LABEL_STEP, LABEL_GESTURE, TONE_REVERENCE)

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "cavin")
FR = os.path.join(WORK, "frames")

SPRITE_H = 96            # budget height
PALETTE_N = 16          # shared palette colours
ATHRESH = 24
THRESH = 0.16           # tunnel if centroid-aligned colour distance below this
CMP_W, CMP_H = 44, 72   # registration canvas for the appearance metric


def load_frames():
    """Returns ordered list of {action,key,img(RGBA @SPRITE_H),cx,cy} + per-action
    index ranges into that list."""
    track = json.load(open(os.path.join(WORK, "track.json")))
    items = []
    actions = []
    for a in track["actions"]:
        rng = []
        for fr in sorted(a["frames"], key=lambda f: f["src_frame"]):
            p = os.path.join(FR, "%s_%04d.png" % (a["name"], fr["src_frame"]))
            if not os.path.exists(p):
                continue
            im = Image.open(p).convert("RGBA")
            s = SPRITE_H / im.height
            im = im.resize((max(1, round(im.width*s)), SPRITE_H), Image.LANCZOS)
            rng.append(len(items))
            items.append({"action": a["name"], "key": fr["src_frame"], "img": im,
                          "cx": fr["centroid"][0], "cy": fr["centroid"][1]})
        if rng:
            actions.append({"name": a["name"], "idx": rng})
    return items, actions


def build_palette(items):
    """16-colour median-cut palette over every opaque pixel of every frame."""
    cols = []
    for it in items:
        a = np.array(it["img"])
        op = a[:, :, 3] > ATHRESH
        cols.append(a[:, :, :3][op])
    allpx = np.concatenate(cols, 0)
    strip = Image.fromarray(allpx.reshape(1, -1, 3).astype(np.uint8))
    pal_img = strip.quantize(colors=PALETTE_N, method=Image.MEDIANCUT)
    raw = pal_img.getpalette()[:PALETTE_N*3]
    palette = [(raw[i*3], raw[i*3+1], raw[i*3+2]) for i in range(PALETTE_N)]
    return palette, np.array(palette, dtype=np.int32)


def encode_frame(im, pal_arr):
    """Sparse-palette encode one RGBA crop -> dancer frame dict."""
    a = np.array(im)
    h, w = a.shape[:2]
    op = a[:, :, 3] > ATHRESH
    mask = op.astype(np.uint8).reshape(-1).tolist()
    rgb = a[:, :, :3][op].astype(np.int32)          # opaque pixels, raster order
    # nearest palette index per opaque pixel
    d = ((rgb[:, None, :] - pal_arr[None, :, :]) ** 2).sum(2)
    idx = d.argmin(1).astype(int).tolist()
    return w, h, mask, idx


def appearance(im):
    """Centroid-registered RGBA descriptor on a CMP_W×CMP_H canvas (the colour
    blocks she wears distinguish front from back, so no silhouette ambiguity)."""
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


def appdist(A, B):
    """0 = identical appearance, ~1 = wholly different. Colour diff where both
    opaque; full penalty where exactly one is opaque. No velocity term — the
    avatar plays discrete pose-to-pose and can reverse time."""
    aA = A[:, :, 3] > ATHRESH; aB = B[:, :, 3] > ATHRESH
    both = aA & aB; either = aA | aB
    n = int(either.sum())
    if n == 0:
        return 1.0
    cd = np.abs(A[:, :, :3][both] - B[:, :, :3][both]).sum() / (255*3)
    mism = int((either & ~both).sum())
    return float((cd + mism) / n)


def build_cavin():
    """Encode Cavin into a 0xda performance. Returns (hdr, body, palette,
    frames, nodes, edges, actions, items, item_node).

    Two structural moves over the naive encode:
      * exact dedup — adjacent actions share their boundary key frame, so the
        same source frame is otherwise inscribed twice; map every occurrence of
        a src_frame to ONE node and inscribe its pixels once (lossless).
      * colour-metric tunnels — centroid-aligned full-character RGB distance,
        all unique-pose pairs below THRESH (not just action ends→starts)."""
    items, actions = load_frames()

    # ---- exact dedup: one node per unique source frame -----------------
    uniq = {}                       # src_frame -> node id
    node_items = []                 # representative item per node
    item_node = []                  # per loaded item -> node id
    for it in items:
        k = it["key"]
        if k not in uniq:
            uniq[k] = len(node_items)
            node_items.append(it)
        item_node.append(uniq[k])
    N = len(node_items)

    palette, pal_arr = build_palette(node_items)
    frames = []
    for it in node_items:
        w, h, mask, idx = encode_frame(it["img"], pal_arr)
        frames.append({"w": w, "h": h, "cx": it["cx"], "cy": it["cy"],
                       "facing": FACE_FRONT, "mask": mask, "idx": idx})
    nodes = list(range(N))
    desc = [appearance(it["img"]) for it in node_items]

    def label(dx, sim):
        if abs(dx) >= 0.06:
            return LABEL_STEP
        return LABEL_IDLE if (abs(dx) < 0.02 and sim < 0.10) else LABEL_GESTURE

    # ---- recorded forward steps (deduped node ids), + their reverses ----
    edges = []
    adj = set()
    seen = set()
    for act in actions:
        seq = [item_node[i] for i in act["idx"]]
        for u, v in zip(seq, seq[1:]):
            if u == v or (u, v) in seen:        # boundary self-collapse / dup
                continue
            seen.add((u, v))
            adj.add((min(u, v), max(u, v)))
            dx = node_items[v]["cx"] - node_items[u]["cx"]
            dy = node_items[v]["cy"] - node_items[u]["cy"]
            lab = label(dx, appdist(desc[u], desc[v]))
            edges.append({"src": u, "dst": v, "op": OP_FORWARD, "span": (u, v),
                          "dx": dx, "dy": dy, "facing_delta": 0, "label": lab})
            edges.append({"src": v, "dst": u, "op": OP_BACKWARD, "span": (v, u),
                          "dx": -dx, "dy": -dy, "facing_delta": 0, "label": lab})

    # ---- tunnels: every non-adjacent unique-pose pair below THRESH ------
    tuns = []
    for i in range(N):
        for j in range(i+1, N):
            if (i, j) in adj:
                continue
            d = appdist(desc[i], desc[j])
            if d < THRESH:
                tuns.append((d, i, j))
    tuns.sort()
    for d, i, j in tuns:
        dx = node_items[j]["cx"] - node_items[i]["cx"]
        dy = node_items[j]["cy"] - node_items[i]["cy"]
        edges.append({"src": i, "dst": j, "op": OP_TUNNEL, "span": (i, j),
                      "dx": dx, "dy": dy, "facing_delta": 0, "label": LABEL_GESTURE})
        edges.append({"src": j, "dst": i, "op": OP_TUNNEL, "span": (j, i),
                      "dx": -dx, "dy": -dy, "facing_delta": 0, "label": LABEL_GESTURE})

    # remap action sequences onto deduped node ids (shared boundary frames now
    # collapse to one node — exactly the continuity we want)
    d_actions = [{"name": a["name"], "idx": [item_node[i] for i in a["idx"]]}
                 for a in actions]

    hdr, body = build_dancer_performance(
        "Cavin", palette, frames, nodes, edges, tone=TONE_REVERENCE)
    return (hdr, body, palette, frames, nodes, edges, d_actions, node_items,
            item_node, len(items))


def main():
    (hdr, body, palette, frames, nodes, edges, actions, items,
     item_node, n_loaded) = build_cavin()
    print(f"loaded key frames: {n_loaded}  ->  unique poses (exact dedup): "
          f"{len(items)}  ({n_loaded-len(items)} shared boundaries collapsed)")
    print(f"palette: {PALETTE_N} colours @ {SPRITE_H}px")
    txid = P.write_inscription(hdr, body)
    total = len(hdr) + len(body)
    strands = math.ceil(total / 80)
    print(f"\n0xda performance inscribed (local): {txid[:16]}…")
    print(f"  header {len(hdr)}B  body {len(body)}B  total {total/1024:.1f} KB")
    print(f"  nodes {len(nodes)}  edges {len(edges)}  "
          f"(fwd/back/tunnel split: "
          f"{sum(1 for e in edges if e['op']==OP_FORWARD)}/"
          f"{sum(1 for e in edges if e['op']==OP_BACKWARD)}/"
          f"{sum(1 for e in edges if e['op']==OP_TUNNEL)})")
    print(f"  ~{strands} knots ≈ {strands*0.05:.1f} DOGE")

    # ---- round-trip + reconstruct a frame ------------------------------
    dec = read_dancer(hdr, body)
    assert dec["variant_name"] == "performance"
    assert dec["footage"]["palette"] == palette
    assert len(dec["footage"]["frames"]) == len(frames)
    # reconstruct frame 0 from the DECODED sparse bytes
    df = dec["footage"]["frames"][0]
    w, h = df["w"], df["h"]
    img = np.zeros((h, w, 4), dtype=np.uint8)
    op = np.array(df["mask"], dtype=bool).reshape(h, w)
    ys, xs = np.nonzero(op)
    palnp = np.array(dec["footage"]["palette"], dtype=np.uint8)
    for (y, x, pi) in zip(ys, xs, df["idx"]):
        img[y, x, :3] = palnp[pi]; img[y, x, 3] = 255
    # verify it equals the palette-mapped source
    pal_arr = np.array(palette, dtype=np.int32)
    src_w, src_h, src_mask, src_idx = encode_frame(items[0]["img"], pal_arr)
    assert (src_w, src_h) == (w, h) and src_mask == df["mask"] and src_idx == df["idx"]
    bg = Image.new("RGBA", (w, h), (20, 24, 40, 255))
    bg.alpha_composite(Image.fromarray(img))
    bg.convert("RGB").resize((w*3, h*3)).save(os.path.join(WORK, "decoded_frame0.png"))
    print("\nround-trip OK — decoded frame 0 matches source exactly")
    print("wrote decoded_frame0.png")


if __name__ == "__main__":
    main()
