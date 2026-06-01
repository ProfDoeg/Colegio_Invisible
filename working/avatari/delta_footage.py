#!/usr/bin/env python3
"""Measure inter-frame DELTA coding of Jeremy's footage against the sparse
baseline. The 2374 frames are one continuous recording, so frame i is nearly
identical to frame i-1; we encode each frame as the pixels that changed in
notional-frame coordinates.

State per pixel = -1 (transparent) or palette index 0..PALN-1.
A pixel "changed" iff its state differs from the previous frame.

Per-frame delta encoding (bytes):
   8                      bbox of changed region (x,y,w,h uint16)
   ceil(bw*bh/8)          1-bit "changed" mask within bbox
   ceil(Nchg/8)           new alpha bit per changed pixel
   ceil(Nopq*5/8)         new 5-bit index per changed pixel that is now opaque
A frame is stored as a KEYFRAME (full sparse sprite) whenever that is smaller,
and additionally every KEY frames so playback has random access.

Run:  RH=128 KEY=30 .venv/bin/python working/avatari/delta_footage.py
"""
import os, sys, json, math
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
FR   = os.path.join(HERE, "_frames_jeremy")
RH   = int(os.environ.get("RH", "128"))
PALN = int(os.environ.get("PALN", "32"))
ALPHA= int(os.environ.get("ALPHA", "100"))
KEY  = int(os.environ.get("KEY", "30"))
STEP = int(os.environ.get("STEP", "1"))          # 1 = 30 fps, 2 = 15 fps
IB   = max(1, math.ceil(math.log2(PALN)))


def sprite_cost(S):
    """Full sparse-sprite bytes for a notional-frame state S (keyframe)."""
    op = S >= 0
    ys, xs = np.where(op)
    if len(xs) == 0:
        return 8 + 1
    bw, bh = int(xs.max()-xs.min()+1), int(ys.max()-ys.min()+1)
    nopq = int(op.sum())
    return 8 + math.ceil(bw*bh/8) + math.ceil(nopq*IB/8)


def delta_cost(S, P):
    """Delta bytes to turn previous state P into current S, plus changed count."""
    chg = S != P
    n = int(chg.sum())
    if n == 0:
        return 8, 0
    ys, xs = np.where(chg)
    bw, bh = int(xs.max()-xs.min()+1), int(ys.max()-ys.min()+1)
    nopq = int((S[chg] >= 0).sum())
    cost = 8 + math.ceil(bw*bh/8) + math.ceil(n/8) + math.ceil(nopq*IB/8)
    return cost, n


def main():
    files = sorted(f for f in os.listdir(FR) if f.startswith("f_"))[::STEP]
    nF = len(files)
    sw0, sh0 = Image.open(os.path.join(FR, files[0])).size
    RW = round(RH * sw0 / sh0)

    # shared palette (same recipe as compress_footage)
    samp = []
    for k in range(0, nF, 30):
        im = Image.open(os.path.join(FR, files[k])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]; rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
        if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
    samp = np.concatenate(samp, 0)
    master = Image.fromarray(samp.reshape(-1, 1, 3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)

    def state(fn):
        im = Image.open(os.path.join(FR, fn)).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]
        q = np.asarray(im.convert("RGB").quantize(palette=master, dither=Image.Dither.NONE)).astype(np.int16)
        return np.where(a > ALPHA, q, -1)

    base = 96                       # palette (32 x 3 bytes)
    sparse_total = base
    delta_cut = base                # delta, keyframe only when smaller (+frame0)
    delta_key = base                # delta + forced keyframe every KEY
    changed = []
    nkey_cut = nkey_period = 0

    P = None
    for i, fn in enumerate(files):
        S = state(fn)
        sc = sprite_cost(S)
        sparse_total += sc
        if P is None:
            delta_cut += sc; delta_key += sc; nkey_cut += 1; nkey_period += 1
        else:
            dc, n = delta_cost(S, P); changed.append(n)
            # variant (b): keyframe only when delta is the bigger option
            if dc < sc: delta_cut += dc
            else:       delta_cut += sc; nkey_cut += 1
            # variant (c): also force a keyframe every KEY frames (random access)
            if i % KEY == 0:
                delta_key += sc; nkey_period += 1
            elif dc < sc: delta_key += dc
            else:         delta_key += sc; nkey_period += 1
        P = S
        if i % 400 == 0: print("  ...frame", i)

    ch = np.array(changed)
    def line(tag, b):
        kn = math.ceil(b/80); return "%-28s %7.2f MB   ~%6d knots  ~%5.0f DOGE" % (
            tag, b/1e6, kn, (kn+2)*0.05)
    px = RW*RH
    print("\nnotional %dx%d = %d px   palette %d (%d-bit idx)   1-bit alpha   frames %d" % (RW,RH,px,PALN,IB,nF))
    print("changed px/frame:  mean %.0f  median %.0f  max %d   (%.1f%% of frame avg)"
          % (ch.mean(), np.median(ch), ch.max(), 100*ch.mean()/px))
    print()
    print(line("(a) sparse baseline", sparse_total))
    print(line("(b) delta, keyframe-on-cut", delta_cut), "  keyframes %d" % nkey_cut)
    print(line("(c) delta + keyframe/%d" % KEY, delta_key), "  keyframes %d" % nkey_period)
    print("\nreduction:  (b) %.1fx   (c) %.1fx   vs baseline" %
          (sparse_total/delta_cut, sparse_total/delta_key))


if __name__ == "__main__":
    main()
