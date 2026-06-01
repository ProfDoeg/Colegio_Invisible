#!/usr/bin/env python3
"""Cost of a short GESTURE CLIP (a few seconds) inscribed as its own 0x02
footage diamond, in the locked profile (16-color, 128px, 30fps, delta).

Each clip = 1 keyframe at frame 0 + per-frame diffs (+ a keyframe every KEY),
plus per-frame placement metadata (bbox+centroid+facing ~13 B) and the diamond's
root+join overhead. Measured on a calm window and an active window so we see
the motion-dependent range.

Run:  .venv/bin/python working/avatari/clip_cost.py
"""
import os, json, math
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
FR   = os.path.join(HERE, "_frames_jeremy")
RH, PALN, ALPHA, KEY, FPS = 128, 16, 100, 30, 30
IB = max(1, math.ceil(math.log2(PALN)))
META = 13          # per-frame: w,h (4) + cx,cy (8) + facing (1)
HDR  = 40          # footage header: magic/type/tone/variant/title/dims/fps/palette


def sprite_cost(S):
    op = S >= 0
    ys, xs = np.where(op)
    if len(xs) == 0: return 8 + 1 + META
    bw, bh = int(xs.max()-xs.min()+1), int(ys.max()-ys.min()+1)
    return 8 + math.ceil(bw*bh/8) + math.ceil(int(op.sum())*IB/8) + META


def delta_cost(S, P):
    chg = S != P; n = int(chg.sum())
    if n == 0: return 8 + META
    ys, xs = np.where(chg)
    bw, bh = int(xs.max()-xs.min()+1), int(ys.max()-ys.min()+1)
    nopq = int((S[chg] >= 0).sum())
    return 8 + math.ceil(bw*bh/8) + math.ceil(n/8) + math.ceil(nopq*IB/8) + META


def main():
    files = sorted(f for f in os.listdir(FR) if f.startswith("f_"))
    nF = len(files)
    sw0, sh0 = Image.open(os.path.join(FR, files[0])).size
    RW = round(RH * sw0 / sh0)
    samp = []
    for k in range(0, nF, 30):
        im = Image.open(os.path.join(FR, files[k])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]; rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
        if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
    master = Image.fromarray(np.concatenate(samp, 0).reshape(-1, 1, 3).astype("uint8")).quantize(colors=PALN, method=Image.MEDIANCUT)

    def state(i):
        im = Image.open(os.path.join(FR, files[i])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]
        q = np.asarray(im.convert("RGB").quantize(palette=master, dither=Image.Dither.NONE)).astype(np.int16)
        return np.where(a > ALPHA, q, -1)

    def clip(start, N):
        b = HDR + sprite_cost(state(start))
        P = state(start)
        for i in range(1, N):
            S = state(start + i)
            if i % KEY == 0: b += sprite_cost(S)
            else:            b += min(delta_cost(S, P), sprite_cost(S))
            P = S
        kn = math.ceil(b / 80)
        return b, kn, (kn + 2) * 0.05

    print("locked profile: %dx%d  %d colors  1-bit alpha  %d fps  delta(c)\n" % (RW, RH, PALN, FPS))
    print("%-22s %7s %7s %8s" % ("gesture clip", "bytes", "knots", "DOGE"))
    for label, start in [("calm (low1 rest)", 47), ("active (praise raise)", 1600)]:
        for sec in (1, 2, 3, 5):
            N = sec * FPS
            if start + N > nF: continue
            b, kn, dg = clip(start, N)
            print("%-22s %7d %7d %8.1f   (%ds / %d frames)" % (label+" "+str(sec)+"s", b, kn, dg, sec, N))
        print()
    # PROOF: the SAME 79s content, monolithic vs chopped into 3s clips
    print("same content, packaged two ways:")
    mono_b = HDR + sprite_cost(state(0)); P = state(0)
    for i in range(1, nF):
        S = state(i)
        if i % KEY == 0: mono_b += sprite_cost(S)
        else:            mono_b += min(delta_cost(S, P), sprite_cost(S))
        P = S
    mk = math.ceil(mono_b/80)
    print("  monolithic 79s footage      %7.2f MB  %6d knots  %6.0f DOGE" % (mono_b/1e6, mk, (mk+2)*0.05))
    chop_b = chop_doge = 0; nclip = 0
    for start in range(0, nF, 90):
        N = min(90, nF-start)
        b, kn, dg = clip(start, N); chop_b += b; chop_doge += dg; nclip += 1
    print("  same 79s in %d x 3s clips    %7.2f MB  %6d knots  %6.0f DOGE  (chopping ADDS overhead)"
          % (nclip, chop_b/1e6, math.ceil(chop_b/80), chop_doge))


if __name__ == "__main__":
    main()
