#!/usr/bin/env python3
"""Compress Jeremy's footage into the 0xda 'little images' representation and
emit a bundle a new player can render directly (no 720-wide reconstitution).

Per frame: alpha-crop to the dancer's bounding box, downsample to a target
height, map colours to one shared palette, store a 1-bit alpha mask + a palette
index per opaque pixel, and remember the bbox + centroid so the renderer can
place the tight sprite back where it stood.

Outputs (working/avatari/live/jeremy_c/):
  atlas_NN.png    tight-sprite atlas pages (decoded back from palette+mask+idx)
  footage.json    {RW,RH,palette,fps, frames:[{page,u,v,w,h, fx,fy,fw,fh, cx}]}

Also encodes the same frames through canonical/dancer.py's footage codec to
report the REAL on-chain body size (and a rough knot / DOGE cost).

Run:  RH=128 .venv/bin/python working/avatari/compress_footage.py
"""
import os, sys, json, math
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "canonical"))
from dancer import build_dancer_footage          # the real codec, for sizing
from image import pack_pixels                     # to size mask/idx independently

FR  = os.path.join(HERE, "_frames_jeremy")
CEN = os.path.join(HERE, "_centroids_jeremy.json")
OUT = os.path.join(HERE, "live", "jeremy_c")
RH    = int(os.environ.get("RH", "128"))          # stored sprite height (the cost/quality dial)
PALN  = int(os.environ.get("PALN", "32"))         # shared palette size
ALPHA = int(os.environ.get("ALPHA", "100"))       # alpha threshold for the 1-bit mask
PAGE  = 2048
FPS   = 30


def main():
    os.makedirs(OUT, exist_ok=True)
    files = sorted(f for f in os.listdir(FR) if f.startswith("f_"))
    nF = len(files)
    sw0, sh0 = Image.open(os.path.join(FR, files[0])).size
    RW = round(RH * sw0 / sh0)
    cxs = json.load(open(CEN))
    print("frames %d  source %dx%d  notional %dx%d  palette %d  alpha>%d"
          % (nF, sw0, sh0, RW, RH, PALN, ALPHA))

    # ---- shared palette: median-cut over a montage of every 30th frame ----
    samp = []
    for k in range(0, nF, 30):
        im = Image.open(os.path.join(FR, files[k])).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        a = np.asarray(im)[..., 3]
        rgb = np.asarray(im.convert("RGB"))[a > ALPHA]
        if len(rgb): samp.append(rgb[:: max(1, len(rgb)//400)])
    samp = np.concatenate(samp, 0)
    smp_img = Image.fromarray(samp.reshape(-1, 1, 3).astype("uint8"), "RGB")
    master = smp_img.quantize(colors=PALN, method=Image.MEDIANCUT)
    pal_flat = master.getpalette()[:PALN*3]
    palette = [(pal_flat[3*i], pal_flat[3*i+1], pal_flat[3*i+2]) for i in range(PALN)]
    pal_np = np.array(palette, np.uint8)

    # ---- per-frame: crop, quantize, mask, sparse-encode ----
    recs, sprites = [], []          # sprites = decoded RGBA arrays for the atlas
    codec_frames = []               # for the real on-chain size
    mask_bytes = idx_bytes = 0
    maxW = maxH = 1
    for i, fn in enumerate(files):
        im = Image.open(os.path.join(FR, fn)).convert("RGBA").resize((RW, RH), Image.LANCZOS)
        arr = np.asarray(im)
        a = arr[..., 3]
        mask = a > ALPHA
        ys, xs = np.where(mask)
        if len(xs) == 0:                                  # empty frame -> 1px stub
            x0 = y0 = 0; sw = sh = 1
            sm = np.array([[False]]); idx = np.zeros((1, 1), np.uint8)
        else:
            x0, x1, y0, y1 = xs.min(), xs.max()+1, ys.min(), ys.max()+1
            sw, sh = int(x1-x0), int(y1-y0)
            spr_rgb = im.convert("RGB").crop((x0, y0, x1, y1))
            idx = np.asarray(spr_rgb.quantize(palette=master, dither=Image.Dither.NONE))
            sm = mask[y0:y1, x0:x1]
        flat_mask = sm.astype(int).flatten().tolist()
        flat_idx  = idx[sm].astype(int).tolist() if sm.any() else [0]
        cx = float(cxs[i])
        cy = float((ys.mean()/RH)) if len(ys) else 0.5
        codec_frames.append(dict(w=sw, h=sh, cx=cx, cy=cy, facing=0,
                                 mask=flat_mask, idx=flat_idx))
        mask_bytes += math.ceil(sw*sh/8)
        idx_bytes  += math.ceil(len(flat_idx)*math.ceil(math.log2(max(2, PALN)))/8)
        recs.append(dict(x0=int(x0), y0=int(y0), w=sw, h=sh, cx=cx))
        # decode back to RGBA for the atlas (proves the round-trip)
        rgb = pal_np[idx]
        rgba = np.dstack([rgb, np.where(sm, 255, 0).astype(np.uint8)])
        sprites.append(rgba)
        maxW = max(maxW, sw); maxH = max(maxH, sh)

    # ---- pack decoded sprites into atlas pages (uniform maxW x maxH cells) ----
    cols = max(1, PAGE // maxW); rows = max(1, PAGE // maxH); per = cols*rows
    pages = math.ceil(nF / per)
    fjson = []
    page_imgs = [Image.new("RGBA", (cols*maxW, rows*maxH), (0, 0, 0, 0)) for _ in range(pages)]
    for i, (rgba, r) in enumerate(zip(sprites, recs)):
        p = i // per; c = (i % per) % cols; rr = (i % per) // cols
        u, v = c*maxW, rr*maxH
        page_imgs[p].paste(Image.fromarray(rgba, "RGBA"), (u, v))
        fjson.append(dict(page=p, u=u, v=v, w=r["w"], h=r["h"],
                          fx=round(r["x0"]/RW, 4), fy=round(r["y0"]/RH, 4),
                          fw=round(r["w"]/RW, 4), fh=round(r["h"]/RH, 4),
                          cx=round(r["cx"], 4)))
    for p, img in enumerate(page_imgs):
        img.save(os.path.join(OUT, "atlas_%02d.png" % p))

    json.dump(dict(RW=RW, RH=RH, fps=FPS, cols=cols, rows=rows, cell_w=maxW,
                   cell_h=maxH, pages=pages, palette=palette, frames=fjson),
              open(os.path.join(OUT, "footage.json"), "w"))

    # ---- REAL on-chain size via the canonical 0x02 footage codec ----
    h, b = build_dancer_footage("Jeremy", palette, codec_frames)
    total = len(h) + len(b)
    knots = math.ceil(total / 80)
    doge = (knots + 2) * 0.05
    print("atlas: %d pages, cell %dx%d, %dx%d/page" % (pages, maxW, maxH, cols, rows))
    print("sparse parts: mask %.1f KB  idx %.1f KB" % (mask_bytes/1024, idx_bytes/1024))
    print("on-chain footage body: %.2f MB  (header+body %d bytes)" % (len(b)/1e6, total))
    print("  ~%d knots  -> ~%.0f DOGE at 0.05/tx  (RH=%d, PAL=%d)" % (knots, doge, RH, PALN))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
