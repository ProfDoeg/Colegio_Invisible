#!/usr/bin/env python3
"""Smooth (dense-frame) playback at the 128px / 32-colour fidelity (the
102-DOGE middle rung). Shows what that fidelity looks like in motion when
every source frame is used, rather than only the key frames — i.e. the
'smooth' axis at the middle quality. Single character, centred by centroid.

Run:  .venv/bin/python working/dancer/cavin_smooth.py
"""
import os
import sys
import subprocess
import tempfile
import shutil

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageOps


def feather(rgba, radius=2.0, pad=4):
    """Render-time edge softening: blur the (hard, 1-bit) alpha so the
    silhouette fades instead of hard-cutting. On a dark backdrop the
    transparent RGB (black) soft edge blends invisibly — no halo. The
    inscription is untouched; this only affects display."""
    rgba = ImageOps.expand(rgba.convert("RGBA"), border=pad, fill=(0, 0, 0, 0))
    soft = rgba.split()[3].filter(ImageFilter.GaussianBlur(radius))
    rgba.putalpha(soft)
    return rgba

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
WORK = os.path.join(HERE, "cavin")

import cavin_clean as CC
from cavin_clean import clean_frame
from cavin_compare import palette_of, enc_frame, recon


def extract_range(start, count):
    """Extract a CONTIGUOUS native-frame window with a single between() term
    (the per-index eq() list overflows ffmpeg for big ranges)."""
    have = ({int(f[2:6]) for f in os.listdir(CC.NAT) if f.startswith("n_")}
            if os.path.isdir(CC.NAT) else set())
    if all(i in have for i in range(start, start+count)):
        return
    os.makedirs(CC.NAT, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="cavin_rng_")
    subprocess.run(
        ["/usr/local/bin/ffmpeg", "-v", "error", "-i", CC.SRC, "-vf",
         "select='between(n\\,%d\\,%d)',format=rgba" % (start, start+count-1),
         "-vsync", "0", os.path.join(tmp, "o_%04d.png")], check=True)
    outs = sorted(f for f in os.listdir(tmp) if f.startswith("o_"))
    for j, f in enumerate(outs):
        os.replace(os.path.join(tmp, f), os.path.join(CC.NAT, "n_%04d.png" % (start+j)))
    shutil.rmtree(tmp, ignore_errors=True)

SH, PN = 128, 32                 # the 102-DOGE fidelity
START, COUNT = 90, 150           # dense window: 150 frames @ 15fps = 10s
W, H = 900, 760
SPRITE_PX = 600
GROUND = 0.93
FPS = 15


def backdrop():
    col = np.linspace(30, 8, H).astype(np.uint8)
    g = np.repeat(col[:, None], W, 1)
    bg = Image.fromarray(np.dstack([g//2, g//2+5, g]).astype(np.uint8))
    d = ImageDraw.Draw(bg)
    gy = int(H*GROUND)
    d.line([(0, gy), (W, gy)], fill=(70, 78, 96))
    return bg


def main():
    idx = list(range(START, START+COUNT))
    print(f"extracting {len(idx)} native frames…")
    extract_range(START, COUNT)
    print("cleaning + downsampling…")
    sprites_src, cxs = [], []
    for k in idx:
        cr, (cx, cy) = clean_frame(k)
        s = SH/cr.height
        cr = cr.resize((max(1, round(cr.width*s)), SH), Image.LANCZOS)
        sprites_src.append(cr); cxs.append(cx)

    # palette-map to 32 colours at 128px, then reconstruct — the ACTUAL
    # 102-DOGE pixels, just dense in time.
    palette, pal_arr = palette_of(sprites_src, PN)
    sprites = []
    for cr in sprites_src:
        w, h, mask, idxs = enc_frame(cr, pal_arr)
        sprites.append(recon({"w": w, "h": h, "mask": mask, "idx": idxs}, palette))
    print(f"{len(sprites)} sprites @ {SH}px / {PN} colours")

    # before/after head comparison (zoom on the crown)
    sp = sprites[40]
    s = SPRITE_PX/sp.height
    hard = sp.resize((max(1, round(sp.width*s)), SPRITE_PX), Image.LANCZOS)
    soft = feather(hard.copy(), radius=2.0)
    hh = int(SPRITE_PX*0.32)

    def head(im, oy):
        im = im.convert("RGBA")
        b = Image.new("RGBA", im.size, (14, 18, 30, 255)); b.alpha_composite(im)
        return b.convert("RGB").crop((0, oy, im.width, oy+hh))
    hc, sc = head(hard, 0), head(soft, 4)
    cw2 = max(hc.width, sc.width)
    cmp = Image.new("RGB", (cw2*2+20, hh+26), (8, 10, 16))
    dd = ImageDraw.Draw(cmp)
    cmp.paste(hc, ((cw2-hc.width)//2, 24)); cmp.paste(sc, (cw2+20+(cw2-sc.width)//2, 24))
    dd.text((8, 6), "hard matte (before)", fill=(232, 232, 242))
    dd.text((cw2+28, 6), "1px feather (after)", fill=(232, 232, 242))
    cmp.resize((cmp.width*2, cmp.height*2), Image.NEAREST).save(
        os.path.join(WORK, "feather_compare.png"))

    bg = backdrop()
    gy = int(H*GROUND)
    tmp = tempfile.mkdtemp(prefix="cavin_sm_")
    strip = []
    for i, (sp, cx) in enumerate(zip(sprites, cxs)):
        s = SPRITE_PX/sp.height
        spr = sp.resize((max(1, round(sp.width*s)), SPRITE_PX), Image.LANCZOS)
        spr = feather(spr, radius=2.0)               # soften the hard matte edge
        frame = bg.convert("RGBA")
        # soft contact shadow
        sh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ImageDraw.Draw(sh).ellipse(
            [W//2-spr.width*0.3, gy-14, W//2+spr.width*0.3, gy+14], fill=(0, 0, 0, 130))
        frame.alpha_composite(sh.filter(ImageFilter.GaussianBlur(7)))
        px = int(0.5*W - 0.5*spr.width)            # centred (in-place dance)
        py = gy - spr.height + 8
        frame.alpha_composite(spr.convert("RGBA"), (px, py))
        frame.convert("RGB").save(os.path.join(tmp, "f_%04d.png" % i))
        if i in (10, 40, 75, 110, 140):
            strip.append(frame.convert("RGB"))

    out = os.path.join(WORK, "cavin_smooth_128.mp4")
    subprocess.run(["/usr/local/bin/ffmpeg", "-v", "error", "-y", "-framerate", str(FPS),
                    "-i", os.path.join(tmp, "f_%04d.png"),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "16", out], check=True)
    shutil.rmtree(tmp, ignore_errors=True)

    # contact strip
    cw = strip[0].width//2; ch = strip[0].height//2
    sheet = Image.new("RGB", (cw*len(strip), ch), (8, 10, 16))
    for i, s in enumerate(strip):
        sheet.paste(s.resize((cw, ch)), (i*cw, 0))
    sheet.save(os.path.join(WORK, "cavin_smooth_128_strip.png"))
    print("wrote cavin_smooth_128.mp4 (%.0fs) + strip" % (len(sprites)/FPS))


if __name__ == "__main__":
    main()
