#!/usr/bin/env python3
"""Stage 1 ingest of Anthony's own dancer dataset (cavin_clean_png.mov) toward
the 0xda motion-sprite type.

Reads the RGBA clip, segments the dance into actions (phrases between rest
poses), key-frames each, tight-crops every key frame to its alpha bounding box
with the centroid recorded, and reports the on-chain byte cost under three
encodings so we can choose resolution with real numbers:

  dense   : bbox W×H × RGBA × bit_depth                (every pixel, incl. clear)
  mask5   : 1-bit alpha mask + 5-bit RGB for opaque px  (sparse colour)
  pal     : 1-bit alpha mask + N-colour palette + index (palette per opaque px)

Outputs (under working/dancer/cavin/):
  frames/<action>_<k>.png   tight-cropped key frames (RGBA)
  contact.png               key frames grouped by action
  preview_<action>.gif      one looping GIF per action
  track.json                per-frame action/bbox/centroid/displacement + cost

Run:  .venv/bin/python working/dancer/cavin_ingest.py
"""
import os
import json
import math
import subprocess
from collections import Counter

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.expanduser("~/Desktop/cavin_clean_png.mov")
WORK = os.path.join(HERE, "cavin")
RAW = os.path.join(WORK, "raw")          # all frames, analysis res
FR = os.path.join(WORK, "frames")        # cropped key frames
os.makedirs(RAW, exist_ok=True)
os.makedirs(FR, exist_ok=True)

ANALYSIS_H = 240        # extract every frame at this height for analysis
ALPHA_THRESH = 24       # alpha above this counts as "figure"
SPRITE_H = 144          # downsample key-frame crops to this tall for cost calc
PAL_COLORS = 32         # palette size for the palette encoding


def extract_all():
    """Extract every frame at ANALYSIS_H, RGBA, if not already done."""
    if len(os.listdir(RAW)) > 100:
        return sorted(f for f in os.listdir(RAW) if f.endswith(".png"))
    subprocess.run(
        ["/usr/local/bin/ffmpeg", "-v", "error", "-i", SRC,
         "-vf", "scale=-1:%d,format=rgba" % ANALYSIS_H, "-vsync", "0",
         os.path.join(RAW, "f_%04d.png")],
        check=True)
    return sorted(f for f in os.listdir(RAW) if f.endswith(".png"))


def frame_stats(path):
    """alpha bbox, centroid (fraction of frame), 16×24 silhouette signature."""
    im = Image.open(path).convert("RGBA")
    a = im.split()[3]
    bb = a.getbbox()
    W, H = im.size
    if not bb:
        return None
    cr = a.crop(bb)
    small = cr.resize((16, 24))
    px = small.load()
    sig = []
    sx = sy = tot = 0
    for y in range(24):
        for x in range(16):
            v = px[x, y]
            sig.append(1 if v > ALPHA_THRESH else 0)
            if v > ALPHA_THRESH:
                sx += x; sy += y; tot += 1
    cx = (bb[0] + (sx / tot if tot else 8) / 16 * (bb[2]-bb[0])) / W
    cy = (bb[1] + (sy / tot if tot else 12) / 24 * (bb[3]-bb[1])) / H
    return {"bbox": bb, "cx": cx, "cy": cy, "sig": sig, "size": (W, H)}


def segment(stats):
    """Split the timeline into actions: motion energy (silhouette change +
    centroid delta) per frame, smoothed; rest poses (local minima) are the
    boundaries. Each phrase between two rests is an action."""
    n = len(stats)
    energy = [0.0] * n
    for i in range(1, n):
        a, b = stats[i-1], stats[i]
        if not a or not b:
            continue
        ham = sum(1 for p, q in zip(a["sig"], b["sig"]) if p != q)
        cd = abs(a["cx"]-b["cx"]) + abs(a["cy"]-b["cy"])
        energy[i] = ham + cd * 400
    # smooth (moving average, window 5)
    sm = []
    for i in range(n):
        lo, hi = max(0, i-2), min(n, i+3)
        sm.append(sum(energy[lo:hi]) / (hi-lo))
    # rest frames: energy below a fraction of the median active energy
    active = [e for e in sm if e > 1]
    thresh = (sorted(active)[len(active)//2] if active else 0) * 0.45
    rest = [i for i in range(n) if sm[i] <= thresh]
    # boundaries = middle of each run of rest frames
    bounds = [0]
    run = []
    for i in range(n):
        if i in set(rest):
            run.append(i)
        elif run:
            bounds.append(run[len(run)//2]); run = []
    bounds.append(n-1)
    bounds = sorted(set(bounds))
    # phrases between consecutive boundaries that carry real motion
    actions = []
    for a, b in zip(bounds, bounds[1:]):
        if b - a < 4:
            continue
        peak = max(range(a, b+1), key=lambda i: sm[i])
        if sm[peak] < thresh * 1.4:
            continue
        actions.append((a, peak, b))
    return actions, sm


def key_frames(a, peak, b):
    """Choose key frames for a phrase: start hold, the motion peak, end hold,
    plus two between — five frames, deduped."""
    cand = [a, (a+peak)//2, peak, (peak+b)//2, b]
    out = []
    for c in cand:
        if c not in out:
            out.append(c)
    return out


def sparse_costs(im, bit_depth=5, pal_colors=PAL_COLORS):
    """Byte cost of one cropped RGBA frame under the three encodings."""
    a = im.split()[3]
    W, H = im.size
    px = im.load()
    opaque = [(x, y) for y in range(H) for x in range(W)
              if px[x, y][3] > ALPHA_THRESH]
    n = len(opaque)
    dense = math.ceil(W * H * 4 * bit_depth / 8)
    mask = math.ceil(W * H / 8)
    mask5 = mask + math.ceil(n * 3 * bit_depth / 8)
    # palette: quantize opaque RGB to pal_colors
    idx_bits = max(1, math.ceil(math.log2(pal_colors)))
    pal = mask + pal_colors * 3 + math.ceil(n * idx_bits / 8)
    return {"opaque": n, "of": W*H, "dense": dense, "mask5": mask5, "pal": pal}


def main():
    print("extracting frames…")
    files = extract_all()
    n = len(files)
    print(f"  {n} frames at {ANALYSIS_H}px")
    print("analysing…")
    stats = [frame_stats(os.path.join(RAW, f)) for f in files]
    actions, sm = segment(stats)
    print(f"  segmented into {len(actions)} actions")

    track = {"source": "cavin_clean_png.mov", "fps": 15, "actions": []}
    contact_cells = []
    total = {"dense": 0, "mask5": 0, "pal": 0, "frames": 0}

    for ai, (a, peak, b) in enumerate(actions):
        name = "action_%02d" % (ai + 1)
        kfs = key_frames(a, peak, b)
        rec = {"name": name, "span": [a, b], "frames": []}
        gif_imgs = []
        prev_c = None
        for k in kfs:
            im = Image.open(os.path.join(RAW, files[k])).convert("RGBA")
            bb = im.split()[3].getbbox()
            cr = im.crop(bb)
            # downsample to SPRITE_H tall
            scale = SPRITE_H / cr.height
            cr = cr.resize((max(1, round(cr.width*scale)), SPRITE_H), Image.LANCZOS)
            outp = os.path.join(FR, f"{name}_{k:04d}.png")
            cr.save(outp)
            cost = sparse_costs(cr)
            st = stats[k]
            disp = [0.0, 0.0] if prev_c is None else [
                round(st["cx"]-prev_c[0], 4), round(st["cy"]-prev_c[1], 4)]
            prev_c = (st["cx"], st["cy"])
            rec["frames"].append({
                "src_frame": k, "w": cr.width, "h": cr.height,
                "centroid": [round(st["cx"], 4), round(st["cy"], 4)],
                "displacement": disp, "cost_bytes": cost,
            })
            for key in ("dense", "mask5", "pal"):
                total[key] += cost[key]
            total["frames"] += 1
            thumb = cr.copy(); thumb.thumbnail((90, 130))
            gif_imgs.append(cr)
            if k == kfs[0]:
                contact_cells.append((name, thumb))
        # looping GIF per action (over the whole phrase, every 2nd frame)
        seq = [Image.open(os.path.join(RAW, files[i])).convert("RGBA")
               for i in range(a, b+1, 2)]
        if seq:
            base = seq[0].size
            seq = [s.resize(base) for s in seq]
            # composite on dark for the gif
            comp = []
            for s in seq:
                bg = Image.new("RGBA", base, (18, 22, 38, 255))
                bg.alpha_composite(s); comp.append(bg.convert("P"))
            comp[0].save(os.path.join(WORK, f"preview_{name}.gif"),
                         save_all=True, append_images=comp[1:],
                         duration=90, loop=0, disposal=2)
        track["actions"].append(rec)

    # contact sheet: one key frame per action
    cols = 6
    cw, ch = 100, 140
    rows = math.ceil(len(contact_cells) / cols)
    sheet = Image.new("RGBA", (cols*cw, rows*ch), (18, 22, 38, 255))
    from PIL import ImageDraw
    d = ImageDraw.Draw(sheet)
    for i, (name, th) in enumerate(contact_cells):
        x = (i % cols)*cw + (cw-th.width)//2
        y = (i // cols)*ch + (ch-th.height)//2
        sheet.alpha_composite(th, (x, y))
        d.text(((i % cols)*cw+4, (i // cols)*ch+2), name[7:], fill=(200, 200, 210))
    sheet.convert("RGB").save(os.path.join(WORK, "contact.png"))

    with open(os.path.join(WORK, "track.json"), "w") as f:
        json.dump(track, f, indent=1)

    kb = lambda v: f"{v/1024:.1f} KB"
    print(f"\nkey frames: {total['frames']} across {len(actions)} actions")
    print(f"per-encoding TOTAL byte cost ({SPRITE_H}px tall, 5-bit):")
    print(f"  dense  : {kb(total['dense'])}")
    print(f"  mask5  : {kb(total['mask5'])}   ({total['dense']/max(1,total['mask5']):.1f}× vs dense)")
    print(f"  palette: {kb(total['pal'])}   ({total['dense']/max(1,total['pal']):.1f}× vs dense)")
    # DOGE estimate: 80 payload bytes per knot, ~0.05 DOGE per tx, ~1 knot/tx
    for key in ("dense", "mask5", "pal"):
        strands = math.ceil(total[key] / 80)
        print(f"  ~{key} on chain: {strands} knots ≈ {strands*0.05:.1f} DOGE")
    print(f"\nwrote: contact.png, preview_*.gif, track.json, frames/ under {WORK}")


if __name__ == "__main__":
    main()
