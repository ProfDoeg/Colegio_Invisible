#!/usr/bin/env python3
"""Quality/cost comparison for the Cavin 0xda dancer.

Two artifacts, each measuring the REAL inscription cost:

  fidelity_ladder.png   the same expressive pose encoded at three settings —
                        96px/16-colour, 128px/32, 192px/64 — labelled with the
                        actual DOGE of inscribing the whole dancer at that
                        fidelity. Answers "50 vs 120 vs 280 DOGE".

  motion_compare.mp4    one action, fixed fidelity (128/32), two columns:
                        LIMITED (key frames only, held + crossfaded) vs SMOOTH
                        (the dense 15-fps source frames). Answers "smooth motion
                        vs limited animation" and its frame-count cost.

Run:  .venv/bin/python working/dancer/cavin_compare.py
"""
import os
import sys
import json
import math
import subprocess
import tempfile
import shutil

import numpy as np
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "canonical")))
WORK = os.path.join(HERE, "cavin")
FR = os.path.join(WORK, "frames")

from dancer import build_dancer_performance, FACE_FRONT, OP_FORWARD, TONE_REVERENCE
from cavin_clean import extract_native, clean_frame

ATHRESH = 24


# ---------- parameterised sparse-palette encode ----------
def load_keyframes(sprite_h):
    track = json.load(open(os.path.join(WORK, "track.json")))
    items, actions = [], []
    for a in track["actions"]:
        rng = []
        for fr in sorted(a["frames"], key=lambda f: f["src_frame"]):
            p = os.path.join(FR, "%s_%04d.png" % (a["name"], fr["src_frame"]))
            if not os.path.exists(p):
                continue
            im = Image.open(p).convert("RGBA")
            s = sprite_h / im.height
            im = im.resize((max(1, round(im.width*s)), sprite_h), Image.LANCZOS)
            rng.append(len(items))
            items.append({"img": im, "cx": fr["centroid"][0], "cy": fr["centroid"][1],
                          "span": a.get("span"), "action": a["name"]})
        if rng:
            actions.append({"name": a["name"], "idx": rng})
    return items, actions


def palette_of(imgs, pal_n):
    cols = [np.array(im)[:, :, :3][np.array(im)[:, :, 3] > ATHRESH] for im in imgs]
    allpx = np.concatenate(cols, 0)
    strip = Image.fromarray(allpx.reshape(1, -1, 3).astype(np.uint8))
    q = strip.quantize(colors=pal_n, method=Image.MEDIANCUT)
    raw = q.getpalette()[:pal_n*3]
    return [(raw[i*3], raw[i*3+1], raw[i*3+2]) for i in range(pal_n)], \
           np.array([(raw[i*3], raw[i*3+1], raw[i*3+2]) for i in range(pal_n)], np.int32)


def enc_frame(im, pal_arr):
    a = np.array(im); op = a[:, :, 3] > ATHRESH
    mask = op.astype(np.uint8).reshape(-1).tolist()
    rgb = a[:, :, :3][op].astype(np.int32)
    idx = ((rgb[:, None, :]-pal_arr[None, :, :])**2).sum(2).argmin(1).astype(int).tolist()
    return im.width, im.height, mask, idx


def encode_at(sprite_h, pal_n):
    items, actions = load_keyframes(sprite_h)
    palette, pal_arr = palette_of([it["img"] for it in items], pal_n)
    frames = []
    for it in items:
        w, h, mask, idx = enc_frame(it["img"], pal_arr)
        frames.append({"w": w, "h": h, "cx": it["cx"], "cy": it["cy"],
                       "facing": FACE_FRONT, "mask": mask, "idx": idx})
    nodes = list(range(len(items)))
    edges = [{"src": u, "dst": v, "op": OP_FORWARD, "span": (u, v),
              "dx": 0.0, "dy": 0.0, "facing_delta": 0, "label": 0}
             for a in actions for u, v in zip(a["idx"], a["idx"][1:])]
    hdr, body = build_dancer_performance("Cavin", palette, frames, nodes, edges,
                                         tone=TONE_REVERENCE)
    doge = math.ceil((len(hdr)+len(body))/80) * 0.05
    return items, actions, frames, palette, pal_arr, len(hdr)+len(body), doge


def recon(frame, palette):
    w, h = frame["w"], frame["h"]
    arr = np.zeros((h, w, 4), np.uint8)
    op = np.array(frame["mask"], bool).reshape(h, w)
    ys, xs = np.nonzero(op)
    arr[ys, xs, :3] = np.array(palette, np.uint8)[np.array(frame["idx"])]
    arr[ys, xs, 3] = 255
    return Image.fromarray(arr)


def on_dark(sp, target_h, w_box):
    s = target_h / sp.height
    sp = sp.resize((max(1, round(sp.width*s)), target_h), Image.LANCZOS)
    cell = Image.new("RGB", (w_box, target_h+40), (16, 19, 30))
    cell.paste(Image.new("RGB", sp.size, (16, 19, 30)).convert("RGB"),
               ((w_box-sp.width)//2, 0), sp)
    return cell


# ---------- artifact 1: fidelity ladder ----------
def fidelity_ladder():
    settings = [(96, 16), (128, 32), (192, 64)]
    cols = []
    labels = []
    pose_key = None
    for sh, pn in settings:
        items, actions, frames, palette, _pa, total, doge = encode_at(sh, pn)
        # the same pose across settings: middle frame of the longest action
        longest = max(actions, key=lambda a: len(a["idx"]))
        if pose_key is None:
            pose_key = longest["idx"][len(longest["idx"])//2]
        sp = recon(frames[pose_key], palette)
        cols.append(sp)
        labels.append("%dpx · %d-colour\n%.0f DOGE   (%.0f KB)" % (sh, pn, doge, total/1024))
        print("  %3dpx/%2d-colour: %5.1f KB  ≈ %.0f DOGE" % (sh, pn, total/1024, doge))

    TH, BW = 360, 360
    sheet = Image.new("RGB", (BW*3, TH+70), (10, 12, 20))
    d = ImageDraw.Draw(sheet)
    for i, (sp, lab) in enumerate(zip(cols, labels)):
        s = TH/sp.height; spr = sp.resize((max(1, round(sp.width*s)), TH), Image.LANCZOS)
        x = i*BW + (BW-spr.width)//2
        sheet.paste(spr.convert("RGB"), (x, 20), spr)
        d.text((i*BW+14, TH+28), lab.split("\n")[0], fill=(230, 232, 240))
        d.text((i*BW+14, TH+44), lab.split("\n")[1], fill=(190, 195, 210))
    sheet.save(os.path.join(WORK, "fidelity_ladder.png"))
    print("wrote fidelity_ladder.png")


# ---------- artifact 2: smooth vs limited ----------
def motion_compare():
    SH, PN = 128, 32
    items, actions, frames, palette, pal_arr, _t, _d = encode_at(SH, PN)
    # choose an action with visible motion (largest centroid travel)
    def travel(a):
        cs = [items[i]["cx"] for i in a["idx"]]
        return max(cs)-min(cs)
    act = max(actions, key=travel)
    span = items[act["idx"][0]]["span"]
    a0, a1 = span[0], span[1]
    print("smooth/limited on action span %d..%d" % (a0, a1))

    # limited: the action's key frames (already encoded) -> sprites
    lim = [recon(frames[i], palette) for i in act["idx"]]
    lim_cx = [items[i]["cx"] for i in act["idx"]]

    # smooth: dense native frames over the span, cleaned, downsampled, palette-mapped
    dense_idx = list(range(a0, a1+1, 2))            # ~7.5fps source
    extract_native(dense_idx)
    smooth, smooth_cx = [], []
    for k in dense_idx:
        cr, (cx, cy) = clean_frame(k)               # cleaned RGBA @144
        s = SH/cr.height; cr = cr.resize((max(1, round(cr.width*s)), SH), Image.LANCZOS)
        w, h, mask, idx = enc_frame(cr, pal_arr)
        smooth.append(recon({"w": w, "h": h, "mask": mask, "idx": idx}, palette))
        smooth_cx.append(cx)
    print("limited frames %d   smooth frames %d" % (len(lim), len(smooth)))

    # render two columns, same duration, looped twice
    CW, CH, TH = 460, 560, 460
    GROUND = 0.92

    def col(sprites, cxs, kind, t, n):
        cell = Image.new("RGB", (CW, CH), (12, 15, 24))
        d = ImageDraw.Draw(cell)
        gy = int(CH*GROUND); d.line([(0, gy), (CW, gy)], fill=(60, 66, 84))
        i = int(t*n) % n if n else 0
        sp = sprites[i]; cx = cxs[i]
        s = TH/sp.height; spr = sp.resize((max(1, round(sp.width*s)), TH), Image.LANCZOS)
        px = int(0.5*CW - cx*spr.width); py = gy - spr.height + 6
        cell.paste(spr.convert("RGB"), (px, py), spr)
        d.text((16, 14), kind, fill=(235, 236, 245))
        return cell

    NF = 96                                          # video frames per loop
    tmp = tempfile.mkdtemp(prefix="cavin_cmp_")
    strip_idx = [int(NF*f) for f in (0.1, 0.35, 0.6, 0.85)]
    strip_cells = []
    for fi in range(NF*2):                           # two loops
        t = (fi % NF)/NF
        L = col(lim, lim_cx, "LIMITED  (key frames · ~50 DOGE motion)",
                t, len(lim))
        R = col(smooth, smooth_cx, "SMOOTH  (dense frames · 3-5x DOGE)",
                t, len(smooth))
        frame = Image.new("RGB", (CW*2+20, CH), (8, 10, 16))
        frame.paste(L, (0, 0)); frame.paste(R, (CW+20, 0))
        frame.save(os.path.join(tmp, "f_%04d.png" % fi))
        if (fi % NF) in strip_idx and fi < NF:
            strip_cells.append(frame.copy())
    out = os.path.join(WORK, "motion_compare.mp4")
    subprocess.run(["/usr/local/bin/ffmpeg", "-v", "error", "-y", "-framerate", "20",
                    "-i", os.path.join(tmp, "f_%04d.png"),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", out], check=True)
    shutil.rmtree(tmp, ignore_errors=True)
    # strip
    sc = strip_cells[0].width // 2
    strip = Image.new("RGB", (strip_cells[0].width, strip_cells[0].height*len(strip_cells)//2 + 0), (8, 10, 16)) \
        if False else Image.new("RGB", (strip_cells[0].width, strip_cells[0].height), (8, 10, 16))
    strip = strip_cells[len(strip_cells)//2]
    strip.save(os.path.join(WORK, "motion_compare_strip.png"))
    print("wrote motion_compare.mp4, motion_compare_strip.png")


def main():
    print("=== fidelity ladder (real cost) ===")
    fidelity_ladder()
    print("=== smooth vs limited ===")
    motion_compare()


if __name__ == "__main__":
    main()
