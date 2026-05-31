#!/usr/bin/env python3
"""Stage 3 — drive the Cavin avatar from the DECODED 0xda bytes and render mp4.

Proves the inscription is a self-sufficient controllable avatar: nothing here
reads the source PNGs. It decodes the 0xda performance, reconstructs each
sprite from the sparse-palette bytes, then walks the control graph through a
scripted choreography — forward / backward (negative time) / tunnel, with
mirror as the facing flip — compositing each pose at its centroid-anchored
world position. Output: cavin_demo.mp4 (+ a representative strip PNG).

Run:  .venv/bin/python working/dancer/cavin_render.py
"""
import os
import sys
import math
import subprocess
import tempfile
import shutil

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
WORK = os.path.join(HERE, "cavin")

from cavin_encode import build_cavin
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..", "canonical"))
from dancer import read_dancer, OP_BACKWARD            # noqa: E402

W, H = 1280, 720
SPRITE_PX = 430              # avatar height on screen
GROUND = 0.90               # ground line, fraction of H
FPS = 30
HOLD = 6                    # video frames per pose
XFADE = 3                   # crossfade frames between poses


def pose_image(df, palette):
    """Reconstruct an RGBA sprite from one decoded sparse-palette frame."""
    w, h = df["w"], df["h"]
    arr = np.zeros((h, w, 4), np.uint8)
    op = np.array(df["mask"], bool).reshape(h, w)
    ys, xs = np.nonzero(op)
    pal = np.array(palette, np.uint8)
    arr[ys, xs, :3] = pal[np.array(df["idx"])]
    arr[ys, xs, 3] = 255
    return Image.fromarray(arr)


def backdrop():
    bg = Image.new("RGB", (W, H), (10, 13, 22))
    top = np.linspace(28, 10, H).astype(np.uint8)
    grad = np.repeat(top[:, None], W, 1)
    bg = Image.fromarray(np.dstack([grad//2, grad//2+4, grad]).astype(np.uint8))
    d = ImageDraw.Draw(bg)
    gy = int(H * GROUND)
    for i in range(34):
        a = 70 - i*2
        d.line([(0, gy+i), (W, gy+i)], fill=(max(8, 20-i), max(10, 22-i), max(14, 30-i)))
    d.line([(0, gy), (W, gy)], fill=(70, 78, 96))
    return bg


def place(base, sprite, cx, world_x):
    """Composite the sprite so its centroid-x sits at world_x and feet on ground."""
    h = SPRITE_PX
    w = max(1, round(sprite.width * h / sprite.height))
    sp = sprite.resize((w, h), Image.LANCZOS)
    gy = int(H * GROUND)
    px = int(world_x * W - cx * w)
    py = gy - h + 8
    # soft contact shadow
    sh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sh)
    sd.ellipse([px + w*0.2, gy-12, px + w*0.8, gy+12], fill=(0, 0, 0, 120))
    sh = sh.filter(ImageFilter.GaussianBlur(6))
    out = base.convert("RGBA")
    out.alpha_composite(sh)
    out.alpha_composite(sp.convert("RGBA"), (px, py))
    return out


def hud(img, text):
    d = ImageDraw.Draw(img)
    d.rectangle([24, H-54, 24+10*len(text)+20, H-22], fill=(0, 0, 0, 110))
    d.text((36, H-50), text, fill=(220, 224, 235))
    return img


def main():
    (hdr, body, _palette, _frames, _nodes, _edges, actions, items,
     _item_node, _n) = build_cavin()
    dec = read_dancer(hdr, body)
    palette = dec["footage"]["palette"]
    dframes = dec["footage"]["frames"]
    sprites = [pose_image(df, palette) for df in dframes]
    cxs = [df["cx"] for df in dframes]
    print(f"decoded {len(sprites)} sprites from 0xda (palette {len(palette)})")

    # choose moves: a locomotion action (max net dx) + the two longest gestures
    def netdx(a):
        return cxs[a["idx"][-1]] - cxs[a["idx"][0]]
    walk = max(actions, key=lambda a: abs(netdx(a)))
    others = sorted((a for a in actions if a is not walk),
                    key=lambda a: -len(a["idx"]))
    g1, g2 = others[0], others[1]

    # script: (action, facing 'R'/'L', reverse?, caption)
    script = [
        (walk, "R", False, "face R · walk"),
        (g1,   "R", False, "gesture"),
        (g1,   "L", False, "face L · mirror"),
        (g1,   "L", True,  "rewind (negative time)"),
        (walk, "L", False, "face L · walk back"),
        (g2,   "R", False, "gesture"),
    ]

    bg = backdrop()
    seq = []                       # rendered video frames
    world_x = 0.30
    strip_marks = []
    for act, facing, rev, cap in script:
        order = list(reversed(act["idx"])) if rev else list(act["idx"])
        strip_marks.append((len(seq), cap))
        prev_img = None
        for ni in order:
            sp = sprites[ni]
            cx = cxs[ni]
            if facing == "L":
                sp = sp.transpose(Image.FLIP_LEFT_RIGHT)
                cx = 1 - cx
            frame = place(bg, sp, cx, world_x)
            frame = hud(frame, "%s · %s" % (facing, cap))
            # crossfade from previous pose
            if prev_img is not None:
                for k in range(1, XFADE+1):
                    seq.append(Image.blend(prev_img, frame, k/(XFADE+1)).convert("RGB"))
            for _ in range(HOLD):
                seq.append(frame.convert("RGB"))
            prev_img = frame
        # locomotion: advance position by the action's net displacement
        dx = netdx(act) * (-1 if facing == "L" else 1)
        world_x = min(0.9, max(0.1, world_x + dx))

    # --- encode mp4 ------------------------------------------------------
    tmp = tempfile.mkdtemp(prefix="cavin_mp4_")
    for i, f in enumerate(seq):
        f.save(os.path.join(tmp, "f_%04d.png" % i))
    out = os.path.join(WORK, "cavin_demo.mp4")
    subprocess.run(
        ["/usr/local/bin/ffmpeg", "-v", "error", "-y", "-framerate", str(FPS),
         "-i", os.path.join(tmp, "f_%04d.png"),
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18",
         "-vf", "scale=1280:720", out], check=True)
    shutil.rmtree(tmp, ignore_errors=True)

    # --- representative strip (one frame per move) -----------------------
    cols = 3
    rows = math.ceil(len(strip_marks) / cols)
    cw, ch = W//3, H//3
    strip = Image.new("RGB", (cols*cw, rows*ch), (8, 10, 16))
    d = ImageDraw.Draw(strip)
    for i, (fidx, cap) in enumerate(strip_marks):
        nxt = strip_marks[i+1][0] if i+1 < len(strip_marks) else len(seq)
        rep = seq[(fidx+nxt)//2].resize((cw, ch))
        x, y = (i % cols)*cw, (i//cols)*ch
        strip.paste(rep, (x, y))
        d.text((x+10, y+8), "%d. %s" % (i+1, cap), fill=(230, 230, 240))
    strip.save(os.path.join(WORK, "cavin_demo_strip.png"))

    dur = len(seq)/FPS
    print(f"rendered {len(seq)} frames -> {dur:.1f}s @ {FPS}fps")
    print("wrote cavin_demo.mp4, cavin_demo_strip.png under", WORK)


if __name__ == "__main__":
    main()
