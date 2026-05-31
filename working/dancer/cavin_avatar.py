#!/usr/bin/env python3
"""Stage 1c — the avatar engine: drive Cavin as a controllable character.

The motion graph (cavin_graph.py) gives poses + transitions under the V4
group {I, M, R, MR}. This treats it as a controller: the avatar holds a
STATE (current pose, facing, world-x), and a stream of CONTROLS picks moves:

    face R / face L      -> facing (M applies the mirror)
    do <action>          -> play that action's key-frame path forward (I)
    rewind <action>      -> play it backward (R = negative time)
    idle <n>             -> hold/breathe at the current pose

Each move's frames are composited onto a backdrop at the avatar's world
position (centroid-anchored), flipped for facing, advancing world-x by the
move's displacement. Output: a control strip PNG (the avatar obeying a
scripted sequence, commands labelled) + a driven GIF.

Run:  .venv/bin/python working/dancer/cavin_avatar.py
"""
import os
import json

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "cavin")
FR = os.path.join(WORK, "frames")

GROUND_Y = 0.86          # where the feet sit, fraction of canvas height
SPRITE_H = 150           # avatar height on the demo canvas (px)
CW, CH = 1100, 360       # control-strip cell is CH tall


def load_actions():
    track = json.load(open(os.path.join(WORK, "track.json")))
    acts = {}
    for a in track["actions"]:
        frames = []
        for fr in sorted(a["frames"], key=lambda f: f["src_frame"]):
            p = os.path.join(FR, "%s_%04d.png" % (a["name"], fr["src_frame"]))
            if os.path.exists(p):
                frames.append({"img": p, "cx": fr["centroid"][0],
                               "cy": fr["centroid"][1]})
        if frames:
            acts[a["name"]] = frames
    return acts


class Avatar:
    """Holds state and renders frames as controls are applied."""
    def __init__(self, acts, canvas_w=560, canvas_h=300):
        self.acts = acts
        self.W, self.H = canvas_w, canvas_h
        self.facing = "R"          # 'R' (identity) or 'L' (mirror)
        self.x = 0.5               # world-x as fraction of canvas
        self.pose = None           # last rendered crop (for idle)
        self.frames = []           # rendered RGBA frames

    def _sprite(self, fr):
        im = Image.open(fr["img"]).convert("RGBA")
        h = SPRITE_H
        w = max(1, round(im.width * h / im.height))
        im = im.resize((w, h), Image.LANCZOS)
        cx = fr["cx"]
        if self.facing == "L":
            im = im.transpose(Image.FLIP_LEFT_RIGHT)
            cx = 1 - cx
        return im, cx

    def _compose(self, im, cx):
        bg = Image.new("RGBA", (self.W, self.H), (16, 20, 34, 255))
        d = ImageDraw.Draw(bg)
        # ground line
        gy = int(self.H * GROUND_Y)
        d.line([(0, gy), (self.W, gy)], fill=(60, 66, 86), width=1)
        # place: avatar centroid-x at world x, feet on ground
        px = int(self.x * self.W - cx * im.width + im.width // 2 - im.width * (cx - 0.5))
        px = int(self.x * self.W - cx * im.width)
        py = gy - im.height + 6
        bg.alpha_composite(im, (px, py))
        self.frames.append(bg)
        self.pose = (im, cx)

    # ---- controls --------------------------------------------------------
    def face(self, d):
        self.facing = d

    def do(self, name, rewind=False):
        seq = self.acts[name]
        seq = list(reversed(seq)) if rewind else seq
        prev = None
        for fr in seq:
            im, cx = self._sprite(fr)
            if prev is not None:
                # accumulate locomotion from centroid displacement
                dx = (fr["cx"] - prev) * (-1 if self.facing == "L" else 1)
                self.x = min(0.92, max(0.08, self.x + dx))
            prev = fr["cx"]
            self._compose(im, cx)

    def idle(self, n=4):
        if self.pose is None:
            self.do(next(iter(self.acts)))
            return
        im, cx = self.pose
        for _ in range(n):
            self._compose(im, cx)


def main():
    acts = load_actions()
    names = list(acts)
    # pick a few expressive actions for the demo (by frame count / motion)
    gesture = max(names, key=lambda n: len(acts[n]))     # the longest phrase
    second = sorted(names, key=lambda n: len(acts[n]))[-2]

    # a scripted control sequence demonstrating the three control axes
    script = [
        ("idle 3",            lambda a: a.idle(3)),
        ("face R",            lambda a: a.face("R")),
        ("do %s" % gesture,   lambda a: a.do(gesture)),
        ("idle 3",            lambda a: a.idle(3)),
        ("face L",            lambda a: a.face("L")),
        ("do %s (mirrored)" % gesture, lambda a: a.do(gesture)),
        ("rewind %s" % gesture,        lambda a: a.do(gesture, rewind=True)),
        ("face R",            lambda a: a.face("R")),
        ("do %s" % second,    lambda a: a.do(second)),
    ]

    av = Avatar(acts)
    marks = []                                   # (frame index, label)
    for label, fn in script:
        marks.append((len(av.frames), label))
        fn(av)

    # --- driven GIF ------------------------------------------------------
    gif = [f.convert("P", palette=Image.ADAPTIVE) for f in av.frames]
    gif[0].save(os.path.join(WORK, "avatar_demo.gif"), save_all=True,
                append_images=gif[1:], duration=110, loop=0, disposal=2)

    # --- control strip: one representative frame per command -------------
    cells = []
    for i, (fidx, label) in enumerate(marks):
        nxt = marks[i+1][0] if i+1 < len(marks) else len(av.frames)
        rep = av.frames[(fidx + nxt) // 2] if nxt > fidx else av.frames[fidx]
        cells.append((label, rep))
    cols = 3
    import math
    rows = math.ceil(len(cells) / cols)
    cw, ch = 380, 240
    strip = Image.new("RGB", (cols*cw, rows*ch), (12, 15, 24))
    d = ImageDraw.Draw(strip)
    for i, (label, rep) in enumerate(cells):
        r = rep.convert("RGB").resize((cw-16, ch-40))
        x, y = (i % cols)*cw, (i // cols)*ch
        strip.paste(r, (x+8, y+30))
        d.text((x+10, y+8), "%d. %s" % (i+1, label), fill=(220, 220, 230))
    strip.save(os.path.join(WORK, "avatar_strip.png"))

    print("controls demonstrated:")
    for i, (_, label) in enumerate(marks):
        print("  %d. %s" % (i+1, label))
    print("\nfacing: M (mirror) = left/right   |   time: R (reverse) = rewind")
    print("frames driven:", len(av.frames))
    print("wrote avatar_demo.gif, avatar_strip.png under", WORK)


if __name__ == "__main__":
    main()
