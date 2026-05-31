#!/usr/bin/env python3
"""Faithful offline replica of avatar_trueplayer (see SYSTEM.md).

Plays the REAL recording frame-by-frame (accumulator +/-1), and only at tagged
pose frames consults coll-map to weighted-random pick an edge -> cut (to_frame),
direction (time), mirror (space). Movement/locomotion is in the pixels; we never
move a billboard by hand. Composites each played frame on the curtain+floor stage
and writes an mp4 (+ a contact strip).

Run:  .venv/bin/python working/avatari/offline_player.py
"""
import os
import sys
import random
import subprocess
import tempfile
import shutil

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import explore as E

MOVIE = "caity1png.mov"
CRUMBS = "caity_super_pcrumbs.txt"
MAP = "caity_map.txt"
FFMPEG = "/usr/local/bin/ffmpeg"

FPS = 30
SECONDS = 30
CONTROL = 1            # active command: 1 = ambient pool
SEED = 7
PAD = 240             # drift room each side of the dancer frame on the stage


def extract_all(movie, cache):
    """Dump every frame of the movie (RGBA) to a STABLE cache dir as 1-indexed
    pngs (skip if already extracted — re-extraction is slow)."""
    os.makedirs(cache, exist_ok=True)
    have = sorted(f for f in os.listdir(cache) if f.startswith("f_"))
    if len(have) > 100:
        return have
    subprocess.run([FFMPEG, "-v", "error", "-i", os.path.join(E.SRCDIR, movie),
                    "-vf", "format=rgba", "-vsync", "0",
                    os.path.join(cache, "f_%04d.png")], check=True)
    return sorted(f for f in os.listdir(cache) if f.startswith("f_"))


def simulate(nodes_frames, graph, nframes, ticks):
    """Run the real engine loop. Returns a list of (frame, mirror) per tick."""
    rng = random.Random(SEED)
    node_set = set(graph)
    # start at a tagged frame near centre stage
    N = min(nodes_frames, key=lambda f: abs(f - 0))  # any node; refined below
    N = nodes_frames[0]
    d = 1
    mirror = False
    path = []
    for _ in range(ticks):
        N += d
        if N < 0:
            N = 0; d = 1
        elif N >= nframes:
            N = nframes - 1; d = -1
        if N in node_set:                       # tagged pose -> map_reader
            es = [e for e in graph[N] if e["control"] == CONTROL and e["weight"] > 0]
            if es:
                tot = sum(e["weight"] for e in es)
                r = rng.uniform(0, tot)
                pick = es[-1]
                for e in es:
                    r -= e["weight"]
                    if r <= 0:
                        pick = e; break
                N = pick["dst"]
                d = 1 if pick["time"] == 1 else -1
                if pick["space"] == 2:
                    mirror = not mirror
        path.append((N, mirror))
    return path


def build_stage(dancer_w, dancer_h):
    """Curtain backdrop + floor band, wide enough for the dancer to drift."""
    head, foot = 30, 70
    W, H = dancer_w + PAD * 2, dancer_h + head + foot
    curtain = Image.open(os.path.join(E.SRCDIR, "curtain.jpg")).convert("RGB").resize((W, H))
    floor = Image.open(os.path.join(E.SRCDIR, "floor.jpg")).convert("RGB").resize((W, foot + 60))
    stage = curtain.copy()
    stage.paste(floor, (0, H - (foot + 60)))
    return stage, head


def main():
    crumbs = E.parse_crumbs(os.path.join(E.SRCDIR, CRUMBS))
    graph = E.parse_map(os.path.join(E.SRCDIR, MAP))
    nodes_frames = sorted(graph)
    print("nodes %d   playing control=%d for %ds @ %dfps"
          % (len(nodes_frames), CONTROL, SECONDS, FPS))

    tmp = os.path.join(HERE, "_allframes")
    files = extract_all(MOVIE, tmp)
    nframes = len(files)
    print("frames available %d" % nframes)

    path = simulate(nodes_frames, graph, nframes, FPS * SECONDS)
    cuts = sum(1 for i in range(1, len(path))
               if abs(path[i][0] - path[i - 1][0]) > 1 or path[i][1] != path[i - 1][1])
    visited = sorted({f for f, _ in path})
    print("ticks %d   distinct frames visited %d   cuts %d"
          % (len(path), len(visited), cuts))

    sample = Image.open(os.path.join(tmp, files[0])).convert("RGBA")
    stage, oy = build_stage(sample.width, sample.height)
    W = sample.width
    stageW = stage.width
    cache, cx = {}, {}

    def load(f):
        if f not in cache:
            im = Image.open(os.path.join(tmp, files[f])).convert("RGBA")
            cache[f] = im
            cx[f] = E.centroid_x(im)            # body centroid (fraction of frame)
        return cache[f]

    def disp_cx(f, mir):                          # centroid as displayed (mirror-aware)
        load(f)
        return (1 - cx[f]) if mir else cx[f]

    # videoplane offset: only at jump cuts, shift by the centroid difference so the
    # body is continuous across the splice (and locomotion accumulates).
    offsets = []
    off = 0.0
    prev = None
    for (f, mir) in path:
        cd = disp_cx(f, mir)
        if prev is not None:
            pf, pmir, pcd = prev
            if abs(f - pf) > 1 or mir != pmir:    # a cut
                off += (pcd - cd) * W
        paste_x = PAD + off
        paste_x = max(0, min(stageW - W, paste_x))   # keep the frame on stage
        off = paste_x - PAD                          # write back (no runaway drift)
        offsets.append(int(round(paste_x)))
        prev = (f, mir, cd)

    out_tmp = tempfile.mkdtemp(prefix="avp_render_")
    strip = []
    strip_at = {int(len(path) * k) for k in (0.06, 0.27, 0.5, 0.73, 0.93)}
    for i, (f, mir) in enumerate(path):
        dancer = load(f)
        if mir:
            dancer = dancer.transpose(Image.FLIP_LEFT_RIGHT)
        frame = stage.convert("RGBA")
        frame.alpha_composite(dancer, (offsets[i], oy))
        frame.convert("RGB").save(os.path.join(out_tmp, "r_%05d.png" % i))
        if i in strip_at:
            strip.append(frame.convert("RGB"))

    if strip:
        sw = strip[0].width // 2
        sheet = Image.new("RGB", (sw * len(strip), strip[0].height // 2), (8, 8, 12))
        for k, s in enumerate(strip):
            sheet.paste(s.resize((sw, s.height // 2)), (k * sw, 0))
        sheet.save(os.path.join(HERE, "caity_offline_strip.png"))

    out = os.path.join(HERE, "caity_offline.mp4")
    subprocess.run([FFMPEG, "-v", "error", "-y", "-framerate", str(FPS),
                    "-i", os.path.join(out_tmp, "r_%05d.png"),
                    "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2",
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", out], check=True)

    shutil.rmtree(out_tmp, ignore_errors=True)   # keep _allframes cache for reuse
    print("wrote caity_offline.mp4 + caity_offline_strip.png")


if __name__ == "__main__":
    main()
