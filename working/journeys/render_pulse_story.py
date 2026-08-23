#!/usr/bin/env python3
"""Render the pulse globe as a vertical Instagram-story clip.

The atlas's history as build_pulse_globe.py animates it, in render_story.py's
frame pipeline: every consecutive-stop leg fires in chronological order, a
gold gaussian crest decaying into the dim blue skeleton, on a translucent
shell tilted to the true obliquity and turning about its own axis. The year
sits alone in the upper left; there is no other chrome. Frames go to
pulse_story_frames/; encoding happens on nodus, which has ffmpeg.

  python3 render_pulse_story.py [--test]

Timing: 30 fps, 44 s of history, 8 s holding on the finished map (52 s).
Spin 1.25 rpm; obliquity 23.5 degrees, south pole toward the camera as in
render_story.py. --test renders three probe frames only.
"""
import glob, json, math, os, sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
HEAL = os.path.join(HERE, '..', 'heal_earth')
OUT = os.path.join(HERE, 'pulse_story_frames')

W, H = 1080, 1920
FPS = 30
HIST_S, HOLD_S = 44, 8
NFRAMES = FPS * (HIST_S + HOLD_S)
SPIN_RPM = 1.25
TILT = math.radians(-23.5)
PHASE0 = math.radians(226)        # open centered on Mesopotamia (44E), where history starts;
                                  # the 2026 hold then sweeps 196->256 deg, closing on Europe
CX, CY, R = W // 2, 830, 430      # story-safe geometry from render_story.py
SS = 2

BG = (11, 21, 38)
COAST = (143, 216, 244)           # the pulse page's coast blue
EMBER = np.array([56, 115, 191], dtype=np.float64)
GOLD = np.array([255, 199, 82], dtype=np.float64)
YEARCOL = (242, 193, 78)

RISE_W = 30.0                     # events; smoothstep half-width of materialization
SIG = 40.0                        # events; gaussian crest sigma (the page's history mode)
ACTIVE = 130.0                    # |dt| beyond which flash is invisible


def datekey(iso):
    if not iso:
        return None
    neg = iso.startswith('-')
    p = ((iso[1:] if neg else iso).split('-') + ['1', '1'])[:3]
    try:
        y, m, d = int(p[0]), int(p[1] or 1), int(p[2] or 1)
    except ValueError:
        return None
    frac = (m - 1) / 12.0 + (d - 1) / 372.0
    return (-y + frac) if neg else (y + frac)


def load_legs():
    legs = []
    for f in sorted(glob.glob(os.path.join(HERE, '*.journey.json'))):
        j = json.load(open(f))
        seq = []
        for seg in j.get('segments', []):
            for s in seg.get('stops', []):
                if isinstance(s.get('lat'), (int, float)):
                    seq.append((s['lat'], s['lng'], datekey(s.get('date', ''))))
        for (la1, lo1, k1), (la2, lo2, k2) in zip(seq, seq[1:]):
            k = k2 if k2 is not None else k1
            if k is None:
                continue
            if abs(la1 - la2) < 1e-6 and abs(lo1 - lo2) < 1e-6:
                continue
            legs.append((k, la1, lo1, la2, lo2))
    legs.sort(key=lambda l: l[0])
    return legs


def load_coast():
    topo = json.load(open(os.path.join(HEAL, 'land-50m.json')))
    sc, tr = topo['transform']['scale'], topo['transform']['translate']
    lines = []
    for arc in topo['arcs']:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sc[0] + tr[0], y * sc[1] + tr[1]))
        if len(pts) > 1:
            lines.append(np.array(pts, dtype=np.float64))
    lakes = json.load(open(os.path.join(HEAL, 'lakes_journey.geojson')))
    for feat in lakes['features']:
        for ring in feat['geometry']['coordinates']:
            lines.append(np.array(ring, dtype=np.float64))
    return lines


def unit(lat, lng):
    la, lo = math.radians(lat), math.radians(lng)
    return np.array([math.cos(la) * math.cos(lo), math.sin(la), -math.cos(la) * math.sin(lo)])


def rotY(v, t):
    c, s = math.cos(t), math.sin(t)
    x, y, z = v[..., 0], v[..., 1], v[..., 2]
    return np.stack([c * x + s * z, y, -s * x + c * z], axis=-1)


def rotX(v, t):
    c, s = math.cos(t), math.sin(t)
    x, y, z = v[..., 0], v[..., 1], v[..., 2]
    return np.stack([x, c * y - s * z, s * y + c * z], axis=-1)


def oriented(v, t):
    return rotX(rotY(v, t), TILT)


def project(v):
    x = CX * SS + v[..., 0] * R * SS
    y = CY * SS - v[..., 1] * R * SS
    return x, y, v[..., 2]


def smoothstep(e0, e1, x):
    t = np.clip((x - e0) / (e1 - e0), 0.0, 1.0)
    return t * t * (3 - 2 * t)


def year_label(y):
    return ('%d BC' % math.ceil(-y)) if y < 0 else ('%d' % math.floor(y))


def arc_points(va, vb, n=12):
    """Great-circle arc lifted off the shell, as the page draws a flashing leg."""
    ang = math.acos(max(-1.0, min(1.0, float(np.dot(va, vb))))) or 1e-4
    lift = 0.02 + 0.22 * ang / math.pi
    ts = np.linspace(0.0, 1.0, n)
    sa = np.sin((1 - ts) * ang)[:, None]
    sb = np.sin(ts * ang)[:, None]
    v = (va[None, :] * sa + vb[None, :] * sb) / math.sin(ang)
    v /= np.linalg.norm(v, axis=1)[:, None]
    v *= (1.008 + lift * np.sin(math.pi * ts))[:, None]
    return v


def main():
    test = '--test' in sys.argv
    os.makedirs(OUT, exist_ok=True)
    legs = load_legs()
    N = len(legs)
    YEARS = np.array([l[0] for l in legs])
    A = np.stack([unit(l[1], l[2]) for l in legs])     # (N,3) leg start
    B = np.stack([unit(l[3], l[4]) for l in legs])     # (N,3) leg end
    coast = load_coast()
    coast_v = [np.stack([np.cos(np.radians(a[:, 1])) * np.cos(np.radians(a[:, 0])),
                         np.sin(np.radians(a[:, 1])),
                         -np.cos(np.radians(a[:, 1])) * np.sin(np.radians(a[:, 0]))], axis=-1)
               for a in coast]
    print(f'{N} legs, span {YEARS[0]:.0f} .. {YEARS[-1]:.0f}; {len(coast_v)} coast arcs')

    try:
        font = ImageFont.truetype('/System/Library/Fonts/Supplemental/Georgia.ttf', 78)
    except OSError:
        font = ImageFont.truetype('/System/Library/Fonts/Menlo.ttc', 72, index=1)

    frames = [0, NFRAMES // 2, NFRAMES - 1] if test else range(NFRAMES)
    hist_frames = FPS * HIST_S
    for fi in frames:
        t = PHASE0 + 2 * math.pi * SPIN_RPM * fi / (60 * FPS)
        now = min(1.0, fi / (hist_frames - 1)) * (N - 1)

        dt = now - np.arange(N)
        rise = smoothstep(-RISE_W, RISE_W, dt)
        flash = np.exp(-dt * dt / (2 * SIG * SIG))
        alpha = 0.10 * rise + 0.9 * flash             # the page's history-mode envelope
        mix = flash[:, None]
        col = EMBER[None, :] * (1 - mix) + GOLD[None, :] * mix

        va = oriented(A, t)
        vb = oriented(B, t)
        xa, ya, za = project(va)
        xb, yb, zb = project(vb)
        zf = (za + zb) / 2
        active = np.nonzero((np.abs(dt) <= ACTIVE) & (rise > 0.001))[0]

        img = Image.new('RGB', (W * SS, H * SS), BG)
        d = ImageDraw.Draw(img, 'RGBA')

        def coastlines(front, a, w):
            for cv in coast_v:
                v = oriented(cv, t)
                x, y, z = project(v)
                vis = (z > 0) if front else (z <= 0)
                if not vis.any():
                    continue
                run = []
                for k in range(len(x)):
                    if vis[k]:
                        run.append((x[k], y[k]))
                    else:
                        if len(run) > 1:
                            d.line(run, fill=COAST + (a,), width=w)
                        run = []
                if len(run) > 1:
                    d.line(run, fill=COAST + (a,), width=w)

        def skeleton(front, scale):
            idx = np.nonzero((rise > 0.001) & ((zf > 0) == front))[0]
            for i in idx:
                if flash[i] > 0.02:
                    continue                          # the crest pass draws these
                a = int(255 * min(1.0, alpha[i]) * scale)
                if a < 2:
                    continue
                c = col[i]
                d.line([(xa[i], ya[i]), (xb[i], yb[i])],
                       fill=(int(c[0]), int(c[1]), int(c[2]), a), width=1 * SS)

        def crest(front, scale):
            idx = [i for i in active if flash[i] > 0.02 and (zf[i] > 0) == front]
            for i in sorted(idx, key=lambda i: flash[i]):
                v = arc_points(A[i], B[i])
                x, y, _ = project(oriented(v, t))
                pts = list(zip(x, y))
                c = col[i]
                a = int(255 * min(1.0, alpha[i]) * scale)
                halo = (int(c[0]), int(c[1]), int(c[2]), a // 4)
                d.line(pts, fill=halo, width=5 * SS)
                d.line(pts, fill=(int(c[0]), int(c[1]), int(c[2]), a), width=2 * SS)

        # the house layering: far side through the planet, shell, near side
        coastlines(False, 42, 1 * SS)
        skeleton(False, 0.55)
        crest(False, 0.55)
        d.ellipse([CX * SS - R * SS, CY * SS - R * SS, CX * SS + R * SS, CY * SS + R * SS],
                  fill=(18, 32, 56, 118), outline=(72, 96, 138, 255), width=1 * SS)
        coastlines(True, 150, 1 * SS)
        skeleton(True, 1.0)
        crest(True, 1.0)

        img = img.resize((W, H), Image.LANCZOS)
        d = ImageDraw.Draw(img, 'RGBA')
        yi = int(max(0, min(N - 1, math.floor(now))))
        d.text((64, 300), year_label(float(YEARS[yi])), font=font, fill=YEARCOL, anchor='lm')

        img.save(os.path.join(OUT, 'f%04d.png' % fi))
        if test or fi % 60 == 0:
            print('frame', fi, year_label(float(YEARS[yi])), flush=True)

    print('wrote frames to', OUT)


if __name__ == '__main__':
    main()
