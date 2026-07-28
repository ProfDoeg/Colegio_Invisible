#!/usr/bin/env python3
"""Render the atlas as a vertical Instagram-story reel.

Same data and palette as build_atlas_globe.py: the heal_earth 50m coastline,
the corrected lakes, and every *.journey.json stop drawn as a through-planet
chord. Orthographic projection, back hemisphere culled, globe spinning on a
vertical axis.

Writes PNG frames to frames/. Encoding to mp4 happens on nodus, which has
ffmpeg; this machine does not.

  python3 render_story.py [--frames N] [--es]
"""
import json, glob, math, os, sys
import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
HEAL = os.path.join(HERE, '..', 'heal_earth')
SRC = os.path.join(HERE, 'es') if '--es' in sys.argv else HERE
OUT = os.path.join(HERE, 'story_frames')

W, H = 1080, 1920
NFRAMES = 300
for i, a in enumerate(sys.argv):
    if a == '--frames':
        NFRAMES = int(sys.argv[i + 1])

BG = (11, 21, 38)
COAST = (143, 163, 200)
STOP = (255, 242, 208)
PAL = [0xf2c14e, 0x5aa9e6, 0x37c2a8, 0xe86a92, 0xc9a15a, 0x9b8cff, 0xf08a4b, 0xd8c26a,
       0x7bd389, 0xdd7373, 0x6fc3df, 0xb583d6, 0xe0b153, 0x64b6ac, 0xd98cb3, 0xa3c46a]
PAL = [((c >> 16) & 255, (c >> 8) & 255, c & 255) for c in PAL]

# Globe geometry. Story-safe: Instagram covers roughly the top and bottom 250px,
# and the link sticker wants a clear band low in the frame.
CX, CY, R = W // 2, 830, 430
SS = 2  # supersample factor for antialiasing


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


def load_journeys():
    out = []
    for f in sorted(glob.glob(os.path.join(SRC, '*.journey.json'))):
        j = json.load(open(f))
        pts = []
        for seg in j.get('segments', []):
            for st in seg.get('stops', []):
                lat, lng = st.get('lat'), st.get('lng')
                if lat is None or lng is None:
                    continue
                pts.append((float(lat), float(lng)))
        if len(pts) > 1:
            out.append((j.get('traveler', ''), pts))
    return out


def unit(lat, lng):
    la, lo = math.radians(lat), math.radians(lng)
    return np.array([math.cos(la) * math.cos(lo), math.sin(la), -math.cos(la) * math.sin(lo)])


def rotY(v, t):
    c, s = math.cos(t), math.sin(t)
    x, y, z = v[..., 0], v[..., 1], v[..., 2]
    return np.stack([c * x + s * z, y, -s * x + c * z], axis=-1)


# Axial tilt, applied AFTER the spin so the globe turns about its own inclined
# axis rather than about the screen vertical. Negative leans the SOUTH pole
# toward the camera: southern hemisphere summer, with the viewer standing in
# for the sun. Check: the south pole (0,-1,0) maps to z = -sin(TILT) > 0, i.e.
# out of the screen, toward us.
TILT = math.radians(-23.4)


def rotX(v, t):
    c, s = math.cos(t), math.sin(t)
    x, y, z = v[..., 0], v[..., 1], v[..., 2]
    return np.stack([x, c * y - s * z, s * y + c * z], axis=-1)


def oriented(v, t):
    return rotX(rotY(v, t), TILT)


def project(v):
    """Orthographic. Returns screen xy and the z depth (>0 = front hemisphere)."""
    x = CX * SS + v[..., 0] * R * SS
    y = CY * SS - v[..., 1] * R * SS
    return x, y, v[..., 2]


def main():
    os.makedirs(OUT, exist_ok=True)
    coast = load_coast()
    journeys = load_journeys()
    print(f'{len(coast)} coast arcs, {len(journeys)} journeys')

    coast_v = [np.stack([np.cos(np.radians(a[:, 1])) * np.cos(np.radians(a[:, 0])),
                         np.sin(np.radians(a[:, 1])),
                         -np.cos(np.radians(a[:, 1])) * np.sin(np.radians(a[:, 0]))], axis=-1)
               for a in coast]
    jour_v = [(name, np.stack([unit(la, ln) for la, ln in pts])) for name, pts in journeys]

    formula = None
    fpath = os.path.join(HERE, 'story_formula.png')
    if os.path.exists(fpath):
        formula = Image.open(fpath).convert('RGBA')
        target = 560
        formula = formula.resize((target, round(formula.height * target / formula.width)),
                                 Image.LANCZOS)

    fbase = '/System/Library/Fonts/Menlo.ttc'
    f_title = ImageFont.truetype(fbase, 62 * SS, index=1)
    f_sub = ImageFont.truetype(fbase, 30 * SS, index=0)
    f_small = ImageFont.truetype(fbase, 24 * SS, index=0)

    # open the loop on the Mediterranean, where the corpus is densest; a spin
    # that starts over the empty Pacific wastes the first seconds of a story
    PHASE0 = 3 * math.pi / 2

    # Spin rate is fixed at one revolution per SPIN_FRAMES, deliberately NOT
    # tied to the clip length: change NFRAMES to make the reel longer and the
    # globe keeps turning at the same speed instead of speeding up or slowing
    # down to fit. 300 frames at 30 fps is one turn per 10 s.
    SPIN_FRAMES = 300

    for fi in range(NFRAMES):
        t = PHASE0 + 2 * math.pi * fi / SPIN_FRAMES
        img = Image.new('RGB', (W * SS, H * SS), BG)
        d = ImageDraw.Draw(img, 'RGBA')


        # The globe is a TRANSLUCENT shell, as in build_atlas_globe.py: the far
        # side is drawn first, the shell frosts it, and the near side goes on
        # top. That is what lets you read a fan like the Rio de la Plata's from
        # the inside, through the planet, instead of losing it behind an opaque
        # ball. Layer order is the whole trick.

        def polyline(cv, front, colour, alpha, width):
            v = oriented(cv, t)
            x, y, z = project(v)
            vis = (z > 0) if front else (z <= 0)
            if not vis.any():
                return
            run = []
            for k in range(len(x)):
                if vis[k]:
                    run.append((x[k], y[k]))
                else:
                    if len(run) > 1:
                        d.line(run, fill=colour + (alpha,), width=width)
                    run = []
            if len(run) > 1:
                d.line(run, fill=colour + (alpha,), width=width)

        def chords(front, alpha, width, dot_alpha):
            for ji, (_, jv) in enumerate(jour_v):
                col = PAL[ji % len(PAL)]
                v = oriented(jv, t)
                x, y, z = project(v)
                for k in range(len(x) - 1):
                    zf = (z[k] + z[k + 1]) / 2
                    if (zf > 0) != front:
                        continue
                    d.line([(x[k], y[k]), (x[k + 1], y[k + 1])], fill=col + (alpha,), width=width)
                if dot_alpha:
                    r = (2.2 if front else 1.6) * SS
                    for k in range(len(x)):
                        if (z[k] > 0) == front:
                            d.ellipse([x[k] - r, y[k] - r, x[k] + r, y[k] + r],
                                      fill=STOP + (dot_alpha,))

        # 1. the far side, seen through the planet
        for cv in coast_v:
            polyline(cv, False, COAST, 42, 1 * SS)
        chords(False, 120, 1 * SS, 90)

        # 2. the shell itself, translucent enough to read through
        d.ellipse([CX * SS - R * SS, CY * SS - R * SS, CX * SS + R * SS, CY * SS + R * SS],
                  fill=(18, 32, 56, 118), outline=(72, 96, 138, 255), width=1 * SS)

        # 3. the near side. Held well below full strength: at full opacity the
        # near chords glare and flatten the globe into a plate of coloured
        # string. Depth now comes mostly from line WIDTH (2px near vs 1px far)
        # rather than from brightness, which keeps the far side readable.
        for cv in coast_v:
            polyline(cv, True, COAST, 178, 1 * SS)
        chords(True, 150, 2 * SS, 185)

        img = img.resize((W, H), Image.LANCZOS)
        d = ImageDraw.Draw(img, 'RGBA')

        # wordmark, monospace to match the site
        d.text((W // 2, 300), 'COLEGIO INVISIBLE',
               font=ImageFont.truetype(fbase, 46, index=1), fill=(240, 236, 226), anchor='mm')
        d.text((W // 2, 356), 'el atlas',
               font=ImageFont.truetype(fbase, 30, index=0), fill=(242, 193, 78), anchor='mm')

        # The description is the formula, not a tally: a scene taken against the
        # indexed family of celestial quipu. The index set is left unnamed on
        # purpose, so the card states what the atlas IS rather than how big it
        # is today. Typeset by XeLaTeX, keyed to alpha (see build_formula.sh).
        if formula is not None:
            img.paste(formula, (W // 2 - formula.width // 2, 1340 - formula.height // 2), formula)

        # y 1450-1700 deliberately left empty for the link sticker

        img.save(os.path.join(OUT, 'f%04d.png' % fi))
        if fi % 25 == 0:
            print('frame', fi, flush=True)

    print('wrote', NFRAMES, 'frames to', OUT)


if __name__ == '__main__':
    main()
