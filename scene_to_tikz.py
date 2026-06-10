#!/usr/bin/env python3
"""scene_to_tikz — project a 0x3d scene to a 3D TikZ plate.

The cemetery scene (and scenes like it) carry no mesh geometry: each node
is a placed object — a textured quad (object_kind 'plane'), a celestial
skydome, a camera — with a translation, a scale, and an optional rotation
quaternion. That makes the scene *portable to vector*: given the camera's
position and field of view, every quad's four corners can be projected
through a pinhole camera to 2D, depth-sorted (painter's algorithm), and
drawn as TikZ. The result is a faithful perspective VIEW of the scene
reconstructed from the bytes — not a screenshot — cheap, scalable, and
inscribable as a 0x5c plate like every other artwork in the corpus.

Render modes:
  wire    — wireframe quads + labels (proves the projection geometry)
  photo   — straight-on camera view, quads filled with decoded photos
  vista   — THE composed plate: one oblique rectilinear camera, the grave
            row receding in true perspective (photos homography-warped
            into their projected quads), and the sidereal spin searched so
            the Winter Triangle + Orion stand in the sky above. No fisheye.
  skyward — companion look-up chart (normal-field, aimed at the Triangle)
  dome    — wireframe hemisphere overview with grave markers

Usage:
  .venv/bin/python scene_to_tikz.py <scene_txid> [wire|photo|vista|skyward|dome] [out.pdf]
"""
import os
import sys
import json
import math

REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import colegio_pipeline as P


# ----------------------------------------------------------------------
# Geometry — quaternion rotation + pinhole projection
# ----------------------------------------------------------------------

def _quat_to_matrix(q):
    """glTF quaternion (x, y, z, w) → 3×3 row-major rotation matrix."""
    x, y, z, w = q
    return [
        [1 - 2*(y*y + z*z), 2*(x*y - z*w),     2*(x*z + y*w)],
        [2*(x*y + z*w),     1 - 2*(x*x + z*z), 2*(y*z - x*w)],
        [2*(x*z - y*w),     2*(y*z + x*w),     1 - 2*(x*x + y*y)],
    ]


def _mat_vec(M, v):
    return [sum(M[i][j] * v[j] for j in range(3)) for i in range(3)]


def _vnorm(v):
    m = math.sqrt(sum(c*c for c in v)) or 1.0
    return [c/m for c in v]


def _vcross(a, b):
    return [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]]


def _vdot(a, b):
    return sum(x*y for x, y in zip(a, b))


def project_scene(gltf, *, aspect=1.55, near=0.02):
    """Project every 'plane' node of a parsed glTF scene through its camera.

    Returns (quads, meta) where each quad is a dict with:
        label, ref, ndc (4 (x,y) corner tuples in NDC), depth (mean camera
        distance), scale (the node's [sx, sy]).
    quads are sorted far→near for painter's-algorithm drawing.
    meta carries the camera position, fov, and the celestial skydome ref.

    The camera is taken as the node with object_kind 'camera'; it is
    assumed to look down −Z (glTF default, no camera rotation in the
    cemetery scene). NDC is the normalized device coordinate in [-1, 1]
    on each axis for points inside the frustum.
    """
    nodes = gltf.get("nodes", [])
    cam = next((n for n in nodes
                if n.get("extras", {}).get("object_kind") == "camera"), None)
    C = (cam or {}).get("translation", [0, 1.6, 4])
    fov_v = math.radians((cam or {}).get("extras", {}).get("fov_deg", 60))
    tan_half = math.tan(fov_v / 2.0)

    sky_node = next((n for n in nodes
                     if n.get("extras", {}).get("object_kind") == "celestial"), None)
    sky_ex = (sky_node or {}).get("extras", {})
    sky = sky_ex.get("quipu_ref")

    quads = []
    for n in nodes:
        ex = n.get("extras", {})
        if ex.get("object_kind") != "plane":
            continue
        T = n.get("translation", [0, 0, 0])
        S = n.get("scale", [1, 1, 1])
        q = n.get("rotation", [0, 0, 0, 1])
        M = _quat_to_matrix(q)
        hw, hh = S[0] / 2.0, S[1] / 2.0
        # local plane corners (CCW), facing +Z
        local = [(-hw, -hh, 0), (hw, -hh, 0), (hw, hh, 0), (-hw, hh, 0)]
        ndc, depths = [], []
        for (lx, ly, lz) in local:
            wp = _mat_vec(M, [lx, ly, lz])
            wx, wy, wz = wp[0] + T[0], wp[1] + T[1], wp[2] + T[2]
            vx, vy, vz = wx - C[0], wy - C[1], wz - C[2]
            d = -vz                      # camera looks −Z; depth is positive in front
            if d < near:
                d = near
            ndc.append(((vx / d) / (tan_half * aspect), (vy / d) / tan_half))
            depths.append(d)
        quads.append({
            "label": ex.get("label", n.get("name", "")),
            "ref":   ex.get("quipu_ref"),
            "ndc":   ndc,
            "depth": sum(depths) / 4.0,
            "scale": [S[0], S[1]],
        })
    quads.sort(key=lambda q: -q["depth"])     # far first (painter's algorithm)
    return quads, {
        "camera": C, "fov_deg": math.degrees(fov_v), "tan_half": tan_half,
        "sky": sky,
        "sky_lat": sky_ex.get("latitude_deg", 0.0),
        "sky_lst": sky_ex.get("initial_lst_deg", 0.0),
    }


# ----------------------------------------------------------------------
# Celestial backdrop — project the al-Jawza skydome through the camera
# ----------------------------------------------------------------------

def _ry(a):
    c, s = math.cos(a), math.sin(a)
    return [[c, 0, s], [0, 1, 0], [-s, 0, c]]


def _rx(a):
    c, s = math.cos(a), math.sin(a)
    return [[1, 0, 0], [0, c, -s], [0, s, c]]


def _radec_xyz(ra_deg, dec_deg, R=80.0):
    ra, dec = math.radians(ra_deg), math.radians(dec_deg)
    return [R*math.cos(dec)*math.cos(ra), R*math.sin(dec), -R*math.cos(dec)*math.sin(ra)]


# The WebGL walk colours each al-Jawza group by hue index (scene_viewer.py):
# HSL(i*36°, 0.42, 0.78). Mirror it here so the print dome matches the walk.
_GROUP_HUE_ORDER = ['Orion', 'Taurus', 'Winter Triangle', 'Lepus', 'Canis Minor',
                    'Canis Major', 'Pleiades', 'Monoceros', 'Canopus', 'Perseus']


def _hsl_to_rgb(h, s, l):
    import colorsys
    r, g, b = colorsys.hls_to_rgb(h, l, s)   # note: colorsys is H,L,S
    return (int(r*255), int(g*255), int(b*255))


def _group_color_hex(name):
    i = _GROUP_HUE_ORDER.index(name) if name in _GROUP_HUE_ORDER else 0
    return "%02X%02X%02X" % _hsl_to_rgb((i*36 % 360)/360.0, 0.42, 0.78)


def _view_project(world, C, pitch, tan_half, aspect):
    """Project a world point through the scene camera (at C, looking −Z),
    pitched UP by `pitch` radians so the dome fills the upper frame. Returns
    NDC (x, y) or None if behind the camera."""
    vx, vy, vz = world[0]-C[0], world[1]-C[1], world[2]-C[2]
    # rotate the view about camera-X by +pitch (forward axis tilts −Z → +Y)
    cp, sp = math.cos(pitch), math.sin(pitch)
    ry = vy*cp - vz*sp
    rz = vy*sp + vz*cp
    d = -rz
    if d <= 0.05:
        return None
    return ((vx/d)/(tan_half*aspect), (ry/d)/tan_half)


def project_sky(sky_ref, fetcher, meta, *, region):
    """Project the al-Jawza stars onto the true celestial sphere and through
    the scene camera — a curved perspective dome, not a flat chart. Each star
    sits at radec() on a sphere of radius 80 centred at eye height; the sphere
    is spun about its polar axis (advanced in sidereal time) until the
    constellation faces the camera, since at the scene's own epoch al-Jawza is
    outside the forward view. The view is pitched up so the dome arcs over the
    memorials. `region` (x0,y0,x1,y1) is the canvas band the dome maps into.
    Returns (stars, lines) in canvas coordinates."""
    from celestial import read_celestial_quipu
    from celestial_render import _split_concat
    blob = fetcher(sky_ref)
    h, b = _split_concat(blob)
    cel = read_celestial_quipu(h, b)
    pts = cel.get("points", [])
    if not pts:
        return [], []

    C = meta["camera"]
    # The sky gets a WIDE, planetarium-style field of view (the camera's own
    # 68° can't fit a constellation spanning ~90° of sky). A wide fov captures
    # al-Jawza whole and keeps the spherical curvature visible in the star
    # positions — a dome arcing overhead, not a flat chart.
    tan_half = math.tan(math.radians(150.0) / 2.0)
    aspect = _ASPECT
    pitch = math.radians(0.0)                  # level gaze — keeps southern Sirius in frame
    Rx = _rx(-math.radians(90.0 - meta["sky_lat"]))   # polar-axis tilt by co-latitude
    sphere = [_radec_xyz(p["ra"], p["dec"]) for p in pts]

    def world_at(lst_deg):
        Ry = _ry(math.radians(lst_deg))
        out = []
        for p in sphere:
            q = _mat_vec(Rx, _mat_vec(Ry, p))
            out.append([q[0], q[1] + 1.6, q[2]])
        return out

    # The Winter Triangle (Sirius, Betelgeuse, Procyon) is the figure the
    # cemetery sky is meant to show — all three must be in frame. Find its
    # three star indices so the sidereal-time search can be scored on framing
    # the triangle, not just on total star count.
    wt_idx = []
    for g in cel.get("groups", []):
        if g.get("name") == "Winter Triangle":
            wt_idx = [i for i in g.get("point_indices", []) if i < len(pts)]
            break

    def _in(p):
        return p is not None and -1.0 <= p[0] <= 1.0 and -1.0 <= p[1] <= 1.0

    # Advance sidereal time: pick the spin that frames the Winter Triangle —
    # all three corners in view, their centroid sitting low and centred — and,
    # among those, the one that brings the most surrounding stars along.
    best = None
    for lst in range(0, 360, 2):
        ndc = [_view_project(w, C, pitch, tan_half, aspect) for w in world_at(lst)]
        vis = [p for p in ndc if _in(p)]
        if not vis:
            continue
        wt = [ndc[i] for i in wt_idx]
        wt_seen = sum(1 for p in wt if _in(p))
        wt_vis = [p for p in wt if _in(p)]
        if wt_vis:
            wcx = sum(p[0] for p in wt_vis)/len(wt_vis)
            wcy = sum(p[1] for p in wt_vis)/len(wt_vis)
            wt_off = -(wcx*wcx + (wcy-0.3)**2)   # triangle centred, sitting a touch high so Sirius clears the photos
        else:
            wt_off = -9.9
        # all three corners first, then triangle centring, then total richness
        score = (wt_seen, wt_off, len(vis))
        if best is None or score > best[0]:
            best = (score, lst, ndc)
    if best is None:
        return [], []
    _, lst, ndc = best

    # Map NDC (the in-frame dome) into the canvas sky region. Clip to the
    # frame: stars whose NDC falls outside [-1.15, 1.15] are off-screen (a
    # perspective projection sends near-edge points to huge coordinates,
    # which would otherwise blow up the standalone bounding box).
    x0, y0, x1, y1 = region

    def to_canvas(p):
        if p is None or not (-1.15 <= p[0] <= 1.15 and -1.15 <= p[1] <= 1.15):
            return None
        return (x0 + (p[0]*0.5 + 0.5)*(x1-x0), y0 + (p[1]*0.5 + 0.5)*(y1-y0))

    canvas = [to_canvas(p) for p in ndc]

    # Per-group: in-frame stars, in-frame line segments, label centroid, and
    # the WebGL group colour. Groups (constellations) are what make the dome
    # identifiable; each is labelled at the centroid of its visible stars.
    groups = []
    for g in cel.get("groups", []):
        idxs = g.get("point_indices", [])
        gstars = [canvas[i] for i in idxs if i < len(canvas) and canvas[i]]
        glines = [(canvas[a], canvas[bx]) for (a, bx) in g.get("lines", [])
                  if a < len(canvas) and bx < len(canvas)
                  and canvas[a] and canvas[bx]]
        if not gstars:
            continue
        cx = sum(p[0] for p in gstars) / len(gstars)
        cy = sum(p[1] for p in gstars) / len(gstars)
        groups.append({
            "name": g.get("name", ""),
            "hex": _group_color_hex(g.get("name", "")),
            "stars": gstars,
            "lines": glines,
            "label": (cx, cy),
            "nvis": len(gstars),
        })
    return groups


def _lookat(eye, target, up_hint, fov_deg, aspect):
    """Return a perspective projector: world point -> NDC (x, y) or None if
    behind the camera. A right-handed look-at basis from `eye` toward
    `target`, `up_hint` resolving roll."""
    f = _vnorm([target[k] - eye[k] for k in range(3)])
    r = _vnorm(_vcross(f, up_hint))
    u = _vcross(r, f)
    tan_half = math.tan(math.radians(fov_deg) / 2.0)

    def proj(w):
        v = [w[k] - eye[k] for k in range(3)]
        cz = _vdot(v, f)
        if cz <= 0.02:
            return None
        return (_vdot(v, r) / cz / (tan_half * aspect), _vdot(v, u) / cz / tan_half)
    return proj


# ----------------------------------------------------------------------
# The celestial-dome view — the graves under a wireframe sky-dome, seen
# obliquely from the right so the dome arcs behind and over them.
# ----------------------------------------------------------------------

_DOME_W, _DOME_H = 13.0, 10.0
_GRAVES = [(-3.6, -2.0, "Sparkle"), (0.0, -3.11, "Peter Bea"), (3.6, -2.0, "Paco")]


def dome_tikz_body(txid, fetcher, *,
                   R=13.0, fov_deg=70.0,
                   eye=(15.0, 7.2, 9.0), target=(0.0, 4.2, -2.6)):
    """Lean into the dome. The al-Jawza skydome is drawn as a true wireframe
    hemisphere — parallels of altitude and meridians of azimuth — with the
    constellation stars and lines lying on its inner surface, and the three
    graves as small markers on the ground beneath. The camera stands to the
    RIGHT of the grave row and looks across it, so the dome arcs up behind
    and over the graves rather than facing the viewer flat. Returns
    (tikz_body, meta)."""
    blob = fetcher(txid)
    bs = blob.find(b"|{", 6)
    gltf = json.loads(blob[bs + 1:].decode("utf-8"))
    _, meta = project_scene(gltf, aspect=_DOME_W / _DOME_H)
    sky_ref = meta.get("sky")
    lat, lst = meta["sky_lat"], meta["sky_lst"]

    C0 = [0.0, 0.0, -2.6]                       # dome centre, on the ground
    proj = _lookat(list(eye), list(target), [0, 1, 0], fov_deg, _DOME_W / _DOME_H)

    def canv(p):
        if p is None or abs(p[0]) > 1.35 or abs(p[1]) > 1.35:
            return None
        return ((p[0] * 0.5 + 0.5) * _DOME_W, (p[1] * 0.5 + 0.5) * _DOME_H)

    def dome_pt(alt_deg, az_deg):
        a, z = math.radians(alt_deg), math.radians(az_deg)
        return [C0[0] + R*math.cos(a)*math.sin(z),
                C0[1] + R*math.sin(a),
                C0[2] + R*math.cos(a)*math.cos(z)]

    L = []
    # background + ground
    L.append("\\fill[skyfill] (0,0) rectangle (%.2f,%.2f);" % (_DOME_W, _DOME_H))

    # ---- wireframe dome: parallels (altitude rings) ----
    for alt in (0, 15, 30, 45, 60, 75):
        ring = []
        for az in range(0, 361, 6):
            c = canv(proj(dome_pt(alt, az)))
            ring.append(c)
        # emit as connected runs (skip None gaps)
        run = []
        for c in ring:
            if c:
                run.append(c)
            elif len(run) > 1:
                L.append("\\draw[domegrid] %s;" %
                         " -- ".join("(%.3f,%.3f)" % p for p in run))
                run = []
        if len(run) > 1:
            L.append("\\draw[domegrid] %s;" %
                     " -- ".join("(%.3f,%.3f)" % p for p in run))

    # ---- wireframe dome: meridians (azimuth arcs, horizon to zenith) ----
    for az in range(0, 360, 30):
        arc = [canv(proj(dome_pt(alt, az))) for alt in range(0, 91, 6)]
        run = []
        for c in arc:
            if c:
                run.append(c)
            elif len(run) > 1:
                L.append("\\draw[domegrid] %s;" %
                         " -- ".join("(%.3f,%.3f)" % p for p in run))
                run = []
        if len(run) > 1:
            L.append("\\draw[domegrid] %s;" %
                     " -- ".join("(%.3f,%.3f)" % p for p in run))

    # ---- stars + constellation lines, on the dome surface ----
    seen_hex = {}
    if sky_ref:
        from celestial import read_celestial_quipu
        from celestial_render import _split_concat
        h, b = _split_concat(fetcher(sky_ref))
        cel = read_celestial_quipu(h, b)
        pts = cel.get("points", [])
        Rx = _rx(-math.radians(90.0 - lat))
        Ry = _ry(math.radians(lst))

        def star_world(p):
            d = _vnorm(_mat_vec(Rx, _mat_vec(Ry, _radec_xyz(p["ra"], p["dec"], 1.0))))
            if d[1] <= 0.02:                    # below the horizon
                return None
            return [C0[0] + R*d[0], C0[1] + R*d[1], C0[2] + R*d[2]]

        cv = [canv(proj(w)) if w else None for w in (star_world(p) for p in pts)]
        for gi, g in enumerate(cel.get("groups", [])):
            cname = "grp%d" % gi
            seen_hex[cname] = _group_color_hex(g.get("name", ""))
            wt = g.get("name") == "Winter Triangle"
            for a, b2 in g.get("lines", []):
                if a < len(cv) and b2 < len(cv) and cv[a] and cv[b2]:
                    style = "wtline" if wt else ("skyline,draw=%s" % cname)
                    L.append("\\draw[%s] (%.3f,%.3f) -- (%.3f,%.3f);"
                             % (style, cv[a][0], cv[a][1], cv[b2][0], cv[b2][1]))
            for idx in g.get("point_indices", []):
                if idx < len(cv) and cv[idx]:
                    L.append("\\fill[%s] (%.3f,%.3f) circle (0.07);"
                             % (cname, cv[idx][0], cv[idx][1]))

    # ---- ground graves: upright headstones at the row, viewed obliquely ----
    # Each is a vertical slab (a quad facing +z) projected through the same
    # camera, so it sits in true perspective on the ground. Drawn far-first
    # (painter's order) by distance from the eye, and rounded at the top.
    gw, gh = 0.42, 0.9
    graves = sorted(_GRAVES, key=lambda g: -((g[0]-eye[0])**2 + (gh*0.5-eye[1])**2 + (g[1]-eye[2])**2))
    for gx, gz, name in graves:
        corners = [canv(proj([gx-gw, 0.0, gz])), canv(proj([gx+gw, 0.0, gz])),
                   canv(proj([gx+gw, gh,  gz])), canv(proj([gx-gw, gh,  gz]))]
        if all(corners):
            top = canv(proj([gx, gh + 0.22, gz]))
            poly = corners[:]                    # base-L, base-R, top-R, top-L
            L.append("\\fill[grave] %s -- cycle;"
                     % " -- ".join("(%.3f,%.3f)" % p for p in poly))
            if top:                              # a small rounded crown
                L.append("\\fill[grave] (%.3f,%.3f) -- (%.3f,%.3f) -- (%.3f,%.3f) -- cycle;"
                         % (corners[3][0], corners[3][1], top[0], top[1],
                            corners[2][0], corners[2][1]))
            L.append("\\draw[graveedge] %s -- cycle;"
                     % " -- ".join("(%.3f,%.3f)" % p for p in poly))
            bx = (corners[0][0] + corners[1][0]) / 2.0
            by = min(corners[0][1], corners[1][1])
            L.append("\\node[gravelabel] at (%.3f,%.3f) {%s};"
                     % (bx, by - 0.16, _tex_escape(name)))

    defs = ["\\definecolor{%s}{HTML}{%s}" % (c, h) for c, h in seen_hex.items()]
    L[:0] = defs
    return "\n".join(L), meta


# ----------------------------------------------------------------------
# The "look up" chart — a normal-field view aimed at the Winter Triangle
# ----------------------------------------------------------------------

_SKY_W, _SKY_H = 12.0, 9.0     # the look-up chart's own (squarer) canvas


def skyward_tikz_body(txid, fetcher, *, fov_deg=62.0):
    """The companion to the cemetery view: the sky as it reads when you tilt
    your head up in the live walk. A normal-field (≈62°) camera at the
    observer is aimed straight at the Winter Triangle with celestial north
    up, so Orion, Sirius and Procyon project at true scale with no fisheye
    warp. Stars and lines are group-tinted; the Winter Triangle is the gold
    focus. Returns (tikz_body, meta)."""
    blob = fetcher(txid)
    bs = blob.find(b"|{", 6)
    gltf = json.loads(blob[bs + 1:].decode("utf-8"))
    _, meta = project_scene(gltf, aspect=_SKY_W / _SKY_H)
    sky_ref = meta.get("sky")
    from celestial import read_celestial_quipu
    from celestial_render import _split_concat
    h, b = _split_concat(fetcher(sky_ref))
    cel = read_celestial_quipu(h, b)
    pts = cel.get("points", [])
    lat, lst = meta["sky_lat"], meta["sky_lst"]
    Rx = _rx(-math.radians(90.0 - lat))
    Ry = _ry(math.radians(lst))
    eye = [0.0, 1.6, 0.0]                              # observer at sphere centre

    def world(p):
        q = _mat_vec(Rx, _mat_vec(Ry, _radec_xyz(p["ra"], p["dec"])))
        return [q[0], q[1] + 1.6, q[2]]

    worlds = [world(p) for p in pts]

    # aim the camera at the Winter Triangle centroid, celestial north up
    wt = next((g for g in cel.get("groups", []) if g["name"] == "Winter Triangle"), None)
    aim = wt["point_indices"] if wt else list(range(len(worlds)))
    cen = [sum(worlds[i][k] for i in aim) / len(aim) for k in range(3)]
    f = _vnorm([cen[k] - eye[k] for k in range(3)])
    pole = _vnorm(_mat_vec(Rx, [0, 1, 0]))             # celestial north → up hint
    r = _vnorm(_vcross(f, pole))
    u = _vcross(r, f)
    aspect = _SKY_W / _SKY_H
    tan_half = math.tan(math.radians(fov_deg) / 2.0)

    def proj(w):
        v = [w[k] - eye[k] for k in range(3)]
        cz = _vdot(v, f)
        if cz <= 0.05:
            return None
        nx = _vdot(v, r) / cz / (tan_half * aspect)
        ny = _vdot(v, u) / cz / tan_half
        if not (-1.05 <= nx <= 1.05 and -1.05 <= ny <= 1.05):
            return None
        return ((nx * 0.5 + 0.5) * _SKY_W, (ny * 0.5 + 0.5) * _SKY_H)

    canvas = [proj(w) for w in worlds]

    groups = []
    for g in cel.get("groups", []):
        idxs = g.get("point_indices", [])
        gstars = [canvas[i] for i in idxs if i < len(canvas) and canvas[i]]
        glines = [(canvas[a], canvas[bx]) for (a, bx) in g.get("lines", [])
                  if a < len(canvas) and bx < len(canvas)
                  and canvas[a] and canvas[bx]]
        if not gstars:
            continue
        cx = sum(p[0] for p in gstars) / len(gstars)
        cy = sum(p[1] for p in gstars) / len(gstars)
        groups.append({"name": g.get("name", ""), "hex": _group_color_hex(g.get("name", "")),
                       "stars": gstars, "lines": glines, "label": (cx, cy),
                       "nvis": len(gstars)})

    L = ["\\fill[skyfill] (0,0) rectangle (%.2f,%.2f);" % (_SKY_W, _SKY_H)]
    seen_hex = {}
    for gi, g in enumerate(groups):
        cname = "grp%d" % gi
        seen_hex[cname] = g["hex"]
        if g["name"] == "Winter Triangle":
            for a, b2 in g["lines"]:
                L.append("\\draw[wtline] (%.3f,%.3f) -- (%.3f,%.3f);" % (a[0], a[1], b2[0], b2[1]))
        else:
            for a, b2 in g["lines"]:
                L.append("\\draw[skyline,draw=%s] (%.3f,%.3f) -- (%.3f,%.3f);"
                         % (cname, a[0], a[1], b2[0], b2[1]))
        for c in g["stars"]:
            L.append("\\fill[%s] (%.3f,%.3f) circle (0.07);" % (cname, c[0], c[1]))
    # labels: WT first (gold, always), then largest groups; drop colliders
    label_groups = [(gi, g) for gi, g in enumerate(groups)
                    if g["nvis"] >= 3 or g["name"] == "Winter Triangle"]
    label_groups.sort(key=lambda t: (t[1]["name"] != "Winter Triangle", -t[1]["nvis"]))
    DX, DY = 1.7, 0.42
    placed = []
    for gi, g in label_groups:
        lx, ly = g["label"][0], g["label"][1] + 0.34
        if any(abs(lx - px) < DX and abs(ly - py) < DY for px, py in placed):
            continue
        col = "wtgold" if g["name"] == "Winter Triangle" else "grp%d" % gi
        L.append("\\node[skylabelbig,text=%s] at (%.3f,%.3f) {%s};"
                 % (col, lx, ly, _tex_escape(g["name"])))
        placed.append((lx, ly))
    # label the three Triangle stars by name (Sirius / Betelgeuse / Procyon)
    name_of = {i: p["name"] for i, p in enumerate(pts)}
    if wt:
        for i in wt["point_indices"]:
            if i < len(canvas) and canvas[i]:
                cx, cy = canvas[i]
                L.append("\\node[starname] at (%.3f,%.3f) {%s};"
                         % (cx + 0.12, cy - 0.18, _tex_escape(name_of.get(i, ""))))
    defs = ["\\definecolor{%s}{HTML}{%s}" % (c, h) for c, h in seen_hex.items()]
    L[:0] = defs
    return "\n".join(L), meta


# ----------------------------------------------------------------------
# The vista — ONE image: across the graves, Winter Triangle + Orion above
# ----------------------------------------------------------------------
#
# The earlier attempts failed by trying to fit ALL of al-Jawza (~90°+ of
# sky) through one camera — forcing a 150° fisheye — or by splitting the
# scene into three partial views. But the picture the scene wants needs
# only Orion + the Winter Triangle: ~34° × 30° of sky, which fits a
# normal ~60° lens with room for the grave row below. So: one rectilinear
# look-at projector for everything (ground, photo quads, stars), an
# oblique eye to the right of the row, and the sidereal spin searched so
# exactly those two figures stand over the graves. No fisheye, no seams.

_VISTA_W, _VISTA_H = 14.0, 8.5


def _find_homography_coeffs(target_quad, source_quad):
    """PIL perspective coeffs mapping OUTPUT pixel coords -> INPUT pixel
    coords, from 4 corner correspondences (the standard 8x8 solve)."""
    import numpy as np
    A = []
    for (tx, ty), (sx, sy) in zip(target_quad, source_quad):
        A.append([tx, ty, 1, 0, 0, 0, -sx*tx, -sx*ty])
        A.append([0, 0, 0, tx, ty, 1, -sy*tx, -sy*ty])
    b = np.array([c for s in source_quad for c in s], dtype=float)
    return np.linalg.solve(np.array(A, dtype=float), b)


def _warp_photo(png_path, quad_cm, out_path, px_per_cm=110):
    """Perspective-warp a photo into its projected quad. quad_cm is the four
    canvas-space corners (BL, BR, TR, TL of the plane). Writes an RGBA PNG
    covering the quad's bounding box (transparent outside the quad) and
    returns (x0, y0, w, h) of that box in cm."""
    from PIL import Image
    im = Image.open(png_path).convert("RGBA")
    W, H = im.size
    xs = [p[0] for p in quad_cm]; ys = [p[1] for p in quad_cm]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    ow = max(2, int(round((x1 - x0) * px_per_cm)))
    oh = max(2, int(round((y1 - y0) * px_per_cm)))
    # output px coords (y down) of the quad corners
    tgt = [((px - x0) * px_per_cm, (y1 - py) * px_per_cm) for px, py in quad_cm]
    src = [(0, H), (W, H), (W, 0), (0, 0)]          # BL, BR, TR, TL
    coeffs = _find_homography_coeffs(tgt, src)
    warped = im.transform((ow, oh), Image.PERSPECTIVE, tuple(coeffs),
                          Image.BICUBIC, fillcolor=(0, 0, 0, 0))
    warped.save(out_path)
    return (x0, y0, x1 - x0, y1 - y0)


def vista_tikz_body(txid, fetcher, *, figdir=None,
                    eye=(4.6, 1.5, 1.6), target=(-1.8, 3.6, -3.0),
                    fov_deg=64.0, wt_aim=(0.08, 0.35)):
    """The single composed view: photo quads in true perspective along the
    receding grave row, Orion + the Winter Triangle in the sky above, one
    rectilinear projection throughout. Returns (tikz_body, meta)."""
    from celestial import read_celestial_quipu
    from celestial_render import _split_concat

    blob = fetcher(txid)
    bs = blob.find(b"|{", 6)
    gltf = json.loads(blob[bs + 1:].decode("utf-8"))
    nodes = gltf.get("nodes", [])
    sky_node = next((n for n in nodes
                     if n.get("extras", {}).get("object_kind") == "celestial"), None)
    sky_ex = (sky_node or {}).get("extras", {})
    lat = sky_ex.get("latitude_deg", 0.0)

    aspect = _VISTA_W / _VISTA_H
    proj = _lookat(list(eye), list(target), [0, 1, 0], fov_deg, aspect)

    def canv(p, lim=1.45):
        if p is None or abs(p[0]) > lim or abs(p[1]) > lim:
            return None
        return ((p[0] * 0.5 + 0.5) * _VISTA_W, (p[1] * 0.5 + 0.5) * _VISTA_H)

    L = []
    L.append("\\clip (0,0) rectangle (%.2f,%.2f);" % (_VISTA_W, _VISTA_H))
    L.append("\\fill[skyfill] (0,0) rectangle (%.2f,%.2f);" % (_VISTA_W, _VISTA_H))

    # ---- ground: fill below the horizon (directions with world-y = 0) ----
    horiz = []
    for t in range(0, 360, 2):
        d = (math.cos(math.radians(t)), 0.0, math.sin(math.radians(t)))
        p = proj([eye[0] + 4000*d[0], eye[1], eye[2] + 4000*d[2]])
        c = canv(p, lim=3.0)
        if c:
            horiz.append(c)
    if horiz:
        horiz.sort(key=lambda c: c[0])
        hline = [(max(0, min(_VISTA_W, x)), y) for x, y in horiz]
        ground = [(0.0, 0.0)] + hline + [(_VISTA_W, 0.0)]
        L.append("\\fill[groundfill] %s -- cycle;"
                 % " -- ".join("(%.3f,%.3f)" % p for p in ground))
        band = hline + [(x, y - 0.55) for x, y in reversed(hline)]
        L.append("\\fill[groundglow] %s -- cycle;"
                 % " -- ".join("(%.3f,%.3f)" % p for p in band))

    # ---- sky: spin the sphere so Orion + the Triangle stand over the row ----
    sky_ref = sky_ex.get("quipu_ref")
    star_lines, star_dots, star_labels = [], [], []
    chosen_lst, wt_seen, ori_seen = None, 0, 0
    if sky_ref:
        h, b = _split_concat(fetcher(sky_ref))
        cel = read_celestial_quipu(h, b)
        pts = cel.get("points", [])
        groups = cel.get("groups", [])
        Rx = _rx(-math.radians(90.0 - lat))
        unit = [_radec_xyz(p["ra"], p["dec"], 1.0) for p in pts]

        gi_of = {g.get("name"): g for g in groups}
        wt_idx = gi_of.get("Winter Triangle", {}).get("point_indices", [])
        ori_idx = gi_of.get("Orion", {}).get("point_indices", [])
        key_idx = wt_idx + ori_idx

        def ndc_at(lst_deg):
            Ry = _ry(math.radians(lst_deg))
            out = []
            for u0 in unit:
                d = _mat_vec(Rx, _mat_vec(Ry, u0))
                if d[1] <= 0.015:                   # below the horizon
                    out.append(None); continue
                out.append(proj([eye[0] + 3000*d[0], eye[1] + 3000*d[1],
                                 eye[2] + 3000*d[2]]))
            return out

        def _in(p, m=0.93):
            return p is not None and abs(p[0]) <= m and abs(p[1]) <= m

        best = None
        for lst in range(0, 360):
            nd = ndc_at(lst)
            wt_in = sum(1 for i in wt_idx if _in(nd[i]))
            kin = sum(1 for i in key_idx if _in(nd[i]))
            kv = [nd[i] for i in key_idx if _in(nd[i])]
            if not kv:
                continue
            cx = sum(p[0] for p in kv) / len(kv)
            cy = sum(p[1] for p in kv) / len(kv)
            off = -((cx - wt_aim[0])**2 + (cy - wt_aim[1])**2)
            nall = sum(1 for p in nd if _in(p, 1.0))
            score = (wt_in, kin, off, nall)     # the Triangle is never sacrificed
            if best is None or score > best[0]:
                best = (score, lst, nd)
        if best:
            (_, chosen_lst, nd) = best
            cv = [canv(p, lim=1.05) for p in nd]
            wt_seen = sum(1 for i in wt_idx if cv[i])
            ori_seen = sum(1 for i in ori_idx if cv[i])
            for g in groups:
                name = g.get("name", "")
                main = name in ("Orion", "Winter Triangle")
                for a, b2 in g.get("lines", []):
                    if a < len(cv) and b2 < len(cv) and cv[a] and cv[b2]:
                        sty = ("wtline" if name == "Winter Triangle"
                               else ("oriline" if name == "Orion" else "skyline"))
                        star_lines.append("\\draw[%s] (%.3f,%.3f) -- (%.3f,%.3f);"
                                          % (sty, cv[a][0], cv[a][1],
                                             cv[b2][0], cv[b2][1]))
                for i in g.get("point_indices", []):
                    if i < len(cv) and cv[i]:
                        r = 0.085 if (i in wt_idx) else (0.062 if main else 0.038)
                        col = "wtgold" if i in wt_idx else ("oric" if main else "star")
                        star_dots.append("\\fill[%s] (%.3f,%.3f) circle (%.3f);"
                                         % (col, cv[i][0], cv[i][1], r))
            # name the three Triangle corners + Rigel; label Orion
            names = {p["name"]: i for i, p in enumerate(pts)}
            for nm in ("Sirius", "Betelgeuse", "Procyon", "Rigel"):
                i = names.get(nm)
                if i is not None and i < len(cv) and cv[i]:
                    star_labels.append("\\node[starname] at (%.3f,%.3f) {%s};"
                                       % (cv[i][0] + 0.14, cv[i][1] - 0.05,
                                          _tex_escape(nm)))
            ovis = [cv[i] for i in ori_idx if cv[i]]
            if len(ovis) >= 5:
                ox = sum(p[0] for p in ovis)/len(ovis)
                oy = max(p[1] for p in ovis) + 0.30
                star_labels.append("\\node[skylabelbig,text=oric] at (%.3f,%.3f) "
                                   "{Orion};" % (ox, oy))
    L += star_lines + star_dots + star_labels

    # ---- the grave row: photo quads in true perspective ----
    quads = []
    for n in nodes:
        ex = n.get("extras", {})
        if ex.get("object_kind") != "plane":
            continue
        T = n.get("translation", [0, 0, 0])
        S = n.get("scale", [1, 1, 1])
        M = _quat_to_matrix(n.get("rotation", [0, 0, 0, 1]))
        hw, hh = S[0]/2.0, S[1]/2.0
        local = [(-hw, -hh, 0), (hw, -hh, 0), (hw, hh, 0), (-hw, hh, 0)]
        world = []
        for lx, ly, lz in local:
            wp = _mat_vec(M, [lx, ly, lz])
            world.append([wp[0]+T[0], wp[1]+T[1], wp[2]+T[2]])
        cc = [canv(proj(w), lim=1.6) for w in world]
        if not all(cc):
            continue
        depth = sum((w[0]-eye[0])**2 + (w[1]-eye[1])**2 + (w[2]-eye[2])**2
                    for w in world) / 4.0
        quads.append({"label": ex.get("label", ""), "ref": ex.get("quipu_ref"),
                      "cm": cc, "depth": depth, "wx": T[0], "ws": S[0]})
    quads.sort(key=lambda q: -q["depth"])           # far first

    captions = []
    for qd in quads:
        cm = qd["cm"]
        cx = sum(p[0] for p in cm)/4.0; cy = sum(p[1] for p in cm)/4.0
        frame = [(cx + (p[0]-cx)*1.10, cy + (p[1]-cy)*1.10) for p in cm]
        L.append("\\fill[frame] %s -- cycle;"
                 % " -- ".join("(%.3f,%.3f)" % p for p in frame))
        png = None
        if qd["ref"] and figdir:
            try:
                src = P.target_to_png(qd["ref"], fetcher, figdir)
                if src:
                    wname = "vista_%s.png" % qd["ref"][:12]
                    box = _warp_photo(os.path.join(figdir, src), cm,
                                      os.path.join(figdir, wname))
                    L.append("\\node[anchor=south west,inner sep=0] at (%.3f,%.3f)"
                             " {\\includegraphics[width=%.3fcm,height=%.3fcm]"
                             "{figures/%s}};"
                             % (box[0], box[1], box[2], box[3], wname[:-4]))
                    png = wname
            except Exception as e:                   # noqa: BLE001
                P._logwarn("vista/photo", e, txid=str(qd["ref"]))
        if not png:
            L.append("\\fill[platefill] %s -- cycle;"
                     % " -- ".join("(%.3f,%.3f)" % p for p in cm))
        L.append("\\draw[frameedge] %s -- cycle;"
                 % " -- ".join("(%.3f,%.3f)" % p for p in frame))
        captions.append({"x": cx, "ybase": min(p[1] for p in frame) - 0.16,
                         "w": qd["ws"],          # WORLD width: the grave's main photo
                         "wx": qd["wx"], "text": _short_label(qd["label"])})

    # one caption per grave cluster (cluster by WORLD x, the triptych is one)
    captions.sort(key=lambda c: c["wx"])
    clusters, cur = [], []
    for c in captions:
        if cur and abs(c["wx"] - cur[-1]["wx"]) < 1.5:
            cur.append(c)
        else:
            if cur:
                clusters.append(cur)
            cur = [c]
    if cur:
        clusters.append(cur)
    for cl in clusters:
        keep = max(cl, key=lambda c: c["w"])
        L.append("\\node[platecaption] at (%.3f,%.3f) {%s};"
                 % (keep["x"], keep["ybase"], _tex_escape(keep["text"])))

    meta = {"camera": list(eye), "fov_deg": fov_deg, "sky": sky_ref,
            "lst": chosen_lst, "wt_in_frame": wt_seen, "orion_in_frame": ori_seen,
            "quads_drawn": len(quads)}
    return "\n".join(L), meta


# ----------------------------------------------------------------------
# TikZ emission
# ----------------------------------------------------------------------

# A landscape canvas; NDC [-1,1] maps to ±HALF_W / ±HALF_H about the centre.
_CANVAS_W, _CANVAS_H = 14.0, 9.0
_HALF_W, _HALF_H = _CANVAS_W / 2, _CANVAS_H / 2
_ASPECT = _CANVAS_W / _CANVAS_H


def _ndc_to_canvas(p):
    """NDC (x, y) in [-1,1] → TikZ canvas coords centred on the page."""
    return (_HALF_W + p[0] * _HALF_W, _HALF_H + p[1] * _HALF_H)


def _poly(corners):
    return " -- ".join("(%.3f,%.3f)" % _ndc_to_canvas(c) for c in corners) + " -- cycle"


def scene_tikz_body(txid, fetcher, *, mode="wire", figdir=None):
    """Return the TikZ body (the picture's contents) for a scene's camera
    view. `mode` is 'wire', 'photo', or 'skyward'. For 'photo', decoded image
    PNGs are written to figdir and referenced via \\includegraphics in a clip.
    'skyward' returns the companion look-up sky chart instead of the camera
    view."""
    if mode == "skyward":
        return skyward_tikz_body(txid, fetcher)
    if mode == "dome":
        return dome_tikz_body(txid, fetcher)
    if mode == "vista":
        return vista_tikz_body(txid, fetcher, figdir=figdir)
    blob = fetcher(txid)
    bs = blob.find(b"|{", 6)
    gltf = json.loads(blob[bs + 1:].decode("utf-8"))
    quads, meta = project_scene(gltf, aspect=_ASPECT)

    L = []
    # backdrop — night sky + dark ground band
    L.append("\\fill[skyfill] (0,0) rectangle (%.2f,%.2f);" % (_CANVAS_W, _CANVAS_H))
    L.append("\\fill[groundfill] (0,0) rectangle (%.2f,%.2f);"
             % (_CANVAS_W, _HALF_H * 0.62))

    # A quiet, sparse starfield — atmosphere only. The recognizable sky (the
    # al-Jawza figure, the Winter Triangle) lives in its own "look up" chart
    # (skyward_tikz_body) and in the celestial charts of *The Celestial
    # Quipu*; this camera view's job is the memorial wall, so the sky here is
    # just a scatter of faint stars, not a fisheye projection of the dome.
    import random
    rng = random.Random(0xCE)
    pts = [(rng.uniform(0.3, _CANVAS_W-0.3), rng.uniform(_HALF_H*0.66, _CANVAS_H-0.3))
           for _ in range(52)]
    L.append("\\foreach \\x/\\y in {%s} { \\fill[star] (\\x,\\y) circle (0.028); }"
             % ", ".join("%.2f/%.2f" % s for s in pts))

    captions = []   # (x, y_top_of_placard, text) — emitted after, de-collided
    for i, qd in enumerate(quads):
        outer = qd["ndc"]
        # frame: scale corners out from their centroid by 1.12 (the WebGL backboard)
        cx = sum(p[0] for p in outer) / 4.0
        cy = sum(p[1] for p in outer) / 4.0
        frame = [(cx + (p[0]-cx)*1.12, cy + (p[1]-cy)*1.12) for p in outer]
        if mode == "photo" and qd["ref"] and figdir:
            png = None
            try:
                png = P.target_to_png(qd["ref"], fetcher, figdir)
            except Exception as e:
                P._logwarn("scene_to_tikz/photo", e, txid=qd["ref"])
            if png:
                # frame board, then clip the photo into the projected quad
                L.append("\\fill[frame] %s;" % _poly(frame))
                cc = [_ndc_to_canvas(p) for p in outer]
                # bounding box of the projected quad for the includegraphics
                xs = [p[0] for p in cc]; ys = [p[1] for p in cc]
                x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
                L.append("\\begin{scope}")
                L.append("  \\clip %s;" % _poly(outer))
                L.append("  \\node[anchor=south west,inner sep=0] at (%.3f,%.3f) "
                         "{\\includegraphics[width=%.3fcm,height=%.3fcm]{figures/%s}};"
                         % (x0, y0, x1 - x0, y1 - y0, png[:-4]))
                L.append("\\end{scope}")
                L.append("\\draw[frameedge] %s;" % _poly(frame))
                # gravestone caption: collect now (with projected width); one
                # caption per grave-cluster is kept later (the widest/dominant
                # photo), so a multi-photo grave like Peter's triptych shows a
                # single name, not one label per photo.
                fxs = [c[0] for c in (_ndc_to_canvas(p) for p in frame)]
                fys = [c[1] for c in (_ndc_to_canvas(p) for p in frame)]
                captions.append({
                    "x": (min(fxs) + max(fxs)) / 2.0,
                    "y": min(fys) - 0.18,
                    "w": max(fxs) - min(fxs),
                    "text": _short_label(qd["label"]),
                })
                continue
        # wire mode (or photo fallback): frame + quad + label
        L.append("\\fill[frame] %s;" % _poly(frame))
        L.append("\\fill[platefill] %s;" % _poly(outer))
        L.append("\\draw[frameedge] %s;" % _poly(outer))
        lc = _ndc_to_canvas((cx, cy))
        L.append("\\node[platelabel] at (%.3f,%.3f) {%s};"
                 % (lc[0], lc[1], _tex_escape(qd["label"][:18])))

    # One caption per grave-cluster: group captions whose centres fall within
    # CLUSTER_GAP of each other (a grave with several photos), and keep only
    # the widest (the dominant, centremost photo). So Peter's central triptych
    # captions collapse to the single "Peter Bea"; the isolated Sparkle and
    # Paco each keep their own.
    CLUSTER_GAP = 1.6
    caps = sorted(captions, key=lambda c: c["x"])
    clusters, cur = [], []
    for c in caps:
        if cur and (c["x"] - cur[-1]["x"]) < CLUSTER_GAP:
            cur.append(c)
        else:
            if cur:
                clusters.append(cur)
            cur = [c]
    if cur:
        clusters.append(cur)
    for cl in clusters:
        keep = max(cl, key=lambda c: c["w"])      # widest = dominant photo
        L.append("\\node[platecaption] at (%.3f,%.3f) {%s};"
                 % (keep["x"], keep["y"], _tex_escape(keep["text"])))

    return "\n".join(L), meta


def _short_label(s):
    """A gravestone-placard label: short labels pass through; long sentence
    labels (the 'This was Peter on her blanket…' kind) clip to a name-length
    fragment so the placard stays small under the photo."""
    s = (s or "").strip()
    return s if len(s) <= 16 else s[:15].rstrip() + "…"


def _tex_escape(s):
    for a, b in [("\\", "\\textbackslash{}"), ("&", "\\&"), ("%", "\\%"),
                 ("_", "\\_"), ("#", "\\#"), ("{", "\\{"), ("}", "\\}")]:
        s = s.replace(a, b)
    return s


_DOC = r"""\documentclass[tikz,border=4mm]{standalone}
\usepackage[utf8]{inputenc}\usepackage[T1]{fontenc}\usepackage{tikz}\usepackage{xcolor}\usepackage{graphicx}
\definecolor{skyfill}{HTML}{0d1430}
\definecolor{groundfill}{HTML}{14110a}
\definecolor{star}{HTML}{f4ead8}
\definecolor{frame}{HTML}{c2a76b}
\definecolor{frameedge}{HTML}{1a1a1a}
\definecolor{platefill}{HTML}{e8dcc0}
\definecolor{platelabelc}{HTML}{1a1a1a}
\definecolor{skylinec}{HTML}{3a4a72}
\definecolor{wtgold}{HTML}{c2a76b}
\definecolor{domegridc}{HTML}{4a5a82}
\definecolor{gravec}{HTML}{3b3a36}
\definecolor{oric}{HTML}{9fb4e8}
\definecolor{groundglow}{HTML}{201a10}
\definecolor{graveedgec}{HTML}{8a8780}
\definecolor{captionc}{HTML}{e8dcc0}
\tikzset{
  frameedge/.style={draw=frameedge,line width=0.6pt},
  skyline/.style={draw=skylinec,line width=0.5pt,opacity=0.85},
  wtline/.style={draw=wtgold,line width=0.7pt,opacity=0.9,dash pattern=on 2pt off 1.6pt},
  skylabel/.style={font=\sffamily\fontsize{6}{7}\selectfont,opacity=0.9,
                   anchor=south},
  skylabelbig/.style={font=\sffamily\fontsize{9}{11}\selectfont,opacity=0.95,
                      anchor=south},
  starname/.style={font=\sffamily\fontsize{6.5}{8}\selectfont,color=star,
                   opacity=0.85,anchor=west},
  domegrid/.style={draw=domegridc,line width=0.35pt,opacity=0.55},
  oriline/.style={draw=oric,line width=0.55pt,opacity=0.9},
  grave/.style={fill=gravec,draw=none},
  graveedge/.style={draw=graveedgec,line width=0.5pt},
  gravelabel/.style={font=\sffamily\fontsize{6.5}{8}\selectfont,color=star,
                     anchor=north},
  platelabel/.style={font=\sffamily\scriptsize,color=platelabelc,align=center},
  platecaption/.style={font=\sffamily\fontsize{5.5}{6.5}\selectfont,
                       color=captionc,align=center},
  captionleader/.style={draw=captionc,line width=0.3pt,opacity=0.5},
}
\begin{document}
\begin{tikzpicture}[x=1cm,y=1cm]
%s
\end{tikzpicture}
\end{document}
"""


def build_plate_tex(txid, fetcher=None, *, mode="wire", figdir=None):
    fetcher = fetcher or P.chained_fetcher()
    body, meta = scene_tikz_body(txid, fetcher, mode=mode, figdir=figdir)
    return _DOC % body, meta


def scene_to_png(txid, fetcher, figdir, *, mode="photo"):
    """Render a 0x3d scene to a projected-view PNG in `figdir`, returning the
    basename (or None on failure). Mirrors target_to_png for 0x03/0xce: the
    scene is the inscription, this projected camera-view is its render. The
    referenced photo quipus are materialised into `figdir` (so the plate's
    \\includegraphics resolve), the TikZ is compiled to PDF in a workdir whose
    figures/ points at figdir, and the PDF is rasterised to PNG."""
    import subprocess, tempfile, shutil
    os.makedirs(figdir, exist_ok=True)
    base = f"scene_{txid[:12]}_{mode}_v{getattr(P, '_FIGURE_CACHE_VERSION', 0)}.png"
    out = os.path.join(figdir, base)
    if os.path.exists(out):
        return base
    # build_plate_tex(photo) materialises each photo PNG into figdir
    tex, _meta = build_plate_tex(txid, fetcher, mode=mode, figdir=figdir)
    work = tempfile.mkdtemp(prefix="quipu_scene_")
    try:
        # make figdir reachable as ./figures from the compile dir
        link = os.path.join(work, "figures")
        try:
            os.symlink(os.path.abspath(figdir), link)
        except (OSError, NotImplementedError):
            shutil.copytree(figdir, link)
        with open(os.path.join(work, "scene.tex"), "w", encoding="utf-8") as f:
            f.write(tex)
        r = subprocess.run(["xelatex", "-interaction=nonstopmode", "-halt-on-error",
                            "scene.tex"], cwd=work, capture_output=True, text=True,
                           timeout=120)
        pdf = os.path.join(work, "scene.pdf")
        if not os.path.exists(pdf):
            P._logwarn("scene_to_png/compile",
                       RuntimeError(r.stdout[-400:]), txid=txid)
            return None
        # rasterise PDF → PNG via PyMuPDF
        import fitz
        doc = fitz.open(pdf)
        doc[0].get_pixmap(dpi=200).save(out)
        return base
    except Exception as e:
        P._logwarn("scene_to_png", e, txid=txid)
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _main(argv):
    if not argv:
        print(__doc__); return
    import subprocess
    txid = argv[0]
    mode = argv[1] if len(argv) > 1 else "wire"
    out  = argv[2] if len(argv) > 2 else os.path.join("/tmp", f"scene_{mode}.pdf")
    work = os.path.dirname(out) or "."
    figdir = os.path.join(work, "figures")
    os.makedirs(figdir, exist_ok=True)
    fetcher = P.chained_fetcher()
    tex, meta = build_plate_tex(txid, fetcher, mode=mode, figdir=figdir)
    print("meta:", {k: (v[:16] if isinstance(v, str) else v) for k, v in meta.items()})
    with open(os.path.join(work, "scene_plate.tex"), "w", encoding="utf-8") as f:
        f.write(tex)
    r = subprocess.run(["xelatex", "-interaction=nonstopmode", "-halt-on-error",
                        "scene_plate.tex"], cwd=work, capture_output=True, text=True)
    produced = os.path.join(work, "scene_plate.pdf")
    if os.path.exists(produced):
        os.replace(produced, out)
        print("wrote", out, os.path.getsize(out), "bytes")
    else:
        sys.stderr.write(r.stdout[-2500:])
        sys.stderr.write("\nCOMPILE FAILED\n")


if __name__ == "__main__":
    _main(sys.argv[1:])
