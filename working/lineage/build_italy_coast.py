"""Extract the land/sea for the Italian-Journey map from the orrery's world-land
TopoJSON (working/cosmos/_land.json) and inscribe it as an earth-0xce coastline
quipu — CLOSED land polygons clipped (Sutherland–Hodgman) to the map window, so
the renderer can fill land vs. water. Points = ring vertices; lines = closed-ring
edges. The renderer (coast mode) fills sea over the window, fills the land rings,
and strokes the coast.

  python working/lineage/build_italy_coast.py
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO); sys.path.insert(0, os.path.join(REPO, "canonical"))
from canonical.celestial import build_celestial_quipu

WIN = (5.0, 36.0, 20.0, 52.0)        # lng0, lat0, lng1, lat1 — covers the banner's map area

topo = json.load(open(os.path.join(REPO, "working/cosmos/_land.json")))
tr = topo["transform"]; (sx, sy) = tr["scale"]; (tx, ty) = tr["translate"]
def dec(arc):
    o = []; x = y = 0
    for d in arc:
        x += d[0]; y += d[1]; o.append((x * sx + tx, y * sy + ty))
    return o
arcs = [dec(a) for a in topo["arcs"]]
def ring(ids):
    pts = []
    for aid in ids:
        a = list(reversed(arcs[~aid])) if aid < 0 else arcs[aid]
        pts += a[1:] if (pts and pts[-1] == a[0]) else a
    return pts
land = topo["objects"]["land"]
geoms = land.get("geometries", [land])
worldrings = []
for g in geoms:
    if g["type"] == "Polygon":
        worldrings += [ring(r) for r in g["arcs"]]
    elif g["type"] == "MultiPolygon":
        for poly in g["arcs"]:
            worldrings += [ring(r) for r in poly]

def clip(poly, win):                 # Sutherland–Hodgman against a rectangle
    x0, y0, x1, y1 = win
    def edge(pts, ins, inter):
        out = []
        for i in range(len(pts)):
            a, b = pts[i], pts[(i + 1) % len(pts)]
            ia, ib = ins(a), ins(b)
            if ia:
                out.append(a)
                if not ib: out.append(inter(a, b))
            elif ib:
                out.append(inter(a, b))
        return out
    p = poly
    p = edge(p, lambda q: q[0] >= x0, lambda a, b: (x0, a[1] + (b[1]-a[1])*(x0-a[0])/(b[0]-a[0])))
    if p: p = edge(p, lambda q: q[0] <= x1, lambda a, b: (x1, a[1] + (b[1]-a[1])*(x1-a[0])/(b[0]-a[0])))
    if p: p = edge(p, lambda q: q[1] >= y0, lambda a, b: (a[0] + (b[0]-a[0])*(y0-a[1])/(b[1]-a[1]), y0))
    if p: p = edge(p, lambda q: q[1] <= y1, lambda a, b: (a[0] + (b[0]-a[0])*(y1-a[1])/(b[1]-a[1]), y1))
    return p

points, lines = [], []
nrings = 0
for r in worldrings:
    c = clip(r, WIN)
    if len(c) < 3:
        continue
    nrings += 1
    base = len(points)
    for (lng, lat) in c:
        points.append({"name": "", "lat": round(lat, 4), "lng": round(lng, 4)})
    n = len(c)
    for k in range(n):
        lines.append((base + k, base + (k + 1) % n))     # closed ring

h, b = build_celestial_quipu("Italy & Mediterranean — land/sea (world-land, clipped)",
                             "earth", points, lines, tone=2)
out = os.path.join(HERE, "italy_coast.0xce.bin")
open(out, "wb").write(h + b)
print("coast 0xce: %d rings, %d points, %d edges, %d B -> %s"
      % (nrings, len(points), len(lines), len(h + b), out))
