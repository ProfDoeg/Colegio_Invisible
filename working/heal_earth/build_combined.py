#!/usr/bin/env python3
"""Heal the orrery's Earth — build the combined journey+coastline quipu.

The Dantean Cosmos' earth sphere refs the Italian Journey quipu
(762043aa…). The 3D viewer has always drawn a world coastline on that
globe, but the coastline lived in a local asset, never on chain — and
the journey's own sixth group is named "Lacuna of Lago di Lugano": the
inscription recorded the missing lake by name. This stage builds ONE
combined 0xce earth quipu that fills the lacuna:

    points[0:K]   the Italian Journey, byte-faithful (names, times,
                  campa texts, traveler ref — indices unchanged)
    points[K:]    50m world-coastline ring vertices + the journey's five
                  lakes at 10m (Garda, Maggiore, Como, Lugano, Iseo)
    groups[0:6]   the journey's six groups, exactly as inscribed
    groups[6:]    one group per ring — coasts unnamed, lakes NAMED
                  (incl. "Lago Maggiore - Verbano", correcting Natural
                  Earth's upstream mislabel of Maggiore as Como)

so that the healing binding

    <<762043aa… (journey)>> = <<combined>>

resolves the orrery's Earth to its full surface for binding-aware
readers, while the original journey stays on chain untouched. Same
primitive, same ethics as the phantom-sky heal: nothing altered, the
corpus heals by addition.

Run:    .venv/bin/python working/heal_earth/build_combined.py
Output: working/heal_earth/artifacts/earth_combined.0xce.bin (+ report)
"""
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "canonical"))

import colegio_pipeline as P
from celestial import build_grouped_celestial_quipu, read_celestial_quipu
from celestial_render import _split_concat

JOURNEY = "762043aaaed3fd92d3e129aa94ffb53753ad0e98a58f3fd7ab816379c13de9c4"
ORRERY = "1fa3a4b90af9b7ac61cb7713b3fe26d20d2e9d65da86ac00343e4115438bddb8"

# Sources (Natural Earth, committed beside this script):
#   land-50m.json          — 50m world land, TopoJSON (world-atlas)
#   lakes_journey.geojson  — the journey's five lakes at 10m, extracted from
#       ne_10m_lakes + ne_10m_lakes_europe with Maggiore's upstream mislabel
#       ("Lago di Como" on Maggiore's water) corrected — see its `note`.
LAND_TOPO = os.path.join(HERE, "land-50m.json")
LAKES_GEOJSON = os.path.join(HERE, "lakes_journey.geojson")


def land_rings(path):
    """Closed land rings (lng,lat) from a TopoJSON land file."""
    topo = json.load(open(path))
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]

    def dec(arc):
        o, x, y = [], 0, 0
        for d in arc:
            x += d[0]; y += d[1]
            o.append((x * sx + tx, y * sy + ty))
        return o

    arcs = [dec(a) for a in topo["arcs"]]

    def ring(ids):
        pts = []
        for aid in ids:
            a = list(reversed(arcs[~aid])) if aid < 0 else arcs[aid]
            pts += a[1:] if (pts and pts[-1] == a[0]) else a
        if pts and pts[0] == pts[-1]:
            pts = pts[:-1]                      # closed implicitly by ring edges
        return pts

    rings = []
    for obj in topo["objects"].values():
        for geom in (obj.get("geometries") or [obj]):
            if geom["type"] == "Polygon":
                rings += [ring(r) for r in geom["arcs"]]
            elif geom["type"] == "MultiPolygon":
                for poly in geom["arcs"]:
                    rings += [ring(r) for r in poly]
    return [r for r in rings if len(r) >= 3]


def lake_rings():
    """(name, ring) pairs for the journey's five lakes — named groups, so
    the names ride the chain with the shapes."""
    out = []
    g = json.load(open(LAKES_GEOJSON))
    for f in g["features"]:
        geom = f["geometry"]
        name = f["properties"]["name"]
        rings = (geom["coordinates"] if geom["type"] == "Polygon"
                 else [r for p in geom["coordinates"] for r in p])
        for ri, r in enumerate(rings):
            pts = [(c[0], c[1]) for c in r]
            if pts and pts[0] == pts[-1]:
                pts = pts[:-1]
            if len(pts) >= 3:
                out.append((name if ri == 0 else "", pts))
    return out


def main():
    land_path = LAND_TOPO
    if not os.path.exists(land_path):
        sys.exit("missing %s — fetch world-atlas land-50m.json" % land_path)

    # fetch the journey RAW — never through the correction lens. A heal must
    # layer on the original inscription; reading through corrections here
    # would bake any prior heal into the new one (and after THIS heal goes
    # live, would bake the combined into itself on a re-run).
    fetch = P.chained_fetcher()
    h, b = _split_concat(fetch(JOURNEY))
    jou = read_celestial_quipu(h, b)
    jpts, jgroups = jou["points"], jou["groups"]
    K = len(jpts)

    points = []
    for p in jpts:                              # journey first, indices stable
        q = {"name": p.get("name", ""), "lat": p["lat"], "lng": p["lng"]}
        for k in ("time", "time_precision", "more"):
            if p.get(k) is not None:
                q[k] = p[k]
        if q.get("more") and q.get("time") is not None:
            # the builder re-appends ('date','date',time) from pt['time'];
            # strip the reader's copy so it isn't doubled
            q["more"] = [m for m in q["more"]
                         if not (m[0] == "date" and m[1] == "date"
                                 and float(m[2]) == float(q["time"]))]
        points.append(q)

    groups = [(g.get("name", ""), list(g.get("point_indices", [])),
               [tuple(l) for l in g.get("lines", [])]) for g in jgroups]

    def add_ring(name, r):
        base = len(points)
        n = len(r)
        for lng, lat in r:
            points.append({"name": "", "lat": round(lat, 4), "lng": round(lng, 4)})
        idxs = list(range(base, base + n))
        lines = [(base + k, base + (k + 1) % n) for k in range(n)]
        groups.append((name, idxs, lines))

    rings = land_rings(land_path)
    for r in rings:                              # coasts: unnamed groups
        add_ring("", r)
    lakes = lake_rings()
    for name, r in lakes:                        # lakes: named groups
        add_ring(name, r)

    h2, b2 = build_grouped_celestial_quipu(
        "Earth — the Italian Journey upon the world's coasts and lakes",
        "earth", points, groups, tone=jou.get("tone", 0))

    # verify: decode and check the journey survived byte-faithfully
    back = read_celestial_quipu(h2, b2)
    for i, (a, c) in enumerate(zip(jpts, back["points"][:K])):
        assert a["lat"] == c["lat"] and a["lng"] == c["lng"], f"point {i} drifted"
        assert a.get("name", "") == c.get("name", ""), f"point {i} name drifted"
        assert a.get("more") == c.get("more"), f"point {i} more drifted"
    for i, (a, c) in enumerate(zip(jgroups, back["groups"][:len(jgroups)])):
        assert list(a.get("lines", [])) == list(c.get("lines", [])), f"group {i} drifted"

    os.makedirs(os.path.join(HERE, "artifacts"), exist_ok=True)
    out = os.path.join(HERE, "artifacts", "earth_combined.0xce.bin")
    open(out, "wb").write(h2 + b2)
    total = len(h2) + len(b2)
    print("journey: %d points, %d groups (verified byte-faithful)" % (K, len(jgroups)))
    print("coast+lakes: %d rings, %d points (%s)" %
          (len(rings), len(points) - K, os.path.basename(land_path)))
    print("combined: %d points, %d groups, %d bytes (~%d knots) -> %s"
          % (len(points), len(groups), total, math.ceil(total / 80), out))


if __name__ == "__main__":
    main()
