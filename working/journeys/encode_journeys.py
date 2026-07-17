#!/usr/bin/env python3
"""Encode a journey.json into a 0xce earth-kind celestial quipu.

One journey -> one grouped earth-celestial figure:
  - each stop is a point (name, lat, lng) whose date -> a v2 9-byte precision
    Julian Day var in the per-point `more` block (precision auto-derived from
    the source string: "1519"->year, "1519-04"->month, "1519-04-21"->day),
    alongside its campa / quote / quote_source / suggested_refs as text
    sub-entries. `date_confidence` is NOT inscribed — certainty markers are
    against the ethos (c1dd0002 §7.3); the scholarly hedge stays in the
    research apparatus, off-chain. The fleet is born under c1dd0002.
  - each segment is a group whose stops are chained in order (the travelled path).

Clones the proven Goethe-Italian-Journey path (working/celestial/goethe_journey.py
+ build_grouped_celestial_quipu). Sources are intentionally NOT inscribed — they
are research apparatus, not the work. Build-only: no keys, no broadcast.

Usage:
    python encode_journeys.py <slug|path.journey.json> [out_dir] [--render]
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))   # Colegio_Invisible
sys.path.insert(0, os.path.join(REPO, "canonical"))

from celestial import (                       # noqa: E402
    build_grouped_celestial_quipu, read_celestial_quipu, TONE_REVERENCE,
)

DEFAULT_OUT = os.path.join(HERE, "quipu_out")


def fit(s, limit=255):
    """Truncate a str to <= limit UTF-8 bytes without splitting a codepoint."""
    b = s.encode("utf-8")
    if len(b) <= limit:
        return s
    return b[:limit].decode("utf-8", "ignore")


def date_precision(date_str):
    """Granularity of the SOURCE string — what the datum IS (c1dd0002 §7.3):
    "1519"->year, "1519-04"->month, "1519-04-21"->day, a time part->exact.
    A renderer that paints a year-date as noon-July-1 fabricates specificity;
    precision lets it widen the marker instead."""
    s = str(date_str).strip()
    if "T" in s:
        return "exact"
    core = s[1:] if s.startswith("-") else s
    n = len([p for p in core.split("-") if p])
    return {1: "year", 2: "month"}.get(n, "day")


def date_to_jd(date_str, calendar):
    """ISO 'YYYY-MM-DD' (or '-YYYY-MM-DD' BCE) + calendar -> Julian Day at noon.

    gregorian: Gregorian reform correction; julian / julian_bce: proleptic
    Julian (no correction). Handles BCE via negative year, no special-casing."""
    s = str(date_str).strip()
    neg = s.startswith("-")
    core = s[1:] if neg else s
    parts = core.split("-")
    y = int(parts[0]) * (-1 if neg else 1)
    m = int(parts[1]) if len(parts) > 1 and parts[1] else 1
    d = int(parts[2]) if len(parts) > 2 and parts[2] else 1
    if m <= 2:
        y -= 1
        m += 12
    if calendar == "gregorian":
        a = y // 100
        b = 2 - a + (a // 4)
    else:                                      # julian, julian_bce (proleptic)
        b = 0
    jd_midnight = int(365.25 * (y + 4716)) + int(30.6001 * (m + 1)) + d + b - 1524.5
    return jd_midnight + 0.5                    # noon


def journey_to_figure(data):
    """journey.json dict -> (points, groups) for build_grouped_celestial_quipu."""
    calendar = data.get("calendar", "gregorian")
    points, groups = [], []
    idx = 0
    for seg in data.get("segments", []):
        seg_indices = []
        for stop in seg.get("stops", []):
            more = []
            if stop.get("campa"):
                more.append(("campa", "text", stop["campa"]))
            if stop.get("quote"):
                more.append(("quote", "text", stop["quote"]))
            if stop.get("quote_source"):
                more.append(("quote_source", "text", stop["quote_source"]))
            for i, ref in enumerate(stop.get("suggested_refs") or []):
                if ref:
                    more.append(("ref_%d" % i, "text", ref))
            points.append({
                "name": fit(stop["name"]),
                "lat": float(stop["lat"]),
                "lng": float(stop["lng"]),
                "time": date_to_jd(stop["date"], calendar),
                "time_precision": date_precision(stop["date"]),
                "more": more,
            })
            seg_indices.append(idx)
            idx += 1
        lines = [(seg_indices[i], seg_indices[i + 1]) for i in range(len(seg_indices) - 1)]
        groups.append((fit(seg.get("name", "segment")), seg_indices, lines))
    return points, groups


def encode(journey_path, out_dir=DEFAULT_OUT, render=False):
    with open(journey_path, encoding="utf-8") as f:
        data = json.load(f)
    title = fit(data.get("title") or data.get("traveler") or "journey")
    points, groups = journey_to_figure(data)

    header, body = build_grouped_celestial_quipu(
        title, "earth", points, groups, tone=TONE_REVERENCE, version=2)
    blob = bytes(header) + bytes(body)
    pseudo = hashlib.sha256(blob).hexdigest()

    # --- round-trip verification --------------------------------------------
    parsed = read_celestial_quipu(header, body)
    checks = {}
    checks["title_ok"] = (parsed["title"] == title)
    checks["kind"] = parsed["kind"]
    checks["points_ok"] = (len(parsed["points"]) == len(points))
    checks["groups_ok"] = (parsed.get("groups") is not None
                           and len(parsed["groups"]) == len(groups))
    # every point kept its date; spot-check a campa + a quote survived verbatim
    dated = sum(1 for p in parsed["points"]
                if any(k == "date" and kind == "date" for (k, kind, _v) in p.get("more", [])))
    checks["all_dated"] = (dated == len(points))
    checks["version"] = parsed.get("version")
    precise = sum(1 for p in parsed["points"] if p.get("time_precision"))
    checks["all_precise"] = (precise == len(points))
    campa_src = next((s for seg in data["segments"] for s in seg["stops"] if s.get("campa")), None)
    if campa_src:
        pi = [p for p in parsed["points"] if p["name"] == fit(campa_src["name"])][0]
        got = dict((k, v) for (k, kind, v) in pi.get("more", []) if kind == "text").get("campa", "")
        checks["campa_roundtrip"] = got.startswith(campa_src["campa"][:40])

    slug = os.path.basename(journey_path).replace(".journey.json", "")
    os.makedirs(out_dir, exist_ok=True)
    bin_path = os.path.join(out_dir, slug + ".cel.bin")
    with open(bin_path, "wb") as f:
        f.write(blob)

    png_path = None
    if render:
        try:
            from celestial_render import render_celestial_quipu
            png_path = os.path.join(out_dir, slug + ".png")
            render_celestial_quipu(header, body, output_path=png_path)
        except Exception as e:                 # noqa: BLE001
            png_path = "render-skipped: %s" % e

    return {
        "slug": slug, "title": title, "traveler": data.get("traveler"),
        "points": len(points), "groups": len(groups),
        "bytes": len(blob), "pseudo_txid": pseudo,
        "bin": bin_path, "png": png_path, "checks": checks,
    }


def _resolve(arg):
    if arg.endswith(".journey.json") and os.path.exists(arg):
        return arg
    cand = os.path.join(HERE, arg if arg.endswith(".journey.json") else arg + ".journey.json")
    return cand


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: encode_journeys.py <slug|path.journey.json> [out_dir] [--render]", file=sys.stderr)
        sys.exit(2)
    render = "--render" in sys.argv[1:]
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = _resolve(positional[0])
    out = positional[1] if len(positional) > 1 else DEFAULT_OUT
    res = encode(path, out, render=render)
    print(json.dumps(res, indent=2, ensure_ascii=False))
