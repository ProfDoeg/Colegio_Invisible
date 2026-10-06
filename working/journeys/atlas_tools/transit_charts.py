#!/usr/bin/env python3
"""Transit charts: the sky of every day-precise stop, and its transits to the subject's natal chart.

    python3 atlas_tools/transit_charts.py                 # every journey -> zodiac/transits/<slug>.transits.{json,md}
    python3 atlas_tools/transit_charts.py <slug> ...      # some journeys (the atlas index is written only on a full run)
    python3 atlas_tools/transit_charts.py --check         # Kennedy at Dallas, Wagner at Venice, the Saturn-return scan

Inputs: zodiac/<slug>.zodiac.json (zodiac_readings.py: which stops are day-precise, their JD) and, for the
journeys whose birth is day-precise, zodiac/charts/<slug>.chart.json (natal_chart.py).

Per day-precise stop, at 0h UT of the civil date (no time of day is known for events; the Moon moves ~13 deg
a day, so its transits are good to that):
  1. the transit sky: Sun..Pluto and the mean nodes with sign, degree, minute, speed, retrograde flag, and the
     aspects among the transiting bodies (same aspects and orbs as natal_chart.py: 8 luminaries, 6 planets,
     3 nodes, the smaller of a pair);
  2. when the natal chart exists: every aspect between a transiting body and a natal body or point, with the
     transit orbs 3 deg for Sun/Moon/Mercury/Venus/Mars, 2 for Jupiter/Saturn, 1.5 for Uranus/Neptune/Pluto,
     2 for the transiting nodes and 2 at most to a natal node; the natal solar house (whole-sign from the natal
     Sun) of each transiting body, and its Placidus house when the natal chart is timed; the returns (Sun within
     3 deg of the natal Sun = within about three days of the birthday; Moon within 13 deg; Mercury, Venus,
     Mars, Jupiter, Saturn and the node within 3 deg); the Moon's phase (transiting Moon from the transiting
     Sun) and the Moon's angle from the natal Sun; the age in years and days; and a weight: the number of
     exact (<1 deg) transit aspects to the natal Sun, Moon, Ascendant and MC.
Everything is computed; nothing is interpreted.

The index zodiac/transits/_atlas_transits.md lists the solar-, Saturn- and Jupiter-return stops, the fifty
heaviest stops, and the most frequent transit aspects to natal Suns.
"""
import glob
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.dirname(HERE)
ZODIAC = os.path.join(JOURNEYS, "zodiac")
CHARTS = os.path.join(ZODIAC, "charts")
OUT = os.path.join(ZODIAC, "transits")
sys.path.insert(0, HERE)
import chart_ephemeris as CE  # noqa: E402

E = CE.E
SIGNS = CE.SIGNS
SIGN_GLYPH = dict(zip(SIGNS, E.SIGN_GLYPH))
BODIES = CE.BODIES
TRANSIT_ORB = {"Sun": 3.0, "Moon": 3.0, "Mercury": 3.0, "Venus": 3.0, "Mars": 3.0, "Jupiter": 2.0, "Saturn": 2.0,
               "Uranus": 1.5, "Neptune": 1.5, "Pluto": 1.5, "North Node": 2.0, "South Node": 2.0}
NODE_ORB = 2.0
RETURN_ORB = {"Sun": 3.0, "Moon": 13.0, "Mercury": 3.0, "Venus": 3.0, "Mars": 3.0, "Jupiter": 3.0, "Saturn": 3.0,
              "North Node": 3.0}
PHASES = ["New Moon", "Waxing Crescent", "First Quarter", "Waxing Gibbous", "Full Moon", "Waning Gibbous",
          "Last Quarter", "Waning Crescent"]
YEAR_DAYS = 365.2425

_SKY = {}


def dms(lon):
    i, d = E.sign_of(lon)
    deg = int(d)
    mins = int(round((d - deg) * 60))
    if mins == 60:
        deg, mins = deg + 1, 0
    return SIGNS[i], deg, mins


def pos_text(lon):
    s, d, m = dms(lon)
    return "%s %d°%02d′" % (s, d, m)


def sky_at(jd):
    """cached transit sky for a JD: (longitudes, speeds, aspects among the transiting bodies)"""
    key = round(jd, 3)
    if key not in _SKY:
        lons = CE.longitudes(jd)
        spd = CE.speeds(jd)
        _SKY[key] = (lons, spd, CE.aspects(dict(lons), spd))
    return _SKY[key]


def phase_name(elong):
    return PHASES[int(((elong + 22.5) % 360.0) // 45.0)]


# ------------------------------------------------------------------ natal
def load_natal(slug):
    p = os.path.join(CHARTS, slug + ".chart.json")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        c = json.load(f)
    points = {n: c["bodies"][n]["longitude"] for n in BODIES}
    if c.get("angles"):
        points["Ascendant"] = c["angles"]["asc"]["longitude"]
        points["MC"] = c["angles"]["mc"]["longitude"]
    cusps = [x["longitude"] for x in c["cusps"]] if c["mode"] == "timed" else None
    return {"chart": c, "points": points, "sun_sign": E.sign_of(points["Sun"])[0], "placidus": cusps,
            "jd": c["birth"]["jd_ut"], "mode": c["mode"]}


def transits_to_natal(lons, spd, natal):
    out = []
    for t in BODIES:
        for n, nlon in natal["points"].items():
            if t in ("North Node", "South Node") and n in ("North Node", "South Node"):
                continue
            sep = abs(E.wrap180(lons[t] - nlon))
            limit = TRANSIT_ORB[t]
            if n in ("North Node", "South Node"):
                limit = min(limit, NODE_ORB)
            for name, angle, glyph in CE.ASPECTS:
                orb = abs(sep - angle)
                if orb <= limit:
                    # applying if the separation moves toward the exact angle over the next half day
                    sep_next = abs(E.wrap180((lons[t] + 0.5 * spd[t]) - nlon))
                    phase = "applying" if abs(sep_next - angle) < orb else "separating"
                    out.append({"transiting": t, "aspect": name, "glyph": glyph, "natal": n, "orb": round(orb, 2),
                                "orb_limit": limit, "phase": phase, "exact": orb < 1.0})
    out.sort(key=lambda x: x["orb"])
    return out


def returns_for(lons, natal):
    r = {}
    for b, limit in RETURN_ORB.items():
        d = abs(E.wrap180(lons[b] - natal["points"][b]))
        r[b] = {"return": d <= limit, "separation": round(d, 2)}
    return r


# ------------------------------------------------------------------ per stop
def stop_block(zstop, natal):
    jd = zstop["jd_ut"]
    lons, spd, sky_aspects = sky_at(jd)
    bodies = {}
    for b in BODIES:
        s, d, m = dms(lons[b])
        bodies[b] = {"longitude": round(lons[b], 3), "sign": s, "degree": d, "minute": m, "text": "%s %d°%02d′" % (s, d, m),
                     "speed": round(spd[b], 4),
                     "retrograde": True if b in ("North Node", "South Node") else (spd[b] < 0 and b not in ("Sun", "Moon"))}
    block = {"segment": zstop["segment"], "stop": zstop["stop"], "date": zstop["date"], "calendar": zstop["calendar_applied"],
             "jd_ut": jd, "moment": "0h UT of the civil date", "sky": {"bodies": bodies, "aspects": sky_aspects}}
    if natal:
        days = jd - natal["jd"]
        years = math.floor(days / YEAR_DAYS)
        rem = days - years * YEAR_DAYS
        block["age"] = {"days_total": round(days, 2), "years": int(years), "days": int(round(rem)),
                        "text": ("%d y %d d" % (years, round(rem))) if days >= 0 else "before the birth (%d d)" % round(-days)}
        for b in BODIES:
            bodies[b]["natal_solar_house"] = ((E.sign_of(lons[b])[0] - natal["sun_sign"]) % 12) + 1
            if natal["placidus"]:
                bodies[b]["natal_placidus_house"] = CE.house_of(lons[b], natal["placidus"])
        block["transits_to_natal"] = transits_to_natal(lons, spd, natal)
        block["returns"] = returns_for(lons, natal)
        elong = E.wrap360(lons["Moon"] - lons["Sun"])
        block["moon"] = {"phase": phase_name(elong), "elongation_from_sun": round(elong, 1),
                         "angle_from_natal_sun": round(E.wrap360(lons["Moon"] - natal["points"]["Sun"]), 1),
                         "caveat": "0h UT; the Moon moves ~13° over the day"}
        heavy = [x for x in block["transits_to_natal"] if x["exact"] and x["natal"] in ("Sun", "Moon", "Ascendant", "MC")]
        block["weight"] = {"exact_to_sun_moon_angles": len(heavy),
                           "orb_sum": round(sum(x["orb"] for x in heavy), 2),
                           "hits": ["%s %s natal %s %.2f°" % (x["transiting"], x["aspect"], x["natal"], x["orb"]) for x in heavy]}
    return block


# ------------------------------------------------------------------ markdown
def natal_summary_lines(natal):
    c = natal["chart"]
    L = ["## Natal chart (%s)" % ("timed, %s houses" % c["house_system"] if c["mode"] == "timed" else "solar chart, no birth time")]
    L.append("")
    L.append("Born %s, %s. " % (c["birth"]["date"], c["birth"]["stop"]) + ", ".join(
        "%s %s" % (CE.GLYPH[b], c["bodies"][b]["text"]) for b in BODIES) + (
        ". Asc %s, MC %s" % (c["angles"]["asc"]["text"], c["angles"]["mc"]["text"]) if c.get("angles") else "") + ".")
    L.append("Full chart: `zodiac/charts/%s.chart.md`." % c["slug"])
    L.append("")
    return L


def block_md(bk, natal):
    L = ["### %s / %s" % (bk["segment"], bk["stop"]), ""]
    head = "%s (%s, 0h UT)" % (bk["date"], bk["calendar"])
    if natal:
        head += ", age " + bk["age"]["text"]
    L.append(head)
    L.append("")
    if natal:
        hdr = "| body | position | motion | natal solar house |" + (" natal Placidus house |" if natal["placidus"] else "")
        sep = "|---|---|---|---|" + ("---|" if natal["placidus"] else "")
    else:
        hdr, sep = "| body | position | motion |", "|---|---|---|"
    L += [hdr, sep]
    for b in BODIES:
        e = bk["sky"]["bodies"][b]
        motion = "mean node" if b in ("North Node", "South Node") else ("R " if e["retrograde"] else "") + "%.2f°/d" % e["speed"]
        row = "| %s %s | %s %s | %s |" % (CE.GLYPH[b], b, SIGN_GLYPH[e["sign"]], e["text"], motion)
        if natal:
            row += " %d |" % e["natal_solar_house"]
            if natal["placidus"]:
                row += " %d |" % e["natal_placidus_house"]
        L.append(row)
    L.append("")
    L.append("Transit sky aspects: " + ("; ".join("%s %s %s %.1f° %s" % (
        CE.GLYPH[a["a"]], a["glyph"], CE.GLYPH[a["b"]], a["orb"], a["phase"][:3]) for a in bk["sky"]["aspects"]) or "none"))
    L.append("")
    if natal:
        L.append("| transiting | aspect | natal | orb | phase |")
        L.append("|---|---|---|---|---|")
        for x in bk["transits_to_natal"]:
            natal_name = x["natal"] if x["natal"] in ("Ascendant", "MC") else "%s %s" % (CE.GLYPH[x["natal"]], x["natal"])
            L.append("| %s %s | %s | %s | %.2f°%s | %s |" % (
                CE.GLYPH[x["transiting"]], x["transiting"], x["aspect"], natal_name,
                x["orb"], " exact" if x["exact"] else "", x["phase"]))
        if not bk["transits_to_natal"]:
            L.append("| (none within orb) | | | | |")
        L.append("")
        r = bk["returns"]
        rets = [("%s return (%.1f°)" % (b, r[b]["separation"])) for b in RETURN_ORB if r[b]["return"]]
        m = bk["moon"]
        L.append("Returns and markers: %s. Moon %s (%.0f° from the Sun), %.0f° from the natal Sun. Weight: %d exact transit%s to natal Sun/Moon/angles%s." % (
            ", ".join(rets) if rets else "none", m["phase"], m["elongation_from_sun"], m["angle_from_natal_sun"],
            bk["weight"]["exact_to_sun_moon_angles"], "" if bk["weight"]["exact_to_sun_moon_angles"] == 1 else "s",
            (" (" + "; ".join(bk["weight"]["hits"]) + ")") if bk["weight"]["hits"] else ""))
        L.append("")
    return L


# ------------------------------------------------------------------ per journey
def process(slug):
    with open(os.path.join(ZODIAC, slug + ".zodiac.json"), encoding="utf-8") as f:
        z = json.load(f)
    natal = load_natal(slug) if z["birth"].get("precision") == "day" else None
    stops = [s for s in z["stops"] if s.get("precision") == "day"]
    blocks = [stop_block(s, natal) for s in stops]
    out = {"slug": slug, "traveler": z["traveler"], "calendar": z["calendar"], "moment": "0h UT of each civil date",
           "natal": ({"source": "zodiac/charts/%s.chart.json" % slug, "mode": natal["mode"], "birth_date": natal["chart"]["birth"]["date"],
                      "points": {k: round(v, 3) for k, v in natal["points"].items()}} if natal else None),
           "natal_note": None if natal else "birth not day-precise (%s): sky only, no transits to a natal chart" % z["birth"].get("precision"),
           "transit_orbs": TRANSIT_ORB, "return_orbs": RETURN_ORB,
           "counts": {"day_precise_stops": len(blocks)}, "stops": blocks}
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, slug + ".transits.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    L = ["# %s: transits" % z["traveler"], ""]
    L.append("Sky at 0h UT of each day-precise stop (%d of %d stops); no time of day is known for events, so the Moon is "
             "good to ~13° and the angles are not computed." % (len(blocks), z["counts"]["stops"]))
    L.append("")
    if natal:
        L += natal_summary_lines(natal)
        L.append("Transit orbs: 3° Sun/Moon/Mercury/Venus/Mars, 2° Jupiter/Saturn, 1.5° Uranus/Neptune/Pluto, 2° nodes. "
                 "Returns: Sun within 3°, Moon within 13°, others within 3°.")
        L.append("")
    else:
        L.append("*" + out["natal_note"] + ".*")
        L.append("")
    for bk in blocks:
        L += block_md(bk, natal)
    with open(os.path.join(OUT, slug + ".transits.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return out


# ------------------------------------------------------------------ the index
def write_index(results, runtime):
    with_natal = [r for r in results if r["natal"]]
    stops_total = sum(r["counts"]["day_precise_stops"] for r in results)
    stops_natal = sum(r["counts"]["day_precise_stops"] for r in with_natal)
    solar, saturn, jupiter, heavy = [], [], [], []
    sun_aspects = Counter()
    for r in with_natal:
        for bk in r["stops"]:
            if bk["age"]["days_total"] < 0.5:
                continue        # before the birth, or the birth stop itself (trivially its own solar return)
            row = (r["traveler"], r["slug"], bk["stop"], bk["date"], bk["age"]["text"])
            if bk["returns"]["Sun"]["return"]:
                solar.append(row + (bk["returns"]["Sun"]["separation"],))
            if bk["returns"]["Saturn"]["return"]:
                saturn.append(row + (bk["returns"]["Saturn"]["separation"],))
            if bk["returns"]["Jupiter"]["return"]:
                jupiter.append(row + (bk["returns"]["Jupiter"]["separation"],))
            w = bk["weight"]
            if w["exact_to_sun_moon_angles"]:
                heavy.append((w["exact_to_sun_moon_angles"], -w["orb_sum"], row, w["hits"]))
            for x in bk["transits_to_natal"]:
                if x["natal"] == "Sun":
                    sun_aspects[(x["transiting"], x["aspect"])] += 1
    heavy.sort(key=lambda h: (-h[0], -h[1]))
    L = ["# Atlas transits", ""]
    L.append("Generated by `atlas_tools/transit_charts.py`; every number computed. Runtime %.0f s. The lists below "
             "exclude each subject's birth stop itself (trivially its own solar and lunar return) and stops before the birth." % runtime)
    L.append("")
    L.append("| what | n |")
    L.append("|---|---|")
    L.append("| journeys with a transits file | %d |" % len(results))
    L.append("| journeys with transits to a natal chart (day-precise birth) | %d |" % len(with_natal))
    L.append("| day-precise stops covered (sky) | %d |" % stops_total)
    L.append("| day-precise stops with transits to natal | %d |" % stops_natal)
    L.append("| unique dates computed | %d |" % len(_SKY))
    L.append("| solar-return stops (Sun within 3° of natal Sun) | %d |" % len(solar))
    L.append("| Saturn-return stops (within 3°) | %d |" % len(saturn))
    L.append("| Jupiter-return stops (within 3°) | %d |" % len(jupiter))
    L.append("")

    def listing(title, rows):
        L.append("## %s (%d)" % (title, len(rows)))
        L.append("")
        for trav, slug, stop, date, age, sep in sorted(rows, key=lambda x: (x[1], x[3])):
            L.append("- %s, %s, %s, age %s (%.1f°)" % (trav, stop, date, age, sep))
        L.append("")
    listing("Solar-return stops: events within about three days of the subject's birthday", solar)
    listing("Saturn-return stops", saturn)
    listing("Jupiter-return stops", jupiter)
    L.append("## The fifty heaviest stops (exact transits, <1°, to the natal Sun, Moon, Ascendant, MC)")
    L.append("")
    for n, negsum, row, hits in heavy[:50]:
        L.append("- %d: %s, %s, %s, age %s: %s" % (n, row[0], row[2], row[3], row[4], "; ".join(hits)))
    L.append("")
    L.append("## Most frequent transit aspects to natal Suns (all stops with a natal chart)")
    L.append("")
    L.append("| transiting body | aspect | stops |")
    L.append("|---|---|---|")
    for (t, a), n in sun_aspects.most_common(25):
        L.append("| %s | %s | %d |" % (t, a, n))
    L.append("")
    path = os.path.join(OUT, "_atlas_transits.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


# ------------------------------------------------------------------ checks
def print_block(slug, date, keyword=""):
    r = process(slug)
    natal = load_natal(slug) if r["natal"] else None
    hits = [bk for bk in r["stops"] if bk["date"] == date]
    hits = [bk for bk in hits if keyword.lower() in bk["stop"].lower()] or hits
    for bk in hits[:1]:
        print("\n".join(block_md(bk, natal)))
        return True
    print("%s: no day-precise stop dated %s" % (slug, date))
    return False


def saturn_scan():
    """independent check: every stop at age 29-30 with transiting Saturn within 3 deg of natal Saturn is flagged"""
    checked = flagged = missed = 0
    examples = []
    for p in sorted(glob.glob(os.path.join(OUT, "*.transits.json"))):
        with open(p, encoding="utf-8") as f:
            r = json.load(f)
        if not r["natal"]:
            continue
        ns = r["natal"]["points"]["Saturn"]
        for bk in r["stops"]:
            if 29 <= bk["age"]["years"] <= 30:
                checked += 1
                sep = abs(E.wrap180(bk["sky"]["bodies"]["Saturn"]["longitude"] - ns))
                if sep <= 3.0:
                    if bk["returns"]["Saturn"]["return"]:
                        flagged += 1
                        if len(examples) < 5:
                            examples.append("%s, %s, %s, age %s (%.1f°)" % (r["traveler"], bk["stop"], bk["date"], bk["age"]["text"], sep))
                    else:
                        missed += 1
    print("Saturn-return scan: %d stops at age 29-30; %d with Saturn within 3° of natal Saturn, all flagged: %s; missed %d" % (
        checked, flagged, "yes" if missed == 0 else "NO", missed))
    for e in examples:
        print("  e.g.", e)


def main(argv):
    t0 = time.time()
    if "--check" in argv:
        print("== Kennedy, Dallas 1963-11-22 ==")
        print_block("john_f_kennedy", "1963-11-22", "Dealey")
        print("\n== Wagner, Venice 1883-02-13 ==")
        print_block("richard_wagner", "1883-02-13")
        print()
        saturn_scan()
        return
    slugs = [a for a in argv if not a.startswith("--")]
    if slugs:
        for s in slugs:
            r = process(s.replace(".journey.json", ""))
            print("%s: %d day-precise stops, natal %s" % (s, r["counts"]["day_precise_stops"], r["natal"]["mode"] if r["natal"] else "none"))
        return
    results = []
    for p in sorted(glob.glob(os.path.join(ZODIAC, "*.zodiac.json"))):
        results.append(process(os.path.basename(p).replace(".zodiac.json", "")))
    path = write_index(results, time.time() - t0)
    print("wrote", path)
    print("journeys %d, with natal %d, day-precise stops %d, unique dates %d, runtime %.0f s" % (
        len(results), sum(1 for r in results if r["natal"]), sum(r["counts"]["day_precise_stops"] for r in results),
        len(_SKY), time.time() - t0))


if __name__ == "__main__":
    main(sys.argv[1:])
