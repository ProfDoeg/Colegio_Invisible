#!/usr/bin/env python3
"""Complete natal chart for a journey's birth stop.

    python3 atlas_tools/natal_chart.py <slug> [--time HH:MM] [--tz +HH:MM] [--place "lat,lng"]
                                              [--houses placidus|whole] [--wheel out.png]
    python3 atlas_tools/natal_chart.py --all            # every day-precise birth in zodiac/*.zodiac.json
    python3 atlas_tools/natal_chart.py --check          # Kennedy 1917-05-29 15:00 EST against the published chart

Writes zodiac/charts/<slug>.chart.json and <slug>.chart.md (and the wheel PNG on demand).

Birth stop, date, calendar and precision come from zodiac/<slug>.zodiac.json (zodiac_readings.py; built on
the fly if missing). Latitude and longitude come from the stop (or --place). Time of day comes from --time,
else from an optional "birth_time" ("HH:MM", with optional "birth_tz" "+HH:MM") on the stop if a journey ever
carries one, else there is NO time. The zone for --time is --tz; without it local mean time from the
longitude is used and said so (Kennedy's published chart uses EST: pass --tz -05:00).

With a time: Ascendant, MC, the twelve cusps (Placidus by default, whole-sign on request or where Placidus
is undefined), houses, aspects including the angles. Without a time: a SOLAR CHART, whole-sign houses counted
from the Sun's sign as the first house, no Ascendant or MC, the Moon's degree flagged as +-7 (its daily
motion) and its sign flagged "may differ" within 7 degrees of a boundary. Positions at 0h UT in that case.

Sky: chart_ephemeris.py over the date-driven ephemeris (Standish 2b, Meeus Moon and node, IAU 2006
precession). Dignities by the traditional table (domicile, exaltation, detriment, fall; the modern rulerships
of Uranus, Neptune, Pluto marked separately). Elements and modes counted over the ten bodies Sun..Pluto.
"""
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.dirname(HERE)
ZODIAC = os.path.join(JOURNEYS, "zodiac")
CHARTS = os.path.join(ZODIAC, "charts")
sys.path.insert(0, HERE)
import chart_ephemeris as CE  # noqa: E402
import zodiac_readings as ZR  # noqa: E402

E = CE.E
SIGNS = CE.SIGNS
SIGN_GLYPH = dict(zip(SIGNS, E.SIGN_GLYPH))
TEN = ["Sun", "Moon", "Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Uranus", "Neptune", "Pluto"]

ELEMENT = {"Aries": "Fire", "Leo": "Fire", "Sagittarius": "Fire", "Taurus": "Earth", "Virgo": "Earth",
           "Capricornus": "Earth", "Gemini": "Air", "Libra": "Air", "Aquarius": "Air", "Cancer": "Water",
           "Scorpio": "Water", "Pisces": "Water"}
MODE = {"Aries": "Cardinal", "Cancer": "Cardinal", "Libra": "Cardinal", "Capricornus": "Cardinal",
        "Taurus": "Fixed", "Leo": "Fixed", "Scorpio": "Fixed", "Aquarius": "Fixed",
        "Gemini": "Mutable", "Virgo": "Mutable", "Sagittarius": "Mutable", "Pisces": "Mutable"}
DOMICILE = {"Sun": ["Leo"], "Moon": ["Cancer"], "Mercury": ["Gemini", "Virgo"], "Venus": ["Taurus", "Libra"],
            "Mars": ["Aries", "Scorpio"], "Jupiter": ["Sagittarius", "Pisces"], "Saturn": ["Capricornus", "Aquarius"]}
MODERN_DOMICILE = {"Uranus": ["Aquarius"], "Neptune": ["Pisces"], "Pluto": ["Scorpio"]}
EXALTATION = {"Sun": "Aries", "Moon": "Taurus", "Mercury": "Virgo", "Venus": "Pisces", "Mars": "Capricornus",
              "Jupiter": "Cancer", "Saturn": "Libra"}


def opposite(sign):
    return SIGNS[(SIGNS.index(sign) + 6) % 12]


def dignity(body, sign):
    tags = []
    if body in DOMICILE:
        if sign in DOMICILE[body]:
            tags.append("domicile")
        if sign in [opposite(s) for s in DOMICILE[body]]:
            tags.append("detriment")
    if body in EXALTATION:
        if sign == EXALTATION[body]:
            tags.append("exaltation")
        if sign == opposite(EXALTATION[body]):
            tags.append("fall")
    if body in MODERN_DOMICILE:
        if sign in MODERN_DOMICILE[body]:
            tags.append("domicile (modern)")
        if sign in [opposite(s) for s in MODERN_DOMICILE[body]]:
            tags.append("detriment (modern)")
    return tags


def dms(lon):
    i, d = E.sign_of(lon)
    deg = int(d)
    mins = int(round((d - deg) * 60))
    if mins == 60:
        deg, mins = deg + 1, 0
    return SIGNS[i], deg, mins


def parse_hhmm(s):
    m = re.match(r"^\s*([+-]?)(\d{1,2})(?::(\d{2}))?\s*$", str(s))
    if not m:
        raise ValueError("bad time/zone %r (want HH:MM or +HH:MM)" % s)
    sign = -1.0 if m.group(1) == "-" else 1.0
    return sign * (int(m.group(2)) + int(m.group(3) or 0) / 60.0)


def fmt_tz(h):
    s = "+" if h >= 0 else "-"
    h = abs(h)
    return "%s%02d:%02d" % (s, int(h), int(round((h - int(h)) * 60)))


# ------------------------------------------------------------------ the chart
def load_birth(slug):
    zpath = os.path.join(ZODIAC, slug + ".zodiac.json")
    if not os.path.exists(zpath):
        ZR.process(os.path.join(JOURNEYS, slug + ".journey.json"))
    with open(zpath, encoding="utf-8") as f:
        z = json.load(f)
    with open(os.path.join(JOURNEYS, slug + ".journey.json"), encoding="utf-8") as f:
        journey = json.load(f)
    b = z["birth"]
    if "date" not in b:
        raise ValueError("%s: no birth stop identified (%s)" % (slug, b.get("note")))
    stop = None
    for seg in journey.get("segments", []):
        for st in seg.get("stops", []):
            if st.get("name") == b["stop"] and st.get("date") == b["date"] and seg.get("name") == b["segment"]:
                stop = st
    return z, b, stop


def build(slug, time_local=None, tz_hours=None, place=None, houses="placidus"):
    z, b, stop = load_birth(slug)
    notes = []
    lat, lng = (place if place else (stop["lat"], stop["lng"]))
    lat, lng = float(lat), float(lng)
    y, m, d = ZR.parse_date(b["date"])
    ay = ZR.astro_year(y)
    gregorian = b["calendar_applied"].startswith("gregorian")
    jd0 = ZR.jd_from(ay, m, d, gregorian)
    if b.get("precision") != "day":
        notes.append("BIRTH DATE NOT DAY-PRECISE (%s): the chart below reads the stated date literally; "
                     "Moon, Mercury, Venus and the houses cannot be trusted" % b.get("precision"))
    if b.get("calendar_note") and "alternative" in b["calendar_note"]:
        notes.append("calendar convention in doubt: " + b["calendar_note"])
    # time
    tz_source = None
    if time_local is None and stop and stop.get("birth_time"):
        time_local = stop["birth_time"]
        if tz_hours is None and stop.get("birth_tz"):
            tz_hours = parse_hhmm(stop["birth_tz"])
            tz_source = "birth_tz on the stop"
    timed = time_local is not None
    if timed:
        local_h = parse_hhmm(time_local)
        if tz_hours is None:
            tz_hours = lng / 15.0
            tz_source = "local mean time from the longitude (no --tz given)"
            notes.append("zone not given: local mean time from the longitude %.4f = UTC%s assumed; a civil "
                         "zone could move the Ascendant by several degrees" % (lng, fmt_tz(tz_hours)))
        elif tz_source is None:
            tz_source = "--tz"
        ut_h = local_h - tz_hours
        jd = jd0 + ut_h / 24.0
    else:
        jd = jd0
        notes.append("NO BIRTH TIME KNOWN: solar chart, positions at 0h UT of the civil date; whole-sign houses "
                     "from the Sun's sign; no Ascendant or MC")
    lons = CE.longitudes(jd)
    spd = CE.speeds(jd)
    T, _, _ = CE.centuries(jd)
    eps, _ = CE.obliquity(T)

    chart = {
        "slug": slug, "traveler": z["traveler"], "title": z.get("title"), "years": z.get("years"),
        "birth": {"stop": b["stop"], "segment": b["segment"], "date": b["date"], "calendar": b["calendar_applied"],
                  "date_precision": b.get("precision"), "date_confidence": b.get("date_confidence"),
                  "lat": lat, "lng": lng, "place_source": "--place" if place else "the stop's pin",
                  "time_local": time_local, "tz_hours": tz_hours, "tz": fmt_tz(tz_hours) if timed else None,
                  "tz_source": tz_source, "ut_hours": round((jd - jd0) * 24.0, 4) if timed else None,
                  "jd_ut": round(jd, 5), "astronomical_year": ay},
        "mode": "timed" if timed else "solar",
        "obliquity": round(eps, 4),
    }
    # houses
    ang = None
    system = None
    if timed:
        ang = CE.angles(jd, lat, lng)
        asc_sign = SIGNS[E.sign_of(ang["asc"])[0]]
        if houses == "placidus":
            cusps = CE.placidus_cusps(ang["ramc"], eps, lat, ang["asc"], ang["mc"])
            if cusps is None:
                notes.append("Placidus undefined at latitude %.2f (polar circle): whole-sign houses used" % lat)
                cusps = CE.whole_sign_cusps(SIGNS.index(asc_sign))
                system = "whole-sign (from the Ascendant's sign)"
            else:
                system = "Placidus"
        else:
            cusps = CE.whole_sign_cusps(SIGNS.index(asc_sign))
            system = "whole-sign (from the Ascendant's sign)"
    else:
        sun_sign_i = E.sign_of(lons["Sun"])[0]
        cusps = CE.whole_sign_cusps(sun_sign_i)
        system = "solar whole-sign (first house = the Sun's sign, %s)" % SIGNS[sun_sign_i]
    chart["house_system"] = system
    chart["cusps"] = []
    for i, c in enumerate(cusps):
        s, dg, mn = dms(c)
        chart["cusps"].append({"house": i + 1, "longitude": round(c, 3), "sign": s, "degree": dg, "minute": mn,
                               "text": "%s %d°%02d′" % (s, dg, mn)})
    if ang:
        chart["angles"] = {}
        for k in ("asc", "mc", "desc", "ic"):
            s, dg, mn = dms(ang[k])
            chart["angles"][k] = {"longitude": round(ang[k], 3), "sign": s, "degree": dg, "minute": mn,
                                  "text": "%s %d°%02d′" % (s, dg, mn)}
        chart["angles"]["ramc"] = round(ang["ramc"], 3)
        chart["angles"]["lst_hours"] = round(ang["lst"] / 15.0, 4)
    # bodies
    chart["bodies"] = {}
    for name in CE.BODIES:
        lon = lons[name]
        s, dg, mn = dms(lon)
        entry = {"longitude": round(lon, 3), "sign": s, "degree": dg, "minute": mn,
                 "text": "%s %d°%02d′" % (s, dg, mn), "glyph": CE.GLYPH[name],
                 "speed_deg_per_day": round(spd[name], 4),
                 "retrograde": bool(spd[name] < 0) if name not in ("Sun", "Moon") else False,
                 "house": CE.house_of(lon, cusps), "dignity": dignity(name, s)}
        if name in ("North Node", "South Node"):
            entry["retrograde"] = True
            entry["note"] = "mean node (always retrograde)"
        if name == "Moon" and not timed:
            entry["degree_uncertainty"] = "±7° (no birth time: the Moon moves ~13° a day)"
            frac = lon % 30.0
            if frac < 7.0 or frac > 23.0:
                entry["sign_may_differ"] = True
                entry["sign_note"] = "within 7° of a sign boundary: the Moon's sign may differ (%s or %s)" % (
                    SIGNS[(SIGNS.index(s) - 1) % 12] if frac < 7.0 else s,
                    s if frac < 7.0 else SIGNS[(SIGNS.index(s) + 1) % 12])
        chart["bodies"][name] = entry
    if not timed:
        notes.append("houses in a solar chart are the signs counted from the Sun's: they say nothing about the horizon")
    # aspects
    asp_lons = {k: lons[k] for k in CE.BODIES}
    if ang:
        asp_lons["Ascendant"] = ang["asc"]
        asp_lons["MC"] = ang["mc"]
    chart["aspects"] = CE.aspects(asp_lons, spd)
    chart["aspect_rules"] = "conjunction 0, sextile 60, square 90, trine 120, opposition 180; orbs 8 Sun/Moon, 6 planets, 3 nodes and angles (a pair uses the smaller); applying/separating from the daily motions"
    # balance
    el, md = {"Fire": [], "Earth": [], "Air": [], "Water": []}, {"Cardinal": [], "Fixed": [], "Mutable": []}
    for name in TEN:
        s = chart["bodies"][name]["sign"]
        el[ELEMENT[s]].append(name)
        md[MODE[s]].append(name)
    chart["balance"] = {"counted": TEN, "elements": {k: len(v) for k, v in el.items()},
                        "elements_bodies": el, "modes": {k: len(v) for k, v in md.items()}, "modes_bodies": md}
    if ang:
        chart["balance"]["ascendant_sign"] = chart["angles"]["asc"]["sign"]
    chart["dignities"] = {n: chart["bodies"][n]["dignity"] for n in CE.BODIES if chart["bodies"][n]["dignity"]}
    chart["notes"] = notes
    return chart


# ------------------------------------------------------------------ markdown
def write_md(chart, path):
    b = chart["birth"]
    L = ["# %s: natal chart" % chart["traveler"], ""]
    L.append("Born %s (%s calendar), %s (lat %.4f, lng %.4f, %s)." % (
        b["date"], b["calendar"], b["stop"], b["lat"], b["lng"], b["place_source"]))
    if chart["mode"] == "timed":
        L.append("Time %s local, zone UTC%s (%s), %.2f h UT, JD %.5f." % (
            b["time_local"], b["tz"], b["tz_source"], b["ut_hours"], b["jd_ut"]))
    else:
        L.append("**NO BIRTH TIME KNOWN.** This is a SOLAR CHART: positions at 0h UT, whole-sign houses counted from "
                 "the Sun's sign as the first house, no Ascendant or Midheaven. The Moon's degree is good to ±7°.")
    for n in chart["notes"]:
        L.append("- " + n)
    L.append("")
    L.append("## Bodies")
    L.append("")
    L.append("| body | position | house | motion | dignity | note |")
    L.append("|---|---|---|---|---|---|")
    for name in CE.BODIES:
        e = chart["bodies"][name]
        sp = e["speed_deg_per_day"]
        motion = ("R " if e["retrograde"] else "") + "%.3f°/d" % sp
        if abs(sp) < 0.01 and name not in ("Sun", "Moon"):
            motion += " (stationary)"
        if name in ("North Node", "South Node"):
            motion = "mean node"
        note = e.get("sign_note", "") or e.get("degree_uncertainty", "")
        L.append("| %s %s | %s %s | %d | %s | %s | %s |" % (
            e["glyph"], name, SIGN_GLYPH[e["sign"]], e["text"], e["house"], motion, ", ".join(e["dignity"]), note))
    L.append("")
    if "angles" in chart:
        a = chart["angles"]
        L.append("## Angles and cusps (%s)" % chart["house_system"])
        L.append("")
        L.append("Ascendant %s, Midheaven %s, Descendant %s, IC %s. RAMC %.2f°, LST %.4f h, obliquity %.4f°." % (
            a["asc"]["text"], a["mc"]["text"], a["desc"]["text"], a["ic"]["text"], a["ramc"], a["lst_hours"],
            chart["obliquity"]))
        L.append("")
    else:
        L.append("## Houses (%s)" % chart["house_system"])
        L.append("")
    L.append("| house | cusp |")
    L.append("|---|---|")
    for c in chart["cusps"]:
        L.append("| %d | %s %s |" % (c["house"], SIGN_GLYPH[c["sign"]], c["text"]))
    L.append("")
    L.append("## Aspects")
    L.append("")
    L.append(chart["aspect_rules"] + ".")
    L.append("")
    L.append("| | aspect | | orb | phase |")
    L.append("|---|---|---|---|---|")
    def named(k):
        g = CE.GLYPH.get(k, "")
        return k if k in ("Ascendant", "MC") else "%s %s" % (g, k)
    for x in chart["aspects"]:
        L.append("| %s | %s | %s | %.2f° | %s |" % (named(x["a"]), x["aspect"], named(x["b"]), x["orb"], x["phase"]))
    L.append("")
    bal = chart["balance"]
    L.append("## Elements and modes (over %s)" % ", ".join(bal["counted"]))
    L.append("")
    L.append("| element | n | bodies |")
    L.append("|---|---|---|")
    for k in ("Fire", "Earth", "Air", "Water"):
        L.append("| %s | %d | %s |" % (k, bal["elements"][k], ", ".join(bal["elements_bodies"][k])))
    L.append("")
    L.append("| mode | n | bodies |")
    L.append("|---|---|---|")
    for k in ("Cardinal", "Fixed", "Mutable"):
        L.append("| %s | %d | %s |" % (k, bal["modes"][k], ", ".join(bal["modes_bodies"][k])))
    if bal.get("ascendant_sign"):
        L.append("")
        L.append("Ascendant in %s (not counted above)." % bal["ascendant_sign"])
    L.append("")
    L.append("## Dignities (traditional table; modern rulerships marked)")
    L.append("")
    if chart["dignities"]:
        for n, tags in chart["dignities"].items():
            L.append("- %s %s in %s: %s" % (CE.GLYPH[n], n, chart["bodies"][n]["sign"], ", ".join(tags)))
    else:
        L.append("- none of the bodies stands in domicile, exaltation, detriment or fall")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


# ------------------------------------------------------------------ the wheel
NAVY, GOLD, BLUE, WHITE = (7, 17, 31), (220, 181, 103), (163, 203, 223), (235, 233, 223)
RED = (205, 92, 92)
GOLD_DIM = (120, 100, 60)
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
ASPECT_COLOUR = {"conjunction": GOLD, "opposition": RED, "square": RED, "trine": BLUE, "sextile": BLUE}


def draw_wheel(chart, out_path, size=1400):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (size, size), NAVY)
    dr = ImageDraw.Draw(img)
    f_glyph = ImageFont.truetype(FONT, int(size * 0.034))
    f_body = ImageFont.truetype(FONT, int(size * 0.030))
    f_small = ImageFont.truetype(FONT, int(size * 0.014))
    f_house = ImageFont.truetype(FONT, int(size * 0.016))
    f_title = ImageFont.truetype(FONT_BOLD, int(size * 0.022))
    f_text = ImageFont.truetype(FONT, int(size * 0.015))
    cx = cy = size / 2.0
    R_out, R_zod, R_house, R_body, R_in = size * 0.425, size * 0.378, size * 0.360, size * 0.318, size * 0.165
    LEVEL_STEP, LABEL_OFF = size * 0.052, size * 0.026
    if chart["mode"] == "timed":
        left_lon = chart["angles"]["asc"]["longitude"]
    else:
        left_lon = chart["cusps"][0]["longitude"]

    def pt(lon, r):
        phi = (180.0 + (lon - left_lon)) * math.pi / 180.0
        return cx + r * math.cos(phi), cy - r * math.sin(phi)

    def ring(r, width=2, colour=GOLD):
        dr.ellipse([cx - r, cy - r, cx + r, cy + r], outline=colour, width=width)

    def text_at(xy, s, font, fill=WHITE):
        w, h = dr.textbbox((0, 0), s, font=font)[2:]
        dr.text((xy[0] - w / 2.0, xy[1] - h / 2.0), s, font=font, fill=fill)

    ring(R_out, 3)
    ring(R_zod, 2)
    ring(R_house, 1, GOLD_DIM)
    ring(R_in, 2)
    # zodiac ring: sign boundaries and glyphs
    for i in range(12):
        lon = 30.0 * i
        dr.line([pt(lon, R_zod), pt(lon, R_out)], fill=GOLD, width=2)
        text_at(pt(lon + 15.0, (R_out + R_zod) / 2.0), E.SIGN_GLYPH[i], f_glyph, GOLD)
        # degree ticks every 5 and 10
        for k in range(0, 30, 5):
            tick = R_zod + (size * 0.012 if k % 10 == 0 else size * 0.006)
            dr.line([pt(lon + k, R_zod), pt(lon + k, tick)], fill=GOLD, width=1)
    # house cusps
    cusps = [c["longitude"] for c in chart["cusps"]]
    for i, c in enumerate(cusps):
        is_angle = chart["mode"] == "timed" and i in (0, 3, 6, 9)
        dr.line([pt(c, R_in), pt(c, R_zod)], fill=GOLD if is_angle else GOLD_DIM, width=4 if is_angle else 1)
        nxt = cusps[(i + 1) % 12]
        mid = c + E.wrap360(nxt - c) / 2.0
        text_at(pt(mid, R_in + size * 0.02), str(i + 1), f_house, GOLD_DIM)
    if chart["mode"] == "timed":
        ax, ay_ = pt(chart["angles"]["asc"]["longitude"], R_zod - size * 0.03)
        text_at((ax + size * 0.045, ay_ - size * 0.03), "Asc", f_house, GOLD)
        mx, my = pt(chart["angles"]["mc"]["longitude"], R_zod - size * 0.03)
        text_at((mx + size * 0.045, my + size * 0.0), "MC", f_house, GOLD)
    # bodies, de-crowded: close bodies step inward
    order = sorted(CE.BODIES, key=lambda n: E.wrap360(chart["bodies"][n]["longitude"] - left_lon))
    placed = []
    radii = {}
    for n in order:
        lon = chart["bodies"][n]["longitude"]
        level = 0
        for (plon, plevel) in placed:
            if abs(E.wrap180(lon - plon)) < 7.0 and plevel == level:
                level += 1
        radii[n] = R_body - level * LEVEL_STEP
        placed.append((lon, level))
    for n in CE.BODIES:
        e = chart["bodies"][n]
        lon = e["longitude"]
        r = radii[n]
        dr.line([pt(lon, R_house), pt(lon, R_zod)], fill=WHITE, width=2)
        text_at(pt(lon, r), e["glyph"], f_body, WHITE)
        label = "%d°%02d" % (e["degree"], e["minute"]) + ("R" if e["retrograde"] and n not in ("North Node", "South Node") else "")
        text_at(pt(lon, r - LABEL_OFF), label, f_small, WHITE)
    # aspect lines inside
    lon_of = {n: chart["bodies"][n]["longitude"] for n in CE.BODIES}
    if chart["mode"] == "timed":
        lon_of["Ascendant"] = chart["angles"]["asc"]["longitude"]
        lon_of["MC"] = chart["angles"]["mc"]["longitude"]
    for x in chart["aspects"]:
        if x["aspect"] == "conjunction":
            continue
        colour = ASPECT_COLOUR[x["aspect"]]
        dr.line([pt(lon_of[x["a"]], R_in - 4), pt(lon_of[x["b"]], R_in - 4)], fill=colour,
                width=2 if x["orb"] <= 3.0 else 1)
    # titles
    b = chart["birth"]
    text_at((cx, size * 0.022), chart["traveler"], f_title, WHITE)
    line2 = "%s, %s" % (b["date"], b["stop"])
    text_at((cx, size * 0.022 + size * 0.028), line2, f_text, GOLD)
    if chart["mode"] == "timed":
        line3 = "%s local (UTC%s), Asc %s, MC %s, %s houses" % (
            b["time_local"], b["tz"], chart["angles"]["asc"]["text"], chart["angles"]["mc"]["text"], chart["house_system"])
    else:
        line3 = "no birth time: solar chart, houses from the Sun's sign, Moon ±7°"
    text_at((cx, size - size * 0.04), line3, f_text, GOLD)
    img.save(out_path)
    return out_path


# ------------------------------------------------------------------ driver
def run_one(slug, time_local=None, tz_hours=None, place=None, houses="placidus", wheel=None, quiet=False):
    chart = build(slug, time_local, tz_hours, place, houses)
    os.makedirs(CHARTS, exist_ok=True)
    jpath = os.path.join(CHARTS, slug + ".chart.json")
    mpath = os.path.join(CHARTS, slug + ".chart.md")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(chart, f, ensure_ascii=False, indent=1)
    write_md(chart, mpath)
    if wheel:
        draw_wheel(chart, wheel)
    if not quiet:
        print("%s: %s chart, %s" % (slug, chart["mode"], chart["house_system"]))
        for n in CE.BODIES:
            e = chart["bodies"][n]
            print("  %-10s %-20s house %2d %s" % (n, e["text"], e["house"], "R" if e["retrograde"] else ""))
        if "angles" in chart:
            print("  Asc %s  MC %s" % (chart["angles"]["asc"]["text"], chart["angles"]["mc"]["text"]))
        print("  wrote", jpath)
        print("  wrote", mpath)
        if wheel:
            print("  wrote", wheel)
    return chart


def run_all():
    import glob
    n = fails = 0
    skipped = []
    for zp in sorted(glob.glob(os.path.join(ZODIAC, "*.zodiac.json"))):
        with open(zp, encoding="utf-8") as f:
            z = json.load(f)
        if z["birth"].get("precision") != "day":
            continue
        slug = z["slug"]
        try:
            run_one(slug, quiet=True)
            n += 1
        except Exception as ex:  # noqa
            fails += 1
            skipped.append("%s: %s" % (slug, ex))
    print("charts written: %d; failures: %d" % (n, fails))
    for s in skipped:
        print("  ", s)


def check():
    print("== outer planets at J2000 (expect Uranus ~Aquarius 14.8, Neptune ~Aquarius 3.2, Pluto ~Sagittarius 11.4) ==")
    L = CE.longitudes(CE.J2000)
    for k in ("Uranus", "Neptune", "Pluto", "North Node"):
        print("  %-10s %s" % (k, E.sign_text(L[k])))
    print("== Kennedy, 1917-05-29 15:00 EST (UTC-05:00), Brookline: published chart Asc Libra (~20), Sun Gemini in the 8th, Moon Virgo (~17) ==")
    chart = run_one("john_f_kennedy", "15:00", -5.0, None, "placidus", None, quiet=True)
    asc = chart["angles"]["asc"]
    sun = chart["bodies"]["Sun"]
    moon = chart["bodies"]["Moon"]
    ok = asc["sign"] == "Libra" and sun["house"] == 8 and moon["sign"] == "Virgo"
    print("  %s  Asc %s | MC %s | Sun %s in house %d | Moon %s in house %d" % (
        "OK" if ok else "CHECK", asc["text"], chart["angles"]["mc"]["text"], sun["text"], sun["house"],
        moon["text"], moon["house"]))
    for n in ("Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Uranus", "Neptune", "Pluto", "North Node"):
        e = chart["bodies"][n]
        print("  %-10s %-20s house %2d %s" % (n, e["text"], e["house"], "R" if e["retrograde"] else ""))
    print("  cusps:", ", ".join("%d %s" % (c["house"], c["text"]) for c in chart["cusps"]))
    lmt = build("john_f_kennedy", "15:00", None, None, "placidus")
    print("  (for comparison, 15:00 local mean time: Asc %s, MC %s)" % (lmt["angles"]["asc"]["text"], lmt["angles"]["mc"]["text"]))


def main(argv):
    if "--check" in argv:
        check()
        return
    if "--all" in argv:
        run_all()
        return
    args = list(argv)
    opts = {"--time": None, "--tz": None, "--place": None, "--houses": "placidus", "--wheel": None}
    slug = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in opts:
            opts[a] = args[i + 1]
            i += 2
        elif a.startswith("--"):
            sys.exit("unknown option " + a)
        else:
            slug = a.replace(".journey.json", "")
            i += 1
    if not slug:
        sys.exit(__doc__)
    place = None
    if opts["--place"]:
        place = tuple(float(v) for v in opts["--place"].split(","))
    tz = parse_hhmm(opts["--tz"]) if opts["--tz"] else None
    run_one(slug, opts["--time"], tz, place, opts["--houses"], opts["--wheel"])


if __name__ == "__main__":
    main(sys.argv[1:])
