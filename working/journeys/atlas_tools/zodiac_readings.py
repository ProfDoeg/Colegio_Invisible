#!/usr/bin/env python3
"""Zodiac readings for every dated stop in the Atlas of Journeys.

    python3 atlas_tools/zodiac_readings.py                 # every *.journey.json in working/journeys
    python3 atlas_tools/zodiac_readings.py vaslav_nijinsky julius_caesar
    python3 atlas_tools/zodiac_readings.py --check         # the built-in validation, then exit

Writes, next to the journeys:
    zodiac/<slug>.zodiac.json      one file per journey, one entry per dated stop, plus the birth
    zodiac/_atlas_zodiac.csv       one row per journey: the birth reading
    zodiac/_atlas_zodiac.md        readable summary: counts, Sun-sign tables, the twelve lists, conjunctions
    zodiac/_atlas_conjunctions.csv every stop where three or more bodies share a sign (day precision only)

The sky comes from the date-driven ephemeris in private_notes/essay_gemini/reels/ephemeris.py
(Standish Keplerian elements, Table 2b, 3000 BC - 3000 AD; Meeus ch. 47 for the Moon; IAU 2006
precession; Espenak-Meeus Delta-T). It is imported by path, never copied. The only addition here is a
thin wrapper that evaluates its primitives at a Julian Day computed from an explicit calendar, because
the ephemeris reads a date string and decides the calendar itself (Julian before 1582-10-15), and
because its parser does not accept the atlas's negative years.

Conventions applied (every one of them is written into the output, per stop):
  * Atlas BCE dates are written "-0100-07-13" and mean 100 BC (Caesar), 106 BC (Cicero), 70 BC (Virgil):
    the year is the historical BCE year, not astronomical numbering. Astronomical year = 1 - Y.
  * calendar "julian" / "julian_bce": the date is a Julian-calendar date. Exception: a date on or after
    1582-10-15 that falls AFTER the subject's own life span (the "years" field) is a reception stop
    written in modern terms and is read as Gregorian; a post-1582 date inside the life span is read
    as Julian as declared, and the Gregorian alternative is given alongside.
  * calendar "gregorian" with a date before 1582-10-15: the declared calendar is applied (proleptic
    Gregorian) and the Julian alternative is given alongside, since such a date may well have been
    recorded Julian by its sources.
  * All positions are for 0h UT of the civil date (no birth times exist in the atlas). The Moon moves
    about 13 degrees a day, so a Moon within ~7 degrees of a sign boundary could sit in the neighbouring
    sign at the true hour; the degree is printed so the reader can judge.
  * Signs are tropical (0 Aries = equinox of date), as in the ephemeris. The sign names are the
    ephemeris's own (Capricornus, not Capricorn).

Precision (derived from the date string and the free-text date_confidence; conservative):
  "day"   no trigger word in date_confidence, full YYYY-MM-DD date;
  "month" trigger words present but the text affirms the month ("attested to the month", "month and
          year attested", "day and month attested", ...), or the date itself is YYYY-MM;
  "year"  otherwise (any trigger word: defaulted, approximately, circa, c., not established, not fixed,
          unknown, placed, inferred, traditional, reconstruct..., undated, placeholder, arbitrary, ...).
  Triggers come in three grades. HARD ones speak about the date and always remove day precision.
  SOFT-YEAR ones (a year range "1868-1870", "span", "in 1853") name only a year; they remove day precision
  unless the text cites the day ("attested to the day", "day and month attested", "8 February 1960").
  SOFT ones (placed, no source, nominal, editorial, reconstruct, generic) often describe the pin or the
  sources ("the coordinate is reconstructed", "no source gives the street address"); they remove day
  precision unless the text cites the day or opens with a plain "attested". A month-year mention with
  no day ("the March 1949 presentation") makes the stop month-precise. Grades are marked in the list.
  A date on the 1st with no explicit day citation is never day-precise: 01-01 is the atlas default for a
  year-only date (year precision) and the 1st for a month-only date (month precision). The first run
  without this rule produced eight six-body "stelliums", all on 1930-01-01 with a bare "attested".
  The words that fired are listed per stop in "precision_triggers". The Sun at the stated date is
  always given; for "month" the range of signs the Sun crosses over that month is given; for "year" the
  Sun can be anywhere, which is said. Moon and planets are given only at "day" precision.

Nothing in this file edits a journey. It only reads them.
"""
import csv
import glob
import importlib.util
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNEYS = os.path.dirname(HERE)
OUT = os.path.join(JOURNEYS, "zodiac")
EPHEMERIS_PATH = os.environ.get(
    "ATLAS_EPHEMERIS", "/home/drdoeg/private_notes/essay_gemini/reels/ephemeris.py")
PRESENT_YEAR = 2026
GREGORIAN_START = (1582, 10, 15)
LAST_JULIAN_CIVIL_YEAR = 1923        # no civil Julian calendar anywhere after Greece switched

# ---------------------------------------------------------------- the ephemeris, imported by path
spec = importlib.util.spec_from_file_location("ephemeris", EPHEMERIS_PATH)
if spec is None or not os.path.exists(EPHEMERIS_PATH):
    sys.exit(f"ephemeris not found at {EPHEMERIS_PATH} (set ATLAS_EPHEMERIS)")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

BODY_ORDER = ["Sun", "Moon", "Mercury", "Venus", "Mars", "Jupiter", "Saturn"]
PLANETS = ["Mercury", "Venus", "Mars", "Jupiter", "Saturn"]


def jd_from(astro_year, m, d, gregorian):
    """Julian Day at 0h UT for a civil date in the given calendar (Meeus 7.1 with an explicit flag;
    astronomical year numbering: 0 = 1 BC, -1 = 2 BC). Differs from the ephemeris's julian_day only
    in letting the caller choose the calendar instead of switching on 1582-10-15."""
    y = astro_year
    if m <= 2:
        y, m = y - 1, m + 12
    B = 0
    if gregorian:
        A = math.floor(y / 100)
        B = 2 - A + math.floor(A / 4)
    return math.floor(365.25 * (y + 4716)) + math.floor(30.6001 * (m + 1)) + d + B - 1524.5


def positions_at_jd(jd_ut):
    """Thin wrapper over the ephemeris primitives: tropical geocentric longitudes (deg) of the seven
    bodies at a Julian Day (UT). Same chain as ephemeris.positions(): Delta-T, Standish 2b, Meeus 47,
    IAU 2006 precession in longitude."""
    year = 2000.0 + (jd_ut - E.J2000) / 365.25
    jd_tt = jd_ut + E.delta_t(year) / 86400.0
    T = (jd_tt - E.J2000) / 36525.0
    pA = E.precession_in_longitude(T)
    ex, ey, _ = E.helio_xyz("earth", T, "2b")
    out = {"Sun": E.wrap360(E.lon_of(-ex, -ey) + pA)}
    for _, name in E.PLANET_OF.items():
        px, py, _ = E.helio_xyz(name, T, "2b")
        out[name.capitalize()] = E.wrap360(E.lon_of(px - ex, py - ey) + pA)
    ml, _ = E.moon_longitude(T)
    out["Moon"] = ml
    return out, T


def reading(lon):
    i, d = E.sign_of(lon)
    return {"sign": E.SIGNS[i], "degree": round(d, 2), "text": E.sign_text(lon), "longitude": round(lon, 3)}


# ---------------------------------------------------------------- dates
DATE_RE = re.compile(r"^(-?)(\d{1,4})-(\d{2})(?:-(\d{2}))?$")


def parse_date(s):
    """atlas date string -> (atlas_year, month, day_or_None); atlas_year negative = BCE year (not astro)"""
    m = DATE_RE.match(str(s).strip())
    if not m:
        return None
    neg, y, mo, d = m.groups()
    y = int(y)
    if neg:
        y = -y
    mo = int(mo)
    d = int(d) if d is not None else None
    if y == 0 or not 1 <= mo <= 12 or (d is not None and not 1 <= d <= 31):
        return None
    return y, mo, d


def astro_year(atlas_year):
    return atlas_year if atlas_year > 0 else 1 - abs(atlas_year)


def is_leap(astro_y, gregorian):
    if not gregorian:
        return astro_y % 4 == 0
    return astro_y % 4 == 0 and (astro_y % 100 != 0 or astro_y % 400 == 0)


def month_length(astro_y, m, gregorian):
    if m == 2:
        return 29 if is_leap(astro_y, gregorian) else 28
    return 31 if m in (1, 3, 5, 7, 8, 10, 12) else 30


def valid_civil(astro_y, m, d, gregorian):
    return 1 <= d <= month_length(astro_y, m, gregorian)


YEARS_NUM_RE = re.compile(r"(\d{1,4})(?:\s*(BCE|BC|AD|CE)\b)?", re.I)


def parse_years(years):
    """'1889-1950', 'c. 428-347 BC', '99 BC - 99 BC', 'c. 4 BC – AD 33', '1950-present', '1950-'
    -> (first_year, last_year) in atlas convention (negative = BCE), either may be None"""
    s = str(years or "")
    if re.search(r"\bmillenni", s, re.I):
        s = re.sub(r"\d+(st|nd|rd|th)\s+millenni\w+(\s+BCE?)?", " ", s, flags=re.I)
    s = re.sub(r"\b(\d+)(st|nd|rd|th)\s+centur\w+", " ", s, flags=re.I)
    toks = [(int(n), (mark or "").upper()) for n, mark in YEARS_NUM_RE.findall(s)]
    toks = [(n, mk) for n, mk in toks if n >= 1]
    if not toks:
        return None, None
    # a number with no era mark inherits BC from the next marked number ("384-322 BC")
    years_out = []
    for i, (n, mk) in enumerate(toks):
        era = mk
        if not era:
            for n2, mk2 in toks[i + 1:]:
                if mk2:
                    era = mk2
                    break
        years_out.append(-n if era in ("BC", "BCE") else n)
    first = years_out[0]
    last = max(years_out) if years_out else None
    if re.search(r"present|\d{4}\s*[-–]\s*$", s):
        last = PRESENT_YEAR
    return first, last


def year_tolerance(years):
    return 5 if re.search(r"\bc\.|circa|\bfl\.|approx|traditional|convention", str(years), re.I) else 1


# ---------------------------------------------------------------- precision
DATEWORD = r"(date|dating|dated|year|month|day|chronolog|when|placement|sequence|stop)"
# HARD triggers speak about the date itself; a hard trigger always removes day precision.
HARD_TRIGGERS = [
    ("defaulted", r"default"), ("approximately", r"approximat"), ("circa", r"\bcirca\b"), ("c.", r"\bc\.\s*\d|\bca\.\s*\d"),
    ("not established", r"not established"), ("not fixed", r"not fixed"), ("unknown", r"unknown"),
    ("inferred", r"\binferr"), ("traditional", r"\btradition"),
    ("undated", r"\bundated"), ("placeholder", r"placeholder"),
    ("arbitrary", r"arbitrar"), ("period only", r"period only"),
    ("legend", r"\blegend"), ("interpretive", r"interpretiv"), ("sequencing", r"sequenc"),
    ("convention", r"convention"), ("unrecorded", r"unrecorded"), ("not recorded", r"not recorded"),
    ("not given", r"not given|not stated|not specified|not supplied|not preserved|not dated|undatable"),
    ("no month/day", r"\bno (month|day|date|year)\b|without (a )?(month|day|date)"),
    ("year only", r"year only|only the year|only to the year"),
    ("to the year", r"to the year|for the year|as to (the )?year|(?<!month and )(?<!day and )(?<!month, )year attested|attested year|(?<!month and )year is attested|year certain"),
    ("year named only", r"attested (for|to|at) \d{3,4}\b(?![-/]\d)|dates? (it |this |the \w+ )?(to|at) \d{3,4}\b(?![-/]\d)"),
    ("disputed", r"disput|contest|unresolved|not resolved|rather than resolved|contradict|conflicting|discrepan|disagree|diverge|not reconciled|not adjudicated"),
    ("uncertain", r"uncertain|unsure|insecure"),
    ("probably", r"probabl|likely|perhaps|possibly|presum"), ("estimated", r"estimat"),
    ("ordering", r"(to|for) order(ing)? the|orders the (segment|stops|sequence)|ordering (only|device)|dated (only )?to order"),
    ("floruit", r"\bfl\.|floruit"),
    ("modern", r"modern (convention|reckon|handbook|chronolog|estimate)"), ("assigned", r"\bassigned|notional|symbolic"),
    ("decade/century", r"\b(decade|century|centuries|millenni)"),
    ("between", r"anywhere between|between \d|somewhere|a range of"),
    ("approximation", r"\broughly (\d|dat|c\.|the (year|month|date|decade))|\bloosely dated"),
    ("placed (the date)", r"(date|year|month|day|stop) (is |was |are )?placed|placed (at|in|on|around|just|generically|here|mid|early|late|c\.|\d)"),
    ("no source (for the date)", r"no (ancient |primary |surviving |contemporary |reachable |consulted )?(source|verse|record|document|text|testimon)[^.;]{0,50}" + DATEWORD),
    ("nominal (the date)", DATEWORD + r"[^.;]{0,20}\b(nominal|schematic|stand-in)|\b(nominal|schematic) " + DATEWORD),
    ("editorial (the date)", DATEWORD + r"[^.;]{0,30}editorial|editorial " + DATEWORD + r"|fixed here|set here|chosen here"),
    ("reconstructed (the date)", r"^\W*(\[R\]\W*)?reconstruct|reconstruct\w*[^.;]{0,40}" + DATEWORD + "|" + DATEWORD + r"[^.;]{0,30}reconstruct"),
    ("generic (the date)", r"generically|generic " + DATEWORD),
]
# SOFT triggers may be about the pin or the sources rather than the date; they remove day precision
# unless the text itself affirms the day (DAY_SURE) or is a plain "attested".
SOFT_TRIGGERS = [
    ("placed", r"\bplaced\b"), ("no source", r"no (ancient |primary |surviving |contemporary |reachable |consulted )?(source|verse|record|document|text|testimon)"),
    ("nominal", r"\bnominal|schematic|stand-in|stands in for"), ("editorial", r"editorial|chosen as a|picked (here|as)"),
    ("reconstruct", r"reconstruct"), ("generic", r"generic"),
]
# SOFT-YEAR triggers: the text names only a year, a span or a range; only an explicit day citation rescues them.
SOFT_YEAR_TRIGGERS = [
    ("year range", r"\b\d{3,4}\s*[-–]\s*\d{3,4}\b|\b\d{3,4} (to|and|or) \d{3,4}\b"),
    ("span/window", r"\bspan\b|\bwindow\b|\bperiod\b"),
    ("year named with preposition", r"\b(in|from|by|until|during|since|before|after) (c\. ?)?\d{3,4}\b(?![-/]\d)"),
]
MONTHS = r"(January|February|March|April|May|June|July|August|September|October|November|December|enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)"
FULL_DATE = r"\b\d{1,2}(st|nd|rd|th)?( of| de)? " + MONTHS + r"( de)?,? \d{3,4}\b|" + MONTHS + r" \d{1,2}(st|nd|rd|th)?,? \d{3,4}\b"
DAY_SURE = re.compile(
    r"attested to the day|day (is |and month (are )?|and month )?attested|attested (for|on|as|at) \d{1,2} [A-Z][a-z]+,? \d{3,4}"
    r"|(day and month|month and day) (are )?(attested|certain|secure|given|recorded)|with day precision|dated to the day"
    r"|exact date|precise date|date attested|attested date|" + FULL_DATE, re.I)
MONTH_SURE = re.compile(
    r"(month and year|year and month|day and month|month and day) (are )?(attested|certain|secure|known|given|recorded)"
    r"|attested (to|for|as to) the month|month (is )?(attested|certain|secure|known|given|recorded)"
    r"|to the month\b|month attested"
    r"|attested (to|for|in) " + MONTHS + r",? \d{3,4}", re.I)
# a month-year mention with no day before it ("the March 1949 presentation")
MONTH_MENTION = re.compile(r"(?<!\d )(?<!\d\d )(?<!of )(?<!de )\b" + MONTHS + r",? \d{3,4}\b", re.I)
MONTH_UNSURE = re.compile(
    r"month (and day )?(is |are )?(unknown|unrecorded|not|default|a default|placeholder|arbitrar|placed|infer|a sequenc|unattested)"
    r"|no month|month default|month and day (default|unknown|unrecorded|not)", re.I)
PLAIN_ATTESTED = re.compile(r"^\W*(\[?[A-Z]\]?\W*)?attested\b", re.I)
DATE_CLAUSE = re.compile(r"\b(date|dating|dated|year|month|day|chronolog|when|placement|sequence|calendar|born)\b|\d", re.I)


def clause_at(text, pos):
    """the clause of text (split on ; . :) that contains character position pos"""
    start = max(text.rfind(c, 0, pos) for c in ";.:") + 1
    ends = [text.find(c, pos) for c in ";.:"]
    ends = [e for e in ends if e != -1]
    end = min(ends) if ends else len(text)
    return text[start:end]


def precision_of(date_tuple, confidence):
    """-> (precision, triggers list, notes list). Conservative: any hard trigger removes day precision;
    soft-year triggers remove it unless the text cites the day; soft (pin) triggers remove it unless the
    text cites the day or opens with a plain 'attested'."""
    text = str(confidence or "")
    hard = [label for label, pat in HARD_TRIGGERS if re.search(pat, text, re.I)]
    soft_year = [label for label, pat in SOFT_YEAR_TRIGGERS if re.search(pat, text, re.I)]
    soft = [label for label, pat in SOFT_TRIGGERS if re.search(pat, text, re.I)]
    fired = hard + ["(soft-year) " + s for s in soft_year] + ["(soft) " + s for s in soft]
    notes = []
    y, m, d = date_tuple
    if d is None:
        return "month", fired + ["date given as YYYY-MM"], notes
    day_sure = bool(DAY_SURE.search(text))
    if day_sure and hard:
        # the day is explicitly attested: a hard trigger counts only if its clause is about the date
        kept, discounted = [], []
        for label, pat in HARD_TRIGGERS:
            mt = re.search(pat, text, re.I)
            if not mt:
                continue
            clause = clause_at(text, mt.start())
            if DATE_CLAUSE.search(clause):
                kept.append(label)
            else:
                discounted.append(label)
        if discounted:
            notes.append("hard triggers (%s) discounted: the day is explicitly attested and their clause names no "
                         "date, year, month or number (it concerns the pin, the house or the sources)" % ", ".join(discounted))
            fired = [f for f in fired if f not in discounted]
        hard = kept
    month_sure = (bool(MONTH_SURE.search(text)) or (bool(MONTH_MENTION.search(text)) and not day_sure)) \
        and not MONTH_UNSURE.search(text)
    if hard:
        return ("month" if month_sure else "year"), fired, notes
    if soft_year and not day_sure:
        return ("month" if month_sure else "year"), fired, notes
    if soft and not (day_sure or PLAIN_ATTESTED.search(text)):
        return ("month" if month_sure else "year"), fired, notes
    if soft or soft_year:
        notes.append("soft triggers (%s) judged to concern the pin, the sources or the surrounding narrative, not the "
                     "date, because the text cites the day%s" % (
                         ", ".join(soft_year + soft), "" if day_sure else " or opens with a plain 'attested'"))
    if month_sure and not day_sure:
        return "month", fired + ["text affirms the month, not the day"], notes
    if d == 1 and not day_sure:
        # 1 January is the atlas's default for a year-only date and the 1st the default for a month-only
        # date; a bare "attested" on such a date does not vouch for the day (the 1930-01-01 stelliums proved it)
        if m == 1:
            return "year", fired + ["01-01 with no explicit day attestation: the atlas default for a year-only date"], notes
        return "month", fired + ["day 01 with no explicit day attestation: the atlas default for a month-only date"], notes
    return "day", fired, notes


# ---------------------------------------------------------------- calendar choice per stop
def calendar_for(journey_cal, atlas_year, m, d, life_last_year):
    """-> (gregorian: bool, label, note, alternate_gregorian_flag_or_None)"""
    ay = astro_year(atlas_year)
    after_reform = (ay, m, d or 1) >= GREGORIAN_START
    jc = (journey_cal or "gregorian").lower()
    if jc in ("julian", "julian_bce"):
        if not after_reform:
            return False, "julian", "journey declares %s; date before 1582-10-15 read as Julian" % jc, None
        if atlas_year > LAST_JULIAN_CIVIL_YEAR or (life_last_year is not None and atlas_year > life_last_year):
            return True, "gregorian", ("journey declares %s but this date is after 1582-10-15 and after the subject's "
                                       "life span (years field): a reception stop, read as Gregorian" % jc), None
        return False, "julian", ("journey declares %s and the date is after 1582-10-15 but within the life span: "
                                 "read as Julian as declared; Gregorian alternative given" % jc), True
    # gregorian-labelled
    if after_reform:
        return True, "gregorian", "journey declares gregorian; date after 1582-10-15", None
    return True, "gregorian (proleptic)", ("journey declares gregorian but the date is before 1582-10-15: proleptic "
                                           "Gregorian applied as declared; Julian alternative given"), False


# ---------------------------------------------------------------- the readings
def sun_range(astro_y, m, gregorian):
    """signs the Sun occupies from the 1st to the last day of the month (sampled daily, 0h UT)"""
    signs = []
    for day in range(1, month_length(astro_y, m, gregorian) + 1):
        pos, _ = positions_at_jd(jd_from(astro_y, m, day, gregorian))
        s = E.SIGNS[E.sign_of(pos["Sun"])[0]]
        if not signs or signs[-1] != s:
            signs.append(s)
    return signs


def read_stop(journey_cal, life_last_year, seg_name, stop):
    date_s = stop.get("date")
    conf = stop.get("date_confidence")
    entry = {"segment": seg_name, "stop": stop.get("name"), "date": date_s, "date_confidence": conf}
    dt = parse_date(date_s)
    if dt is None:
        entry["error"] = "unparsed date"
        return entry
    atlas_y, m, d = dt
    ay = astro_year(atlas_y)
    gregorian, label, cal_note, alt = calendar_for(journey_cal, atlas_y, m, d, life_last_year)
    day_for_jd = d if d is not None else 1
    if not valid_civil(ay, m, day_for_jd, gregorian):
        entry["error"] = "day %d does not exist in month %d of that year in the %s calendar" % (day_for_jd, m, label)
        return entry
    if not (-2999 <= ay <= 2999):
        entry["error"] = "year outside the ephemeris's range (3000 BC - 3000 AD)"
        return entry
    precision, fired, notes = precision_of(dt, conf)
    jd = jd_from(ay, m, day_for_jd, gregorian)
    pos, T = positions_at_jd(jd)
    entry.update({
        "calendar_applied": label,
        "calendar_note": cal_note,
        "astronomical_year": ay,
        "jd_ut": round(jd, 1),
        "precision": precision,
        "precision_triggers": fired,
    })
    if notes:
        entry["notes"] = notes
    if ay < 0 or ay > 2050:
        entry.setdefault("notes", []).append(
            "far from J2000: planets to ~1 degree (Standish 2b), the Moon's abridged series to a few degrees")
    entry["sun"] = reading(pos["Sun"])
    if precision == "month":
        rng = sun_range(ay, m, gregorian)
        entry["sun_range"] = rng
        entry["sun_caveat"] = ("month precision: over this month the Sun runs %s; the degree above is for the stated day only"
                               % " -> ".join(rng))
    elif precision == "year":
        entry["sun_range"] = list(E.SIGNS)
        entry["sun_caveat"] = ("year precision: the Sun could be in any sign; the reading above is for the stated "
                               "(defaulted or conventional) day and should not be trusted")
    if precision == "day":
        for b in ["Moon"] + PLANETS:
            entry[b.lower()] = reading(pos[b])
        if alt is not None:
            alt_greg = not gregorian
            alt_jd = jd_from(ay, m, day_for_jd, alt_greg) if valid_civil(ay, m, day_for_jd, alt_greg) else None
            if alt_jd is not None:
                apos, _ = positions_at_jd(alt_jd)
                entry["alternate"] = {
                    "calendar": "gregorian" if alt_greg else "julian",
                    "note": "the same civil date read in the other calendar",
                    **{b.lower(): reading(apos[b]) for b in BODY_ORDER},
                }
        by_sign = defaultdict(list)
        for b in BODY_ORDER:
            by_sign[E.SIGNS[E.sign_of(pos[b])[0]]].append(b)
        conj = [{"sign": s, "bodies": bs} for s, bs in by_sign.items() if len(bs) >= 3]
        if conj:
            entry["conjunctions"] = conj
    else:
        entry["moon_and_planets"] = "omitted: the Moon changes sign every ~2.3 days; only day-precise stops get them"
    return entry


# ---------------------------------------------------------------- the birth
BIRTH_RE = re.compile(r"\b(birth|born|nace|naci[oó]|nacimiento)\b", re.I)


def find_birth(journey, entries):
    first, _ = parse_years(journey.get("years"))
    tol = year_tolerance(journey.get("years"))
    dated = [e for e in entries if "error" not in e]

    def year_of(e):
        return parse_date(e["date"])[0]

    def near(e):
        return first is not None and abs(year_of(e) - first) <= tol

    def sort_key(e):
        y, m, d = parse_date(e["date"])
        return (astro_year(y), m, d or 1)

    stops_by_entry = {id(e): s for e, s in zip(entries, journey_stops(journey))}
    ordered = sorted(dated, key=sort_key)
    tiers = [
        ("name matches birth/born/nace and the year matches the journey's first year",
         lambda e: BIRTH_RE.search(e["stop"] or "") and near(e)),
        ("campa mentions birth/born/nace and the year matches the journey's first year",
         lambda e: BIRTH_RE.search(stops_by_entry[id(e)].get("campa") or "") and near(e)),
        ("first stop whose year matches the journey's first year",
         lambda e: near(e)),
        ("name matches birth/born/nace (year does not match the years field: check)",
         lambda e: BIRTH_RE.search(e["stop"] or "")),
    ]
    for method, test in tiers:
        for e in ordered:
            if test(e):
                return dict(e, method=method, years_field=journey.get("years"), first_year_parsed=first)
    return {"note": "no stop identified as the birth (no birth/born/nace in a stop name, no stop in the first year %r)"
            % first, "years_field": journey.get("years"), "first_year_parsed": first}


def journey_stops(journey):
    for seg in journey.get("segments", []):
        for st in seg.get("stops", []):
            yield st


# ---------------------------------------------------------------- per journey
def process(path):
    slug = os.path.basename(path).replace(".journey.json", "")
    with open(path, encoding="utf-8") as f:
        journey = json.load(f)
    cal = journey.get("calendar", "gregorian")
    first, last = parse_years(journey.get("years"))
    entries = []
    failures = []
    for seg in journey.get("segments", []):
        for st in seg.get("stops", []):
            e = read_stop(cal, last, seg.get("name"), st)
            entries.append(e)
            if "error" in e:
                failures.append({"stop": st.get("name"), "date": st.get("date"), "error": e["error"]})
    birth = find_birth(journey, entries)
    out = {
        "slug": slug,
        "traveler": journey.get("traveler"),
        "title": journey.get("title"),
        "years": journey.get("years"),
        "years_parsed": {"first": first, "last": last},
        "calendar": cal,
        "ephemeris": os.path.basename(EPHEMERIS_PATH),
        "conventions": [
            "BCE atlas years '-0100' mean 100 BC; astronomical year = 1 - Y",
            "positions at 0h UT of the civil date; tropical signs of date",
            "Moon and planets only at day precision",
        ],
        "birth": birth,
        "stops": entries,
        "counts": {
            "stops": len(entries),
            "dated": len(entries) - len(failures),
            "unparsed": len(failures),
            "day": sum(1 for e in entries if e.get("precision") == "day"),
            "month": sum(1 for e in entries if e.get("precision") == "month"),
            "year": sum(1 for e in entries if e.get("precision") == "year"),
        },
        "parse_failures": failures,
    }
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, slug + ".zodiac.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    return out


# ---------------------------------------------------------------- the summaries
def sign_or_blank(entry, body):
    r = entry.get(body)
    return r["sign"] if isinstance(r, dict) else ""


def write_csv(results):
    path = os.path.join(OUT, "_atlas_zodiac.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "traveler", "birth_stop", "birth_date", "calendar_applied", "precision", "sun_sign",
                    "sun_degree", "sun_range", "moon_sign", "mercury_sign", "venus_sign", "mars_sign",
                    "jupiter_sign", "saturn_sign", "birth_method"])
        for r in results:
            b = r["birth"]
            if "date" not in b:
                w.writerow([r["slug"], r["traveler"], "", "", "", "", "", "", "", "", "", "", "", "", "", b.get("note", "")])
                continue
            day = b.get("precision") == "day"
            w.writerow([
                r["slug"], r["traveler"], b.get("stop"), b.get("date"), b.get("calendar_applied"), b.get("precision"),
                b["sun"]["sign"], b["sun"]["degree"], " > ".join(b.get("sun_range", [])) if b.get("precision") != "year" else "any",
                sign_or_blank(b, "moon") if day else "",
                *[sign_or_blank(b, p.lower()) if day else "" for p in PLANETS],
                b.get("method", ""),
            ])
    return path


def write_conjunctions_csv(results):
    path = os.path.join(OUT, "_atlas_conjunctions.csv")
    rows = []
    for r in results:
        for e in r["stops"]:
            for c in e.get("conjunctions", []):
                rows.append([len(c["bodies"]), c["sign"], " ".join(c["bodies"]), r["slug"], r["traveler"], e["stop"],
                             e["date"], e["calendar_applied"]])
    rows.sort(key=lambda x: (-x[0], x[1], x[3], x[6]))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["bodies_count", "sign", "bodies", "slug", "traveler", "stop", "date", "calendar_applied"])
        w.writerows(rows)
    return path, rows


def write_md(results, conj_rows, skipped):
    path = os.path.join(OUT, "_atlas_zodiac.md")
    n = len(results)
    births = [r for r in results if "date" in r["birth"]]
    day_births = [r for r in births if r["birth"]["precision"] == "day"]
    month_births = [r for r in births if r["birth"]["precision"] == "month"]
    year_births = [r for r in births if r["birth"]["precision"] == "year"]
    no_birth = [r for r in results if "date" not in r["birth"]]
    stops_total = sum(r["counts"]["stops"] for r in results)
    stops_dated = sum(r["counts"]["dated"] for r in results)
    stops_fail = sum(r["counts"]["unparsed"] for r in results)
    prec = Counter()
    trig = Counter()
    cal_applied = Counter()
    for r in results:
        for e in r["stops"]:
            if "precision" in e:
                prec[e["precision"]] += 1
                cal_applied[e["calendar_applied"]] += 1
                for t in e["precision_triggers"]:
                    trig[t] += 1
    method = Counter(r["birth"].get("method", "none") for r in results)

    L = []
    L.append("# Atlas zodiac: readings for every dated stop")
    L.append("")
    L.append("Generated by `atlas_tools/zodiac_readings.py` from the journey files; every number below is computed, "
             "none typed. Sky from the date-driven ephemeris (Standish Table 2b planets, Meeus ch. 47 Moon, IAU 2006 "
             "precession, Espenak-Meeus Delta-T), positions at 0h UT of the civil date, tropical signs of date.")
    L.append("")
    L.append("## Counts")
    L.append("")
    L.append("| what | n |")
    L.append("|---|---|")
    L.append("| journeys processed | %d |" % n)
    L.append("| journeys skipped (unreadable JSON) | %d |" % len(skipped))
    L.append("| stops | %d |" % stops_total)
    L.append("| stops with a readable date | %d |" % stops_dated)
    L.append("| stops whose date could not be read | %d |" % stops_fail)
    for p in ("day", "month", "year"):
        L.append("| stops at %s precision | %d |" % (p, prec[p]))
    L.append("| journeys with a birth stop identified | %d |" % len(births))
    L.append("| birth day-precise (Moon and planets given) | %d |" % len(day_births))
    L.append("| birth month-precise (Sun range given) | %d |" % len(month_births))
    L.append("| birth year-precise only | %d |" % len(year_births))
    L.append("| no birth stop identified | %d |" % len(no_birth))
    L.append("")
    L.append("Calendar applied per stop: " + ", ".join("%s %d" % (k, v) for k, v in cal_applied.most_common()) + ".")
    L.append("")
    L.append("How the birth stop was found: " + "; ".join("%s: %d" % (k, v) for k, v in method.most_common()) + ".")
    L.append("")
    L.append("Precision trigger words, by how many stops they fired on (a stop may fire several): "
             + ", ".join("%s %d" % (k, v) for k, v in trig.most_common()) + ".")
    L.append("")

    # Sun sign table
    L.append("## Sun sign at birth")
    L.append("")
    L.append("Day-precise births are counted by the Sun's sign at 0h UT of the date. Month-precise births are counted "
             "by the sign at the stated (usually defaulted) day, with the number whose month straddles two signs noted; "
             "those could belong to either sign of their range.")
    L.append("")
    day_c = Counter(r["birth"]["sun"]["sign"] for r in day_births)
    mon_c = Counter(r["birth"]["sun"]["sign"] for r in month_births)
    straddle = sum(1 for r in month_births if len(r["birth"].get("sun_range", [])) > 1)
    L.append("| sign | day-precise | month-precise (stated day) | total |")
    L.append("|---|---|---|---|")
    for s in E.SIGNS:
        L.append("| %s | %d | %d | %d |" % (s, day_c[s], mon_c[s], day_c[s] + mon_c[s]))
    L.append("| **all** | %d | %d | %d |" % (len(day_births), len(month_births), len(day_births) + len(month_births)))
    L.append("")
    L.append("Month-precise births whose month straddles two signs: %d of %d." % (straddle, len(month_births)))
    L.append("")

    # the twelve lists
    L.append("## The twelve lists (travellers by birth Sun sign)")
    L.append("")
    L.append("Day-precise first, then month-precise marked (month: range). Degree is the Sun's degree in the sign at 0h UT.")
    for s in E.SIGNS:
        L.append("")
        L.append("### %s (%d)" % (s, day_c[s] + mon_c[s]))
        L.append("")
        rows = sorted(day_births, key=lambda r: r["birth"]["sun"]["degree"])
        for r in rows:
            b = r["birth"]
            if b["sun"]["sign"] != s:
                continue
            extra = ""
            if b.get("alternate"):
                extra = " (alt. %s: %s)" % (b["alternate"]["calendar"], b["alternate"]["sun"]["sign"])
            L.append("- %s, %s, %s %s, Moon %s%s" % (r["traveler"], b["date"], s, b["sun"]["text"].split(" ", 1)[1],
                                                       b["moon"]["sign"], extra))
        for r in sorted(month_births, key=lambda r: r["birth"]["date"]):
            b = r["birth"]
            if b["sun"]["sign"] != s:
                continue
            L.append("- %s, %s (month: %s)" % (r["traveler"], b["date"], " -> ".join(b.get("sun_range", []))))
    L.append("")

    # births without a reading
    L.append("## Births known only to the year (no sign claimed)")
    L.append("")
    L.append("%d journeys. Their stated birth dates are conventional or defaulted; the Sun could be in any sign. "
             "Listed in `_atlas_zodiac.csv` with precision `year`." % len(year_births))
    L.append("")
    if no_birth:
        L.append("## Journeys with no birth stop identified (%d)" % len(no_birth))
        L.append("")
        for r in no_birth:
            L.append("- %s (%s): %s" % (r["traveler"], r["slug"], r["birth"].get("note", "")))
        L.append("")

    # conjunctions
    L.append("## Notable conjunctions (three or more bodies in one sign, day-precise stops)")
    L.append("")
    by_n = Counter(row[0] for row in conj_rows)
    L.append("Counted over all day-precise stops: " + ", ".join("%d bodies: %d stops" % (k, by_n[k]) for k in sorted(by_n, reverse=True))
             + ". The full list, triples included, is `_atlas_conjunctions.csv`. Sun, Mercury and Venus are never far "
               "apart, so a triple of just those three is the common case. Positions are for 0h UT, so a Moon near a "
               "sign boundary may have crossed it by the true hour.")
    L.append("")
    inner = {"Sun", "Mercury", "Venus"}
    trip_other = [row for row in conj_rows if row[0] == 3 and set(row[2].split()) != inner]
    trip_inner = [row for row in conj_rows if row[0] == 3 and set(row[2].split()) == inner]
    L.append("Triples: %d of Sun-Mercury-Venus only, %d involving the Moon or an outer planet (CSV only)."
             % (len(trip_inner), len(trip_other)))
    L.append("")
    sign_n = Counter(row[1] for row in conj_rows if row[0] >= 4)
    L.append("Four-plus gatherings by sign: " + ", ".join("%s %d" % (s, sign_n[s]) for s in E.SIGNS) + ".")
    L.append("")
    for k in sorted(by_n, reverse=True):
        if k < 4:
            continue
        rows = [row for row in conj_rows if row[0] == k]
        L.append("### %d bodies in one sign (%d stops)" % (k, len(rows)))
        L.append("")
        for row in rows:
            L.append("- %s in %s: %s, %s, %s (%s)" % (row[2].replace(" ", "-"), row[1], row[4], row[5], row[6], row[7]))
        L.append("")

    # failures
    fails = [(r["slug"], f) for r in results for f in r["parse_failures"]]
    L.append("## Dates that could not be read (%d)" % len(fails))
    L.append("")
    for slug, f in fails:
        L.append("- %s: %r at %r: %s" % (slug, f["date"], f["stop"], f["error"]))
    if skipped:
        L.append("")
        L.append("Journeys skipped: " + ", ".join(skipped))
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


# ---------------------------------------------------------------- validation
def check():
    """prints the built-in checks: wrapper vs ephemeris.positions, Nijinsky, Caesar, three famous births"""
    print("== wrapper vs ephemeris.positions (same date string, positive years) ==")
    for ds in ("1889-03-12", "1265-05-21", "2026-05-22", "1810-05-25"):
        ref = E.positions(ds)
        y, m, d, _ = E.parse_iso(ds)
        mine, _ = positions_at_jd(jd_from(y, m, d, E.is_gregorian(y, m, d)))
        worst = max(abs(E.wrap180(mine[b] - ref["bodies"][k]["lon"]))
                    for b, k in (("Sun", 3), ("Moon", 0), ("Mercury", 1), ("Venus", 2), ("Mars", 4), ("Jupiter", 5), ("Saturn", 6)))
        print("  %s  max |diff| = %.6f deg" % (ds, worst))
    print("== calendar: 1582-10-04 Julian + 1 day must be 1582-10-15 Gregorian ==")
    print("  JD(1582-10-04 J) = %.1f, JD(1582-10-15 G) = %.1f" % (jd_from(1582, 10, 4, False), jd_from(1582, 10, 15, True)))
    print("== BCE: atlas -0100-07-13 (Caesar, 13 July 100 BC) -> astro year %d, JD %.1f ==" % (astro_year(-100), jd_from(astro_year(-100), 7, 13, False)))
    print("== 0h UT Sun at the 2026 equinox/solstice dates (expect ~0/90/180/270) ==")
    for ds in ("2026-03-20", "2026-06-21", "2026-09-23", "2026-12-21"):
        y, m, d, _ = E.parse_iso(ds)
        p, _ = positions_at_jd(jd_from(y, m, d, True))
        print("  %s Sun %.2f" % (ds, p["Sun"]))
    checks = [
        ("vaslav_nijinsky", "1889-03-12", "Pisces", "born 12 March 1889 Gregorian (28 Feb Julian); Sun in Pisces"),
        ("abraham_lincoln", "1809-02-12", "Aquarius", "born 12 February 1809; Sun in Aquarius"),
        ("napoleon", "1769-08-15", "Leo", "born 15 August 1769; Sun in Leo"),
        ("karl_marx", "1818-05-05", "Taurus", "born 5 May 1818; Sun in Taurus"),
        ("newton", "1642-12-25", "Capricornus", "born 25 Dec 1642 Julian = 4 Jan 1643 Gregorian; Sun in Capricorn"),
        ("julius_caesar", "-0100-07-13", "Cancer", "born 12/13 July 100 BC (Julian proleptic); Sun in Cancer"),
    ]
    print("== births against known facts ==")
    for slug, expect_date, expect_sign, why in checks:
        path = os.path.join(JOURNEYS, slug + ".journey.json")
        if not os.path.exists(path):
            print("  %s: no journey file" % slug)
            continue
        r = process(path)
        b = r["birth"]
        if "date" not in b:
            print("  %s: NO BIRTH FOUND (%s)" % (slug, b.get("note")))
            continue
        ok_date = b["date"] == expect_date
        ok_sign = b["sun"]["sign"] == expect_sign
        verdict = "OK" if ok_date and ok_sign else "CHECK"
        alt = ""
        if b.get("alternate"):
            alt = "; alt %s: %s" % (b["alternate"]["calendar"], b["alternate"]["sun"]["text"])
        moon = b["moon"]["text"] if "moon" in b else "(not day-precise)"
        print("  %s %s: stop %r date %s [%s, %s] Sun %s Moon %s%s | expected %s %s (%s)" % (
            verdict, slug, b["stop"], b["date"], b["calendar_applied"], b["precision"], b["sun"]["text"], moon, alt,
            expect_date, expect_sign, why))


# ---------------------------------------------------------------- main
def main(argv):
    if "--check" in argv:
        check()
        return
    slugs = [a for a in argv if not a.startswith("--")]
    if slugs:
        paths = [os.path.join(JOURNEYS, s.replace(".journey.json", "") + ".journey.json") for s in slugs]
    else:
        paths = sorted(glob.glob(os.path.join(JOURNEYS, "*.journey.json")))
    results, skipped = [], []
    for p in paths:
        try:
            results.append(process(p))
        except (json.JSONDecodeError, OSError) as ex:
            skipped.append("%s (%s)" % (os.path.basename(p), ex.__class__.__name__))
    if not slugs:
        csv_path = write_csv(results)
        conj_path, conj_rows = write_conjunctions_csv(results)
        md_path = write_md(results, conj_rows, skipped)
        print("wrote", csv_path)
        print("wrote", conj_path)
        print("wrote", md_path)
    day_births = sum(1 for r in results if r["birth"].get("precision") == "day")
    fails = sum(r["counts"]["unparsed"] for r in results)
    print("journeys %d, skipped %d, unparsed dates %d, day-precise births %d" % (len(results), len(skipped), fails, day_births))
    for r in results if slugs else []:
        b = r["birth"]
        if "date" in b:
            print("  %s: birth %r %s [%s] Sun %s%s" % (
                r["slug"], b["stop"], b["date"], b["precision"], b["sun"]["text"],
                (", Moon " + b["moon"]["text"]) if "moon" in b else ""))
        else:
            print("  %s: %s" % (r["slug"], b.get("note")))


if __name__ == "__main__":
    main(sys.argv[1:])
