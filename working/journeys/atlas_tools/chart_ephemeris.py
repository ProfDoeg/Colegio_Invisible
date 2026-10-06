#!/usr/bin/env python3
"""Chart-grade additions to the date-driven ephemeris, for natal_chart.py.

Imports private_notes/essay_gemini/reels/ephemeris.py by path (never edits it) and adds what a complete
astrological chart needs beyond the seven classical bodies it already gives:

  * Uranus, Neptune, Pluto      Standish, "Keplerian Elements for Approximate Positions of the Major Planets",
                                Table 2b (3000 BC - 3000 AD) with its extra M terms (b, c, s, f), the same
                                table and the same Kepler solver the base module uses for Mercury..Saturn.
  * Moon's mean north node      Meeus, Astronomical Algorithms, 47.7 (Omega); South Node = Omega + 180.
  * true obliquity of date      Meeus 22.2 (mean obliquity) + 22 (abridged nutation in obliquity, 4 terms).
  * nutation in longitude       Meeus 22 abridged (4 terms); used for apparent sidereal time.
  * sidereal time               GMST Meeus 12.4, apparent = + Delta-psi cos(eps); LST = GST + east longitude.
  * Ascendant, Midheaven        the standard spherical formulas from RAMC, obliquity and latitude.
  * houses                      whole-sign (from the Ascendant's sign, or from any given sign) and Placidus
                                (the classical iterative semi-arc method; cusps 11, 12, 2, 3 and opposites;
                                undefined above the polar circles, reported as such).
  * retrograde and speed        longitude at t+0.5 d minus t-0.5 d (deg/day; negative = retrograde).
  * aspects                     conjunction 0, sextile 60, square 90, trine 120, opposition 180 between all
                                bodies plus Ascendant and MC; orbs 8 Sun/Moon, 6 planets, 3 nodes and angles
                                (a pair uses the smaller of its two orbs); applying/separating from the speeds.

All longitudes are tropical geocentric longitudes of date, degrees; time is UT.
"""
import importlib.util
import math
import os
import sys

EPHEMERIS_PATH = os.environ.get(
    "ATLAS_EPHEMERIS", "/home/drdoeg/private_notes/essay_gemini/reels/ephemeris.py")
_spec = importlib.util.spec_from_file_location("ephemeris", EPHEMERIS_PATH)
if _spec is None or not os.path.exists(EPHEMERIS_PATH):
    sys.exit(f"ephemeris not found at {EPHEMERIS_PATH} (set ATLAS_EPHEMERIS)")
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)

D2R, R2D = math.pi / 180.0, 180.0 / math.pi
J2000 = E.J2000
SIGNS = E.SIGNS

# ------------------------------------------------------------------ Standish Table 2b: the outer planets
# a (au), e, I (deg), L (deg), long.peri (deg), long.node (deg); each (value at J2000, rate per century)
OUTER_2B = {
    "uranus":  ((19.18797948, -0.00020455), (0.04685740, -0.00001550), (0.77298127, -0.00180155),
                (314.20276625, 428.49512595), (172.43404441, 0.09266985), (73.96250215, 0.05739699)),
    "neptune": ((30.06952752, 0.00006447), (0.00895439, 0.00000818), (1.77005520, 0.00022400),
                (304.22289287, 218.46515314), (46.68158724, 0.01009938), (131.78635853, -0.00606302)),
    "pluto":   ((39.48686035, 0.00449751), (0.24885238, 0.00006016), (17.14104260, 0.00000501),
                (238.96535011, 145.18042903), (224.09702598, -0.00968827), (110.30167986, -0.00809981)),
}
# extra terms: M = L - long.peri + b T^2 + c cos(f T) + s sin(f T)   (deg; f in deg per century)
OUTER_EXTRA_2B = {
    "uranus":  (0.00058331, -0.97731848, 0.17689245, 7.67025000),
    "neptune": (-0.00041348, 0.68346318, -0.10162547, 7.67025000),
    "pluto":   (-0.01262724, 0.0, 0.0, 0.0),
}

BODIES = ["Sun", "Moon", "Mercury", "Venus", "Mars", "Jupiter", "Saturn", "Uranus", "Neptune", "Pluto",
          "North Node", "South Node"]
GLYPH = {"Sun": "☉", "Moon": "☽", "Mercury": "☿", "Venus": "♀", "Mars": "♂", "Jupiter": "♃", "Saturn": "♄",
         "Uranus": "♅", "Neptune": "♆", "Pluto": "♇", "North Node": "☊", "South Node": "☋",
         "Ascendant": "Asc", "MC": "MC"}


def helio_xyz_outer(planet, T):
    """heliocentric J2000-ecliptic position (au) of uranus/neptune/pluto, Standish 2b + extra terms"""
    el = OUTER_2B[planet]
    a, e, I, L, wbar, Om = (v0 + v1 * T for v0, v1 in el)
    b, c, s, f = OUTER_EXTRA_2B[planet]
    M = L - wbar + b * T * T + c * math.cos(f * T * D2R) + s * math.sin(f * T * D2R)
    w = wbar - Om
    Ecc = E.kepler(M, e)
    xp = a * (math.cos(Ecc * D2R) - e)
    yp = a * math.sqrt(1.0 - e * e) * math.sin(Ecc * D2R)
    cw, sw = math.cos(w * D2R), math.sin(w * D2R)
    cO, sO = math.cos(Om * D2R), math.sin(Om * D2R)
    cI, sI = math.cos(I * D2R), math.sin(I * D2R)
    x = (cw * cO - sw * sO * cI) * xp + (-sw * cO - cw * sO * cI) * yp
    y = (cw * sO + sw * cO * cI) * xp + (-sw * sO + cw * cO * cI) * yp
    z = (sw * sI) * xp + (cw * sI) * yp
    return x, y, z


# ------------------------------------------------------------------ time
def centuries(jd_ut):
    """(T_TT, T_UT, decimal year) for a JD in UT"""
    year = 2000.0 + (jd_ut - J2000) / 365.25
    jd_tt = jd_ut + E.delta_t(year) / 86400.0
    return (jd_tt - J2000) / 36525.0, (jd_ut - J2000) / 36525.0, year


def mean_node(T):
    """Moon's mean ascending node, Meeus 47.7 (deg)"""
    return E.wrap360(125.0445479 - 1934.1362891 * T + 0.0020754 * T ** 2 + T ** 3 / 467441.0 - T ** 4 / 60616000.0)


def nutation(T):
    """(Delta-psi, Delta-epsilon) in degrees, Meeus ch. 22 abridged (the four largest terms)"""
    Om = mean_node(T) * D2R
    L = (280.4665 + 36000.7698 * T) * D2R
    Lp = (218.3165 + 481267.8813 * T) * D2R
    dpsi = (-17.20 * math.sin(Om) - 1.32 * math.sin(2 * L) - 0.23 * math.sin(2 * Lp) + 0.21 * math.sin(2 * Om)) / 3600.0
    deps = (9.20 * math.cos(Om) + 0.57 * math.cos(2 * L) + 0.10 * math.cos(2 * Lp) - 0.09 * math.cos(2 * Om)) / 3600.0
    return dpsi, deps


def obliquity(T):
    """(true obliquity of date, mean obliquity) in degrees, Meeus 22.2 + nutation"""
    eps0 = (23.0 + 26.0 / 60 + 21.448 / 3600) - (46.8150 * T + 0.00059 * T ** 2 - 0.001813 * T ** 3) / 3600.0
    _, deps = nutation(T)
    return eps0 + deps, eps0


def sidereal_time(jd_ut, lng_east=0.0):
    """(GMST, apparent GST, LST) in degrees; Meeus 12.4; LST adds the east longitude"""
    T_tt, T_ut, _ = centuries(jd_ut)
    gmst = E.wrap360(280.46061837 + 360.98564736629 * (jd_ut - J2000) + 0.000387933 * T_ut ** 2 - T_ut ** 3 / 38710000.0)
    dpsi, _ = nutation(T_tt)
    eps, _ = obliquity(T_tt)
    gast = E.wrap360(gmst + dpsi * math.cos(eps * D2R))
    return gmst, gast, E.wrap360(gast + lng_east)


# ------------------------------------------------------------------ positions
def longitudes(jd_ut):
    """tropical geocentric longitudes of date (deg) for the twelve BODIES at a JD (UT)"""
    T, _, _ = centuries(jd_ut)
    pA = E.precession_in_longitude(T)
    ex, ey, _ = E.helio_xyz("earth", T, "2b")
    out = {"Sun": E.wrap360(E.lon_of(-ex, -ey) + pA)}
    for _, name in E.PLANET_OF.items():
        px, py, _ = E.helio_xyz(name, T, "2b")
        out[name.capitalize()] = E.wrap360(E.lon_of(px - ex, py - ey) + pA)
    for name in ("uranus", "neptune", "pluto"):
        px, py, _ = helio_xyz_outer(name, T)
        out[name.capitalize()] = E.wrap360(E.lon_of(px - ex, py - ey) + pA)
    ml, _ = E.moon_longitude(T)
    out["Moon"] = ml
    node = mean_node(T)
    out["North Node"] = node
    out["South Node"] = E.wrap360(node + 180.0)
    return out


def speeds(jd_ut):
    """daily motion (deg/day) of each body from the longitudes at jd-0.5 and jd+0.5; negative = retrograde"""
    a = longitudes(jd_ut - 0.5)
    b = longitudes(jd_ut + 0.5)
    return {k: E.wrap180(b[k] - a[k]) for k in a}


# ------------------------------------------------------------------ angles and houses
def ecliptic_lon_of_ra(ra_deg, eps_deg):
    """longitude of the ecliptic point whose right ascension is ra (deg)"""
    return E.wrap360(math.atan2(math.sin(ra_deg * D2R), math.cos(ra_deg * D2R) * math.cos(eps_deg * D2R)) * R2D)


def midheaven(ramc_deg, eps_deg):
    return ecliptic_lon_of_ra(ramc_deg, eps_deg)


def ascendant(ramc_deg, eps_deg, lat_deg):
    """Ascendant longitude (deg): atan2(cos RAMC, -(sin RAMC cos eps + tan lat sin eps))"""
    r, e, p = ramc_deg * D2R, eps_deg * D2R, lat_deg * D2R
    asc = math.atan2(math.cos(r), -(math.sin(r) * math.cos(e) + math.tan(p) * math.sin(e))) * R2D
    return E.wrap360(asc)


def placidus_cusps(ramc_deg, eps_deg, lat_deg, asc_deg, mc_deg):
    """the twelve Placidus cusps (deg), or None where the method is undefined (|lat| >= 90 - eps)"""
    if abs(lat_deg) >= 90.0 - eps_deg:
        return None
    te, tp = math.tan(eps_deg * D2R), math.tan(lat_deg * D2R)

    def solve(offset, f, below):
        ra = ramc_deg + offset
        for _ in range(60):
            x = math.sin(ra * D2R) * te * tp
            x = max(-1.0, min(1.0, x))
            if below:
                new = ramc_deg + 180.0 - math.acos(x) * R2D * f
            else:
                new = ramc_deg + math.acos(-x) * R2D * f
            if abs(E.wrap180(new - ra)) < 1e-7:
                ra = new
                break
            ra = new
        return ecliptic_lon_of_ra(ra, eps_deg)

    c11 = solve(30.0, 1.0 / 3.0, False)
    c12 = solve(60.0, 2.0 / 3.0, False)
    c2 = solve(120.0, 2.0 / 3.0, True)
    c3 = solve(150.0, 1.0 / 3.0, True)
    cusps = [asc_deg, c2, c3, E.wrap360(mc_deg + 180.0), E.wrap360(c11 + 180.0), E.wrap360(c12 + 180.0),
             E.wrap360(asc_deg + 180.0), E.wrap360(c2 + 180.0), E.wrap360(c3 + 180.0), mc_deg, c11, c12]
    return cusps


def whole_sign_cusps(first_sign_index):
    return [E.wrap360(30.0 * ((first_sign_index + i) % 12)) for i in range(12)]


def house_of(lon, cusps):
    """1..12: the house whose cusp is the last one at or before lon, going counter-clockwise"""
    for i in range(12):
        a, b = cusps[i], cusps[(i + 1) % 12]
        span = E.wrap360(b - a)
        if E.wrap360(lon - a) < span:
            return i + 1
    return 12


def angles(jd_ut, lat_deg, lng_east_deg):
    """dict(ramc, lst, eps, asc, mc, desc, ic) for a moment and place"""
    T, _, _ = centuries(jd_ut)
    eps, _ = obliquity(T)
    _, _, lst = sidereal_time(jd_ut, lng_east_deg)
    mc = midheaven(lst, eps)
    asc = ascendant(lst, eps, lat_deg)
    # the MC must be the meridian point above the horizon: within 180 deg counter-clockwise behind the Asc
    if not (0.0 < E.wrap360(asc - mc) < 180.0):
        mc = E.wrap360(mc + 180.0)
    return {"ramc": lst, "lst": lst, "eps": eps, "asc": asc, "mc": mc,
            "desc": E.wrap360(asc + 180.0), "ic": E.wrap360(mc + 180.0)}


# ------------------------------------------------------------------ aspects
ASPECTS = [("conjunction", 0.0, "☌"), ("sextile", 60.0, "⚹"), ("square", 90.0, "□"), ("trine", 120.0, "△"),
           ("opposition", 180.0, "☍")]
LUMINARIES = {"Sun", "Moon"}
TIGHT = {"North Node", "South Node", "Ascendant", "MC"}


def orb_for(a, b):
    def one(x):
        if x in TIGHT:
            return 3.0
        if x in LUMINARIES:
            return 8.0
        return 6.0
    return min(one(a), one(b))


def aspects(lons, spd):
    """all aspects among the keys of lons (deg); spd gives deg/day for the moving bodies (angles absent).
    Returns a list of dicts sorted by orb."""
    keys = list(lons)
    out = []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            if {a, b} == {"North Node", "South Node"}:
                continue
            sep = abs(E.wrap180(lons[b] - lons[a]))
            for name, angle, glyph in ASPECTS:
                orb = abs(sep - angle)
                limit = orb_for(a, b)
                if orb <= limit:
                    phase = "n/a (angle)"
                    if a in spd and b in spd:
                        # separation half a day later, from the daily motions
                        sep_next = abs(E.wrap180((lons[b] + 0.5 * spd[b]) - (lons[a] + 0.5 * spd[a])))
                        phase = "applying" if abs(sep_next - angle) < orb else "separating"
                    out.append({"a": a, "b": b, "aspect": name, "glyph": glyph, "angle": angle,
                                "orb": round(orb, 2), "orb_limit": limit, "phase": phase})
    out.sort(key=lambda x: x["orb"])
    return out


# ------------------------------------------------------------------ self-test
if __name__ == "__main__":
    # J2000 positions of the outer planets, for the eye: Uranus ~314.8, Neptune ~303.2, Pluto ~251.4 (tropical)
    L = longitudes(J2000)
    for k in ("Uranus", "Neptune", "Pluto", "North Node"):
        print(f"{k:11s} {L[k]:8.3f}  {E.sign_text(L[k])}")
    T, _, _ = centuries(J2000)
    print("obliquity J2000", obliquity(T))
    print("GMST 2000-01-01 0h UT (expect 100.46 deg = 6h41m50s)", sidereal_time(J2000 - 0.5)[0])
