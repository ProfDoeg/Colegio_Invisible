"""
celestial.py — 0xce celestial-figure quipu type (clean redesign, May 2026).

This is a full redesign that abandons backward compatibility with the only
pre-canonical 0xce inscription on chain (Sky of al-Jawza, root 4e53bb26…),
which is now treated as a draft prototype outside the canonical corpus.

Design principle: every byte in the header carries exactly one meaning. No
bit-packed flags. A hexdump of the header is directly readable: each byte
position has a stable, single semantic role.

Spec
----
HEADER (12 + T bytes):

    c1dd 0001                       magic + protocol version 0.1
    ce                              type byte = celestial
    <tone:1>                        00 ordinary, 0d demonic, ff reverence
    <kind:1>                        00 earth, 01 star
    <grouped:1>                     00 ungrouped (lines block follows points)
                                    01 grouped   (groups block follows points)
    <meta:1>                        00 no per-point metadata
                                    01 per-point metadata present
    <K_hi K_lo>                     point count, uint16 big-endian (max 65535)
    <T:1>                           title length in UTF-8 bytes
    <title:T>                       UTF-8 title

POINTS BLOCK (K records, each):

    [<pmeta:1>]                     present iff figure header's <meta> = 01
                                      00 no metadata for this point
                                      01 time present, exact precision
                                      02 time present, day precision (noon JD)
                                      03 time present, month precision (15th noon)
                                      04 time present, year precision (Jul 1 noon)
    <a:f32-be>                       lat (earth) | RA (star)
    <b:f32-be>                       lng (earth) | dec (star)
    [<jd:f64-be>]                    present iff pmeta > 00
    <namelen:1>
    <name:namelen>                   UTF-8

UNGROUPED LINES BLOCK (when grouped = 00): fills remainder of body with
4-byte (a_hi a_lo b_hi b_lo) uint16 BE index pairs.

GROUPED BODY (when grouped = 01):

    <G_hi G_lo>                     group count, uint16 BE
    for each group:
        <namelen:1> <name>
        <P_hi P_lo>  P × <idx_hi idx_lo>             point indices, uint16 BE
        <L_hi L_lo>  L × <a_hi a_lo b_hi b_lo>       line pairs, uint16 BE

Coordinate conventions
    earth (kind 0x00): a = latitude [-90, +90], b = longitude [-180, +180]
    star  (kind 0x01): a = RA [0, 360),         b = declination [-90, +90]
    All angles in decimal degrees; star positions at J2000.0 epoch.

Time encoding
    Astronomical Julian Day Number as IEEE 754 binary64, big-endian.
    JD 0 = noon UT, 1 Jan 4713 BCE (proleptic Julian).
    JD 2451545.0 = noon UT, 1 Jan 2000 (J2000.0).
    Handles BCE dates with no special-casing.
    Times are defined on earth points in v1; pmeta > 00 on star points is
    rejected at build and read time, reserving star-time semantics for a
    future Estandarte amendment.

Standalone points
    A point in the points block need not be referenced by any line nor be a
    member of any group. Such points are standalone markers — in a star
    figure they represent isolated objects; in a timed earth figure they
    represent location-events (something happened at this place at this time
    but it is not part of a journey path). Renderers must draw every point.

Removed in this redesign
    - KIND_MIXED (0x02) — bad science; never canonical.
    - 1-byte K — replaced by uint16 BE for atlas-scale figures.
    - Bit-packed flags in the kind byte — split into separate <kind>,
      <grouped>, and <meta> byte fields for readability.
"""

from __future__ import annotations

import struct


# ---------------------------------------------------------------------------
# Constants — each is the value of a single byte field
# ---------------------------------------------------------------------------

TYPE_CELESTIAL    = 0xCE

TONE_ORDINARY     = 0x00
TONE_DEMONIC      = 0x0D
TONE_REVERENCE    = 0xFF
_VALID_TONES      = (TONE_ORDINARY, TONE_DEMONIC, TONE_REVERENCE)

# kind byte (header offset 6)
KIND_EARTH        = 0x00
KIND_STAR         = 0x01

# grouped byte (header offset 7)
GROUPED_NO        = 0x00
GROUPED_YES       = 0x01

# meta byte (header offset 8)
META_NO           = 0x00
META_YES          = 0x01

# pmeta byte (per-point, present iff figure meta = 01)
PMETA_NONE        = 0x00
PMETA_TIME_EXACT  = 0x01
PMETA_TIME_DAY    = 0x02
PMETA_TIME_MONTH  = 0x03
PMETA_TIME_YEAR   = 0x04

_KIND_NAME_TO_BYTE = {"earth": KIND_EARTH, "star": KIND_STAR}
_KIND_BYTE_TO_NAME = {v: k for k, v in _KIND_NAME_TO_BYTE.items()}

_PRECISION_NAME_TO_PMETA = {
    "exact": PMETA_TIME_EXACT,
    "day":   PMETA_TIME_DAY,
    "month": PMETA_TIME_MONTH,
    "year":  PMETA_TIME_YEAR,
}
_PMETA_TO_PRECISION_NAME = {v: k for k, v in _PRECISION_NAME_TO_PMETA.items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_kind(kind):
    if isinstance(kind, int):
        return kind
    if isinstance(kind, str):
        try:
            return _KIND_NAME_TO_BYTE[kind.lower()]
        except KeyError:
            raise ValueError(
                f"unknown kind {kind!r}; expected 'earth' or 'star' "
                f"(mixed was removed in the May 2026 redesign)"
            )
    raise TypeError(f"kind must be int or str, got {type(kind).__name__}")


def _pmeta_for_point(pt, figure_kind, idx):
    """Compute the per-point pmeta byte for a point. Returns 0 if untimed."""
    if "time" not in pt or pt["time"] is None:
        return PMETA_NONE
    if figure_kind != KIND_EARTH:
        raise ValueError(
            f"point {idx}: time is defined for earth points only in v1 "
            f"(star-point times reserved for a future Estandarte amendment)"
        )
    prec_name = pt.get("time_precision", "exact")
    if isinstance(prec_name, int):
        # Caller passed a raw pmeta value
        if prec_name not in (PMETA_TIME_EXACT, PMETA_TIME_DAY,
                             PMETA_TIME_MONTH, PMETA_TIME_YEAR):
            raise ValueError(
                f"point {idx}: pmeta value {prec_name} out of v1 range (1..4)"
            )
        return prec_name
    if not isinstance(prec_name, str):
        raise TypeError(
            f"point {idx}: time_precision must be int or str, "
            f"got {type(prec_name).__name__}"
        )
    try:
        return _PRECISION_NAME_TO_PMETA[prec_name.lower()]
    except KeyError:
        raise ValueError(
            f"point {idx}: unknown time_precision {prec_name!r}; "
            f"expected 'exact', 'day', 'month', or 'year'"
        )


def _figure_needs_meta(points, figure_kind):
    """meta byte = 01 iff any point declares a time."""
    for i, pt in enumerate(points):
        if _pmeta_for_point(pt, figure_kind, i) != PMETA_NONE:
            return META_YES
    return META_NO


def _build_header(title, kind, grouped, meta, K, tone):
    if tone not in _VALID_TONES:
        raise ValueError(f"tone must be 0x00, 0x0d, or 0xff (got {tone:#04x})")
    if kind not in (KIND_EARTH, KIND_STAR):
        raise ValueError(f"kind must be 0x00 or 0x01 (got {kind:#04x})")
    if grouped not in (GROUPED_NO, GROUPED_YES):
        raise ValueError(f"grouped must be 0x00 or 0x01 (got {grouped:#04x})")
    if meta not in (META_NO, META_YES):
        raise ValueError(f"meta must be 0x00 or 0x01 (got {meta:#04x})")
    if K > 0xFFFF:
        raise ValueError(f"max 65535 points per figure (got {K})")
    title_bytes = title.encode("utf-8")
    if len(title_bytes) > 255:
        raise ValueError(
            f"title encodes to {len(title_bytes)} UTF-8 bytes; max 255"
        )
    return (
        b"\xc1\xdd\x00\x01"
        + bytes([TYPE_CELESTIAL])
        + bytes([tone])
        + bytes([kind])
        + bytes([grouped])
        + bytes([meta])
        + struct.pack(">H", K)
        + bytes([len(title_bytes)])
        + title_bytes
    )


def _emit_point(pt, figure_kind, figure_meta, idx):
    """Serialize one point record."""
    if "name" not in pt:
        raise ValueError(f"point {idx} missing required 'name' key")
    name_bytes = pt["name"].encode("utf-8")
    if len(name_bytes) > 255:
        raise ValueError(
            f"point {idx} name encodes to {len(name_bytes)} UTF-8 bytes; max 255"
        )

    if figure_kind == KIND_EARTH:
        try:
            a = float(pt["lat"]); b = float(pt["lng"])
        except KeyError as e:
            raise ValueError(f"earth point {idx} missing required key {e.args[0]!r}")
        if not (-90.0 <= a <= 90.0):
            raise ValueError(
                f"point {idx} ({pt['name']!r}) latitude {a} out of [-90, +90]"
            )
        if not (-180.0 <= b <= 180.0):
            raise ValueError(
                f"point {idx} ({pt['name']!r}) longitude {b} out of [-180, +180]"
            )
    elif figure_kind == KIND_STAR:
        try:
            a = float(pt["ra"]); b = float(pt["dec"])
        except KeyError as e:
            raise ValueError(f"star point {idx} missing required key {e.args[0]!r}")
        if not (0.0 <= a < 360.0):
            raise ValueError(
                f"point {idx} ({pt['name']!r}) RA {a} out of [0, 360)"
            )
        if not (-90.0 <= b <= 90.0):
            raise ValueError(
                f"point {idx} ({pt['name']!r}) declination {b} out of [-90, +90]"
            )
    else:
        raise ValueError(f"unknown figure_kind {figure_kind:#04x}")

    buf = b""

    if figure_meta == META_YES:
        pmeta = _pmeta_for_point(pt, figure_kind, idx)
        buf += bytes([pmeta])

    buf += struct.pack(">ff", a, b)

    if figure_meta == META_YES and _pmeta_for_point(pt, figure_kind, idx) != PMETA_NONE:
        buf += struct.pack(">d", float(pt["time"]))

    buf += bytes([len(name_bytes)]) + name_bytes
    return buf


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_celestial_quipu(title, kind, points, lines, tone=TONE_ORDINARY):
    """Build an ungrouped 0xce celestial-figure quipu.

    Args:
        title: UTF-8 title, ≤ 255 bytes.
        kind:  'earth' or 'star' (or 0x00 / 0x01).
        points: list of point dicts:
            earth: {'name': str, 'lat': float, 'lng': float,
                    ['time': float JD, 'time_precision': 'exact'|'day'|'month'|'year']}
            star : {'name': str, 'ra':  float, 'dec': float}
            If any point declares 'time', the figure's meta byte is set to 01
            and every point in the figure carries a 1-byte pmeta prefix.
        lines: list of (a, b) integer index pairs into points. Self-loops and
               out-of-range indices rejected.
        tone:  TONE_ORDINARY (0x00), TONE_DEMONIC (0x0d), or TONE_REVERENCE (0xff).

    Returns:
        (header_bytes, body_bytes)
    """
    figure_kind = _coerce_kind(kind)
    if figure_kind not in (KIND_EARTH, KIND_STAR):
        raise ValueError(
            f"kind must be 'earth' or 'star'; got {figure_kind:#04x}"
        )

    K = len(points)
    meta = _figure_needs_meta(points, figure_kind)

    header = _build_header(title, figure_kind, GROUPED_NO, meta, K, tone)

    points_blob = b""
    for i, pt in enumerate(points):
        points_blob += _emit_point(pt, figure_kind, meta, i)

    lines_blob = b""
    for li, pair in enumerate(lines):
        if len(pair) != 2:
            raise ValueError(f"line {li} must be a (a, b) 2-tuple (got {pair!r})")
        a_idx, b_idx = pair
        if not (0 <= a_idx < K) or not (0 <= b_idx < K):
            raise ValueError(
                f"line {li} index out of range: ({a_idx}, {b_idx}) with K={K}"
            )
        if a_idx == b_idx:
            raise ValueError(
                f"line {li} is degenerate: point {a_idx} connected to itself"
            )
        if a_idx > 0xFFFF or b_idx > 0xFFFF:
            raise ValueError(f"line {li} index exceeds uint16: ({a_idx}, {b_idx})")
        lines_blob += struct.pack(">HH", a_idx, b_idx)

    return header, points_blob + lines_blob


def build_grouped_celestial_quipu(title, kind, points, groups, tone=TONE_ORDINARY):
    """Build a grouped 0xce celestial-figure quipu.

    A point may appear in zero, one, or many groups, and may be referenced by
    zero or more lines. Standalone points (in no group, no line) are legal.

    Args:
        title, kind, points, tone: same as build_celestial_quipu.
        groups: list of (group_name, point_indices, line_pairs) tuples.

    Returns:
        (header_bytes, body_bytes)
    """
    figure_kind = _coerce_kind(kind)
    if figure_kind not in (KIND_EARTH, KIND_STAR):
        raise ValueError(
            f"kind must be 'earth' or 'star'; got {figure_kind:#04x}"
        )

    K = len(points)
    meta = _figure_needs_meta(points, figure_kind)

    G = len(groups)
    if G > 0xFFFF:
        raise ValueError(f"max 65535 groups per figure (got {G})")

    header = _build_header(title, figure_kind, GROUPED_YES, meta, K, tone)

    points_blob = b""
    for i, pt in enumerate(points):
        points_blob += _emit_point(pt, figure_kind, meta, i)

    groups_blob = struct.pack(">H", G)
    for gi, (gname, p_indices, l_pairs) in enumerate(groups):
        gname_bytes = gname.encode("utf-8")
        if len(gname_bytes) > 255:
            raise ValueError(f"group {gi} name length {len(gname_bytes)} > 255")
        P = len(p_indices)
        if P > 0xFFFF:
            raise ValueError(f"group {gi} point count {P} > 65535")
        L = len(l_pairs)
        if L > 0xFFFF:
            raise ValueError(f"group {gi} line count {L} > 65535")
        for idx in p_indices:
            if not (0 <= idx < K):
                raise ValueError(f"group {gi} point index {idx} out of range")
        for li, pair in enumerate(l_pairs):
            if len(pair) != 2:
                raise ValueError(f"group {gi} line {li} must be 2-tuple")
            a_idx, b_idx = pair
            if not (0 <= a_idx < K) or not (0 <= b_idx < K):
                raise ValueError(
                    f"group {gi} line {li} ({a_idx},{b_idx}) out of range"
                )
            if a_idx == b_idx:
                raise ValueError(f"group {gi} line {li} is degenerate self-loop")

        groups_blob += bytes([len(gname_bytes)]) + gname_bytes
        groups_blob += struct.pack(">H", P)
        for idx in p_indices:
            groups_blob += struct.pack(">H", idx)
        groups_blob += struct.pack(">H", L)
        for a_idx, b_idx in l_pairs:
            groups_blob += struct.pack(">HH", a_idx, b_idx)

    return header, points_blob + groups_blob


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_celestial_quipu(header_bytes, body_bytes):
    """Parse the bytes of a 0xce celestial quipu (clean v1).

    Returns:
        {
          'title':  str,
          'tone':   int (0x00 / 0x0d / 0xff),
          'kind':   'earth' | 'star',
          'grouped': bool,
          'meta':   bool,
          'points': [{'kind': str, 'name': str, ...coords...,
                      ['time': float JD, 'time_precision': str]} ...],
          'lines':  [(int_a, int_b), ...],         # group-flattened
          'groups': None | [{'name': str, 'point_indices': [int...],
                             'lines': [(int_a, int_b), ...]} ...],
        }
    """
    if header_bytes[:4] != b"\xc1\xdd\x00\x01":
        raise ValueError("not a quipu (c1dd0001 magic missing from header)")
    if len(header_bytes) < 12:
        raise ValueError(
            f"header too short: {len(header_bytes)} bytes (need ≥ 12)"
        )
    if header_bytes[4] != TYPE_CELESTIAL:
        raise ValueError(
            f"not a celestial quipu (type byte = {header_bytes[4]:#04x}, "
            f"expected 0xce)"
        )

    tone        = header_bytes[5]
    figure_kind = header_bytes[6]
    grouped     = header_bytes[7]
    meta        = header_bytes[8]
    K           = struct.unpack(">H", header_bytes[9:11])[0]
    T           = header_bytes[11]
    title_bytes = header_bytes[12:12 + T]
    if len(title_bytes) != T:
        raise ValueError(
            f"header truncated: declared title length {T} but only "
            f"{len(title_bytes)} bytes available"
        )
    title = title_bytes.decode("utf-8")

    if figure_kind not in (KIND_EARTH, KIND_STAR):
        raise ValueError(
            f"kind byte {figure_kind:#04x} not defined in v1 "
            f"(only 0x00 earth and 0x01 star)"
        )
    if grouped not in (GROUPED_NO, GROUPED_YES):
        raise ValueError(f"grouped byte {grouped:#04x} must be 0x00 or 0x01")
    if meta not in (META_NO, META_YES):
        raise ValueError(f"meta byte {meta:#04x} must be 0x00 or 0x01")
    kind_name = _KIND_BYTE_TO_NAME[figure_kind]

    p = 0
    points = []
    for i in range(K):
        if meta == META_YES:
            if p >= len(body_bytes):
                raise ValueError(f"body truncated reading point {i} pmeta")
            pmeta = body_bytes[p]; p += 1
            if pmeta not in (PMETA_NONE, PMETA_TIME_EXACT, PMETA_TIME_DAY,
                             PMETA_TIME_MONTH, PMETA_TIME_YEAR):
                raise ValueError(
                    f"point {i}: pmeta {pmeta:#04x} not defined in v1 (0..4)"
                )
        else:
            pmeta = PMETA_NONE

        if p + 8 > len(body_bytes):
            raise ValueError(f"body truncated reading coords for point {i}")
        a, b = struct.unpack(">ff", body_bytes[p:p + 8])
        p += 8

        if pmeta != PMETA_NONE:
            if figure_kind != KIND_EARTH:
                raise ValueError(
                    f"point {i}: pmeta {pmeta:#04x} (time) on a non-earth figure "
                    f"(v1 reserves star-point times for a future amendment)"
                )
            if p + 8 > len(body_bytes):
                raise ValueError(f"body truncated reading JD for point {i}")
            jd = struct.unpack(">d", body_bytes[p:p + 8])[0]
            p += 8
        else:
            jd = None

        if p >= len(body_bytes):
            raise ValueError(f"body truncated reading name length for point {i}")
        nl = body_bytes[p]; p += 1
        if p + nl > len(body_bytes):
            raise ValueError(
                f"body truncated reading name for point {i} "
                f"(need {nl} bytes, have {len(body_bytes) - p})"
            )
        name = body_bytes[p:p + nl].decode("utf-8")
        p += nl

        if figure_kind == KIND_EARTH:
            pt = {"kind": "earth", "lat": a, "lng": b, "name": name}
        else:
            pt = {"kind": "star", "ra": a, "dec": b, "name": name}
        if pmeta != PMETA_NONE:
            pt["time"] = jd
            pt["time_precision"] = _PMETA_TO_PRECISION_NAME[pmeta]
        points.append(pt)

    if grouped == GROUPED_NO:
        remaining = len(body_bytes) - p
        if remaining % 4 != 0:
            raise ValueError(
                f"line block has {remaining} trailing bytes; "
                f"expected multiple of 4 (uint16 BE index pairs)"
            )
        lines = []
        while p + 4 <= len(body_bytes):
            a_idx, b_idx = struct.unpack(">HH", body_bytes[p:p + 4])
            p += 4
            if a_idx >= K or b_idx >= K:
                raise ValueError(
                    f"line ({a_idx},{b_idx}) references index >= K ({K})"
                )
            lines.append((a_idx, b_idx))
        return {
            "title": title, "tone": tone, "kind": kind_name,
            "grouped": False, "meta": meta == META_YES,
            "points": points, "lines": lines, "groups": None,
        }

    # Grouped body
    if p + 2 > len(body_bytes):
        raise ValueError("body truncated reading group count G")
    G = struct.unpack(">H", body_bytes[p:p + 2])[0]; p += 2
    groups = []
    all_lines = []
    for gi in range(G):
        if p >= len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} name length")
        gn = body_bytes[p]; p += 1
        if p + gn > len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} name")
        gname = body_bytes[p:p + gn].decode("utf-8"); p += gn

        if p + 2 > len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} point count")
        P_g = struct.unpack(">H", body_bytes[p:p + 2])[0]; p += 2
        if p + P_g * 2 > len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} point indices")
        p_indices = []
        for _ in range(P_g):
            idx = struct.unpack(">H", body_bytes[p:p + 2])[0]; p += 2
            if idx >= K:
                raise ValueError(
                    f"group {gi} ({gname!r}) point index {idx} >= K ({K})"
                )
            p_indices.append(idx)

        if p + 2 > len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} line count")
        L_g = struct.unpack(">H", body_bytes[p:p + 2])[0]; p += 2
        if p + L_g * 4 > len(body_bytes):
            raise ValueError(f"body truncated reading group {gi} line pairs")
        g_lines = []
        for _ in range(L_g):
            a_idx, b_idx = struct.unpack(">HH", body_bytes[p:p + 4]); p += 4
            if a_idx >= K or b_idx >= K:
                raise ValueError(
                    f"group {gi} ({gname!r}) line ({a_idx},{b_idx}) "
                    f"references index >= K ({K})"
                )
            g_lines.append((a_idx, b_idx))
            all_lines.append((a_idx, b_idx))
        groups.append({"name": gname, "point_indices": p_indices, "lines": g_lines})

    return {
        "title": title, "tone": tone, "kind": kind_name,
        "grouped": True, "meta": meta == META_YES,
        "points": points, "lines": all_lines, "groups": groups,
    }


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

CASSIOPEIA_POINTS = [
    {"name": "Schedar", "ra": 10.1268, "dec": 56.5373},
    {"name": "Caph",    "ra":  2.2944, "dec": 59.1497},
    {"name": "Cih",     "ra": 14.1772, "dec": 60.7167},
    {"name": "Ruchbah", "ra": 21.4534, "dec": 60.2353},
    {"name": "Segin",   "ra": 28.5988, "dec": 63.6701},
]
CASSIOPEIA_LINES = [(0, 1), (1, 2), (2, 3), (3, 4)]


def _selftest_cassiopeia():
    h, b = build_celestial_quipu(
        "Cassiopeia", "star", CASSIOPEIA_POINTS, CASSIOPEIA_LINES,
        tone=TONE_REVERENCE,
    )
    print(f"=== Cassiopeia (ungrouped star, untimed) ===")
    print(f"  header {len(h)}B body {len(b)}B total {len(h)+len(b)}B")
    print(f"  header hex: {h.hex()}")
    assert h[:4] == b"\xc1\xdd\x00\x01"
    assert h[4] == TYPE_CELESTIAL
    assert h[5] == TONE_REVERENCE
    assert h[6] == KIND_STAR
    assert h[7] == GROUPED_NO
    assert h[8] == META_NO
    assert struct.unpack(">H", h[9:11])[0] == 5
    assert h[11] == len("Cassiopeia")
    assert h[12:] == b"Cassiopeia"

    parsed = read_celestial_quipu(h, b)
    assert parsed["title"] == "Cassiopeia"
    assert parsed["kind"] == "star"
    assert parsed["grouped"] is False
    assert parsed["meta"] is False
    assert parsed["lines"] == CASSIOPEIA_LINES
    for orig, got in zip(CASSIOPEIA_POINTS, parsed["points"]):
        assert abs(orig["ra"]  - got["ra"])  < 1e-4
        assert abs(orig["dec"] - got["dec"]) < 1e-4
        assert "time" not in got
    print(f"  ✓ round-trip OK")
    print()


def _selftest_bordados():
    pts = [
        {"name": "Domrémy",      "lat": 48.4392, "lng":  5.6736},
        {"name": "La Verna",     "lat": 43.7053, "lng": 11.9358},
        {"name": "Monte Verità", "lat": 46.1683, "lng":  8.7706},
    ]
    h, b = build_celestial_quipu(
        "Bordado landscape pilgrimage", "earth", pts, [(0, 1), (1, 2)],
        tone=TONE_REVERENCE,
    )
    print(f"=== Three-bordado pilgrimage (ungrouped earth, untimed) ===")
    print(f"  header {len(h)}B body {len(b)}B")
    assert h[6] == KIND_EARTH
    assert h[7] == GROUPED_NO
    assert h[8] == META_NO

    parsed = read_celestial_quipu(h, b)
    assert parsed["kind"] == "earth"
    assert parsed["meta"] is False
    for orig, got in zip(pts, parsed["points"]):
        assert abs(orig["lat"] - got["lat"]) < 1e-4
        assert "time" not in got
    print(f"  ✓ meta byte correctly = 0x00; round-trip OK")
    print()


def _selftest_joan():
    pts = [
        {"name": "Domrémy",      "lat": 48.4392, "lng":  5.6736,
         "time": 2237165.5, "time_precision": "year"},
        {"name": "Vaucouleurs",  "lat": 48.6080, "lng":  5.6675,
         "time": 2244907.5, "time_precision": "day"},
        {"name": "Chinon",       "lat": 47.1668, "lng":  0.2400,
         "time": 2244974.5, "time_precision": "day"},
        {"name": "Orléans",      "lat": 47.9029, "lng":  1.9039,
         "time": 2245043.5, "time_precision": "day"},
        {"name": "Reims",        "lat": 49.2583, "lng":  4.0317,
         "time": 2245122.5, "time_precision": "day"},
        {"name": "Rouen",        "lat": 49.4431, "lng":  1.0993,
         "time": 2245795.5, "time_precision": "day"},
    ]
    lines = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]
    h, b = build_celestial_quipu(
        "La pucelle: Domrémy à Rouen", "earth", pts, lines,
        tone=TONE_REVERENCE,
    )
    print(f"=== Joan of Arc (ungrouped earth, fully timed) ===")
    print(f"  header {len(h)}B body {len(b)}B")
    assert h[6] == KIND_EARTH
    assert h[7] == GROUPED_NO
    assert h[8] == META_YES

    parsed = read_celestial_quipu(h, b)
    assert parsed["meta"] is True
    for orig, got in zip(pts, parsed["points"]):
        assert "time" in got
        assert abs(orig["time"] - got["time"]) < 1e-6
        assert got["time_precision"] == orig["time_precision"]
    print(f"  ✓ kind=0x00 grouped=0x00 meta=0x01; pmeta enum preserved")
    print()


def _selftest_grouped_star():
    pts = [
        {"name": "Alnitak",  "ra": 85.1897, "dec": -1.9426},
        {"name": "Alnilam",  "ra": 84.0533, "dec": -1.2019},
        {"name": "Mintaka",  "ra": 83.0017, "dec": -0.2991},
        {"name": "Alcyone",  "ra": 56.8711, "dec": 24.1051},
        {"name": "Atlas",    "ra": 57.2914, "dec": 24.0533},
    ]
    groups = [
        ("Orion's belt",  [0, 1, 2], [(0, 1), (1, 2)]),
        ("Pleiades stub", [3, 4],    [(3, 4)]),
    ]
    h, b = build_grouped_celestial_quipu(
        "Belt and stub", "star", pts, groups, tone=TONE_ORDINARY,
    )
    print(f"=== Grouped star (Orion's belt + Pleiades stub) ===")
    print(f"  header {len(h)}B body {len(b)}B")
    assert h[6] == KIND_STAR
    assert h[7] == GROUPED_YES
    assert h[8] == META_NO

    parsed = read_celestial_quipu(h, b)
    assert parsed["grouped"] is True
    assert len(parsed["groups"]) == 2
    assert parsed["groups"][0]["name"] == "Orion's belt"
    print(f"  ✓ kind=0x01 grouped=0x01 meta=0x00; groups round-trip OK")
    print()


def _selftest_grouped_earth_with_standalone_event():
    pts = [
        {"name": "Rome",   "lat": 41.8967, "lng": 12.4822,
         "time": 2374121.5, "time_precision": "day"},
        {"name": "Naples", "lat": 40.8359, "lng": 14.2488,
         "time": 2374241.5, "time_precision": "day"},
        {"name": "Schwendemann assassination", "lat": 41.8967, "lng": 12.4822,
         "time": 2374130.5, "time_precision": "month"},
    ]
    groups = [
        ("Itinerary",    [0, 1], [(0, 1)]),
        ("Roman events", [2],    []),
    ]
    h, b = build_grouped_celestial_quipu(
        "Tiny Goethe slice", "earth", pts, groups, tone=TONE_REVERENCE,
    )
    print(f"=== Grouped earth with standalone event (Goethe slice) ===")
    print(f"  header {len(h)}B body {len(b)}B")
    assert h[6] == KIND_EARTH
    assert h[7] == GROUPED_YES
    assert h[8] == META_YES

    parsed = read_celestial_quipu(h, b)
    assert len(parsed["points"]) == 3
    assert len(parsed["lines"]) == 1
    assert parsed["points"][2]["name"] == "Schwendemann assassination"
    assert parsed["points"][2]["time_precision"] == "month"
    print(f"  ✓ kind=0x00 grouped=0x01 meta=0x01; standalone point OK")
    print()


def _selftest_large_K():
    pts = [{"name": f"s{i}", "ra": (i * 0.1) % 360.0, "dec": 0.0}
           for i in range(1000)]
    h, b = build_celestial_quipu("1000 stars", "star", pts, [])
    print(f"=== Large K test (1000 points) ===")
    print(f"  header {len(h)}B body {len(b)}B")
    assert struct.unpack(">H", h[9:11])[0] == 1000
    parsed = read_celestial_quipu(h, b)
    assert len(parsed["points"]) == 1000
    print(f"  ✓ K=1000 round-trip OK")
    print()


def _selftest_validation():
    cases = [
        ("lat out of range",
         lambda: build_celestial_quipu(
             "x", "earth", [{"name": "a", "lat": 91.0, "lng": 0.0}], []),
         "latitude"),
        ("RA out of range",
         lambda: build_celestial_quipu(
             "x", "star", [{"name": "a", "ra": 360.0, "dec": 0.0}], []),
         "RA"),
        ("self-loop line",
         lambda: build_celestial_quipu(
             "x", "star",
             [{"name": "a", "ra": 0.0, "dec": 0.0},
              {"name": "b", "ra": 1.0, "dec": 0.0}], [(0, 0)]),
         "degenerate"),
        ("line index out of range",
         lambda: build_celestial_quipu(
             "x", "star", [{"name": "a", "ra": 0.0, "dec": 0.0}], [(0, 1)]),
         "out of range"),
        ("time on star point",
         lambda: build_celestial_quipu(
             "x", "star",
             [{"name": "a", "ra": 0.0, "dec": 0.0, "time": 2451545.0}], []),
         "earth points only"),
        ("mixed kind no longer allowed",
         lambda: build_celestial_quipu("x", "mixed", [], []),
         "earth"),
        ("unknown time_precision",
         lambda: build_celestial_quipu(
             "x", "earth",
             [{"name": "a", "lat": 0.0, "lng": 0.0,
               "time": 2451545.0, "time_precision": "nanosecond"}], []),
         "time_precision"),
    ]
    print(f"=== Validation tests ===")
    for desc, fn, want in cases:
        try:
            fn()
        except (ValueError, TypeError) as e:
            status = "OK" if want in str(e) else "WRONG ERR"
            print(f"  {desc:40s} -> {status}: {e}")
        else:
            print(f"  {desc:40s} -> DID NOT RAISE (bug)")
    print()


if __name__ == "__main__":
    _selftest_cassiopeia()
    _selftest_bordados()
    _selftest_joan()
    _selftest_grouped_star()
    _selftest_grouped_earth_with_standalone_event()
    _selftest_large_K()
    _selftest_validation()
