# Quipu type `0xce` — Celestial figure

> **STATUS: DRAFT.** Not yet implemented in `colegio_tools.py`. No
> inscriptions of this type exist on chain. This document is the spec
> against which the future `mk_celestial()` / `read_celestial()`
> functions will be written.

A *celestial figure* is a named set of named points (each in some
coordinate system), with named pairs marking which points are connected.

One inscription can encode a single point, a single line, a constellation
(many star points connected by lines tracing the figure), a path (earth
waypoints in sequence, lines between consecutive waypoints), or a mixed
figure that anchors an earth location to specific stars (a vigil, a
celestial alignment, a gaze upward).

---

## Byte layout

### Header — first bytes of the strand

```
c1dd        2B   protocol magic
0001        2B   protocol version
ce          1B   type — celestial
TT          1B   tone (00 ordinary, ff reverence)
KIND        1B   00 = all earth, 01 = all stars, 02 = mixed
K           1B   number of points (0–255)
T           1B   title length
TITLE       T B  UTF-8 figure name
```

Total fixed header: **10 bytes + title length**.

`L` (line count) is intentionally absent. Lines fill the strand from the
end of the points block to the end of the OP_RETURN stream. A reader
knows the strand is over when no further OP_RETURN-bearing transaction
spends the previous one's output 0.

### Points — packed continuously after the header

```
HOMOGENEOUS (KIND = 00 or 01)
  for each of K points:
    COORD_A    4B   IEEE 754 float32 big-endian
    COORD_B    4B   float32 big-endian
    NAMELEN    1B
    NAME       NAMELEN bytes UTF-8 (NAMELEN may be 0 for unnamed)

MIXED (KIND = 02)
  for each of K points:
    KIND_P     1B   00 = earth, 01 = star
    COORD_A    4B   float32 big-endian
    COORD_B    4B   float32 big-endian
    NAMELEN    1B
    NAME       NAMELEN bytes UTF-8
```

### Lines — packed after the points, fill rest of strand

```
for each line until end-of-stream:
  A          1B   index into points, 0 .. K−1
  B          1B   index into points
```

Two-byte pairs. No count, no separator. The strand termination is the
delimiter.

---

## Coordinate-system mapping

The `KIND` byte (figure-level for homogeneous, per-point for mixed) tells
the parser how to interpret each point's two coordinates:

| Kind | COORD_A | COORD_B | Coordinate system |
|---|---|---|---|
| `0x00` earth | latitude (°) | longitude (°) | WGS84 decimal degrees |
| `0x01` star  | right ascension (°) | declination (°) | ICRS / J2000.0 decimal degrees |

Conventions:
- Latitudes and declinations are signed, range `[−90, +90]`.
- Longitudes are signed, range `[−180, +180]`.
- Right ascensions are unsigned, range `[0, 360)`.
- All angles in decimal degrees, never hours-minutes-seconds.
- Stars are positioned at J2000.0 epoch. Proper motion is ignored;
  catalog values from any modern source (Hipparcos, Gaia, SIMBAD) work
  directly without conversion.

Float32 gives ~7 decimal digits of precision: ~1 m on Earth, ~2″ on the
celestial sphere. Both finer than naked-eye resolution and sufficient
for any catalog you'd cite.

---

## Worked example — Cassiopeia (the W)

The figure: 5 stars (Schedar, Caph, Cih, Ruchbah, Segin), 4 lines
tracing the W shape.

Source RA/Dec values (J2000.0, from SIMBAD):

| Star | RA (°) | Dec (°) |
|---|---|---|
| Schedar | 10.1268 | 56.5373 |
| Caph    |  2.2944 | 59.1497 |
| Cih     | 14.1772 | 60.7167 |
| Ruchbah | 21.4534 | 60.2353 |
| Segin   | 28.5988 | 63.6701 |

Encoded byte breakdown (homogeneous KIND = 01, no per-point kind byte):

```
Header section (20 bytes):
  c1 dd                      magic
  00 01                      version
  ce                         type = celestial
  ff                         tone = reverence
  01                         KIND = star (homogeneous)
  05                         K = 5 points
  0a                         title length = 10
  43 61 73 73 69 6f 70 65 69 61   "Cassiopeia"

Points section (5 × (8 + 1 + name) = 70 bytes):
  41 22 22 ce  42 62 25 09  07 53 63 68 65 64 61 72   Schedar  (10.1268, 56.5373)
  40 12 da 91  42 6c 99 4c  04 43 61 70 68            Caph     (2.2944, 59.1497)
  41 62 ad 95  42 72 dc 7f  03 43 69 68               Cih      (14.1772, 60.7167)
  41 ab 9b ee  42 70 e6 27  07 52 75 63 68 62 61 68   Ruchbah  (21.4534, 60.2353)
  41 e4 c8 78  42 7e ad 51  05 53 65 67 69 6e         Segin    (28.5988, 63.6701)

Lines section (4 × 2 = 8 bytes):
  00 01                       Schedar–Caph
  01 02                       Caph–Cih
  02 03                       Cih–Ruchbah
  03 04                       Ruchbah–Segin
```

**Total: 98 bytes.** Fits in 2 OP_RETURN-bearing transactions per strand.

(The exact float32 byte sequences above are illustrative; the
reference encoder below produces the bit-exact values.)

---

## Reference parser (Python, ~30 lines)

```python
import struct

def read_celestial(payload: bytes) -> dict:
    """Parse the entire body of a 0xce celestial quipu (after the
    c1dd0001ce TT protocol header has already been stripped, OR including
    it — both work). Returns a dict with name, points, lines."""

    # If protocol header is included, strip it.
    if payload[:4] == b'\xc1\xdd\x00\x01':
        assert payload[4] == 0xce, "not a celestial quipu"
        payload = payload[6:]   # skip magic+version+type+tone

    p = 0
    kind = payload[p]; p += 1
    K    = payload[p]; p += 1
    T    = payload[p]; p += 1
    title = payload[p:p+T].decode('utf-8'); p += T

    points = []
    for _ in range(K):
        if kind == 0x02:
            kp = payload[p]; p += 1
        else:
            kp = kind
        a, b = struct.unpack('>ff', payload[p:p+8]); p += 8
        nl = payload[p]; p += 1
        name = payload[p:p+nl].decode('utf-8'); p += nl
        if kp == 0x00:
            points.append({'kind': 'earth', 'lat': a, 'lng': b, 'name': name})
        elif kp == 0x01:
            points.append({'kind': 'star',  'ra':  a, 'dec': b, 'name': name})
        else:
            raise ValueError(f"unknown point kind {kp:#x}")

    # Remaining bytes are line index pairs
    lines = []
    while p + 1 < len(payload):
        lines.append((payload[p], payload[p+1])); p += 2

    return {'name': title, 'points': points, 'lines': lines}
```

The encoder is the symmetric inverse, ~25 lines.

---

## Why `0xce`

`ce` is the start of the Latin word *cælum* — sky, heaven, the celestial
sphere. Reads cleanly in hex dumps. No collision with existing protocol
bytes (`03` image, `04` reserved, `05` reserved, `0e` encrypted, `1d`
identity, `cc` certificate, `f0` error proof).

---

## Open questions

1. **Should COORD_A / COORD_B for stars carry distance as well?**
   Currently the celestial sphere is treated as 2D (RA, Dec) — the
   inscription places a direction-on-sky, not a 3D star position. If
   distance matters (parsec for nearby stars, Gpc for galaxies), a
   future protocol-version bump could add an optional 4-byte distance
   field per star point. For now: direction only.

2. **Should there be a coord-system tag richer than earth/star?**
   The current 2-value `KIND` covers the WGS84 / ICRS pair we'll use
   immediately. Future systems (galactic coordinates `(l, b)`, ecliptic
   `(λ, β)`, selenographic for the lunar surface) would need new KIND
   values: `0x03`, `0x04`, etc. Reserved without committing.

3. **Symmetry of lines.** Lines are unordered pairs `{A, B}` — there's
   no semantic difference between writing `(0, 1)` and `(1, 0)`. For
   paths where direction matters (a pilgrimage walked east), the
   inscriber convention is "lines listed in walked order, A is the
   earlier waypoint, B is the next."

4. **Repeated names.** Names within a single figure should be unique
   (the line block references points by index, but a reader displaying
   the figure may key by name). Spec is currently silent — readers
   should treat duplicate names as a malformed inscription.
