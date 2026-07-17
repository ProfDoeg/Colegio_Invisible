# Quipu type `0xce` — Celestial figure

> **STATUS: CANONICAL v1 · v2 declared** (redesigned May 2026; v2 layout
> per [c1dd0002](../design/c1dd0002.md), registered in
> `canonical/registry_v2.py`). Implemented in `canonical/celestial.py`
> (builder + reader, both versions) and `canonical/celestial_render.py`
> (matplotlib rendering); the node-edge kinds live in `etymology.py` /
> `network.py` / `genealogy_to_tikz.py`. One pre-canonical prototype exists on
> chain at root `4e53bb26…` (Sky of al-Jawza, inscribed under a 1-byte-K
> draft); it is abandoned and outside the canonical corpus.

A *celestial figure* is a named set of named points (each in some
coordinate system), with named pairs marking which points are connected,
optionally grouped into named constellations, and optionally timestamped
for journey atlases.

One inscription can encode:

- a single star or earth point
- a constellation (many star points connected by lines)
- a path (earth waypoints in sequence)
- a timed journey (earth waypoints with Julian Day timestamps and chronological arrowing)
- a grouped figure (multiple named groups in one inscription, e.g. atlas plates)
- a location-event (standalone point with timestamp, not on any path)

---

## Design principle

Every byte in the header carries exactly one meaning. There is no
bit-packing within a byte. A hexdump of the header is directly readable:
each byte position has a stable, single semantic role. This is a
deliberate trade of compactness for human-decodability.

---

## Byte layout

### Header — 12 + T bytes

```
offset  bytes        meaning
0..1    c1 dd        magic
2..3    <version>    protocol version, uint16 BE (0001 v1, 0002 v2)
4       ce           type byte = celestial
5       <tone>       tone byte — see tone.md for the canonical vocabulary
6       <kind>       00 earth, 01 star, 02 mixed (per-point system byte),
                     03 genealogy, 04 etymology, 05 network (node-edge
                     bodies — routed to their own codecs; grouped and
                     meta MUST be 00 for kinds 03–05)
7       <grouped>    00 ungrouped (lines block follows points block)
                     01 grouped   (groups block follows points block)
8       <meta>       00 no per-point metadata
                     01 per-point pmeta byte + optional jd   (v1 ONLY)
                     02 per-point more-block of typed variables
9..10   <K_hi K_lo>  point count, uint16 big-endian (max 65535)
11      <T>          title length in UTF-8 bytes
12..    <title>      UTF-8 figure name
```

For a **mixed** figure (`kind = 02`) each point record opens with its
own 1-byte `system` tag (00 earth / 01 star) — coordinates are read
per-point, not per-figure. With `meta = 02` each point carries, after
its name, `morelen:u16` + a more-block of typed variables from the
atom namespace (`canonical/atoms.py`): `Nvar:u8`, then per variable
`keylen:u8 · key · atom:u8 · value`.

### Points block — K records, each:

```
[<pmeta:1>]          present iff figure header's <meta> = 01
                       00 no metadata for this point
                       01 time present, exact precision
                       02 time present, day precision (noon JD)
                       03 time present, month precision (15th noon JD)
                       04 time present, year precision (Jul 1 noon JD)
<a:f32-be>           lat (earth) | RA (star)
<b:f32-be>           lng (earth) | dec (star)
[<jd:f64-be>]        present iff pmeta > 00
<namelen:1>          UTF-8 name length
<name:namelen>       UTF-8 point name (may be empty for unnamed)
```

### Ungrouped lines block — when `<grouped> = 00`

Fills the remainder of the body with 4-byte uint16-big-endian index pairs:

```
for each line until end-of-body:
    <a_hi a_lo>      index A, uint16 BE
    <b_hi b_lo>      index B, uint16 BE
```

No count field, no separator. The strand termination is the delimiter. A
point referenced by no line is a **standalone marker** — see below.

### Grouped body — when `<grouped> = 01`

```
<G_hi G_lo>          group count, uint16 BE
for each group:
    <namelen:1>      group name length
    <name>           UTF-8 group name
    <P_hi P_lo>      P = point count in this group, uint16 BE
    P × <idx_hi idx_lo>           point indices, each uint16 BE
    <L_hi L_lo>      L = line count in this group, uint16 BE
    L × <a_hi a_lo b_hi b_lo>     line pairs, each two uint16 BE
```

A point may appear in zero, one, or many groups. A point referenced by
no group renders with default styling.

---

## Coordinate-system mapping

The `<kind>` byte tells the parser how to interpret each point's two
coordinates:

| `<kind>` | a | b | Coordinate system |
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
  directly.

Coordinates are f32 — **lossy by decision, not by default**
([c1dd0002 §7.6](../design/c1dd0002.md)): quantization is ~2.4 m on
the ground, ~0.08 arcsec on the sky. Both finer than naked-eye
resolution and sufficient for any catalog you'd cite; an astrometric
need someday becomes its own kind carrying f64 atoms.

---

## Time encoding

The optional Julian Day field is IEEE 754 binary64 big-endian
(`>d` in Python `struct`).

```
JD 0          noon UT, 1 Jan 4713 BCE (proleptic Julian — handles BCE dates)
JD 2451545.0  noon UT, 1 Jan 2000 (J2000.0)
JD 2244907.5  noon UT, 23 Feb 1429 (Joan of Arc departs Vaucouleurs)
JD 2374121.5  noon UT, 29 Oct 1786 (Goethe enters Rome)
```

The `<pmeta>` enum byte advertises how literally to take the JD:

- `01 exact` — the JD points at a specific moment (event happened at this second).
- `02 day` — JD points at noon UT; the renderer should treat the value as `the day of [date]` rather than `at 12:00 UT on [date]`.
- `03 month` — JD points at the 15th of the month at noon UT; the value means `during [month] [year]`.
- `04 year` — JD points at July 1 at noon UT; the value means `during [year]`.

Times are defined on **earth points only**. `<pmeta>` > `00` on a
star point is rejected at build and read time, reserving star-point time
semantics (epoch, observation log, variable-star photometry) — if a
dated sky is ever truly needed it enters as its own declared
subtype/version, not as a leak.

**The pmeta path is v1-only.** The v2 grammar has exactly one date
mechanism — the typed date var (see the v2 section below); `meta = 01`
is not in the v2 grammar and a v2 blob carrying it is malformed.

---

## Standalone points

A point in the points block need not be referenced by any line nor be a
member of any group. Such a point is a **standalone marker**:

- In a **star figure**: an isolated object — a supernova, an asterism
  of one, a discovered asteroid.
- In a **timed earth figure**: a **location-event** — something
  happened at this place at this time but it is not part of the
  journey path. Example: Goethe in Rome, Nov 1786, hearing of the
  Schwendemann assassination — point at Rome, dated Nov 1786, with no
  incident line.

Renderers must draw every point in the points block, then draw every
line; they must not skip points that no line references.

---

## Worked example — Cassiopeia (the W)

5 stars (Schedar, Caph, Cih, Ruchbah, Segin), 4 lines tracing the W.
RA/Dec values from SIMBAD, J2000.0:

| Star | RA (°) | Dec (°) |
|---|---|---|
| Schedar | 10.1268 | 56.5373 |
| Caph    |  2.2944 | 59.1497 |
| Cih     | 14.1772 | 60.7167 |
| Ruchbah | 21.4534 | 60.2353 |
| Segin   | 28.5988 | 63.6701 |

Encoded byte breakdown:

```
Header (22 bytes):
  c1 dd 00 01                         magic + version
  ce                                  type = celestial
  ff                                  tone = reverence
  01                                  kind = star
  00                                  grouped = ungrouped
  00                                  meta = no metadata
  00 05                               K = 5 (uint16 BE)
  0a                                  T = 10
  43 61 73 73 69 6f 70 65 69 61       "Cassiopeia"

Points block (5 × 13 = 65 bytes — no pmeta byte since meta = 00):
  41 22 22 ce  42 62 25 09  07 Schedar
  40 12 da 91  42 6c 99 4c  04 Caph
  41 62 ad 95  42 72 dc 7f  03 Cih
  41 ab 9b ee  42 70 e6 27  07 Ruchbah
  41 e4 c8 78  42 7e ad 51  05 Segin

Lines block (4 × 4 = 16 bytes — uint16 BE pairs):
  00 00 00 01                         Schedar–Caph
  00 01 00 02                         Caph–Cih
  00 02 00 03                         Cih–Ruchbah
  00 03 00 04                         Ruchbah–Segin
```

**Total: 22 + 87 = 109 bytes.** Fits in 2 OP_RETURN-bearing transactions.

---

## Worked example — Joan of Arc journey (timed earth)

6 earth points, all with timestamps. Demonstrates the `<meta>` and
`<pmeta>` fields:

```
Header (41 bytes):
  c1 dd 00 01                         magic
  ce                                  type
  ff                                  tone = reverence
  00                                  kind = earth
  00                                  grouped = ungrouped
  01                                  meta = per-point metadata present
  00 06                               K = 6
  1e                                  T = 30 (UTF-8 byte length of title)
  4c 61 20 70 75 63 65 6c 6c 65 …    "La pucelle: Domrémy à Rouen"

Points (each: 1 pmeta + 8 coords + 8 jd + 1 namelen + name):
  04 <f32 48.4392> <f32 5.6736> <f64 2237165.5> 07 Domrémy        pmeta=04 (year)
  02 <f32 48.6080> <f32 5.6675> <f64 2244907.5> 0b Vaucouleurs    pmeta=02 (day)
  02 <f32 47.1668> <f32 0.2400> <f64 2244974.5> 06 Chinon
  02 <f32 47.9029> <f32 1.9039> <f64 2245043.5> 08 Orléans
  02 <f32 49.2583> <f32 4.0317> <f64 2245122.5> 05 Reims
  02 <f32 49.4431> <f32 1.0993> <f64 2245795.5> 05 Rouen

Lines (5 × 4 = 20 bytes, sequential journey):
  00 00 00 01  00 01 00 02  00 02 00 03  00 03 00 04  00 04 00 05
```

A renderer that handles the `<meta>` flag draws the lines as arrows from
earlier to later (chronological direction). One that doesn't handle the
flag still draws the points and the lines correctly; the time fields
are ignored.

---

## Header decomposition matrix

| Figure type | kind | grouped | meta | example |
|---|---|---|---|---|
| ungrouped star, untimed | 00 | 00 | 00 | Cassiopeia |
| ungrouped earth, untimed | 00 | 00 | 00 | 3-bordado pilgrimage |
| ungrouped earth, timed | 00 | 00 | 01 | Joan of Arc |
| grouped star, untimed | 01 | 01 | 00 | Sky of al-Jawza, Bode atlas |
| grouped earth, untimed | 00 | 01 | 00 | atlas of pilgrimage sites |
| grouped earth, timed | 00 | 01 | 01 | Goethe Italian Journey by phase |

A `kind = 01` (star) figure with `meta = 01` is currently rejected at
build/read time, since `pmeta > 00` on a star point is reserved for a
future amendment.

---

## Reference parser

See [`canonical/celestial.py`](../../canonical/celestial.py) for the
authoritative builder + reader. Round-trip self-tests cover:

- Cassiopeia (untimed star)
- Three-bordado pilgrimage (untimed earth)
- Joan of Arc (timed earth, ungrouped)
- Orion belt + Pleiades stub (grouped star)
- Tiny Goethe slice (grouped earth, timed, with standalone event-point)
- K = 1000 (proves the uint16 widening works at scale)
- 7 validation cases

---

## Why `0xce`

`ce` is the start of the Latin word *cælum* — sky, heaven, the celestial
sphere. Reads cleanly in hex dumps. No collision with existing protocol
bytes (`00` text, `03` image, `07` audio, `0e` encrypted, `1d` identity,
`ab` binding, `cc` certificate, `ee` Estandarte).

---

## Removed in this redesign (vs. the pre-canonical prototype)

- **`KIND_MIXED` (0x02)** — removed as bit-packed sloppiness, later
  **restored by amendment** with clean semantics: each point record
  opens with its own `system` byte, and a renderer gives the two
  coordinate systems separate plots — never one shared set of axes.
- **1-byte K** — replaced by uint16 BE so atlas-scale figures (Bode,
  IAU 88) fit in one quipu.
- **Bit-packed flags in the kind byte** — split into separate `<kind>`,
  `<grouped>`, and `<meta>` bytes so every byte in the header has
  exactly one meaning.

---

## v2 — the second standard (`c1dd0002`)

Declared by the v2 registry (`canonical/registry_v2.py`, a keyed
override of v1's celestial entry riding the estandarte chain) and
dispatched by the version at header bytes 2–3. Per the re-engineering
criterion, v2 owes v1's layout nothing — v1 blobs keep their parser
forever, selected by their version byte.

**What changes in v2:**

- **One date mechanism.** The typed date var is the only way a point
  carries time: atom `0x02`, wire `precision:u8 · jd:f64-BE` (9 bytes),
  precision `00 unspecified · 01 exact · 02 day · 03 month · 04 year`,
  legal on **earth points only** — a date var on a star-tagged point is
  refused uniformly. The v1 pmeta path (`meta = 01`) is not part of
  the v2 grammar. Precision is **structural** — the granularity the
  datum has, never how sure anyone is; no certainty vocabulary exists
  anywhere in the standard. A renderer widens the marker to the
  precision instead of fabricating noon-of-July-1 specificity.
- **The atom namespace is law.** More-block variables range over the
  full atom table (`canonical/atoms.py`, `0x00 text` … `0x08 bytes`),
  declared on chain by the v2 registry's `atoms` convention — the
  variable-union statement. v1 more-blocks remain limited to
  text/ref/date, with the 8-byte precision-less date.
- **The node-edge kinds enter the law.** `03 genealogy`, `04
  etymology`, `05 network` — on chain and in code since birth, now
  declared. Their bodies route around the point reader by the kind
  byte at offset 6; `grouped`/`meta` are reserved MUST-be-0 for them.
  v2 network node types are a **closed enum of four**
  (place/agent/relay/resource): `NTYPE_UNCERTAIN` is not in the v2
  grammar (resolved 2026-07-17 — the last certainty-flavored byte).
- **f32 ratified.** Coordinates and the genealogy/etymology year spans
  stay f32, quantization stated honestly above.

**Unchanged:** the envelope, the points/lines/groups framing, the K
u16, the earth/star/mixed coordinate semantics, standalone points, and
every inscribed v1 blob — a mixed-version corpus is correct by
construction. The heavens enter time through the event: a dated earth
point may carry a `ref` var citing a star figure; the star stays
timeless on the sphere.

---

## Open questions

1. **Should COORD_A / COORD_B for stars carry distance as well?**
   Currently the celestial sphere is treated as 2D (RA, Dec) — the
   inscription places a direction-on-sky, not a 3D star position. If
   distance matters (parsec for nearby stars, Gpc for galaxies), a
   future amendment could allocate a new `pmeta` value carrying an
   additional f32 distance. For now: direction only.

2. **New coordinate systems beyond earth/star.**
   Galactic `(l, b)`, ecliptic `(λ, β)`, selenographic for the lunar
   surface — each would need a new `<kind>` value (`0x02`, `0x03`, …).
   Reserved without committing.

3. **Star-point times.** Reserved, indefinitely and honestly — v2
   resolved the v1 side door by closing, not lifting. Future use cases
   (epoch, observation log, variable-star photometry) enter as their
   own declared subtype/version with their own render semantics, never
   as a leak.

4. **Repeated names.** Names within a single figure should be unique
   (lines reference by index, but a reader may key by name). The spec
   is silent; readers should treat duplicate names as malformed.

5. **Symmetry of lines.** Lines are unordered pairs `{A, B}` in the
   wire format. For paths where direction matters (a pilgrimage, a
   timed journey), the inscriber convention is `A = earlier, B = later`
   and the renderer arrows accordingly when `<meta>` is set.
