# Future data types — scratch notes

Captured 2026-08-16, from a conversation with Anthony about extending the
atlas beyond individual traveler journeys. Not a work order — nothing here
gets built until Anthony says go on a specific piece.

## What already exists (rediscovered mid-conversation, more built than either
## of us remembered)

`working/networks/` already holds a second, parallel pillar to
`working/journeys/`: standing webs of connection instead of one traveler's
chronological path. Five of them, already fully built:

- `templar.network.json` — the Templars as a banking/transfer network,
  1119-1312, houses from Jerusalem to Paris
- `rothschild.network.json` — five houses in five states, one capital,
  1798-1938
- `cybersyn.network.json` — Chile's economy wired to one control room, July
  1971 to 11 September 1973
- `invisible-college.network.json` — the Hartlib correspondence and what
  came out of it, 1628-1700 (the project's own namesake)
- `qhapaq.network.json` — the Inca road system (Qhapaq Ñan) at imperial
  extent, Pachacuti to the conquest — the exact kind of thing Anthony meant
  by "network" in tonight's conversation (ceque lines, pilgrim routes, wire
  services), independently already done

`build_network_globe.py` renders any of these onto the same translucent
globe shell the journey atlas uses (`joan_globe.html` is the donor). The
real design idea, already implemented: nodes WITH coordinates pin to the
surface; nodes WITHOUT coordinates (agents, corporations, crowns — things
with no fixed locus) float free and get pulled every frame toward the mean
position of their neighbours. Since those neighbours are pinned ON the
sphere, that mean lies INSIDE it — nobody positions the placeless nodes by
hand, the edges do it, migrating inward on their own. Edge types are typed
and colored: road, sea_lane, river, wire, relay, credit, kinship, uncertain.

So the "networks" idea from tonight isn't a new feature to design — it's an
existing, working system that just needs feeding. The real question for any
new network idea is just: does it fit `{nodes, edges}` with the existing
ntype/etype vocabulary, or does it need a new edge type added.

## New idea 1: gods as a two-layer entity

Not a journey (no single chronological life) and not quite a network either
— closer to a network with "shared worship" as the edge instead of a
physical route. Two layers under one god-entity:

- **the myths**, told in the same biography-shaped house style as a
  traveler's journey (present tense, mythic register), even though the
  subject was never one person in one place
- **the worship**, a literal network file: every temple/church/shrine
  dedicated to the god, as `network.json` nodes pinned to real coordinates,
  edges representing spread/succession/syncretism between cult sites

Much of the myth material is arguably already scattered through existing
traveler files (Kojève reading Hegel's dialectic, Zoroaster's light/dark
cosmology surfacing in the Philip K. Dick VALIS stop) rather than living
anywhere of its own. A god-entity could pull those threads into one place.

## New idea 2: constellations, detailing the myth per constellation

Prompted by realizing `johann_bode.journey.json` already exists (he's
researched) but nothing captures HIS constellations — Bode's 1801
Uranographia named/popularized a set of constellations beyond the classical
48, several now-obsolete (Officina Typographica, Globus Aerostaticus, and
others that didn't survive into the IAU's modern 88). Anthony wants the
actual myths behind each constellation detailed, not just the star-pattern.

Likely shape: same two-layer pattern as gods — a fixed sky position (no
lat/lng, but RA/Dec or similar) instead of worship geography, paired with
the myth narrative in house style. Could plausibly reuse the network schema
again, with "stars in the pattern" as nodes and the constellation's own
myth as the connecting narrative, or could warrant its own simpler format
since constellations don't move the way cult networks spread over time.
Worth deciding once a first constellation is attempted as a prototype,
same way `templar.network.json` was clearly the prototype for the whole
networks pillar.

## Open questions, not yet decided

- Does "gods" reuse `network.json` directly, or need its own schema variant
  (a `deity.json` combining a journey-shaped myth doc with an embedded or
  linked network file)?
- For constellations: RA/Dec vs some other fixed-sky coordinate convention,
  and whether `build_network_globe.py`'s globe-shell renderer can even
  represent a sky position meaningfully, or whether constellations want a
  wholly different (flat star-chart) renderer.
- Scale: is this a "few prototypes for the idea" project or a "systematically
  do all 88 IAU constellations plus Bode's obsolete ones" project? Not
  decided — matches the same question that was open for networks before
  Qhapaq Ñan etc. turned out to already answer it by example.
