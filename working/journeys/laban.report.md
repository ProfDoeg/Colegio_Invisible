# Laban journey — research report

**Dataset:** `laban.journey.json` — 7 segments, 62 stops, 1879–1958, gregorian. Register: national mythology (the canon of *A Life for Dance*, the Laban Collection, and the hagiographic biographies is treated as true; visions and callings are dated events).

## Sources
Primary canon: *A Life for Dance* (1935, trans. Ullmann 1975), *Choreutics* (1966), *Die Welt des Tänzers* (1920), *Effort* (1947), *The Mastery of Movement on the Stage* (1950). Biographies: Preston-Dunlop *An Extraordinary Life* (1998), Doerr *Dancer of the Crystal* (2008), Hodgson *Mastering Movement* (2001), Kant/Karina *Hitler's Dancers* (2003), Green *Mountain of Truth* (1986). Web: en/de Wikipedia, Cabinet magazine 36 (Turner, "The Art of Movement" — source of the 1920 letter and the mobility quote), siegfried-wagner.org (Bayreuth 1930 + Mannheim 1921 Bacchanal), de.wikipedia *Sang an die Sonne* (the 1917 sun festival at Gräser's grotto), Archives Hub Laban Collection and Leeds special collections (Tauwind), dartington.org, Trinity Laban, Lisa Ullmann pages, Surrey archives blog.

## Judgment calls
- **Tauwind dress rehearsal** dated 1936-06-20 (widely given; Goebbels' diary reaction follows it) — marked *attested*; the ban is a separate stop.
- **Dervish episode** placed at the Hadži Sinan tekke, Sarajevo, ~1894 — the canon names dervishes in Bosnia but not the tekke or year; marked *traditional*.
- **Bayreuth** anchored to the attested Festival opening of *Tannhäuser*, 22 July 1930 (Toscanini).
- Uncertain days use first-of-month dates with confidence downgraded (*traditional*/*inferred*) — e.g. Magdeburg 1927 and Essen 1928 congresses (month-level), Mannheim Bacchanal 1921, Schloss Banz winter.
- **Quotes:** only 4, all with recorded provenance (1920 letter; *A Life for Dance* mobility line; *Choreutics* living-architecture; *Mastery* opening axiom). Everything else is null — the Goebbels diary line is paraphrased in campa, not put in the quote field, since the field is for the traveler's own words.
- The Nazi years are told as tragedy-within-the-myth (the magus's error), not sanitized; Kant/Karina backs the harness/fall framing.
- 1940–42 (London transit, Newtown Wales) is the thinnest documentary stretch; kept to two stops at low confidence.
- Monte Verità honored as the corpus waypoint: five stops on the hill across 1913–1917.

## Gaps
Exact Paris addresses (1900s and 1937); the Zurich school street; the Choreographisches Institut's Berlin address; precise Mannheim premiere date; whether the Dover landfall or a Newhaven crossing is correct (no port attested — marked inferred).

## Five richest episodes
1. **The dervishes at Sarajevo (~1894)** — the seed, told by Laban himself as the origin of everything.
2. **Monte Verità 1913–14** — Wigman's arrival, the sun-worship meadow, the Meisenbach photographs, war breaking over the second summer (with the Sarajevo assassination closing the childhood circle).
3. **Sang an die Sonne, August 1917** — the night-long sun festival at Gräser's grotto during the OTO congress: movement choir as liturgy in wartime.
4. **Essen 1928** — kinetography unveiled; movement gets its alphabet (*Schrifttanz*).
5. **The Tauwind, 20 June 1936** — a thousand dancers, twenty thousand watching, Goebbels in the dark; the fall, Schloss Banz, the flight via Paris to Jooss's door at Dartington.

## Verification (2026-07-05)

Independent pass on structure and canon-fidelity. Repairs made in place; file re-validates.

**Structure.** JSON parses; 62 stops / 7 segments; every stop carries the full 10-key schema matching the sibling journeys; dates strictly ordered within segments and across segment boundaries; all dates full `YYYY-MM-DD`; quote/quote_source always null together; sources non-empty throughout. Campa range 66–93 words, all present tense; the great episodes (Sang an die Sonne, the Tauwind rehearsal, the Weybridge close) read at full register. Stop count within the 45–65 target — nothing added.

**Coordinates.** Twelve stops web-spot-checked (Nominatim/Wikidata/Wikipedia). Exact or within ~150m as-shipped: Cabaret Voltaire Spiegelgasse 1, Waldbühne (Dietrich-Eckart-Bühne), Bayreuth Festspielhaus, Theresian Military Academy, Stari Most Mostar, Woburn Hill Addlestone, Newtown Powys. **Fixed in place:**
- **Schloss Banz** — was ~3.5 km southwest of the monastery; now 50.1330, 11.0009.
- **Dartington Hall** (3 stops) — was ~700 m off in the village; now clustered on the Hall at 50.4515, −3.6942.
- **Monte Verità** (5 stops) — cluster sat ~330 m west of the hilltop (lng ~8.7616); moved onto the hill around the canonical 46.1608, 8.7658. The separate Ascona-town stop (war of 1914) moved down to the town, 46.1547, 8.7695.
- **Hadži Sinan tekke, Sarajevo** — nudged ~380 m to the building at 43.8647, 18.4292.

**Quotes.** All four checked against the canon; all four verbatim with correct provenance: the 1920 letter ("...proper value as Art and the Artist... warped psyche of our time" — Cabinet 36, Turner); *A Life for Dance* mobility line; *Choreutics* "living architecture — ... changing emplacements as well as changing cohesion"; *Mastery of Movement* opening axiom "Man moves in order to satisfy a need." No nulling required. Only four quotes exist, so all were checked (target was six).

**Dates and confidence.** Attested anchors confirmed: birth 15 Dec 1879 Pozsony; Tannhäuser at Bayreuth 22 Jul 1930; Tauwind dress rehearsal 20 Jun 1936 at the Dietrich-Eckart-Bühne (Goebbels' diary reaction dated the 21st — the rehearsal itself the 20th, as shipped); death Weybridge 1 Jul 1958. **One downgrade:** the flight to Paris (1937-08-15) — August 1937 is attested only at month level, the day is conventional, so confidence lowered from *attested* to *traditional*. Attested count now 5.

**Verdict.** Sound. Coordinate cluster fixes and one confidence downgrade applied; no quote, campa, or ordering repairs needed.
