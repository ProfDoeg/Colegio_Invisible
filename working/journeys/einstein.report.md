# Einstein journey — report

**File:** einstein.journey.json — 9 segments, 44 stops, 32 quoted, span 1879-1955 (gregorian).

## Sources
Primary spine: Einstein's own *Autobiographical Notes* (1949) for the childhood material (compass, geometry booklet, loss of faith); *The Collected Papers of Albert Einstein* (Princeton) for letters and the 1905/1915 physics; the four 1905 *Annalen der Physik* papers directly for the miracle-year quotes. Biographical backbone: Walter Isaacson, *Einstein: His Life and Universe* (2007) and Albrecht Fölsing's *Albert Einstein: A Biography* (1997), cross-checked against Abraham Pais's *'Subtle is the Lord...'* for the physics chronology. Specific episodes verified this session by web search against: the Einstein–Szilard letter text (dannen.com / Atomic Heritage Foundation), the Royal Society's 1919 eclipse announcement (Royal Society *Notes and Records*, 2020), the Nobel Prize archive on the 1921/1922 award and Einstein's absence from Stockholm, the Royal Albert Hall's own archive of the 3 October 1933 speech, the Jewish Telegraph Agency / *Forward* record of the 1923 Jerusalem visit, the Jewish Virtual Library's text of the 1952 Israeli-presidency correspondence, and Jim Holt's *When Einstein Walked with Gödel* for the Gödel walking-companion quote.

## Judgment calls
- **Register.** Einstein is not a figure of miracle or revelation in the hagiographic sense, but the direction's principle still applies: this is the physics establishment's own founding myth, and it is narrated as true — the compass "hides something behind things," the eclipse "confirms" rather than "appears to confirm," Gödel's rotating universes are presented as a real gift, not a curiosity. No hedging language ("allegedly," "as legend has it") was used except where the canon itself flags something as uncertain (Lieserl's fate).
- **Physical-location convention.** Followed the sibling-file precedent of anchoring each stop to Einstein's own body — even world-historical news (the 1919 eclipse) is staged where *he* received it (Berlin), not where the astronomers stood (Príncipe/London), keeping the itinerary a true itinerary rather than a scrapbook of "things that happened during his life."
- **Lieserl.** The illegitimate daughter's fate (adoption? death by scarlet fever?) is genuinely unresolved in the historical record — rendered as an honest mystery, not resolved either way, matching the "healing model" rule against inventing false certainty.
- **The bomb.** Kept factually precise: Einstein wrote the letter but was refused Manhattan Project clearance for his prior pacifism and never worked on the weapon himself — a distinction easy to blur and worth holding exactly, especially next to the Oppenheimer stop.
- **Nine segments / 44 stops** sits at the top of the requested range; a life this well-documented, spanning four countries and two world wars, resisted compression below that without losing named sites the curator asked for by name (Ulm, Bern, Prague, the 1919 eclipse, the 1933 flight, Princeton, Oppenheimer, the Roosevelt letter).

## Gaps / time-folds
- Several Bern stops (marriage, Olympia Academy, all four 1905 papers) share the same coordinates (his rented rooms/patent office) since the entire annus mirabilis happened at one desk in one small city — this compresses geography, not time; the dates are exact and chronological.
- The Caputh stop folds two dated events (the July 1932 Freud letter and the December 1932 farewell to the house) into a single stop rather than two, to keep segment 7 from ballooning — flagged in the campa text itself ("that December...").
- The Prague stop's famous "insane asylum view from his office window" anecdote (recorded by biographer Philipp Frank) could not be confirmed with an exact quoted sentence this session, so it was left out rather than risk a fabricated quote; the stop instead uses Einstein's own attested Prague-era physics (the first, still-incomplete 1911 light-bending prediction).

## Five richest episodes
1. **The compass (Munich, 1884)** — the founding relic of the whole myth, in Einstein's own words: "something deeply hidden had to be behind things."
2. **The annus mirabilis (Bern, 1905)** — four papers from a patent clerk's desk in seven months: light-quanta, the atom proved, special relativity, E=mc².
3. **The November 1915 field equations (Berlin)** — racing Hilbert, correcting Mercury's orbit to the decimal, "beside myself with joyous excitement."
4. **The 1919 eclipse (Berlin, receiving the London news)** — overnight fame, and the "sorry for the dear Lord" line that shows the myth's actual register: confidence prior to confirmation.
5. **The 1939 Roosevelt letter (Peconic) paired against Oppenheimer at the Institute (Princeton, 1947)** — the letter that starts the bomb and the man who builds it, sharing one small campus for the rest of Einstein's life without ever quite closing the distance between them.

## Connections to the atlas
Direct edges as specified: **robert_oppenheimer** (Institute for Advanced Study directorship, 1947 stop), **bohr** and the quantum-reality debates (Solvay 1927, EPR 1935), and the essay corpus generally (pacifism, Zionism, the unified-field quest as a life-long, ultimately unresolved argument — the same register of "faithful failure" that recurs across the atlas's scientist- and mystic-adjacent figures). The Jerusalem/Hebrew University stops sit naturally beside any future Zionist-movement journey (Weizmann, Ben-Gurion) already implied by the 1952 presidency-refusal stop. The flight from Nazi Germany (1933) is the same historical hinge crossed by any other 1930s émigré figure the atlas may later add.

---

## Verification pass — 2026-07-24

Independent structural and canon-fidelity review by verifier subagent.

**Lint.** `json_check.py` passes clean (exit 0, 0 WARN) both before and after repair: traveler=Albert Einstein, segments=9, stops=44, quoted=32. Well above the 30-45 stop target; no additions needed.

**Chronology.** Dates monotonic within every segment and across segment seams (…1932-07-30 Caputh → 1933-03-28 Le Coq → … → 1935-05-15 EPR → … → 1955-04-18 death). Gregorian throughout; a living-person clamp is not applicable (dies 1955). Date_confidence values honest and defensible (childhood compass/geometry stops marked `traditional`, family departure `inferred`, all documented events `attested`).

**Coordinates — spot-checked, two fixed in place:**
- **Le Coq-sur-Mer / De Haan** — was lng `2.9557` (≈5.4 km out to sea, west of the town). Corrected to `3.033` per De Haan, Belgium (51.267 N, 3.033 E). Lat `51.2711` kept.
- **Caputh (Einstein summer house)** — was `52.3733, 13.009` (≈2.6 km north of the village). Corrected to `52.35, 13.0141` per Einsteinhaus Caputh (52°21′00″N, 13°00′51″E).
- Verified accurate (within atlas city-scale tolerance): Ulm 48.398/9.992; ETH Zürich 47.3763/8.548; Aarau 47.390/8.044; Novi Sad 45.267/19.833; Bern 46.948/7.445; Prague 50.073/14.421; Brussels 50.850/4.352; Berlin Unter den Linden 52.517/13.390; Caltech Pasadena 34.1377/-118.1253; Royal Albert Hall 51.5009/-0.1774; Princeton IAS/campus ~40.349/-74.659. Nassau Point/Peconic (41.020/-72.433) and Mount Scopus (31.779/35.240) sit a couple km off their strict sites but within the atlas's town-scale convention; left as-is rather than guess without a source (web-search budget was exhausted this session).

**Quotes.** Spot-checked 8 against canon — all carried faithfully and correctly sourced: the compass "Something deeply hidden had to be behind things" (Autobiographical Notes); "holy curiosity of inquiry"; the 1905 light-quanta and E=mc² lines (Annalen der Physik); "He does not play dice" (Born letter, 1926); "sorry for the dear Lord" (Rosenthal-Schneider); the Gödel-walk recollection (Morgenstern/Holt); the 1952 Israel-presidency refusal; "Remember your humanity" (Russell–Einstein Manifesto). The "fanatic freethinking" quote lightly compresses the original ("positively fanatic [orgy of] freethinking") but stays true to wording and meaning — acceptable. No quote/quote_source mismatches; the 12 null-quote stops are honest (no reliable exact wording carried).

**Campa.** All 44 within the 60-110 word band (lint-enforced), present tense, mythic-national register sustained; the great episodes (compass, annus mirabilis, 1919 eclipse, Bohr debates, Roosevelt letter, Gödel walks, the "elegant" death) carry weight rather than flatten.

**Canon fidelity.** Nothing debunked. The Lieserl mystery is left genuinely unresolved (matching the record); the Prague light-bending stop honestly carries the attested 1911 work with a null quote rather than an unverified anecdote; the Caputh date-fold (July Freud letter + December farewell) is a legitimate single-stop compression, not a silent error. Structure sound. Repairs limited to the two coordinate corrections above.
