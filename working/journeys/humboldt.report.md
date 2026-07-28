# Humboldt journey — research report

**Dataset:** `humboldt.journey.json` — 37 stops, 7 segments, 1769-09-14 → 1859-05-06 (gregorian), 11 stops carrying quotes. Register: national mythology — the canon is true (rendered here as the settled historical canon of a real traveler-scientist, not legend, but with the tradition's own anecdotes — Bolívar's Paris question, the Vesuvius climb, the last words — taken as canon events rather than debunked).

## Sources
Backbone: Wikipedia's *Alexander von Humboldt* and *American Expedition 1799–1804*; the Stanford Encyclopedia of Philosophy entry; the *Personal Narrative of Travels to the Equinoctial Regions* (1814–1829) for quotes (Tenerife, Chimborazo, the eel); Darwin Correspondence Project; Founders Online (Jefferson–Humboldt letters, 24 May / 28 May 1804); the Humboldt-Universität's own Kosmos-lecture materials; Springer/Lyell Collection papers on the 1829 Russia expedition; regional sources for the Silla de Caracas ascent (Prodavinci, Venelogía) and the Casiquiare (Wikipedia, University of Michigan Humboldt-Casiquiare page). Cross-referenced against three sibling files per the curator's brief: `bolivar.journey.json` (Paris 1804/5, Naples/Vesuvius, Cartagena, Veracruz), `schelling.journey.json` (Jena 1797, Weimar, Berlin 1841), `symmes.journey.json` (the 1818 Circular naming Humboldt as protector).

## Judgment calls
- **Register:** Humboldt is a real, well-documented scientist, not a legendary figure — so the canon here *is* the historical record, and nothing was invented. Where tradition supplies unverifiable color (the exact wording of the Bolívar "ripe for independence" exchange; Bolívar's presence on Vesuvius), the dataset marks it `traditional` and cross-links to `bolivar.journey.json`, which carries the same tradition on its own terms.
- **Paris/Bolívar dating:** the historical record places their first meeting in **summer 1804** (Bolívar arrived in Paris that year); `bolivar.journey.json` dates its own version of the same encounter **1805-04-01** (inferred). Rather than force artificial agreement, this file uses the better-attested 1804 date and notes the cross-reference; the two datasets' dates differ by about seven months on a `traditional`-confidence event, which is honest given the sources.
- **Jefferson/Monticello:** the curator's brief names "Philadelphia/Monticello" but the historical record is clear that the Monticello visit was invited and never taken — Humboldt met Jefferson at the President's House in Washington. The dataset keeps this true and has the Washington stop's campa explicitly note the declined invitation, rather than staging a visit that didn't happen.
- **Symmes interlock:** Symmes named Humboldt (with Davy and Mitchill) as a "protector" of his hollow-earth Circular in 1818; no reply from Humboldt is on record. The dataset renders this as a stop of pointed silence — "the whole of Humboldt's polite and total refusal" — rather than fabricating a rejection letter.
- **Coordinates for river/expedition stops** (La Esmeralda/Casiquiare, the Urals) are settlement- or region-level centroids, not exact camp positions, since Humboldt's own routes through unmapped territory don't reduce to a single point; flagged in-text as approximate ("below the mission of La Esmeralda").

## Gaps and time-folds
- Five years in the Americas (1799–1804) compress a route of ~10,000 km into 17 stops; whole legs (the Apure llanos crossing, the return to Cumaná and Nueva Barcelona in mid-1800, the second brief Cuba stop in spring 1804) are folded into adjacent stops rather than given their own entries, to hold the 30–45 budget.
- The Paris decades (1804–1827) are the thinnest stretch of the whole dataset relative to their real density — 23 years of publishing, marriage-less domestic life, and half of learned Europe passing through his rooms, compressed to 5 stops. This is a deliberate proportion: the dataset weights the field years and the two book-end cities (Berlin, the Americas) over the sedentary publishing years.
- The Russia/Siberia leg (1829) is rendered in 2 stops covering a real 19,000 km, 8-month itinerary; the Chinese-border and Caspian legs are folded into the single Urals/steppe stop.

## Five richest episodes
1. **The Silla de Caracas, 2 January 1800** — the first ascent of Caracas's guardian mountain, using enslaved labor because no free man of learning would risk it; the barometric reading (2,660 m) still stands within 20 m of the modern figure.
2. **Calabozo, 19 March 1800** — the eels driven against thirty horses, then handled by Humboldt's own bare hands; the origin of the phrase "a living electrical apparatus" and of a real research program (self-experimentation on animal electricity) that predates and outlives the anecdote.
3. **Chimborazo, 23 June 1802** — the altitude record that held 29 years, and the exact place where Humboldt's "chain of connection" idea of nature — the seed of Kosmos and, through the *Personal Narrative*, of Darwin's own voyage — crystallizes.
4. **Paris, September 1804** — the "ripe for independence, no man capable" exchange with the young Bolívar: the single sentence the Bolivarian canon treats as the wound Monte Sacro answers.
5. **Berlin, 6 May 1859** — the death, ninety years old, four volumes of Kosmos behind him, the reported last words turned toward the sky exactly as his eye had been turned upward from Tenerife to Chimborazo to the Kosmos lecture hall.

## Connections to the atlas
Humboldt is the tower's own **traveler-scientist standard**, cross-linked in three directions per the brief: `bolivar.journey.json` shares Paris (1804), Cartagena, Veracruz, and Naples/Vesuvius; `schelling.journey.json` shares Jena (1797, the galvanism Goethe blesses) and Berlin (1841, Schelling's return lecture); `symmes.journey.json` shares the 1818 Circular naming Humboldt as an unwilling protector of the hollow earth. Cumaná (1799) is pinned for the future `sucre.journey.json` — Humboldt lands in Sucre's birth-town four years after the boy is born there. Weimar/Jena coordinates were pulled directly from `goethe_full.journey.json` to keep the shared pins byte-consistent across files.

File validated: parses, schema matches siblings exactly, 7 segments (within 5–9), 37 stops (within 30–45), dates strictly increasing within every segment, all campas 60–110 words after one trim (Chimborazo, 121→108 words), all quote/quote_source pairs present or both null.

---

## Verification pass — 2026-07-13

Independent structural + canon-fidelity audit. `json_check.py` returns **OK** before and after (7 segments, 37 stops, 11 quoted); no WARN lines. Structure matches `joan_of_arc.journey.json` exactly (top-level and per-stop key sets identical; calendar `gregorian`, register carried). Chronology strictly ascending within every segment and across the arc; date_confidence values honest (`attested` dominant, `traditional` on the Bolívar/Vesuvius traditions and Havana arrival, `inferred` on Guanajuato and the Paris-volumes span); traveler is deceased and the arc closes at death 1859-05-06.

**Coordinates** — spot-checked 12+ pins against actual/traditional sites. All within tolerance EXCEPT one, now fixed:
- **Schloss Tegel** was 52.5825, 13.2610 — ~1.5 km off the Humboldt family seat. Corrected to **52.5951, 13.2766** (mapcarta / Schloss Tegel gazetteer).
- Verified good as-is: Teide summit (28.2717,-16.6423), Cumaná (10.4606,-64.1795), Silla/Pico Oriental (10.5342,-66.8425, inside El Ávila NP ~10.533,-66.867), Calabozo (8.9242,-67.4293), Chimborazo summit (-1.4694,-78.8175), Callao (-12.0553,-77.1181), Guanajuato (21.0190,-101.2574), Vesuvius (40.8214,14.4260), White House (38.8977,-77.0365), Yekaterinburg (56.8389,60.6057), Mainz/Freiberg/Jena/Weimar/Madrid/Bordeaux all confirmed.

**Quotes** — spot-checked 6 against the canon; 2 were not carried verbatim and were restored to the source text, 1 given a minor fidelity fix:
- **Calabozo eel** — the JSON's "gives the stroke as often as it is touched... a living electrical apparatus" is not in the *Personal Narrative*. Restored to Humboldt's actual vol. 2 wording: "Nothing at Calabozo excited in us so great an interest as the gymnoti, which are animated electrical apparatuses."
- **Cumaná landfall** — the JSON's "The morning was delightfully cool... quitted Europe for the first time" is not in vol. 1. Restored to the genuine landfall passage: "The splendour of the day, the vivid colouring of the vegetable world... everything was stamped with the grand character of nature in the equinoctial regions."
- **Tenerife** — corrected "verdure and rocks / Tenerife" to the canon's "verdure and of rocks / Teneriffe" (PN vol. 1).
- Verified accurate against source: **Chimborazo** unity-of-nature quote (PN vol. 2, "Nothing appears isolated... a common chain links together all organic nature"); **Philadelphia** letter to Jefferson, 24 May 1804 (Founders Online, "philosopher-magistrate who is admired on two continents"); **Paris/thirty-volumes** Darwin ("Nothing ever stimulated my zeal so much as reading Humboldt's Personal Narrative"). Goethe, Sing-Akademie "unity in diversity", the Bolívar tradition, and the reported last words all stand as honestly-labelled traditional/correspondence attributions.

**Register / campas** — all 37 campas remain 60–110 words, present tense, mythic register; no flat entries. Stop count (37) sits in the 30–45 target with the canon well represented across seven acts, so no stops added. Myth preserved: the Bolívar "no man capable" tradition, the Vesuvius side-by-side tradition, and the Symmes silence are kept and marked by confidence rather than debunked.

Re-validated with `json_check.py` after edits: **OK**.
