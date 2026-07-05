# Columbus journey — research report

**Dataset:** `columbus.journey.json` — 70 stops, 9 segments, 1451–1899, calendar `julian` (note: the three post-1582 after-death stops — Havana 1796, Seville 1899 — carry civil/Gregorian dates as the tradition records them).

## Sources
Primary canon: the **Diario** of the first voyage (Las Casas abstract) — prologue, doctored-log entry (9 Sep), Sargasso (16 Sep), mutiny (10 Oct), the light (11 Oct), landing (12 Oct), Cuba (28 Oct), the wreck (26 Dec), the barrel (14 Feb); the **Barcelona letter** to Santángel (15 Feb 1493); the **Letter on the Third Voyage** (pear-shaped earth, Earthly Paradise, La Mina witness); the **Lettera Rarissima** (7 Jul 1503 — the celestial voice at Belén, "weep for me", the hurricane grievance); letter to **Juana de la Torre** (1500, "an Other World"); the **Mayorazgo** of 1498 ("in Genoa I was born"); **Ferdinand Columbus, Historie** (Cape St Vincent swim, Thule, the eclipse, the deathbed); **Las Casas, Historia de las Indias**; Chanca letter (2nd voyage); Morison, *Admiral of the Ocean Sea*; Wikipedia/EBSCO for relic-transfer dates (Cartuja delivery 11 Apr 1509; 1544 fleet arriving Santo Domingo 9 Sep; exhumation 20 Dec 1795, Havana deposit Jan 1796; Seville reception 19 Jan 1899 — web-verified).

## Judgment calls
- **The expulsion weave** is carried per the commissioned register: the Diario prologue's own juxtaposition of the expulsion and the commission is quoted verbatim at the Palos sailing; the 30 April titles stop pairs the two Granada decrees. Stated as the canon's reading, not as biography.
- **Legends kept as events** (register requires it): the unknown pilot of Porto Santo (Oviedo/Las Casas), the oar-swim at Lagos (Ferdinand), Puente de Pinos courier, the Alhambra audience date 17 Dec 1500 (Morison's date; marked `traditional`).
- **Quotes** only where the canon records words; several Diario quotes are Las Casas's third-person abstract, flagged as such in `quote_source`. Mid-ocean stops (double log, Sargasso, false landfall, mutiny eve, the light) use reconstructed track coordinates, marked by `inferred`/`attested` date confidence rather than positional claims.
- Fernandina/Isabela compressed into one "naming chain" stop; Pinzón's desertion folded into Río de Mares; Funchal into Porto Santo — to stay ≤70.

## Gaps in the canon
Birth date (Aug–Oct 1451, `traditional`); everything 1451–1476 is thin; the 1485 La Rábida arrival and first Córdoba audience dates are tradition, not document; exact reception date at Barcelona (mid–late April 1493) unrecorded; the Belén vision's precise day; whether the chains actually went into the 1544 grave (tradition via Ferdinand's report of the wish).

## Five richest episodes
1. **The light of 11 October** — the Admiral claiming America's first light (and the annuity) four hours before Triana's cry.
2. **Christmas night 1492** — the flagship wrecked and resurrected as La Navidad, the first town built of shipwreck.
3. **The Earthly Paradise at Paria** — fresh-water sea, pear-shaped earth, Eden declared to the sovereigns with bleeding eyes.
4. **The chains** — kept in his chamber, ordered into his grave: self-made relics of injustice.
5. **The eclipse at Jamaica, 29 Feb 1504** — Regiomontanus's tables turned into a public miracle; the canon's own conjuring, and the after-death coda (7 ocean crossings, 5 graves) as its mirror.

## Verification pass (2026-07-05)

Independent structural and canon-fidelity check; all repairs made in place and re-validated with python.

**Structure.** JSON parses; 9 segments, 70 stops (within the 50–70 target — no additions needed); every stop carries the full key set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`).

**Chronology.** One inversion found and fixed: the Córdoba (Beatriz/Fernando, 1488-08-15) and camp-before-Málaga (1487-08-18) stops were transposed; blocks swapped so Málaga now precedes Córdoba. Full sequence 1451-08-25 → 1899-01-19 is now strictly non-decreasing.

**Coordinates.** Eleven sites web-spot-checked: Casa di Colombo Genoa, Elmina Castle, Bariay, La Isabela (El Castillo), Pinos Puente, St Ann's Bay, Cabo Gracias a Dios, Havana Cathedral, La Rábida, Anjos hermitage, Río Belén. Three fixes applied:
- **La Rábida** (both stops): −6.8926/−6.8925 → **37.2078, −6.9259** (friary was placed ~3 km east, wrong side of the Tinto).
- **Anjos, Santa Maria (Azores)**: → **37.0059, −25.1537** (snapped to the hermitage of Nossa Senhora dos Anjos itself, where the pilgrims were seized).
- **Río Belén, Veragua**: 8.914, −81.148 → **8.8833, −80.8667** (GEOnet mouth of the Belén; the old point sat ~31 km west of the river).
All other checked sites were within ~1 km of the true locations; open-ocean track points accepted as reconstructions per the report's own flag.

**Quotes.** 22 quotes, all from the declared canon (Diario/Las Casas abstract flagged, Barcelona letter, Third Voyage letter, Juana de la Torre, Lettera Rarissima, Mayorazgo, Historie last words). Six spot-checked against the sources — prologue expulsion sentence, the candle-light of 11 Oct, Cuba "most beautiful land", the pear-shaped earth, "I came to serve at twenty-eight… not a hair that is not white" (Lettera Rarissima, web-confirmed), "an Other World… Spain, which was reckoned poor" (Juana de la Torre, web-confirmed; standard translations vary "Other/second World"). No quote nulled; none found outside the canon.

**Campa voice.** All 70 in present tense; none flat at the great episodes (the light, the wreck, Paria, the eclipse, the relic crossings carry their weight). Twenty stops ran over the 110-word ceiling (up to 134); each trimmed to ≤110 by cutting connective tissue only — no episode, legend, or canonical detail dropped. Post-repair range: 81–110 words.

**Result.** File re-validated clean: parses, schema complete, chronological, coordinates corrected, quotes canonical, campas in range. 70 stops stand.
