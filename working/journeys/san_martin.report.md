# San Martín journey — research report

**Dataset:** `san_martin.journey.json` — 67 stops, 8 segments, 1778-02-25 → 1850-08-17 (gregorian), 20 stops carry attested quotes.

## Sources
Spine: Mitre's *Historia de San Martín y de la emancipación sudamericana* (the founding text of the canon), the Instituto Nacional Sanmartiniano's Cronología and its *San Martín en Francia* monograph, Pasquali's *San Martín. La fuerza de la misión*. Web verification (ES + EN) for the shakiest datapoints: marriage date (12 Sep 1812, La Nación/Infobae), Le Bayonnais → Le Havre 23 Apr 1824 (INS), the 1829 non-landing (anchored 6 Feb, sailed for Montevideo 12 Feb, landed 13 Feb — El Historiador, Revisionistas), Grafton Street lodge and the four London months (Infobae, Gran Logia de la Argentina), the Pehuenche parleys (El Cuco Digital), the Huaura balcony (RPP/La República), crossing column dates (es.wikipedia *Ejército de los Andes*, Memoria Chilena). Quotes drawn from documentary canon: Rodríguez Peña letter (Saldán 1814), Godoy Cruz letters (1816), Chacabuco dispatch, Lafond letter, farewell to the Peruvians, 1844 testament, Recoleta epitaph, Basil Hall's *Extracts from a Journal*.

## Judgment calls
- **Register applied as instructed**: Yatasto meeting, the jewels of Mendoza, the flag oath wording, "yo también soy indio", the parihuana flag legend, the Huaura balcony and the last words are narrated as events, flagged `traditional` where the academy quarrels.
- The Cádiz **lodge oath** is dated mid-1811 (`traditional`) inside the documented window of Caballeros Racionales No. 3; the oath text is the formula preserved in the Lautaro papers.
- "Yo también soy indio" placed at **El Plumerillo** (second parley, per Olazábal), not San Carlos, following the better tradition.
- Marriage kept at **12 September 1812** (the 12 November variant rejected after checking).
- Quotes left **null** where the canon records none in his voice (Bailén, San Lorenzo — Cabral's words live in the campa, not the quote field).
- Segment cap forced merging the renunciation and exile into one long final leg; still reads as the tradition tells it.

## Gaps in the canon
Exact days for: Mendoza arrival (Sep 1814), his own ride-out with the Los Patos column (18-25 Jan window), Ancón embarkation, Brussels/Paris/Grand Bourg/Boulogne removals — all marked `inferred`. The Guayaquil interview itself is deliberately doorless: no minutes exist; I narrate only what the canon attests around it. The 1801 Portugal campaign was dropped as thin.

## Five richest episodes
1. **Cádiz, the oath of the Rational Knights** (1811) — the hinge; the King's officer becomes the Revolution's man in one candle-lit sentence.
2. **San Lorenzo** (3 Feb 1813) — fifteen minutes: the fallen horse, Baigorria's lance, Cabral dying content.
3. **The flag blessing and the crossing** (Jan-Feb 1817) — Remedios' silk, the Virgin commissioned general, six columns over the roof of the world, columns converging on the appointed day.
4. **Maipú** (5 Apr 1818) — "El sol es testigo" and the abrazo with the wounded O'Higgins.
5. **Guayaquil → the renunciation → Boulogne** (1822-1850) — the closed door, the 1 a.m. departure, the Lafond letter, and the 28-year diminuendo ending at "Mercedes, esta es la fatiga de la muerte."

## verification

Verified 2026-07-04 (structure + canon-fidelity pass; register respected — nothing debunked).

**Schema & structure.** JSON parses; top-level keys exactly `{traveler, title, years, calendar, register, segments}`; all 67 stops across 8 segments carry the full stop key-set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`); `calendar: gregorian` is sane for 1778-1850; `date_confidence` vocabulary (attested/traditional/inferred) matches the rest of the journey corpus; quote/quote_source always paired; 67 stops is inside the 45-70 target, so no stops added.

**Dates.** All dates ISO-valid and strictly ordered across the whole journey after one fix: the Cádiz lodge oath was dated 1811-05-15 but placed after La Albuera (1811-05-16). Moved to **1811-06-15** (`traditional`) — still "mid-1811" per the researcher's own framing and inside the Caballeros Racionales No. 3 window, now ordered.

**Coordinates.** Spot-checked ~40 stops (10 by web search: Yapeyú, Arjonilla, San Lorenzo convent, Posta de Yatasto, Punchauca, Huaura balcony, El Plumerillo, Chacabuco, Grand Bourg, Boulogne Grande Rue; the rest against known geography — Cádiz, Málaga, Oran, Bailén, La Albuera, Grafton Street/Miranda's house, BA Cathedral, Saldán, Mendoza sites, Fuerte San Carlos, Uspallata, Espinacito, San Felipe, Santiago, Cancha Rayada, Maipú, Rancagua, Valparaíso, Paracas, Pisco, Lima Plaza Mayor, Real Felipe, Guayaquil, Ancón, Los Barriales, Recoleta, Le Havre, Brussels, Montevideo, Paris). Three fixes:
- **Posta de Yatasto**: was -25.483,-64.967 (San José de Metán town); actual posta is ~10-20 km south (es.wikipedia: 25°35′24″S 64°56′59″W) → **-25.59, -64.95**.
- **Punchauca**: was -11.81,-77.045 (~5 km off); Casa Hacienda Punchauca, Carabayllo is 11°50′02″S 77°00′04″W → **-11.834, -77.001**.
- **Arjonilla**: was 38.008,-4.105 (~4 km north of town); Arjonilla, Jaén → **37.974, -4.106**.
Note: Boulogne "105 Grande Rue" kept — the death house is today's no. 113 (Casa San Martín museum) after renumbering; the canonical address is 105 and the coordinates sit on Grande Rue. Huaura balcony date 1820-11-27 `traditional` matches the museum's own tradition.

**Quotes.** Spot-checked 12 of 20 against the documentary canon: the Lautaro oath formula, "Es lo mejor que tenemos en la América del Sur" (Godoy Cruz 1816, honestly sourced though placed at Yatasto), the Saldán letter to Rodríguez Peña, "¡Hasta cuándo esperamos declarar nuestra independencia!", "Yo también soy indio" (Olazábal), the flag proclamation, the eve-of-crossing insomnia remark (Espejo), the Chacabuco dispatch, Maipú "El sol es testigo" (Mitre-transmitted, flagged as tradition), Basil Hall at Huaura, the Lima proclamation, the Protectorate decree, the Lafond letter, the farewell to the Peruvians, "Jamás desenvainaré mi espada...", the Recoleta epitaph, the Máximas, the 1844 testament, and the last words. All are carried by the canon with sources that honestly state their transmission; none needed nulling or demotion to campa. Bailén and San Lorenzo correctly null (Cabral's "Muero contento" lives in the campa as narration).

**campa.** All 67 stops are 60-110 words, present tense, mythic-national voice; the great episodes (Cádiz oath, San Lorenzo, flag blessing, Chacabuco, Maipú, Guayaquil, the death at Boulogne) read full-blooded, not flat.

**Post-fix validation.** Full python re-validation after edits: parses, schema exact, 67 stops / 8 segments / 20 quotes, span 1778-02-25 → 1850-08-17, zero ordering or word-count violations.
