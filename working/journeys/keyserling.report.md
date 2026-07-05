# Keyserling journey — research report

**Dataset:** 55 stops, 7 segments, 1880–1946 (gregorian). Register: national mythology — the canon (Reisetagebuch, Südamerikanische Meditationen, Reise durch die Zeit, the Ocampo memoirs) treated as true.

## Sources
- German/English Wikipedia and Kulturstiftung/LAGIS Hessische Biografie for the biographical spine (Könno 20.7.1880; Geneva 1897–99; Dorpat duel 1899; Vienna doctorate 1902; Paris 1903–06; Berlin 1906–08; Rayküll 1908; estates expropriated 1918–19; marriage Friedrichsruh 11.3.1919; Innsbruck 26.4.1946).
- The Travel Diary of a Philosopher vols. 1–2 (archive.org full text) — the complete world-tour itinerary was taken from the actual tables of contents (Suez→Ceylon→India→Burma→China→Japan→Hawaii→America→Rayküll); the Colombo quote ("It is not I who think, but something thinks in me") verified against the English text.
- schuledesrades.org digital edition of the Südamerikanische Meditationen (chapter structure: Kontinent des dritten Schöpfungstages, Gana, Delicadeza); scielo/UNAM and U. Chile papers on the gana concept.
- Stephenson, *The Correspondence of Victoria Ocampo, Count Keyserling and C. G. Jung* (Versailles, Hôtel des Réservoirs, early January 1929); Ocampo, *El viajero y una de sus sombras*.
- Universität Innsbruck newsroom article on the Innsbruck refounding (Aurach 1943, Mühlau house 1946, 100 hotel rooms, radio lectures).

## Judgment calls
- The Travel Diary is famously undated; all world-tour stop dates are month-scale interpolations across the attested Oct 1911–Oct 1912 span, marked `inferred`. The "Himalayas" chapter is placed above Darjeeling (route Benares→Buddh-Gaya→Himalayas→Calcutta makes this near-certain but the diary never names the hill station).
- Ku Hung-ming is placed at Tsingtao per the prompt's tradition and the diary's Tsing-Tau chapter (the loyalist exiles' refuge in 1912); no verified verbatim quote found, so quote=null.
- Buenos Aires arrival is given as June 1929 (Gale/Mallea scholarship); some sources imply later. Marked `traditional`. The Chile→Bolivia routing (trans-Andean rail, then altiplano) is the standard route, marked `inferred`. La Paz doctorate: year attested, day invented→`traditional`.
- The death-before-the-permission irony is kept (per the commissioning tradition) but the uibk article does not confirm the day-after detail — narrated as tradition, date confidence honest.
- Egypt: the diary has no Egypt chapter (Port Said/Suez/Red Sea only), so Egypt appears as the canal passage, not a Cairo stop.
- Quotes kept to 4 verifiable items (motto, Colombo, "Kontinent des dritten Schöpfungstages" as chapter title, the tengo gana formula); everything else null rather than invented — including all Ocampo-affair dialogue.

## Gaps in the canon
Exact Kõnnu manor pinpoint (village-level coords used); London/Italy years thinly documented (memoir-level only, flagged inferred); the 1927 Jung congress day; precise South American lecture calendar; wedding details beyond date/place.

## Five richest episodes
1. **Benares at dawn** — the diary's ecstatic center; holiness as breathable medium.
2. **Tsingtao 1912** — the sage Ku Hung-ming among the mandarin exiles weeks after the empire fell.
3. **Versailles/San Isidro 1929** — the Ocampo delirio, with both testimonies canonized as simultaneously true.
4. **The pampa/altiplano** — la gana and the third day of creation; the corpus's own borrowed word given its richest campa.
5. **Innsbruck 1946** — the last founding, 100 hotel rooms reserved, death the day before permission: the tradition's perfect irony.

## Verification (2026-07-05)

Independent structural and canon-fidelity pass over `keyserling.journey.json`.

**Structure.** JSON parses; 55 stops in 7 segments (within the 35-55 target — no additions needed); every stop carries the full key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources); all dates are `YYYY-MM-DD`, all confidence values in {attested, inferred, traditional}.

**Chronology.** One ordering violation found and repaired: Berlin (1907-01-15) was listed after Rome (1907-02-01) in the Wanderjahre segment. The two stops were swapped (Berlin now precedes Rome); the narrative flow of both campa texts survives the swap. Full sequence now strictly non-decreasing 1880-07-20 → 1946-04-30.

**Coordinates.** Twelve stops web-spot-checked against the actual sites (Wikipedia coordinates): Raikküla, Kandy Temple of the Tooth, Sri Maha Bodhi Anuradhapura, Ramanathaswamy Rameswaram, Shwedagon, Temple of Heaven, Taj Mahal, Friedrichsruh, Kõnnu manor, Villa Ocampo, Aurach bei Kitzbühel, Mühlau (Innsbruck). Seven matched within tolerance. Five repaired in place:
- Könno (Kõnnu) manor birth stop: 58.639/24.454 → **58.717/24.825** (was ~23 km off; et.wikipedia gives 58.7172/24.825 for Kõnnu mõis, Pärnu-Jaagupi)
- Villa Ocampo, San Isidro: -34.471/-58.514 → **-34.458/-58.518** (villa itself, per en.wikipedia)
- Aurach bei Kitzbühel: 47.399/12.428 → **47.417/12.433** (village center)
- Innsbruck-Mühlau founding: 47.281/11.402 → **47.284/11.413** (Mühlau district)
- Mühlau cemetery: 47.284/11.402 → **47.286/11.408** (Mühlauer Friedhof, Trakl's ground)

**Quotes.** All four checked against the canon; all four stand:
- Motto "Der kürzeste Weg zu sich selbst führt um die Welt herum" — verbatim (wiki.yoga-vidya.de carries the exact wording).
- Colombo "Everything that happens in me, develops in me as the plants develop out there. It is not I who think, but something thinks in me." — verbatim against the English Travel Diary full text on archive.org (the canon sentence continues "...it is not I who wish, but something wishes in me"; the excerpt is a clean truncation, no words altered).
- "Der Kontinent des dritten Schöpfungstages" — confirmed as the title of meditation I of the Südamerikanische Meditationen (schuledesrades.org digital edition).
- "tengo gana … no tengo gana" — meditation VII is indeed titled "Gana" and carries the Spanish formula; source attribution correct.

**Campa voice.** All 55 texts fall in 60-110 words (script-verified), present tense throughout; the great episodes (Benares, Tsingtao/Ku Hung-ming, Versailles/San Isidro delirio, the pampa gana, Innsbruck death-before-permission) are rendered at full pressure, not flat.

**Verdict.** Dataset valid after repairs; myth intact, register preserved.
