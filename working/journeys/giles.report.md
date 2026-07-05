# Saint Giles journey — research report

**Dataset:** `giles.journey.json` — 30 stops in 7 segments, Athens c. 650 to Vierzehnheiligen 1446, calendar julian, register "national mythology — the canon is true."

## Sources
Primary canon: the tenth-century *Vita sancti Aegidii* (as summarized in the standard hagiographic literature) and the *Legenda Aurea* ch. 130 in Caxton's 1483 English (christianiconography.info and catholicsaints.info full texts — all eight quotes in the dataset are verbatim Caxton). Supporting: Wikipedia (Saint Giles, Abbey of Saint-Gilles, Veredemus, St Giles' Cathedral, Cripplegate, St Giles' Oxford, Fourteen Holy Helpers), the National Gallery pages for the Master of Saint Giles panels, encyclopedia.com and the Compostela/Via Tolosana pilgrimage literature, and the Nemausensis/Germer-Durand dossier on Saint Vérédème for the Gardon cave (La Baume Saint-Vérédème, Sanilhac-Sagriès).

## The vita's time-folds — kept whole
1. **Caesarius of Arles** (d. 542) receives Giles c. 673 — marked *traditional*, narrated as the vita has it ("the legend folds time in its hand… and it is true").
2. **Charles = Charlemagne**: the Mass of Saint Giles is placed at Orléans in the vita's own chronology (dated 0695-01-06, Epiphany, *traditional*), while the campa names the king as the tradition does — Charlemagne — and marks the fold explicitly. This stop is written to face the Charlemagne journey directly (angel, scroll, fading letters; Master of Saint Giles NG4681 and the Chartres Charlemagne window in refs).
3. A minor forward-fold noted in passing: Veredemus later bishop of Avignon.

## Judgment calls
- **Dates**: almost nothing is attested inside the vita; everything 650–710 is *traditional* or *inferred*, anchored where the tradition gives anchors — Wamba's historical reign (672–680) dates the hunt; the feast of 1 September dates birth/hind/death stops; Peter-and-Paul (June 29) for the Rome arrival. Only Urban II's 1096 consecration is marked *attested*.
- **The hunt king** is Flavius Wamba per the vita (not the Golden Legend's vaguer "king of France").
- **The arrow stop** got the fullest campa, per instruction — the wound as the making of the patron of cripples, with the refusal-of-healing split into its own following stop to carry the Caxton "virtue should profit to him in infirmity" quote.
- **Sea route**: one open-sea stop off western Sicily for the storm; landing at Marseille (the vita's Provençal landing; also the pleasing Athens-founded-Massalia echo).
- **Afterlife**: six stops — 1096 crypt (fourth pilgrimage), 1150 facade + Via Tolosana, then the name's own journey north (Edinburgh 1124, Oxford 1120, Cripplegate 1090) and the Fourteen Holy Helpers at Vierzehnheiligen (1446 vision).

## Five richest episodes
1. **The arrow through the hand** — the wound kept open as mortification; the patron of cripples made in one instant.
2. **The Mass of Saint Giles** — the angel's scroll with Charlemagne's unconfessable sin fading as the hermit prays.
3. **The hind** — God's own dairy; the gentle economy of the thicket.
4. **The cypress doors** — cast into the Tiber at Rome, arriving at the abbey gate before the abbot.
5. **The storm calmed** — "he made his prayer, and anon the tempest ceased," the sea-road west bought with a single prayer.

## Verification (2026-07-05)

Independent pass over `giles.journey.json` — structure, canon-fidelity, coordinates, quotes.

**Structure.** JSON parses; 30 stops / 7 segments; every stop carries the full key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources); all dates YYYY-MM-DD; all campas 60–110 words; quote/quote_source always paired. Confidences: 1 attested (Urban II 1096), 3 inferred, 26 traditional — both time-folds (Caesarius of Arles; the Charlemagne of the Mass) kept whole and marked `traditional`, as the vita tells them.

**Repairs made (4):**
1. **Cloak quote made verbatim.** The second clause read "and anon as he was clad therein he received full and entire health" — a paraphrase. Corrected to Caxton's own words: "…which gave him his coat. And as soon as he clad him withal he received full and entire health." All 8 quotes now verbatim Caxton, Legenda Aurea ch. 130 (checked against christianiconography.info and catholicsaints.info transcriptions).
2. **Orléans (Mass of Saint Giles) campa trimmed** from 116 to 110 words; the angel, the scroll, and the fading letters all retained.
3. **Afterlife segment reordered chronologically:** Cripplegate 1090 → crypt consecration 1096 → Oxford 1120 → Edinburgh 1124 → facade/Via Tolosana 1150 → Vierzehnheiligen 1446 (was 1096, 1150, 1124, 1120, 1090, 1446).
4. **Vierzehnheiligen coordinates corrected** from 50.1122, 11.0605 to 50.1156, 11.0544 (basilica proper; was ~500 m off).

**Coordinate spot-checks (9 web-verified):** Athens/Acropolis, Arles Saint-Trophime, Saint-Gilles abbatiale (OSM/Nominatim 43.67678, 4.43223 — file within ~35 m; the EN-Wikipedia infobox value 43.6786 is the outlier, not the file), Nîmes, Rome St Peter's, Edinburgh St Giles', St Giles-without-Cripplegate, Vierzehnheiligen (fixed), and the Baume Saint-Vérédème (chapel/cave lies ~2.9 km below Sanilhac-Sagriès on the Gardon meander; the file's point sits inside that meander — consistent with the walk waypoints, kept). Marseille Vieux-Port, Piraeus, Collias, Orléans, Oxford verified against known site positions.

**Canon-fidelity.** The hind, the arrow, the floating cypress doors, the angel's scroll, the resurrection at Nîmes, and both centuries-folds all stand as the vita carries them; the folds are marked by confidence, never flattened. Hunt king remains Wamba per the vita, dated inside 672–680. Re-validated after repair: 30/7, ordered, schema complete, zero problems.
