# Marco Polo — build report

**Shape:** 8 segments, 42 stops, 17 quoted, span 1254–1324 (julian).

## Sources
Canon spine is *Il Milione* / *The Travels of Marco Polo* (Rustichello da Pisa's Franco-Italian redaction, cited throughout in Henry Yule's 1903 Yule-Cordier translation, book/chapter numbers given in each stop's `sources`). Supporting texture from Wikipedia and Britannica biographical entries, New World Encyclopedia, the Kököchin article, Silk Road Foundation's route notes, erenow.org's *Marco Polo: From Venice to Xanadu*, chinadaily.com.cn on Quinsai, historyofinformation.com and the Ezra Pound Cantos project on the paper-money chapter, and — for the deathbed legend specifically — Jacopo d'Acqui's *Imago Mundi seu Chronica* (c. 1330), the earliest attestation, reached via ilmattino.it and livescience.com secondary citations. No PDF sources were needed; everything came through WebSearch/WebFetch on open web texts and Gutenberg/archive.org editions of Yule.

## Judgment calls
- **The two "first journeys" compressed.** Niccolò and Maffeo's 1260–69 trip (Constantinople → Sarai → Bukhara → the Great Khan's court → home) is canon but not Marco's own experience; I gave it six stops as scene-setting rather than skipping it, since it's the hinge that explains why a Venetian teenager ends up crossing Asia at all.
- **Khanbaliq used for the 1266 first audience.** Sources disagree on exactly where Kublai received the brothers before Khanbaliq was formally the capital; I placed it there as the best-attested seat, marked `traditional`, rather than inventing a more specific but unverifiable site.
- **Yangzhou governorship flagged as contested**, per the campa text itself — modern scholarship finds no Chinese record of it, and the stop says so rather than passing off a live controversy as settled fact.
- **Pamir coordinates are a plateau, not a point** (37.5°N, 74.5°E) — the canon describes forty days on a featureless tableland, not a single site, so the pin is a reasonable centroid rather than a specific traceable location.
- **The deathbed quote is explicitly a legend**, not from *Il Milione* itself — `quote_source` names Jacopo d'Acqui's chronicle as the earliest recorded version so the reader can see it's a later attestation, not the canon's own words.
- **Champa's tributary claim** ("since Marco's own embassy years before") is Marco's own chronologically-strained boast, flagged as such in the campa rather than silently corrected.

## Time-folds / gaps
Three years (1279–1282, roughly) of unnamed missions between Yangzhou and Yunnan are folded into a single "seventeen years of service" arc rather than invented as false-precise stops. The exact months of most inland stops (Kerman, Balkh, Badakhshan, Kashgar, Yarkand, Khotan, Ganzhou) are `inferred` — the canon gives sequence and rough duration, not calendar dates, so months were spaced out evenly across the known ~3.5-year overland transit (1271 Acre departure → May 1275 Shangdu arrival).

## Five richest episodes
1. **The Desert of Lop** — spirit-voices calling stragglers by name, drums and clashing arms heard in empty air; the direct Yule quote is one of the most-cited passages in the whole book and gives the atlas its first Gobi ghost-story.
2. **Shangdu/Xanadu** — the gilded marble palace and the portable cane pavilion, the passage that later fed Coleridge's poem; a clean bridge from 13th-century Mongol court to English Romanticism.
3. **Quinsai (Hangzhou)**, "the city of heaven" — Marco's longest, warmest chapter, twelve thousand bridges and a lake he never tires of describing.
4. **The sea return with Princess Kökötchin** — fourteen ships, six hundred souls, eighteen survivors at Hormuz; the human cost of the "sea road home" the curator asked for is stated plainly, not softened.
5. **The Genoa prison** — Curzola's defeat delivering, almost as an accident of one lost naval battle, the one Venetian whose testimony would outlast the war that captured him; Rustichello's presence in the same cell is the mechanism by which the whole canon exists at all.

## Connections to the atlas
- **Jerusalem/Sepulchre pin (31.7785, 35.2295) is byte-identical** to `jesus.journey.json`'s tomb pin, per instruction.
- **Acre pin (32.9204, 35.0692) is byte-identical** to `joffrey_bourlemont.journey.json`'s Saint-Jean-d'Acre stop — same crusader port, shared without alteration.
- **Tabriz stop cross-references `nizami.journey.json`** explicitly in its campa and sources: Marco passes through the same Ilkhanid Persia roughly sixty years after Nizami's death at Ganja, two travelers through one long Persian afternoon.
- Fills the atlas's stated East Asia/desert gap (previously Keyserling alone in that quadrant) with a full Silk Road transit: Persia → Pamir → Kashgar → Gobi → North China → South China → maritime Southeast Asia → Indian Ocean.

## Verification pass — 2026-07-13

Independent structure/canon-fidelity check. `json_check.py`: OK, no WARN (segments=8, stops=42, quoted=17). Top-level and per-stop keys byte-match the joan_of_arc.journey.json schema. Chronology strictly increasing 1254-09-15 → 1324-01-08 across all eight segments; dead traveler correctly ends at the will/death stop. Stop count 42 sits inside the 30–45 target; no additions needed. Campa word counts all in range; register holds (the canon is true — the Lop spirits, the Sepulchre oil, the deathbed refusal all stand, legend flagged as legend).

### Coordinates (spot-checked 20+ against actual/traditional sites)
- **FIXED — Sarai on the Volga**: was 47.867, 46.117 (empty steppe ~120 km NW of any site); now **47.1814, 47.4345**, the Selitrennoye gorodishche = Sarai-Batu ruins the suggested_ref names.
- Verified good as-pinned: Venice/S. Giovanni Grisostomo, Constantinople, Bukhara, Khanbaliq, Acre (byte-shared with joffrey), Jerusalem/Sepulchre (byte-shared with jesus), Ayas/Yumurtalık, Tabriz, **Hormuz at the mainland Minab-side old-Hormuz site (correct for pre-1300, a thoughtful pin)**, Kerman, Balkh, Badakhshan/Fayzabad, Pamir plateau, Kashgar, Yarkand, Khotan, Lop = Charkhlik/Ruoqiang (the canon's "city of Lop"), Ganzhou/Zhangye, Shangdu ruins, Yangzhou, Kunming, Hangzhou, Quanzhou, Champa/Vijaya (Quy Nhon), Ferlec/Peureulak, Kollam, Trebizond, Curzola, Genoa/Palazzo San Giorgio. Ceylon pinned at the southern coast (Galle) — acceptable for a coasting fleet.

### Quotes (checked 14 of 17 against Yule-Cordier — scan of vol. 1 via archive.org, Columbia AFE ch. XXIV facsimile, CMU excerpt text, phrase-level web checks)
Verified verbatim as filed: Tabriz (Baudas/Cremesor), Kinsay (head trimmed to canon "The city is..."), paper money (both halves verbatim; normalized Khan's→**Kaan's**), Xanadu first clause, deathbed legend (correctly attributed to Jacopo d'Acqui as legend, not canon-proper — kept).

Restored to canon wording (were paraphrases or wrong-translation wordings attributed to Yule-Cordier):
1. **Hormuz ships** — dropped intrusive "but" ("Their ships are wretched affairs...").
2. **Balkh** — now Yule verbatim "Balc is a noble city and a great, though it was much greater in former days..."
3. **Badakhshan** — now "It is in this province that those fine and valuable gems the Balas Rubies are found... azure... 'tis the finest in the world."
4. **Pamir** — tail "This is truly the highest place in the world" was not carried; replaced with the verbatim continuation "...so that travellers are obliged to carry with them whatever they have need of." Cite fixed ch. XXIX→XXXII.
5. **Lop** — replaced with Yule verbatim "Even in the day-time one hears those spirits talking..." Cite tidied to ch. XXXIX.
6. **Xanadu park tail** — now "...fountains and rivers and brooks, and beautiful meadows, with all kinds of wild animals."
7. **Yunnan/Carajan** — now "In this country gold-dust is found in great quantities... And for small change they use porcelain shells."
8. **Zaiton** — trimmed to the carried fragment "It is one of the two greatest havens in the world for commerce."
9. **Sumatra stockade** — now Yule (Ramusio-bracket) verbatim "They dug large ditches on the landward side... bulwarks or stockades of timber for fear of those brutes of man-eaters." Cite fixed ch. IX→X (Samara).
10. **Ceylon** — now "It has a compass of 2400 miles... rubies are found in this Island and in no other country in the world but this..." Cite fixed ch. XVI→XIV.
11. **Genoa prologue** — the "creation of Adam" wording was Marsden/Wright, not Yule; replaced with Yule's preamble verbatim "Since our Lord God did mould with his hands our first Father Adam... as hath had this Messer Marco!"

### Canon-number correction (the big one)
The departure/survivor quotes were cited to "Book II, ch. XVIII" — the episode is **Prologue ch. XVIII**, and Yule-Cordier (1871 1st ed. verified against the archive.org scan; 1903 3rd ed. confirmed by phrase-match) reads **"He then caused thirteen ships to be equipt"** and **"only eight survived"** of the some 600 embarked — not the fourteen ships / eighteen souls of the popular (Ramusio-descended) retellings. Quotes restored to canon verbatim, cites fixed to Prologue, and the campa harmonized (thirteen ships; "a bare eight lived to see this harbor"). The canon spine cited per stop is Yule-Cordier, so the canon's own numbers govern.

Re-validated after repair: `json_check.py` OK, no WARN — segments=8, stops=42, quoted=17.
