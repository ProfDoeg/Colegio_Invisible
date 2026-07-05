# Bernard of Clairvaux — Fontaine to Clairvaux (1090–1153)

**Shape:** 30 stops in 8 named segments (the legs named as the hagiographic tradition folds his life: the Dream of Aleth, the Thirty into Cîteaux, the Valley of Wormwood, the Mellifluous Doctor, In Praise of the New Knighthood, the Schism and the Hammer, the Cross of Vézelay, the Bright Valley). Calendar julian. Register: national mythology — the canon (the *Vita Prima*, his letters and sermons) is TRUE and narrated as event. 18 of 30 stops carry a quote; the rest are honestly null.

## Sources
- **Vita Prima Sancti Bernardi** (William of Saint-Thierry, Arnold of Bonneval, Geoffrey of Auxerre) — the primary hagiographic canon: Aleth's dream of the barking white dog, the conversion of the kin, the novitiate custody of the senses, the confrontation with William X, the Midi mission.
- **Bernard's own corpus**, quoted directly: *De Diligendo Deo*, *Apologia ad Guillelmum*, *Liber ad milites Templi de laude novae militiae*, *Homiliae super Missus est* ("In dangers... think of Mary"), *Sermones super Cantica Canticorum*, *De Consideratione*, and the Letters (Ep. 106, 190, 363).
- Wikipedia (Bernard, Clairvaux Abbey, Cistercians, Council of Vézelay, Second Crusade, Siege of Damascus, Rhineland massacres, Liber de laude), Catholic Encyclopedia (newadvent), EWTN, the CCJR primary-text collection for the Jews-and-Crusade letter, Stanford Encyclopedia (Abelard/Sens), and the Oxford *Historical Research* article on his untranslated German preaching.

## Judgment calls
- **The lactation and amplexus** are late-medieval legend, not in the earliest Vita; I placed them at Clairvaux c.1120 marked *traditional*, narrated as event per the register, since the *Doctor Mellifluus* epithet and the whole iconographic tradition hang on them.
- **Parthenay / La Coudre (William X)**: the earliest sources say "the church of La Coudre" and admonition "at Mass"; the dramatic version (Bernard carrying the consecrated Host to the door, the duke falling as dead) is the tradition's own retelling. I set it at Parthenay, 1135 (the sources waver 1134/35), *traditional*, and gave the confrontation-quote as a Vita paraphrase, not a verbatim.
- **Speyer Salve Regina**: the "O clemens, O pia, O dulcis Virgo Maria" genuflection legend and the ascription of those three clausulae to Bernard are traditional; I marked the quote as such. The cross-taking of Conrad (28 Dec 1146) is attested.
- **Sens**: dated 1141 (the scholarly correction) though older sources say 1140.
- **The Song of Songs sermons** span c.1135–1153; I anchored the stop at 1152 to sit inside "the passing" segment and keep segment chronology monotonic.
- **German-tour route** (Frankfurt Nov → Constance/Freiburg/Basel Dec → Speyer Christmas) is reconstructed to keep dates in order; the individual southern cities are attested as a group, not each precisely dated.

## The tradition's own folds and gaps
The Vita Prima is frankly a promotional dossier assembled for canonization by men who adored him (Geoffrey of Auxerre was his secretary). Modern historians warn that our whole picture of the Abelard confrontation is *his side's* account. The register embraces this: the miraculous is narrated as fact. The real gap the tradition papers over is the **Second Crusade disaster** — Bernard promised divine victory at Vézelay and got Damascus; the canon's answer (blame the crusaders' sins, *De Consideratione*) is itself a fold, and I let his own grieving words carry it.

## The five richest episodes
1. **Aleth's dream of the barking white dog** — the founding omen, quoted, that names his whole vocation (watchdog of God's house); the *Vita's* keynote.
2. **The Lactation / amplexus at Clairvaux** — the Marian milk on his lips, source of the "mellifluous" name and centuries of painting (Cano, the Ghent master).
3. **The Rule of the Templars at Troyes + "In Praise of the New Knighthood"** — his pen founds the order Molay dies for; the "kills not homicide but *malicide*" doctrine, quoted.
4. **William X falling before the Host at Parthenay** — the schism's strongest sword broken by a wafer; pure Vita theatre.
5. **Vézelay, Easter 1146** — the platform on the Magdalene's hill, the cloth crosses running out, Bernard tearing his own habit into strips; the mobilizing sermon of the age.

## Connection to the atlas
This journey is built to **face Molay** (`molay.journey.json`): Bernard's Troyes/1129 stop and the *Liber de laude* stop deliberately name the Temple, the white mantle and red cross, and the Île aux Juifs — the order Bernard's pen founds is the order Molay burns for two centuries later, so the two itineraries clasp at the Temple. His **crusade legs (Vézelay → Speyer → Damascus)** face the Holy Land shared with Molay's Outremer and with the crusader journeys already in the directory. His **Abelard leg at Sens** faces the atlas's scholastic/heterodox strand (Hypatia, and the reason-vs-faith pole). His **Marian and Song-of-Songs interior** rhymes with the mystic journeys (Jung, Gurdjieff, the visionaries), while as sober medieval hagiography anchored on real coordinates it sits beside Joan of Arc and Clovis/Clotilde as French-Christian sacred geography.

## Verification (2026-07-05)

Structure- and canon-fidelity pass. The register was upheld throughout: no theophany, marvel, or channeled-as-authored episode was debunked — the lactation/amplexus, the milk of eloquence, William X falling before the Host, the untranslated German preaching that still moved crowds, and the Salve-Regina genuflection all STAY, marked by confidence, not removed.

- **Schema / parse.** JSON parses. Top-level keys (`traveler, title, years, calendar, register, segments`) and per-stop keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) are byte-identical to the sibling `joan_of_arc.journey.json`. Segments carry only `name, stops`. 30 stops in 8 segments — in the 30–45 target band; canon is fully represented across birth→canonization, so no stops added.
- **Chronology / confidence.** Dates are monotonic globally AND within every segment (re-verified after edits). Confidences are honest: legendary/undated stops (Aleth's dream, the lactation, Parthenay-Host, the Salve-Regina) are `traditional`; documentary anchors (Cîteaux 1113, Clairvaux foundation 1115, Troyes 1129, Sens 1141, Vézelay 1146, Damascus 1148, death 1153, canonization 1174) are `attested`. Bernard died in 1153, so the itinerary rightly closes with his death and canonization — the "living person ends at the present" rule does not apply.
- **Coordinates.** Web-spot-checked 12 stops (Fontaine-lès-Dijon, Châtillon-sur-Seine, Grancey, Jully-sur-Sarce, Cîteaux, Clairvaux, Fontenay, Vézelay, Parthenay, Étampes, Speyer, Damascus). Ten were accurate. **Two fixed IN PLACE:** *Grancey* 47.6033,4.8981 → **47.669,5.027** (was ~10 km off, wrong commune-adjacent point) and *Jully-sur-Sarce* lat 47.9994 → **48.107** (was ~12 km south of the actual village/priory; longitude 4.305 kept).
- **Quotes.** Spot-checked 6 against the canon, all faithful and carried — none nulled. Verbatim/faithful: *De Diligendo Deo* I ("God himself is the reason he is to be loved… no limit to that love"); *Missus est* Homily II ("In dangers, in doubts… think of Mary"); *Liber ad milites Templi* III (the malicide / "God's minister for the punishment of evildoers" passage, confirmed against the Fordham text); *Sermones super Cantica* (the bride = "the soul thirsting for God"); *Epistola 363* ("The Jews are not to be persecuted, killed, or even put to flight," confirmed against the CCJR primary text). The Salve-Regina and Parthenay quotes remain correctly flagged as `traditional` in their `quote_source`.
- **Campa.** All 30 present-tense and in register, 92–110 words (target 60–110). The five great episodes (Aleth's dream, the lactation/amplexus, Troyes/New Knighthood, William X before the Host, Vézelay) are full-blooded, not flat.

Net repairs: 2 coordinate corrections. No quotes nulled, no dates reordered, no stops added or removed. Re-validated with python after edits.
