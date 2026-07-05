# Hannibal journey — research report

**Dataset:** `hannibal.journey.json` — 65 stops in 7 segments, 247–183 BC, calendar `julian_bce`.

## Sources
Primary canon: **Polybius** (Histories 2–3, 8–11, 15 — including his autopsy of the bronze tablet at Cape Lacinium, 3.33/3.56) and **Livy** (books 21–39). Secondary canon woven in where the tradition lives there: **Cornelius Nepos** (Hannibal — the wigs are Polybius; the Gortyn lead-amphorae and serpent-pots are Nepos), **Plutarch** (Fabius, Marcellus, Flamininus, Lucullus 31 for Artaxata), **Cicero** (De Divinatione 1.49 dream; De Oratore 2.75 Phormio; the Juno-column dream at Lacinium, De Div. 1.24), **Aulus Gellius 5.5** (the gilded-army joke), **Strabo**, **Pliny NH 5.43** (Prusa, the Libyssa tumulus), **Justin**, **Silius Italicus** (Imilce only). Web verification via Perseus, Livius.org, topostext, Dickinson Commentaries, and the Alps-route literature (Smithsonian/Mahaney on Traversette).

## Judgment calls
- **Dates:** almost nothing is calendar-attested except Cannae (a.d. IV Non. Sext. = 2 Aug 216). Only Cannae is marked `attested`; battle-year traditions (Trasimene ~21 June, Trebia ~solstice, Zama ~19 Oct) are `traditional`; march logistics are `inferred`. Death year follows Livy's 183 over Polybius's implied 182.
- **The Alpine pass:** placed at Col de Clapier coordinates with the Clapier/Traversette debate named inside the campa — the canon itself argues, so the dataset says so rather than pretending certainty.
- **Zama's field:** location debated; used Zama Regia (Jama/Siliana) and flagged the uncertainty in the campa; the parley is separately placed at Naraggara per Livy.
- **Quotes:** 11, all from the canon (Polybius 3.11 oath; Livy 21.35, 22.30, 22.51, 27.51, 30.30, 30.44 condensed, 35.14, 39.51; Plutarch Fabius 15; Gellius 5.5). Maharbal's rebuke is not Hannibal's own words — the brief includes it by name, so it rides in the quote field with the speaker identified. Everything else is null; no invention.
- **Register:** the dream of the serpent, the unfelt earthquake, Juno's threat to his good eye, the vinegar-split boulder, and the snake-pots are narrated as events, per the brief. The Goethe counter-crossing is felt at the Alpine summit, Trasimene, Spoleto, and the walls of Rome.

## Gaps in the canon
Birth date (year only); Imilce and the son (poets, not historians); the route and stations between Tagus victories; the whole of 215–212 compressed (Nola stands for it); the exile's Armenian itinerary rests on two sentences of Strabo/Plutarch; the tomb's exact site is genuinely lost (Pliny knew only the tumulus; the Gebze monument is modern homage) — the dataset says so.

## Five richest episodes
1. **The Tophet oath** (Polybius 3.11 — told by Hannibal himself at Ephesus, so the oath frames both ends of the journey).
2. **Rhone-to-Alps sequence** — elephants walking the riverbed with raised trunks, the white rock, the summit speech, vinegar and fire.
3. **Cannae diptych** — the Gisgo joke at dawn, the double envelopment, then Maharbal and the bushels of rings at next dawn.
4. **Hannibal ad portas** — the spear over the wall, the twin hailstorms, the auction duel.
5. **The Libyssa endgame** — seven doors, the ring, the last words, and the paired death of Scipio at Liternum.

---

## Verification (2026-07-05)

Independent structure-and-canon pass over `hannibal.journey.json`. Repairs applied in place; file re-validated after.

**Structure.** JSON parses; 7 segments / 65 stops (inside the 50–70 target, no additions needed); all 10 schema keys present on every stop.

**Chronology.** All 65 dates sorted numerically as BCE (−247 → −183, astronomical year comparison, not string order): strictly chronological. Confidence flags sane — Cannae (2 Aug 216) is the sole `attested`; everything else `traditional`/`inferred`.

**Coordinates.** 13 stops web-checked against the actual sites: Sancti Petri/Melqart, Cástulo, Ruscino, Col de Clapier, Tuoro–Trasimene, Cannae (both stops), Naraggara (Sakiet Sidi Youssef), Artaxata (Khor Virap), Libyssa (Dilovası), the tumulus, plus the Maurienne approach stops read against the Clapier route. Five fixes applied:
- Gades/Melqart temple (2 stops): 36.3772 → 36.388, −6.2213 (onto the Sancti Petri islet/Boquerón site).
- Ruscino: → 42.7085, 2.9456 (Château-Roussillon archaeological site).
- Summit of the pass: → 45.1675, 6.9228 (Col de Clapier proper, 45°10′03″N 6°55′22″E; the file's point sat ~3.4 km east of the pass).
- Tumulus of Libyssa: → 40.7823, 29.4417 (Hannibal Hill memorial, Gebze). The Libyssa house stop stays at Dilovası, consistent with the current identification.
All other spot-checked stops were on site (Naraggara and Khor Virap essentially exact).

**Quotes.** 6+ spot-checked against the canon; all 11 verified genuine and correctly sourced (Polybius 3.11; Livy 21.35, 22.30, 22.51, 27.51, 30.30, 30.44, 35.14, 39.51; Plutarch Fabius 15; Gellius 5.5). None nulled.

**Campa.** Present tense throughout, great episodes vivid (Rhone elephants, vinegar and fire, Trasimene fog, Cannae diptych, serpent-pots, seven doors). 28 campa ran over the 110-word ceiling (111–125). Each trimmed surgically — a clause dropped or tightened, no image or canon detail removed — to land the whole set at 68–110 words. The Clapier/Traversette acknowledgment, Zama-field flag, Goethe weave, and register lines all survive.

**Post-repair validation.** Python re-check: parse ✓, keys ✓, numeric BCE order ✓, word band 68–110 ✓, 11 quotes ✓, 65 stops ✓. Dataset passes clean.

Sources used for coordinate checks: [Col de Clapier — Wikipedia](https://en.wikipedia.org/wiki/Col_de_Clapier), [Cannae — Wikipedia](https://en.wikipedia.org/wiki/Cannae), [Canne della Battaglia](https://www.italyreview.com/cannae.html), [Naraggara — Wikipedia](https://en.wikipedia.org/wiki/Naraggara), [Zama (Tunisia) — Wikipedia](https://en.wikipedia.org/wiki/Zama_(Tunisia)), [Libyssa — Wikipedia](https://en.wikipedia.org/wiki/Libyssa), [Libyssa mausoleum survey](https://bikeclassical.blogspot.com/2025/02/libyssa-hannibal-mausoleum-mystery.html), [Ruscino site — Ville de Perpignan](https://www.mairie-perpignan.fr/culture-patrimoine/patrimoine/le-site-archeologique-de-ruscino), [Cástulo — spain.info](https://www.spain.info/en/places-of-interest/archaeological-site-castulo/), [Battle of Lake Trasimene — Wikipedia](https://en.wikipedia.org/wiki/Battle_of_Lake_Trasimene), [Artaxata — Wikipedia](https://en.wikipedia.org/wiki/Artaxata), [Temple of Hercules Gaditanus — Wikipedia](https://en.wikipedia.org/wiki/Temple_of_Hercules_Gaditanus).
