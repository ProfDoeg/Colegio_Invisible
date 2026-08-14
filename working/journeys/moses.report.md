# Moses — Drawn from the Water: the Nile to Mount Nebo

**45 stops / 9 segments. Span c. 1391–1271 BC (julian_bce). 44 of 45 stops carry a canonical quote.**

## Register
Reverent mythography on the Torah's own terms: the canon (Exodus, Leviticus, Numbers, Deuteronomy) and the aggadah are TRUE. Theophanies, plagues, the parted sea, the fire on Sinai, the earth swallowing Korah, the speaking donkey, and God burying Moses by His own hand are narrated as events, placed and dated. Quotes are the KJV verbatim (verified against King James online / Bible Hub), used only where scripture records speech; where it does not, `quote` is null — but the Torah is so richly spoken that 44/45 stops have one.

## Sources
- **The Torah** (KJV): Exodus 1–40, Leviticus 8–9, Numbers 11–24, 33, Deuteronomy 1–34. Primary throughout.
- **Aggadah / Talmud**: Sotah 12a–13b (birth; the coal that scarred his tongue; God buries him), Bava Batra 17a (death by the kiss of God), Nedarim 31b–32a and Exodus/Numbers Rabbah for the legendary amplifications.
- **Chronology**: rabbinic *Seder Olam Rabbah* (Jose ben Halafta, c. 160 CE) — the 120-year life 1391–1271 BC, Exodus 2448 AM = 1313 BC, given in the brief and confirmed via Wikipedia/Seder Olam summaries.
- **Geography**: Wikipedia *Stations of the Exodus* (the 42 encampments and their conjectural identifications), *Pi-Ramesses*, *Midian*, *Mount Nebo*; site notes on Al-Bad'/Madyan (Well of Moses, Caves of Jethro), Jebel Musa, Wadi Gharandel (Elim), Wadi Feiran (Rephidim), Jebel Harun (Mount Hor / Aaron), Punon/Feinan (copper, the bronze serpent), Ras Siyagha (Nebo/Pisgah).

## Judgment calls
- **Chronology is the tradition's, not the academy's.** I use *Seder Olam*'s traditional dates (as the brief directs) and mark nearly everything `traditional` or `inferred` — the mainstream scholarly view (Moses as legendary, no archaeological Exodus) is deliberately not the register here. There are no `attested` stops: none of these dates is externally anchored.
- **The Exodus year folds flat.** From the burning bush (1313) through Sinai (1313) the calendar-year barely moves — a single year holds the ten plagues, the sea, the wilderness marches, and the theophany. I preserved the Torah's own month/day markers (Passover 14 Nisan; Sinai in the third month; the Tabernacle reared on 1 Nisan of year two) rather than inventing spacing, so many stops share `-1313`. Then a 38-year silence (the wandering) collapses: the narrative leaps from year 2 to the fortieth year at Meribah (1273).
- **Geographic split — the two Sinais.** I placed Sinai/Horeb at **Jebel Musa** (28.539, 33.975), the site venerated since the 4th c. and home to St Catherine's, the majority Christian tradition. Note: a rival tradition puts it at Jebel al-Lawz in Arabian Midian; I kept the classical southern-Sinai site for the burning bush, Rephidim, and the giving of the Law so the route reads coherently.
- **Two burials of Aaron.** Numbers 20 puts Aaron's death at **Mount Hor** (I used Jebel Harun above Petra, 30.317, 35.407); Deuteronomy 10:6 says Moserah. I followed Numbers, the fuller scene.
- **Coordinates are the traditional sites**, not scholarly reconstructions of the "real" route — as instructed. Many delta/wilderness points (Succoth, Pi-hahiroth, the sea-crossing) are approximate; I flagged the crossing and inn as `inferred`.
- **Nebo's death-day.** The rabbinic tradition sets Moses' death on **7 Adar**, the same date as his birth; I dated both the sight from Pisgah and the death to a single day (-1271-02-07) to honor that fold.

## The five richest episodes
1. **The burning bush at Horeb** — the bush that burns unconsumed, "I AM THAT I AM," the rod-to-serpent and leprous-hand signs. The hinge of the whole life; split into two stops (theophany; the Name and signs).
2. **The Passover and the tenth plague** — the blood on the lintel, the destroyer passing over, the great cry at midnight, the founding rite of Israel dated to 14 Nisan.
3. **The Red Sea** — the east wind, the wall of waters, the drowned host, and the Song of Moses and Miriam with the timbrel; three tightly-linked stops on the same shore.
4. **Sinai** — the smoking mountain, the trumpet, the Ten Words spoken from fire, forty days in the cloud, then the golden calf and the shattered tablets, the second tables, and the shining/veiled face (the seven Sinai stops are the mythic core).
5. **Nebo** — the whole Land shown and denied, the death "by the word of the LORD," God Himself burying him so that "no man knoweth of his sepulchre." The counter-mountain to Sinai: on one he saw God face to face, on the other he is hidden from all faces.

## Faces (per the brief)
Moses' Sinai theophany and face-to-face speech with God are set to answer Elijah at Horeb, Christ's Transfiguration (Moses himself appears there), and every mountain-summit revelation across the corpus — the recurring image of the man taken up into the cloud who comes down changed.

---

## Verification (2026-07-05)

Structural, canon-fidelity, and geographic audit. Register preserved throughout — no miracle, theophany, or time-fold removed; mythic events remain dated events, flagged by confidence, not debunked.

**Structure.** JSON parses. Top-level keys (`traveler, title, years, calendar, register, segments`) and per-stop keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the sibling schema `joan_of_arc.journey.json` exactly. 9 segments / 45 stops (within the 45–65 target, at the floor; the Torah scope is already comprehensive, so no stops were added). One null quote — the Pi-Ramesses court stop — honestly null (the aggadah of the coal, not scripture). Confidences: 44 `traditional`, 1 `inferred` (the bridegroom-of-blood inn); zero `attested`, correctly, since no stop is externally anchored.

**Chronology.** Dates are `julian_bce` (leading-minus). Sorted numerically (−1391 earliest → −1271 latest, remembering −1391 is *earlier* than −1379), every segment is internally monotonic and the whole sequence is globally monotonic. The two deliberate time-folds are intact and correct: the Exodus/plagues/sea/Sinai cycle collapsed into the single year −1313 with the Torah's own month–day markers; the 38-year silence folding to Meribah in the 40th year (−1273); Moses' Pisgah-sight and death sharing −1271-02-07 (7 Adar, to match the birthday per rabbinic tradition).

**Coordinates — web spot-check, 8 distinct site-clusters, all accurate (no fixes):**
| Stop | File | Canonical/venerated site | 
|---|---|---|
| Pi-Ramesses / Rameses (court, going-out) | 30.808, 31.833 | Qantir 30.799, 31.834 ✓ |
| Well of Midian, house of Jethro | 28.478, 35.021 | Al-Bad' (Madyan) 28.475, 35.015 ✓ |
| Horeb / burning bush / Sinai (all Sinai stops) | 28.539, 33.975 | Jebel Musa 28.539, 33.975 ✓ |
| Kadesh-barnea (spies, sentence, Korah, Meribah) | 30.664, 34.418 | Tell el-Qudeirat 30.648, 34.423 ✓ |
| Mount Hor — death of Aaron | 30.317, 35.407 | Jabal Harun 30.317, 35.406 ✓ |
| Mount Nebo / Pisgah | 31.768, 35.725 | Moses Memorial, Siyagha 31.767, 35.722 ✓ |
| Beth-peor — God's burial | 31.780, 35.730 | Ayoun Musa 31.777, 35.738 ✓ (correctly NE of the summit) |

Sinai/Horeb consistently placed at Jebel Musa (southern-Sinai tradition, not the rival Jebel al-Lawz); Aaron's death at Jabal Harun above Petra (following Numbers 20 over Deuteronomy's Moserah) — both judgment calls held, coordinates match the venerated sites.

**Quotes — KJV spot-check, 9 verified verbatim (Bible Gateway KJV), no nulling or restoration needed:** Exodus 3:14 (I AM THAT I AM), 12:13 (Passover blood), 14:22 (the wall of waters), 20:2–3 (first commandments), 32:19 (the tables broken), Numbers 16:32 (the earth swallows Korah), 22:28 (the speaking donkey), Deuteronomy 6:4–5 (the Shema), 34:4 & 34:6 (the Land shown/denied; God's hidden sepulchre). All are verbatim KJV excerpts; leading capitals adjusted where a clause is lifted mid-verse; "Beth-peor" hyphenated vs KJV "Bethpeor" is a standard editorial variant, not an error.

**Voice.** All 45 campas present-tense and reverent. Word counts 58–112; a cluster of the great episodes runs 111–112 (a few words over the 60–110 guide), retained deliberately — the burning bush (split across 2 stops), Passover, the Red Sea + Song of the Sea, the seven Sinai stops, Korah, Balaam's donkey, and Nebo are all vivid and non-flat, which the register demands. No trimming that would flatten them was applied.

---

## Rashi commentary pass (2026-08-14)

By request: Rashi's own Torah commentary (not modern scholarship about him) folded into five existing stops as a distinct, explicitly attributed voice ("Rashi says/writes/reports"), sourced verse-by-verse from Sefaria's English translation of Rashi (Rosenbaum-Silbermann). Kept even where it diverges from the plain narrative already in the campa, per instruction, rather than harmonized.

- **[A: Rashi on Exodus 7:19, Sefaria]** The Nile-to-blood stop keeps the existing "Moses... lifts the rod" line and adds Rashi's contrary tradition that it was Aaron's staff, since the river had once sheltered infant Moses. The two readings stand side by side, unreconciled.
- **[A: Rashi on Exodus 32:5, Sefaria]** The golden calf stop adds Rashi's exculpatory reading that Aaron built the altar himself and set the feast for the next day, stalling rather than surrendering.
- **[A: Rashi on Exodus 34:29, Sefaria]** The shining-face stop adds Rashi's philological gloss on *keren* ("horn"/light-ray), the direct source of the horns in Michelangelo's Moses, already named in `suggested_refs`.
- **[A: Rashi on Numbers 20:11–12, Sefaria]** The Meribah stop adds Rashi's reasoning for why the missed "sanctify Me" mattered: a rock obeying speech alone would have been the greater lesson.
- **[A: Rashi on Deuteronomy 34:5, Sefaria]** The Beth-peor death stop adds Rashi's classic paradox — how could Moses have written "and Moses died there" — with the dictated-in-tears answer.

Word counts on these five now run 114–132, above the file's original 58–112 range; accepted as a further, explicitly commissioned instance of the same "vivid, non-flat, don't flatten" policy already governing the great-episode cluster above, not reopened for trimming. Full findings (including material not used here — Aaron's own miracles, Abraham/Isaac/Jacob) are in the standalone deep-dive report, not duplicated in this file. Spanish edition (`es/moses.journey.json`) updated to match.

**Result: PASS. No repairs required.** The dataset is structurally identical to the schema sibling, chronologically ordered, geographically accurate at every checked site, and canon-faithful in quote and register.
