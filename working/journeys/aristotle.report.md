# Aristotle: Stagira to Chalcis — build report

## Sources
Primary spine: Diogenes Laertius, *Lives of Eminent Philosophers*, Book V (the only ancient source that preserves Aristotle's will and several of his sayings in full — read via Wikisource/Perseus). Supplementary ancient sources: Plutarch's *Life of Alexander* (the annotated Iliad "casket copy," the letter exchange on the esoteric/exoteric lectures, Callisthenes' execution); Pliny the Elder, *Natural History* VIII.44 (Alexander's specimen-gathering for the Lyceum); Athenaeus, *Deipnosophistae* XV, and R. Renehan's philological study (the Hymn to Virtue for Hermias); Demetrius, *On Style* §144 (the solitude/myths letter-fragment); Strabo, *Geography* XIII.1.54 and Plutarch's *Life of Sulla* (the library's burial-and-recovery story). Modern synthesis and site detail from MacTutor, Neel Burton's biographical essays, GreekReporter and labrujulaverde on the Mieza excavations, and the relevant Wikipedia articles (Aristotle, Pythias, Eurymedon the Hierophant, Roger Bacon). The legacy segment draws also on the household essay `essays/190_al_andalus_and_reconquista.md` for the Maimonides/Guide-for-the-Perplexed detail the curator flagged.

## Judgment calls
- **The Euripus "suicide."** Scholarship is unanimous the story is a later Christian polemical invention (Aristotle almost certainly died of a stomach ailment). Rather than either asserting it as literal fact or silently dropping it, I narrated it as the legend the tradition itself produced — present tense, quoted, but framed as what "centuries later, Christian writers" told, with the household's own account of a wasting illness given first. This keeps the register's "canon is true" rule (the legend is a real, tellable event *of the reception*) without asserting a debunked medical claim as history.
- **Hermias' death vs. the Lesbos years, timing.** Sources disagree slightly on exact years; the move to Lesbos (c. 345 BC) actually precedes Hermias' capture and execution (341 BC) by several years. I placed the Lesbos segment before the Pella/Mieza segment, and folded the news of Hermias' death and the Hymn to Virtue into the Mieza stops (Aristotle was already tutoring Alexander by then) rather than in the Assos segment, to keep the whole file chronological — this cost two reorderings caught by the linter and fixed.
- **The final "afterlife" segment.** Aristotle's own life ends at Chalcis in 322 BC, but the curator's brief asks for edges to maimonides, hypatia, dante, and roger_bacon — none of whom have their own journey files yet in this atlas. Rather than force those as false "shared pins" or invent premature sibling files, I folded the whole transmission chain (Sulla's sack → Baghdad's Bayt al-Hikma → Averroes in Córdoba → Maimonides in Fustat → Toledo → Roger Bacon at Oxford → Dante's Limbo) into a seventh segment of Aristotle's own journey, on the model of Hypatia's "Folding"/"Cult Flows West" segments. This keeps every edge honest (all are documented reception-history, not invention) while giving future plato/alexander/maimonides/dante/roger_bacon journeys clear, unforced places to shared-pin back into this file later.
- **Hypatia edge:** left implicit. Hypatia's own journey (`hypatia.journey.json`) is a Neoplatonist, not an Aristotelian, lineage; I did not force a direct textual link, judging that manufacturing one would violate "generalize, don't memorialize." The natural connective tissue is simply that both are Alexandrian/Athenian schools of the same broader Greek philosophical world; no invented shared pin was added.
- Dates before c. 340 BC are almost all year-only in the sources; month/day are my own placeholders (matching the convention already used in sibling BCE-era files like `abraham.journey.json`), marked with appropriate `date_confidence`.

## Gaps / time-folds
- No stop for the intervening years Aristotle spent literally in Persian-adjacent Assos vs. Atarneus (Hermias' capital moved between both; I treated them as one court, using Assos' coordinates for both).
- The exact chronology of Alexander's estrangement from Aristotle after Callisthenes' execution (327 BC) is compressed into a single stop; the ancient sources themselves are thin here.
- The seventh segment necessarily leaps centuries per stop (86 BC → AD 832 → 1180 → 1190 → 1230 → 1267 → 1308) — an explicit "folding," flagged in the segment name itself ("The Long Afterlife") rather than disguised as continuous time.

## Five richest episodes
1. **The Hymn to Virtue for Hermias** (Mieza, -341) — the fragment survives whole, is Aristotle's only known poem, and is the very text that kills him politically thirty years later.
2. **The will** (Chalcis, -322) — uniquely preserved in full by Diogenes Laertius; every clause (Herpyllis's silver and handmaids, Nicanor's marriage to the daughter, the freed slaves, Pythias's bones) reads like nothing else in the ancient philosophical record: a systematic mind closing its own accounts.
3. **"I will not let Athens sin twice against philosophy"** (Athens, -323) — the single sentence that will outlive most of the treatises, deliberately answering Socrates' trial 76 years earlier.
4. **The annotated Iliad / casket copy** (Mieza, -341) — a physical object that travels with Alexander to Issus and back, linking teacher and pupil across the whole Asian campaign.
5. **The buried, worm-eaten, Sulla-looted library** (Rome, -86) — the strange, almost accidental survival of the corpus itself, and the origin of the very word "Metaphysics" (a shelving accident, ta meta ta physika).

## Connections to the atlas
This file is the first Aristotle-adjacent node in the corpus. It leaves clean, textually-grounded hooks for future siblings: **plato** (the Academy years, Plato's "colt" remark, "dear to me... dearer still is truth"), **alexander** (Pella/Mieza tutoring, the Iliad, the Callisthenes rupture — Alexander's own journey file, when written, should shared-pin these same stops), **maimonides** (the Fustat stop, tied directly to essay 190), **dante** (the Inferno IV Limbo stop, verbatim quoted), and **roger_bacon** (the Oxford stop on the Arabic-mediated reception and Opus Maius). **hypatia** was deliberately left unforced — no manufactured shared pin, per the "generalize, don't memorialize" rule — since her own lineage is Neoplatonist rather than Aristotelian and the existing `hypatia.journey.json` gives no natural seam.

---

## Verification pass — 2026-07-24

`json_check.py` clean before and after repair: **OK, 7 segments, 40 stops, 11 quoted, no WARN**. Top-level and per-stop schema match `joan_of_arc.journey.json` exactly (`traveler / title / years / calendar / register / segments`; stops carry `name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`). Stop count 40 sits inside the 30-45 target, so no stops were added. Chronology is monotonic within every segment *and* across segment boundaries (-0384 → -0322, then the flagged fold to +1318). Campa word counts run 73-107, all present tense, register held.

### Coordinates corrected (12 sites, web-verified)

Spot-checked every distinct site against Wikipedia's own gazetteer coordinates and against sibling journey files for shared-pin alignment.

| Site | Was | Now | Error |
|---|---|---|---|
| Assos (Behramkale) | 39.4917, 26.7167 | 39.4878, 26.3369 | **~33 km** — longitude was badly wrong, landing inland of the Troad coast |
| Pyrrha lagoon, Lesbos | 39.2000, 26.1833 | 39.1605, 26.2864 | **~9 km** |
| Stagira | 40.5667, 23.9333 | 40.5917, 23.7947 | ~12 km — was on the modern village, not the excavated site above Olympiada |
| Mieza / the Nymphaeum | 40.6275, 22.1333 | 40.6307, 22.0984 | ~3 km |
| Pella | 40.7667, 22.5167 | 40.7547, 22.5211 | ~1.4 km |
| Plato's Academy | 37.9926, 23.7097 | 37.9925, 23.7081 | snapped to the exact pin used by `plato.journey.json` and `cicero.journey.json` |
| The Lyceum | 37.9757, 23.7428 | 37.9741, 23.7435 | ~190 m, snapped to the Rigillis St site |
| Chalcis | 38.4634, 23.5931 | 38.4625, 23.5950 | ~200 m |
| Mytilene | 39.1097, 26.5603 | 39.1100, 26.5550 | ~460 m |
| Fustat | 30.0059, 31.2313 | 30.0059, 31.2312 | snapped to the exact `maimonides.journey.json` pin |
| Oxford | 51.7548, -1.2544 | 51.7528, -1.2537 | snapped to the `roger_bacon.journey.json` schools pin |
| Ravenna (Dante) | 44.4184, 12.2035 | 44.4177, 12.1998 | snapped to the `dante.journey.json` pin |

### Dante stop re-dated 1308 → 1318

The stop sat at Ravenna's coordinates but bore 1308, a year Dante spent in the Casentino/Lunigiana, not Ravenna (`dante.journey.json` puts him at Guido Novello's court from 1318). Rather than move the pin to a speculative composition site, the date now follows the pin: Ravenna, 1318, the Comedy moving toward its end, `date_confidence: traditional`. The campa opening was rewritten to match ("In his last exile, sheltered at Ravenna by Guido Novello da Polenta…"). The Inferno IV quote is unaffected.

### Quotes — 11 checked, 4 restored to canon wording

Verified verbatim, unchanged: the liars saying (DL V), Plato's "colt" remark (DL V.2), "a single soul dwelling in two bodies" (DL V), the Hymn to Virtue line on gold and soft-eyed sleep (DL V.7-8), "I will not allow the Athenians to sin twice against philosophy" (confirmed at the Wikipedia *Aristotle* article, verbatim), Dante *Inferno* IV.131-132.

Restored where the file carried a paraphrase rather than the canon's own words:

- **Plutarch, *Alexander* 7.** Was a loose composite ("They have been published and not published, since in fact they will be intelligible only to those who have heard our lectures"). Now the Perrin text verbatim: *"The doctrines of which he spoke were both published and not published; for in truth his treatise on metaphysics is of no use for those who would either teach or learn the science, but is written as a memorandum for those already trained therein."*
- **Nicomachean Ethics I.6.** Was "Both are dear to me, yet it is a sacred duty to give the preference to truth" — a rendering no standard translation carries. Now the Ross text: *"While both are dear, piety requires us to honour truth above our friends."* (1096a16). The campa was adjusted to match.
- **Aristotle's will, the Herpyllis clause.** Was an elided paraphrase. Now the Hicks text verbatim from Diogenes Laertius V.11-16.
- **Demetrius, *On Style* §144.** Was "The more solitary and withdrawn I am, the more I have come to love myths." Now the standard rendering of the Greek doublet *αὐτίτης καὶ μονώτης*: *"The more solitary and alone I am, the fonder I have become of myths."*

The Euripus legend quote was left standing, per the canon-fidelity rule. It is *not* debunked: the household's stomach ailment is still narrated first, the legend second and explicitly as what the later polemicists told, with `quote_source` already flagging it apocryphal. The pun on *grasp* rightly carries the Latin *cepit*.

### Factual correction

Stagira's destruction is dated 348 BC, not 349. The rebuilding stop (-0342) said "Five years before"; corrected to "Six years before."

### Correction to the build report above

The §"Judgment calls" and §"Connections" claims that **plato, alexander, maimonides, dante, and roger_bacon "have no journey files yet in this atlas"** are **false as of this pass** — all five exist in `working/journeys/`. The seventh "afterlife" segment is nonetheless the right structure (it mirrors `hypatia.journey.json`'s own folding segments and every stop is documented reception-history), and the coordinate snapping above has now turned Fustat, Oxford, Córdoba, Toledo, Baghdad and Ravenna into genuine shared pins with those sibling files rather than near-misses. No stops were removed.

### Open item for a later pass

`alexander.journey.json` places Mieza at 40.6170, 22.0670 and Pella at 40.7590, 22.5290 — both drift ~2-3 km from the verified archaeological coordinates now used here. Aristotle's file was set to the verified values rather than to Alexander's; the two should be reconciled when Alexander's file is next verified.
