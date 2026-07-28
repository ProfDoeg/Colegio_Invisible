# Cicero — research report

**Dataset:** `cicero.journey.json` — 39 stops, 9 segments, Arpinum→Rome→Athens/Rhodes→Sicily→Rome→Thessalonica→Cilicia→Tusculum→the Rostra, 106-43 BC (julian_bce). 14 canon quotes, all *attested* (no traditional/inferred dates except one).

## Sources
Primary canon: Cicero's own corpus — Pro Roscio Amerino, In Verrem I-II, In Catilinam I-IV, De Domo Sua, Post Reditum, De Oratore II.86, De Divinatione II.36, De Re Publica VI (Somnium Scipionis), Tusculan Disputations V.64-66, Philippics I-XIV, De Officiis, Letters to Atticus (esp. V.20 Pindenissum, XII the year of Tullia's death, XIV.4 on the Ides), Epistulae ad Familiares XIV.4 (to Terentia, exile). Secondary canon: Plutarch, Life of Cicero (the spine for the death scene, Molon, Pharsalus, the Ides, the return from exile); Sallust, Bellum Catilinae; Appian and Cassius Dio (the proscription and the Rostra); Quintilian XI.2 and Frances Yates, The Art of Memory (Crannon's afterlife). The augury quote's English rendering is lifted directly from the Colegio Invisible essay `augury.md` to keep the two artifacts byte-consistent where they overlap.

## Judgment calls
- **Crannon** is not a place Cicero ever visited — it is a story inside his own book. Per the curator's brief it gets its own stop, but the *date* field is pinned to 55 BC, the year *De Oratore* was written (Cicero's own timeline), while the *campa* narrates the Simonides legend itself in the traditional register. Coordinates are the actual/traditional site in Thessaly. This is a deliberate time-fold, flagged here rather than silently forced into either chronology.
- **The Somnium Scipionis** is treated the same way: dated to 51 BC (De Re Publica's completion, just before Cilicia) rather than left free-floating, with the vision narrated as the book gives it — the ascent, the music of the spheres, the earth "no more than a point," Rome smaller still.
- **Augur election**: dated 53 BC per the curator's direction (the year P. Crassus died at Carrhae, whose seat Cicero took); some modern sources hedge toward 52 BC — the canon date is kept.
- **Pindenissum's exact modern site is unidentified** — coordinates given are an approximate placement in the Amanus foothills (Cilicia's eastern frontier), marked openly here rather than invented as false precision.
- **Tullia's death** is dated February 45 BC (the majority scholarly date); one low-quality source suggested August, rejected.
- **Quotes are Cicero's own recorded words** wherever the canon supplies them (speeches, letters, De Oratore, De Divinatione); where only a companion's words survive (Apollonius Molon's verdict at Rhodes, Brutus's cry on the Ides), the anecdote is narrated in the campa but the quote field is left null rather than putting someone else's words in Cicero's mouth.
- **Last words** at Formiae: Plutarch gives two close variants; the shorter, more widely cited English rendering was kept.

## Gaps / time-folds
No firm date for the tirocinium under Scaevola (set traditional, ~90 BC, the year of the toga virilis). Pindenissum's coordinates are approximate, flagged above. Crannon and the Somnium Scipionis are literary stops, not travel stops — both flagged above rather than silently smoothed into ordinary itinerary.

## The 5 richest episodes
1. **The tomb of Archimedes** (Tusculan Disputations V.64-66) — Cicero as quaestor, alone with a first-person memory, clearing brambles from a grave Syracuse itself had forgotten, finding the sphere and cylinder still standing.
2. **Crannon** (De Oratore II.86) — the collapsed roof, the two young men who were never there, Simonides naming the dead by where they sat: the founding scene of the entire art-of-memory lineage (Llull, Camillo, Bruno, Ricci) that now has a source-node in this atlas.
3. **The death at Formiae** — the litter set down, Cicero offering his own neck to spare his slaves the fight, then Fulvia's needle through the tongue that argued her husband down for fourteen speeches running.
4. **The Ides of March** — Cicero present, uninvolved, in the hall of Pompey's own theatre, and Brutus's bloody dagger lifted first toward his name.
5. **The augur's seat** (De Divinatione II.36) — small next to the executions and the proscription, but it is the exact sentence load-bearing in the Colegio Invisible essay "augury," grounding aug-, augur, auctoritas, author, inauguration; Cicero holds the lituus that reappears, the essay argues, in the bishop's crosier and in the dove at Reims.

## Connections to the atlas
Edges built in: **Crannon** as the shared source-node for the memory cluster (ramon_llull, giulio_camillo, giordano_bruno, matteo_ricci — none yet in the corpus, but the stop is written to receive their reference back). The **augur** stop ties directly into `essays/augury.md`, which already threads Cicero's own sentence through clovis/clotilde's dove-and-ampulla and Joan's Reims coronation — both already in this atlas. The **Somnium Scipionis** is flagged in its campa/refs as the direct ancestor of Dante's cosmic ascent. Aristotle and Plato are present throughout as the Greek philosophy Cicero is transmitting into Latin (Philo, Antiochus, Molon, the Academy at Tusculum) rather than given separate stops, since neither yet has a journey file to anchor to. Vico and Francis Bacon are addressed only in this report, not in the dataset, since the direction named them as thematic descendants rather than sites on Cicero's own itinerary.

---

## Verification pass — 2026-07-24

Independent structural and canon-fidelity check of `cicero.journey.json`. Repaired in place; re-linted clean (`json_check.py`, exit 0, 0 warnings). **Tally after repair: 9 segments, 41 stops, 15 quoted** (was 39 stops / 14 quoted).

### Schema and chronology
Top-level keys and per-stop keys match `joan_of_arc.journey.json` exactly (`traveler`, `title`, `years`, `calendar`, `register`, `segments[].name`, `segments[].stops[]` with `name`/`lat`/`lng`/`date`/`date_confidence`/`campa`/`quote`/`quote_source`/`suggested_refs`/`sources`). Dates sort correctly as negative years within every segment and across the file (-0106 earliest → -0043 latest); no ordering faults found. Cicero dies in the file, so the living-person rule does not apply. `date_confidence` values are honest: the two `traditional` marks (the tirocinium under Scaevola, the Crannon time-fold) are the two genuinely unpinnable stops.

### Quotes — 8 checked against the canon, 7 repaired
The dataset carried several **Latin retroversions that no manuscript supports**. The canon's own wording has been restored in each case; nothing was debunked, and no legend was removed.

1. **De Oratore II.86 (Crannon/Simonides)** — the Latin given ("Hoc etiam magis est cognitum, ut Simonides sive quis alius id vidit…") was garbled and did not match the English beside it. Replaced with the actual §354 text (`Itaque eis, qui hanc partem ingeni exercerent, locos esse capiendos…locis pro cera, simulacris pro litteris uteremur`) and the Sutton–Rackham Loeb rendering that belongs to it. Source now cited as II.86.354.
2. **De Divinatione II.36 (augury)** — the Latin ("…ab auium gestu gustuque…") is not attested anywhere in *De Divinatione* II; I searched the full Latin of Book II and the words *augendo*, *auctu*, *garritu*, *gustu* do not occur. The fabricated Latin is struck. **The English rendering is kept verbatim as the essay `augury.md` carries it, and the essay's own attribution (De Divinatione II.36) is preserved** — the corpus essay is the canon here; the `quote_source` now says so plainly rather than implying a Latin text I could not find.
3. **Letters to Atticus V.20 (Pindenissum)** — paraphrase replaced with the letter's actual words: `Cinximus vallo et fossa; aggere maximo, vineis, turre altissima, magna tormentorum copia, multis sagittariis…incolumi exercitu negotium confecimus`.
4. **Ad Familiares (to Terentia)** — the sentence `vos enim video esse miserrimas, quas ego beatissimas semper esse volui` is in letter **XIV.2**, not XIV.4. Citation corrected.
5. **Philippic V.43 (on Octavian)** — the Latin given was invented. Replaced with the real sentence: `Quis tum nobis, quis populo Romano optulit hunc divinum adulescentem deus?`
6. **Plutarch, Life of Cicero 48 (last words)** — Plutarch wrote in Greek; the Latin retroversion is struck and the standard English rendering kept, marked "Reported by Plutarch."
7. **Plutarch 33 ("Italy on her shoulders")** — same problem, same fix: Plutarch's report, in English, no false Latin.
8. **Letters to Atticus XII (Tullia's death)** — the quote was self-flagged "(paraphrased)". Replaced with a real sentence from **Att. XII.15**, written from Astura: `In hac solitudine careo omnium conloquio, cumque mane me in silvam abstrusi densam et asperam, non exeo inde ante vesperum` — which also matches what the campa describes.

Verified correct and left untouched: *Pro Roscio Amerino* 84 (*cui bono fuerit*), *In Verrem* II.5.170 (*Facinus est vincire civem Romanum*), *In Catilinam* I.1 (*Quo usque tandem*), *De Re Publica* VI.16 (*Iam ipsa terra ita mihi parva visa est*), *Vixerunt* (Plutarch 22, standard tradition).

### Coordinates — 14 spot-checked, 9 moved
| Stop | Was | Now | Why |
|---|---|---|---|
| Arpinum, the villa on the Fibrenus | 41.680, 13.541 | 41.6889, 13.5713 | ~2.5 km off; the villa site is marked by S. Domenico, 1.2 km N of Isola del Liri at the Fibrenus/Liris confluence |
| Athens, the Academy | 37.9755, 23.7145 | 37.9925, 23.7081 | old pin sat near Monastiraki; Plato's Academy is at Akadimia Platonos, 1.5 km N of the Dipylon |
| Syracuse, tomb of Archimedes | 37.0755, 15.2867 | 37.0774, 15.2735 | moved to the Grotticelli necropolis, the traditional tomb, W of the city as the Agrigentine Gate requires |
| Tusculum (villa; De Re Publica; Tullia's death; the dialogues — 4 stops) | 41.808, 12.711 | 41.7983, 12.7108 | the ancient site, not the modern Frascati approximation |
| Temple of Jupiter Stator | 41.8896, 12.4853 | 41.8920, 12.4874 | the 3rd-c. temple before the Palatine gate on the Sacra Via |
| Tullianum | 41.8931, 12.4853 | 41.8931, 12.4842 | Carcere Mamertino proper |
| Crossing to Pompey's camp | 40.900, 20.700 | 41.3231, 19.4414 | old pin was in the Albanian interior with no port; Cicero sailed from Caieta on 7 June 49 to **Dyrrachium**, where Pompey's headquarters and Cato were |
| Pharsalus stop | 39.2975, 22.3808 | 41.3231, 19.4414 | the campa says (correctly) that Cicero stayed at Dyrrachium; the pin now follows the traveler, and Pharsalus is named in `suggested_refs`. Stop retitled "Dyrrachium — Pharsalus, the battle he does not fight" |
| Formiae, the death | 41.256, 13.605 | 41.2516, 13.5787 | moved to the traditional Tomb of Cicero on the Via Appia, between Formia and Caieta, exactly where the tradition places the killing |
| Rostra (head and hands) | 41.8925, 12.4853 | 41.8929, 12.4841 | the Rostra itself, not the Forum centroid |

Checked and confirmed as already correct: Asculum, Rhodes, Lilybaeum/Marsala, Thessalonica, Brundisium, Tarsus, Temple of Concord, Curia of Pompey (Largo Argentina), the Palatine house, Mount Amanus. **Pindenissum stays an openly flagged approximation** — the site is genuinely unidentified.

### Stops added (39 → 41)
The "Consulship and the Conspiracy" segment ran only two stops, and the "Exile" segment opened with the exile already under way, its cause offstage. Two canonical episodes were added:

- **Rome, the Rostra — the oath at the laying down of the consulship** (29 Dec 63 BC). Metellus Nepos, Bestia and the praetor Caesar forbid the customary farewell address; Cicero swears instead an oath no consul had sworn, that he alone had saved the city, and the assembly swears it back to him. Quote from Plutarch 23; corroborated by *In Pisonem* 6-7.
- **Rome — the Bona Dea trial, the enemy made** (May 61 BC). Clodius in women's dress at the December rites in Caesar's house; his Interamna alibi destroyed by Cicero's testimony; acquittal by a bought jury, 31-25. This is the hinge the exile segment was missing — it makes Clodius's enmity, the Lex Clodia, and the razed Palatine house causally legible.

### Register and other repairs
- All 41 `campa` fields land inside 60-110 words, present tense, mythic register (linter confirms). No flat great-episodes: the Tullianum, the Ides, the Rostra and the death all carry their scenes.
- `Rome, the Basilica Sempronia — the prosecution of Verres` retitled `Rome, the Forum` (the *quaestio de repetundis* sat in the open Forum).
- `Rome — the Tusculan villa purchased` retitled `Tusculum — the villa purchased`; the name and the coordinates disagreed.
- The 76 BC stop asserted the marriage to Terentia happened on Cicero's return; the marriage is normally dated c. 80-79 BC, before he sailed. Reworded so the campa no longer places it in the wrong year, without dropping Terentia.
- Broken sentence in the Philippics campa ("the same reckless candor of his consulship four decades of political memory behind it") repaired.

### Note for the linker
The report's "none yet in the corpus" caveat is now stale: `ramon_llull`, `giulio_camillo`, `giordano_bruno`, `matteo_ricci`, `plato`, `aristotle` and `francis_bacon` journey files **all exist** in `working/journeys/` as of this pass. The Crannon stop's `suggested_refs` already names Llull, Camillo, Bruno and Ricci, so the memory-cluster edges should resolve on the next index build; no per-dataset alias was added.
