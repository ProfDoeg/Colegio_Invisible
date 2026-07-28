# Otto III — Aachen to Rome, Gniezno, and Home to Aachen (983–1002)

**Shape:** 19 stops in 7 named segments (The Child Crowned and Two Regencies; Rome, and the Cousin-Pope; The Antipope and the Martyr; The Hermits' Penance and the Teacher's Ring; Gniezno, March 1000; Aachen, Pentecost 1000; The Fall of Rome, Paterno, and the Long Way Home) — inside the curator's 15–20 target, deliberately short: a life of twenty-one years, seven of them under regency. Calendar julian. Register: national mythology — the canon is true. 4 of 19 stops carry a quote; the rest are honestly null where no words survive.

## Sources
- Wikipedia, "Otto III, Holy Roman Emperor" (primary chronology anchor: birth, coronations, regencies, death dates).
- Thietmar of Merseburg, *Chronicon* (books III–IV) — the abduction, the tower speech tradition, the death.
- *Chronicon Novaliciense* III.32 — the Aachen tomb-opening, quoted verbatim, copied byte-identical from `charlemagne.journey.json` per the curator's instruction.
- Bruno of Querfurt, *Vita Sancti Adalberti* (1004) — Adalbert's martyrdom.
- Gallus Anonymus, *Gesta principum Polonorum* I.6 — the Congress of Gniezno, the diadem, the banquet vessels.
- *Vita di San Nilo di Rossano* (attrib. Bartholomew of Grottaferrata) — the hermit's rebuke over the mutilated antipope.
- History of the Germans Podcast, episodes 11–14 (Althoff-informed narrative synthesis, useful for sequencing the 1001 revolt and the winter cortège) and the Grokipedia/Wikipedia pages on the *Renovatio imperii Romanorum* bulla, Pope Gregory V, Pope Sylvester II, and the Congress of Gniezno.

## Judgment calls
- **The Aachen Pentecost 1000 stop is copied verbatim** from `charlemagne.journey.json` (lat/lng/date/campa/quote/quote_source/suggested_refs/sources all byte-identical) per the curator's explicit instruction — it is the hinge where the two journeys touch.
- **The abduction (984)** is dated to its resolution, 29 June — the day Henry the Quarrelsome surrendered the boy — rather than to the seizure itself (exact day unrecorded), so the campa narrates the whole six-month standoff retrospectively.
- **Serperi and Pereum (999)** carry only month-level precision; historians place Otto's penitential pilgrimage to Nilus and Romuald "in 999," between Crescentius's execution (Apr 998) and Sylvester II's election (2 Apr 999). I anchored them January/February 999 to keep segment chronology monotonic — this is the report's one soft date-invention, flagged `traditional`.
- **Pereum's coordinates are approximate** (the pine marshes north of Ravenna, no fixed modern site) — marked accordingly.
- **The "Renovatio" lead-seal stop (Aventine, 998-04-01)** and **Crescentius's execution (998-04-29)** are both dated to April 998; I sequenced the palace/seal first since the bulla's ideological program predates and frames the vengeance that follows, though the sources don't give a strict day-order between the two.
- **Easter 1002 (burial)** — no source states the exact burial day; I computed Julian Easter for 1002 (5 April) via the standard Meeus algorithm, since the canon agrees the cortège reached Aachen "in time for Easter."
- **Adalbert's own last words** are not recorded in any Vita I could verify; the stop's quote is honestly null rather than invented.

## The five richest episodes
1. **The abduction by Henry the Quarrelsome (984)** — a four-year-old king seized from his archbishop's custody, carried into Bavaria, and haggled back across a kingdom's worth of oaths.
2. **The mutilation of the antipope and Nilus's rebuke (998–999)** — the nearly-ninety-year-old hermit who walks into the emperor's presence and gets the broken antipope handed over to him to heal, then refuses Otto's stone monastery and takes only a purse.
3. **Gniezno, March 1000** — barefoot in the snow to a martyred friend's tomb, then the diadem lifted from his own head onto Bolesław's, and a national church founded in the same week.
4. **Aachen, Pentecost 1000** (shared with Charlemagne's own file) — the floor broken, the enthroned corpse found incorrupt, the golden nose.
5. **The tower speech and the winter cortège (1001–1002)** — "Are you not my Romans?" from a besieged palace, followed a year later by his own household fighting stone-throwers up the length of Italy to bring his body home.

## Connection to the atlas
This is the desert-bridge journey the curator asked for: the atlas has no traveler active between Charlemagne's death (814) and Bernard of Clairvaux's birth (1090), and Otto III fills the middle of that gap almost exactly at its center (983–1002). The **Aachen Pentecost 1000 stop is a literal shared pin** with `charlemagne.journey.json` — same coordinates, same campa, same quote — so the two files touch at one physical, dated event: a boy who was already crowned king before he was four opening the grave of the man he modeled his empire on. The **Gniezno leg** plants a second thread for any future Polish-line journey (Bolesław I the Brave, Adalbert of Prague himself) to grab onto — Adalbert's tomb, the diadem, and the "frater et cooperator imperii" title are all there waiting. The **hermits' penance (Nilus, Romuald)** connects forward to the Italian eremitic/monastic reform strand that Bernard of Clairvaux's Cistercians will later systematize, and the **Renovatio Imperii Romanorum** program — Byzantine ceremonial grafted onto a Roman title, run by a half-Greek emperor — gives the atlas its clearest pre-Crusade example of an East-meets-West political mysticism, a theme several later travelers (Bernard's Templar writings, the esotericist figures) will pick back up on their own terms.

## Verification pass — 2026-07-13

Structure-and-canon-fidelity verification (independent pass over the finished file).

**Validation.** `json_check.py`: OK — 7 segments, 19 stops, 4 quoted, 0 warnings, both before and after repairs. Top-level and per-stop key sets compared programmatically against `joan_of_arc.journey.json`: identical (same register line, `calendar: julian`). All 19 campas fall inside the 60–110 word band, present tense, in register — the great episodes (the opened vault, Gniezno barefoot, the tower speech, the winter cortège) are not flat. 19 stops sits inside the 15–20 target; no additions needed. Dates strictly chronological across the whole file; Otto III died 1002, so no living-traveler ending applies. The Aachen Pentecost 1000 stop re-confirmed dict-identical to `charlemagne.journey.json` after repairs.

**Coordinates web-spot-checked (14 stops).** Verified against actual/traditional sites: Aachen cathedral (x3), Cologne, Solingen, Pavia, St. Peter's, the Aventine, Castel Sant'Angelo, the Lateran (Sylvester II consecration), the Palatine, Serperi/Serapo at Gaeta, Verona, and Castel Paterno — the last confirmed to the third decimal against Wikidata/second.wiki (42.268, 12.419; file matches). Truso/Elbląg coordinates match one of the two traditional Adalbert martyrdom sites (the stop name says Truso, the refs honestly note the rival Tenkitten/Beregovoe marker — the dispute is real and the file carries both). Two fixed:
- **Nijmegen** moved from generic city center to the Valkhof itself (51.848, 5.869) — the campa names "the palace above the Waal," and the Valkhof is independently attested as where Theophanu died in June 991.
- **Both Gniezno stops** moved ~1 km from town center onto Gniezno Cathedral (52.5371/17.5969 and 52.5373/17.5972, tiny offset kept so the pins don't stack) — per Wikipedia's cathedral coordinates 52.537121, 17.596858; both campas are physically at the tomb/cathedral.

**Dates web-spot-checked.** 983-12-25 coronation, 984-06-29 (the Rohr handover of the boy — confirmed against Althoff-line sources; English Wikipedia's stray "985" refers to Henry's later Frankfurt submission, not the surrender of the child), 991-06-15 Theophanu, Solingen September 994 (day soft, honestly `traditional`), 996-05-21 imperial coronation, 998-04-29 Crescentius (late April attested; day traditional-grade but marked attested — acceptable, several references give the 29th), 999-04-02 Gerbert's election, Gniezno March 1000, 1002-01-23 death, Easter 1002 burial (computed Julian Easter = April 5, marked `traditional`). Confidences honest throughout.

**Quotes checked (all 4 — file only carries 4).**
1. *Nilus* — the "shown no mercy / find no mercy" message is the canonical line of the Vita di San Nilo tradition (the reproach-and-prophecy episode independently carried by Encyclopedia.com and the Antipope John XVI literature); kept.
2. *Gallus Anonymus, Gesta I.6* — matches published translations ("taking the imperial diadem from his own head... as a token of alliance and friendship"); kept.
3. *Chronicon Novaliciense III.32* — byte-identical with the already-verified Charlemagne file; kept untouched.
4. *The tower speech* — wording matches the standard English renderings, but the attribution was wrong: the speech is recorded by **Thangmar in the Vita Bernwardi (c. 25)**, who was in Rome with Bernward of Hildesheim during the 1001 negotiations — not Thietmar. **quote_source corrected** to "Thangmar, Vita Bernwardi c. 25 (the address from the tower, Rome 1001)".

**Canon fidelity.** Nothing debunked: the enthroned corpse and the golden nose, Nilus's prophecy, the Iron Crown's nail of the True Cross, and the Gniezno diadem (which some scholars call a 12th-century Piast retrojection) all stand as the canon tells them, with confidence markers doing the honest work.

**Repairs applied in place:** 3 coordinate fixes (Nijmegen, Gniezno x2), 1 quote_source correction (Thangmar). Re-validated clean.
