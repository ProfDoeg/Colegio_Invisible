# Giordano Bruno — report

**Sources.** Primary anchor is the trial record itself (Firpo, *Il processo di Giordano Bruno*, and the Venetian/Roman deposition tradition), plus Treccani's *Dizionario Biografico* entry, the Stanford Encyclopedia of Philosophy and MacTutor biographical summaries, Frances Yates's *Giordano Bruno and the Hermetic Tradition* and her essay on the Oxford conflict, Gaspar Schoppe's eyewitness letter to Konrad Rittershausen (17 Feb 1600, the source for both the "maiori forsan" retort and the execution scene), and Italian-language popular/scholarly sites (grandeoriente.it, ultimavoce.it, alessandrodiadamo.wordpress.com, iniziazioneantica.altervista.org) cross-checked against each other for the denunciation and sentencing dates. Wikipedia's Italian and English Bruno/*Processo* pages served as a spine for chronology, checked wherever possible against Treccani. The Padua/Galileo chair detail comes from the University of Padua's own heritage pages and the Museo Galileo itinerary.

**Judgment calls.** Bruno's birth date is attested only to "January 1548"; I placed it at the 15th as a traditional midpoint, flagged accordingly. Several campa entries compress documented multi-month spans (the Wittenberg two years, the Rome eight years) into a single anchoring date at the start of the period — the prose gestures at the duration. The Il Candelaio "prologue contempt" and the Oxford "stolen from the moon" lines are close paraphrase/reconstruction from secondary characterization rather than verbatim primary quotation; I marked their quote_source as attributed/paraphrased rather than claiming exact archival wording, in keeping with the honesty the schema asks for. The De la causa and De l'infinito quotations are widely circulated English renderings of the Italian original (dialogue V and dialogue I respectively) — accurate in substance, translation-dependent in exact wording.

**Gaps / time-folds.** The itinerary compresses some minor stops the curator didn't name (Savona, Turin are folded into single transit lines rather than given their own stops) to hold the count near the 30–45 target. The lost *De' segni de' tempi* (Venice, 1576) is included though the text does not survive — its existence and title are attested, its content is not, so the campa stays deliberately thin there. The Roman trial's documentary record itself has real gaps (the original process file went missing for centuries and was only partly recovered in the Vatican Secret Archives in 1940), so the Rome segment leans on the reconstructed narrative historians have assembled from surviving fragments and Schoppe's outside testimony rather than a continuous transcript.

**Five richest episodes.** (1) The Ash Wednesday Supper at Fulke Greville's chambers, London 1584 — the single dinner-party frame Bruno turned into his greatest dialogue. (2) The Oxford disputation, June 1583 — plagiarism charge, ridicule, and the birth of his lasting grievance against the schools. (3) Mocenigo's locked attic and triple denunciation, Venice May 1592 — the betrayal that ends the run. (4) Bellarmine's eight propositions and Bruno's flat December 1599 refusal — the hinge where patience becomes martyrdom. (5) Campo de' Fiori, 17 February 1600 — the gag, the turned face, Schoppe's letter.

**Connections to the atlas.** Ramon Llull is the declared master of the combinatory art from Bruno's Naples schooling under Teofilo da Vairano straight through to *De compendiosa architectura* (Paris, 1582) — an explicit edge for llull's own journey file. Giulio Camillo's memory theatre is the implicit rival/precedent behind every demonstration Bruno gives at Henri III's court and in the *De umbris idearum* — both men were received by kings curious about the same art. Hallaj stands as the other burned mystic in the atlas: gagged/silenced at execution (Hallaj's own dismemberment scene, Bruno's mordacchia) and both refusing recantation to the end. Hypatia anchors the martyr-axis on the pagan/philosophical side of the same theme — reason burned or torn by an institutional mob. The Frankfurt/Venice hinge (Ciotti carrying Mocenigo's letter) is the same kind of fatal-invitation device that recurs across the corpus wherever a wanderer is drawn back into reach of an old enemy.

---

## Verification pass — 2026-07-24

`json_check.py` clean before and after (exit 0, no WARN). Final tally: **9 segments, 45 stops, 11 quoted**; global chronology monotonic 1548-01-15 → 1600-02-17; all campa within 60–110 words. Compared structurally against `joan_of_arc.journey.json`: same six top-level keys, same ten per-stop keys, same segment shape. Nothing structural to fix.

### Dates corrected

| Stop | Was | Now | Why |
|---|---|---|---|
| Helmstedt, Academy Julia | 1588-12-01 *attested* | 1589-01-13 *traditional* | Bruno matriculated at the Academia Julia in January 1589, not late 1588; the day is conventional, so confidence downgraded. |
| Helmstedt, excommunicated | 1589-01-15 *attested* | 1589-02-01 *traditional* | Sources give only "1589" / "shortly after arrival"; the precise day is not attested, and it cannot precede the matriculation. |
| Venice, arrest | 1592-05-24 | 1592-05-23 | Treccani DBI and the *Processo* record both give 23 May 1592. |
| Rome, Bellarmine's propositions | 1599-01-01 | 1599-01-14 | SEP: the congregation approved Bellarmine's eight propositions on 14 January 1599. (Italian Wikipedia gives 18 January for the abjuration demand; the January anchor holds either way.) |
| Geneva, proofreader | *attested* | *inferred* | The arrival date is not documented; only the matriculation of 20 May 1579 is. Campa now names that date instead of "in May". |

Everything else checked out: novitiate **15 July 1565** confirmed by Treccani (Italian Wikipedia's "15 giugno" is the outlier); ordination after his 24th year, i.e. 1572; Geneva consistory 13 August 1579 with absolution on the 27th; Cambrai 28 May 1586; Marburg matriculation 25 July 1586; Wittenberg farewell oration 8 March 1588; Rome 27 February 1593; refusal 21 December 1599; Clement VIII 20 January 1600; sentence 8 February; fire 17 February 1600.

### Coordinates corrected (13 stops)

Spot-checked 15 sites against Wikipedia/Treccani coordinates; eight distinct locations were off and were repaired:

- **San Domenico Maggiore, Naples** 40.8494,14.2571 → **40.8487,14.2544** (2 stops)
- **Noli** 44.2058,8.4053 → **44.2057,8.4162** (~900 m west of the town)
- **French embassy, London** 51.5111,−0.1075 → **51.5135,−0.1063** (Salisbury Court/Square, off Fleet Street; 4 stops)
- **Whitehall** 51.5033,−0.1276 → **51.5040,−0.1260**
- **Collège de Cambrai, Paris** 48.8447,2.3467 → **48.8489,2.3459** (site now occupied by the Collège de France; was ~470 m south)
- **Marburg** 50.8021,8.7734 → **50.8085,8.7718**
- **Wittenberg** 51.8667,12.6500 → **51.8664,12.6435** (2 stops, ~1.2 km east)
- **San Domenico di Castello, Venice** 45.4368,12.3548 → **45.4316,12.3549** (the demolished convent stood at the corner of via/viale Garibaldi; was ~580 m north)
- **Palazzo del Sant'Uffizio, Rome** 41.9022,12.4547 → **41.9010,12.4561** (4 stops)
- **Sentencing venue, 8 Feb 1600** 41.8969,12.4767 → **41.8987,12.4726** (see below)

Verified as already correct: Nola, Naples city, Santa Maria sopra Minerva, Venice San Marco, Padua, Chambéry, Geneva, Toulouse, Paris, Oxford, Prague, Helmstedt, Frankfurt, Zurich, Palazzo Mocenigo at San Samuele, Campo de' Fiori (41.8955,12.4723 vs. the surveyed 41.8956,12.4720).

### Factual repairs to campa

1. **Age at death was wrong.** Campo de' Fiori read "He dies, forty-two years old". Born January/February 1548, died 17 February 1600 — he died at **fifty-two**. Corrected.
2. **Wrong venue for the sentence.** The stop had the sentence of 8 February 1600 read "in the hall of the Dominican convent of Santa Maria sopra Minerva". The record places it in the **palace of Cardinal Ludovico Madruzzo, near Piazza Navona**. Campa, suggested_ref and coordinates all rewritten; the Minerva echo (his 1576 shelter) was a pleasing but false rhyme and had to go.
3. **First Mass was not in Naples.** The stop read "Naples, ordination and the first Mass … amid the incense and gold of a Neapolitan Dominican church". Treccani DBI: he was consecrated priest after his 24th year and said his first Mass in the Dominican convent church of **San Bartolomeo at Campagna, near Salerno**. Retitled, moved to 40.6666,15.1064, campa rewritten. This adds a genuine new node to the route (the only inland Campanian stop).
4. **Venice extradition month.** Campa said the Senate "yields in February"; it yielded in **January** 1593 (Bruno reached Rome 27 February). Corrected.
5. **Noli duration.** Campa said "a few months"; the deposition says **four months**. Corrected to match the quote.
6. **Helmstedt excommunicator.** Campa asserted Gilbert Voët flatly while citing Omodeo's *"Helmstedt 1589: wer exkommunizierte Giordano Bruno?"* — an article about an attribution error. Treccani does name Voët, so the name stays, but the campa now adds that who pronounced the ban is still argued over. Source line rewritten to cite both.
7. **Bogus source.** One stop cited "MacTutor History of Mathematics, 'Giordano Bruno'" — MacTutor's `/Biographies/Bruno/` is Giuseppe Bruno (1828–1893), a different man. Replaced with Treccani on both stops that carried it.

### Quotes

Six-plus checked against the canon; three replaced, two nulled, one added.

- **Oxford — replaced.** "The Oxonians pronounced I had stolen from the moon and drunk from Ficino's cup…" was sourced to *La Cena de le Ceneri* but is not in Bruno: it is a modern paraphrase of **George Abbot's** hostile 1604 account of the Ficino plagiarism charge. Replaced with the genuine *Cena* verdict on the Oxford doctors: *"Pedantic, obstinate ignorance and presumption, mixed with rustic incivility."* The campa's account of the episode was accurate and stands.
- **De la causa — trimmed to the carried text.** "The universe is then one, infinite, immobile… this is the whole, this is essence, this is life." The trailing clause is not carried by any edition I could reach. Cut to the verified sentence: *"The universe is one, infinite, immobile."*
- **Noli — restored to the deposition's wording.** "In Noli I supported myself for some months…" → *"I went to Noli, on the Genoese riviera, and stayed there four months, teaching grammar to boys and reading the Sphere to certain gentlemen."*
- **Schoppe / the crucifix — tightened.** "He turned away his face, full of scorn…" → *"When the image of our crucified Saviour was shown to him before his death, he thrust it away with a fierce look"*, closer to Schoppe's Latin.
- **Wittenberg valedictory — nulled.** "I render thanks to this most noble nation…" was self-declared "paraphrased from the Latin". I could not reach the *Oratio valedictoria* text to restore canon wording, so quote and quote_source are now null rather than presenting invention as quotation. The campa carries the tribute to Luther unchanged.
- **Venice deposition — nulled.** "I have held and hold the world to be infinite…" was flagged as a "paraphrased summary of his defense", i.e. a composite, not a quotation. Nulled; the campa already narrates the substance.
- **Added.** The Ash Wednesday Supper stop, previously unquoted, now carries the sourced *Cena* line *"Time is the father of truth, its mother is our mind."*
- **Confirmed as carried, unchanged:** the *"Maiori forsan cum timore sententiam in me fertis quam ego accipiam"* retort (Schoppe to Rittershausen, 17 Feb 1600); the 21 December 1599 refusal to retract; *De l'infinito*'s innumerable suns; the Marburg matriculation entry; the memory-not-magic reply to Henri III; the *De umbris idearum* deposition (which is complete, not truncated — an artefact of my first console read).

### Canon fidelity

Nothing mythic was removed. The gag of wood and iron, the pyre, the thrust-away crucifix, the "greater fear" retort, the drowned brother rumour at the Minerva, the scraped-but-legible Erasmus scholia, the three excommunications from three churches — all stand. The only removals are a fabricated quotation, a paraphrase masquerading as a quotation, and three plain errors of fact (age, venue, city). Where the record is genuinely contested — the Helmstedt excommunicator, the Ash Wednesday Supper's exact room, the arrival in Geneva — the uncertainty is now carried in the confidence field or in the prose, not smoothed away.

### Not changed, noted

- Stop count is **45**, the top of the 30–45 target, so no stops were added despite obvious candidates (Savona, Turin, Brescia, Lyon, Tor di Nona). The route is full.
- The Ash Wednesday Supper stays at 1584-02-14 / *traditional* / Whitehall. England was still on the Julian calendar in 1584 and the file declares `gregorian`; the day is conventional either way, and the confidence field already says so.
- `register` uses an em-dash where the Joan file uses a colon. Both forms are in the fleet (13 files and 59 files respectively); left alone as cosmetic.
