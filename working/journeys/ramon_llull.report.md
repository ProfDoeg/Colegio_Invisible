# Ramon Llull — build report

**Sources.** Primary spine is the *Vita Coetanea* (dictated Paris, c. 1311; Bonner translation and the Qui és Ramon Llull project's English summaries at quisestlullus.narpan.net), the only autobiographical account and the source of every verbatim quote in the dataset (the five visions, the three resolves, the sale of his goods, the Randa illumination). Secondary: Stanford Encyclopedia of Philosophy ("Ramon Llull"), Anthony Bonner's *The Art and Logic of Ramon Llull*, Umberto Eco's short essay on the Ars Magna, J.N. Hillgarth's *Ramon Lull and Lullism in Fourteenth-Century France*, IEMed's "Ramon Llull and his Islamic Undertaking" (for the Tunis 1293 disputation and near-execution), erenow.org's Crusades encyclopedia entry and Christianity Today (for the 1307 Bugia imprisonment), the Christian History Institute's narrative piece (for the 1314–15 final mission and stoning), Wikipedia's chronology cross-check, and E. Allison Peers's translation of the *Book of the Lover and the Beloved* for the two closing quotes. Coordinates for Miramar, Puig de Randa/Santuari de Cura, and Port Ayas were separately verified.

**Judgment calls / time-folds.** (1) The five visions of 1263 are compressed to two stops (first and fifth) rather than five, since the canon gives no distinguishing detail between them beyond repetition. (2) Several stretches of Llull's life are documented only by *season* or *year*, never by day — Tunis, Bugia, Cyprus, Port Ayas, the Genoa crises — so those stops carry `"traditional"` confidence with a placeholder month; only the papal bull (17 Oct 1276), the will (26 Apr 1313), and the final Tunis departure (14 Aug 1314, per one source) carry exact dates. (3) The Tunis mission is sometimes dated 1291 (Wikipedia) and sometimes 1293 (Vita Coetanea chronology, IEMed); I followed the Vita Coetanea's own sequence, which places it after the Genoa crisis of 1292. (4) Scholarship treats the Ambrosia de Castello legend and the slave's suicide as later hagiographic accretion rather than the Vita Coetanea's own text — both are marked `"traditional"` and flagged as legend in the campa prose itself, per the register's own logic (canon as lived truth, without erasing that some of it arrived by later retelling). (5) "Bugia" is given as Béjaïa, Algeria throughout; some sources say the final 1315 stoning happened at Tunis rather than Bugia — I followed the majority reading (Bugia, scene of the earlier 1307 imprisonment, making a deliberate return to finish the witness).

**Gaps.** No stop was built for the c. 1304 "second Tunis visit" mentioned vaguely by several sources (letters to the Tunisian king, otherwise undocumented) — folding it in would have added a stop with no real content. The Cyprus/Port Ayas leg (1301–02) is real but thinly attested next to the missions; the campa stays general rather than inventing incident.

**Five richest episodes.** (1) The five visions in the Palma chamber — the interrupted love-song, looked-for on the right, that will not stop returning. (2) The purchase and the death of the Arabic-teaching slave — the one episode where Llull's own violence, not the world's, breaks something irreparably. (3) The Randa illumination — the instant the whole Art arrives at once, "form and method," after nine years of preparation. (4) The Tunis 1293 wager to the doctors of the law — reason staked nakedly against a death sentence, with no army behind it. (5) The final Bugia stoning and the death at sea in sight of Palma — the Book of the Lover and the Beloved's own dialogue of departure ("I go to my Beloved") standing as the epitaph he had already written decades earlier without knowing it.

**Connections to the atlas.** Essay 190 (al-Andalus and Reconquista) already names Llull as the Christian philosopher "heavily influenced by Islamic thought," transposing Arabic dialectic into a Christian combinatoric art — this journey is that essay's biography. Essay 209 (thread and wheel) supplies the deeper resonance: the Ars Magna's rotating letter-wheels sit in the same lineage of wheel-and-cord technologies as Indra's net and the spinning Fates, a mechanical loom for arguments rather than yarn. `ibn_arabi.journey.json` shares the Andalusi-Almohad milieu (Murcia/Seville) one generation earlier, though the two never meet on the page. `kircher.journey.json` is the direct heir — his *Ars Magna Sciendi* is explicitly a 17th-century refit of Llull's wheels — and a forward pin from this file into his would be natural. Giordano Bruno (declared Lullist, wrote his own *De Lulliana Ars*) and Roger Bacon (contemporary Franciscan combinatorics, also petitioning popes for language schools) are edges named by the brief but not yet built as journeys; when they are, Miramar (1276) and the Paris stays (1287–89, 1309–11) are the natural shared pins.

---

## Verification pass — 2026-07-24

`json_check.py`: **OK**, no WARN lines. 9 segments, **45 stops** (was 43), 7 quoted. Schema matches `joan_of_arc.journey.json` exactly (same top-level, segment, and stop keys). Dates ascend globally as well as within each segment; every campa now falls inside 60–110 words, present tense.

Authorities used for this pass: Stanford Encyclopedia of Philosophy, "Ramon Llull"; the *Qui és Ramon Llull* project (quisestlullus.narpan.net) — its **Chronology** and **Conversion** pages, which paraphrase the *Vita coaetanea* closely; Wikipedia, "Ramon Llull" (which quotes Bonner 1985 verbatim); E. Allison Peers's 1923 translation of the *Book of the Lover and the Beloved* (archive.org full text); OpenStreetMap/Nominatim for coordinates.

### Canon errors corrected

1. **Ramon de Penyafort's counsel was wrong.** The build had him warning Llull off "a rash first plan to travel at once among the Saracens." The *Vita coaetanea* has Llull proposing to go and **study at Paris**, and Penyafort persuading him to return to Majorca instead. Stop rewritten and retitled *"Barcelona and Palma, Penyafort's counsel and the purchase of the Moorish slave."*
2. **The pilgrimages were in the wrong order.** The *Vita* names **Rocamadour first, then Santiago de Compostela**. The two stops were swapped (Rocamadour now 1264-01, Compostela 1264-06) and their campa re-linked accordingly.
3. **The renunciation had no date and the wrong trigger.** The canon places the decision to sell his goods **three months after the visions, on the feast of Saint Francis**, after hearing a bishop preach on Francis's abandonment of everything. Stop redated **1263-10-04** and retitled *"Palma, the feast of Saint Francis, the goods sold."* The coarse habit, which the *Vita* has him putting on only **after** the pilgrimages and on returning to Majorca, was moved out of this stop into the 1265 one.
4. **The slave's death was dated three years too early.** The chronology places it in **1274**, immediately before the ascent of Randa — which is what the campa's own "grieved and shaken" transition requires. Slave's death 1272 → **1274-01**; Randa 1274-01 → **1274-06**; La Real 1274-04 → **1274-09**. The *Book of Contemplation* stop moved 1268 → **1271** (the 1271–74 writing window).
5. **Clement V's coronation was mis-set in 1309.** The 1309 Montpellier stop had Llull following the "new pope" to Lyon for a coronation that happened in **1305**; its `suggested_refs` even carried the correct 1305 date, contradicting its own campa. Rewritten around the **general council Clement had summoned and twice postponed** — which is what the 1309 memoranda were actually aimed at.
6. **The Council of Vienne stop was dated June 1311 and called Llull eighty-one.** Redated to the council's documented opening, **1311-10-16**; born 1232, he was **seventy-nine**. Same fix logic applied at Cyprus 1301 ("Past seventy" → "Nearing seventy," he was 69).
7. **The Paris 1310 endorsement came from the wrong faculty.** It was the **masters of arts and medicine** (February 1310), with the **chancellor's** certification following in 1311 — not "masters of medicine and theology." Both now named. The stop was also called "the fourth stay" while the 1298 stop is called "the second," an internal contradiction (SEP counts three visits, the narpan chronology four); retitled neutrally *"Paris, the last stay."*
8. **The 1307 disputation title was garbled.** Standard Latin is ***Disputatio Raymundi christiani et Homeri saraceni***; the Muslim interlocutor is the Latin "Homer." Corrected in both campa and refs.
9. **Llull's birth was three years after the conquest, not four** (Madina Mayurqa fell 31 December 1229; born 1232).

### The Bugia/Tunis problem, resolved by confidence rather than deletion

The martyr's death at **Bugia** stays — it is what the cult keeps, and the register does not debunk. But Wikipedia's chronology is explicit that **Llull's last dated work is Tunis, December 1315**, and both SEP and the narpan chronology place the final mission at Tunis throughout 1314–15. The build had him leaving Tunis for Bugia in January 1315 and being stoned there in June, which his own dated pages contradict.

Repaired as follows, without touching the stoning itself:
- the "secret strengthening of the converts" stop **moved from Bugia to Tunis** (1315-01), where the documents put him;
- a new stop added — ***"Tunis, the last book, December 1315"*** (`attested`) — the final page of the corpus, dated by Llull's own hand;
- the stoning **moved to 1316-01**, at Bugia, `traditional`, its campa opening "The tradition of his cult carries him back to Bugia for the end." Its `sources` now record that the accounts name Bougie **or** Tunis and that the cult keeps Bougie. The stones, the mob, the Genoese rescue, the death at sea within sight of the island: all intact.

### Quotes (all 7 checked; 3 were not carried as printed)

| stop | verdict |
|---|---|
| first vision, "he looked to his right and saw our Lord Jesus Christ on the Cross, as if suspended in mid-air" | **verbatim Bonner 1985, pp. 10–11** — confirmed |
| three resolves, "to give up his soul for the sake of God's love and honor…" | **verbatim Bonner** — confirmed |
| "to sell his goods, leaving the amount necessary for the upkeep of his family…" | consistent with Bonner ch. 2; kept |
| Randa, "the Lord suddenly illuminated his mind, giving him the form and method…" | consistent with Bonner ch. 4; kept |
| **"He who loves not lives not."** | **not carried.** No such line in Peers 1923. The nearest are verse 15 ("to whom not to love is to sin") and verse 62 ("to cease to love is death and love is life"). **Replaced** with Peers verse 1, verified verbatim: *"The Lover asked his Beloved if there remained in Him anything still to be loved."* |
| the paths of the lover ("…filled with worries, sighs, and tears") | **paraphrase, not Peers.** **Restored** to verse 2 verbatim: *"Long and perilous are the paths by which the Lover seeks his Beloved. They are peopled by cares, sighs and tears. They are lit up by love."* |
| the death-at-sea epitaph ("Whither goest thou?… I go to my Beloved…") | **garbled** — it collapsed the exchange and reversed Peers's deliberate paradox. **Restored** to verse 24 verbatim, including the answer *"I come from my Beloved"* to *"Whither goest thou?"* |

All three restored quotes now carry `verse N` and the 1923 edition in `quote_source`.

### Coordinates (22 spot-checked against Nominatim; 4 moved)

| site | was | now | note |
|---|---|---|---|
| Santa Eulàlia, Palma | 39.5713, 2.6493 | **39.5695, 2.6512** | ~250 m off |
| Monestir de la Real | 39.5814, 2.6187 | **39.6023, 2.6417** | ~3 km off, wrong side of the city |
| Miramar, Valldemossa | 39.7238, 2.6289 | **39.7391, 2.6175** | ~1.9 km off |
| Sant Francesc, Palma | 39.5722, 2.6551 | **39.5686, 2.6525** | ~450 m off; now on Plaça de Sant Francesc |
| Famagusta | 35.1264, 33.9391 | 35.1205, 33.9388 | tightened |
| Vienne | 45.5236, 4.8782 | 45.5252, 4.8748 | tightened |

Verified correct as built and left alone: Palma centre, Palau de l'Almudaina (39.5680, 2.6472), Santuari de Cura on Puig de Randa (Nominatim 39.5276, 2.9260 vs. dataset 39.5277, 2.9258 — an excellent hit), Santiago, Rocamadour, Montpellier, Rome, Paris/Sorbonne, Genoa, Naples, Barcelona, Tunis, Yumurtalık/Port Ayas (36.7676, 35.7916), Béjaïa, Pisa, Messina.

### Stop added beyond the two above

**"Majorca, the Cant de Ramon, the old man's own accounting" (1300).** The build had a silent year between the Barcelona license (1299) and Cyprus (1301); the chronology puts an extended Majorca stay there, and it produced the *Cant de Ramon* — fourteen stanzas of six eight-syllable lines walking his own life past the reader, the repudiated troubadour craft taken up again, complaining of how little the labour has come to and asking God for "intelligent companions." Too good an episode to leave out of a life this long.

### Correction to this report's own earlier claims

Judgment call (4) above stated that scholarship treats **the slave's suicide** as later hagiographic accretion rather than the *Vita coaetanea*'s own text. That is wrong: the blasphemy, the blow, the knife, the cell and the belt are narrated in the *Vita coaetanea* itself (ch. 3), which is why the stop's `sources` cite it directly. The stop's `suggested_refs` line, which called it "later Lullian hagiography's retelling," has been corrected to name the *Vita* as the source. Only the **Ambrosia de Castello** legend is genuinely later accretion, and it remains marked as such in the campa's own wording ("named in later memory").

### Left standing, on purpose

- **The Genoa crisis at 1292-06.** SEP dates the Tunisia attempt "spring 1292 to September 1293"; the narpan chronology compresses the whole crisis into 1293. `traditional` confidence covers the disagreement; the sequence Genoa-terror → secret sailing → Tunis is the *Vita*'s own and is preserved.
- **The three resolves as Bonner gives them** (life, conversion of the Saracens, the best book), rather than the narpan variant which substitutes the language-monasteries for the first. Bonner's is the verbatim quoted text.
- **Ambrosia de Castello, the horse in the nave, the five visions, the illumination on Randa, the martyr's stoning.** All theophany and legend intact, carried at `traditional`.
