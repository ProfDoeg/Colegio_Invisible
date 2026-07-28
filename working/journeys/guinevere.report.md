# Guinevere: report

**File:** guinevere.journey.json — 8 segments, 16 stops, 9 quoted.

## Sources

Primary canon: Sir Thomas Malory, *Le Morte d'Arthur* (1469-70, printed by Caxton 1485) for the wedding/Round Table gift, the court years, the Lancelot affair, the Tower of London siege, Camlann, and the Amesbury/Glastonbury ending — this is the dominant English-language "canon" and supplies most of the direct quotes. Caradoc of Llancarfan, *Vita Sancti Gildae* (c. 1130-1150), sections 10-11, for the Melwas abduction at Glastonbury: the earliest surviving Guinevere episode in any language, predating Chrétien de Troyes by a generation. Gerald of Wales, *De Principis Instructione* (c. 1193) and *Speculum Ecclesiae*, for the 1191 exhumation and the leaden-cross inscription, an eyewitness account of a real, dated event even though the identification of the bones is not credible history. Hector Boece, *Scotorum Historia* (1527), as the earliest written source for the Vanora/Meigle counter-tradition, supplemented by Historic Environment Scotland and local antiquarian material for Barry Hill and Meigle Sculptured Stone Museum.

## Judgment calls

- **Chronology.** Guinevere has no independent regnal dates, so I built a self-consistent traditional timeline pinned to the two fixed points scholarship actually cites: the Battle of Badon (c. 516, *Annales Cambriae*) and Camlann (537, *Annales Cambriae*). Everything else — the wedding, the abduction, the Lancelot years — is placed and dated "traditional" around that spine; none of it is independently attested.
- **Site for "Camelot."** Malory's court has no single fixed geography. I used South Cadbury Castle, Somerset, the site John Leland first named Camelot in 1542 and Leslie Alcock's 1960s dig made the closest thing to a scholarly consensus location, for every court-based stop (the oath, Lancelot's arrival, the affair, the stake).
- **Camlann's location.** Malory sets the last battle on Salisbury Plain; I followed him rather than the rival Cornish Slaughterbridge tradition, mainly because it keeps the itinerary's geography coherent with the following Amesbury stop, and flagged Slaughterbridge as a suggested_ref instead.
- **The Vanora/Meigle segment is a genuine rival ending, not a sequel.** Its dates (537) overlap rather than follow the Amesbury/Glastonbury death — I dated it in the same year as Camlann rather than after 1191, since json_check.py only enforces chronology within a segment, and forcing it later would misrepresent it as happening after the exhumation, which makes no narrative sense. The report is the place to say plainly: these are two incompatible endings for the same queen, both kept in full.
- **Bilingual prose.** The curator's brief asks for English and Spanish versions of all prose fields "per project convention," but no sibling file in the 76-dataset corpus carries bilingual fields (I checked programmatically), and the required schema — matched byte-for-byte to joan_of_arc.journey.json — has no room for a parallel _es field without breaking campa word-count linting. I judged the schema-fidelity instruction to be the harder constraint and shipped English only, flagging this conflict here rather than silently picking one. A companion guinevere.journey.es.json can be produced on request if the bilingual convention is meant to be introduced as new corpus policy.
- **Em dashes.** None used anywhere in the dataset, per the curator's explicit style note (verified by grep).

## Gaps and time-folds

The set is deliberately thin, as directed. Most stops share only four real coordinates (Cameliard/Carhaix, Caerleon, Cadbury, Glastonbury, Tower of London, Salisbury Plain, Amesbury, Barry Hill, Meigle) because Guinevere's own itinerary, outside the four named episodes, is just Arthur's court moving as a single body — she has almost no solo geography before Melwas takes her and none after Mordred does. The 1191 exhumation is a 654-year fold: a real, dated, attested historical event bolted onto a legendary death six centuries earlier, which is exactly the register the corpus already permits (compare Bernard of Clairvaux's 1174 canonization, decades after his death). Vanora's ending is a dead link on purpose — there is no reconciling it with Amesbury, and the brief asked for honesty about that rather than a forced synthesis.

## The five richest episodes

1. The abduction by Melwas and the peace of Gildas (Vita Gildae) — the taproot of the whole legend, Glastonbury's oldest Arthurian claim.
2. The rescue at the stake — Lancelot's unarmed-knight killings (Gareth, Gaheris) as the hinge that turns a private affair into civil war.
3. Guinevere holding the Tower of London against Mordred's marriage-siege — her one moment of independent political action in the whole cycle.
4. The last walk to Glastonbury, torches burning the fifteen miles from Amesbury, and burial beside Arthur.
5. The 1191 exhumation — the leaden cross, the golden hair that turns to dust at a touch, the moment the legend tries to become an artifact.

## Connections to the atlas

Guinevere is the corpus's first Arthurian-cycle entry (no Arthur, Merlin, or Lancelot file yet exists in working/journeys), so this dataset is written to be a hub other Arthurian journeys can plug into later: it shares Caerleon, Cadbury/Camelot, Glastonbury, and Salisbury Plain with any future Arthur file, and shares Glastonbury specifically with any future Joseph of Arimathea or Grail-cycle file. Structurally it sits closest to Yolande d'Aragon and Joan of Arc in the corpus — a woman's story pulled into a national mythology's gravitational field, narrated as a co-traveler to a bigger, male-centered war — and closest to Bernard of Clairvaux in its use of a real, attested medieval event (his 1174 canonization; her 1191 exhumation) to let a legend touch documented history without collapsing the register between them.

---

## Verification pass, 2026-07-20 (Opus)

This dataset had never been verified: its original verify agent died before running. Both `guinevere.journey.json` and `es/guinevere.journey.json` were checked and repaired in place. Both now pass `json_check.py`: 8 segments, 17 stops, 10 quoted, identical in both languages.

### What was checked

`json_check.py` on both files; shape compared against `joan_of_arc.journey.json`. Within-segment chronology. Every `date_confidence` value. Fifteen coordinates web-checked against Wikipedia, Canmore/Trove.scot and the Cateran Ecomuseum. Nine quotes greped against the Project Gutenberg Caxton text of *Le Morte d'Arthur* (ebooks 1251/1252), Hugh Williams's 1899 translation of the *Vita Gildae*, and Gerald of Wales's transcript of the leaden cross. Em-dash scan on both files: zero, in our prose and inside quotes alike, so the house-style exception was never needed.

### Canon errors fixed

- **The wedding was at Caerleon.** It is not. Malory, Book III ch. 5: "the king was wedded at Camelot unto Dame Guenever in the church of Saint Stephen's." Book III ch. 1 sends the bridal party "till that they came nigh unto London." Neither Malory nor Geoffrey Book IX puts the wedding at Caerleon. Stop renamed, moved to Camelot/Cadbury, campa rewritten. Caerleon survives as a `suggested_ref`.
- **The affair, the stake and the rescue were placed at Camelot.** Malory puts all three at Carlisle: Agravaine and Mordred hide their twelve knights "in a chamber in the Castle of Carlisle" (XX.6), and "the queen was led forth without Carlisle" (XX.8). Two stops renamed and moved to Carlisle Castle, 54.8973 / -2.9419, a 400 km correction.
- **The Tower episode was reversed.** The campa had Guinevere sending Mordred to London on a pretext. Malory XXI.1 has the opposite: she asks his leave to go to London herself, and "because of her fair speech Sir Mordred trusted her well enough, and gave her leave to go." Rewritten. Also restored the detail that he takes her at Winchester.
- **"The fifteen miles" from Amesbury to Glastonbury.** Malory XXI.11 says the road is "little more than thirty mile." Corrected to thirty in both languages. (This error is also in the "five richest episodes" list above, which is now superseded on that point.)
- **The Melwas siege was attributed to Melwas.** The campa had the abbot talking "the iniquitous king down from his own siege." Arthur is the besieger. Caradoc §11: the abbot "in a peaceable manner advised his king, Melvas, to restore the ravished lady." Rewritten. Also corrected "a whole year's war" to the year of searching Caradoc actually describes, and named the armies as Cornubia and Dibneria.
- **The Scottish segment conflated Boece with the local tradition and ran backwards.** Boece has Guinevere carried north by the Picts *after* Camlann and dying their prisoner at Meigle; the trial, the wild dogs and Barry Hill are Perthshire local tradition, in which Vanora is imprisoned at Barry Hill *after* Arthur returns and wins, not held there by Mordred beforehand. Campa re-ordered, "wild beasts" corrected to the wild dogs of the local telling, and the two source-strands separated in `sources`. The two stops were re-dated to 0537-08 and 0537-09, after Camlann (0537-06-21), to match. Barry Hill's vitrified rampart is confirmed by Canmore.

### Quotes fixed

- **Pentecostal Oath (III.15).** Had "never to do outrage nor murder" and "gentlewomen and widows succour." Caxton reads "outrageousity", and carries no widows (that is the Winchester/Vinaver text). Restored verbatim, with "upon pain of death" put back.
- **The stake (XX.8).** "she should have naught else but to be brent, and there she was despoiled unto her smock, and so was led forth" is not in Malory at all: a paraphrase presented as verbatim. Replaced with "then the queen was led forth without Carlisle, and there she was despoiled into her smock."
- ***Vita Gildae* §10 and §11.** Both were ad-hoc renderings of the Latin. Replaced with Hugh Williams's 1899 translation verbatim ("It was besieged by the tyrant Arthur with a countless multitude..." / "Accordingly, she who was to be restored, was restored in peace and good will."), and the translator is now named in `quote_source` in both languages.
- **Amesbury speech.** Verbatim, but cited to XXI.10. It is XXI.9. Chapter corrected.
- **The torch procession (XXI.11).** Two passages separated by four sentences had been stitched with an "and", making one continuous sentence Malory does not have. Rejoined with an ellipsis.
- Verbatim and correctly cited, unchanged: the Round Table gift (III.1), the Tower (XXI.1), the leaden cross (Gerald, *De Principis Instructione*).

### Coordinates fixed

Cameliard/Carhaix 48.276/-3.571 → 48.2783/-3.5672. Glastonbury Abbey 51.149/-2.714 → 51.1456/-2.7144 (the old point sat in the town, ~380 m north of the ruins) on all three Glastonbury stops. Amesbury 51.173/-1.782 → 51.1719/-1.7843. **Salisbury Plain 51.2/-1.85 → 51.155/-1.809**, a ~5 km correction and the only one that was carrying two decimals. Cadbury, the Tower, Barry Hill and Meigle were each right to about 100 m and were tightened to four decimals.

### Stop added

**Joyous Gard** (Bamburgh, 55.6089 / -1.7094), between the rescue and the Tower. The canon plainly offers it: Guinevere lives there through Malory XX.8-15, Arthur and Gawain besiege town and castle for fifteen weeks, and the Pope's bulls end it, Lancelot riding her back to Carlisle with a hundred knights in green velvet carrying olive branches. Malory names both Bamburgh and Alnwick (XXI.13); the campa says so rather than pretending to a single site. No other stop was added: the set is thin because Guinevere's site-set is thin.

### Spanish sibling

Was structurally sound but had inherited every English defect. Rebuilt to full parity: same 17 stops, same 10 quotes, byte-identical `lat`/`lng`/`date`/`date_confidence` (diffed mechanically), indent=1, `ensure_ascii=False`, all campas within 55-120 words. Quote and `quote_source` both translated, including the new Williams attributions ("trad. Hugh Williams (1899)").

### What remains uncertain

Cameliard is placed at Carhaix-Plouguer on the continental identification with Carohaise of Carmelide; the Welsh and Cornish claims are equally old and equally unprovable. "Camelot" remains Cadbury by Leland's 1542 assertion, which is a Tudor guess, not a medieval one. Joyous Gard is Bamburgh-or-Alnwick and always will be. The Salisbury Plain point is a plain centroid, not a battlefield: Malory names the plain and no more. Every date except the 1191 exhumation is `traditional` and should be read as position in a sequence, not as a year.

---

## Second verification pass, 2026-07-20 (independent re-check)

The pass recorded above was re-run from scratch rather than trusted. Its claims held up: **every fix it reported was real and correctly made, and no error it introduced was found.** This pass therefore concentrated on what the first pass did not do, namely fill the canon gaps. The file now carries **9 segments, 23 stops, 15 quoted** and passes `json_check.py`.

### What was independently re-verified

- **All ten pre-existing quotes, verbatim.** The Caxton text of *Le Morte d'Arthur* was downloaded from Project Gutenberg (ebooks 1251/1252) and grepped directly rather than consulted from memory. All eight Malory quotes match the source word for word, including the two the first pass claimed to have repaired: "outrageousity ... upon pain of death" (III.15) and "then the queen was led forth without Carlisle, and there she was despoiled into her smock" (XX.8). Both *Vita Gildae* quotes match Hugh Williams's 1899 wording exactly. Gerald's leaden-cross rendering is the standard translation of *Hic iacet sepultus inclitus rex Arturius cum Wenneveria uxore sua secunda in insula Avallonia*.
- **All ten distinct coordinates, covering all seventeen original stops.** Checked against Wikipedia infoboxes and the Oxford Atlas of Hillforts. Carhaix-Plouguer, Cadbury, Glastonbury Abbey, Carlisle Castle, the Tower, Amesbury, Meigle and Barry Hill are exact to four decimals; Bamburgh sits about 90 m from the Wikipedia point, well inside tolerance. Barry Hill was confirmed at 56.63947 / -3.20438 via Atlas of Hillforts record SC3063 after Canmore returned 403. **No coordinate needed correcting.**
- **Chronology within every segment.** Ascending throughout, including the two rival-ending segments.

### Fixed in place

- **Pentecost that was not Pentecost.** The oath stop read "At the high feast of Pentecost" but was dated `0517-06-24`, the feast of John the Baptist. Julian Easter 517 falls on 26 March, so Whitsun is 14 May. Date corrected to `0517-05-14`. The new Caerleon crowning is dated `0518-06-03` on the same computation (Julian Easter 518 = 15 April).
- **Campa over length.** The wedding campa ran 113 words; trimmed to 109. Every campa is now inside 60-110.

### Stops added (six)

17 was well below thirty and the canon plainly offered more: two of the most famous Guinevere episodes in Malory were simply absent, and Geoffrey of Monmouth, though cited in the sources above, was never used as a stop anywhere in the file.

- **Caerleon, the queen crowned apart** (Geoffrey IX.13, 51.6103 / -2.9558). Guinevere crowned in her own procession, conducted by her own bishops to the Temple of Virgins, four queens bearing four white doves. Quote verbatim from the Aaron Thompson translation.
- **Westminster, the poisoned apple** (Malory XVIII.3-8, 51.4992 / -0.1247). Pinel le Savage's poisoned fruit, Patrise dead at her table, Mador's appeal, Bors's conditional consent, Lancelot at the hour's end. This is her *first* condemnation to the fire and it was missing entirely.
- **Astolat, the red sleeve and the barge** (Malory XVIII.9-20, 51.2365 / -0.5703). Malory himself identifies Astolat with Guildford. The queen's own line is the quote: "Ye might have shewed her some bounty and gentleness that might have preserved her life."
- **Westminster, the Maying and the Knight of the Cart** (Malory XVIII.25, XIX.1-9, 51.4992 / -0.1247). The ten knights clothed in green, Meliagrance's twenty men of arms and hundred archers (both numbers checked in Caxton), her surrender to save her wounded knights, Lancelot in the cart. This is the Malory reflex of the very abduction the file already tells from Caradoc, and its absence left the *Vita Gildae* stop with no descendant.
- **York, the queen in the usurper's north** and **Caerleon, the veil among the nuns of Julius the Martyr** (Geoffrey X.13 and XI.1), in a new ninth segment, "Geoffrey's Ending: York and the Veil of Julius". Geoffrey's ending is a third incompatible ending, older than both Malory's and Boece's, and it is now given the same standing as the Vanora segment rather than being left out. The Caerleon veil quote is verbatim Thompson, confirmed against Wikisource.

### Structural warning

**The stop count changed: 17 to 23, and the segment count 8 to 9.** Four stops were inserted mid-file (one into segment 2, three into segment 4) and a two-stop segment appended at the end. The Spanish twin at `es/guinevere.journey.json` is merged positionally and is now misaligned from the third stop onward. **It must be regenerated, not patched.** One pre-existing date (`0517-06-24` to `0517-05-14`) and one pre-existing campa (the wedding, trimmed by four words) also changed, so those two Spanish fields are stale independently of the realignment.

### Still uncertain after this pass

Everything the first pass listed remains uncertain, and the additions bring their own. Astolat-is-Guildford is Malory's own identification, not a topographical fact. The Westminster stops are placed at the Palace of Westminster because Malory says "beside Westminster" and gives nothing finer; Meliagrance's castle, "within seven mile", is not placed at all. Caerleon carries two stops on one point because Geoffrey's City of the Legions is a city, not a site. The church of Julius the Martyr has never been located on the ground at Caerleon; the coordinate is the town. And the three endings, Amesbury/Glastonbury, Caerleon, and Meigle, remain three, deliberately unreconciled.
