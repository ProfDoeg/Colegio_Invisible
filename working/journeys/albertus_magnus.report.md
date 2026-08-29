# Albertus Magnus (Albert of Lauingen, c. 1200-1280): research report

*Compiled 2026-08-29 for `albertus_magnus.journey.json`. **[A]** = attested, source named. **[R]** = reconstruction, tradition, hagiography, or a claim this pass could not confirm against a fetched source. Disagreements are printed and left standing. SEP = Stanford Encyclopedia of Philosophy, "Albert the Great"; NA = Catholic Encyclopedia (1913), s.v. "Albertus Magnus"; deWP / enWP / itWP / frWP = the Wikipedias.*

Two speeds run through this life. The opening stops are almost entirely [R]; the birth year cannot be narrowed inside a thirteen-year window. From 1245 to 1280 nearly every stop carries a year from two or more independent reference works. The most productive discipline here was checking what the pool *attributed* to a source against the source itself: roughly a third of its attributions were wrong the same way, a real fact hung on SEP, which does not contain it.

---

## 1. Birth and formation (c. 1200 - 1223)

- **Lauingen an der Donau** [A for the place by inference, R for the year]. The place rests on his own byname, *Albertus de Lauingen*; no birth record exists, and enWP lists him as a native of the town without independent proof. The father's identification with the Bollstädt line is late and is not asserted.
- **The year is not recoverable.** The pool submitted 1200 as [A]; too strong. Four positions circulate: "around 1200 or somewhat earlier" (Weisheipl, in deWP); "between 1193 and 1206" (itWP); 1205 or 1206 (NA); "his date of birth is not known" (Linda Hall Library). File uses `1200-01-01`. *Not adjudicated.*
- **Padua, faculty of arts** [R]. SEP says only that he "likely studied at the Faculty of Arts of the University of Padua." **The pool's 1220 is unsupported by anything reached** and was dropped; deWP places him at Padua in 1223. File uses `1222-01-01`, read as "early 1220s."
- **Entry into the Order of Preachers, 1223** [A]. SEP, "became a Dominican in 1223"; deWP and NA agree, and the 1229 in enWP's infobox is a minority reading. The pool's "probably Padua or Cologne" is refinable: entry at Padua, novitiate at Cologne (deWP). That the habit came from **Jordan of Saxony** rests on one reached source, a Vatican general audience of 24 March 2010, a devotional text and not a record.
- **The Marian apparition** [R]. Dominican hagiography: the Virgin promises the young friar learning, forewarning it will be withdrawn before death so he should not die a philosopher. **The pool attributed this to SEP; that entry does not contain it, and neither does NA**, whose "Some time after 1278... he suffered a lapse of memory" is ordinary decline with no prophecy attached. Legend kept, tagged [R], false citation removed. No early hagiographic carrier identified: gap.

## 2. The lector's circuit (1230s)

- **De natura boni** [A], but not as framed. SEP: "His first published work, *On the Nature of the Good* (*De natura boni*), dates from the first half of the 1230s." Neither dated 1233 nor called "first securely datable" there; both were pool additions.
- **Four convents, not five** [A]. SEP: he "lectured in convents in Hildesheim, Freiburg im Breisgau, Regensburg and Strasbourg." **Cologne, which the pool inserted as a fifth, belongs to a different phase**; enWP has him "continued studies in Cologne before lecturing at" the four. The file keeps it out of the circuit.
- **Only Freiburg is dated** [A]: deWP gives him the office of Lesemeister there *von 1236 bis 1238*. The pool's 1235 anchor is arbitrary, dropped. **The order of the four lectorships is not recoverable**; 1234, 1236, 1238, 1239 in the file are sequencing devices and each `date_confidence` says so. That his natural-history material dates to these years is inference from the content of *De vegetabilibus* and *De animalibus*. Flagged.

## 3. Paris (early 1240s - 1248)

- **Sent to Paris** [A for the fact, R for the year]. SEP: "In the early 1240s, he was sent to the University of Paris." **No source names a year of arrival; the pool's 1241 is false precision**, kept only as a labelled sequencing date. **Open disagreement**: NA has him "ordered to repair to Paris" in 1245, for the mastership. Reconcilable if NA compresses arrival and promotion, but nothing reached says so.
- **Mastership, 1245** [A]. SEP and NA agree, as does the "first German Dominican at a Paris chair" formula; the circle of Guerric of Saint-Quentin is from enWP.
- **Thomas Aquinas from 1245** [A], and the atlas agrees with itself: `thomas_aquinas.journey.json` independently places Thomas's arrival at Saint-Jacques the same year and names Albert directly in its stop "Under Albert: Paris and Cologne." The strongest two-file interlock here.
- **The "dumb ox" saying** [R]. Traces to William of Tocco's *Ystoria sancti Thomae de Aquino*, early fourteenth century. **Tocco's Latin could not be fetched**; only a modern English rendering via enWP on Aquinas (citing Eleonore Stump 2003), which does not quote Tocco. `thomas_aquinas.journey.json` already carries it as legend, so the two files agree.
- **Regency to 1248** [A], SEP. That the 1248 general chapter resolved to found four new *studia generalia* is standard but **was not verified against a chapter act**.

## 4. Cologne and the order's business (1248 - 1259)

- **Founding the studium generale, 1248** [A]. SEP and NA; Thomas goes with him, corroborated by `thomas_aquinas.journey.json` ("Cologne, the new studium generale," 1248-1254). The file states explicitly that this is **not** the University of Cologne, founded 1388. **Physica, c. 1251-1252** [A], per SEP.
- **Provincial of Teutonia, 1254** [A], **elected at Worms, not Cologne**, per deWP; the pool's geography lens put it at Cologne. Corrected.
- **The papal curia, 1256** [A for Albert; companions dropped]. NA: "He journeyed to Rome in 1256," serving as Master of the Sacred Palace (also itWP). **The pool placed Bonaventure and Humbert of Romans there with him; nothing consulted supports it.** enWP's Anagni article names neither, and its William of Saint-Amour article names only Aquinas and Albert. Removed rather than hedged, and the removal stated in `date_confidence`.
- **Condemnation of *De periculis novissimorum temporum*, 5 October 1256** [A]. NA gives the full date, enWP's Anagni article corroborates verbatim. **Resignation of the provincialate, 1257** [A], NA; month undocumented, June set as chapter season.
- **Grosser Schied, 1258** [A], the arbitration between Archbishop Konrad von Hochstaden and the citizens of Cologne. **The specialist source named in the dossier, Groten 2011, was not fetched**; this rests on encyclopedia treatments. Pinned at the cathedral, distinct from the convent pin. *Interlock:* `thomas_aquinas.journey.json` dates Thomas's Cologne ordination "probably 1250" (NA) **under this same archbishop**, so two atlas files touch him eight years apart, once as ordaining prelate and once as a party in arbitration. The Cologne-lectures stop cites this across.
- **Valenciennes general chapter, 1259** [A], enWP, whose Valenciennes article confirms the chapter and Aquinas's presence. The five-man commission (Albert, Aquinas, Bonushomo Britto, Florentius, Peter of Tarentaise) is given only by the Albert article; no chapter act reached, no building identified. Gap.

## 5. Regensburg (1260 - 1262)

- **Appointed bishop, 1260** [A]; **the day 5 January is [R]**, dossier-only. NA gives the year, SEP corroborates, and NA reports that the appointment ran against Dominican preference and his own inclination. No individual's plea is attested, so the file names nobody.
- **"Bundschuh"** [R], the hobnailed-shoe nickname for crossing the diocese on foot. **Could not be confirmed against any fetched source**, including the enWP article the dossier cites for it. Carried as unverified tradition; the same tradition supplies the "refused horses" detail on the Worms stop.
- **The release: three errors in the pool, all corrected.** (1) **Wrong city**: the pool said Viterbo; deWP puts Albert at Urban IV's court at **Orvieto**, which Urban held alongside Viterbo. (2) **Wrong year**: the pool said 1261; four sources say 1262, SEP, NA, itWP, and deWP with the month, *im Februar 1262*. (3) **Impossible as submitted**: the pool had him departing December 1260 to seek release *from Urban IV*, who was not elected until **29 August 1261**. Smaller: the Viterbo palace the pool named was completed only "around 1266" (enWP).

## 6. Preaching, teaching, the last Cologne years (1263 - 1280)

- **Crusade preaching, 1263** [A]. enWP: Urban IV "requested he preach the Eighth Crusade in German-speaking countries." **Not one preaching station is named anywhere consulted**: twenty months of documented travel with zero recoverable itinerary. The file marks its 50.0 / 9.0 coordinate as a centroid that is not a place.
- **Würzburg and Strasbourg, 1264-1269** [A as a pair, R as to division]. SEP gives them together; how the five years split is not documented anywhere reached. **Return to Cologne, c. 1269**, with deWP's qualifier *um*, "around." **The pool added that John of Vercelli recalled him as "lector emeritus." Neither the man nor the title appears in SEP, NA, or deWP.** Both dropped.
- **Memoir sent to Paris, 1270** [A]. NA: "In the year 1270 he sent a memoir to Paris." **Identifying it with the unity-of-the-intellect controversy is my inference** from SEP's account of his continuing engagement with those disputes; no single source joins the two. Flagged.
- **Death of Thomas Aquinas, 7 March 1274** [A]; **the weeping** [R], later devotion with no contemporary witness. Under the house rule Fossanova is Thomas's stop, so the file places the news at Albert's Cologne pin and says so.
- **Second Council of Lyons, 1274** [A], better documented than the pool allowed. Its hedge, "less documented than devotional accounts claim," does not survive deWP, which records a specific act: he spoke for the recognition of **Rudolf of Habsburg** as German king. NA lists the council among his activities; the Vatican audience states his participation flatly. Retagged [A] with that intervention.
- **The 1277 Paris journey: split, and printed split.** NA asserts it as fact, "1277: Journeyed to Paris to defend St. Thomas's writings," and itWP agrees. **SEP is silent**, and **the pool cited SEP as the source of the *doubt*, which it is not.** Modern biographers are generally reported as treating it as unconfirmed, though I reached no named biographer saying so. Tempier's condemnation of 219 propositions, 7 March 1277, is [A]. The journey is [R]. *Not adjudicated.*
- **The testament: a real year conflict, and the pool contradicted itself.** NA puts it in **1278**, deWP *aus dem Jahr 1279*, and the pool's own two lenses shipped the two different years. The file adopts January 1279 and prints 1278 as the competing reading. That the bequest funded a choir exceeding mendicant building norms is dossier-only and **was not checked against a transcription of the will**.
- **Decline of memory from c. 1278** [A as decline, R as prophecy]. enWP and NA both present it as ordinary aging.
- **Death at Cologne, 15 November 1280** [A]. NA, corroborated by SEP and enWP. **A naming discrepancy worth keeping**: the Vatican audience specifies "his cell at the convent of the Holy Cross," more precise than the plain "Dominican convent" used elsewhere. Recorded, not resolved. No cause of death named anywhere. **Burial in the choir** [A], NA, but **the funeral date is not recorded**; the file's 17 November is a sequencing device and says so.

## 7. Cult, relics, printed afterlife

- **1483 opening of the tomb** [R on the day]: documented across the cult literature, but **11 January 1483 could not be verified from a fresh fetch**. The incorrupt-body story at three years is legend, and enWP reports the 1483 skeleton against it. Both are in the file, side by side.
- **Beatified by Gregory XV, 1622** [A], NA. **Canonized and made Doctor of the Church, 16 December 1931** [A]: SEP the date, NA the year; the 830-page *Positio* and the 1927-1931 campaign are **dossier-only**. **Patron of natural scientists, 1941** [A]: SEP and the Vatican audience.
- **Relics** [A, contested date]. The pool tagged the St. Andreas transfer [R]; it should be [A], with a conflict inside deWP itself: its **Albertus Magnus** article dates the bones' arrival to the convent's suppression in 1804, its **Dominikanerkloster Köln** article to 1802, the church closed 28 September 1802 and demolished 1804. The file reads this as **1802-1804** and prints both. The third-century Roman sarcophagus is [A]; the **1954** installation is dossier-only, used as the stop's ordering date. A secondary relic at St. Stephen's, Nijmegen, is [A].
- **Editio Coloniensis** [partly confirmable]. The Albertus-Magnus-Institut site confirms its purpose, Bonn location under the Archdiocese of Cologne, and **1931** founding, but gives no start year or volume count, so the commonly quoted **1951 remains unconfirmed**. Superseded collections [A]: Jammy, Lyon 1651, 21 folio volumes; Borgnet, Paris 1890-1899, 38. Printing history [A], Linda Hall Library: *De mineralibus* printed 1476, five editions before 1501; *De animalibus* 1478, twenty more that century.
- **Statue** [A]. Gerhard Marcks's bronze on Albertus-Magnus-Platz, University of Cologne, with replicas at Jena, the University of the Andes, and Houston.

**Coordinates.** The statue pin moves from the pool's 50.9279 / 6.9218 to enWP's **50.9281 / 6.9286**. The 13 Cologne convent stops take the canonical atlas pin **50.9407 / 6.9583** (byte-identical from Aquinas, Cusanus, Agrippa) over the pool's 50.9377 / 6.955; the 4 Paris stops take the canonical **48.8472 / 2.3433**, matching frWP's point for the Couvent des Jacobins, over the pool's 48.844 / 2.345. The provincial election moves to **Worms, 49.6319 / 8.3653**, the release from the see to **Orvieto, 42.7185 / 12.1113**; St. Andreas, 50.9417 / 6.9539, is confirmed exactly. **One tension is recorded, not fixed**: deWP places Heilig Kreuz at 50.9430 / 6.9543, some 300 m north of the canonical pin, and moving to it would have to happen on Aquinas, Cusanus and Agrippa at once or the map splits. The novitiate stop's `date_confidence` says so.

---

## 8. Attribution failures in the submitted pool

Seven, all with a real claim hung on a source that does not carry it. Five are flagged in place above: the Marian apparition, the 1277 journey "doubted by SEP," the "first securely datable work," the five-convent circuit, Bonaventure and Humbert at Anagni. Two touch quoted text and appear only here. **Ulrich Engelbert's praise** (*Vir in omni scientia adeo divinus...*) was attributed to SEP, which is absent there and mentions Ulrich only as author of *On the Supreme Good*; **the sentence is in NA**, cited to *De summo bono*, tr. III, iv, and the source line is corrected in the file. **The Physica preface quotation** is genuinely in SEP (*Physica* I, tr. 1, cap. 1, p. 1, l. 9-49), but the pool's tail was a paraphrase; verified wording restored, and the pool's "continuation elided" caveat is also wrong.

---

## 9. Apparatus relations for the operator

**Albertus Magnus is not listed in `EXCEPTIONS.md`.** Nothing is silently deleted; the relations I caught are named here with their direction. **Direction caught: FORWARD in every case, so none is licensable and none was written into the file.** Under the block rule Albert's file stopped its clock in 1280 and cannot embed a later artifact. Each already lives on the later subject's own file:

- **`nicholas_of_cusa.journey.json`**, stop "Cologne, the studium and Heimerich de Campo" (1425/1426), names Albert directly alongside Ramon Llull and Proclus as one of three authors put into the young Cusanus's hands.
- **`heinrich_cornelius_agrippa.journey.json`**, stop "Cologne, matriculation at thirteen," names Albert as the house authority of the arts curriculum there c. 1499-1502; its *De occulta philosophia* stops trace the pseudo-Albertine natural-magic line.
- **`johannes_trithemius.journey.json` / `paracelsus.journey.json`**: the pseudo-Albertine alchemical reception. `paracelsus.journey.json` carries **no** Albert reference; the bridge is thematic only and is asserted nowhere.
- The **brazen-head legend family**, attached to Albert (enWP, "Brazen head") and also to Gerbert of Aurillac, Robert Grosseteste, and Roger Bacon. `roger_bacon.journey.json` was checked: no direct Albert reference, so **the campa names only Gerbert and Grosseteste, neither of whom has an atlas file**, rather than name-drop Bacon on shared legend alone. If the operator knows of Bacon's documented attacks on Albert by name, the campa can take it.

**Direction: BACKWARD, needing no exception.** Albert's engagement with **Aristotle**, **Plato**, **Avicenna**, **Averroes** and **Maimonides** is rooted in his own life and texts, and is named in campas. `maimonides.journey.json` carries no reciprocal reference, so that relation is one-directional and flagged in its stop's `date_confidence`.

**No counterpart file exists** (checked by filename and grep) for Averroes, Avicenna, Bonaventure, William of Saint-Amour, Urban IV, Alexander IV, Konrad von Hochstaden, Heimerich de Campo, Guerric of Saint-Quentin, Jordan of Saxony, John of Vercelli, Humbert of Romans, Ulrich of Strasbourg, Tempier, or Rudolf of Habsburg.

**Slugs named in campa text:** `thomas_aquinas`, `aristotle`, `plato`, `maimonides`.

## 10. Honest gaps

Not recoverable: the birth year; the order of the four lectorships, only Freiburg dated; the crusade itinerary of 1263-1264, twenty months of travel and zero named stations; the 1264-1269 split between Würzburg and Strasbourg. Left split: the 1277 Paris journey, the testament year. **Buildings**: the Regensburg cathedral he knew is gone (rebuilding began 1280), the Cologne Dominican church is gone (1804), Saint-Jacques is gone (1800-1849), so three of the file's most-used pins are landmarks standing in for vanished buildings, and each such stop says so.

Named but not reached: **Groten 2011**; **William of Tocco's Latin**, so the "dumb ox" saying rests on a modern English rendering; **Kierkegaard, *The Concept of Anxiety***, so the memory-loss stop's quote comes from enWP and `quote_source` says so; the ***Positio*** for 1931; any early text carrying the Marian apparition. Dossier-only: the 1954 sarcophagus installation, 11 January 1483, 5 January 1260.

---

## Sources

**Reached and used.** SEP, https://plato.stanford.edu/entries/albert-great/ : spine of the chronology, fetched twice, including to check for the 1277 journey and the Ulrich Engelbert sentence, both absent. NA, https://www.newadvent.org/cathen/01264a.htm : six of the seven verified Albert quotations plus the Ulrich Engelbert testimony. deWP "Albertus Magnus," the most corrective source in this pass (Worms, Orvieto and February 1262, Freiburg 1236-1238, the Cologne novitiate, Rudolf of Habsburg at Lyons, the 1279 testament) and "Dominikanerkloster Köln." enWP "Albertus Magnus," "Brazen head," "Anagni," "William of Saint-Amour," "Valenciennes," "Lauingen," "St. Andreas, Cologne," "Strasbourg Cathedral," "Regensburg Cathedral," "Thomas Aquinas." itWP "Alberto Magno." frWP "Couvent des Jacobins." Benedict XVI, general audience of 24 March 2010, vatican.va. Linda Hall Library, "Scientist of the Day: Albertus Magnus." albertus-magnus-institut.de, whose substantive text was reachable here though an earlier pass reported only boilerplate.

**Atlas files consulted directly.** `thomas_aquinas.journey.json` (canonical pins, the 1245 arrival, the 1248-1254 Cologne years, the "probably 1250" ordination under Konrad von Hochstaden, the "dumb ox" story already carried as legend); `nicholas_of_cusa`, `heinrich_cornelius_agrippa`, `maimonides`, `paracelsus`, `roger_bacon`; `EXCEPTIONS.md`, read before writing, Albert not listed, hence section 9.
