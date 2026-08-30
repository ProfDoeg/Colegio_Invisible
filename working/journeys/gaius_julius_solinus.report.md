# Gaius Julius Solinus: research report

*2026-08-30. The compiler of the* Collectanea rerum memorabilium *(revised as the* Polyhistor*), a Latin world-circuit assembled chiefly out of Pliny and Mela. Slug:* `gaius_julius_solinus`.

**Legend.** **[A]** = attested, source named and reachable in this pass · **[R]** = reconstruction, tradition, or a claim reaching me only through the dossier and not re-fetched. Contradictions are flagged, not adjudicated.

**The governing fact, stated once at the top.** There is no life: no birth, death, city, family, career, teacher, pupil, anecdote, tomb, portrait, inscription, papyrus, letter, or contemporary who names him. Every date printed beside his name in any reference work came from the text itself or from one nineteenth-century conjecture about a dedicatee. A conventional journey file cannot be written here and was not attempted. The file plots instead (1) the text's own circuit, marked as text and not as travel in every `date_confidence`, and (2) the book's physical stations as an object. Both departures are declared stop by stop, on the precedent of `megasthenes.journey.json`, whose stops read "Content of the *Indika*, not a documented stop."

**File:** 38 stops, 8 segments, 12 quotes, calendar julian.

---

## 1. Dating: the whole problem in one section

**The internal edge [A].** Vespasian, dead 79, is the latest Roman emperor named anywhere in the *Collectanea* (29.6), and nothing refers to a later reign. That is the only hard chronological statement the text makes about itself, and it is a *terminus post quem* with no upper bound.

**The conjecture that supplies everything else [R].** Solinus dedicates the work, twice, to an "Adventus". Mommsen identified him with **Marcus Oclatinius Adventus, consul for the second time in AD 218**. The consulship is documented; the identification is not. No ancient source connects the two men, and the New World Encyclopedia line ("Adventus is identified with Oclatinius Adventus, Roman consul in AD 218") repeats Mommsen's hypothesis, not a testimonium. The traditional dating rests entirely on that one unproved equation.

**Three datings in circulation, none adjudicated here.** *Early 3rd c.* **[R]**, New World Encyclopedia, on the Adventus identification. *Middle 3rd c.* **[R]**, same entry, Mommsen's own preference: "though Mommsen places him in the middle of the 3rd century." *Reign of Constantine I, late 3rd to early 4th c.*, Giovanni Piccolo, PhD diss., Univ. of Melbourne, 2022, arguing from internal evidence and the work's political design: **[A]** for the dissertation (minerva-access, fetched), **[R]** for its conclusion.

The two reference entries **contradict each other inside a single article**, and Piccolo contradicts both. Flagged, not resolved. In the file this is three separate stops (0218, 0230, 2022) rather than a settled date; `years` reads `fl. 3rd or 4th century CE (no birth, death or documented life event attested)`. Every stop dated inside the notional floruit (0079 to 0243) says in `date_confidence` that its date orders the segment and asserts nothing.

---

## 2. The two prefaces: the only first-person material that survives

All three below were fetched from **The Latin Library, `solinus1a.html`**, and all three needed correction against the truncated forms in circulation.

**[A] The dedication.** `Cum et aurium clementia et optimarum artium studiis praestare te ceteris sentiam...` *Caveat in the stop:* the clause came from a fetch-and-summarize pass, not a continuous read; the ellipsis marks that it was not re-verified word for word.

**[A] The method.** `liber est ad conpendium praeparatus...` **Correction applied:** the circulating short form stops at the second comma with a full stop, turning a subordinate clause into a sentence and dropping the result clause (`ut nec prodiga sit in eo copia nec damnosa concinnitas`) that *is* the method statement. The stop quotes it whole. Manuscript spelling is `conpendium`.

**[A] The disclaimer of originality.** `...vestigia monetae veteris persecuti opiniones universas eligere maluimus potius quam innovare.` **Correction applied:** the circulating form begins mid-sentence at a capitalized "Vestigia", dropping the governing `quoniam quidem`; the stop quotes from `quapropter quaeso`. The next sentence, `constantia veritatis penes eos est quos secuti sumus`, is equally verified and sharper for the "Pliny's ape" question; it is in `suggested_refs` and paraphrased in the campa.

### The second preface: a live textual dispute, flagged not resolved

The dossier framed the expanded recension as **Solinus's own second edition**, issued after an unauthorized draft escaped him and renamed *Polyhistor*. That overstates what the sources support. Four positions stand:

1. **Sixth-century reworking**, the older and majority position. 1911 *Encyclopaedia Britannica* (Wikisource): "The *Collectanea* underwent revision in the 6th century, renamed *Polyhistor* (later mistakenly attributed as the author's name)." **[A** for what the source says**]**
2. **Cautious agnosticism.** English Wikipedia: "A greatly revised version of his original text was made, perhaps by Solinus himself." **[A]**
3. **Solinian authorship defended.** Hermann Walter, 1969, against Mommsen. Minority view. **[R]**, dossier report.
4. **A property of one manuscript branch.** Von Büren, p. 22, makes the second dedicatory letter a distinguishing feature of **Mommsen's third manuscript class**: "la troisième étant caractérisée par 26 ajouts textuels et une deuxième lettre de dédicace..."

So "the second preface" is not a settled part of the text at all. The stop "Rome, a second preface and a second name" says so and ends "Neither side has produced a witness the other accepts." The JSON keeps plain ASCII, so the French is carried without accents and the `quote_source` says so.

---

## 3. The text as itinerary

Twenty stops plot the book's route, not the author's. **No source places Solinus anywhere.**

| stop | pin | tag / note |
|---|---|---|
| Rome, the head of the world | 41.9028, 12.4964 | [R] structural. Pin inherited byte-identical from `plinio_el_viejo.journey.json`; the text's own reference is the Capitoline (41.8931, 12.4828), named in the campa but not used as coordinate |
| Bay of Naples / Vesuvius · Mount Etna | 40.8214, 14.426 · 37.751, 14.9934 | [R], *Collectanea* 2-8 and the Sicily chapters |
| Massalia | 43.2951, 5.3739 | [R], Gallia sequence; a conventional anchor for the turn west |
| Strait of Dover / Britannia | 51.1279, 1.3719 | [R] for the text, [A] for Bede's use (see §6) |
| Cádiz (Gades) | 36.5297, -6.2925 | **Label corrected.** The pool called this the Temple of Hercules Gaditanus, which was not in the city: Wikipedia (fetched) puts it, on LiDAR evidence, underwater in the Sancti Petri marsh (approx. 36.392, -6.210) or at the cerro de los Mártires. Relabelled plainly as Cádiz, coordinate kept, temple to `suggested_refs` |
| Tenerife / Fortunatae Insulae | 28.2916, -16.6291 | [R], *Collectanea* 56. The Canary identification is later convention, not in the text |
| Carthage · Alexandria, Pharos | 36.8528, 10.3233 · 31.2139, 29.8853 | [R]; the Africa sequence opens at one and hinges into Asia at the other |
| Cyrenaica, basilisk (2 stops) | 32.8253, 21.8586 | [A] text, **[R] coordinate**, see gap below |
| Meroë | 16.9333, 33.75 | [R]; text says only *in Aethiopiae partibus* |
| Palibothra · India, manticore and monoceros | 25.6127, 85.1228 | [R] for the Megasthenes source-city, [A] for the text; no locality given for the beasts |
| Mountains of India, dog-heads · Monocoli | **27.5, 88.5** | [A] text; **inherited byte-identical** from `megasthenes.journey.json`, 'The mountains of the dog-headed men'. 52.29 sits two sentences after 52.27, so both reuse the pin |
| Taprobane | 6.8096, 80.4994 | [R], closes the outward reach |

**Honest gap: two coordinates here are mine, not the pool's.** The pool supplies **no coordinate for the basilisk passage (27.50-53)**, which sits in the African chapters without a locality. Rather than pin it at Meroë or Carthage, which would mislead, I used **Cyrene, 32.8253, 21.8586**, following Pliny's Cyrenaica; both stops say so in `date_confidence`. To keep to pool coordinates only, merge them into Meroë and drop one basilisk quote.

**Verbatim Latin used** (all [A], The Latin Library, chapter and file in each stop's `quote_source`): 27.50-53 basilisk, twice · 27.58 Ethiopian cynocephali as **apes** · 52.27 Indian cynocephali as **nationes**, credited by Solinus to Megasthenes · 52.29 Monocoli · 52.37-38 manticore · 52.39-40 monoceros.

**Internal tension recorded, not a source contradiction.** Solinus carries *two incompatible dog-headed populations* without reconciling them: at 27.58 apes, `e numero simiarum`; at 52.27 `nationes`, with claws, hides and a language of barking. The Meroë campa states this and leaves it open.

---

## 4. The book as object: what the file plots

| stop | tag | evidence |
|---|---|---|
| Reading Abbey, c. 1150 | **[R]**, doubly hedged | BPL 68's provenance given as "probably... possibly Reading" by the dossier itself |
| Leiden, BPL 68 | [R] | **Coordinate corrected** to 52.1575, 4.4811 (Wikipedia) from the pool's 52.1601, 4.4848, about 390 m off. **Tag downgraded [A] to [R]:** the catalogue was unreachable, so contents, date and interpolation rest on the dossier |
| London, BL Egerton 818 | [R] | holding a catalogue fact; image description from dossier. Contradiction below |
| Ann Arbor, Clements Library | [R] | holding standard; 86-leaf description from the dossier |
| Venice 1473, Jenson, *De mirabilibus mundi* | **[A]** | Wikipedia: "The first printed edition was published in Venice in 1473" |
| Vienna 1520, Camers | [R] edition, [A] the *Life* | Camers's *Life of Solinus* read directly in the 1587 Golding scan |
| Poitiers 1554, Vinet · Antwerp 1572, Delrio | [R] | dossier only; the Plantin pin is conventional, not a documented imprint |
| London 1587, Golding | **[A]** | archive.org full text; ota.bodleian handle 20.500.12024/A12581 |
| Paris 1629, Saumaise | **[A]** | de.wikipedia: "*Plinianae exercitationes in Solinum* (Paris, 1629)" |
| Berlin 1895, Mommsen · Melbourne 2022, Piccolo | **[A]** | New World Encyclopedia; minerva-access (fetched) |

**Contradiction flagged, not adjudicated: Egerton 818 and Salutati.** The pool calls Egerton 818 a **fifteenth-century Italian manuscript** and simultaneously the copy **annotated by Coluccio Salutati**, who died **4 May 1406**. Both cannot be right unless "fifteenth century" means its first six years, or the annotated copy is a different book from the illuminated one. The campa names the death year; the confidence field states the conflict plainly.

**Correction carried: the 1689 Saumaise is Utrecht, not Paris.** Internet Archive records **A212099** and **A212100** give the imprint as *Trajecti ad Rhenum: Johannem vande Water, Johannem Ribbium, Franciscum Halma, et Guilielmum Vande Water*. Trajectum ad Rhenum is **Utrecht**; only the 1629 first edition is Parisian. The file keeps one Paris stop and names Utrecht in the campa. Saumaise died 1653, so 1689 is posthumous.

### Correction carried: "Plinies Ape" is not Golding's verdict and is not Golding's sentence

The most consequential fix in this pass, because the received story inverts the passage. Verified from the archive.org full text of the 1587 volume. Spelling is **"Plinies Ape"**, no apostrophe. It sits under the heading **"THE LIFE OF SOLINUS, WRITTEN BY IOHN CAMERTES"**, the prefatory Life that Golding merely translated, not in Golding's own preface. And it is quoted **in order to be refuted**: "such are wont to be called Apes, as eyther repeate thinges written by others altogether in the same order without alteration... But Solinus hath so folowed Plinies phrase, that... there may scarce any other be found, that hath approched neerer to the maiestie."

Correct citation: [Johannes Camers], 'The Life of Solinus', in Arthur Golding, trans., *The Worthie Worke of Iulius Solinus Polyhistor* (London, 1587), prefatory matter. *The Excellent and Pleasant Worke* is a genuine variant title-page of the same edition, so the dossier's title is defensible.

---

## 5. Interlocks

Named in a campa, each on a direct or one-directional relation:

- **`megasthenes` [A].** **Solinus names Megasthenes inside the sentence** at 52.27. `megasthenes.journey.json` reciprocally names Solinus in the campa of 'The mountains of the dog-headed men'.
- **`plinio_el_viejo` [A]** as a source relation. The *Naturalis Historia* is the largest source body for the *Collectanea* and the reason the "Pliny's ape" controversy exists, though `plinio_el_viejo.journey.json` never mentions Solinus.
- **`ctesias` [R].** Ctesias reported barking men near the Indus; Solinus receives it **at second hand through Pliny**, who names Ctesias among his authorities. Labelled as indirect in the campa.
- **`adam_of_bremen` [A]**, the strongest reception hit in the atlas. **Cites Solinus by name, twice, as an authority tested against living informants:** *Gesta* IV.38-40 on Thule and the midnight sun, IV.25 on the one-footed hoppers. His cathedral-school stop also names "the geography of Solinus and Martianus Capella".

**Coordinate inherited byte-identical:** 27.5, 88.5 from `megasthenes.journey.json`. Rome uses the canonical 41.9028, 12.4964 from `plinio_el_viejo.journey.json` throughout.

Deliberately **not** named in any campa, though present in the pool: `san_cristobal`, `ratramnus_of_corbie`, `saint_mercurius`, `odoric_of_pordenone`, `ibn_battuta`, `jacobus_de_voragine`. All carry cynocephalus material, but **none cites Solinus and Solinus has no relation to any of them.** Shared motif is not a relation. Ratramnus's letter and Christopher's Passion sit in `suggested_refs` on the 52.27 stop, without slugs in the prose. **No journey file exists** for Adventus, Priscian, Isidore, Bede, Mela, Martianus Capella, Fazio, Salutati, or the Hereford map, so the reception network has almost no atlas node to interlock with. QUEUE.md has no Solinus entry under any spelling checked.

---

## 6. Apparatus relations for the operator

Solinus is **not** listed in `EXCEPTIONS.md`, and none of what follows is an apparatus case in that file's sense: no framework of his is applied to anything. But the rule is not to delete silently, so here is every relation I found that is **not rooted in Solinus's own life**. **Direction is backward in every case**, later people reaching back to a text.

| relation | disposition and what came out of checking it |
|---|---|
| **Bede**, Jarrow, c. 731 | Jarrow is *Bede's*. Dropped; named in the campa and `sources` of the Britannia stop. *Coordinate correction for Bede's file:* the pool's 54.9836, -1.4877 is about 1.1 km off; St Paul's is **54.9804, -1.4722** |
| **Adam of Bremen**, Roskilde and Hälsingland | His stops, on his own file. Named in two Solinus campas as a citing reader, no scene staged, no coordinate borrowed |
| **Isidore**, Seville; **Augustine**, Hippo Regius | Both places are theirs, and Hippo already appears in `san_cristobal.journey.json`. Dropped. *Honest gaps:* my Wikipedia fetch did **not** confirm Isidore's dependency, and the dossier flags Augustine's as "real but more textually complicated than older source lists assumed" |
| **Priscian**, Constantinople, c. 500 | **Dropped, and doubted.** Wikipedia confirms *fl.* 500 and Constantinople, but its list of the authors he quotes (Virgil, Terence, Cicero, Plautus, Lucan, Horace, Juvenal, Sallust, Ovid, Livy and others) **does not include Solinus**. The pool's [A] item is unsupported here and should be [R] |
| **Aberdeen Bestiary**, Canterbury, c. 1200-1210 | The compilers' object. Dropped; in `suggested_refs` on the monoceros stop. *Upgrade recorded:* Wikipedia confirms the creature list (elephant, hyena, crocotta, bonnacon, monoceros, leucrota, parandrus, yale) and names the *Collectanea* among its sources; **place is Canterbury, not bare England**; [R] to [A] |
| **Hereford Mappa Mundi**, c. 1300 | Dropped, and doubted independently of the ownership rule: Wikipedia names Orosius, the Alexander myths, bestiaries and the Monstrous Races, **not Solinus**. *Coordinate correction:* Hereford Cathedral is **52.0542, -2.7160**, and the map has sat in the Whitfield building since 1996, not the nave |
| **Coluccio Salutati**, Florence | The chancery is his. Dropped; the annotation is named on the Egerton 818 stop, the *book's* station, with the 1406 death date flagged |
| **Fazio degli Uberti**, *Dittamondo* | **The one the operator may want to overrule me on.** Not a reader citing a text: Solinus is written into the poem *as a walking character*, guiding the narrator as Virgil guides Dante. Staging it would put a fictional Solinus where the real one never went, so it is out of the map and recorded here. *Corrections:* the pool's note that it.wikipedia "returned no page" is **false**; the article confirms the substance verbatim ("in compagnia del geografo romano Gaio Giulio Solino"; "Trasparente l'imitazione della Commedia dantesca") and dates it "dal 1346 alla morte, senza completarlo". [R] to [A] |
| **Apps** (Macquarie 2011), **Brodersen** (*Solinus: New Studies*, 2014) | Sydney and Heidelberg are theirs. Dropped; both in `suggested_refs` on the Melbourne stop. *Correction:* OpenLibrary gives Brodersen as editor, Verlag Antike, 2014, at **Heidelberg**, filling the pool's "unknown (publication)"; [R] to [A] |
| **Giovanni Piccolo**, Melbourne 2022 | **Kept as a stop**, because the redating is a claim about the *text's own date* and closes the loop opened in segment 1. If the operator judges a scholar's university to be the scholar's stop and not the book's, drop it and fold the redating into the floruit stop's confidence field |

No forward-reaching relation was found and none is written, so no `EXCEPTIONS.md` listing is requested.

---

## 7. Gaps, stated as gaps

- **No life** (see the head of this report). Confirmed by direct check of English Wikipedia: textual legacy only, no memorial of any kind.
- **The dedicatee may not be Oclatinius Adventus.** If he is not, the third-century dating has no support at all, and Piccolo's Constantinian argument is the only positively argued date on the table.
- **Reported through the dossier, not re-fetched:** the *Liber genealogus* (455) citation; Weyman's 1896 review; Walter 1969; von Büren's full 1996 article and her "at least 251 manuscripts" figure (her p. 22 sentence *was* fetched twice); the Vienna 1520, Poitiers 1554, Antwerp 1572 and Venice 1559 editions.
- **Unreachable:** the Leiden catalogue (connection reset); EEBO for Golding (403, worked around via archive.org, which is how the Camers attribution surfaced); the Hereford Cathedral and David Rumsey pages (access-verification screens).
- **No coordinate exists in the pool for the basilisk chapter.** See §3.
- **The pool's "over a hundred creature descriptions" is not supported.** bestiary.ca's own list runs to a few dozen entries. Its chapter citations check out verbatim (basilisk 27.50-53, elephant 25.2-14, lion 17.11, dragon 30.15-18, manticore 52.37-38, and others), but the count does not. Nothing in the file repeats the figure.

---

## Sources

**Primary text (all fetched, all [A]):** The Latin Library `solinus1a.html`, `solinus3a.html`, `solinus4a.html` · archive.org `bim_early-english-books-1475-1640_the-worthie-worke-of-jul_solinus-caius-julius_1587`, Golding 1587 with Camers's *Life* · Internet Archive A212099 and A212100, Saumaise, Utrecht 1689

**Reference and scholarly (fetched):** Wikipedia 'Gaius Julius Solinus', 'Priscian', 'Isidore of Seville', 'Historia ecclesiastica gentis Anglorum', 'Aberdeen Bestiary', 'Hereford Mappa Mundi', 'Coluccio Salutati', 'Temple of Hercules Gaditanus', 'Leiden University Libraries', 'Monkwearmouth-Jarrow Abbey', 'Hereford Cathedral', 'Arthur Golding'; it.wikipedia 'Fazio degli Uberti'; de.wikipedia 'Claudius Salmasius' · 1911 *Encyclopaedia Britannica* 'Solinus' (Wikisource); New World Encyclopedia 'Gaius Julius Solinus' · von Büren, *Scriptorium* 50.1 (1996), p. 22: persee.fr/doc/scrip_0036-9772_1996_num_50_1_1744 · minerva-access.unimelb.edu.au (Piccolo diss.); topostext.org/work/747; ota.bodleian.ox.ac.uk handle 20.500.12024/A12581; bestiary.ca/prisources/psdetail947.htm; OpenLibrary search API

**Atlas files consulted:** `megasthenes`, `plinio_el_viejo`, `ctesias`, `adam_of_bremen`, `san_cristobal`, `ratramnus_of_corbie`, `saint_mercurius`, `odoric_of_pordenone`, `ibn_battuta`, `jacobus_de_voragine`; `abdelkader` and `bourlemont_roster.md` for form; `EXCEPTIONS.md`. Unreachable and dossier-only sources are in §7.
