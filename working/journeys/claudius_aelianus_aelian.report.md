# Claudius Aelianus (Aelian): research report

*Slug: `claudius_aelianus_aelian`. Compiled 2026-08-29 against the two surviving ancient testimonia and the primary text. Journey file: `claudius_aelianus_aelian.journey.json`, 8 segments, 35 stops.*

**Legend.** **[A]** = attested, source named. **[R]** = reconstruction, tradition, handbook consensus, or inference from absence. Contradictions are flagged, not resolved. Unreachable sources are named with the reason.

---

## The shape of the problem

Aelian's whole biography fits on one page, and his whole geography is a dispute. Two ancient texts describe him: **Philostratus, *Lives of the Sophists* 2.31** (two pages, near-contemporary, written in the 230s) and **the Suda, entry alpha-iota 178** (four sentences, tenth century). There is no inscription, no correspondence, no property record, no securely identified portrait **[A: absence confirmed across both testimonia, both fetched]**. Against that he left some twenty-three books, and those books travel to India, Persia, Taprobane, Ethiopia, the upper Nile and the Aeolian islands. Philostratus says the author never boarded a ship.

The journey file therefore keeps two kinds of stop apart. Stops where a source **places Aelian** (Praeneste, Rome, and the disputed Alexandria), and stops where **his book goes**, marked in `date_confidence` as the composition window and the place the text sends its marvel, never as travel. Alexandria straddles both, and that is where the central contradiction sits, unresolved.

---

## Phase 1: Praeneste, c. 161-177

**Birth at Praeneste in Latium [A].** The Suda: "Of Praeneste in Italy. High-priest and sophist; surnamed Claudius. He was nicknamed 'honey-tongued' or 'honey-voiced'. He was a sophist in Rome itself in the period after Hadrian."

Two errors in the research pool, corrected before writing:

- The entry is **alpha-iota 178**, not "alpha,178", which is a different entry. Both artifacts use the corrected form throughout.
- **"Offspring of freedmen" is not in the Suda.** It appears only in the Suda On Line editorial note, which paraphrases the 1911 Britannica. That makes the freedman parentage **[R]** at second hand from a century-old encyclopedia, and it is not carried into the journey file at all. The birth campa says instead that no document names his father or a trade.

**Birth year [R].** No ancient date exists; it is back-calculated from Philostratus's "over sixty years of age" plus the post-222 terminus. OCD (Trapp) brackets 161/177; Wikipedia gives c. 175. The file uses 0170-01-01 and says so. **The OCD entry could not be fetched (academic.oup.com, 403); cited at second hand only.**

**The priesthood [A as title, R as to cult and place].** The Suda calls him *archiereus* and names no god, no city, no date. Steven D. Smith (*Man and Animal in Severan Rome*, 2014) builds weight on the detail; C. W. Marshall in **BMCR 2015.09.15** says Smith "perhaps over-invested with meaning" that detail from the Souda.

**Correction.** The pool attributed to Smith, via that review, a link between the priesthood and the **cult of Fortuna Primigenia**, and between the sanctuary's **Nile mosaic** and Aelian's Egyptian material. **BMCR 2015.09.15 mentions neither Fortuna Primigenia nor Praeneste nor the mosaic** (re-fetched and checked). The attribution is dropped. What survives into the file: the sanctuary and its mosaic as the town's own attested furniture (Wikipedia, 'Palestrina, Lazio': the mosaic decorated the eastern nymphaeum, "thought they were realised by artists from Alexandria at the end of the 2nd century BC") **[A for the mosaic, R for any link to Aelian]**; the oracular lots from Cicero, *De divinatione* 2.85-87 **[A]**; and a campa saying a reader who wants the sanctuary to explain his appetite for portents "must supply the connection themselves".

---

## Phase 2: Rome, the sophist who would not perform

All of this is Philostratus *VS* 2.31, and the gather pass's failure to fetch it was corrected: the verify pass retrieved **Wright's Loeb 134 (1922) from archive.org, identifier `philostratuseuna00phil`**, and every item below is verbatim-confirmed at pp. 305-307. The pool's `[R]` tags on the Pausanias, Herodes, sophist-title, declamation and death-notice items are accordingly **upgraded to [A]**.

- **Pupil of Pausanias of Caesarea [A].** "He was a pupil of Pausanias." One teacher, no date, no place.
- **Admired Herodes Atticus [A].** "he admired Herodes as the most various of orators" (*poikilotaton rhetoron*). **Admiration, not instruction**: Herodes died in 177 and the chronologies make study under him implausible.
- **Attic Greek [A].** "Aelian was a Roman, but he wrote Attic as correctly as the Athenians in the interior of Attica."
- **Title of sophist [A].** Granted by those authorized to grant it; he did not trust the honour or let it flatter him.
- **The turn to writing [A].** Judging his abilities unsuited to declamation, "he applied himself to writing history and won admiration in this field." Philostratus adds a style note: simple, with Nicostratus's charm and occasional imitation of Dio's vigour.
- **The vow of the landsman [A].** He used to say he had never gone beyond the confines of Italy, never boarded a ship, never known the sea, and Rome esteemed him more for it.

**A rule applied here.** The pool staged the Herodes admiration at the **Odeon of Herodes Atticus in Athens**: Herodes's building, in a city Aelian never entered. Under the rule that a stop belongs to whoever was actually there, the admiration is written **at Aelian's own Rome pin**, with the Odeon named in `suggested_refs` as built by the orator he admired and never visited. The Athenaeum of Hadrian likewise appears only in `suggested_refs`, flagged as a modern guess, since Philostratus names no venue for anything Aelian did. All Rome stops use **41.9028, 12.4964**, byte-identical to the corpus pin in `auguste_rodin.journey.json`; the pool's Forum coordinate (41.8925, 12.4853) is not used.

---

## Phase 3: the book that travels for him

Fourteen stops carry marvels rather than the man, all verbatim-verified against **Attalus.org's Scholfield translation**, fetched chapter by chapter: the Indian Dog-heads (*DNA* 4.46), the Manticore and Ctesias (4.21), Cartazonus and the Colunda satyrs (16.20-21), the sea-satyrs of Taprobane (16.17-19), Amphisbaena against Hydra (9.23), the seven days of desert and the Ethiopian Dog-faces (10.25), the five-footed ox (11.40), the lamb of Bocchoris (12.3), the Nile prodigies (11.39-40), the Diomedean birds (1.1), the dolphin of Poroselene (2.6), the sea-crane of Corinth (15.9), and the Delphi deer, Acropolis sheep, Paphlagonian partridges and Bisaltian hares (all 11.40). In every case the **text is [A]** and the **pin is [R]** wherever Aelian names a region rather than a place, which is nearly always.

**Four coordinate errors in the pool, corrected:**

1. **Poroselene.** Pool gave 39.0333, 26.7333, open water some 37 km south of the island. Cunda (Alibey) is at **39.3606, 26.6428**.
2. **Isthmia.** Pool gave 37.9256, 23.2003, out in the Saronic Gulf about 18 km off. Correct: **37.9159, 22.9932**.
3. **Castra Praetoria.** Pool gave 41.9086, 12.5177, a kilometre past the Porta Tiburtina. Correct: **41.9059, 12.5060**.
4. **Newstead Abbey** (a `suggested_ref`, not a stop). Pool gave 53.0847, -1.2011; correct **53.0783, -1.1925**.

**One wrong place, corrected.** The pool pinned the seven-days-of-desert passage at **Siwa**. *DNA* 10.25 names no oasis, and Siwa sits in the far northwestern Libyan desert with no road toward Ethiopia. The file uses the **Great Oasis (Kharga, c. 25.44, 30.55)**, on the southbound route to Nubia, and `date_confidence` states that the identification is editorial and that the Siwa placement was wrong.

**One factual error, corrected.** The pool said the young of the Colunda satyrs go to the Prasian king. *DNA* 16.21 says **the sick and the pregnant females** do. The Cartazonus foals are the ones exhibited at the shows (16.20, quoted verbatim in the file).

**One over-claim, downgraded.** The pool pinned the Alexandria passage at the **Serapeum** and tagged it [A]. Aelian names neither Serapis nor the Serapeum: the offering is "to this god", unnamed across 11.39-40. The file uses the **canonical Alexandria pin, 31.2001, 29.9055**, inherited byte-identical from `strabo.journey.json`, and calls the Serapeum identification editorial.

---

## The contradiction, flagged and left standing

- **[A]** Philostratus, *VS* 2.31: Aelian used to say he had never gone beyond Italy, never set foot on a ship, never known the sea, and Rome esteemed him for it.
- **[A]** Aelian, *DNA* 11.40, first person: "And I myself have seen a sacred ox with five feet which was an offering to this god in the great city of Alexandria, in the far-famed grove of the god, where the persea-trees close-planted afforded the loveliest shade and coolness... True, these phenomena appear far from conformity to nature, but I have reported what I myself have seen and heard."

Both were fetched independently. No ancient writer notices the clash and none reconciles it. The modern readings on offer (a rhetorical "I have seen" meaning "I have found in my sources"; a lost early voyage; Philostratus repeating a boast) are conjecture and **none is adopted**. The Alexandria stop carries the first-person quote intact with the Philostratus statement named in its own `suggested_refs`, so a reader meets both.

A second contradiction is also left standing: **the two dog-head passages are not the same creature.** *DNA* 4.46 gives Indian Dog-heads who keep goats and understand Indian speech; 10.25 gives black-skinned human Dog-faces seven days beyond an Egyptian oasis on the Ethiopian road. Aelian never equates them, and the Meroe campa says so.

**One reception claim dropped as unevidenced.** The pool asserted [A] that later reception "recombined" the two passages into one synthetic cynocephalus and that modern cryptid treatments misrepresent Aelian as an eyewitness. Its only citations were the two primary texts, which support the *distinction* and say nothing about reception. The distinction is kept; the reception sentence is not.

---

## Phase 4: Severan Rome, 222

**Elagabalus killed by the Praetorians, 13 March 222 [A]**, standard chronology, corroborated by Wright's note to *VS* 2.31 identifying "Gynnis", the womanish man, as Heliogabalus, "who was put to death in 222". **This is the only fixed date in Aelian's life.**

**The scene [A].** Philostratus of Lemnos finds Aelian holding a book and reading it aloud "in an indignant and emphatic voice"; Aelian says, "I have composed an indictment of Gynnis," his name for the tyrant just put to death, whose wanton wickedness had disgraced the Roman Empire.

**The retort, and a correction.** The pool presented the whole retort as verbatim. **In Wright only the first clause is direct speech**: "I should admire you for it, if you had indicted him while he was alive." The rest is reported indirectly. The journey file quotes only the direct-speech clause and paraphrases the remainder, unquoted.

**The Indictment of Gynnis is lost entirely [A].** No line survives and no other ancient author mentions it. Smith (2014) proposes a link between the lost *On the Syrian Mime* and the Gynnis indictment; that is named in `suggested_refs` and tagged nowhere as fact.

---

## Phase 5: death, and the absence of a body

- **Over sixty, unmarried, childless [A]**: "He lived to be over sixty years of age and died leaving no children; for by never marrying he evaded begetting children."
- **Year of death [R].** Nothing ancient. Handbooks give c. 230-235, outer range c. 238; Wikipedia c. 235. File uses 0234. **Place of death [R]**: no ancient source states it, Rome is a modern default, and `date_confidence` says so.
- **Cause, illness, funeral, burial, tomb, epitaph, inscription, property record, letter: no record whatsoever [A as absence]**, by exhaustion of both testimonia.
- **No securely identified portrait [R].** No museum, epigraphic or numismatic record was located, and no counter-example either.

---

## Phase 6: transmission, and where the file stops

Only **two** afterlife stops were written, because most of Aelian's afterlife is other people's travel.

- **Constantinople, the Suda and Manuel Philes** (41.0082, 28.9784), with `date_confidence` stating outright that Aelian is seven centuries dead and the stop marks where the text survives, not a place he went. The Suda's heavy quotation is why the two lost works, *Peri pronoias* and *Peri theion enargeion*, survive at all. **Correction:** those titles are **not in Suda alpha-iota 178**, which names no works; they come from the Suda On Line notes and standard reference literature. The claim survives, the citation is fixed. The **Philes** connection rests on **Kindstrand 1986, not read**; tagged [R].
- **Rome, the editio princeps of 1545** (Blado; editor Camillo Peruschi, bishop of Alatri; sources including Codex Vaticanus graecus 1375) **[A]**, Rochester rare-books blog, fetched. A stop because it happens in Aelian's own city, to Aelian's own book.

**Deliberately not written as stops**, being somebody else's journey: Zurich 1556 (Gessner), London 1665 (Stanley), Jena 1832 (Jacobs), London 1922 (Wright), 1958-59 (Scholfield), Cambridge 2014 (Smith), Stuttgart 2025 (Trachsel and Muller), Newstead Abbey (Wildman's binding). All appear instead in `sources` and `suggested_refs` on the stops they bear on.

**Correction on Scholfield.** The pool cited Attalus for "Loeb volumes 446, 448, 449". Attalus gives only "A.F. Scolfield's 1958 translation", that spelling, no volume numbers; Wikipedia confirms only "the Loeb Classical Library (1958-59)". The numbers are dropped and the spelling corrected to Scholfield.

---

## Apparatus relations for the operator

Aelian is **not** listed in `EXCEPTIONS.md`, so nothing licensed there applies. Three relations surfaced by the interlock lens were kept out of the journey file rather than silently deleted. **Direction caught: forward, all three.** Under the block rule, Aelian's file cannot embed a pointer to anything that did not exist when his clock stopped, so no slug, file name or `suggested_ref` for any of these appears in it.

1. **`saint_mercurius`.** The Cappadocian hunt scene, the two dog-headed beings, and the Coptic Museum icon by Ibrahim al-Nasikh descend from the same Greco-Roman dog-head dossier. That file does not cite Aelian; the relation is inferred. Mercurius's material, on Mercurius's file.
2. **`san_cristobal`.** The Marmaritae stop sits in the same ethnographic zone as Aelian's Ethiopian Dog-faces. Adjacency only, no citation chain through Aelian. Christopher's material, on Christopher's file.
3. **`ratramnus_of_corbie`.** The *Epistola de cynocephalis* (c. 863-865) works from the inherited classical dossier but does not name Aelian. Ratramnus's material, on Ratramnus's file.

If the operator wants these visible from Aelian's side, the legal move is not an exception grant but an addition **on each of those three files**, citing *DNA* 4.46 and 10.25 for the tradition they inherit. Old hash, new block.

**Interlocks written into the journey file**, where Aelian has a real one-directional textual relation:

- **`ctesias`**, named in two campas. Aelian cites him **by name** at *DNA* 4.21 and appends "if Ctesias is to be regarded as a sufficient authority on such matters" **[A]**. The Susa stop inherits the canonical Ctesias pin (32.189, 48.257) byte-identical. The Dog-heads campa names him as the source seven centuries upstream **[A via Photius, cod. 72, per the corpus's Ctesias file]**.
- **`megasthenes`**, named in the Pataliputra campa: he went to the Prasian court as ambassador and the Greek picture of the Prasii descends from him. **Tagged [R]: Aelian does not name Megasthenes in any passage fetched this pass**, and the campa states the relation as transmission, not citation. The canonical placeholder pin (27.5, 88.5) was **not** inherited, since Aelian's text puts the Cartazonus at the Prasian capital, not the Himalayan borderlands.
- **`strabo`** and **`auguste_rodin`**: pins inherited only, **not named in any campa**, since Aelian has no relation to either beyond a shared city.

**Corpus gaps, recorded not filled.** No atlas file stages **Pausanias of Caesarea**, **Herodes Atticus**, **Philostratus**, **Elagabalus**, **Julia Domna**, **Caracalla** or **Septimius Severus**: Aelian's teacher, his model, his biographer and the whole Severan court are unreachable from any other file. Grepped `pindar`, `gustave_flaubert`, `paul_the_deacon`, `alexander`, `saint_eustace`, `adriano`, no hits.

---

## Honest gaps

- **The whole middle of his life.** Between birth and 222 there is no dated event of any kind. Every stop in segments 1 through 5 carries a `date_confidence` saying the year is an ordering device.
- **No school, no patron, no student, no location for the teaching.** Philostratus names Pausanias and stops.
- **The *Rustic Letters* [R].** Twenty fictional letters in an imagined Attic countryside, in the manner of Alciphron. Title and count come from the modern edition tradition (Domingo-Forasté, Teubner 1994) and **were not verified against a primary text**. No stop written.
- **The *Varia Historia*'s posthumous release [R].** Wilson's Loeb introduction reports that it still needed revision at his death and was released by his executors. **The introduction was not examined**; the claim sits only in a `date_confidence` field and in `sources`, never in narrative.
- **The Greek text is unstable [A].** Hercher's 1864 Teubner still underlies most digital access, and Attalus flags that Perseus mislabels the Greek of books 8 and 9. Every quotation here is Scholfield's English via Attalus, not a critical Greek edition.
- **No independent check on Smith 2014.** The book was not read, only the BMCR review; where the pool's summary exceeded the review, the excess was cut.

---

## Sources

**Reached and used directly**

- Aelian, *On the Characteristics of Animals*, trans. A. F. Scholfield, at `attalus.org/translate/animalsN.html` for books 1, 2, 4, 9, 10, 11, 12, 15, 16, 17. All quotations in the journey file come from here.
- Philostratus, *Lives of the Sophists* 2.31, trans. Wilmer Cave Wright, Loeb 134 (1922), pp. 305-307, archive.org identifier `philostratuseuna00phil`, including Wright's note identifying Gynnis as Heliogabalus.
- Suda On Line, entry alpha-iota 178: https://cs.uky.edu/~raphael/sol/sol-entries/alphaiota/178
- Bryn Mawr Classical Review 2015.09.15 (C. W. Marshall on Smith): https://bmcr.brynmawr.edu/2015/2015.09.15/
- University of Rochester, 'Aelianus, Historia Varia': https://www.library.rochester.edu/rbscp/blog/aelianus-variae
- Attalus.org, 'Aelian' index; Franz Steiner Verlag page for Trachsel and Muller, eds. (2025); ToposText works 560, 220 and 224; Penelope/LacusCurtius for Jacobs's 1832 Latin.
- Wikipedia: 'Aelian (writer)', 'Palestrina, Lazio', 'Cunda Island', 'Isthmia (ancient city)', 'Castra Praetoria', used for coordinates and the simplified date range.
- Corpus files consulted for pins and interlocks: `strabo`, `ctesias`, `megasthenes`, `auguste_rodin`, `saint_mercurius`, `san_cristobal`, `ratramnus_of_corbie`, `QUEUE.md`

**Named and not reached, with the reason**

- **Oxford Classical Dictionary**, 'Aelian' (M. B. Trapp), for the 161/177-230/238 bracket. `academic.oup.com` returned **403 Forbidden**; cited at second hand only.
- **J. F. Kindstrand**, 'Manuel Philes' Use of Aelian's *De natura animalium*', *SIFC* 4 (1986): 119-139. **Not open access, not read**; cited as a lead.
- **Steven D. Smith**, *Man and Animal in Severan Rome* (2014): **not read**, known only through BMCR 2015.09.15. **N. G. Wilson**, introduction to *Historical Miscellany*, Loeb 486 (1997): **not examined**. **Domingo-Forasté**, *Epistulae et fragmenta* (Teubner, 1994): **not consulted**, no stop written.
- **Loeb Classical Library catalogue**, for Scholfield volume numbers. **Not consulted**; the pool's 446/448/449 are unsupported and omitted.

---

**Artifact.** `claudius_aelianus_aelian.journey.json`: 8 segments, 35 stops, 15 with verbatim quotes. Register `national mythology: the canon is true`, calendar `julian`. Canonical pins inherited byte-identical: Rome 41.9028/12.4964, Alexandria 31.2001/29.9055, Susa 32.189/48.257. Slugs named in campa: `ctesias`, `megasthenes`. Neither file has been committed; the orchestrator commits after the run.
