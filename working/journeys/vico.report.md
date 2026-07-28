# Giambattista Vico — The New Science of Naples

**39 stops, 9 segments, 1668-1744, gregorian, 2/39 quoted.**

## Sources
Primary spine: Vico's own *Vita di Giambattista Vico scritta da se medesimo* (1725-1731, third-person philosophical autobiography), read via the Fisch & Bergin translation (Cornell, 1944) and secondary summaries (Stanford Encyclopedia of Philosophy, IEP, Britannica, EBSCO Research Starters). Works cited directly by title and date: *De nostri temporis studiorum ratione* (1708/1709), *De antiquissima Italorum sapientia* (1710), *Il Diritto Universale* in three volumes (*De uno universi juris principio*, 1720; *De constantia iurisprudentis*, 1721; *Notae*, 1722), the three editions of the *Scienza Nuova* (1725, 1730, 1744), and *De mente heroica* (1732). Geography verified stop-by-stop: birthplace and baptismal parish on Via San Biagio dei Librai / San Gennaro all'Olmo, the Palazzo Vargas at Vatolla (now a Vico museum, coords confirmed), the Palazzo dei Regi Studi (the university seat from 1616, today the Museo Archeologico Nazionale di Napoli — this resolved what could have been a vague "university" pin into an actual, checkable building), the Palazzo Reale for the 1734 historiographer appointment, and the Girolamini church and its documented fourth-chapel tomb plaques. The frontispiece (*dipintura*) and the funeral dispute are both independently attested anecdotes (JHU/Jscholarship article on the frontispiece; Villarosa's 1818 continuation to the Vita on the funeral). The two edge stops draw on Vico's own Dante fragment (*Giudizio sopra Dante*) and on Borges's *Historia de la eternidad* (1936, essay "El tiempo circular").

## Judgment calls
- **Only two direct quotes.** I deliberately used *verum et factum convertuntur* (the four-word Latin formula, extremely stable across all scholarship) and the single Bergin-Fisch sentence on the civil world "made by men" (§331, the single most-reproduced line in Vico studies) — both quotes I could stand behind with confidence. Everywhere else I left `quote: null` rather than reconstruct 18th-century translated prose from memory. This is the more conservative choice than most siblings in the corpus, and an honest one: most of Vico's biography comes from a single narrative source (the Vita) whose exact period-translation wording I did not want to risk misquoting.
- **Day-level dates are mostly placeholders.** Vico's own Vita gives ages and years, rarely days. Where no day is attested (the fall, the baptism, most Vatolla and Naples stops) I assigned a plausible month/day and marked the stop `traditional` or `inferred` rather than `attested`, reserving `attested` for dates with real documentary anchors (18 October 1708 for the *De ratione* oration; 20 October 1732 for *De mente heroica*; 23 January 1744 for the death).
- **The doctorate (1694) sits inside the Vatolla segment**, not the schooling segment, because Vico earned it during a return trip to Naples while still resident at the castle (1686-1695) — geographically a Naples stop, narratively still "Vatolla years."
- **The historiographer-royal date is marked `inferred`**: sources split between 1734 and 1735; I committed to 1734 (more commonly cited) rather than manufacture false certainty.
- **One deliberate time-fold**: the closing segment, "The Register Itself," runs 1730 (Dante) → 1744 (Vico's own mature statement) → 1936 (Borges, Buenos Aires) — a 200-year jump the corpus otherwise avoids, justified because these are the edges the curator explicitly asked for: the register statement, Dante, Borges.

## Gaps
No verified quote for the fall itself, the schoolroom quarrel, or the funeral dispute in Vico's or witnesses' own words — all are narrated in indirect free style rather than quoted, per the "null is honest" rule. The 1688 "trial of the freethinkers" stop is well-attested Neapolitan intellectual history but is placed at Vatolla by inference (Vico would have heard of it there, not witnessed it) rather than by a specific attested letter.

## The five richest episodes
1. **The fall from the ladder** — the seven-year-old's five hours unconscious, the surgeon's death-or-idiocy prophecy, and Vico's own retrospective claim that the injury made the philosopher's melancholic temperament.
2. **The castle library at Vatolla** — nine years of tutoring two boys by day and reading Plato, Tacitus, Bacon, and Grotius alone by candlelight, quietly assembling the New Science decades before it has a name.
3. **The ring sold to print the first Scienza Nuova (1725)** — an act of pure conviction with no institutional backing, this is Vico's own version of an oath or ordeal.
4. **The dipintura** — Vico spending eighty pages explaining his own frontispiece, image by image, as if the whole science could be compressed into a single emblematic engraving: the closest this rationalist-mystic ever comes to a vision.
5. **The silent bier** — professors and confraternity both walking away from an unburied coffin over a point of precedence, an almost too-perfect closing irony for a philosopher of civil institutions and their discontents.

## Connections in the atlas (as written)
Vico is explicitly framed by the curator as "the atlas's own theorist" — the closing segment makes that literal: his claim that a nation's myths are "the first, plain, unmetaphorical history" a people could tell of itself is, word for word, the operating principle stamped into every sibling file's `register` field. Where Aeneas, Joan, and the rest *are* the myth narrated as true, Vico is the one traveler in the corpus who *theorizes* why that narration is the right one — poetic wisdom as the root of every fable-keeping people, corsi e ricorsi as the shape every one of these journeys' surrounding civilizations rises and falls in. The Dante stop reaches sideways toward any future Dante or Homer journey in the fleet; the Borges stop is the corpus's first explicit 20th-century echo-chamber, and could anchor a future Borges-adjacent addition (a `borges.journey.json` already exists in the directory but does not currently cite Vico — a natural cross-reference to add later). Geographically this is one of the atlas's most compact journeys: every stop but one sits inside a single square kilometer of old Naples or a hill town a hundred kilometers south, a small, honestly rendered geography for a life whose real distances were all traveled inward.

---

## Verification pass, 2026-07-24

**Result: repaired in place. 40 stops, 9 segments, 3 quoted. `json_check.py` exits OK with zero WARN lines** (parses, required keys present, chronology within every segment, all campa 60-110 words, quote/quote_source paired, lat/lng numeric and in range).

### 1. Structure
Checked against `joan_of_arc.journey.json`: same top-level key set and per-stop key set, same value vocabulary. Two fixes: the stop "The claim: myth is the true history of the nations" was missing `date_confidence` in its normal position (the key sat after `campa`) and is now in canonical order; the `register` field used an em-dash variant and is now `"national mythology: the canon is true"`, matching the canon file and the plurality of the fleet. Stop count rose 39 to 40 (see §5).

### 2. Dates and confidences
Chronology is monotonic inside every segment. Segments 6 ("The New Science", 1725-1732) and 7 ("The Life Written to Order", 1725-1731) overlap, and segment 9 ("The Register Itself") folds 1729 to 1939 — both deliberate thematic braids, kept.

Confidences tightened where the researcher had marked an invented month/day as `attested`:
- 1686 arrival at Vatolla: `attested` to `traditional` (the nine-year tutorship is the Vita's own account; Nicolini and later scholarship redate the arrival, often to 1689).
- 1694 doctorate: `attested` to `inferred`, and the campa now says outright that the conferring university is disputed (Naples vs. Salerno — Italian scholarship favours Salerno, c. 1693-94). The `suggested_ref` claiming "University of Naples doctoral records" was removed as a citation that does not exist in that form.
- 1699-06 marriage, 1725-10 (three New Science stops), 1725-06 (Vita begun), 1744-07 (third edition): `attested` to `inferred` — the years are documented, the months are editorial.
- 1744-01-24 funeral dispute and 1744-01-26 burial: `attested` to `traditional` (both rest on Villarosa's 1818 continuation, not on a register entry).
- 1723 competition: upgraded with a real date, 24 April 1723 (sessions of 24 March and 24 April), and the winning rival named: Domenico Gentile.
- 1734 historiographer royal: left at 1734 / `inferred`. English Wikipedia and IEP give 1734, Italian Wikipedia gives 1735; the split is real and the confidence flag carries it.
- The traveler is long dead; the file ends at his posthumous reception, as it should.

### 3. Coordinates (all 40 re-checked, 8 distinct sites; 7 moved)
| site | was | now | source |
|---|---|---|---|
| Naples home/bookshop (25 stops) | 40.8493, 14.2585 | 40.8495, 14.2580 | centreline of Via San Biagio dei Librai |
| San Gennaro all'Olmo | 40.8497, 14.2578 | 40.8496, 14.2583 | it.wiki 40°50′58.49″N 14°15′29.84″E |
| Jesuit schools | 40.8478, 14.2544 | 40.8467, 14.2570 | Gesù Vecchio / Collegio del Salvatore, 40.846737, 14.257013 — the old pin was ~280 m off, in the wrong block |
| Vatolla (3 stops) | 40.2821, 15.0276 | 40.2825, 15.0264 | it.wiki 40°16′56.96″N 15°01′35.15″E |
| Palazzo degli Studi (5 stops) | 40.8531, 14.2508 | 40.8536, 14.2506 | MANN 40°51′13″N 14°15′02″E; confirmed the building housed the university until 1777, so it is the right seat for 1699-1741 |
| Palazzo Reale | 40.8355, 14.2487 | 40.8361, 14.2493 | it.wiki 40.836136, 14.249283 |
| Girolamini | 40.8508, 14.2582 | 40.8519, 14.2585 | it.wiki 40.851929, 14.258482 — old pin ~125 m south of the church |
| Buenos Aires | -34.6037, -58.3816 | stop removed | see §5 |

### 4. Quotes
Six checks run against three quoted lines and three quote-shaped claims in campa.
- **`Verum et factum convertuntur` replaced.** The Latin actually printed in *De antiquissima* ch. 1 is a longer clause (`Latinis verum et factum reciprocantur, seu ... convertuntur`); the four-word form is a scholarly compression. Swapped for **`Verum esse ipsum factum.`**, which Wikiquote and SEP both carry verbatim from the 1710 work, with `quote_source` reduced to the work and year.
- **§331 restored to the Bergin-Fisch wording.** The file had a truncated, subtly re-punctuated fragment. Now the full sentence from "But in the night of thick darkness..." with `trans. Bergin & Fisch` in the source line.
- **"Muratori's Raccolta" was wrong on both counts.** The Vita's first part appeared in **volume 1** (Venice, 1728) of the *Raccolta d'opuscoli scientifici e filologici* begun that year by **Angelo Calogerà**, printed alongside Porcìa's own *Progetto ai letterati d'Italia*. Muratori removed, stop renamed, campa and refs rewritten.
- **"seven inaugural orations survive"** corrected to **six** (1699-1707); the seventh oration is *De nostri temporis studiorum ratione* itself, which the next stop already says.
- **"struck, strikes back"** at the Jesuit school removed — the Vita reports an unjust demotion and Vico's walking out, not a blow exchanged. Campa now names the actual school (Collegio del Salvatore at the Gesù Vecchio) instead of "Jesuit and Piarist schools".
- **"three of his eight children died in infancy"** softened to a claim I could carry (eight children, not all surviving childhood); the "three" is unverified in the sources reachable here.
- Two further un-carried claims corrected: the 1699 stop's "competition oration, revised across decades" (replaced with the actual first inaugural oration of October 1699), and the burial's "fourth chapel on the right ... beside his wife Teresa Caterina Destito" (the attested marker is a plaque along the colonnade between nave and left aisle; the old Naples guides place the body in the hypogeum beneath the chapel of Sant'Agnese; no evidence for the wife's plaque).

### 5. The Borges stop failed verification and was replaced
The closing stop claimed Borges "gathers Vico among the philosophers of eternal return" in *El tiempo circular* (*Historia de la eternidad*, 1936). Two independent checks contradict this: the essay's own roll of thinkers is Plato, Nietzsche, Hume, Russell, Heraclitus, Poe, Marcus Aurelius, Shelley — no Vico — and the essay is dated 1943 in the reference literature, not 1936. Rather than debunk the reception (the point of the stop is sound: Vico's wheel outlives him), the stop was replaced by **two stops that verify cleanly**:
- **Michelet in Paris, 1827** — *Principes de la philosophie de l'histoire, traduits de la Scienza nuova de J.-B. Vico*, Paris, Jules Renouard (Internet Archive catalogue records confirm the 1827 first and the 1835 *Oeuvres choisies* reprint). This is the actual hinge of Vico's fortunes, and it belongs in the atlas.
- **Finnegans Wake, 4 May 1939** — pinned to Faber and Faber, 24 Russell Square, London (simultaneous Viking issue in New York), quoting the opening sentence exactly: "riverrun, past Eve and Adam's, ... by a commodius vicus of recirculation back to Howth Castle and Environs." Joyce's four-part structure on Vico's cycle is attested, and the pun on the name makes this the strongest register-edge in the file.

Stop count 39 to 40, quoted 2 to 3. Nothing mythic was removed: the fall from the ladder, the surgeon's prophecy, the sold ring, the dipintura's providential ray, the silent bier, all stand as canon, with their confidences (not their content) carrying the uncertainty.

### 6. Campa
All 40 pass 60-110 words, present tense, register intact. The rewritten campas (Jesuit school, Vatolla library, doctorate, 1699 chair, marriage, orations, 1723 defeat, Porcìa, Calogerà, funeral, burial, Michelet, Joyce) were composed to the same measure. One substantive enrichment beyond the corrections: the Vatolla library stop now names **the convent library of Santa Maria della Pietà** alongside the castle's own books, since Italian sources give the convent as the reading room that actually mattered.

### 7. Not raised to stops (considered, left out)
Vico's imprisoned son Ignazio, and the *Life of Antonio Carafa* (1716) that first sent him to Grotius — both real and both tempting, but at 40 stops the file is inside the target band and neither could be pinned to a checkable place and date without more source work than this pass allows.
