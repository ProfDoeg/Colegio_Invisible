# Dante Alighieri: Florence to the Empyrean — report

**45 stops, 8 segments, 30 quoted, span 1265-1321 (Florence to Ravenna, plus the Commedia's own internal itinerary of Good Friday to Easter Wednesday, 1300).**

## Sources
Biographical spine: Leonardo Bruni's *Vita di Dante* (the earliest source for the Campaldino letter and the "origin and cause of all my ills" line about the priorate), Boccaccio's *Trattatello in laude di Dante* (death, burial, the hidden-cantos miracle, the Gemma Donati silence), Dino Compagni's contemporary *Cronica*, and Giovanni Villani's *Nuova Cronica*. Documentary anchors verified this session: the 27 January / 10 March 1302 sentences, the 8 June 1302 San Godenzo pact, the 6 July 1295 guild matriculation, the 6 October 1306 Peace of Castelnuovo (Dante's actual power-of-attorney as Malaspina procurator, drawn by notary Giovanni di Parente di Stupio), the 20 January 1320 *Quaestio de aqua et terra* at Sant'Elena, and the September 1321 Venice embassy and death. The Commedia itself (Inferno, Purgatorio, Paradiso) is the primary canon for the whole final third of the file, cross-checked against the traditional chronology (Good Friday 1300 entry, Easter Wednesday exit) that most modern editions print.

## Judgment calls
- **The dark wood has no fixed site.** Commentators have proposed Florence's own hills, the Casentino near San Benedetto in Alpe (Dante's own 1302 exile route, celebrated for the Acquacheta falls of Inferno XVI), and even the Sibillini mountains; none is canonical. I pinned it to Florence itself — the pilgrim is explicitly a Florentine and most illustrated traditions (Botticelli's map among them) start the itinerary there — and said so plainly in the campa rather than pretending certainty.
- **The vertical cosmology, made literal.** Per Dante's own geography (Inferno XXXIV, Purgatorio II, and the *Quaestio*), Hell's funnel bottoms out at the earth's center directly beneath Jerusalem, and Mount Purgatory rises antipodal to it in the southern ocean, the land Lucifer's fall displaced. I pinned every Inferno interior stop to Jerusalem/Golgotha (31.7784, 35.2298) and every Purgatorio/Paradiso stop to that point's exact antipode (-31.7784, -144.7702) — a real Pacific coordinate, matching the curator's instruction almost to the letter. This mirrors how `muhammad.journey.json` pins the entire seven-heaven Mi'raj to the single Jerusalem launch coordinate rather than inventing celestial lat/lngs.
- **Paradiso is compressed.** Ten heavens (Moon, Mercury, Venus, Sun, Mars, Jupiter, Saturn, Fixed Stars, Primum Mobile, Empyrean) are folded into three stops — Mars/Cacciaguida, Fixed Stars, Empyrean — to stay inside the 30-45 budget while giving the poem's true climax (the exile prophecy, the look back at earth, the final vision) full weight. This is the same proportion-by-importance move `ulysses.journey.json` made with Ithaca.
- **Quotes drawn from memory of a 700-year-old public-domain text.** Every Commedia and Vita Nuova line quoted is centuries out of copyright, so full lines are used freely (unlike the Borges file's copyright caution). I flagged authorship uncertainty explicitly where scholarship disputes it: the Epistle to Cangrande's authenticity is contested by some Dantisti, and Dante's own authorship of his tomb epitaph is traditional, not certain — both noted in `quote_source`. A handful of quotations (Farinata's rising, Currado Malaspina's scene, St. Peter's examination) were judged too uncertain to render as exact lines from memory and were either swapped for a more secure adjacent line or left `null` rather than risk misquotation; a philological pass against a critical edition (Petrocchi) is recommended before this file is treated as citation-grade.
- **Gemma Donati's marriage date is soft** (traditional c. 1285, some scholars prefer earlier); it is placed before Campaldino to keep the segment chronological, which required moving it out of natural narrative position in a first draft (caught and fixed by `json_check.py`).

## Gaps and time-folds
- The Commedia's own three-day-to-four-day fictional itinerary (8-14 April 1300, Julian) runs concurrent with, and long after, the real biographical years it is embedded chronologically after in this file — a deliberate structural fold, not an error: the poem is dated *within the story* to 1300, but written 1304-1321, so it sits at the file's end, matching the sibling convention (see `muhammad.journey.json`'s Mi'raj placed at its point in the life, not at composition date).
- Bologna's exact years (1304-1306) and Lucca's (c. 1314) are scholarly consensus ranges, not fixed dates — marked `inferred`.
- The Convivio and De Vulgari Eloquentia are both unfinished works; the file uses their composition, not completion, as the datable event.

## The five richest episodes
1. **Farinata's tomb in the City of Dis** — a dead Ghibelline enemy rising from his own flaming sepulcher to demand Dante's lineage while, beside him, Cavalcante de' Cavalcanti begs news of his living son: politics and grief sharing one grave.
2. **Cacciaguida's prophecy (Paradiso XV-XVII)** — Dante's own ancestor, from inside a cross of Martian light, tells him outright what the whole poem has been circling: exile, another man's stairs, another man's salt bread, and the loneliness of a party of one.
3. **Ugolino at Poppi** — the single richest time-fold in the file: Dante composes the Tower of Hunger's cannibal-grief canto as the guest of Ugolino's own daughter, in the very castle where her father's rival house never reached him.
4. **The finding of the last thirteen cantos** — Boccaccio's own marvel, narrated as fact per the register: Jacopo's dream-visitation, the wall recess behind the straw mat, the poem completing itself from beyond the grave.
5. **The Empyrean** — the white rose, Bernard's prayer, and the poem's own last line, closing a structure that opened in a dark wood nobody can find on a map.

## Connections to the atlas
- **ulysses.journey.json** — direct textual splice: Inferno XXVI's Ulysses tells his *own* last voyage, past the Pillars of Hercules, to the mountain and the whirlwind — the same mariner, a wholly different ending than Homer's Ithaca, cross-referenced in `suggested_refs`.
- **borges.journey.json** — Borges's *Nueve ensayos dantescos* and the Asín Palacios thesis (Attar's Simurgh, Ibn Arabi's Mi'raj, both read against Dante's cosmology) are the edge the curator named; this file is the missing anchor those essays were always pointing at from outside.
- **muhammad.journey.json / ibn_arabi.journey.json** — the Mi'raj and the *Isra* are the Islamic counterpart to the Paradiso's ascent through the spheres; both this file's Jerusalem/antipode geography and its single-coordinate-per-celestial-stage convention were built to sit consistently beside them.
- **aristotle** — no journey file for him yet, but Inferno IV's "il maestro di color che sanno" is the seed of one, sitting in Dante's own Limbo alongside Homer and the noble pagans.
- **virgil** — no journey file for him yet either; he is the poem's own guide-character throughout Inferno and Purgatorio, vanishing wordlessly the instant Beatrice arrives, a role any future virgil.journey.json would have to reckon with directly.
- The libertadores/exile cluster (san_martin, miranda, alvear) and Joan of Arc share the file's other spine: a sentence of death in absentia, a life spent as "pilgrim, almost a beggar" through other men's courts, and a homeland that keeps a fire, or a stake, lit for the exile it will not let return.

---

## Verification pass — 2026-07-24

Independent structural and canon-fidelity check. `json_check.py` exits 0 with no WARN lines both before and after repair: 8 segments, 45 stops, 30 quoted. Top-level keys, per-stop keys, date_confidence vocabulary and campa word counts all match the `joan_of_arc.journey.json` reference. Register held throughout: nothing was debunked. The theophany (Beatrice in the Earthly Paradise), the vision of God, Boccaccio's dream-visitation of the missing cantos, Farinata's prophecy, and Lucifer at the world's centre all stand as told, marked `traditional` rather than trimmed.

### Coordinates corrected (13 stops)

Web-verified against Italian Wikipedia coordinate boxes and OpenStreetMap/Nominatim.

| Stop | Was | Now | Note |
|---|---|---|---|
| Campaldino, the cavalry charge | 43.7203, 11.7419 | 43.7376, 11.7526 | ~2.1 km off; corrected to the Piana di Campaldino by Certomondo, where the Colonna di Dante stands |
| Caprona, the surrender | 43.6975, 10.5825 | 43.7073, 10.5047 | was pinned on Vicopisano town, ~6 km east of Caprona itself |
| San Godenzo, the pact | 43.9269, 11.5911 | 43.9261, 11.6186 | longitude ~2.2 km off the Abbazia di San Gaudenzio |
| Lunigiana, Peace of Castelnuovo | 44.0928, 9.9814 | 44.0994, 10.0178 | ~3.1 km off Castelnuovo Magra |
| Casentino, Poppi Castle | 43.7239, 11.7717 | 43.7224, 11.7671 | onto the Castello dei Conti Guidi proper |
| Verona, Quaestio de aqua et terra | 45.4445, 11.0007 | 45.4476, 10.9970 | onto the Chiesa di Sant'Elena beside the Duomo |
| Venice, the embassy | 45.4408, 12.3155 | 45.4337, 12.3404 | was on the northern city, not the Palazzo Ducale where the Doge received him |
| Ravenna, the burial | 44.4171, 12.1975 | 44.4162, 12.2009 | onto the Tomba di Dante beside San Francesco |
| Priorate / Cavalcanti / both sentences (4 stops) | 43.7699, 11.2626 | 43.7704, 11.2583 | onto the Palazzo del Bargello, seat of the podestà who pronounced both sentences |
| Death of Beatrice | 43.7731, 11.2560 | 43.7712, 11.2573 | was on the Baptistery; moved to Santa Margherita de' Cerchi, the traditional site the stop's own `suggested_refs` names |
| Marriage to Gemma Donati | 43.7731, 11.2560 | 43.7717, 11.2578 | into the Donati/Portinari quarter |
| Charles of Valois and the Black coup | 43.7731, 11.2560 | 43.7694, 11.2558 | onto the Palazzo Vecchio, as the stop's own `suggested_refs` says |
| First sight of Beatrice | 43.7716, 11.2593 | 43.7714, 11.2570 | onto the Portinari houses by Santa Margherita |

Verified correct and left untouched: Rome/Lateran (41.8862, 12.5058), Forlì, Verona (Scaliger), Bologna, Lucca, Ravenna court, Florence birth and guild stops. The Jerusalem/Golgotha pin (31.7784, 35.2298) is the Holy Sepulchre exactly, and the Purgatory/Paradiso pin (-31.7784, -144.7702) is its true antipode to four decimals — the cosmology Dante argues for in the Quaestio, and the geometry the curator asked for. Both held.

### Quotes corrected (8)

- **Inferno X, 36** — read "com'avesse l'inferno **in gran dispregio**", a paraphrase. Canon is "com'avesse l'inferno **a gran dispitto**." Restored. (The researcher had flagged Farinata's wording as risky; it was indeed wrong.)
- **Purgatorio IX, 113** — "Fa che **lave**" corrected to "Fa che **lavi**."
- **Convivio I.iii.4** — the quote was a rearrangement of two separated clauses. Restored to the printed order: "per le parti quasi tutte a le quali questa lingua si stende, peregrino, quasi mendicando, sono andato, mostrando contra mia voglia la piaga de la fortuna."
- **Bruni on the priorate** — "l'origine e cagione di tutti i mali miei" was a modernised paraphrase. Restored to Bruni's text: "Tutti li mali e tutti gli inconvenienti miei dalli infausti comizi del mio priorato ebbono cagione e principio."
- **Bruni on Campaldino** — "temetti forte... grandissima letizia" is not the transmitted wording. Restored to the attested fragments ("ebbi temenza molta... e nella fine allegrezza grandissima"), with the ellipses and their fragmentary status stated in `quote_source`.
- **Paradiso XVII, 76-78** — "e con lui vedrai colui che 'mpresso **fu**" corrected to "Con lui vedrai colui che 'mpresso **fue**", and the tercet completed with line 78.
- **Vita Nuova II** — "**apparve a me** vestita" corrected to "**Apparve** vestita", and the sentence closed.
- **Inferno XXVI** — citation was 118-120 but the text began at 119. Line 118 ("Considerate la vostra semenza:") restored so quote and citation agree.
- **Inferno V** — citation 100-105 corrected to 103-105.

Spot-checked verbatim against Wikisource and found correct, left alone: Paradiso XXII 112-114 and 151, Paradiso XVII 58-60 and 70-72, Inferno XXI 94-96, Inferno XXXIII 75, Inferno XXXIV 1-3, Inferno IV 131-132, Inferno XIX 90-92, Purgatorio XXIV 49-51, Purgatorio XXVI 140-141, Purgatorio XXX 73, Purgatorio I 40-41, De Vulgari Eloquentia I.i, Epistola XIII §39, the tomb epitaph. No quote needed nulling — every one was carried, and every defect was a wording slip repairable against the canon.

### Dates and confidences

- **Marriage to Gemma Donati** carried an invented day, 1285-01-09, marked `traditional`. Nothing fixes the day; the tradition fixes only the year. Changed to 1285-01-01 / `inferred`.
- **The Gate of Peter** was dated 1300-04-10, but Dante sleeps in the Valley of the Princes and is carried to the gate by Lucia at dawn the following morning. Moved to 1300-04-11. The Commedia's internal itinerary now reads 7 April (dark wood) to 14 April (Empyrean) without a compressed day.
- **Forlì, 1303** — the campa said the war of return ended "the next year" at Puliciano. Puliciano falls in 1303, La Lastra in July 1304. Recast to name both without asserting a wrong year.
- All other dates check out: priorate 15 June 1300, first sentence 27 January 1302, second sentence 10 March 1302, San Godenzo 8 June 1302, Peace of Castelnuovo 6 October 1306, Quaestio 20 January 1320, death in the night of 13/14 September 1321, burial the 14th. Dante is not living; the file ends correctly at the tomb, and then at the poem.

### Structure

45 stops is the top of the target band, so nothing was added on count grounds. The eight-segment shape holds, including the deliberate fold that places the Commedia's April 1300 itinerary after the 1321 death — the poem's time, not the poet's.

One open door the original report listed has since closed: `aristotle.journey.json` and `plato.journey.json` now exist in the atlas. The Limbo stop's `suggested_refs` now cross-references both, matching the Ulysses edge already realised there. `virgil.journey.json` remains unwritten and remains the largest open edge in this file.

**Verdict: sound.** No canon was debunked, no confidence inflated. Thirteen coordinate fixes and eight quote fixes; the dataset now validates clean and cites accurately.
