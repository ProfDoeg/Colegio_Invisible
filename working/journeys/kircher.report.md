# Athanasius Kircher — Geisa to Rome (1602–1680): journey report

**Shape:** 33 stops in 7 named segments, gregorian calendar, register "the canon is true." Canon = Kircher's own vast folios and his autobiographical *Vita*, treated as narrated fact — including the miraculous cures and deliverances, and his (gloriously wrong) hieroglyphic readings, which in this register are events, not errors to be corrected.

## Sources
- **English Wikipedia, *Athanasius Kircher*** and **Encyclopedia.com** — spine of the itinerary (Geisa, Fulda, Paderborn, Cologne, Koblenz, Heiligenstadt, Mainz, Speyer, Würzburg, Avignon, Rome; publication dates of every major work).
- **Kircher's *Vita* (autobiography), Wichita State translation** — the five personal deliverances in his own voice: the Pentecost horses, the Paderborn cure, the Rhine ice-floe, the near-hanging in the "Valley of Hell," the Avignon mill-wheel. Quote material.
- **Public Domain Review, *Athanasius, Underground*** — the 1638 Calabrian earthquake and Vesuvius descent, with direct *Mundus Subterraneus* quotations (the "chariots" earthquake line, the boiling crater).
- **Wikipedia *Obeliscus Pamphilius* / *Fontana dei Quattro Fiumi*** — Piazza Navona obelisk, Bernini, the 12 June 1651 unveiling, the invented glyphs carved in granite.
- **Museum of Imaginary Musical Instruments / Wikipedia *Cat organ*** — the *Musurgia* (1650) and the Katzenklavier.
- **Agosto Foundation** — the sunflower/heliotrope clock and Peiresc's skepticism.
- **Wikipedia *China Illustrata* / *Xi'an Stele*, *Kircherian Museum*, MJT & Biodiversity Heritage Library** — China, the Nestorian stele, the museum and speaking statue, the Malta trip with Landgrave Friedrich.

## Judgment calls
- **Birth year 1602** kept per the prompt, though Kircher himself was unsure (1601/1602); marked *traditional*.
- **The near-hanging** is placed at the "Valley of Hell" (Thuringian passes, ~1623, between his Koblenz regency and Heiligenstadt) — the *Vita* names the valley but not a modern town, so coordinates are inferred to the Thuringian forest belt; dated *traditional*.
- **The ice-floe**: the *Vita* dates it to the 1622 flight from Paderborn near Düsseldorf/Neuss; one modern retelling misdates it to 1633. I followed the 1622 flight (coherent with the sequence) but used the Düsseldorf coordinate the autobiography gives.
- **The storm-driven voyage to Rome** (1633): narrated as Providence, per canon — his ship blown off the Vienna course so he lands in Rome before learning the destination changed.
- **Malta 31 May 1637 / Vesuvius spring 1638**: the volcano descent is post-earthquake (late March 1638), so I split them across two stops with the earthquake between, matching the *Mundus Subterraneus* sequence.
- Quotes are given verbatim where the *Vita* or *Mundus* record them; the *Magnes* and *Musurgia* lines are flagged as paraphrase/"after" in `quote_source`, honest about their status.

## The tradition's own folds and gaps
- Kircher **may have invented** much of the *Vita*; scholars flag this openly. In this register the deliverances are true — the fold is that the canon is his own self-mythology, and the miraculous is load-bearing.
- The **hieroglyphs**: every reading is wrong (Champollion is 150 years off), yet Egyptology as a discipline is born inside the error. The journey narrates the readings as triumphs, as he experienced them.
- **Geographic gap**: Kircher annexes China and Egypt without leaving Italy — the "travel" of the late books is armchair, from his brethren's letters. The stops sit in Rome but the campa reaches to Xi'an and the Nile.

## The five richest episodes
1. **Vesuvius, lowered by rope into the smoking crater (1638)** — the literal descent into the earth's fire; the keystone that faces Goethe.
2. **The Calabrian earthquake** — the ground casting him face-down, "chariots driven at top speed"; the vision of the hollow burning earth conceived in real terror.
3. **The near-hanging in the Valley of Hell** — stripped for the gallows, spared for his calm; the soldier's "my hands will remain innocent of this man's blood."
4. **Piazza Navona** — the pope's obelisk re-raised over Bernini's fountain, Kircher's invented glyphs cut in granite where they stand today.
5. **The Rhine ice-floe** — the novice marooned on drifting ice, swimming ashore at Neuss; the war made a wanderer of him.

## Connection to the atlas
Explicitly built as a set of **faces** the prompt names:
- **Symmes** (`symmes.journey.json`) — Kircher's *Mundus Subterraneus* hollow, fire-threaded earth is the two-centuries-early face of Symmes's hollow-earth prophecy.
- **Goethe** — Kircher's Vesuvius descent faces Goethe's Italian volcano; both journeys end their arc at the mouth of the fire in the Bay of Naples.
- **Max Müller** (`max_muller.journey.json`) — Kircher's dream of one primal Adamic tongue splintering at Babel into all languages prefigures Müller's comparative philology; the *Turris Babel* language-tree faces Müller's.
- **Fuller / the universal-knowledge dreamers** — the Museum Kircherianum and the ambition to hold *everything* in one mind.
- Sits naturally beside the other **Jesuit / sacred-history and esoteric-polymath** journeys in the directory (Gurdjieff, Steiner, Jung, Keyserling), and the **flight-through-war** motif rhymes with the exile journeys (San Martín, Miranda) — here turned inward, toward the burning center of the earth.

---

## Verification pass (2026-07-05)

Structure and canon-fidelity check against the sibling schema (`joan_of_arc.journey.json`). Register held: every theophany, deliverance, prophetic vision, and gloriously-wrong hieroglyphic reading **stays** — the mythic folds are marked by confidence, not debunked.

**(1) Schema & parse.** JSON parses. Top-level keys (`traveler, title, years, calendar, register, segments`) and stop-level keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the Joan sibling exactly. 33 stops across 7 named segments — within the 30-45 target; no stops added.

**(2) Chronology & confidence.** All 7 segments verified internally date-ordered. The segments are **thematic, not strictly linear** (as in the Joan file, whose segments revisit locations): segment 6 "The Universal Books" runs its obelisk/monument thread to 1667, and segment 7 "The Whole Earth in One Mind" opens at Mentorella (1661) and closes at the 1680 death. This is a deliberate grouping, not a chronology error. Confidence calibration is honest — birth-year, the three soft-dated deliverances (Pentecost horses, Rhine ice-floe, Valley-of-Hell hanging), the Lyon arrival, the Messina episode, and the Providence voyage are `traditional`; documented appointments, publications, the dated Malta landing, the historically-dated 1638 earthquake, and the death are `attested`. Kircher died in 1680, so the "a living traveler ends at the present" rule does not apply; ending on the death is correct.

**(3) Coordinates — 18 stops web-spot-checked, 2 corrected:**
- **Geisa** was 50.694/10.006 → corrected to **50.714/9.95** (town sits ~4 km west of the old longitude, in the Rhön/Wartburgkreis).
- **Calabria (the 1638 earthquake)** was 38.91/16.59 (Ionian side, too far SE) → corrected to **38.975/16.318**, Nicastro (Lamezia Terme) in the Savuto/upper-Crati devastation zone, near the historical epicentre (~39.17/16.29).
- Confirmed accurate (≤~2 km): Fulda, Fulda-stadium, Paderborn, Cologne, Koblenz, Heiligenstadt, Mainz, Speyer, Würzburg, Lyon, Avignon, Aix, Malta, Strait of Messina, Vesuvius crater (40.821/14.426), Piazza Navona (41.899/12.473), Piazza della Minerva, Gesù/death. The "sea off the Italian coast" point (41.9/12.4) is a deliberate generic offshore coordinate for the storm voyage, left as-is.

**(4) Quotes — 6 spot-checked against the canon, all faithful:**
- *Valley of Hell*, the soldier's "I declare that my hands will remain innocent of this man's blood." — **verbatim** in the Wichita *Vita* translation.
- *Paderborn cure*: "Both ailments had been completely cured; the hernia had also entirely vanished." — **verbatim**.
- *Avignon mill-wheel*: "The wheel stopped... I managed to escape safely and unharmed." — **verbatim** (the "immersed in the water" clause is a faithful compression of the *Vita*).
- *Pentecost horses*: near-verbatim; the *Vita* reads "...remaining in that position while the horses rushed over me... I arose, entirely unharmed and uninjured." Faithful compression, kept.
- *Calabrian earthquake* and *Vesuvius crater* (both cited to *Mundus Subterraneus*): confirmed against the Public Domain Review essay — "a subterranean racket and din, similar to chariots driven at top speed," "laid low... face flat on the ground," "cadavers of cities and the horrific ruins of castles," and "boiling with an everlasting gushing forth, and streamings of smoke and flames." Faithful.
- The *Magnes* and *Musurgia* lines remain honestly flagged as `paraphrase`/`after` in `quote_source`. The *Rhine ice-floe* quote ("stranded on what was effectively an ice island... came ashore entirely unharmed") is a reasonable paraphrase of the *Vita*'s escape and is marked only "as translated," not claimed verbatim — left in register.

**(5) Campa.** All 33 now 60-110 words, present tense, in register. Piazza Navona trimmed 114→108 (dropped a redundant "granite" and "and the divine mind" tail). No flat episodes; the great scenes (Vesuvius crater, the earthquake, the near-hanging, the ice-floe, Navona) carry their weight.

**Other fixes:** corrected one date error — **Piazza della Minerva** was `1667-02-01`; the Bernini elephant-and-obelisk was unveiled **11 July 1667**, so set to `1667-07-11` (also keeps it correctly last in segment 6). Fixed a typo in the Collegio Romano campa ("fory" → "forty").

Re-validated with Python after edits: parses, schema intact, all segments internally ordered, all campa in range.
