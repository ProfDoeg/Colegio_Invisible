# Odysseus (Ulysses) — The Homeward Voyage: research report

**Canon:** Homer, *Odyssey* (8th c. BC), taken as true and narrated as such. The stops ARE the epic's stations; every stop is marked `traditional`, and coordinates are the *ancient/traditional* identifications, not literal history. 31 stops in 9 named segments (legs named as the tradition names its acts: the *nostos* from Troy, the wanderings, the descent, the strait, the cattle of the Sun, Calypso, the Phaeacians, Ithaca).

## Sources
- **Homer, *Odyssey*, Books 1, 5–24** — the primary and only narrative canon. Quotes drawn from Books 1, 5, 6, 9, 11, 12, 14, 16, 17, 19, 21, 22, 23, 24, cited by book+line in the Greek numbering, with translator noted (Fagles, Kline, or paraphrase where I compressed a passage — flagged in `quote_source`).
- **Wikipedia, *Geography of the Odyssey*** — the consolidated map of ancient identifications, itself sourced to Strabo (1.2), Polybius, Thucydides (6.2.1), Herodotus, Pausanias, and Eratosthenes.
- **Strabo, *Geographica* 1.2** — the ancient authority who fixed most stations to real Mediterranean places (Djerba, Sicily/Etna, Lipari, Monte Circeo, Messina, Gozo, Corcyra).
- **Victor Bérard, *Les Phéniciens et l'Odyssée*** — the modern systematizer of the "western Mediterranean" reading (Laestrygonians at Bonifacio, Circe at Circeo, Sirens on the Lucanian/Sirenuse coast).
- Supporting: `poetryintranslation.com` (Kline), SparkNotes and Theoi for line-location of the bed and Argos passages, Wikipedia *Outis* and *Argos (dog)*.

## Judgment calls
- **Geography is contested; I used the majority ancient identification and said so.** Where the tradition splits I picked the best-attested and noted the rival in `suggested_refs`/`sources`: Sirens = Sirenuse/Li Galli (with Strabo's Cape Faro alternate); Ogygia = Gozo (Strabo) not Bérard's Gibraltar; Underworld = Acheron Nekromanteion in Epirus (with Avernus as the Campanian rival); Laestrygonians = Bonifacio/N. Sardinia (Bérard).
- **Dates are all `traditional`/inferred.** I anchored the fall of Troy at the Eratosthenic-conventional 1184 BC and spread the ten years across `-1184` to `-1174`, ending the poem's action in 1174. These are ordering devices, not claims; the whole journey is legendary.
- **The "seven years" fold.** Calypso holds him seven years, yet the wanderings proper occupy only the first months after Troy. I placed the raw wanderings in 1184, Ogygia across 1183–1174, so the arithmetic of "twenty years gone" (ten at war + ten returning) holds on the timeline.
- **Ithaca is over-weighted (6 → now 7 stops).** Deliberate: the *nostos* climax is half the poem. I split it into the discrete recognitions the tradition itself dwells on (Eumaeus, Telemachus, Argos, the scar, the bow, the slaughter, the bed, Laertes).
- **Quotes:** null only where the canon records no direct speech (Goat Island, the two wreck-drift beats). Several long speeches are marked "(paraphrase)" where I condensed for length — the register stays Homer's.

## The tradition's own folds and gaps
- **The poem is not linear.** Books 9–12 are Odysseus narrating his own past at Alcinous's feast — the wanderings are a tale-within-the-tale. I flattened them into forward chronology (the natural itinerary shape) but the Phaeacian court is where they are *spoken*.
- **No fixed map exists.** Ancient and modern scholars are openly divided on whether anything between Ismarus and Ithaca is real. The atlas honors this by marking every coordinate `traditional`.
- **The Telemachy** (Books 1–4, Telemachus's own voyage to Pylos and Sparta) is a separate journey and is excluded; only Odysseus's track is charted.

## The five richest episodes
1. **The Cyclops' cave** — the "Nobody" pun, the burning olive-stake, the ram escape, and the fatal boast that earns Poseidon's curse: the engine of the whole return.
2. **The Underworld** — the trench of blood, Tiresias's whole-poem prophecy, the mother who slips thrice through his arms, Achilles preferring a serf's life to kingship of the dead.
3. **Sirens / Scylla / Charybdis** — the mast-binding and beeswax; then the six men lifted writhing overhead, calling his name — Homer's own "most pitiable" sight.
4. **Calypso and the refusal of immortality** — seven years, godhood offered and declined for the smoke of his own hearth: the poem's thesis on mortality and home.
5. **The bed of the olive-tree** — the recognition token rooted in living wood; the one secret no impostor could know, that finally breaks Penelope's guard.

## Connection to the atlas
This is the **archetype every journey in the atlas descends from** — the *nostos*, the structured return-through-trials. It rhymes directly with **Aeneas** (the sibling epic itinerary, same TRUE-canon register, the Mediterranean recharted westward toward a founding) and with **Moses** and **Jesus** (canon narrated as fact, the miraculous as event). Its descent to the dead prefigures every katabasis in the collection; its "trials in named stations" is the literal template the Goethe *Italian Journey* and the modern travelers secularize. Ithaca is the terminal form of "home" that Bolívar, Belgrano, Columbus and the exiles are all, in their register, sailing toward.

---

## Verification (2026-07-05)

Structural and canon-fidelity pass. Nothing debunked; the marvels stand.

**Schema.** JSON parses (python `json.load`). Top-level keys (`traveler, title, years, calendar, register, segments`) and every stop-key shape (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match the sibling `joan_of_arc.journey.json` exactly. 31 stops in 9 segments — within the 30-45 target, so no stops added; the Odyssey's remaining material (the Telemachy's Nestor/Menelaus) belongs to Telemachus, not to Odysseus's own nostos, and was rightly left out.

**Dates / confidence.** All 31 dates sort chronologically as julian_bce (−1184 earliest → −1174 latest; verified by numeric sort). All confidences are `traditional` — the honest label for a wholly legendary itinerary anchored to the Eratosthenic 1184 BC fall of Troy; there are no real-world attested anchors to mark otherwise, and Odysseus is not a living person, so no present-day terminus applies.

**Coordinates.** Web spot-checked 10 stops against the majority ancient/traditional identification; all sound, none moved:
- Troy/Hisarlık 39.957, 26.239 — correct.
- Lotus-Eaters / Djerba (Meninx) 33.807, 10.845 — island interior, ~5 km off town centroid; fine.
- Cyclops cave / Aci Trezza (Faraglioni dei Ciclopi) 37.556, 15.161 — matches 37.564, 15.162.
- Aeolia / Lipari 38.483, 14.950 — correct for the Aeolian group.
- Laestrygonians / Bonifacio 41.212, 9.407 — loosest of the set (Bonifacio town is 41.387, 9.159); coordinate sits in the strait toward Sardinia. Left in place: Bérard's Laestrygonian harbour is itself a contested western reading, and the point is defensibly within the identified zone.
- Circe / San Felice Circeo 41.240, 13.089 — matches 41.237, 13.094.
- Nekromanteion of Acheron 39.236, 20.535 — exact (39.236, 20.534).
- Scylla & Charybdis / Strait of Messina 38.250, 15.633 — matches 38.241, 15.626.
- Calypso / Gozo (Calypso's Cave) 36.046, 14.239 — ~3 km from the cave at 36.060, 14.276; fine.
- Ithaca cluster 38.42-38.44, 20.68-20.72 — within Ithaki island (38.37, 20.72).

**Quotes.** Spot-checked 6 against the canon: the Fagles proem (1.1-2) verbatim; Achilles "I'd rather slave on earth… over all the breathless dead" (11.489-491, Fagles) verbatim; the Cyclops naming-taunt (9.502-505) a faithful rendering; the bow-and-swallow simile (21.406-411) faithful; Calypso (5.215-220) and Nausicaa (6.160-169) both in register. Paraphrases (Kline/Fagles) are honestly flagged as such. The two null quotes — Goat Island (9) and the Cimmerian grove of Persephone (11) — are genuinely speechless scene-settings; correctly left `null` rather than invented. No quote repairs required.

**Campa (repaired in place).** The researcher reported "5 entries 116-118 words"; a full recount found **15** entries over the 110-word ceiling (111-118). All 15 were trimmed by cutting redundancy, not imagery — the great episodes (Polyphemus, the Descent, Scylla, Thrinacia, Calypso, the bed, Laertes) keep their vividness. Post-repair all 31 campa fall within 60-110 words (range 92-110), present tense and register preserved. Re-validated: JSON parses, 31 stops / 9 segments intact.

**Verdict.** Canon-faithful and structurally sound. Only substantive repair was the systematic campa over-length; coordinates, dates, quotes, and confidences all pass as written.

## Pin stitch — 2026-07-13
Connectivity audit: same-site pins normalized to weld the hard pin-lattice (atlas convention: shared sites byte-identical). Troy (the horse and the sack, -1184-06-01) repinned 39.957,26.239 → 39.9576,26.2389 to byte-match aeneas's citadel stop of the same date — the two epics now stand on one coordinate.
