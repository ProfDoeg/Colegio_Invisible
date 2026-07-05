# Aeneas — The Aeneid, from Burning Troy to Latium

**35 stops in 7 segments; c. 1184–1180 BC (traditional); calendar julian_bce; every stop quoted (35/35).**

## Sources
The canon is Virgil's **Aeneid** (Books 1–12), read in the Latin (Perseus, Theoi, Dickinson College Commentaries) with cross-reference to English summaries (SparkNotes, LitCharts, CliffsNotes). Geography and modern site identifications were verified against the **Council of Europe's certified "Aeneas Route"** (aeneasroute.org), which fixes the canonical modern places — Antandros/Mt Ida, Ainos (Thrace), Delos, Knossos, the Strofades, Butrint, Castro/Castrum Minervae, Capo Colonna, Etna, Trapani, Carthage, Palinuro, Cuma, Gaeta, Lavinium — and against Wikipedia for Castro (Apulia) and Palinurus. Latin quotations were checked line-by-line against Perseus/Theoi.

## Judgment calls
- **Dates are traditional/inferred throughout.** I anchored the fall of Troy at the Eratosthenic 1184 BC and spread the "seven years' wandering" (3.1) forward, so the arrival in Latium lands c. 1180 BC. Month-level dates are narrative sequencing, not attestation — hence `date_confidence: traditional` for legendary sites and `inferred` nowhere here (every stop is canon-placed).
- **Coordinates are the real/traditional sites**, not open sea. For the two purely-maritime events (Neptune's storm; the sea off Sicily) I placed a plausible point on the traced route rather than invent a landmark.
- **Book order vs. travel order.** Aeneas narrates Books 2–3 as flashback inside Carthage (Book 1). I restored *travel* chronology: Troy → wanderings → Carthage → Sicily games → Cumae → Latium, so the map reads as an itinerary, not as Virgil's frame.
- **The underworld** (Book 6) is rendered as four stops clustered at Avernus/Cumae — the descent is a real place in the poem's geography (the Campi Flegrei), narrated as fact per the register.

## The tradition's own folds
- **The oracle misread**: Apollo says "seek the ancient mother"; Anchises reads Crete, the Penates correct it to Italy — a built-in false start that doubles the wandering. Kept as two stops.
- **Celaeno's curse of the tables** (3.255) is *fulfilled as blessing* at the Tiber mouth (7.116) — a deliberate long-range rhyme I placed at both ends.
- **Two Sicily landfalls** (Drepanum, Books 3 and 5) frame Anchises's death and funeral games a year apart; both are kept, correctly dated a year apart.
- A genuine gap: Virgil never dates anything. All temporal structure here is editorial, faithful to sequence but not to any calendar.

## The five richest episodes
1. **The last night of Troy** — Laocoön and the serpents, Hector's ghost, Anchises on the shoulders, Creusa lost (four stops; the poem's most-illustrated matter, Bernini and Barocci).
2. **Dido** — the murals of Troy, the cave, Mercury's command, and the **pyre-curse that names Hannibal** (`exoriare aliquis... ultor`).
3. **The descent** — the golden bough at Avernus, Charon, and Dido's *silent* shade turning away like Marpesian flint.
4. **Elysium's pageant of unborn Roman souls** — Anchises naming Rome's art (`parcere subiectis et debellare superbos`), the ideological heart of the whole atlas.
5. **The Harpies / Celaeno** — the eating-of-the-tables prophecy, whose payoff opens Latium.

## Connections in the atlas
This journey is the **keystone of the Roman arc**. Dido's curse is the explicit seed of **Hannibal** (already in the directory) — his oath at the Tophet answers her pyre; his Alps answer her `arma armis`. Anchises's prophecy of empire (`tu regere imperio`) is the charter that **Charlemagne** claims as *renovatio imperii* and that **Bolívar** inverts, founding republics against the imperial line. Aeneas carrying the Penates from a burning city rhymes with **Moses** and **Abraham** as founder-exiles bearing a god's charge to a promised land; his underworld descent is sibling to **Jesus** and to the mystery-initiations in **Gurdjieff/Jung**. Where Ulysses (Homer) wanders home, Aeneas wanders *forward* — the same eastern-Mediterranean sea, read as destiny rather than nostos.

---

## Verification (2026-07-05)

Independent structural and canon-fidelity pass. **Verdict: PASS**, with two coordinate corrections applied in place. The register was preserved throughout — no myth was debunked; theophanies, marvels, and the underworld descent all remain narrated as fact, and the tradition's folds (misread oracle, Celaeno's table-curse) stay marked by structure, not removed.

**(1) Schema & parse.** `aeneas.journey.json` parses cleanly. Top-level keys (`traveler, title, years, calendar, register, segments`) and the ten-key stop shape (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) are byte-for-byte identical to the sibling `joan_of_arc.journey.json`. 7 segments / 35 stops, as summarized.

**(2) Chronology & confidences.** All 35 stops sort chronologically both within each segment and globally, using correct julian_bce numeric ordering (−1184 earlier than −1180). Every `date_confidence` is `traditional`, which is honest for a wholly legendary/undated journey — Virgil dates nothing; the temporal scaffold is editorial and labeled as such. No living-person concern (the traveler is mythic; the poem correctly ends at Turnus's death, the canon's own terminus).

**(3) Coordinates.** Web-spot-checked 12 stops against actual/traditional sites. Ten were accurate to within a plausible margin: Troy/Hisarlik, Delos, Butrint, Castro/Castrum Minervae, Trapani/Drepanum, Byrsa/Carthage, Cumae, Capo Palinuro, Gaeta/Caieta, Strofades. **Two were corrected in place:**
- **Antandros** (39.5089, 26.7908 → **39.5758, 26.7906**): latitude was ~7 km south of the excavated site near Altınoluk; longitude was already right.
- **Tarentum/Lacinian headland** (38.9333, 17.1500 → **39.0242, 17.2026**): the point sat ~11 km out to sea, southwest of the named landmark; moved onto Capo Colonna / the temple of Hera Lacinia, which the stop's own `suggested_refs` name.

**(4) Quotes.** All 35 stops carry a quote (0 nulls). Spot-checked 8 against Perseus/Theoi/DCC, all faithful to the canon: `timeo Danaos et dona ferentis` (2.49, archaic *-is* preserved); `sunt lacrimae rerum et mentem mortalia tangunt` (1.462); `exoriare aliquis nostris ex ossibus ultor / qui face Dardanios ferroque sequare colonos` (4.625-26, Dido→Hannibal); `tu regere imperio populos, Romane... parcere subiectis et debellare superbos` (6.851-53); `monstrum horrendum, informe, ingens, cui lumen ademptum` (3.658); `vitaque cum gemitu fugit indignata sub umbras` (12.952, the true final line); and the Caieta epitaph `tu quoque litoribus nostris, Aeneia nutrix...` (7.1-2). The two non-verbatim quotes are honestly self-labeled in `quote_source`: the Book 5 Anchises-shade line ("paraphrased from 5.724ff" — its opening `Nate, mihi vita quondam, dum vita manebat, / care magis` is in fact verbatim 5.724-25, then compressed) and the ellipsis-joined games fragment. No paraphrase is passed off as verbatim.

**(5) Campa.** All 35 present-tense, in register, and within the 60-110 word band (measured range 80-108). The great episodes — the flight from Troy, Dido's pyre-curse, the descent and Dido's silent shade, Elysium's pageant, the fall of Turnus — are full and not flat.

**(6) Count.** 35 stops sits inside the 30-45 target; no additions needed.

No further changes. JSON re-validated after the two coordinate edits.
