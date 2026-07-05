# François Delsarte — Solesmes to Paris (1811–1871)

**Journey file:** `delsarte.journey.json` — 7 segments, 23 stops, 12 preserved quotes. Calendar: gregorian. Register: the Delsartean canon (the disciple-transmitted System) narrated as true; his observations, discoveries and demonstrations placed and dated as events.

## Sources
The primary canon is **disciple-transmitted**, since Delsarte never published. Core texts used:
- *Delsarte System of Oratory* (Delaumosne & Angélique Arnaud, tr. Frances A. Shaw / Abby Alger; Werner, 1887) via Project Gutenberg #12200 — supplies the biographical note (1822 porcelain apprenticeship, 1825 Conservatoire, ruined voice) and most verbatim aphorisms.
- **Genevieve Stebbins**, *Delsarte System of Expression* (1885) and the *Address before the Philotechnic Society of Paris* (delivered at the Sorbonne; manuscript obtained from Delsarte's widow) — the one whole lecture in his own words.
- Dartmouth's *François Delsarte* project (journeys.dartmouth.edu) — life/technique/impact pages.
- "Rick On Theater" (2014) long-form biography — observation anecdotes, pupils, Legion of Honor, Sorbonne 1867, death "ill, broken, out of fashion."
- Wikipedia (Delsarte, Steele MacKaye, Bizet, Siege of Paris), the Philippy-Bucelly-d'Estrées genealogy blog (marriage 4 June 1833; Bizet kinship), delsarteproject.com.

## Judgment calls
- **Coordinates.** Delsarte's exact studio/salon address is not preserved in the sources found, so studio/salon stops use plausible Right-Bank points near the Conservatoire/Opéra-Comique quarter, flagged `traditional`/`inferred`. Solesmes, the Conservatoire, Opéra-Comique (Salle Favart), Tuileries, Sorbonne, Montmartre cemetery are real coordinates.
- **The frozen-brother legend.** The prompt's "brother frozen to death in his arms" is the darker folk form; the documentable core is that mother and brother Louis both died in Paris leaving François alone. I narrated the death and *named* the legend without asserting the mechanism as fact ("whether fever or frost").
- **Dates.** Only anchored events are `attested` (birth 19 Nov 1811; apprenticeship 1822; Conservatoire 1825; marriage 4 Jun 1833; course opens May 1839; MacKaye Oct 1869–Jul 1870; siege begins 19 Sep 1870; death 20 Jul 1871; Stebbins 1885). The observation years and doctrine-formation stops are `traditional`/`inferred` with representative years.
- **Bambini / the starving apprentice** kept as `inferred` — the professor Bambini who opened the Conservatoire door is attested; the near-poisoning from hunger is the tradition's coloring.

## The tradition's own folds and gaps
- **The unpublished system** is the central fold: everything survives at one or two removes (Delaumosne, Arnaud, MacKaye, Stebbins), each adding — Stebbins/MacKaye grafted on "harmonic gymnastics" Delsarte never taught. The "canon" is genuinely a transmission, not an autograph.
- **Burial** is contested in some sources (Montmartre vs. Montparnasse); I used Montmartre per Wikidata/Wikipedia.
- Few of his exact words survive; `quote: null` is used honestly where the tradition preserves only paraphrase (the flight from the North, the asylums/graveside, the salons, the death-siege).

## The five richest episodes
1. **The Tuileries nurse and the child's thumb** — the founding observation: love spreads the infant's thumb from the hand; the true mother's clasp shows it, the hired nurse's never does. The whole Law of Correspondence in one sign.
2. **The ruined voice at the Conservatoire** — the wound that converts singer into scientist; "that loss happy, which gave the world its first law-giver."
3. **The watcher of the dying, the mad, the grieving** — hospital wards, asylums, gravesides: the empirical census of Paris from which the constant law is distilled.
4. **The Sorbonne / Philotechnic address** — the one whole lecture; the scripture-in-his-own-voice, rescued via the widow's manuscript.
5. **MacKaye and the crossing to America (1871)** — the disciple lecturing in New York/Boston in March while the master dies in besieged Paris in July; doctrine outliving author by transmission.

## Connection to the atlas
Delsarte is a **root-node of the movement/expression lineage**. He faces forward to **Muybridge** (freezing gesture in the frame) and **Laban** (notating it) — named in the final stop — and to his American heir Stebbins, and stands beside the atlas's other bodies-of-technique and pedagogues. He shares the sibling territory of **Froebel** (the childless-then-universal pedagogue who systematizes an intuition, dies before full publication) and **Braille** (a French sensory-grammar that outlives its author by disciple-transmission). Geographically he is a **Paris journey** — Conservatoire, Opéra-Comique, Tuileries, Sorbonne, the 1870–71 Siege and Commune — overlapping the atlas's other Paris deaths and the Franco-Prussian rupture. Thematically: the **wound that founds a science** (the ruined voice), kin to any founder whose incapacity becomes doctrine.

---

## Verification pass (2026-07-05)

Structural + canon-fidelity audit against the sibling `joan_of_arc.journey.json`. Register preserved throughout — nothing debunked; the disciple-transmitted System stays narrated as canon, mythic folds (frozen brother, the thumb-law, the ruined-voice-as-vocation) kept and flagged by confidence, not removed.

**(1) Schema / validity.** Parses with `python -json`. Top-level keys, segment keys, and stop keys are byte-identical to the Joan sibling (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`). 7 segments, 23 stops — within the 20–35 target (low end but the canon is thin; Delsarte published nothing, so padding would mean inventing).

**(2) Chronology.** `gregorian`, so plain string-date sort. Found and **fixed** one within-segment reversal: in *Le Savant de l'Expression* the marriage (1833-06-04) sat after the 1834 hospital and 1835 asylum stops. Moved it to sit after the Tuileries observation (1833-05-01) and before the 1834 wards, so every segment is now internally chronological. The two remaining cross-segment "reversals" (America 1871-03 precedes the Siege 1870-09; both in different, thematically-parallel segments) are by design — the sibling Joan file has the same overlapping-segment structure. Confidences honest: real anchors `attested` (birth, apprenticeship, Conservatoire, marriage, course-opening, MacKaye, siege, death, Stebbins 1885), doctrine-formation and observation years `traditional`/`inferred`. Not a living person; journey correctly runs past the 1871 death to the 1885 legacy stop.

**(3) Coordinates — spot-checked 10+, all correct or defensibly representative:** Solesmes (50.1908, 3.4964 ≈ 50.186, 3.498 ✓), Conservatoire (48.8720, 2.3486 ≈ 48.872, 2.347 ✓), Opéra-Comique/Salle Favart (48.8709, 2.3378 ✓ Place Boieldieu), Tuileries (48.8634, 2.3275 ✓), Sorbonne (48.8489, 2.3431 ≈ 48.843, 2.339 ✓, within the Sorbonne block), Montmartre-cemetery Paris point, New York (40.7128, -74.0060 ✓), the flight-road waypoint (49.89, 2.30, Amiens on the Cambrai→Paris road ✓), plus the Paris-center and hospital-district points. No fixes needed. Studio/salon points remain inferred Right-Bank coordinates as flagged (exact address unpreserved).

**(4) Quotes — spot-checked 6+ against the canon.** Verified verbatim in *Delsarte System of Oratory* (Gutenberg #12200): the 1822/1825 apprenticeship-and-Conservatoire note; "placed in the vocal classes… lost his voice"; "inconsolable… first law-giver"; "It is not what we say that persuades, but the manner of saying it"; "Art gives wings for ascent to God"; "Man says what he feels by inflections of the voice…"; "Gesture must always precede speech." The Sorbonne "fit manifestation of feeling / revealer of thought / commentator upon speech" formula is confirmed genuine Delsarte (Mime Journal / scholarly corpus). The "shipwreck to learn to swim" line is confirmed in the Rick On Theater biography and is already honestly marked *attributed* (not claimed for Gutenberg). **One fix:** the birth-stop quote ("born November 19, 1811, at Solesmes") did **not** match its cited source — the Gutenberg note actually reads "November **11**… at **Solesme**" (a source typo for the true 19 Nov / Solesmes). Rather than import the source's wrong date into a quotation or fabricate a corrected "verbatim" line, the quote was **nulled** (quote + quote_source → null); the correct date survives in the campa and the `attested` anchor. Quote count 12 → 11; `null` used honestly.

**(5) Campa.** All 23 between 89 and 103 words (target 60–110), present tense, in register. The five great episodes (Tuileries thumb, ruined voice, watcher of dying/mad/grieving, Sorbonne address, MacKaye's crossing) are not flat.

**(6) Stop count.** 23, inside target; not expanded — the disciple-transmitted canon offers no further reliably-anchored, distinctly-placed episodes without invention.

**Result:** valid, re-validated after in-place edits. Two repairs — marriage stop reordered; corrupted birth quote nulled.
