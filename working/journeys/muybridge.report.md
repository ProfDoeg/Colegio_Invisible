# Eadweard Muybridge — Kingston to Kingston (1830–1904)

**Shape:** 25 stops across 8 named segments; 4 attested quotes; span 9 Apr 1830 – 8 May 1904, gregorian. Register: the canon (photographs, trial record, biographies) is true and narrated as event.

## Sources
Primary spine from the [Wikipedia biography](https://en.wikipedia.org/wiki/Eadweard_Muybridge) (dates cross-checked against the [UPenn Archives biography](https://archives.upenn.edu/exhibits/penn-people/biography/eadweard-muybridge/) and [Britannica](https://www.britannica.com/biography/Eadweard-Muybridge)). The murder and trial from [People v. Muybridge](https://en.wikipedia.org/wiki/People_v._Muybridge) and the [SF Examiner](https://www.sfexaminer.com/news/the-very-san-francisco-story-of-the-inventor-of-the-movies-killing-his-wifes-lover/article_4404aa32-ecf0-11ec-adae-e7393fa59ef2.html). Horse experiment from [The Horse in Motion](https://en.wikipedia.org/wiki/The_Horse_in_Motion) + the [LoC caption record](https://www.loc.gov/item/97502309/). Yosemite from [Muy Blog](https://ejmuybridge.wordpress.com/2010/05/20/muybridge-yosemite/); Central America from the [Smithsonian exhibition](https://americanart.si.edu/exhibitions/muybridge) and [Stanford Spotlight](https://exhibits.stanford.edu/muybridge/catalog/rs028yq2265); zoopraxiscope from [Wikipedia](https://en.wikipedia.org/wiki/Zoopraxiscope); Animal Locomotion from [Wikipedia](https://en.wikipedia.org/wiki/Animal_Locomotion) and [UPenn](https://archives.upenn.edu/exhibits/penn-history/muybridge/); the head-injury thesis from the [Neurosurgical Focus 2015 paper](https://thejns.org/focus/view/journals/neurosurg-focus/39/1/article-pE4.xml).

## Judgment calls
- **The murder quote.** Multiple wordings circulate ("Good evening, Major…here's the answer to the letter/message you sent my wife"). I used the fullest attested form and labeled it as recorded in trial testimony and biographies rather than a single verbatim transcript — it is the tradition's line, honestly framed.
- **The head-injury "remaking."** The prompt asks this be narrated as event; the 2015 neurosurgery paper treats the personality change as real (orbitofrontal-type disinhibition). I narrate the transformation as fact while keeping the grey-hair-in-three-days as "it is said."
- **Coordinates.** The Texas crash (north of Fort Worth) and the Yellow Jacket Mine are approximate — the mine site near Calistoga is not precisely pinned publicly, so I placed it in the correct hills NE of town. Sacramento used for the 1872 first trials (Occident) which preceded the 1878 Palo Alto success.
- **Two Yosemite stops (1867, 1872)** kept distinct because the mammoth-plate 1872 campaign is a separate mythic event and the hinge where Stanford enters.
- **Segment count is 8** (target 5–9): the legs are named as the tradition frames them — Helios, the Wager, the Bullet.

## The tradition's own folds and gaps
- The 1862–1865 years are genuinely dark in the record; I render them as "years of shadow," which the sources themselves do.
- Whether Stanford's "wager" was a literal bet or a myth is disputed; I placed the wager in the campa but flagged "they say."
- Flora's death (July 1875) and the son Florado's consignment to an orphanage are folded into the Panama stop rather than given their own stop, to keep the exile leg lean.

## Five richest episodes
1. **Fort Smith, 1860** — waking with nine days erased; the blow that the tradition says made the artist.
2. **Palo Alto, 15 June 1878** — the trip-wire camera bank proves all four hooves leave the earth; motion arrested and read.
3. **Yellow Jacket Mine, 17 Oct 1874** — the point-blank killing and the calm confession among the miners.
4. **San Francisco, 4 May 1880** — the zoopraxiscope throws the first projected moving pictures on a wall; the ghost of cinema.
5. **Chicago Midway, 1893** — Zoopraxographical Hall, the world's first commercial movie theatre, as a fairground sideshow.

## Connection to the atlas
This journey was built to face two neighbors explicitly. Its **arrested motion** faces the movement-lineage — the notated body of Delsarte and Laban (motion made legible, the stride decomposed into numbered phases). Its **gallery of moving bodies** and the projected horse face **Falconetti** and the moving image: Muybridge invents the illusion (the zoopraxiscope, the first movie theatre) whose century-later flower is the close-up on Falconetti's face in Dreyer's *Passion*. He is thus the atlas's hinge from the still image to the cinema — and the *Animal Locomotion* atlas (781 plates, every gait indexed) is a mirror of the quipu's own project: a stop-by-stop reading of bodies in motion. As a Kingston-to-Kingston closed circle, he sits among the other "the-circle-returns" journeys in the collection.

---

## Verification (2026-07-05)

Structural and canon-fidelity pass against the sibling schema (`joan_of_arc.journey.json`). Repaired **in place**; re-validated with python (parses; 26 stops / 9 segments; all campa 90–110 words, present tense; 0 out-of-order dates; no zero coords; schema keys identical to Joan).

**(1) Schema.** Top-level keys and per-stop keyset (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match Joan exactly. No change needed.

**(2) Chronology — FIXED.** The reference journey is strictly date-monotonic across the whole stop array (0 inversions); Muybridge had **two** inversions, both from thematic segments whose spans overlapped:
- *The Wager* (1872/73–1878) bracketed *The Bullet* (Oct 1874–Feb 1875) and *The Tropics of Exile* (1875), so the 1878 Palo Alto climax sat before the 1874 murder in reading order.
- The Sacramento first-trials stop was dated **1872-05-01**, landing after the 1872-06-01 Yosemite mammoth plates.

Fix: split *The Wager* into two segments — **"The Wager — Stanford's Question and the First Trials"** (1873 trials + Modoc) kept in place, and a new **"The Wager Settled — Palo Alto and the Horse in the Air"** (the 15 June 1878 climax) moved to its true chronological slot after the exile. The array is now fully monotonic. Segment count 8→9 (still within the 5–9 frame; the split is also historically truer — the wager was *posed* in 1872–73 and only *settled* in 1878, after the killing and the exile).

**(2b) Date/fact correction — FIXED.** The Sacramento stop claimed the first Occident trials were "In 1872 at his Sacramento stables." The canon (Wikipedia; historyofinformation) puts the first (blurry, single-camera) Occident photographs in **1873 at Union Park racetrack, Sacramento**. Corrected the date to **1873-04-01** (before the May 1873 Modoc stop) and rewrote the campa to 1873 / Union Park; kept Stanford *posing* the question in 1872. This correction simultaneously resolved one of the inversions.

**(2c) Confidences — honest, no change.** Real anchors (birth, stagecoach 22 July 1860, Helios return 13 Feb 1867, Yosemite/Alaska/lighthouse commissions, Palo Alto, the killing 17 Oct 1874, Napa acquittal, Paris soirée, UPenn, Chicago, death) are `attested`; softer or approximate items (New Orleans arrival, the bookseller start, Fort Smith waking, the Gull "years of shadow," the 1873 first trials) are `traditional`. Death-ending is correct: Muybridge died 8 May 1904 — not a living traveler, so closing on the grave/ashes is proper (the "living person ends at the present" rule does not apply).

**(3) Coordinates — spot-checked 18 stops; 1 FIXED.** Kingston (51.412,-0.300), New Orleans, all San Francisco stops (~37.79,-122.40), N-of-Fort-Worth (32.90,-97.35, approx — flagged), Fort Smith (35.386,-94.399), London/RI (51.510,-0.142, Albemarle St), Yosemite (37.745,-119.593), Sitka (57.053,-135.330), Point Reyes lighthouse (37.996,-123.024), Sacramento (38.578,-121.494), Lava Beds/Captain Jack (41.714,-121.508), Palo Alto (37.436,-122.171), Napa courthouse (38.298,-122.285), Panama City, Antigua, UPenn 36th&Pine (39.951,-75.196), Chicago Midway (41.788,-87.597) — all correct.
- **Yellow Jacket Mine** was at 38.706,-122.529 (nearly due north of Calistoga). The mine sits in the **West Mayacmas district, Sonoma County**, ~9 km **NW** of Calistoga near Pine Flat / Castle Rock Springs (mindat loc-95850). Nudged west to **38.660,-122.680** — still approximate (report already flags the site is not precisely pinned publicly), but now in the correct hills to the northwest rather than due north.
- New stop (Paris/Marey) placed at 48.858,2.288 — 11 Boulevard Delessert, 16e, below the Trocadéro. Correct.

**(4) Quotes — spot-checked all 4; all carried, none nulled.**
- Bookshop notice "I have this day sold to my brother, Thomas S. Muybridge" — SF *Bulletin*, **15 May 1860** (stop labels it "May 1860"). Verbatim per the canon. ✓
- Sallie Gardner caption "The Horse in Motion. 'Sallie Gardner,'… over the Palo Alto track, 19th June 1878." ✓ (the caption's 19 June vs. the demonstration's 15 June is a real, sourced distinction, preserved.)
- Larkyns line "Good evening, Major, my name is Muybridge, and here's the answer to the letter you sent my wife." — matches the fullest attested wording; framed as trial-testimony/biography record, not a verbatim transcript (judgment call already flagged). ✓
- Napa jury "If their verdict was not in accordance with the law, it was in accordance with the law of human nature." — matches the canon. ✓

**(5) Register/campa.** All 26 present tense, in the mythic register; the head-injury remaking and "the ghost of cinema" held as event per instruction; the great episodes (Fort Smith, Palo Alto, Yellow Jacket, the zoopraxiscope premiere, Chicago) are not flat. Two over-length campas (Palo Alto 115→108, UPenn 114→110) were trimmed without gutting; the "richest" UPenn atlas passage keeps its force.

**(6) Added stop.** Was at the 25-stop floor; the canon plainly offered more on the cinema/atlas neighbor. Added **"Paris — Marey's soirée and the meeting of the motion-hunters"** (26 Sep 1881, Marey's apartment; then Meissonier's studio; Helmholtz present) — attested (precinemahistory ch. 15; Wikipedia), and the pivot where Muybridge and Marey fuse the motion-study lineage that faces the Delsarte/Laban and cinema neighbors. Removed the now-redundant "in Paris he dazzles Marey" clause from the 1882 Royal Institution stop so the two do not double-tell. Total now **26 stops / 9 segments**.

No myth was debunked: theophany-of-the-blow, the sun-name Helios, the wager, the "ghost of cinema," and the first-movie-theatre claim all stand; corrections were confined to ordering, one hard date/place fact, one coordinate, word-length, and one additive stop.
