# Freud journey — report

**Sources.** Primary: Freud's own *An Autobiographical Study* (1925), *The Interpretation of Dreams* (1900), *Beyond the Pleasure Principle* (1920), *The Moses of Michelangelo* (1914), and the Freud–Fliess correspondence. Biographical spine from Ernest Jones's three-volume *Life and Work of Sigmund Freud* and Peter Gay's *Freud: A Life for Our Time*. Jung's *Memories, Dreams, Reflections* ch. 5 supplied the shared Berggasse/Bremen/Munich material (cross-checked so pins and dates match jung.journey.json exactly). Freud Museum London and Sigmund Freud Museum Vienna web materials confirmed the 1938 exodus timeline, Anna's arrest, and the Maresfield Gardens move. Max Schur's *Freud: Living and Dying* supplied the deathbed scene.

**Judgment calls.**
- **Berggasse 19 coordinates**: jung.journey.json and reich.journey.json give slightly different values (48.2191/16.3632 vs 48.218/16.361 — both round to the same point at 3 decimals but aren't byte-identical to each other). I standardized on jung's higher-precision figure for every Freud stop at that address; a truly byte-identical three-way match isn't possible without editing the other two files, which was out of scope here.
- **Moses statue chronology**: sources disagree on whether the intensive three-week study happened in September 1912 or September 1913. Freud's own 1933 letter to Edoardo Weiss says "September 1913," and that date lets the stop follow immediately on the Munich congress rupture with Jung — narratively right (he goes to Rome to grieve the break) and evidentially the better-sourced claim, so I used it, placing the *first sighting* of the statue back in 1901 as a separate, earlier stop.
- **The Gestapo statement myth**: the famous "I can heartily recommend the Gestapo to anyone" line is now known to be apocryphal (the real document, recovered in 1989, contains no such line). I left it out entirely rather than launder a debunked quote into the canon register.
- **Prater poet prophecy**: sourced only from Jones/Martin Freud family lore, no verbatim quote survives, so it's marked `traditional` with `quote: null`.
- **Sophie's death location**: she died in Hamburg, but the stop is pinned to Vienna/Berggasse 19 because the journey follows Freud's own body — he received the telegram there and could not travel.

**Gaps / time-folds.** The 1914–1938 Wednesday-Society/Vienna Psychoanalytic Society afterlife (Adler's 1911 defection, the 1913 formation of the secret Ring committee) is compressed almost to nothing to keep the curator's 30–45-stop budget for the six other major arcs; readers wanting that texture should cross-reference reich.journey.json's "In Freud's Circle" segment. The 1938 exodus (segment 9) compresses roughly three months of visa struggle into two stops.

**Five richest episodes.** (1) The bookcase detonating twice in the Berggasse study, 1909 — the "poltergeist" Freud dismissed and Jung never did. (2) Freud fainting twice at Jung's talk of death, Bremen 1909 and Munich 1912, each time at the same buried subject. (3) The three lonely weeks alone with Michelangelo's Moses in September 1913, taken almost as therapy for the Jung rupture. (4) Heinele's death in 1923, which broke something in Freud that even his father's death and his own cancer diagnosis, that same year, had not. (5) The diary's four words — "Anna bei Gestapo" — the whole crisis of March 1938 compressed into a note meant only to jog his own memory.

**Connections to the atlas.** Berggasse 19 (1907-03-03, 1909-03-25), Bremen (1909-08-20), Clark University (1909-09-10), the Munich Park Hotel faint (1912-11-24), and the last Munich sighting (1913-09-07) are all byte-identical pins shared with jung.journey.json. Reich's own 1919 Berggasse visit sits chronologically inside this file's Wednesday-Society/Rome/Clark span, so a reader can walk from Freud's founding of the Society (1902) through to Reich's arrival seventeen years later without a seam. The Orient Express departure (4 June 1938) is Freud's own version of the exile-by-rail motif that also carries reich (ship from Oslo, 1939) and elsa_lindenberg out of Europe — no shared pin exists yet for that motif across the corpus, but the thematic rhyme is there for a future curator to formalize.

---

## Verification pass — 2026-07-13

**Structure.** `json_check.py`: OK, 0 WARN — segments=9, stops=39, quoted=20 (unchanged tallies). Top-level and per-stop keys match joan_of_arc.journey.json exactly, including the register line. Chronology is clean within every segment; one deliberate cross-segment fold stands (segment 4, "The Rome Neurosis," opens at 1897-09-01 after segment 3 closes at 1902-11-01) — a thematic arc, kept as-is. The traveler is dead; the journey ends at his death (1939-09-23). Stop count 39 sits inside the 30–45 target; no additions needed.

**Shared pins.** Re-checked against jung.journey.json directly: Berggasse 19 thirteen-hours/bookcase (48.2191/16.3632), Bremen (53.077/8.807), Clark (42.2509/-71.8229), Munich faint (48.142/11.569), Munich last sight (48.1404/11.5716) — all numerically identical. None were touched.

**Coordinates.** Spot-checked 15+ against the actual sites (Příbor birth house, Leopoldstadt, Prater, Trieste, Salpêtrière, Wandsbek, Trasimene, Rome, San Pietro in Vincoli, Frankfurt, rue Adolphe-Yvon all verified good). Five fixed:
- Schloss Bellevue/Bellevuehöhe: 48.2570/16.3360 → **48.2594/16.3169** (de.wikipedia Bellevuehöhe, site of the 1977 Freud stele)
- Hotel Metropol, Morzinplatz (Anna's arrest): 48.2131/16.3789 → **48.2129/16.3743** (was ~350 m east of the Morzinplatz)
- Orient Express departure: 48.1897/16.3378 → **48.1966/16.3385** (the train left from the Westbahnhof; old pin was ~750 m south)
- 39 Elsworthy Road (London landfall): 51.5460/-0.1730 → **51.5399/-0.1673** (OSM geocode of the actual address)
- 20 Maresfield Gardens (both stops): 51.5566/-0.1770 → **51.5483/-0.1774** (Freud Museum London; old lat was ~0.9 km north)

**Quotes.** Spot-checked all 20 against the canon; 15 verified verbatim ("thirteen hours," "sheer bosh," "How sweet it must be to die," "the aim of all life is death," "Anna bei Gestapo," "Insight such as this…," the Bellevue plaque, the Fliess father-death letter, the Hannibal passage, the Pfister Sophie letter, the Eitingon triumph/grief letter, the Adler invitation, the leukoplakia letter, "Die Natur," the Schur deathbed words). Five repaired:
- Charcot: "The theory is good, but that doesn't prevent it from existing" → **"Theory is good, but it doesn't prevent things from existing"** (the canonical rendering of "La théorie, c'est bon, mais ça n'empêche pas d'exister"); source corrected from An Autobiographical Study to **On the History of the Psycho-Analytic Movement (1914)**, where Freud actually recounts the exchange.
- Clark: "In Europe I felt like an outcast; here I found myself received by the best as an equal" → canonical Strachey **"In Europe I felt as though I were despised; but over there I found myself received by the foremost men as an equal."**
- Weiss/Moses letter: restored the full canonical wording (**"…three lonely weeks of September 1913, I stood in church…measuring it and drawing it until there dawned…"**).
- Heinele: paraphrase restored to the attested letter (**"For me, that child took the place of all my children and other grandchildren…find no enjoyment in life either"**) and source corrected from Binswanger 12 April 1929 to **Binswanger, 15 October 1926** (PEP archive dates the passage to the 1926 letter).
- "Leaving today": expanded to the attested full line to Arnold Zweig (**"Leaving today for 39 Elsworthy Road, London N.W.3."**), source corrected from "Postcard" to **Note to Arnold Zweig, 4 June 1938** (Freud Museum London); campa adjusted to name Zweig.

**Campa.** All 39 within 60–110 words (0 WARN), present tense, in register; the great episodes (bookcase, Bremen faint, Munich faint, three weeks with Moses, Heinele, Anna bei Gestapo, the deathbed morphine) carry their full mythic weight. Canon-fidelity intact: the Prater prophecy, the caul, the fainting-as-death-wish reading, and the bookcase oracle all stand untouched, marked by confidence, not debunked.

**Verdict.** Dataset sound after 10 in-place fixes (5 coordinates, 5 quote/source repairs). Re-validated: OK, 0 WARN.
