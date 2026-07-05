# Wilhelm Reich — Dobrzanica to Lewisburg (1897–1957): Research Report

**Dataset:** `reich.journey.json` — 49 stops in 8 named segments, Gregorian, register = national mythology (the canon is true: the orgone is real, the rain falls where the cloudbuster points, the burnings are documented fact).

## Sources
The spine is Reich's Wikipedia biography (cross-checked against the **Wilhelm Reich Museum** biography and property pages, Encyclopedia.com, the Boston Psychoanalytic Society archive, and Britannica). Specialist sources filled particular episodes: the **euppublishing / Psychoanalysis & History** paper on the Vienna Ambulatorium and Technical Seminar; **psychorgone.com** and **wilhelmreich.gr** for the bion/orgone chronology; **Encyclopedia Nomadica** and the Museum's *Einstein Affair* for the Princeton meeting; **en-academic** and the Cloudbuster literature for the 1953 blueberry rain; **JSTOR Daily "Twice Burned"** and the Beat Museum for the book burnings; **Justia/OpenJurist 239 F.2d 134** and law.jrank for the injunction and trial; **Find a Grave** and Orgonon/Wikipedia for burial. Coordinates for the two lost Galician-Bukovinan villages come from the Ukrainian Wikipedia geo-tags: Dobrianychi (≈49.562, 24.524) and Yuzhynets/Jujinetz (48.536, 25.659).

## Judgment calls
- **Mother's suicide dated 1910-10-01** (`traditional`). Sources conflict: Wikipedia gives 1 October 1910; others say she made repeated attempts and died of Lysol poisoning in 1911. I used the 1910 date but flagged confidence as traditional. The Lysol detail is folded into the campa.
- **The Isonzo front** is placed at Gorizia (45.940, 13.622) as a representative coordinate; the canon says "Italian front, lieutenant, forty men, sent three times," not a single named battle site.
- **The 1953 cloudbusting** is placed at Grand Lake near the Bangor hydro dam (45.176, -67.774), per the newspaper account; the measured rainfall was recorded downstate at Ellsworth. Grand Lake Stream is the best-fit named site for "Grand Lake near the Bangor dam."
- **Flight from Berlin (1933-03-02)** is `inferred` — the canon fixes it to "the days after the Reichstag fire," early March, not an exact day.
- **Einstein's "bombshell in physics"** is narrated in the campa (attributed to Einstein by Reich) rather than placed in the `quote` field, which is reserved for Reich's own recorded words.

## Gaps in the canon
- Precise dates for the childhood tragedy sequence (tutor discovered, the boy's disclosure) are not attested; dated by inference within 1910.
- Reich's exact departure vessel in August 1939 is traditionally the *Stavangerfjord* (Norwegian America Line) but not firmly documented; listed as suggested_ref, and the harbor stop is coordinate-anchored to Oslo.
- The Swedish/Malmö interlude (1934) is thinly documented — a stateless-drift stop, confidence `traditional`.
- Only **two** verbatim Reich quotes were confidently placeable from the canon (the letter to Judge Clifford, Feb 1954; the "Love, work and knowledge" motto at the grave). Every other `quote` field is honestly `null` rather than invented.

## The five richest episodes
1. **The mother's death at Jujinetz (1910)** — the founding wound; the boy's disclosure, the Lysol, the lifelong guilt that the register lets steer the entire arc.
2. **The double excommunication (1933–34)** — cast out by the Danish Communists (Copenhagen, Nov 1933) and the psychoanalysts (Lucerne, Aug 1934) inside a single year: the man of both churches expelled by both.
3. **The Einstein meeting (13 Jan–7 Feb 1941)** — five hours of attention, the To-T temperature difference, the assistant's convection explanation, the door bolted shut: the American pattern in miniature.
4. **The blueberry rain (6 July 1953)** — the canon reported by the Bangor paper; the queer clouds, the midnight soaking rain, the farmers' fee, nine-year-old Peter at the cloudbuster.
5. **The burning (June–Aug 1956)** — accumulators axed by his own son under FDA eyes at Orgonon, then six tons of books incinerated on Gansevoort Street: books burned in America, some already burned by the Nazis — twice burned, two lands, two decrees. This is the campa that carries the full weight.

**Facing line:** Reich's body-energy world (armor, orgone, the freed pulse of the living) faces Rudolf Laban's movement world across the register.

## Verification pass (2026-07-05)

Independent structure and canon-fidelity check of `reich.journey.json`. The file re-validates by python after repairs: parses, 8 segments, 49 stops (within the 45–65 target), all stops carry the full key set, all campa 60–110 words, dates strictly chronological.

**Findings and repairs (all in place):**

1. **Date ordering** — one violation: the SAPA-bions stop (1939-01-01) preceded the press-campaign stop (1938-01-01) inside "The Northern Exile." Swapped: the year of mockery now precedes the SAPA winter, as the calendar demands. No dates altered.
2. **Coordinates** — web-spot-checked 10+ sites. Confirmed accurate: Dobrianychi (49°34′N 24°31′E per the birthplace literature), Yuzhynets (Wikidata 48.536, 25.659 — exact), Berggasse 19, Gansevoort Destructor Plant (the incinerator by the Hudson, beside today's Whitney), Forest Hills 9906 69th Avenue, New School, Ellis Island, Portland courthouse. Fixed five sites that pointed near-but-wrong:
   - **Orgonon** (7 stops incl. the grave): file had ~44.970, −70.683 (east of the hill); actual site of the observatory/museum is 44.985, −70.716 (Wikipedia/museum). All Orgonon stops moved.
   - **Einstein meeting/retraction**: moved to the house itself, 112 Mercer Street (40.343, −74.667 per the Albert Einstein House landmark record) from a generic Princeton point ~1 km off.
   - **Danbury**: file pointed at the city (41.401, −73.478); FCI Danbury is 41.437, −73.468.
   - **Lewisburg**: file pointed at the town (40.966, −76.887); USP Lewisburg is 40.984, −76.915.
   - **The blueberry rain**: file used Grand Lake Stream, Washington County (45.176, −67.774), ~100 km from the event. The canon (Bangor Daily News account and its retellings) sets the operation on a blueberry barren outside Ellsworth, "off the shores of Grand Lake, near the Bangor hydro-electric dam," with the 0.24-inch rainfall recorded at Ellsworth. Moved to the Ellsworth blueberry country by the Graham Lake (Bangor Hydro) dam: 44.57, −68.40. The stop keeps the canon's own place-name.
3. **Quotes** — both non-null quotes checked verbatim against the canon and confirmed: the letter to Judge Clifford ("Scientific matters can only be clarified by prolonged, faithful bona fide observations in friendly exchange of opinion, never by litigation" — Reich's February 1954 Response to the FDA complaint, quoted by the Wilhelm Reich Museum biography) and the "Love, work and knowledge" motto (title-page epigraph, first in *The Function of the Orgasm*; cut into the Orgonon record). Nothing nulled; all other quote fields were already honestly null.
4. **Campa voice** — present tense throughout, the great episodes carry their weight (the Lysol, the double excommunication, the five Einstein hours, the queer clouds, the smoke over the Hudson). Two stops had leaked schema vocabulary into the myth-voice: the Gansevoort stop said "The campa must carry the whole weight" and the Lewisburg stop closed "the register keeps every fact of it." Rewritten in-voice ("Let it be said plainly: books are burned in America…" / "…and every fact of it is kept."); word counts remain in range.
5. **Stop count** — 49 stops, inside the 45–65 target; no additions required.

The myth stands as written: the orgone real, the rain real, the burnings documented fact.
