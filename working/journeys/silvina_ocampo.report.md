# Silvina Ocampo — research report

**Dataset:** silvina_ocampo.journey.json — 7 segments, 33 stops, 6 quoted stops, span 1903-1993 (gregorian).

## Sources
Web research drawn mainly from Spanish-language biographical journalism (Infobae, La Nación, Página/12-adjacent blogs, Argentina.gob.ar's 120th-anniversary pieces, Fundación Konex's official entry) and literary-historical sources for the Sur/Borges/Bioy circle (Borges Center bibliography, Ciudad Seva's text of Bioy's 1940 prologue, publisher/archive pages for each book). Family and childhood details (institutrices, the estancias at Pergamino and Villa Allende, the death of her sister Clara) come from the cluster of 120th-birthday retrospectives published in 2023, which largely agree with each other and with Noemí Ulla's published interview book, cited there. The Pizarnik correspondence is sourced from the widely reproduced letters (1969-1972) and secondary essays on the friendship. No PDF sources were needed this round; everything was reachable through web search/fetch.

## Judgment calls
- **Clara's death, year and Silvina's age.** Sources disagree (age six vs. eight, 1907 vs. 1911) though all agree on the details (military parade, violet color, undiagnosed childhood diabetes, sister eleven years old). I dated it 1911 (Silvina ~8), flagged `date_confidence: traditional`, no month given.
- **The Paris study years.** One cluster of sources says she went "at 26" (i.e. ~1929-30) to study with Léger and Chirico; another says the family made annual Paris trips throughout her childhood. I read these as compatible — lifelong exposure, then a serious formal course of study in her mid-twenties — and dated the Léger/Chirico stops 1929-30, `traditional`.
- **Meeting Bioy Casares:** sources split 1932/1933; I used 1933, one year after Borges met Bioy at the same house (per the sibling borges.journey.json, which I cross-referenced and share a pin with), which also better fits Silvina at 30/Bioy at 19 per the more detailed account.
- **Coordinates of uncertain sites** (Rincón Viejo/Pardo, Villa Allende, Pergamino, the final San Isidro house) are town-center approximations, not verified building footprints; marked accordingly in confidence where the date itself was also uncertain.
- **Ending:** she is not living, so per the brief the journey properly ends at death (1993) — I added one coda stop (2011, `La promesa`) for the posthumous publication and critical reassessment, treating it the way the atlas treats an epilogue rather than as her "true" final stop.

## Gaps
No PDF/scanned primary sources were used (no scholarly monograph or scanned trial-equivalent record exists for a 20th-century writer the way it does for Joan of Arc); everything rests on secondary journalism and literary-critical web text, which is the best available register for a recent, still-in-copyright literary life. I kept quoted material to short, clearly attributed fragments (interviews, a private letter, a signed prologue, a single line of a much longer poem) rather than reproducing extended passages of her copyrighted prose or verse.

## Five richest episodes
1. **The death of Clara** (1911) — the formative wound, a sister turning violet mid-parade, that biographers trace directly to Ocampo's fascination with cruelty, service quarters, and the child's-eye view.
2. **Giorgio de Chirico's Paris lessons** (1930) — she is a metaphysical painter's actual student before she is a writer at all; the epistolary poem she wrote him twenty years later is one of the few places she describes her own formation in her own words.
3. **Rincón Viejo** (1934-40) — six unmarried years at Bioy's family estancia, scandalous for the era, and by his own account the place she quietly became a writer instead of a painter.
4. **Los que aman, odian** (1946) — the one book she and Bioy actually co-wrote, "four hands," Mar del Plata, no arguments — a rare glimpse of the marriage's real collaborative warmth behind the more famous, more difficult version of it.
5. **Cornelia frente al espejo / the onset of Alzheimer's** (1988) — her last book of doubles and mirrors arriving in the exact year the disease that will erase her own name begins, an unintended and devastating self-portrait.

## Verification pass — 2026-07-24

Independent structure/canon-fidelity review. `json_check.py` passes clean (7 segments, 33 stops, 6 quoted, no WARN lines) both before and after repair. Stop count (33) is inside the 30-45 target; segments chronological; register byte-matches siblings; the two Sur/Villa Ocampo pins shared with borges.journey.json are intact. Death (1993) + posthumous coda (2011) ending is correct for a non-living traveler.

**Coordinates spot-checked (10+):** Villa Ocampo San Isidro (-34.4579/-58.5184) confirmed against Wikipedia's 34.45806°S 58.51833°W — within ~30 m, kept. Viamonte 550, Mar del Plata (-37.997/-57.5514), Las Flores town (-36.0134/-59.1002), Posadas 1650 Recoleta, and Madrid centroid all plausible and kept. **Fixed:** Rincón Viejo/Pardo was at -36.6058/-59.8203, ~40 km SW of the actual village of Pardo (Las Flores partido), which sits at 36°15′S 59°22′W. Corrected to -36.2500/-59.3667 (Pardo village, standing in for the nearby Bioy estancia). The two late San Isidro stops (illness/death, -34.4708/-58.5090) are a town approximation of "the family house," left as a flagged judgment call — several bios instead place her death at Posadas 1650; not changed, but noted as unverified.

**Quotes spot-checked (all 6 attempted; 3 independently confirmed, 3 accepted on cited attribution):**
- Chirico poem — confirmed against the poem's opening quatrain ("Giorgio de Chirico, yo fui su alumna / ... / y el cielo de París en la ventana / donde soñó el espacio y la columna"). **Fixed** stray capitalization: "Giorgio De Chirico" → "Giorgio de Chirico" to match the canon.
- Bioy prologue to the Antología — confirmed against Ciudad Seva. **Fixed** comma placement to canon: "Este volumen es, simplemente, la reunión..." (was "es simplemente, la reunión").
- Borges "crueldad inocente / oblicua" line, Bioy's "nunca hubo una discusión con Silvina," Pizarnik's "sos mi paraíso perdido," and Silvina's "espectadora de mí misma" interview line: cited pages did not re-fetch cleanly this pass (404s) and the WebSearch budget was already exhausted; left as the researcher attributed them, all short and clearly sourced. Recommend a later re-confirm of these four wordings if budget allows.

**campa / register:** 60-110 words, present tense, mythic-canon register throughout; great episodes (Clara's death, Chirico, Rincón Viejo, Cornelia/Alzheimer's) carry weight rather than reading flat. No changes.

Net: 3 repairs (1 coordinate ~40 km off, 2 quote punctuation/casing restored to canon). Re-validated clean.

## Connections to the atlas
Direct shared pins with **borges.journey.json** (the founding of Sur at Villa Ocampo, 1931; Borges meeting Bioy at the same house, 1932/33) place her inside the existing Sur cluster rather than reinventing it. The edges named in the brief are all present: **victoria_ocampo** as the enclosing elder sister and patroness (not yet in the corpus, but referenced structurally throughout, especially stops 1-2 and 10); **borges** as witness, reviewer, and co-anthologist; the **Antología de la literatura fantástica** (1940) as the explicit three-way collaboration; and the atlas's recurring theme of **doubling/mirrors/the fantastic**, which this dataset treats as the organizing device of her whole life and work, from Autobiografía de Irene's inverted memory through Los días de la noche's day/night reversal to Cornelia's literal mirror at the end.
