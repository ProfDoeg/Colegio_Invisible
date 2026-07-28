# Borges: The Library and the Night — report

**42 stops, 9 segments, 18 quoted, span 1899–1987 (Buenos Aires to Geneva).**

## Sources
Primary spine: Edwin Williamson's *Borges: A Life* (2004) and Borges's own *An Autobiographical Essay* (1970) for the biographical armature. Dates and micro-details for the Spanish years (Barcelona → Valldemossa/Palma → Sevilla → Madrid → Zaragoza → Mallorca again → home) came from llegeixbarcelona.net's documentary reconstruction, which quotes Borges's own 1919 letter to Maurice Abramowicz. The Simurgh/Attar thread is anchored on two verified facts: the essay "El Simurgh y el águila" first ran in *La Nación* on 14 March 1948, decades before it gave its title to *Nueve ensayos dantescos* (1982) — I pulled the actual excerpt ("Treinta, purificados por los trabajos...") from borgestodoelanio's transcription rather than paraphrasing it. The Kabbalah thread runs on "Una vindicación de la Cábala" (*Discusión*, 1932) and the later poem "El Golem" (*La Nación*, 1958), both tied back to Cansinos-Assens's Madrid tertulia via a direct, sourced Borges quote ("de algún modo yo soy discípulo de Cansinos"). The library-and-blindness material (director of the Biblioteca Nacional, 1955; "Poema de los dones") and the Old Norse/Iceland material are both well-attested and cross-checked across multiple outlets. The gravestone description (Old English "And ne forhtedon na," the Völsunga Saga line, no Spanish on the stone) is confirmed by Infobae's detailed 2016 piece on the lápida.

## Judgment calls
- **Register vs. copyright.** Borges died in 1986; his work is still under copyright in most jurisdictions. I kept every quote from his own fiction/poetry/essays short (a sentence or a short passage, never a full poem or scene) rather than reproducing extended text, even though the schema wants his "own recorded words" densely, as with Joan's trial testimony. This is the one structural difference from a medieval or 19th-century traveler's file: the quote density (18/42, ~43%) is lower than Joan's near-100%, by design.
- **Several dates are placeholders within a known year or season** (marked `inferred` or `traditional`): the exact day he crossed to Geneva in March 1914, the exact day the Old Norse study group began, the two specific nights of the *Siete Noches* cycle I picked for "1001 Nights" and "La Cábala" (the cycle ran seven Wednesdays, 1 June–3 Aug 1977, but I could not confirm which calendar date belonged to which topic, so I spaced two plausible dates across the known range).
- **The "inspector of poultry and rabbits" story** (1946) is narrated as fact per the register instruction — one source flags it as possibly legendary/undocumented, but it is the canon Borges himself told for the rest of his life, so it stays true here, the way Joan's fairy-tree testimony stays true.
- **Time-fold:** the essay "El acercamiento a Almotásim" (1936) is placed *before* the 1938 accident that opens the next segment, which is correct chronologically, but I had to keep it inside the "Mythology of the Suburb" segment (ending 1937) rather than "The Wound, the Labyrinth, and the Tyranny" (starting 1938) to preserve internal chronological ordering — a segment-boundary artifact, not an error.
- Coordinates for diffuse "Buenos Aires" events (essays, lectures, appointments with no single fixed building confirmed) are pinned to the city center (-34.6037, -58.3816); Boedo, Recoleta, San Isidro, and Constitución stops get their own more specific coordinates where the site is a real, locatable building (Biblioteca Miguel Cané, Villa Ocampo, the Biblioteca Nacional's old México St. building, Calle Garay for the fictional Aleph stairway).

## The five richest episodes
1. **The Café Colonial, Madrid (1920)** — the whole journey's hinge: a twenty-year-old at the edge of Cansinos-Assens's all-night tertulia hears Kabbalah, the *1001 Nights*, and Sufi poetry spoken as living doctrine for the first time, sixty years before *Nueve ensayos dantescos* closes the same circle.
2. **The Christmas Eve accident (1938)** — septicemia, near-death, and a self-administered literary test that produces "Pierre Menard" and, with it, the entire second half of Borges's career.
3. **"El Simurgh y el águila" (1948)** — the essay the curator named directly: Attar's thirty birds who climb to find the Simurgh and discover they *are* the Simurgh, set beside Dante's eagle, with the actual excerpted Spanish.
4. **Director of the Biblioteca Nacional, blind (1955)** — the single most quoted irony in his biography, textually anchored to "Poema de los dones."
5. **The Geneva gravestone (1987)** — Anglo-Saxon warriors, a Volsunga Saga line, no Spanish: the whole life's library-and-Kabbalah-and-saga apparatus converging on two dead Northern languages over Argentine bones.

## Connections to the atlas
- **rumi.journey.json / nizami.journey.json** — the Persian Sufi register Borges reaches secondhand through Attar (never dramatized directly as his own journey elsewhere in the atlas, but rumi/nizami give the corpus a native anchor for the same devotional-Sufi cosmos Borges writes about from outside).
- **The libertadores cluster** (san_martin, miranda, belgrano, alvear, bolivar, sucre) — "El escritor argentino y la tradición" (1951) is the essay-form counterpart to their whole 19th-century project of defining an Argentine/American identity against and within European inheritance; Borges's gaucho argument (Martín Fierro) talks directly across the corpus to that cluster's foundational anxiety.
- **freud, jung, steiner** — fellow travelers in the atlas whose "journeys" are also mostly intellectual/publication events rather than physical itineraries; borges.journey.json uses the same register solution they do (essays and lectures as datable "stops").
- **tolkien** — the strongest formal echo: both files end in the Old English/Old Norse philological register (Beowulf, the Eddas, the sagas), and both travelers built a private mythology out of the same northern shelf, from opposite ends of the 20th century and opposite hemispheres.
- **blavatsky** — a structural contrast rather than a kinship: where Blavatsky's journey narrates invented esoteric cosmology as lived fact, Borges's journey narrates real, dated, verifiable publication events *about* esoteric cosmologies (Kabbalah, Sufism) he studied and wrote through, never claimed to enter.
- No existing file for Attar, Ibn Arabi, or Asín Palacios yet — those doors stay open on the Buenos Aires/Madrid side, ready for future siblings.

---

## Verification pass — 2026-07-20

`json_check.py`: **OK** before and after repair — segments=9, stops=42, quoted=18, no WARN lines. Structure matches the canon file `joan_of_arc.journey.json` exactly (same top-level keys, same per-stop keys). Stop count 42 sits inside the 30–45 target, so no stops were added. Chronology is sound within every segment; campa word-counts, present tense and register all pass; the traveler is dead and the file ends at the grave, as it should.

### Quotes — 9 spot-checked against the canon, 5 repaired

| Stop | Finding | Action |
|---|---|---|
| "Tlön, Uqbar, Orbis Tertius" | Quote **not in the story** — "Yo recuerdo apenas... que Bioy Casares venía de estudiar con atención una de las herejías de Uqbar" is invented. | Replaced with the canonical opening: "Debo a la conjunción de un espejo y de una enciclopedia el descubrimiento de Uqbar." Campa also claimed Bioy was "credited in the story's first sentence"; he is not — he enters in the opening paragraph, remembering the heresiarch on mirrors. Campa reworded. |
| "Una vindicación de la Cábala" | Paraphrase, with names (Nahmánides, Abulafia) Borges does not use there. | Restored: "No quiero vindicar la doctrina, sino los procedimientos hermenéuticos o criptográficos que a ella conducen." Source note now records first publication 1931, collected in *Discusión* (1932). |
| Siete Noches — "La Cábala" | **Conflation**: the "colaboración del azar es calculable en cero" phrasing belongs to the 1931 essay, not the 1977 lecture. | Restored the lecture's own wording: "El curioso modus operandi de los cabalistas está basado en una premisa lógica: la idea de que la Escritura es un texto absoluto, y en un texto absoluto nada puede ser obra del azar." (verified against the *Siete noches* text) |
| Siete Noches — "Las mil y una noches" | Fabricated wording. | Restored: "Las mil y una noches no han muerto. El infinito tiempo de Las mil y una noches prosigue su camino." |
| "El escritor argentino y la tradición" | One word off — "esa tradición" for canonical "esta tradición". | Corrected against the printed lecture text. |
| "El Golem" | Stanza wording ("El rabí lo miraba con ternura…") **verified correct**. But the venue was wrong: no evidence of a *La Nación*, August 1958 printing, and the poem was collected in ***El otro, el mismo* (1964)**, not *El hacedor* (1960). | Campa no longer says La Nación printed it; date_confidence attested → **traditional**; quote_source and sources corrected to *El otro, el mismo* (1964). |
| "Pierre Menard" | Verified exact. | none |
| "El Simurgh y el águila" | Verified exact, word for word. | none |
| Collège Calvin ("A Ginebra le debo…") | Wording verified; source was vague ("later interviews"). | Tightened to Borges, 'Ginebra', in *Atlas* (1984). |

*El Aleph*, *La biblioteca de Babel* and the Norton Lecture quotes also checked and left as they stand.

### Coordinates — 13 sites checked, 9 corrected (14 stops moved)

Geocoded against OpenStreetMap/Nominatim and the site record.

| Site | Was | Now | Error |
|---|---|---|---|
| Birthplace, Tucumán 840 | -34.6042, -58.3784 | **-34.6013, -58.3787** | ~320 m |
| Malagnou 17, Geneva (2 stops) | 46.1993, 6.1553 | **46.2007, 6.1524** | street renamed **Rue Ferdinand-Hodler** in 1964; old coord sat on the surviving stretch of rue de Malagnou, not the house |
| Collège Calvin (2 stops) | 46.2016, 6.1487 | **46.2008, 6.1513** | ~210 m |
| Villa Ocampo, San Isidro (2 stops) | -34.4711, -58.5087 | **-34.4579, -58.5184** | **~1.7 km** |
| Biblioteca Miguel Cané (2 stops) | -34.6295, -58.4197 | **-34.6247, -58.4261** | ~800 m |
| Biblioteca Nacional, México 564 (2 stops) | -34.6136, -58.3805 | **-34.6150, -58.3740** | ~600 m |
| Hotel Formentor, Mallorca | 39.9053, 3.0806 | **39.9267, 3.1449** | **~6 km** — old point was near Port de Pollença, not the hotel |
| Geneva, the death | 46.2044, 6.1432 | **46.2017, 6.1462** | now pinned to **Grand-Rue 28**, Vieille-Ville, the rented apartment where he died |
| Cimetière des Rois | 46.1949, 6.1389 | **46.2022, 6.1363** | ~830 m |

Verified as already correct and left alone: Teatro Coliseo (within 55 m), Paraninfo of Alcalá de Henares (within 80 m), Valldemossa, Reykjavík, Harvard/Cambridge MA, Asunción, Café Colonial (Puerta del Sol approximation, acceptable — the café is gone).

### Other

- `years` was **1899-1986** while the final stop (the gravestone) is dated 1987. Corrected to **1899-1987**.
- Canon-fidelity: nothing was debunked. The 1946 "inspector of poultry and rabbits" dismissal stands as narrated — it is the story Borges told for life, and the register rule keeps it. The Christmas Eve 1938 wound and the whole Menard-as-proof-of-sanity chain stand. Inferred/traditional dates left marked as such rather than sharpened past the evidence.

---

## Second verification pass — 2026-07-20 (independent re-check)

This pass was run without trusting the section above: every coordinate and quote it claims to have fixed was re-derived from source. **The earlier pass holds up well** — its coordinate corrections were confirmed exact, not merely plausible. Three genuine defects survived it, and are fixed here.

`json_check.py`: **OK** before and after — segments=9, stops=42, quoted=18. Schema and per-stop keys match `joan_of_arc.journey.json`. **No stops added, removed or reordered; the Spanish twin stays positionally aligned.**

### Coordinates — 12 re-derived against OSM/Nominatim, 2 corrected

| Site | Nominatim | File | Verdict |
|---|---|---|---|
| Tucumán 840, San Nicolás (birthplace) | -34.60129, -58.37874 | -34.6013, -58.3787 | exact |
| Collège Calvin, Rue Théodore-de-Bèze | 46.20084, 6.15132 | 46.2008, 6.1513 | exact |
| Rue Ferdinand-Hodler 4 (ex-Malagnou) | 46.20069, 6.15237 | 46.2007, 6.1524 | exact |
| Cimetière des Rois, Genève | 46.20223, 6.13631 | 46.2022, 6.1363 | exact |
| Biblioteca Nacional, México 564 | -34.61497, -58.37401 | -34.6150, -58.3740 | exact |
| Villa Ocampo, Elortondo 1837, Beccar | -34.45802, -58.51846 | -34.4579, -58.5184 | exact |
| Biblioteca Miguel Cané, Carlos Calvo | -34.62486, -58.42634 | -34.6247, -58.4261 | ~25 m, fine |
| Grand-Rue 28, Vieille-Ville (the death) | 46.20165, 6.14615 | 46.2017, 6.1462 | exact |
| Teatro Coliseo, M.T. de Alvear 1125 | -34.59674, -58.38328 | -34.5972, -58.3833 | ~50 m, fine |
| Platja de Formentor (Hotel Formentor) | 39.92703, 3.14219 | 39.9267, 3.1449 | ~230 m, fine |
| Universidad de Alcalá, Pl. de San Diego | 40.48292, -3.36174 | 40.4818, -3.3635 | ~200 m, same campus |
| **Palermo, the paternal library** | JL Borges (ex-Serrano) 2135: **-34.58542, -58.42497** | was -34.5885, -58.4238 | **~380 m off — CORRECTED** |
| **Calle Maipú 994 (Old English study)** | Retiro: **-34.59642, -58.37701** | was -34.5951, -58.3798 | **~300 m off — CORRECTED** |

Neither error was continental, but both put the pin off the actual house; the Palermo one matters most, since that address (Serrano 2135, since renamed Calle Jorge Luis Borges) *is* the paternal library, the file's founding scene.

### Quotes — 15 checked against the canon, 3 repaired

Verified **exact, no change**: "Debo a la conjunción de un espejo…" (*Tlön*, opening); "El universo (que otros llaman la Biblioteca)…" (*Biblioteca de Babel*, opening); "El texto de Cervantes y el de Menard son verbalmente idénticos…"; "Vi el populoso mar…" (*El Aleph*, ellipsis-joined but both halves canonical); "Nadie rebaje a lágrima o reproche…" (*Poema de los dones*); "El rabí lo miraba con ternura…" (*El Golem*); "Treinta, purificados por los trabajos, pisan la montaña del Simurgh…" (*El Simurgh y el águila*, and the *La Nación*, 14 March 1948 date confirmed with it); "no quiero vindicar la doctrina, sino los procedimientos hermenéuticos o criptográficos que a ella conducen"; "Creo que nuestra tradición es toda la cultura occidental… derecho a **esta** tradición" (the earlier pass's `esa`→`esta` fix confirmed correct); "El curioso modus operandi de los cabalistas…" (*Siete noches*, La Cábala); "Las mil y una noches no han muerto…"; "A Ginebra le debo la revelación del francés…" (*Atlas*); "I am nearing seventy… I can offer you only doubts" (*The Riddle of Poetry*, first Norton lecture); "If I were asked to name the chief event in my life…" (*An Autobiographical Essay*).

| Stop | Finding | Action |
|---|---|---|
| Madrid, Café Colonial | The Spanish "Luego marchamos a Madrid… Aún me gusta pensar en mí como su discípulo" is a **back-translation**. Borges wrote *An Autobiographical Essay* **in English** (with di Giovanni, *New Yorker*, 1970); no Spanish original exists for this sentence, and the attribution to Schwartz's 1986 article dressed a retranslation as a primary source. | Restored the English canon: "There the great event to me was my friendship with Rafael Cansinos-Asséns... I still like to think of myself as his disciple." Source corrected to *An Autobiographical Essay* (1970), flagged "written in English". **This is the one quote whose language changed** — done because the file's other quote from the same text is already English, and keeping a back-translation would have been the less faithful option. |
| Director of the Biblioteca Nacional | Quote "Yo siempre me había imaginado el Paraíso bajo la especie de una biblioteca" is **real and exact**, but was mis-sourced to "An Autobiographical Essay and later interviews". It is from the lecture **"La ceguera"** (*Siete noches*, 1977/1980), where Borges recalls the 1955 appointment. The widely circulated "Siempre imaginé que el Paraíso sería algún tipo de biblioteca" is a modernized paraphrase and was rightly *not* used. | quote_source corrected. Quote kept verbatim. |
| Reykjavík | Wording confirmed, but source was "widely cited from later interviews". | Tightened to the *La Nación* piece "La Islandia de Borges", which also confirms the 1971 first visit and the two later returns the campa asserts. |

### Campa lengths — 6 over the 110-word ceiling, all trimmed

*Tlön* (120), *El Aleph* (111), *El Simurgh y el águila* (112), the Kabbalah night (113), Geneva/the death (120), the gravestone (111) — all now inside 60–110. Trims were compressions of trailing clauses only; no episode lost its turn, and present tense and register are unchanged. The great episodes (the paternal library, the Café Colonial, the Christmas Eve wound, the blind directorship, the gravestone) all remain at full weight.

### Chronology and confidences

Dates are strictly ascending inside all nine segments; calendar is `gregorian`, so no julian_bce sign trap applies. Anchor dates re-confirmed: born 24 Aug 1899; *Himno al mar* in *Grecia*, 31 Dec 1919; Menard in *Sur*, May 1939; Tlön May 1940; *El Aleph* Sept 1945; dismissal 1946; the 1951 lecture; directorship 1955; Formentor shared with Beckett 1961; Norton chair 1967–68; Cervantes Prize 23 Apr 1980 shared with Gerardo Diego; Kodama marriage by proxy in Asunción 26 Apr 1986; death 14 Jun 1986. Confidence labels are honest — the two *Siete noches* nights stay `inferred` because the cycle's seven Wednesdays (1 Jun–3 Aug 1977) cannot be matched to topics from the sources available, and the Geneva arrival, the Old Norse study group and the Reykjavík trip stay `inferred` for the same reason.

### Could not confirm

- Which calendar night of the *Siete noches* cycle carried "Las mil y una noches" and which carried "La Cábala" (both left `inferred`, spaced across the known range).
- The exact day of the family's March 1914 arrival in Geneva, and the exact day the Maipú Old English group began.
- The 1919 letter to Maurice Abramowicz is quoted from llegeixbarcelona.net's transcription; I could not reach a facsimile of the manuscript, so it rests on that single secondary witness.
- The "inspector of poultry and rabbits" appointment remains documentarily thin, and stands by the register rule as the canon Borges told for life — unchanged, not debunked.
