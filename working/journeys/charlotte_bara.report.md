# Charlotte Bara — report

**Dataset:** `charlotte_bara.journey.json` — 9 segments, 43 stops, 2 quotes, gregorian, 1901–1986 (coda to 2018).

## Sources
The spine is the *Dizionario della musica nella Svizzera italiana* entry (ricercamusica.ch/dizionario/56.html) — by far the richest single source: teachers, debuts, the d'Annunzio episodes with his French sentences, the San Materno guest lists, the Olga Schwind liturgies, the July 1958 last dance. Cross-checked against de.wikipedia (Charlotte Bara; Teatro San Materno), teatrosanmaterno.ch/en/history, museoascona.ch (exhibition + Fondo, 2,400+ documents), Deutsches Tanzarchiv Köln (Bestand 147, the Feb 1928 Berliner Zeitung review), Jüdische Allgemeine ("Der Kaufhauskönig und die Tänzerin" — the 1910 Locarno holiday, the Vogeler letter about magnolias), Artribune (work titles, tour cities), and the Monte Verità media guide (Szeemann 1978).

## Judgment calls
- **The Laban tie, per the curator's honesty note:** rendered exactly as milieu + lineage, never collaboration. Three stops carry it: "Monte Verità — the inherited mountain" (he was gone before she arrived; "she never stands in his studio"), the Trümpy/Skoronel Berlin stop (Laban→Wigman→Trümpy→Skoronel→Bara, "by descent, never by his hand"), and Magdeburg 1927 ("a congress, not a collaboration").
- **Vittoriale quotes:** d'Annunzio's French ("Elle sait par quels mystères…", "J'ai inventé une danse pour vous…") is *his* speech, so it lives in campa; the `quote` fields keep only Bara's own recorded words (2: her estimation of Jodjana, and "a school for expressive form").
- **Bossi:** the dictionary's American-tour anecdote collides with Bossi's 1925 death at sea, so it is folded into the 1931 guests stop as a dream already left dreamed, not given its own dated stop.
- **Coordinates:** Teatro San Materno from Wikidata (46.1612, 8.7736); the castle, Kursaal, Vittoriale, Barkenhoff from known sites; the Landwehrkasino and Trümpy school addresses are approximate Berlin (inferred).

## Gaps and time-folds
Segment 4 (Ascona, from 1920) folds back behind segment 3's Berlin end (1921) — she genuinely shuttled; each segment is internally chronological. Sources disagree on the family's arrival (1919 vs 1920 — I use 1920) and on the castle purchase date. The Einsiedeln *Ridda degli angeli* is undated in the source; placed at the 1930 Welttheater staging, inferred. The Sainte-Gudule childhood stop is an inferred station built from the Tanzarchiv's attested account of her Gothic sources. Her burial site could not be confirmed (Findagrave blocked); death at Locarno is attested.

## Five richest episodes
1. **The Vittoriale, 1924** — d'Annunzio dreams a dance for her in the night, names her *santa ballerina*, assigns titles like relics (*La dernière colonne du Temple*).
2. **The war refuge** — the theater dark, its rooms housing refugees and the persecuted: the 1936 *Flight into Egypt* enacted in earnest in the corridors.
3. **James Simon at Auschwitz, 1944** — the school's music master murdered; the one stop that leaves the lake, deliberately.
4. **The 1952 reopening with Olga Schwind** — the wise and foolish virgins resurrected with vielle and portative organ, "almost a domestic liturgy."
5. **Szeemann's Monte Verità, 1978** — the 77-year-old attending her own canonization in the museum of the hill's myth.

## Connections in the atlas
Direct bridge to **dannunzio** (the Vittoriale segment slots between his 1924 Montenevoso ennoblement and Mussolini's 1925 pilgrimage) and to **laban** (his Monte Verità stops 1913–17 precede her arrival on the same hill; Magdeburg 1927 is the one shared room). Kin to the sacred-movement line — **delsarte**, **stebbins**, **falconetti** (the other woman whose Gothic face carried a canon) — and to the Ascona/esoteric cluster (**steiner**: the Goetheanum eurythmists dance at her theater; **gurdjieff**, **keyserling**). Her Worpswede refuge touches the Vogeler world adjacent to **itten**'s and the Bauhaus-era stops; the confiscated-and-resettled Jewish arc echoes the Oppenheimer family journeys.

## Verification pass — 2026-07-12

Structure and canon-fidelity check against the Joan of Arc reference schema; repairs made in place.

**json_check.py**: OK before and after repair — segments=9, stops=43, quoted=3 (was 2), no WARN lines. Top-level and per-stop keys match joan_of_arc.journey.json exactly; register/calendar conventions consistent. All dates chronological within segments; deceased traveler correctly ends at death (1986-12-07) with a restored-theater coda (2018). Stop count 43 sits inside the 30-45 target; no additions needed.

**Coordinates** — 13 sites spot-checked (Nominatim/OSM + landmark cross-check). Confirmed good: Teatro San Materno (exact: 46.16121, 8.77363), Castello San Materno, Monte Verità, Kursaal Locarno, Sainte-Gudule, Amsterdam Leidseplein (Stadsschouwburg), Vittoriale, Comédie des Champs-Élysées, Bad Godesberg, Magdeburg Rotehorn exhibition grounds, Einsiedeln abbey, Auschwitz-Birkenau, Locarno. Fixed three:
- Barkenhoff, Worpswede: 53.2237,8.9285 → 53.2158,8.9324 (~900m; now on the Vogeler house grounds, Ostendorfer Str.)
- Kammerspiele des Deutschen Theaters, Berlin: 52.5253,13.3845 → 52.5244,13.3824 (Schumannstr. 13a)
- Kolbe stop, Berlin: 52.5164,13.2611 → 52.5099,13.2549 (Georg-Kolbe studio/museum site, Sensburger Allee)

**Quotes** — both existing quotes checked against the canon (ricercamusica.ch dizionario entry 56; teatrosanmaterno.ch history):
- "the finest mystical dancer" (Jodjana stop): CARRIED — the Dizionario records Bara's judgment "il miglior ballerino mistico". Kept.
- "a school for expressive form" (temple stop): NOT carried by the cited theater history. Restored to the canon's wording from the school prospectus quoted in the Dizionario — "the school's aim is training in the expressive dance of the inner conditions of the soul" — and re-sourced accordingly.
- ADDED one genuine Bara quote the canon plainly carries, to the 1955 Easter-liturgy stop: "Dance is the most complete prayer, for the sense and the intensity of the gesture have no equal in the word" (Dizionario: "La danza rappresenta la preghiera più completa...").

**Campa**: all within word-count lint, present tense, in register; the great episodes (Vittoriale dream-commission, war refuge, Simon at Auschwitz, Szeemann canonization) carry their weight. **Canon-fidelity**: the Laban distinction (milieu + Wigman-Trümpy descent, never his hand) is kept exactly as the curator's honesty note requires; dates cross-checked against the Dizionario (birth 20.4.1901, 1917 debut, 1922 Kursaal, 1924/1926 Vittoriale, 1952 Schwind reopening, July 1958 last dance, death 7.12.1986) — all agree. Nothing debunked; nothing needed debunking.
