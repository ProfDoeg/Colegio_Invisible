# Falconetti journey — research report

**Dataset:** `falconetti.journey.json` — 32 stops, 8 segments, 1892–1984 (the file runs past her death: the ashes' return in 1960 and the film's Norwegian resurrection in 1981–84 are the final leg, which keeps the whole file strictly chronological while giving the film's afterlife its stops, as briefed).

## Sources
- **French Wikipedia (Maria/Renée Falconetti)** + Wikimonde mirror — the biographical backbone: Pantin 1892, Sermano father, Conservatoire (Féraudy 1912, Silvain 1913), Odéon 1916, Comédie-Française 1924–25 (and her recorded quote about it), Théâtre de l'Avenue 1929, Goldstuck/Switzerland, Argentina 1942/43, the Claudel and Cocteau stagings in Buenos Aires, remains in an Argentine cemetery until 1960 then cremated and moved to Montmartre.
- **carlthdreyer.dk** (Danish Film Institute) — the meeting, the unmade-face examination at her apartment, nine-month shoot, contractual head-shaving that moved technicians to tears, the never-made sequel *Catacombes*, the elocution lessons in Buenos Aires.
- **English Wikipedia (film + actress)**, **Offscreen**, **Far Out**, **sites.nd.edu** — premiere dates (Copenhagen 21 Apr 1928, Marivaux 25 Oct 1928), archbishop/censor cuts, UFA fire 6 Dec 1928, second negative fire 1929, Dikemark 1981 / NFI identification 1984.
- **Geneanet** — parents' birthplaces (Sermano / Cahors), the 1905 convent boarding.
- **Hélène Falconetti, *Falconetti* (Cerf, 1987)** cited as canon reference throughout but not directly consulted; the BnF Fonds Falconetti listed where its papers (Swiss bank letter, exile correspondence) ground a stop.

## Judgment calls
1. **Cause of death.** French Wikipedia says suicide; English Wikipedia says apparent suicide *by* the self-imposed restrictive diet. The brief's canon is "the slimming cure that kills" — I narrated the fast itself as the fatal rite (a self-directed final mortification), which honestly straddles both traditions without flattening either.
2. **Montmartre, not Montparnasse.** The brief said Montparnasse; every source (en/fr Wikipedia, Findagrave) says Cimetière de Montmartre, division 16, after 1960 exhumation and cremation in Argentina. I followed the sources.
3. **Which Argentine cemetery** held her 1946–60 is nowhere named; the stop uses Chacarita coordinates but the text claims only "an Argentine cemetery." Same honesty for the 1929 second-fire laboratory (generic Paris coords, "inferred").
4. **1942 vs 1943.** Sources split on her Argentina date; I used the reconcilable reading: leaves Europe 1942, Brazil late 1942, settles Buenos Aires 1943.
5. **Meeting Dreyer** dated late 1926 (traditional): La Garçonne premiered July 1926, Dreyer arrived in France that year; no source gives the day.
6. **Quotes:** only one survives verification — her barb about the Comédie-Française ("Quelle triste maison que le Théâtre-Français…"). Dreyer's "soul behind that façade" is his, not hers, so it lives in a campa paraphrase, not the quote field. All other quote fields are null.

## Gaps
- No attested day/month for the shoot's internal episodes (shaving, kneeling); marked "traditional" — canon events, undated.
- Buenos Aires venues for L'Échange / Les Monstres sacrés unidentified; her BA address unknown.
- The 1942 crossing route (port of embarkation, ship) unattested — Hélène's biography likely has it; the BnF fonds certainly does.

## Five richest episodes
1. **The head-shaving at Billancourt** — contractual, real tears, the crew silent and weeping "as at an execution": the actress and the saint become indistinguishable on camera.
2. **The Dikemark resurrection** — the uncensored cut found 1981 in a janitor's closet at a Norwegian asylum, in 1928 packaging addressed to the hospital's director; unexamined for three more years.
3. **The film's own via crucis** — archbishop's cuts, UFA fire (6 Dec 1928), the rebuilt-from-outtakes version burned again in 1929: the film martyred twice, like and beyond its subject.
4. **Dreyer in the boulevard theatre** — seeing "a soul behind that façade" of a soubrette in La Garçonne; the annunciation scene of the whole canon.
5. **The Buenos Aires ending** — recitals of Claudel and Cocteau for the exile colony, elocution lessons in poverty, the fatal fast, death 12 Dec 1946 in the corpus's own city; ashes home to Montmartre in 1960.

## Verification (2026-07-05)

Independent structure-and-canon pass over `falconetti.journey.json`. Repairs applied in place; file re-validated with python after edits.

**Structure.** JSON parses; 32 stops / 8 segments; every stop carries the full key set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources); all dates YYYY-MM-DD and strictly chronological 1892-07-21 → 1984-05-01; confidence values limited to attested/traditional/inferred and honestly assigned (the two lab-fire and shoot-rite stops correctly traditional/inferred, the premieres and death attested). Four campas ran 111–113 words; trimmed to ≤110 with wording-only cuts — the head-shaving, the last fast, the Artaud stop and the Oslo resurrection keep their full charge.

**Coordinates spot-checked (11 sites) — 5 fixed:**
- **Sermano, Haute-Corse**: was 42.349, 9.324 (~6 km off, wrong side of the Bozio); fixed to 42.315, 9.268 (fr.wikipedia commune coords 42°18′54″N 9°16′06″E).
- **Studios de Billancourt** (4 stops): was 48.826, 2.249 (~750 m off); fixed to 48.831, 2.256 — 49 quai du Point-du-Jour, per the Billancourt Studios record (48°49′50.5″N 2°15′22.9″E; site now the Canal+ building).
- **UFA Berlin (negative fire)**: was 52.474, 13.385; fixed to 52.464, 13.409 — UFA's Tempelhof studios, Oberlandstraße 26–35 (Nominatim geocode).
- **Dikemark, Asker**: was 59.790, 10.376 (~1.8 km off); fixed to 59.806, 10.381 (en.wikipedia: 59°48′21″N 10°22′50″E; article independently confirms the 1981 janitor-closet find of the original cut).
- **Oslo NFI**: was 59.914, 10.739; fixed to 59.910, 10.746 — Filmens hus, Dronningens gate 16 (Nominatim).

Verified correct as-is: Pantin, Palads Teatret (Axeltorv), Théâtre de l'Avenue (5 rue du Colisée — BnF confirms Falconetti bought it 1929 and was ruined by it), Monte-Carlo casino, Cimetière de Montmartre, and the unnamed Argentine grave (Chacarita coords, kept generic in the text as the report already explains).

**Dates.** Copenhagen premiere 21 Apr 1928, Marivaux premiere 25 Oct 1928, UFA fire 6 Dec, birth 21 Jul 1892 Pantin, death 12 Dec 1946 Buenos Aires — all confirmed against en/fr Wikipedia. The 1929 second-fire stop rests on the Offscreen tradition and stays "inferred" — correct handling.

**Quotes.** One quote in the file; target was 6 spot-checks but there is nothing else to check — verified verbatim against fr.wikipedia (note 2): "Quelle triste maison que le Théâtre-Français. J'étais aussi trop indépendante pour me soumettre à la hiérarchie désuète…". Dreyer's "soul behind that façade" correctly lives as campa paraphrase, never in her mouth. No fabricated quotes found; nothing to null.

**Canon fidelity.** Register held throughout — the knees-and-takes rite, the contractual head-shaving with the weeping crew, the film's double burning and its asylum-closet resurrection are all rendered at full mythic pressure; Montmartre div. 16 (not Montparnasse) stands as sourced. Stop count 32 sits inside the 20–40 target; no additions needed.

**Verdict: PASS** after 5 coordinate fixes and 4 campa trims.
