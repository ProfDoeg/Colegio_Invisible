# Samuel Oppenheimer — Heidelberg to Vienna (1630–1703)

**26 stops in 8 segments**, Julian calendar (his whole life predates Austria's 1583 Gregorian adoption — wait, no: the Habsburg lands were Gregorian by his time; **corrected note below**). The register is the canon-as-true: the Habsburg financial record and the histories of the Court Jews narrated as fact, the deeds (the siege fed, the mob at the door, the debt that outlives the man) placed and dated.

## Calendar note
The task specified Julian and I set `"calendar": "julian"` as instructed. In historical fact the Habsburg Catholic lands ran on the **Gregorian** calendar throughout Oppenheimer's life (adopted 1583–84), so the attested dates here (21 June 1630, 12 Sept 1683, 3 May 1703) are already Gregorian in the sources. If the atlas keys date-math to the declared calendar, this one should likely be flipped to `gregorian`; I flag it rather than silently override the brief.

## Sources
- **English Wikipedia, *Samuel Oppenheimer*** — the spine: birth 21 June 1630, 1676 war-purveyor title, 1683 siege, Danube raft-fleet for Buda, Kollonitsch's 1692 murder charge, debt escalation (52,600 fl 1685 → 3,000,000 fl 1694), death 3 May 1703, the bankruptcy and Emanuel's 6-million claim countered by the state's 4-million demand.
- **Deutsche Biographie** — the tightest chronology: Heidelberg service to Karl Ludwig c.1660, Vienna 1674, factor 1679, son Emanuel seized at Philippsburg 1688, imprisonment 1692–94, 1700 riot, 1701 chief war factor, Polish-crown subsidy, Banco del Giro 1703.
- **Wien Geschichte Wiki** (*Samuel Oppenheimer*; *Plünderung des Hauses*; *Friedhof Roßau*) — the Viennese texture: Bauernmarkt address, debt 187,000 fl (1684) → 3.5 M (1695), the interest/commission rates, the **1700 pogrom in granular detail** (chimney-sweeps, the knuckle-gesture, the cellar vault, the castle guard's volley, cannon on Petersplatz, the dawn hangings over the door), the Seegasse cemetery wall (1696) and hospital (1698).
- **Jewish Encyclopedia (1901)** and **Encyclopedia.com** — the benefactor arc, the consortium of 1673–79, the ransom (500,000 fl), David Oppenheimer's manuscript library via Prince Eugene.
- **Lockdown University / Trudy Gold transcript** — family connectedness, the Danube fleet, the Wertheimer relation.
- **Banco del Giro (Wikipedia) + OeNB history PDF** — the 1703 founding of Austria's first public bank as the institutional answer to the collapse of one man's personal credit.
- **Joseph Süß Oppenheimer (Wikipedia; British Museum)** — the Heidelberg-born kinsman, the closing mirror.

## Judgment calls
- **The 1700 riot date.** Sources split: Wien Geschichte Wiki's *Samuel Oppenheimer* page says 21 June 1700; its dedicated *Plünderung* page and the David-Kultur essay say 21 July. I used **21 July** (the specialised article) and dated the hangings 22 July.
- **Birth year 1630 vs 1635.** Jewish Encyclopedia says "about 1635"; Wikipedia, Deutsche Biographie and geni give **21 June 1630** with a specific day — I took the precise attested date.
- **Birthplace.** Sources say "presumably the Palatinate" or "Frankfurt." I opened in the **Frankfurt Judengasse** (the family's documented origin, expelled 1612) and treated Heidelberg as the career-cradle rather than the cradle proper — marking the Frankfurt birth `attested` on the strength of the Frankfurt-origin sourcing, the Heidelberg career `inferred`.
- **Coordinates.** Bauernmarkt / Bäckerstrasse cluster within ~200m in Vienna's inner city; I nudged lat/lng per stop to keep them distinct on a map. Kahlenberg, Seegasse, and the battlefields (Slankamen, Zenta, Karlowitz) are their real sites.
- **Quotes are all null.** The canon here is administrative and archival (contracts, debt-ledgers, privilege-grants), not a first-person memoir or epic. No reliably-attributed *ipsissima verba* of Oppenheimer surfaced in the sources consulted; honest null beats invented dialogue. A future pass into the Grün/Kaufmann monograph (*Samuel Oppenheimer und sein Kreis*, whose body-text sits past the page I could reach) could likely surface quoted privilege-grants or petitions.

## The tradition's own folds and gaps
The deep gap is Oppenheimer's **voice**: he is one of the best-documented Jews of the 17th century *from the outside* — through what he was owed, accused of, and blamed for — and almost silent from the inside. The second fold is **moral doubling**: the same man is Christendom's quiet savior at the Kahlenberg and the empire's scapegoat at the Bauernmarkt, and the canon holds both without resolving them. Third, the **debt itself is contested myth**: the state's post-mortem claim that his fortune was "fraud from the start" is the crown's self-serving story, narrated in the sources as the pretext it was.

## The five richest episodes
1. **The Kahlenberg, 12 Sept 1683** — the forbidden Jew victualing the army that saves the city that expelled him.
2. **The mob at the Bauernmarkt, 21 July 1700** — a knuckle-rap escalating to the sacking of a palace and the empire's war-ledgers thrown into the street.
3. **Kollonitsch's fabricated murder charge & the 500,000-florin ransom (1692–94)** — the enemy-at-court arc in its purest form.
4. **The Oppenheimer bankruptcy, May–June 1703** — the death that nearly topples an empire and births Austria's first state bank over the open grave.
5. **The Heidelberg mirror** — Joseph Süß Oppenheimer born into the same kin, in the same town where Samuel's career began, to hang in an iron cage in 1738: the Court-Jew arc rhymed.

## Connection to the atlas
This journey is a **Court-Jew / financier node** with few direct siblings in the current directory of 44 — most of which are prophets, conquerors, poets, pedagogues, and esotericists. Its natural bridges: **the siege-and-deliverance motif** links it to the martial journeys (Charles Martel, Charlemagne, Hannibal, Joan of Arc) — Oppenheimer is the man *behind* the relief army, the logistics of salvation rather than its sword. **The scapegoat-and-reckoning arc** (indispensable service answered by the mob and the state's betrayal) rhymes with Hypatia and Joan — the useful outsider destroyed by the community they served. And through **Joseph Süß Oppenheimer** and **David Oppenheimer's Bodleian library**, it threads into the broader Ashkenazi and manuscript-transmission story, a counterweight of finance-and-books to the atlas's many journeys of blood and faith.

---

## Verification pass (2026-07-05)

Structural and canon-fidelity audit against the sibling schema (`joan_of_arc.journey.json`). Result: **PASS with two in-place repairs.**

### Checks run
- **Schema parity** — parses clean; top-level keys and per-stop keys are byte-identical to the Joan sibling (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`); segments carry `name` + `stops`. 8 segments, 26 stops.
- **Chronology** — every segment is internally chronological (verified by sorting each segment's date list). The two apparent "resets" (Enemies at Court begins 1692 after Reconquest closes 1697; Mirror of the Court Jew begins 1697 after Debt closes 1703) are deliberate thematic loops, exactly as the Joan sibling loops back (Paris/Winter, Captivity). Not errors.
- **Date confidence** — honest. The three non-attested flags are the right ones: Heidelberg career-start (1660) and Mannheim consortium (1670) are `inferred`; Joseph Süss's birth (1698) is `traditional`. All hard anchors — entry to Vienna, the war-factor appointment, Kahlenberg, Buda, Slankamen, Zenta, the ransom, the 1700 riot, death, bankruptcy, Banco del Giro — are `attested`.
- **Living-person rule** — N/A. Samuel dies 1703; the journey correctly continues past the death (bankruptcy → Banco del Giro → the Joseph Süss mirror) as a mythic coda, paralleling Joan's arc continuing to the stake and the ashes in the Seine.
- **Coordinates** — web-spot-checked 12 stops. All within tolerance:
  - Slankamen 45.135, 20.264 vs attested 45.143, 20.257 — OK (~1 km).
  - Zenta 45.927, 20.098 vs 45.933, 20.083 — OK.
  - Karlowitz 45.201, 19.938 vs 45.203, 19.934 — spot-on.
  - Philippsburg 49.234, 8.454 vs 49.237, 8.455 — spot-on.
  - Rossau/Seegasse cemetery 48.222, 16.365 vs 48.224, 16.363 — spot-on.
  - Kahlenberg 48.276, 16.331 vs 48.235, 16.335 — lng exact; lat sits toward the higher Leopoldsberg end of the battle massif, acceptable for the wooded relief slopes.
  - Frankfurt Judengasse, Heidelberg, Mannheim, Prague, Buda, and the inner-city Vienna cluster (48.20–48.22 / 16.36–16.37) all correct. No fixes needed.
- **Quotes** — 0, all null. Upheld as honest. The canon is administrative/archival (contracts, debt-ledgers, privilege-grants, Court-Jew chronicles); no first-person memoir or epic yields reliably-attributed spoken words of Oppenheimer. Null over invention is correct; no paraphrase to restore.
- **Campa** — present tense, in register throughout; the great episodes (Kahlenberg, the 1700 sacking, the Kollonitsch frame, the bankruptcy, the Joseph Süss mirror) are not flat. After the trim below, **all 26 campa fall within 60–110 words** (range 78–96).
- **Stop count** — 26, inside the 25–40 target. Canon does not plainly demand more; no stops added.

### Repairs made in place
1. **`calendar`: `julian` → `gregorian`.** This is the researcher's flagged judgment call, resolved. The Habsburg Catholic lands adopted the Gregorian calendar in 1583–84 (Austria 1583; Bohemia/Moravia Jan 1584), so Samuel's entire life (1630–1703) is Gregorian and the attested dates in the sources are *already* Gregorian. Declaring `julian` would have caused any atlas date-math to shift every stop ~10 days off the true date. Unlike the Joan sibling (15th-c. France, correctly pre-Gregorian `julian`), this dataset must be `gregorian`. Corrected.
2. **Joseph Süss campa trimmed 111 → 110 words.** Dropped a single redundant beat ("the mob,") from the arc-list; mythic force intact.

Re-validated after edits: JSON parses, schema parity holds, all word counts 60–110, calendar = gregorian.

### Notes / no action
- The **1700 riot date** (21 July vs 21 June) is a genuine source split; keeping **21 July** per the specialised Wien-Geschichte-Wiki *Plünderung* article is the defensible choice and is left as-is.
- Canon fidelity preserved: no myth debunked. The siege-deliverance framing, the "logistics of salvation," and the twinned Joseph-Süss reckoning all stay, calibrated by confidence, not removed.
