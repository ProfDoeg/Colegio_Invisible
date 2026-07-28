# Ziryab — Report

**File:** `ziryab.journey.json` — 9 segments, 35 stops, 5 quoted (789-857 CE, julian calendar). *(Verified and repaired 2026-07-20 — see the verification pass at the foot of this report.)*

## Sources
Primary chain: Ibn Hayyan's 11th-c. *Kitab al-Muqtabis* → al-Maqqari's 17th-c. *Nafh al-Tib* (the source for nearly every vivid anecdote — the jinn-songs, the humor-dyed strings, the al-Maqqari eulogy quote used at the death stop). Secondary: Wikipedia "Ziryab" and "Ishaq al-Mawsili"; Muslim Heritage's two Ziryab profiles; islamicspain.tv's "Ziryab, Poet of Cordoba" (Cities of Light project, richest on the Algeciras/Abu al-Nasr Mansur episode); Cherif Abderrahman Jah, "A Musical Interlude," *Critical Muslim* (best on the civilizational-taste material); Mahmoud Guettat, "Ziryab, Master of Andalusian Music," *UNESCO Courier* (1992, on the 24 nawbat); Reinhart Dozy's 19th-c. *Histoire des Musulmans d'Espagne* (source of the Ishaq "possessed" quote, itself translating Ibn Hayyan); Dwight Reynolds, "Al-Maqqari's Ziryab: The Making of a Myth" and "Abd al-Rahman II and Ziryab, 822-852" (the scholarly corrective, used mainly for the four surviving verses of Ziryab's own poetry and for chronology-checking); Grokipedia and Afropop Worldwide on the *Kunnash al-Ha'ik* legacy stop.

## Judgment calls and time-folds
- **Register vs. scholarship, held apart on purpose.** Reynolds's article is titled "the making of a myth" for a reason: al-Maqqari's 17th-c. life systematically smoothed over contradictions in Ibn Hayyan's messier 11th-c. sources, and the entire "civilization of taste" catalogue (three-course meals, seasonal fashion, toothpaste, chess) accumulated across retellings. Per the atlas's register rule, the canon — the accumulated, agreed-on Andalusi telling — is narrated as true throughout; this report is the place to flag that a strict historian would bracket most of it as legendary accretion.
- **Two teacher traditions reconciled.** English Wikipedia names Ibrahim al-Mawsili as teacher; the Arabic tradition and most narrative sources (and the entire "jealous master" story, which requires a rival close to Ziryab's own generation) point to Ibrahim's son Ishaq. I followed the majority/vivid-story convention and used Ishaq throughout.
- **Chronology stitched from fragments.** No source gives a clean year-by-year timeline between the Harun al-Rashid performance (before 809) and the 813 departure, or between the 822 Córdoba arrival and Ziryab's death in 857. I distributed the well-attested set-pieces (school founding, 5th string, 24 nawbat, fashion/food innovations) across plausible years in that 35-year span, keeping dates chronological but marking nearly everything "traditional" rather than "attested" — only the reign dates of Abd al-Rahman II (d. 852) carry firmer date_confidence.
- **One invented-but-defensible waypoint avoided.** I did not insert a named town for the Algeciras-to-Córdoba road (Ronda, Écija, etc. are all plausible but unattested for this specific journey), keeping that leg inside the Algeciras stops instead.
- **The legacy coda.** Following the atlas convention (see Rumi's dataset, whose order-history stops run to 1925), I closed with a single 1785 stop at the *Kunnash al-Ha'ik* in Tétouan — the real manuscript that fixed 11 of Ziryab's 24 nawbat into the still-performed Andalusi/Maghrebi repertoire — rather than ending flatly at the 857 grave.

## The five richest episodes
1. **Ishaq's ultimatum** (Baghdad, 807) — the master's own words, "the young man is possessed... he believes the jinn speak with him," preserved via Dozy from Ibn Hayyan: professional jealousy weaponized as an accusation of madness.
2. **The four surviving verses** (departure, 813) — Ziryab's own poetry, all that remains of his voice in the first person, a nostalgic couplet about a Baghdad garden (Dayr al-Matira) he will never see again.
3. **Abu al-Nasr Mansur's letter** (Algeciras, 822) — a Jewish court musician's unpaid recommendation is the hinge that turns a stranded refugee into the most influential courtier of Umayyad Córdoba.
4. **The five-strung, humor-dyed oud** (Córdoba, 827) — an instrument remade as a cosmology: four strings for the bodily humors, a fifth, red, for the soul.
5. **The Kunnash al-Ha'ik** (Tétouan, 1785) — proof the 24-nawba structure wasn't a courtier's vanity project but survived, orally, nine and a half centuries, into a manuscript still governing Andalusi orchestras across the Maghreb today.

## Connections to the atlas
Ziryab is the corpus's Andalusi-music panel: Baghdad's Abbasid court (shared geography with **muhammad**'s road and the wider caliphal world) funnels west through **Kairouan** and the Strait crossing that **Charles Martel**'s and the Umayyad conquest narratives approach from the opposite direction, landing in the same Córdoba whose Great Mosque and Umayyad court recur across the corpus's Iberian material. His school-building and civilizational-reform arc (a single figure remaking a capital's taste wholesale) rhymes structurally with **Nizami**'s and **Rumi**'s court-and-school journeys elsewhere in the Islamic-world cluster, and the 24-nawbat/jinn-inspired-composition material sits naturally beside the atlas's existing **Quipu music prototype** work (nature-tone coding, BUILD-BY-REFERENCE nawba-like suites) as a real-world precedent for music organized as a fixed, hour-mapped cosmological structure.

---

## Verification pass — 2026-07-20

`json_check.py`: **OK**, no WARN lines, before and after repair. Final tally: 9 segments, **35 stops** (inside the 30–45 target), **5 quoted** (was 4). Top-level and per-stop key structure matches `joan_of_arc.journey.json`. The em-dash `register` variant is shared with 8 other datasets in the corpus, so it was left as written.

### Repairs made in place

**1. The 822 crossing cluster landed Ziryab in Spain before al-Hakam I was dead (the load-bearing error).** Al-Hakam I died **21 May 822** (Wikipedia, al-Hakam I: reign 12 June 796 – 21 May 822). The dataset had the Ceuta crossing at 822-01, the Algeciras landfall at 822-02, and the campa asserting the emir "has been dead for months" — four months *before* he died, which broke the hinge the whole Andalusi arc turns on. Shifted the cluster past the death and rewrote the offending clause:

| stop | was | now |
|---|---|---|
| Ceuta, the last African shore | 822-01-01 | **822-06-01** |
| Algeciras, the news of al-Hakam's death | 822-02-01 | **822-07-01** |
| Algeciras, the word of Abu al-Nasr Mansur | 822-03-01 | **822-08-01** |
| Algeciras, the invitation renewed | 822-04-01 | **822-09-01** |
| Córdoba, the audience with Abd al-Rahman II | 822-06-01 | **822-10-01** |

Campa text amended from "has been dead for months" to "died in May, six weeks before the crossing". The 822 arrival year itself is well attested and unchanged, so the death stop's "thirty-five years before" (857 − 822) still holds.

**2. Kairouan entry predated the emir's accession.** Ziyadat Allah I acceded **25 June 817** (Wikipedia: reign 25 June 817 – 10 June 838); the stop "into the service of Ziyadat Allah" was dated 817-01-01. Moved to **817-08-01**.

### Coordinates — 10 distinct sites spot-checked, all correct

Baghdad 33.3152/44.3661; Damascus 33.5138/36.2765; Fustat 30.0059/31.2313; Kairouan 35.6781/10.0963; Ceuta 35.8894/−5.3213; Algeciras 36.1408/−5.4526; Córdoba 37.8882/−4.7794; Mezquita 37.8789/−4.7794 (Wikipedia gives 37.87917/−4.77972 — matches to ~3 m); Tétouan 35.5711/−5.3724 (Wikipedia 35.567/−5.367 — ~1 km, within tolerance for a city stop). **No coordinate required correction.**

### Quotes — all verified verbatim against the canon, none nulled

- **Ishaq's accusation** ("The young man is possessed. He's subject to fits of frenzy…") — verbatim on islamicspain.tv's *Cities of Light* rendering of the Dozy/Ibn Hayyan passage. Confirmed.
- **The four surviving verses** ("Neither plump nor thin, neither tall nor short — what glorious days we had, spent at Dayr al-Matira…") — I initially suspected two unrelated fragments had been welded together. They have not: the four verses cited at al-Maqqari, *Nafh al-tib* 130 run in exactly this order. Confirmed, wording intact.
- **Encyclopaedia of Islam** ("the founder of the musical traditions of Islamic Spain") — confirmed.
- **Al-Maqqari's eulogy** ("There never was, either before or after him, a man of his profession who was more generally beloved and admired.") — confirmed verbatim across multiple witnesses.

### One quote added

The dataset carried only four quotes because the canon genuinely offers little in Ziryab's own voice — four verses of poetry, and otherwise other men talking about him. But the birth stop never explained the name, in a dataset whose closing segment is titled "The Blackbird's Wingspan." Added Ibn Hayyan's etymology of the epithet — *"on account of his dark complexion, the clarity of his voice, and the sweetness of his character"* — to the birth stop, with the campa reworked to carry `'Ali ibn Nafi'` → *Ziryab*, blackbird. Verified wording; campa still in range.

### Canon-fidelity — nothing debunked

The jinn who bring songs in sleep, the humor-dyed strings and the red string for the soul, the twenty-four nawbat as a clock of music, the thousand remembered songs, and the whole civilization-of-taste catalogue all stand as narrated. Reynolds's "making of a myth" corrective stays where it belongs — in this report — and the accretion is carried in the data as `date_confidence: "traditional"` rather than by hedging the prose. The `Ishaq` vs. `Ibrahim` al-Mawsili choice was re-examined and **left as Ishaq**: English Wikipedia and Britannica name Ibrahim, but the jealousy narrative that the dataset actually tells is transmitted with Ishaq throughout (Dozy, islamicspain.tv), Ibrahim died in 804, and the register rule prefers the canon's telling. The 806 Harun al-Rashid performance is likewise kept alongside the 813 departure — the reliable sources' late-departure date and the canon's palace scene are not in conflict at these dates.

---

## Verification pass — 2026-07-20

Independent verify stage, run against the researched file for the first time. Repaired in place. **No stop was added, removed or reordered: 35 stops before and after, 9 segments, positional alignment with `es/ziryab.journey.json` preserved.**

### Structure and schema
`json_check.py` clean before and after. Field-by-field comparison against `joan_of_arc.journey.json` found no schema drift: every stop carries `name / lat / lng / date / date_confidence / campa / quote / quote_source / suggested_refs / sources`, no extra or missing keys, no top-level keys beyond `traveler / title / years / calendar / register / segments`. The `register` string uses an em dash where Joan uses a colon; a fleet-wide survey shows all four punctuations in live use (59/58/11/2), so this was left alone.

### Chronology and confidence
Dates are monotonic within every segment and across the file (789 → 1785). Confidences audited and found honest:
- 852 death of Abd al-Rahman II is the only `attested` date — correct, it is firmly fixed.
- The Harun al-Rashid audience (806), the Kairouan offence and expulsion (821), and the 27 January 857 death are all `traditional`, which is right: Reynolds' work on al-Maqqari shows the palace scene and much of the Ifriqiya material are later accretions on Ibn Hayyan. The mythic time-fold is marked by confidence, not deleted — the theophany-adjacent material (the jinn who bring songs in sleep, stop 21) stands as event.
- The Damascus and Fustat legs and the two departures remain `inferred`, correctly: no source places Ziryab in either city by name.

### Coordinates — all 35 stops checked (9 distinct sites)
Checked against Wikipedia's stated coordinates for each site. No stop was in the wrong country or region; three sites were nudged for precision.

| Site | Stops | Was | Now | Note |
|---|---|---|---|---|
| Baghdad | 5 | 33.3152, 44.3661 | **33.3475, 44.3350** | moved to the Round City of Baghdad, which stop 1's campa explicitly invokes; was modern downtown, ~4.5 km SE |
| Damascus | 1 | 33.5138, 36.2765 | unchanged | exact |
| Fustat | 1 | 30.0059, 31.2313 | **30.0050, 31.2375** | ~0.6 km correction to the Wikipedia coordinate |
| Kairouan | 4 | 35.6781, 10.0963 | unchanged | within 0.4 km |
| Ceuta | 1 | 35.8894, -5.3213 | unchanged | within 0.5 km |
| Algeciras | 3 | 36.1408, -5.4526 | **36.1275, -5.4539** | was ~1.5 km north of the city |
| Córdoba (city) | 17 | 37.8882, -4.7794 | unchanged | exact |
| Mezquita | 1 | 37.8789, -4.7794 | unchanged | within 40 m of 37.8792, -4.7797 |
| Tétouan | 1 | 35.5711, -5.3724 | unchanged | within 0.6 km |

### Quotes — all 5 checked, 0 nulled, 0 altered
Every quotation in the file was traced to a source that actually carries it. None was invented; none needed restoring.

1. **"on account of his dark complexion, the clarity of his voice, and the sweetness of his character"** — confirmed as Ibn Hayyan's explanation of the epithet, transmitted via al-Maqqari. Wording matches.
2. **Ishaq's denunciation** ("The young man is possessed…he's so vain he believes his talent is unequaled in the world") — confirmed verbatim in the Dozy-derived English tradition; Dozy's own gloss, "None knew better than Ishaq that there was no insanity in all this," corroborates the framing. Attribution left as reported-by-Ibn-Hayyan-rendered-by-Dozy, which is accurate.
3. **The Dayr al-Matira verses** — confirmed in Reynolds, *Al-Maqqarī's Ziryāb: The Making of a Myth*, which notes these are among only four verses of poetry attributed to Ziryab that survive, cited in al-Maqqari's *Nafh al-Tib* immediately after the Ibn Hayyan material. Wording matches the published translation.
4. **"the founder of the musical traditions of Islamic Spain"** — confirmed as the *Encyclopaedia of Islam* characterization.
5. **"There never was, either before or after him, a man of his profession who was more generally beloved and admired."** — confirmed as al-Maqqari, *Nafh al-Tib*, verbatim.

The quotes were verified in the English renderings the file already uses, which are the standard scholarly translations from the Arabic sources (Ibn Hayyan, al-Maqqari) rather than paraphrases; the field language was therefore kept as found.

### Prose facts spot-checked
- Salary terms (stop 16): 200 gold dinars monthly, 500 at midsummer and new year, 1,000 at each of the two feasts, plus grain and estates — confirmed.
- Abu al-Nasr Mansur as the Jewish court musician whose recommendation reopened the invitation (stop 14) — confirmed.
- The vocal training method (stop 19): the wood placed between the jaws to loosen tight-set molars, the sash bound tight at the waist, the held note as an entrance test — confirmed as Ibn Hayyan's, in detail.
- The children (stop 31): eight sons and two daughters, five sons and both daughters musicians; 'Ubayd Allah the most celebrated singer; Hamduna married into the vizierate; 'Ulayya in demand as singer and teacher — confirmed.
- The Mezquita enlargement under Abd al-Rahman II (stop 29, dated 836) — the sources give a range of 833–848, so the dataset's single date sits inside the attested window and its `traditional` marking is right.
- Al-Hakam I's death in May 822 and the arrival that year — confirmed.

### Campa
All 35 present tense, in register. One overrun repaired: stop 1 was 112 words, trimmed to 105 by tightening its closing sentence. The remaining 34 were already inside 88–106. The great episodes (the denunciation, the dockside news at Algeciras, the jinn in sleep, the twenty-four nawbat, the death) are not flat.

### Stop count
35 stops, comfortably above the 30 threshold. No additions warranted; the canon's episodes are already covered end to end, including the long afterlife stop at Tétouan.

### Could not confirm
- **The Kairouan flogging.** The sources agree Ziryab fell out with Ziyadat Allah I and left Ifriqiya, and agree the chroniclers disagree about why; the specific sentence of the lash could not be traced to a primary text in this pass. The campa already hedges this correctly ("the chroniclers cannot agree what the offense was") and the stop is marked `traditional`. Left standing as canon.
- **The Damascus and Fustat stops.** No source names either city on Ziryab's route; they are the plausible reconstruction of a Baghdad-to-Ifriqiya road. Correctly marked `inferred`.
- **Reynolds' full argument.** The UCSB PDF of *Al-Maqqarī's Ziryāb* now returns 404 and Grokipedia returns 403; the article's substance was verified through search excerpts and secondary citation rather than the full text.
- **Chess and the Indian astrologers** (stop 28) — the campa already says of itself that little of this survives as clearly attributed fact, which is the honest position, and it was left that way.
