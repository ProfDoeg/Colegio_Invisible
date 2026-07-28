# Maimonides — build report

**Stops:** 35 across 7 segments. **Quoted:** 10. **Span:** 1138–1205 (julian calendar). *(Updated by the 2026-07-24 verification pass; see the section at the end.)*

## Sources
Primary spine: Joel Kraemer's *Maimonides: The Life and World of One of Civilization's Greatest Minds* (2008), the Stanford Encyclopedia of Philosophy entries on Maimonides and on Islamic influence upon him, Wikipedia's Maimonides/Mishneh Torah/Guide for the Perplexed/Tomb of Maimonides/Ibn Jumay'/Nagid articles, the Jewish Encyclopedia (1906) entry, and several direct-quote sources: the Temple Institute's page on his Temple Mount colophon note, Haaretz and Portuguese Jewish News pieces reconstructing the 1165 Acre/Jerusalem/Hebron dates from his own marginal note, the Jewish Link's excerpt of his 1185 grief letter over his brother David, the Jewish Virtual Library's excerpt of his letter to Samuel ibn Tibbon on his court-physician schedule, and Wikisource's Epistle to Yemen. Medical-treatise details from PMC and medicinetraditions.com; the ransom-of-Bilbays receipt from the National Library of Israel blog; the tomb legend from Danny the Digger and Bein Harim Tours. Essay 190 (al_andalus_and_reconquista) in the corpus already names Maimonides as the exemplar of La Convivencia — this journey expands that single paragraph into full stops.

## Judgment calls and time-folds
- **Birth date**: sources split 1135 vs. 1138; the curator specified 1138, and recent Geniza-based scholarship (March 28, 1138) supports it, so I used that over the older Sefer Yuhasin date (1135).
- **The "wandering years" (1148–1160)**: undocumented by any signed page. I anchored them at Almería (a plausible, commonly-cited refuge under Christian rule 1147–1157) rather than inventing an itinerary the record doesn't support — both stops there are marked "inferred."
- **David's death date**: sources genuinely disagree — some say the shipwreck itself was ~1169/1170, others calculate ~1177 from Maimonides' own 1185 letter ("eight years" since the tidings reached him). I used 1177 for "the tidings reach him," which is the phrase his own letter supports, and flagged it "inferred" rather than "attested."
- **Egypt's timeline is deliberately non-linear across segments**: Segment 4 (Nagid, ransom, David's death, 1166–1177) and Segment 5 (the Code, 1170–1185) and Segment 6 (physician, 1174–1199) overlap in real time — this mirrors how sibling datasets (e.g. al_kamil.journey.json) split a single life into parallel thematic legs rather than forcing one flat chronology. Each segment is internally chronological, per the linter.
- **Arrival date at Acre**: Wikipedia says May 16, 1165; I used May 23 ("3rd of Sivan"), because that date comes with a direct quote from Maimonides' own colophon and is corroborated by two independent secondary accounts.
- The "Oath of Maimonides" (the famous physician's prayer) is a known 18th-century forgery misattributed to him — I deliberately did not use it, despite its ubiquity in medical-history pop writing.

## The five richest episodes
1. **The martyrdom of ibn Susan and the flight from Fez** (1165) — his own teacher executed for refusing, this time openly, what the family had been quietly faking for years.
2. **The storm at sea and the vow at Acre** (1165) — the only place in his corpus where Maimonides, arch-rationalist, institutes a personal ritual out of sheer gratitude for survival, in his own hand.
3. **The ransom of the Bilbays captives** (1168) — his first public act in Egypt, a receipt in his own hand, years before any title.
4. **The letter to Yefet on David** (1185, recalling 1177) — the one unguarded grief in an otherwise supremely composed corpus: "my heart goes faint within me."
5. **The letter to Ibn Tibbon on the impossible day** (1199) — the Guide's own author too exhausted by medicine to answer his translator in person.

## Connections to the rest of the atlas
- **ibn_arabi**: near-exact contemporary geography (Córdoba, Fez) one generation later (b. 1165, the very year Maimonides fled Fez) — the same Almohad Maghreb producing, almost simultaneously, the rationalist who reconciles Aristotle with Torah and the mystic who reconciles Ibn Arabi's own visions with the Qur'an. Neither records meeting the other's world, but they breathe the same convivencia air.
- **al_kamil**: al-Kamil (b. 1180, Cairo) is a young prince in the same Ayyubid Cairo where the aging Maimonides serves as court physician (1174–1204) — they almost certainly crossed paths at court, though no direct record survives; the shared geography (Cairo/Damascus/Jerusalem) is now pinned in both files.
- **abdelkader**: the Damascus/Jerusalem geography and the theme of interfaith rescue (Abdelkader shelters Christians in 1860 as Maimonides once served a Muslim sultan's court) bookend the corpus's Convivencia thread nearly seven centuries apart.
- **columbus**: the crypto-Jewish thread — Maimonides' own Fez decade of feigned conversion is the medieval template for the conversos and crypto-Jews of 1492 Iberia, several of whom sailed with or after Columbus; essay 190 already draws this line explicitly.
- **ramon_llull**: named in essay 190 alongside Maimonides as the two poles of Andalusi philosophical cross-pollination — Llull's combinatoric art answers, a century later, the same problem of reconciling revealed religion with a rigorous universal method that the Guide poses first.
- **aristotle**: the entire Guide for the Perplexed is Maimonides' sustained argument with him; this is now the explicit throughline connecting this file to any future Aristotle journey.

No stops needed inventing outright; the record — Geniza letters, his own colophons, the Mishneh Torah's colophon, the Guide's dedicatory epistle — is unusually rich and self-documenting for a medieval life, which is why "attested" outnumbers "inferred" and "traditional" combined.

---

## Verification pass — 2026-07-24

Structure and canon-fidelity audit against `joan_of_arc.journey.json` as schema reference. `json_check.py` passed clean before and after (no WARN lines). Top-level and per-stop key sets match the reference exactly. Final tally: **7 segments, 35 stops, 10 quoted**, span 1138–1205.

### Chronology and dates

Within-segment ordering was already correct throughout, and the deliberate cross-segment overlap of the Egypt legs (4/5/6) is a legitimate structural choice matching `al_kamil.journey.json`. Two date defects were found and fixed, both in the 1165 voyage, where the whole sequence is anchored on Maimonides' own colophon note.

Working from the colophon's fixed points (3 Sivan 4925 = Sunday = 23 May 1165, per the Temple Institute transcription the file already cites), the Hebrew–Julian arithmetic resolves cleanly and confirms most of the file:

- 10 Iyar (the storm) = 22 days before 3 Sivan = **1 May 1165**, and 22 mod 7 = 1, so a **Saturday** — exactly as the canon says ("On Shabbat, on the 10th of the month of Iyar"). The file's date was already right.
- 6 Marcheshvan 4926 = 151 days after 3 Sivan = **21 October 1165**, and 151 mod 7 = 4, so a **Thursday** — exactly as the canon says. The file's date was already right. (The Temple Institute page brackets this as "October 21, 1166"; the year is their typo, since the colophon itself says 4926, whose Marcheshvan falls in autumn 1165. The file's 1165 is correct.)
- 9 Marcheshvan = **24 October 1165**, a Sunday — matches the canon ("On Sunday of the following week, the 9th of the month"). Already right.
- 4 Iyar (the flight from Fez) = 28 days before 3 Sivan = **25 April 1165**, and 28 mod 7 = 0, so the same weekday, i.e. the Hebrew day that begins Saturday night — exactly the canon's "on the night following the Sabbath." **The file had 1165-04-18 and called it "Friday": both wrong, and mutually inconsistent with its own storm date one week later.** Fixed to `1165-04-25`, campa reworded to "On the night following the Sabbath, the fourth of Iyar."

Also adjusted: the funeral journey ran Fustat → Ashkelon in a single calendar day (1204-12-13, one day after death) and Ashkelon → Tiberias in seven more. That is roughly 430 km overland in twenty-four hours. The tradition fixes no timing, so the two "traditional" stops were spaced to a plausible overland pace: road `1204-12-26`, tomb `1205-01-12`. The death date (1204-12-12) and the 20th-of-Tevet pilgrimage framing are untouched and correct — the pilgrimage is the yahrzeit of the death, not of the burial.

Confidences audited stop by stop and left as the researcher set them; the 1148–1160 Almería anchor and the 1177 tidings-of-David are honestly marked "inferred," and the birth, the storm-vow and the tomb legend "traditional." The camel that chooses its own resting place beside Yohanan ben Zakkai stays exactly as written.

### Coordinates — 12 spot-checked

| Stop | Was | Now | Note |
|---|---|---|---|
| Córdoba (Mezquita) | 37.879, -4.7794 | unchanged | exact |
| Almería | 36.8381, -2.4597 | unchanged | exact |
| Fez | 34.0656, -4.9731 | unchanged | lands on the Qarawiyyin in Fes el-Bali; apt for the stop's own suggested_ref |
| Acre | 32.928, 35.0817 | unchanged | Wikipedia 32.92778, 35.08167 |
| Temple Mount | 31.7767, 35.2345 | **31.7781, 35.2358** | was generic Old City; now the Haram itself (31.77806, 35.23583) |
| Cave of Machpelah | 31.5253, 35.1103 | **31.5247, 35.1107** | Wikipedia 31.5247, 35.1107 |
| Alexandria | 31.2001, 29.9187 | unchanged | exact |
| Fustat / Ben Ezra | 30.0059, 31.2312 | unchanged | Ben Ezra Synagogue 30.00581, 31.23097 |
| Bilbays | 30.4306, 31.5619 | **30.4167, 31.5667** | was ~1.6 km off; Wikipedia Bilbeis 30.41667, 31.56667 |
| Cairo Citadel | 30.0287, 31.2599 | unchanged | exact |
| Ashkelon (funeral road) | 31.6688, 34.5742 | unchanged | exact; a real waypoint on the coastal road |
| Tomb, Tiberias | 32.7957, 35.5321 | unchanged | Wikipedia carries only two decimals (32.79, 35.54); the file's value is central Tiberias and within the rounding neighbourhood. Left alone rather than moved to a less certain point. |

The open-sea stop (34.0, 28.0) is a notional mid-Mediterranean point on the Maghreb–Palestine lane; correct as a symbolic waypoint.

### Quotes — 8 checked, 2 trimmed, 1 restored, 2 added

Verified verbatim and carried unchanged:
- **Psalm 129:2 in the Epistle to Yemen** — confirmed present in Iggeret Teiman with the file's exact wording.
- **Guide, Dedicatory Epistle** ("Your absence moved me to compose this Treatise…") — Pines translation, exact.
- **Letter to Ibn Tibbon on the impossible day** — confirmed present in the cited Jewish Virtual Library text.
- **Letter to Yefet on David's death** — confirmed verbatim ("the demise of the saint, may his memory be blessed, who drowned in the Indian sea").
- **"From Moses to Moses arose none like Moses"** — the traditional Tiberias epitaph; correctly labelled traditional.

Repaired:
- **Acre colophon.** The second sentence ("These days I vowed will be for me and my house festival days…") could not be verified in any accessible transcription and conflates the two vows. Trimmed to the verified first sentence.
- **Jerusalem colophon.** The appended Psalm 27:4 tail ("to behold the pleasantness of the Lord…") is likewise unverified in the colophon. Trimmed to the verified sentence.
- **Mishneh Torah, Matnot Aniyim 8:10.** The file carried a loose older rendering. Restored to the canon's wording as it stands in the standard translation: "The redemption of captives receives priority over sustaining the poor and providing them with clothing. There is no mitzvah as great as the redemption of captives."

Added (both verified against the same colophon the file already cites):
- **The storm**, 10 Iyar 4925 — "we were confronted with great waves which nearly drowned us all, as a violent storm arose at sea."
- **Hebron**, 9 Marcheshvan — "I left Jerusalem and set out for Hevron, to visit the graves of our forefathers in the cave of the Machpelah."

### Campa

All 35 pass the 60–110 word band, present tense, in register. One campa was rewritten for canon-fidelity rather than length: the storm stop had Maimonides "say nothing of panic," counting the trial "among the sea's ordinary dangers," and vowing the day of landfall as a feast. The canon says the opposite on both counts — the waves nearly drowned them all, and the day he vowed as a *fast* is the storm day (10 Iyar), with the feasting reserved for the landfall (3 Sivan). The rewrite restores the fast, which is the sharper detail: the arch-rationalist institutes a private day of dread. This was the single flattened great episode in the file.

### Stops added

The file was inside the 30–45 band at 34, so no padding was needed, but segment 6 jumped 1186 → 1198 across the one event that closes the file's own strongest circle. Added **"Jerusalem falls to Saladin, the circle closed"** (2 October 1187): the Frankish kingdom that let a stateless refugee climb the Haram in 1165 ends, and the city belongs to the sultan whose pulse Maimonides now takes. Placed at generic Old City coordinates to keep it distinct from the Temple Mount prayer stop.

### Considered and rejected

The episode of Maimonides being denounced in Egypt as a renegade Muslim by a faqih from Fez, and saved by the ruling that a forced convert is no convert, would have been a superb addition to the Fez/Egypt hinge. It could not be confirmed from any source reachable in this pass (Jewish Encyclopedia, Britannica and New World Encyclopedia all failed to return it), so it was **not** added. It remains the best candidate for a future stop if the Ibn al-Qifti attribution can be sourced properly.

The researcher's exclusion of the apocryphal "Oath of Maimonides" was checked and endorsed.
