# Attar of Nishapur — build report

**File:** `attar.journey.json` — 7 segments, 33 stops, 5 quoted. Validated clean (json_check.py: OK, no WARN lines).

## Sources
Primary: Wikipedia ("Attar of Nishapur," "Tazkirat al-Awliya," "The Conference of the Birds," "Ilāhī-Nāma," "Siege of Nishapur (1221)," "Otrar Catastrophe," "Mongol invasion of Khorasan," "Mausoleum of Attar of Nishapur"), Encyclopaedia Iranica ("ATTAR, FARID-AL-DIN," "MOḴTĀR-NĀMA"), Encyclopaedia Britannica ("Farid al-Din Attar," "Mosibat-nama," "Elahi-nama"), the Institute of Ismaili Studies (Hermann Landolt on Attar), Mizan Project ("The Druggist of Nishapur"), New World Encyclopedia, *The Conference of the Birds* trans. Afkham Darbandi & Dick Davis (Penguin Classics), *Muslim Saints and Mystics* trans. A. J. Arberry / R. A. Nicholson (Tazkirat al-Awliya), Franklin Lewis's *Rumi: Past and Present, East and West*, and Jorge Luis Borges's essay "El Simurgh y el águila" (*Nueve ensayos dantescos*, 1982). Cross-referenced against the already-inscribed `rumi.journey.json` and `genghis_khan.journey.json` for shared-pin events.

## Judgment calls
- **Chronology of the works.** Scholars genuinely cannot fix firm composition dates for Attar's mathnavis — even the "circa 1180" sometimes given for the *Mosibat-nama* conflicts with other estimates. I built one internally consistent, chronologically increasing sequence (Tazkirat al-Awliya → Divan → Asrar-nama → Elahi-nama → Mosibat-nama → Mantiq al-Tayr → Mokhtar-nama/Pand-nama, c. 1190–1210) and marked every date "traditional," being honest that the ordering is a narrative convenience over a real scholarly gap, not an attested fact.
- **Birth date and place.** c. 1145 in Kadkan is the most commonly repeated tradition, but is itself contested (some push it a generation earlier); marked "traditional."
- **The India leg.** Later biographers report travel into India; modern scholarship doubts it. Kept as canon (the register calls for this), marked "traditional," with the doubt folded honestly into the prose rather than erased.
- **Attar's own death legend** (refusing the higher ransom, naming his own price as a sack of straw) is the single most repeated anecdote about him and is almost certainly apocryphal in its exact form — but it is the canon's account of his death, so it is narrated as fact, sourced as legend.
- **Two coordinate points for "Nishapur."** I split the city center (36.2064, 58.7958 — matching the pin already fixed in `rumi.journey.json`) from Shadiyakh, the western garden suburb the family actually lived and worked in after 1161, and where Attar's own tomb now stands (36.1671, 58.8070, per the Mausoleum's Wikipedia infobox). Most of the adult-life stops use the Shadiyakh point.
- **No post-death epilogue stop.** Following the convention set by `joan_of_arc.journey.json` (ends at the stake, no rehabilitation coda), the mausoleum built by Ali-Shir Nava'i two and a half centuries later is folded into `suggested_refs` on the death stop rather than given its own out-of-period stop.

## Gaps / time-folds
The travel segment (Bastam → Kufa → Mecca → Medina → Baghdad → Basra → Gorganj → Turkestan/India) has no attested itinerary or date order in the sources — only a bare list of place-names repeated across biographies. I sequenced it as a plausible single westward-then-eastward loop and dated it evenly across roughly 1176–1184; this is invention within honest limits, flagged "traditional" throughout. The gap between his return (c. 1186) and his death (1221) — roughly 35 years — is real biographical silence filled almost entirely by his books; there is essentially no attested external event in his life during this stretch beyond the works themselves and the Rumi encounter.

## Five richest episodes
1. **The dying dervish at the shop door** (Segment 2) — the conversion scene, quoted, the hinge of the whole life.
2. **The Simurgh is themselves** (Segment 4) — the climax of *Mantiq al-Tayr*, with the actual closing lines of the Darbandi/Davis translation as the quote.
3. **"Here comes a sea followed by an ocean"** (Segment 5) — the blessing of the child Rumi, a shared pin with `rumi.journey.json`, load-bearing for the whole atlas's Persian-Sufi cluster.
4. **Toquchar slain beneath the walls** (Segment 6) — the single arrow that turns Nishapur from spared to doomed.
5. **The ransom refused** (Segment 7) — Attar's own legendary death, closing the life on the same self-effacement his poetry argued for.

## Connections to the atlas
- **Forward/backward edge to `rumi.journey.json`**: exact shared pin at Nishapur, 1219-06-01, the Asrar-nama gift.
- **Shared destruction with `genghis_khan.journey.json`**: the Nishapur siege stop reuses that dataset's exact coordinates and date (1221-04-01) for the three skull-pyramids, and the Otrar/Bukhara/Samarkand news-stops reference its background chronology.
- **Forward literary edge to a future `borges.journey.json`** (not yet built): Borges's 1948 essay "El Simurgh y el águila" compares Attar's Simurgh to Dante's Eagle; noted in `suggested_refs` on the Simurgh-revelation stop as the seed of that future dataset's own inbound pin.

---

## Verification pass — 2026-07-20

Independent verify stage, run against the researched file. Repairs applied in place. **No stop was added, removed or reordered — stop count 33, segment count 7, order unchanged. The Spanish twin at `es/attar.journey.json` remains positionally aligned.**

### Structure
`json_check.py` clean before and after (7 segments, 33 stops). Schema compared field-by-field against `joan_of_arc.journey.json`: same keys, same nesting, `quote`/`quote_source` nulled in pairs throughout, `suggested_refs` and `sources` present on every stop. Register string uses the em-dash variant ("national mythology — the canon is true"); the fleet carries four punctuations of the same formula, so this was left alone. Campa word counts audited: five stops ran over 110 words (Mecca 112, Mosibat-nama 112, Jebe/Subutai 111, Tolui 118, the ransom 114) and were trimmed to range. All 33 now fall between 95 and 110 words, present tense, in register.

### Chronology
The file was chronological within every segment but **not** across the file: the Rumi blessing (1219-06-01, segment 5) sat ahead of the Otrar news (1218-01-01, segment 6). The Rumi stop is a shared pin with `rumi.journey.json`, which carries the same event at the same coordinates on 1219-06-01 — so that date was left untouched and the inversion resolved at the other end. The Otrar stop was re-dated to **1219-08-01** and its campa reworded: this stop is not the massacre but *news of* the massacre reaching Nishapur's caravanserais, and a season's lag on a frontier report is honest. The Otrar Catastrophe itself stays dated 1218 in `suggested_refs`. The file is now monotonic end to end.

Two internal age slips fixed: Bayazid al-Bastami (d. 874) was "the ecstatic of two centuries before" a visit dated 1176 — corrected to **three centuries**. Attar in 1218/1219 was called "closer to eighty than seventy" at age 73 — corrected to "past seventy now."

The Hajj was dated 1178-03-01. Dhu al-Hijja 573 AH falls in late May 1178, so a March pilgrimage is out of season; Mecca moved to **1178-05-01** and Medina to **1178-06-01**, preserving order.

### Confidences
Eight stops carried `traditional` for dates that no tradition supplies — the composition years of the Tazkirat (1190), Divan (1192), Asrar-nama (1195), Elahi-nama (1198), Mosibat-nama (1201), the two Mantiq al-Tayr stops (1205, 1206) and the Mokhtar-nama/Pand-nama (1210). These are the researcher's reconstruction of a plausible order, not a received dating, and were downgraded to **`inferred`**. This matters most at the Mantiq al-Tayr: two manuscripts give **1177** as the year the poem was finished (Darbandi & Davis, introduction to the Penguin translation), which flatly contradicts a "traditional" 1205. That manuscript date is now recorded in the hoopoe stop's `suggested_refs` rather than silently overridden. The travel-segment dates were left `traditional`: the itinerary is the tradition's, even if the years are the file's.

### Coordinates — 12 spot-checked, 0 wrong
| stop | file | check | verdict |
|---|---|---|---|
| Kadkan | 35.5874, 58.8747 | 35.5850, 58.8781 (Wikipedia) | ~400 m, keep |
| Nishapur city | 36.2064, 58.7958 | 36.2133, 58.7958 (Wikipedia) | ~800 m S of centre, keep; matches the pin in `rumi.journey.json` |
| Shadiyakh / mausoleum | 36.1671, 58.8070 | 36.1671, 58.8070 (Mausoleum, Wikipedia); Shadiyakh site 36.1694, 58.8042 | exact, keep |
| Bastam | 36.4864, 55.0087 | 36.4847, 55.0000 (Wikipedia) | ~800 m, keep |
| Great Mosque of Kufa | 32.0286, 44.4009 | 32.0289, 44.4008 | exact |
| Kaaba, Mecca | 21.4225, 39.8262 | 21.4225, 39.8262 | exact |
| Prophet's Mosque, Medina | 24.4672, 39.6111 | 24.4675, 39.6114 | exact |
| Baghdad | 33.3152, 44.3661 | 33.3152, 44.3661 | city centre, keep |
| Basra | 30.5085, 47.7804 | 30.5085, 47.7804 | modern city centre — see caveat below |
| Gorganj / Konye-Urgench | 42.3277, 59.1544 | 42.3277, 59.1544 | exact |
| Turkistan, Kazakhstan | 43.2970, 68.2710 | 43.2973, 68.2518 | ~1.5 km, keep |
| Nishapur (siege stop) | 36.2131, 58.7975 | 36.2133, 58.7958 | exact |

Nothing put the traveller in the wrong country or the wrong quarter. Note that English Wikipedia's prose calls the mausoleum "6 km west of Nishapur" while its own infobox coordinate — and the Persian sources, which place it *ضلع جنوب شرقی*, the south-east side, on Erfan Street — put it south-south-east. The coordinate, not the prose, is what the file uses, and it agrees with the Shadiyakh site coordinate 400 m away.

### Quotes — 6 checked, 2 repaired, 1 rewritten, 1 added
1. **The dying dervish** (1173). The file carried an invented composite in the dervish's mouth ("I own nothing in this world but the rags I stand in…"). No source carries it, and it inverts the canon: in the attested versions it is *Attar* who challenges the dervish, or the dervish who challenges Attar's readiness to die. Restored to the version told by Sholeh Wolpé — already one of the stop's own cited sources — in which the dervish asks whether Attar could die as a dervish can, Attar answers **"Of course I can,"** and the dervish sets his begging bowl under his head, calls on God, and dies on the shop floor. Campa rewritten to match. The theophany-adjacent miracle stands as an event; only the fabricated words are gone.
2. **Tazkirat al-Awliya preface.** The file's text was a first-person paraphrase. Restored to Nicholson's actual wording verbatim ("…were likewise uttered, for the most part, in Arabic. Consequently the author has translated them into Persian, in order that they may become accessible to all"), and `quote_source` corrected — this is Nicholson rendering Attar's reason in his introduction, not a direct first-person line from the preface.
3. **The Simurgh is themselves.** "And all who come before My splendour see / Themselves, their own unique reality… / Though you have struggled, wandered, travelled far, / It is yourselves you see and what you are." **Confirmed verbatim** in Darbandi & Davis. Kept unchanged.
4. **"Here comes a sea followed by an ocean."** Confirmed as the standard English rendering of the Aflaki/Dowlatshah anecdote. Kept, and left at 1219-06-01 to hold the shared pin with `rumi.journey.json`.
5. **The ransom refused.** The file's wording was a loose paraphrase. Restored to the wording actually carried by its own cited source: **"Don't sell me as cheaply; you will find someone willing to give more… Sell me to him, for that is all I am worth."** `quote_source` now credits New World Encyclopedia after Margaret Smith.
6. **Added** to the hoopoe stop, from Darbandi & Davis verbatim: "The world's birds gathered for their conference / And said: 'Our constitution makes no sense. / All nations in the world require a king; / How is it we alone have no such thing?'" This brings the quoted count from 5 to 6 without touching structure.

### Canon corrections in the campas
- **Mosibat-nama.** The file named the wayfarer "Fikrat, 'Reflection'" as though it were a proper name. It is not: the traveller is the *sālek-e fekrat*, the wayfarer *of* Thought, and he is guided by a master. The forty interlocutors were also generic; they are now listed as Encyclopaedia Iranica gives them (Gabriel and the angels, the throne and its pedestal, the tablet and the pen, paradise and hell, sun and moon, the four elements, mountains and seas, plants, animals, jinn, mankind, the prophets, the faculties). The ending was tightened to the canon's actual resolution: only the universal soul answers, telling him to cast himself into the ocean of the soul and be utterly effaced.
- **Tolui's sack.** "Toquchar's widow, the khan's own daughter" — the widow's supervision of the massacre is well attested but the daughter identification is not carried by the sources consulted, so the appositive was dropped. The seventy breaches in the wall were added in its place.

### Verified without change
Birth c. 1145 at Kadkan; the 1158 burning of the druggists' market in the Hanafi/Shafi'i factional war; the earthquake dated 1160 by one of the two sources; the 1161 abandonment of the old city for Shadyakh — all four confirmed against the Mizan Project's "The Druggist of Nishapur," which the file already cited. The Majd al-Din Baghdadi encounter is correctly framed: it is the only claimed teacher of Attar that scholarship accepts as within possibility (Landolt). Seven valleys correctly named. Elahi-nama's six sons and their six desires correct. Mokhtar-nama as the last poetic work Attar edited, ~2,000 quatrains by subject: correct. Tazkirat: 72 lives, Ja'far al-Sadiq to Hallaj, Rabia the sole woman: correct. Jebe and Subutai at Nishapur May 1220, departing in June; Toquchar killed by an arrow November 1220; Tolui's siege April 1221, three skull-pyramids: all confirmed, `attested` justified.

### Could not confirm
- **Rabia al-Adawiyya's grave at Basra.** Sources agree she was buried "outside the city" and that the Jerusalem tomb is a confusion with a different Rabia, but no site is fixed. The pin sits on modern Basra centre; medieval Basra lay some 15 km south-west near al-Zubayr. Right city, imprecise ground — left as is rather than invent a location.
- **The India leg.** Still only tradition, as the original report said. Unchanged.
- **Composition order of the mathnavis.** Attar lists his works in the Mokhtar-nama preface, which fixes the Mokhtar-nama as last but does not order the rest. The file's sequence is a reconstruction and is now labelled as one.
- **The Hallaj execution ground in Baghdad.** No usable coordinate for the specific site; the city-centre pin stands.
- **Attar's trial for heresy, banishment, and the looting of his property**, reported by Davis after Browne. Not in the dataset at all. It would be a genuine addition, but adding a stop would misalign the Spanish twin, so it is recorded here for a future structural pass rather than inserted.
