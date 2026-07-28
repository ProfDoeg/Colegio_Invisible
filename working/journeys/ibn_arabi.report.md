# Ibn Arabi — Murcia to Damascus: build report

**Shape:** 7 segments, 42 stops, 6 quoted stops (1165-1240, Julian calendar). Validated clean with json_check.py.

## Sources
Primary scaffolding came from the Muhyiddin Ibn Arabi Society's Anqa Publishing biographical pages ("Ibn 'Arabi in the West, 1165-1200," "in Mecca, 1201-04," "in the East, 1204-40"), cross-checked against Wikipedia's chronology and Claude Addas's standard biography *Quest for the Red Sulphur* (cited throughout via secondary summaries, not directly read). Specific episodes drew on: Ibn Arabi's own *Ruh al-Quds* (the women masters Fatima of Cordoba and Shams of Marchena), the Futuhat's own account of the Ibn Rushd meeting (via sunofwest.com and futmak.com transcriptions), the preface to *Tarjuman al-Ashwaq* for Nizam (via Michael Sells's translation, quoted secondhand), the *Fusus al-Hikam* prologue for the Muhammad-vision, and Archnet/Wikipedia for the Damascus shrine and Selim I legend.

## Judgment calls
- **Dates are mostly "traditional," not "attested."** Ibn Arabi's own writings rarely give a day-month-year; most stops carry biographer consensus-years with an invented plausible month/day (flagged `traditional`) rather than false precision. Only the handful with real chronicle anchors (birth, Baghdad's twelve days, Mecca 1202, Futuhat drafts of 1231/1238, death, burial, Selim I's 1516 mosque) are marked `attested`.
- **The Cairo "trial for heresy"** that some popular accounts mention could not be pinned to a primary source in the time available, so I wrote the Cairo stops as documented tension with the exoteric jurists rather than asserting a specific plot or death sentence — a case of pulling back from a dramatic but unverified claim.
- **The Ibn Arabi–Rumi encounter** ("a sea followed by an ocean") is itself a later Mevlevi tradition (Aflaki), not something Ibn Arabi wrote; I dated and marked it `traditional` and cited the tradition as its source rather than presenting it as documented fact, while still narrating it as an event per the register's rules for traditional material.
- **Malatya household stop is `inferred`** (no single year is given anywhere for "settling in," only that he had a house there across the 1210s before Majduddin's 1220 death).

## Gaps / time-folds
No outright folding, but real texture is missing between 1207 (Mecca) and 1223 (Damascus) — sixteen years compressed into four Anatolian stops (Konya 1210, Malatya household, Aleppo 1215, Malatya 1220) because the sources agree he circulated constantly among Anatolia/Iraq/Syria in this period without a clean itinerary. A future pass with Addas's full biography in hand could add 3-5 more stops here (further Aleppo/Konya returns are attested but undated in the secondary sources I had access to).

## Five richest episodes
1. **The Ibn Rushd meeting** (Cordoba, ~1184) — the "yes and no... necks detach from bodies" exchange, straight from the Futuhat's own account.
2. **The vision of the Youth at the Kaaba** (Mecca, 1202) — the seven theophanies that dictate the Futuhat's architecture.
3. **Nizam and the Tarjuman al-Ashwaq** (Mecca, 1203) — the love poetry later defended as pure theology in the Aleppo commentary.
4. **The Fusus al-Hikam dream** (Damascus, 1229) — Muhammad himself hands him the book, in Ibn Arabi's own quoted prologue.
5. **Selim I's dream-guided rediscovery of the tomb** (Damascus, 1516) — the "Sin into Sham" wordplay, and the thread forward to Abd al-Qadir al-Jaza'iri's own burial there.

## Connections to the atlas
Ibn Arabi is the hinge the curator named: his Andalusi mystical world (Cordoba, Seville) sits behind Kyot's claimed Arabic source for the Grail material (edges to `kyot-willehalm.journey.json` and `parzival.journey.json`), and his stepson Sadr al-Din al-Qunawi's Konya circle physically overlaps `rumi.journey.json` — hence the dated "sea and ocean" encounter stop, written to connect without duplicating Rumi's own dataset. His Damascus tomb, rebuilt by Selim I and later chosen as Abd al-Qadir al-Jaza'iri's own resting place, is written as the explicit "Syria knot" pin for a future `abdelkader` journey (no such file exists yet in the corpus).

---

## Verification pass — 2026-07-20

Structural, chronological, geographic and canon-fidelity audit. `json_check.py` exits clean, no WARN: 7 segments, 42 stops, 6 quoted. Schema keys match `joan_of_arc.journey.json`. Stop count sits inside the 30–45 target, so no stops were added. Register and mythic content left intact throughout — theophanies (the Youth at the Kaaba, the three prophets, the Fusus dream, the khirqa of Khidr) stand as canon, marked by confidence rather than hedged in prose.

### Coordinates corrected

- **Tomb / shrine on Qasiyun (2 stops).** File had `33.5442, 36.3010` — roughly 2 km off, up the bare mountainside rather than in the Salihiyya quarter. Wikidata and the Wikipedia article on the Salimiyya Takiyya both give `33.52944, 36.28806`. This also reconciles the dataset with the corpus's own `abdelkader.journey.json`, which already carried `33.5294, 36.288` for the same shrine — the two files now agree, which matters because they cross-reference each other. Corrected to `33.5294, 36.2881`.
- **Fatima bint al-Muthanna.** Stop was placed in Cordoba on Cordoba coordinates. Fatima was a Cordoban by origin but Ibn Arabi served her at Seville; the Ibn Arabi Society (Souad Hakim) describes her as "a woman of gnosis from Seville, Fatima bint al-Muthanna of Cordoba." Moved to Seville `37.3891, -5.9845` and retitled; the Cordoban origin is now carried in the campa where it belongs.

The other sixteen distinct sites (Murcia, Seville, Cordoba, Marchena, Tunis, Fez, Gibraltar, Salé, Cairo, Mecca/Kaaba, Baghdad, Mosul, Jerusalem, Konya, Malatya, Aleppo, Damascus) spot-checked and correct.

### Quotes

All six checked against the canon; three were carrying paraphrase and have been restored.

- **Fatima bint al-Muthanna.** Had "I am your spiritual mother…" The transmitted wording is *divine*, not spiritual — a substantive difference, since the whole point is that she claims a rank above the earthly mother rather than a metaphor alongside her. Restored: "I am your divine mother, and the light of your earthly mother."
- **Ibn Rushd's funeral.** Had "On one side the master, on the other what the master left behind" — a smoothing. The attested remark is "On one side the Master, on the other his books!" Restored, with the source corrected to the *Futuhat* account rather than unattributed "recorded tradition." The campa's closing gesture toward the verse (whether his hopes were ever answered) is kept, as that verse is likewise transmitted.
- **The young Rumi.** Had "What an extraordinary sight — a sea followed by an ocean!" This inverts the image: in the hagiography the *son* is the ocean and the *father* the lake, which is the entire force of the saying. Restored to "Praise be to God! An ocean walking behind a lake!" The quote_source now states plainly that the encounter is Mevlevi hagiography unconfirmed by contemporary sources — the stop keeps `traditional` confidence, so the time-fold is marked, not deleted.
- **Ibn Rushd's "yes and no"** (Corbin's rendering), the **Nizam description** from the Tarjuman preface, and the **Fusus prologue** all verified verbatim. No change.

### Dates

The Hijri years quoted inside several campas did not convert to the CE dates on the stops. Corrected so prose and field agree:

- Birth `1165-07-28` → `1165-07-27`, matching the Anqa/Ibn Arabi Society chronology for 17 Ramadan 560.
- Badr al-Habashi `1197-01-01` → `1197-11-01`; 594 AH began 14 November 1197, so January was still 593.
- Gibraltar crossing: campa said "the year 597" on a March 1200 date, which is 596 AH. Changed the prose to 596 rather than move the stop, since the crossing must precede the Salé farewell in June.
- Fusus dream `1229-12-01` → `1229-12-12`; the campa specifies the last ten days of Muharram 627, which is 10–19 December 1229.
- Death of Majduddin Ishaq `1220-01-01` → `1220-06-01`; 617 AH began 8 March 1220.

Chronology otherwise ordered and internally consistent; the 1240 death and the 1516 posthumous stop are correctly the last two, and the posthumous stop is legitimate under the schema (cf. the Joan dataset's rehabilitation and canonization stops).

### Confidence honesty

- **Ibn Rushd's funeral** downgraded `attested` → `traditional`. Ibn Arabi's presence is attested from his own account, but the March 1199 date of the transfer of remains is not; only Averroes's death (11 December 1198) is firmly dated.
- The **Ibn Rushd meeting** at 1184 is left as `traditional`. There is a real scholarly split — Anqa/Hirtenstein put it c. 1181 right after the retreat, making better sense of Ibn Arabi's "beardless youth," while the dataset's own cited source (sunofwest) gives ~580/1184. `traditional` correctly marks the contested date; flagging here rather than silently picking a side.

### Factual corrections

- **Averroes "died in Marrakesh in disgrace."** Wrong. He was exiled and his books burned, but al-Mansur pardoned him within months and recalled him to court; he died back in favour. The campa now carries exile, burning, pardon and death in favour — which sharpens rather than dulls the image, since the books tied to the bier are then books that outlived their own condemnation.
- **The Selim I complex** dated "1516-1518." Selim took Damascus in 1516, but the Salimiyya Takiyya was built in 924 AH / 1518–19, on his return from the conquest of Egypt. Corrected in campa and suggested_refs, and noted as the first Ottoman building in Syria.

### Cross-link

The researcher's note states that no `abdelkader.journey.json` exists in the corpus. **It does** — it was created earlier the same day and already contains two stops at this shrine ("Damascus, at the tomb of Ibn Arabi," 1826; "Salihiyya, buried beside the Shaykh al-Akbar," 1883). The Syria knot the researcher intended is therefore live, and the final stop's suggested_refs now names the file explicitly. Coordinates between the two datasets have been reconciled as described above.

### Not changed

The deliberate exclusion of the Cairo death-sentence-for-heresy story is correct and was left alone; documented jurist hostility carries the same weight with a source behind it. All campas verified present tense, 60–110 words, in register.

---

## Verification pass — 2026-07-20

Independent verify stage. `json_check.py` clean before and after: 7 segments, 42 stops, quoted 6 → 9. **No stop added, removed, or reordered** — every repair made in place. The Spanish twin remains positionally aligned; six campas and four quote fields were rewritten, so those positions need re-translation, not re-alignment.

### Coordinates — 17 distinct sites checked, 2 corrected

Verified against gazetteers and site records: Murcia, Seville, Cordoba, Marchena, Tunis, Fez, Gibraltar, Salé, Cairo, Mecca (Kaaba), Baghdad, Mosul, Jerusalem, Konya, Malatya, Aleppo, Damascus, and the Qasiyun tomb.

- **Tomb of Ibn Arabi** `33.5294, 36.2881` — confirmed exact against the Salimiyya Takiyya record (33°31′46″N 36°17′17″E). No change.
- **Jerusalem** corrected `31.7683, 35.2137` → `31.7771, 35.2354`. The stop is specifically "at the Farthest Mosque"; the old value was the city centroid, ~2 km off the Haram al-Sharif.
- **Marchena** corrected `37.3308, -5.4131` → `37.3269, -5.4162` (~0.5 km).
- All others correct as given. Salé `34.0531, -6.7985` matched the gazetteer digit for digit.

### Quotes — 6 checked, 1 restored, 1 realigned, 3 added

- **Ibn Rushd, "Yes and no…"** — real, but the file carried a loosened paraphrase. Restored to the canonical rendering: "spirits take **their** flight from **their** matter, and necks **are separated from** their bodies," and the campa's inline quotation brought into agreement.
- **Nizam.** The file's "She would bind the gaze, dazzle a gathering with her speech, and astonish anyone engaging her in conversation" is **not in the preface.** Read the Tarjumān preface in full (Jane Clark's translation after Nicholson). The canon says she "adorned the assemblies, delighting whoever was addressing the gathering and confounding her peers" — she delights the *speaker* and confounds her *equals*, which is a different and better sentence. Restored.
- **Averroes funeral**, "On one side the Master, on the other his books!" — confirmed verbatim. No change.
- **Fatima bint al-Muthanna**, "I am your divine mother, and the light of your earthly mother" — confirmed verbatim. No change.
- **Fusus prologue** — confirmed; minor alignment to the attested wording ("people who will benefit from it").
- **Rumi, "An ocean walking behind a lake!"** — the wording is the standard one and the file already flagged the encounter as unconfirmed, which is right. But I could not confirm the specific attribution to Aflaki's *Manāqib al-ʿārifīn*; the saying circulates without a traced early source. Attribution generalised rather than asserted.
- Three quotes **added**, each verified: the voice at Seville ("O Muhammad, it was not for this that you were created"), the figure in the death-fever ("I am Surat Yasin, I am your guard"), and the Sīn/Shīn prophecy.

### Factual repairs

- **Khidr's mantle at Mosul — chain was inverted.** The file had Khidr investing Qadib al-Ban, with Ibn Jami merely his disciple. The canon: Khidr invested **Ibn Jami himself**, with Qadib al-Ban standing as witness, and Ibn Jami then passed that khirqa to Ibn Arabi on the same spot in the same garden. Corrected — and the corrected version is the stronger claim, since it puts only one hand between Ibn Arabi and the deathless one.
- **Aleppo — the outcome was reversed.** The file ended "The jurists do not withdraw their suspicion." In fact the commentary was read aloud in Ibn Arabi's lodging before Ibn al-ʿAdīm, the doubting qadi's son, who declared he would never again question a Sufi claiming a hidden sense in ordinary words. The canon records a conversion, not a stalemate. Corrected.
- **The Nizam campa asserted she was "her own father's teacher."** Nothing in the preface supports this. What the preface actually gives is the *aunt* — Fakhr al-Nisāʾ bint Rustam, "the glory of women, or rather the glory of men and learned people," from whom Ibn Arabi took a licence to transmit hadith. The invented detail is gone and the real one is in.
- **Two masters were one man.** "al-Uryabi" (first master) and "al-Urayni, a Portuguese" (the retreat) are variant transliterations of Abu al-ʿAbbās al-ʿUryabī of ʿUlyā near Loulé — the illiterate peasant, already correctly named in the earlier stop. The duplicate figure is dissolved.
- **Death date** `1240-11-16` → `1240-11-09`. Wikipedia gives 16 November, but 22 Rabīʿ II 638 AH converts to 9–10 November 1240, and Anqa — the Ibn Arabi specialist press — gives 9 November. Arithmetic and the specialist source agree against the general one. Applied to both the death and burial stops, preserving their shared date.
- The **illness stop** was flat ("a grave illness brings visions with it"). The canon carries a real scene — the household giving him up for dead, the menacing figures, the perfumed guardian, the father reciting Yāsīn at the bedside as he surfaces. Written in.
- The **Selim stop's** "entry of Sin into Sham" was half-remembered. The actual prophecy is a letter-riddle: *when the Sīn enters the Shīn, the tomb of Muhyī al-Dīn will appear* — Salīm into al-Shām. Restored as a quote with the Shajara al-Nuʿmāniyya literature cited.

### Checked and left alone

- **Birth 27 July 1165.** Wikipedia gives 28 July, Anqa gives 27 July; both render 17 Ramadan 560. The file follows Anqa, which is also among its cited sources. Left as-is; the one-day spread is noted here rather than silently resolved.
- **Chronology** verified ascending within all seven segments. No violations.
- **Confidences** honest throughout. The three great unverifiables — the Rumi meeting, the Kaaba theophanies, the Selim dream — are all `traditional`, which is the correct marking. None debunked; the theophanies, the Night-Journey, the mantle of Khidr and the Prophet's delivery of the *Fusus* all stand as events, as they must.
- **Stop count 42**, well above the floor. The canon offers more (the Sadr al-Dīn teaching sessions, the Yemen and Baghdad returns) but the dataset is not thin, and adding would have broken the Spanish alignment for no gain.

### Could not confirm

- Early textual source for the "ocean behind a lake" saying (flagged in-field).
- The exact month of the 1200 Murcia farewell and the Gibraltar crossing; both remain `traditional`.
- Whether *Kitāb al-Isrāʾ* belongs to 1197 (Anqa) or 1198 (the file, following Ramadan 594). Left at 1198 with `traditional` confidence; the ordering against Badr al-Habashi's arrival holds either way.
