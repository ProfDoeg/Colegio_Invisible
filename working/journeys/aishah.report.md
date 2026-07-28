# Mecca to Basra: the Mother of the Believers and the Day of the Camel

**Traveler:** Aishah bint Abi Bakr · **Calendar:** Julian · **Register:** national mythology — the canon is true. **Shape:** 8 segments, 40 stops, 15 quoted (her own hadith-narrations carry most of the quoted weight, since she is canon's chief eyewitness voice for the Medina years).

## Sources
Sahih al-Bukhari and Sunan Abi Dawud/an-Nasa'i (her own narrations: the betrothal dream 3895, Uhud water-carrying 2880, the two races [Abu Dawud 2578], the Ifk narration in full [Bukhari 4141, her longest first-person hadith], the menses-at-Hajj ruling 294, the seven-skins hadith 5714, her husband's death 4446/5217, the broken-dish jealousy [Nasa'i 3955]); Ibn Ishaq's *Sirat Rasul Allah* for the Hijra-era narrative spine and the disputed Isra report; Ibn Sa'd's *Tabaqat al-Kubra* for biography, teaching, and her death/burial; al-Tabari's *Tarikh* and Ibn Kathir's *al-Bidaya wa'l-Nihaya* for the Fitna and the Battle of the Camel, including the Hawab-dogs episode; al-Dhahabi's *Siyar A'lam al-Nubala* for her standing as jurist and teacher; Wikipedia/Wikishia for site coordinates and cross-checks.

## Judgment calls
- **The curator's brief** ("narrator of the Isra and the washing of the Prophet's heart") pointed to a single compound episode: in `muhammad.journey.json` the heart-washing and the launch of the Night Journey are narrated in one stop (Sacred Mosque, before Buraq). I placed a stop late in her teaching years (seg. 6, "she tells of the Night Journey and the washing of the heart") where she is asked about that night and gives the specific report attributed to her by Ibn Ishaq — that the Messenger's body never left his bed, only his spirit. This report is historically thin-chained (al-Albani and Qadi Iyad judged it weak, and Aishah wasn't yet born/married at the time of the event itself), but it is a real transmitted tradition bearing her name, so per the register it is placed and dated as her own teaching, not debunked — while the campa text is honest that it is *her report of* an event she didn't witness, which is exactly what hadith transmission is.
- **Marriage age** follows the classical canon (betrothal ~age 6-7 in 620, consummation ~age 9 in 623) rather than the modern revisionist chronologies — per the brief's instruction to narrate the canon in its own terms, not debunk it.
- **Coordinates**: most Medina stops share the Sacred Chamber's coordinates (24.4674, 39.6112), matching `muhammad.journey.json` exactly, since her entire married and widowed life was spent in that one room. Hawab's location is only traditionally known (southern Iraq, on the Basra road); I placed it at an approximate desert point rather than inventing false precision.
- **Shared pins**: five stops explicitly cross-reference `muhammad.journey.json` stops (Thawr, Uhud, the Trench, the Night Journey's start, the last illness, the grave) — the two datasets should read as one continuous fabric where their lives overlap, per the "edge into the existing muhammad journey" instruction.

## Gaps and time-folds
- The Ifk incident's exact date is disputed among scholars (Sha'ban 5 AH vs. 6 AH); I follow the more commonly cited early dating (Jan-Feb 627) and marked its stops **attested** since the Quran itself (24:11) confirms the event's historicity, even though the precise day is a scholarly reconstruction.
- Several "Keeper of the Sunnah" stops (her school, her correction of Companions) have no fixed date in the canon — I marked these **inferred**, spacing them across her four decades of widowhood (632-671) to represent an ongoing practice rather than a single dated event, following Joan of Arc's precedent for using all three confidence tiers.
- The Battle of Uhud and the Trench are dated per the fixed anchors already established in `muhammad.journey.json`, kept identical for cross-dataset consistency.

## The five richest episodes
1. **The Ifk** (seg. 4, six stops) — the lost necklace, Safwan's rescue, the slander, her own defense quoting Jacob's words, and the ten verses of An-Nur descending to clear her name. Her longest and most personal hadith narration, told entirely in her own voice.
2. **The Day of the Camel** (seg. 7) — from the barking dogs of Hawab (a prophecy she herself remembered and tried, too late, to heed) through the arrow-porcupined howdah to Ali's chivalry and her brother's escort home. The one time in Islamic history a Prophet's widow led an army into open battle.
3. **His death in her arms** (seg. 5) — the seven skins of water, his head between her chest and chin, and her grief-hardened line that she never again feared anyone else's death-agony.
4. **The betrothal dream and the milk-bowl wedding** (seg. 1-2) — Gabriel's silk-wrapped image, and a wedding whose entire feast was a single passed bowl of milk: intimacy at the vanishing point of empire.
5. **Her school** (seg. 6) — the curtained room that outlived the Prophet by forty-six years, becoming the single richest channel (2,000+ hadith) through which his words reached every later century, including the report of the Night Journey itself.

## Connection to the atlas
This journey is built to interlock with `muhammad.journey.json`: five stops carry explicit shared-pin references, and Aishah's own chamber — the site of his death, his grave, and her forty-six years of teaching — is the single most-repeated coordinate in the dataset (24.4674, 39.6112), anchoring both journeys to one physical room. Her narration of the Night Journey answers the curator's brief directly: the canon's chief witness to the Prophet's private hours becomes, in her own old age, the keeper of the account of the night he was carried to the seven heavens and back.

---

## Verification pass — 2026-07-20

Independent structural and canon-fidelity check. `json_check.py` passes clean before and after (8 segments, 40 stops, 15 quoted, no WARN lines); top-level and per-stop key sets are identical to `joan_of_arc.journey.json`. Register held throughout: no theophany, prophecy, or miracle was softened or debunked — the silk-wrapped image shown by the angel, the descent of An-Nur from above the seven heavens, the Prophet's warning about the dogs of Haw'ab, and Aishah's spirit-only report of the Isra all stand as the canon gives them, marked by confidence rather than trimmed.

### Corrected: chronology

- **The Ifk segment was globally out of order.** Segment 4 opened at 0627-01-05, earlier than the Trench (0627-03-01) and the race (0628-01-01) at the end of segment 3, so the dataset ran backwards across the segment boundary. The al-Muraysi expedition is dated **Sha'ban 6 AH / December 627** (Ibn Ishaq; Wikipedia, *Invasion of Banu Mustaliq*) — the researcher had used al-Waqidi's 5 AH dating without flagging the fork. Re-anchored the whole Ifk cluster to Ibn Ishaq: lot drawn 0627-11-20, al-Muraysi 0627-12-10, Safwan 0627-12-11, slander 0627-12-25, her defense 0628-01-05, An-Nur 0628-01-10. Her stated age of thirteen still holds on this dating.
- **Two races** moved 0628-01-01 → 0627-06-01 (undated in the canon; "traditional") so segment 3 closes before the Ifk opens.
- **Day of the Camel** moved 0656-11-07 → **0656-12-08** (15 Jumada I 36 AH), with the escort home to 0656-12-12 and the truce stop to 0656-12-06. The truce collapsed the night before the battle, not seven weeks before; the stop was retitled "Basra, the city taken and the truce that fails" and its campa now separates the October entry into the city from the December parley.
- Verified correct and left alone: Uhud 0625-03-23, the Trench 0627-03-01, the Prophet's last illness 0632-06-01 and death 0632-06-08, Abu Bakr 0634-08-23, Umar 0644-11-03, Uthman's murder 0656-06-17, Aishah's death 0678-07-16 (17 Ramadan 58 AH). The Uhud and Trench dates match `muhammad.journey.json`'s shared pins exactly and were held there deliberately over Wikipedia's 19 March 625, for fleet consistency.

### Corrected: coordinates (10+ spot-checked)

| Stop | Was | Now | Basis |
|---|---|---|---|
| Tan'im, the makeup Umrah | 21.4548, 39.745 | **21.4677, 39.8013** | Masjid at-Taneem, Wikipedia — was ~6 km off |
| Sarif, the interrupted Hajj | 21.55, 39.85 | **21.53, 39.76** | ~10-16 km NNW of Mecca on the Hijrah road; old value sat on the wrong side of the city |
| Al-Muraysi | 22.45, 39.53 | **22.36, 39.18** | the well was in the Qudayd district *on the Red Sea coast* between Jeddah and Rabigh; old value ~35 km inland |
| The road back with Safwan | 22.7, 39.7 | **22.75, 39.30** | placed on the coastal road home, consistent with the corrected al-Muraysi |
| Jannat al-Baqi | 24.4696, 39.6142 | **24.4672, 39.616** | Al-Baqi Cemetery, adjacent to the eastern wall of the Prophet's Mosque |
| Basra: truce, battle, escort | 30.5085, 47.7804 / 30.45, 47.75 | **30.3833, 47.7083** / **30.395, 47.725** | the Camel was fought at *old* Basra — the site of modern al-Zubayr, 13 km SW of the modern city, "outside the town walls" (Britannica) |

Checked and left as they stand: Mecca/Kaaba precinct (21.4229, 39.8261), Mount Uhud and Jabal Sila' (both shared pins with `muhammad.journey.json`), the Sacred Chamber (24.4674, 39.6112), the Hijrah road. The wells of **Hawab** (29.9, 47.0) have no recorded GPS in any source — the site is traditional only, and the coordinate is an honest approximation on the Medina-Basra desert road; left in place, already carrying `date_confidence: traditional`.

### Corrected: quotes (8 checked against the canon)

Six of eight carried a paraphrase rather than the canon's wording; all restored.

- **Bukhari 3895** (the silk dream) — restored "When I uncovered the picture, I saw that it was yours. I said, 'If this is from Allah, it will be done.'"
- **Bukhari 2880** (Uhud water-skins) — the canon reads "bangles around their ankles," not "bangles on their legs"; restored in full, with Anas's opening clause "when some people retreated and left the Prophet."
- **Bukhari 294** (Sarif) — restored "ordained" for "decreed" and the canon's "with the exception of the Tawaf round the Ka'ba"; dropped "until you are purified," which belongs to a parallel narration.
- **Abu Dawud 2578** (the race) — restored "When I became fleshy."
- **Bukhari 4446** (his death) — restored "between my chest and chin… after the Prophet."
- **Bukhari 297**, **Nasa'i 3955** ("Your mother got jealous; eat") — verified verbatim, no change.
- **Abu Musa al-Ash'ari** — the attribution was loose. The report is **Jami' at-Tirmidhi 3883**, graded *hasan sahih*; quote and source corrected to the canon text rather than a summary.
- **Her deathbed will** — the previous wording ("so that I not be looked upon as better than I really am") was not carried by any source. Replaced with the attested Ibn Sa'd report, which is stronger and franker: "I did something major after the Messenger of Allah. Do not bury me with them; bury me with my companions in al-Baqi', so that I not be praised thereby." Her remorse for the Camel now speaks in her own voice at the grave rather than in the narrator's.
- **"Take me back! Take me back!"** at Hawab — attested in al-Tabari and Ibn Kathir; left as it stands.

### Corrected: prose

- **Uhud**: "At eleven years married she is still young enough…" read as *married for eleven years*, which is wrong by nine. Now "Eleven years old and two years married."
- **The death of Umar**: the sentence "who… once permitted the wives of the Messenger to be buried within his own household plot" had the transaction backwards — it was Umar who begged the third grave from *her*. Rewritten so she gives away the place she had wanted for herself, which is the point of the episode.

All campa remain 60-110 words, present tense, in register; no stop was flattened. At 40 stops the dataset sits inside the 30-45 target, so nothing was added.

---

## Independent verification pass — 2026-07-20 (second reviewer)

A second, independent check run without assuming the section above was correct. `json_check.py` passes clean before and after: **8 segments, 40 stops, 15 quoted**. **No stop was added, removed, or reordered** — the Spanish twin at `es/aishah.journey.json` (verified: same 8 segments, same 5/4/3/6/5/6/7/4 stop distribution) remains positionally aligned.

### Structure
Top-level keys and the per-stop key set are byte-identical to `joan_of_arc.journey.json` (`campa, date, date_confidence, lat, lng, name, quote, quote_source, sources, suggested_refs`). All 40 dates are monotonically non-decreasing across the whole file, including across every segment boundary. All 40 campa fall inside 60–110 words (range 82–106), present tense, register intact. No theophany, dream, prophecy, or miracle was softened: the angel's silk-wrapped image, the descent of An-Nur, the Prophet's warning about the dogs of Haw'ab, the infant-era miracles, and Aishah's spirit-only report of the Isra all stand as canon gives them, graded by confidence rather than trimmed.

### Coordinates — 14 spot-checked, 1 corrected

| Stop | Verdict |
|---|---|
| **Wells of Haw'ab** | **CORRECTED 29.9, 47.0 → 30.05, 46.75.** See below. |
| Mount Uhud (24.5062, 39.6083) | Kept. Wikipedia gives the summit as 24.5103, 39.6139 (~600 m off), but this is a deliberate **shared pin**, byte-identical to `muhammad.journey.json`. Fleet consistency wins over 600 m. |
| Trench / Jabal Sila' (24.4869, 39.6047) | Kept — shared pin, matches `muhammad.journey.json` exactly. |
| Last illness (24.4674, 39.6112) and grave (24.4670, 39.6109) | Kept — both match `muhammad.journey.json` exactly. |
| Jannat al-Baqi (24.4672, 39.6160) | **Confirmed correct** (latitude.to: 24.4672, 39.6160; adjacent to the Prophet's Mosque east wall). |
| Sarif (21.53, 39.76) | Confirmed. ~13 km NNW of Mecca; Bukhari 294 itself glosses Sarif as "six miles from Mecca". |
| Tan'im (21.4677, 39.8013) | Confirmed against Masjid Aisha. |
| Old Basra / al-Zubayr (30.3833, 47.7083 and 30.395, 47.725) | Confirmed. The Camel was fought at *old* Basra, the site of modern al-Zubayr, not the modern city. |
| Kaaba precinct stops (21.4225–21.4232, 39.8257–39.8262) | Confirmed; the Mecca pin matches `muhammad.journey.json`'s Sacred Mosque exactly. |
| Al-Muraysi (22.36, 39.18), Safwan road (22.75, 39.30), Hijrah road (22.9, 39.9) | Kept as reasonable approximations on the coastal/caravan corridors. |

**The Haw'ab correction.** The pin sat at 29.9 N, 47.0 E while its `suggested_refs` read "southern Iraq, on the Basra road" — so I checked whether it had landed in Kuwait. It probably had *not*: the Iraq–Kuwait border follows the Wadi al-Batin thalweg north-eastward to 30°06′13″ N before turning east, and by interpolation the border sits near 47.28 E at that latitude, leaving the old pin roughly 25–30 km inside Iraq. But that margin is thinner than my interpolation is accurate, and a pin meant to read "southern Iraq" should not depend on a 25 km estimate. Moved to **30.05, 46.75** — ~60 km west of the border, unambiguously in the Iraqi Dibdibah desert, ~100 km WSW of old Basra on the Mecca–Basra caravan corridor. Arabic sources (islamic-content.com; ar.wikishia) place al-Haw'ab only as "a water-pool near Basra on the Mecca road," a watering hole of the Banu Kilab — there is **no recorded GPS for the site in any source**, so this remains an honest approximation and correctly keeps `date_confidence: traditional`.

### Quotes — 12 checked against the canon, 1 corrected

Verified verbatim, no change: **Bukhari 3895** (the silk dream, incl. "If this is from Allah, it will be done"), **Bukhari 2880** (Uhud water-skins — the file uses the "carrying the water skins on their backs" variant, which Bukhari 2880 itself carries as an alternate narration), **Bukhari 294** (Sarif), **Bukhari 297** (recitation on her lap), **Bukhari 4446** (his death between chest and chin), **Bukhari 5714** (the seven water skins — trivial word-order variance between published translations, faithful), **Abu Dawud 2578** (the two races, "when I became fleshy… this is for that outstripping"), **Nasa'i 3955** ("Your mother got jealous; eat" — narrated by Anas; the parallel Umm Salamah narration names Aishah as the one who broke the dish, so the campa's attribution is sound), **Quran 24:11** (accurate elided rendering of Sahih International), **"Take me back! Take me back!"** at Haw'ab (attested, with the fifty men brought to swear falsely — corroborated).

- **Bukhari 4141 (the words of Jacob) — CORRECTED.** The file read "I find for myself no example concerning this matter…". The Arabic is `فَوَاللَّهِ لاَ أَجِدُ لِي وَلَكُمْ مَثَلاً إِلاَّ أَبَا يُوسُفَ` — "for me **and you**." Dropping *wa-lakum* loses the whole edge of the line: she is not describing her own predicament, she is telling the room that she and they together are Jacob and the sons who came with false news. Restored to "By Allah, I find no similitude for me and you except that of Joseph's father, when he said: So patience is most fitting, and it is Allah Whose help can be sought against that which you describe."
- **Tirmidhi 3883** — the English was flagged as a paraphrase, but checking the Arabic (`مَا أَشْكَلَ عَلَيْنَا أَصْحَابَ رَسُولِ اللَّهِ… حَدِيثٌ قَطُّ`) shows the file uses Abu Amina Elias's published translation of exactly that text. Wording left alone; grading in `quote_source` refined to at-Tirmidhi's own **hasan sahih gharib**.
- **Her deathbed will** — both halves are attested ("I did something major after the Messenger of Allah" / "Do not bury me with them, bury me with my co-wives in al-Baqi'"), though the file presents them as one continuous utterance. Wording kept; `quote_source` widened to name Ibn Sa'd vol. 8 **and Sahih al-Bukhari 1391**, which also carries the burial instruction.

### Could not confirm
- **Al-Haw'ab's true location.** No source in Arabic or English gives coordinates; the identification is traditional only.
- **The milk-bowl wedding quote** (Ibn Sa'd) and the **Ibn Ishaq spirit-only Isra report** could not be checked against a primary text online; both are cited to the right works and the Isra report is already flagged in `quote_source` as thinly-chained, which is the honest handling.
- **Al-Muraysi and the Safwan road** are placed on the right corridor but no source fixes the wells to a coordinate.

### Not changed
Stop count, stop order, segment structure, all dates, and every campa. At 40 stops the dataset is well above the 30-stop floor, so nothing was added.
