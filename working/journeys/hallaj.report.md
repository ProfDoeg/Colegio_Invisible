# Hallaj — build report

**Traveler:** Mansur al-Hallaj (al-Husayn ibn Mansur al-Hallaj), c. 858–922. 8 segments, 37 stops, 8 quoted. Islamic panel of the martyr axis (hypatia, catherine_alexandria, joan_of_arc).

## Sources
Primary spine: Louis Massignon, *The Passion of al-Hallaj, Mystic and Martyr of Islam* (4 vols., tr. Herbert Mason) — the definitive scholarly reconstruction, drawing on the *Akhbar al-Hallaj* (sayings/anecdotes compiled by his own disciples, including his servant Ibrahim ibn Fatik), the trial dossier, and the *Kitab al-Tawasin* and *Diwan al-Hallaj* for his own words. Farid al-Din Attar's *Tadhkirat al-Awliya* (early 13th c.) supplies the canonical hagiographic execution narrative (the laughter at the gibbet, the "what is love" exchange, Shibli's rose). Encyclopaedia Iranica's "Hallaj" article and al-Kalabadhi's *Kitab al-Ta'arruf* (tr. Arberry) supplied biographical chronology and the "nothing in my turban/cloak but God" sayings. Wikipedia and Britannica cross-checked dates and the Sind/Multan/Qarmatian context.

## Judgment calls
- **Chronology is a hagiographic composite, not a documentary timeline.** Only the execution (26 March 922, and the trial dossier's specific fatwa) carry real date-level attestation; everything from birth through the second Turkestan journey is traditional sequencing built from Massignon's careful but necessarily reconstructive ordering of conflicting early sources. I marked these `traditional`/`inferred` throughout and reserved `attested` for the trial fatwa, Ibn Ata's death, and the execution-day physical acts (scourging, mutilation, beheading) — all independently corroborated across multiple contemporary chronicles (Ibn al-Athir, Tanukhi, al-Khatib al-Baghdadi).
- **Two conflicting Junayd traditions** exist for where "Ana'l-Haqq" was first spoken: publicly in the Mosque of al-Mansur, or privately at Junayd's midnight door. I kept both as separate stops rather than picking a winner — the mosque version as the "earliest report," the door version as the enduring legend that carries Junayd's gibbet prophecy.
- **Attar's three-day death sequence** (killed one day, burned the next, ashes scattered the third) is followed literally for the final three stops, even though some sources compress it to a single day — it's the version that gives the "you will see it today, tomorrow, and the day after tomorrow" prophecy its payoff, and Attar is the canonical hagiographic source for this register.
- **The Arafat prayer** ("make him despised") is well-attested in substance (Iranica, Massignon) but I could not source Massignon's exact English wording, so I left `quote: null` there rather than reconstruct a quotation — honest per the schema's own instruction.
- Sind is represented by Multan specifically (the Qarmatian-adjacent sun-temple city most sources name); "Turkestan" is split across Transoxiana/Samarkand, Sistan, and the far outlier claim of Qocho near Turfan among Manichaean Uighurs, which Massignon treats as legendary but transmitted.

## Gaps
No time-folds of more than a year or two; the five-years-preaching stretch (Khuzestan) and the India/Turkestan circuit are each collapsed to a handful of representative waypoints rather than a full itinerary, which does not survive in the sources anyway. Coordinates for al-Bayda (modern Tall-e Bayza/Beyza, Fars), Wasit (ruins near Kut), and Qocho (Gaochang ruins near Turfan) are best-effort placements for sites with no fixed modern address.

## Five richest episodes
1. The prayer at Arafat to be made "despised in the eyes of Your creatures" — a vow of vicarious suffering he then spends the rest of his life fulfilling.
2. "Ana'l-Haqq" cried in the Mosque of al-Mansur, and Junayd's midnight-door rebuke and gibbet prophecy — doctrine and its own foretold punishment in one scene.
3. The vision in prison recorded in the Tawasin ("I saw my Lord with the eye of the heart... He replied: You") beside the "Kill me, my faithful friends" poem written awaiting death — his own mysticism and his own execution converging in his own words.
4. Ibn Ata beaten to death in open court for defending him — the trial's collateral martyrdom, and the clearest evidence the case was political as much as theological.
5. The execution day itself: laughing at the gibbet and nails, the thousand lashes, Shibli's rose hurting more than the crowd's stones, and the final cry before the sword — Attar's set-piece, and the reason this figure occupies the Islamic panel of the atlas's martyr axis at all.

## Connections in the atlas
Sits beside hypatia, catherine_alexandria, and joan_of_arc as the martyr-axis Islamic panel — a teacher/preacher killed by the learned authorities of his own civilization for a claim about the relation of the self to the divine, versus philosophers, virgin martyrs, and the maid of Orléans. Shares the Baghdad/Khorasan/Transoxiana geography with rumi.journey.json three centuries later (Rumi's Balkh and Nishapur world is the same Sufi road-network Hallaj's Turkestan mission opened), and Attar's *Tadhkirat al-Awliya*, the source for Hallaj's execution, is also the source-genre for the register itself — a saints' martyrology, read here as true.

---

## Verification pass — 2026-07-20

Verified for structure and canon-fidelity (not for plausibility: theophanies, prison miracles, the
speaking ashes and the foretold three days all stand). Re-validated with `json_check.py`: exit 0,
no WARN. **8 segments, 41 stops, 14 quoted** (was 37 stops / 8 quoted).

### 1. Structure
Schema matches `joan_of_arc.journey.json` key-for-key at both top level and per stop. Dates
chronological within every segment; `date_confidence` values all in the permitted set; campa word
counts all inside 60–110.

### 2. Dates — one real error found and fixed
- **`0922-03-23` → `0922-03-25`** on "the trumpets of the eve". The campa correctly says
  "the twenty-third of Dhu'l-Qa'da", but the `date` field had transcribed the *Hijri day number*
  as a Julian day. The execution is 24 Dhu'l-Qa'da 309 = 26 March 922 (Massignon), so the eve is
  25 March. Confirmed against the standard account ("March 25, 922: execution announced for the
  following day"). The 26–28 March passion sequence is otherwise correct.
- Attar's own headnote gives 29 Dhu'l-Qa'da 309 and a garbled "28 March 913"; Massignon's
  26 March 922 is retained as the scholarly standard.

### 3. Coordinates — 13 spot-checked, 5 corrected
| Stop | Was | Now | Note |
|---|---|---|---|
| al-Bayda, Fars | 29.933, 52.867 | **30.008, 52.358** | old pin was ~50 km east, on the Estakhr/Persepolis meridian; Beyza (Tall-e Bayza) is 25 mi N of Shiraz at 30°00′29″N 52°21′30″E |
| Mosque of al-Mansur | 33.328, 44.365 | **33.3475, 44.335** | Round City / Madinat al-Salam, 33°20′51″N 44°20′6″E |
| Execution ground ×5 | 33.345, 44.4 | **33.352, 44.373** | 44.4 sat on the **east** bank; sources place the gibbet on the **west** bank of the Tigris before Bab Khurasan |
| Ashes / great bridge | 33.315, 44.366 | **33.351, 44.3745** | was inland in Karkh, not on the river |
| Multan | 30.157, 71.525 | **30.1985, 71.469** | Multan Fort / Prahladpuri, site of the sun-temple |
| Samarkand | 39.627, 66.975 | **39.672, 66.991** | moved to Afrasiab, the mound of the pre-Mongol city |

Verified as already correct: Wasit (32.188, 46.298), Tustar/Shushtar, Basra, Mecca/Kaaba, Ahwaz,
Sus/Susa, Zaranj, Qocho/Gaochang (42.85, 89.527 — matches the ruins exactly).

Left deliberately: the Arafat prayer sits on the Mecca pin rather than Mount Arafat, because the
stop covers the whole third pilgrimage from entering the sanctuary onward.

### 4. Quotes — checked against Arberry's translation of Attar, full text
Six-plus checked; four repaired, two source-lines tightened, three new quotes recovered.

- **Shibli's throw — materially corrected.** The file paraphrased. Attar's actual wording restored:
  *"Because those who cast stones do not know what they are doing. They have an excuse. From him it
  comes hard to me, for he knows that he ought not to fling at me."* Note also that **Attar has
  Shibli throw a clod of earth, not a rose** — the rose is the later Persian-poetic form. Per the
  register the rose is *not* removed: the campa now carries both, "a clod of earth in Attar's
  telling, a single rose in the tellings that come after."
- **"Kill me, my faithful friends" — spliced quote repaired.** The second half was a loose modern
  rendering welded on without attribution. It is a genuine but *different* poem; the text now gives
  Massignon/Nicholson's reading and the `quote_source` names both pieces.
- **The Kaaba-substitution charge — completed.** The dossier teaching also required alms and the
  feeding of thirty orphans; that clause was missing and is the part that makes the teaching a work
  of mercy rather than a bare substitution. Restored.
- **Turban-and-cloak** — kept, but the source line no longer claims a specific Arberry page it
  cannot bear; now attributed to the tradition (`ma fi jubbati siwa Allah`) with al-Kalabadhi cited
  as comparison.
- **Last words** — kept in Massignon's rendering, with Attar's parallel ("Love of the One is
  isolation of the One") now named in the source line. Qur'an 42:18 confirmed as the closing verse.
- **New quotes recovered** for three stops that were `quote: null` while sitting on quotable canon:
  the gallows ("The ascension of true men is the top of the gallows"), the blood-cosmetic ("The
  cosmetic of heroes is their blood"), and the prison.

### 5. Campa
All in register, present tense, inside the word band. Two campas rewritten (Shibli; the walk to the
gibbet) to carry the corrected canon rather than a smoothed version of it.

### 6. Stops added (+4, 37 → 41)
Attar's chapter carries major episodes the first pass dropped. Added:
1. **The three nights the prison could not hold him** — the gaolers find neither him nor the prison.
2. **The three hundred prisoners loosed** — bonds burst at a sign, walls crack, and he stays:
   *"I have a secret with Him which cannot be told save on the gallows."*
3. **Junayd signs in the gown of the academy** — flagged in `suggested_refs` as a hagiographic
   **time-fold**: the historical Junayd died in 298/910, twelve years before the trial. Marked
   `traditional`, kept, and the campa says plainly that the memory folds time.
4. **The ashes will not be quiet and the robe on the bank** — the Tigris rises crying *Ana'l-Haqq*
   until the servant lays the master's robe on the bank. This is the proper close of Attar's
   account and the journey now ends on it.

### Outstanding / not changed
- The 5-year Khuzestan circuit and the India–Turkestan mission remain collapsed to representative
  waypoints; the sources do not support finer resolution.
- Attar's later mutilations (eyes, ears, nose, tongue) and the old woman with the pitcher are not
  broken out as separate stops; the existing execution stops already carry the sequence and further
  splitting would thin them.

---

## Verification pass — 2026-07-20

Independent verify stage. Schema and register checked against `joan_of_arc.journey.json`.
`json_check.py`: **OK** before and after — 8 segments, **41 stops**, 14 quoted.
**No stops added, removed or reordered.** All repairs are in place, so the Spanish twin at
`es/hallaj.journey.json` remains positionally aligned. Two campas were reworded and eight
coordinates moved; the Spanish twin's corresponding campas and coordinates now differ from the
English and should be refreshed for those stops, but the array indices are untouched.

### Structure
Every stop carries exactly the Joan key set (`name, lat, lng, date, date_confidence, campa, quote,
quote_source, suggested_refs, sources`). Top-level keys match. Dates are chronological within all
eight segments and across them. Confidence labels are honest: `attested` only on the trial and
passion events that the chronicles carry (Ibn Ata's beating, the fatwa, the scourging, the
mutilation, the beheading), `traditional` on the hagiography, `inferred` on the flight, the capture,
the case-building and the prison poem. Campa word counts now all fall in 60–110 (one at 114 trimmed).

### Coordinates — 14 spot-checked, 8 stops moved
Verified correct, no change: al-Bayda/Beyza (30.008, 52.358 vs. Beyza town 30.0088, 52.360);
Wasit (32.188, 46.298 — exact match to the ruins); Tustar/Shushtar (32.042, 48.856 vs. 32.0436,
48.8567); Ahwaz (31.318, 48.671 — exact); Mecca/Kaaba (21.423, 39.826); Multan (30.1985, 71.469,
sitting on the fort and Prahladpuri sun-temple mound, apt for the campa); Samarkand (39.672, 66.991
— this is **Afrasiab**, the pre-Mongol mound, correct for 898 and not modern Samarkand); Qocho /
Gaochang (42.85, 89.527 vs. 42.8556, 89.5292); Sus / Susa (32.194, 48.246, on the Tomb of Daniel
the campa names); Great Mosque of al-Mansur (33.3475, 44.335 — matches the published Round City
coordinate exactly).

**Fixed:**
- **Basra ×2 stops** (1.0, 1.2): 30.509, 47.783 → **30.400, 47.700**. The file had pinned *modern*
  Basra. The 9th-century city where Sahl al-Tustari and Amr al-Makki taught lies ~15 km south-west,
  beside az-Zubayr. `suggested_refs` updated to say so.
- **The whole execution cluster, 6 stops** (7.1–7.6): 33.352, 44.373 → **33.3545, 44.3445**. The old
  coordinate sat on the **east** bank of the Tigris, contradicting the file's own campas and
  `suggested_refs`, which correctly say *near Bab Khurasan*. Bab Khurasan was the north-eastern gate
  of al-Mansur's Round City, on the **west** bank, by the Khuld Palace and the bridge of boats; the
  execution is attested there. Moved ~2.5 km west onto the right bank and the right gate.
- **The ashes and the robe, 2 stops** (7.7, 7.8): 33.351, 44.3745 → **33.356, 44.348**, same
  correction, kept slightly riverward of the gibbet as the original offset intended.
- **Zaranj** (3.3): 30.967, 61.879 → **30.960, 61.860**, tightened ~2 km onto the town.

### Quotes — 8 checked against the canon
The Attar quotes were checked line by line against Arberry's translation of the *Tadhkirat al-Awliya*
(full text, Internet Archive). **Seven verified verbatim, no drift:** the three nights in the
Presence; "I am God's captive… save on the gallows"; Junayd's "We judge according to externals";
"The ascension of true men is the top of the gallows"; "The cosmetic of heroes is their blood";
Shibli and the clod; and the robe on the bank. All are exact, including the ellipsis joins.

**Fixed:**
- **5.5, "I saw my Lord with the eye of the heart."** Wording is faithful to the Arabic
  (*ra'aytu rabbi bi-'ayni qalbi / fa-qultu man anta? qala: anta*) and the file's rendering is the
  more literal of the two circulating English forms — **kept**. But the attribution was wrong: this
  is a qasida of the **Diwan**, not the *Kitab al-Tawasin*. `quote_source`, `sources` and the campa
  corrected; the Tawasin remains in the stop as the prison's actual literary product.
- **6.2, the substitute-pilgrimage teaching.** The file carried a composite paraphrase ending
  "feed thirty orphans". The orphan almsgiving is attested as part of the teaching, but **the number
  thirty could not be confirmed in any source**. Replaced with the wording actually reported from the
  confiscated trial document (mihrab, purification, ihram, and thereby freed from the pilgrimage to
  the Bayt al-Haram). The seven-fold circling stays in the campa, which the charge does carry.
- **4.1, turban and cloak.** Quote is genuine and well attested (*ma fi jubbati illa Allah*) —
  **kept**. The attribution to al-Kalabadhi's *Kitab al-Ta'arruf* could not be confirmed and has been
  removed from `quote_source`, `suggested_refs` and `sources` rather than left standing unverified.
- **7.0, "You will see it today, tomorrow, and the day after tomorrow."** Confirmed genuine Attar —
  it is the "What is love?" exchange, present in the fuller Persian recension though not in Arberry's
  abridged selection, and the `quote_source` already said exactly that. **Kept.** The campa placed
  the exchange "in his cell"; the tradition places it on the way. Reworded to "reaches him", and the
  matching phrase at 7.6 ("the stranger at his cell door") reworded to match.

### Canon kept
Nothing mythic was removed. The three nights the prison could not hold him, the three hundred
prisoners loosed at a sign, the fruit out of season, Junayd's midnight door and the gibbet foretold,
the blood that spells *Allah*, the ashes that go on crying *Ana'l-Haqq*, and the robe that turns back
the Tigris all stand as events. The Junayd time-fold (he died 298/910, twelve years before the
warrant) remains marked by confidence and named in the campa, not argued away.

### Could not confirm
- The **thirty orphans** and the seven dirhams of the substitute-hajj instruction. Removed from the
  quote rather than asserted.
- The earliest textual witness for the **turban** clause specifically, as distinct from the cloak.
- Whether Massignon's exact English for *hasb al-wajid ifrad al-wahid lahu* (7.5) reads "reduce him
  to Unity" or "to His unity". The Arabic is attested and Attar's parallel is quoted alongside it in
  `quote_source`, so the rendering was left as it stands.
- The **execution ground to better than a few hundred metres**. Bab Khurasan and the west bank are
  attested; the Round City itself is unexcavated and its coordinate is a scholarly estimate. Note
  also that Attar names *Bab al-Taq*, which is on the east bank — a genuine divergence in the canon.
  The Massignon/west-bank location was followed because it is what the file's own prose already said.
