# Rabia al-Adawiyya — build report

**File:** `rabia.journey.json` — 8 segments, 38 stops, 31 quoted (31/38, the highest quote-density in the atlas so far — the canon here is almost entirely reported speech).

## Sources
The spine of the dataset is the chapter on Rabe'a al-'Adawiya in **Farid al-Din Attar's *Tadhkirat al-Awliya* ("Memorial of the Saints," c. 1220)**, read in **A. J. Arberry's translation, *Muslim Saints and Mystics* (1966)** — pulled in full from the Internet Archive OCR and used almost verbatim for both quotes and campa. This single chapter supplied roughly two-thirds of all 38 stops: birth, enslavement, the lantern, the desert hermitage, the pilgrimage, and nearly every anecdote and deathbed scene. Supplementary material came from **Margaret Smith, *Rabi'a the Mystic and Her Fellow-Saints in Islam* (1928)**, the first Western scholarly biography, which supplied the Emir's marriage proposal and the torch-and-water episode; **Jami's *Nafahat al-Uns* (15th c.)**, source for the Ibrahim ibn Adham / wandering-Kaaba scene and the Kaaba encounter; and **Abu 'Abd al-Rahman al-Sulami's *Dhikr an-Niswa al-Muta'abbidat as-Sufiyyat* ("Early Sufi Women," tr. Rkia Cornell, 1999)**, source for Maryam of Basra and 'Abda bint Abi Shawwal. Geography for the one outward journey — the Basra-Mecca pilgrim road through Wadi al-Batin and the Ad-Dahna sands — comes from Muslim Heritage's and Saudipedia's accounts of the historic Darb Zubayda network. The Jerusalem tomb material comes from Museum With No Frontiers and the Madain Project's descriptions of the Mount of Olives / Chapel of the Ascension complex.

## Judgment calls, gaps, and time-folds
- **The torch and the pail of water** — the single image the curator's brief centers on — does **not** appear in the core Attar chapter as translated by Arberry. It is universally attributed to "the tradition" in tertiary sources but I could not pin an early primary citation; I've sourced it to Margaret Smith (1928) and the general oral/hagiographic tradition rather than inventing a false precision.
- **Chronology is the tradition's own, not mine to fix.** Attar strings together interlocutors — Hasan al-Basri (d. 728), Malik ibn Dinar (d. 748), Sufyan al-Thawri (d. 778), Shaqiq al-Balkhi (d. c. 809) — as though they were contemporaries visiting one saint across a single lifetime, but their historical deaths span nearly a century. Modern scholarship (Cornell, in her introduction to *Early Sufi Women*) explicitly doubts Rabia and Hasan ever met. Rather than silently reconcile this or discard the Hasan cycle (it is the tradition's own best-loved material), I dated the Hasan-of-Basra encounters mid-life and the sickbed visits late, following the *narrative* order Attar gives, and flag the achronology here rather than pretending precision I don't have. All affected dates carry `date_confidence: "traditional"`.
- **Birth/death years**: sources split her death between 135 AH (752) and 185 AH (801); I followed the majority tertiary convention (717–801) for the header span, which is itself only one of several proposed ranges.
- **The Jerusalem tomb is very likely a case of mistaken identity**, not a genuine relocation: a second, later Damascene ascetic, Rabi'a bint Isma'il (d. 844), was also buried near Jerusalem, and the same cave is separately claimed by Christian tradition (Pelagia of Antioch) and Jewish tradition (the prophetess Huldah). I kept this as an honest multi-tradition coda rather than either endorsing or debunking any single claim — this is the connective tissue to the rest of the atlas (see below).
- **No stop count padding.** The real itinerary — Basra, the desert, the Mecca road, Mecca, back to Basra — is thin; I did not invent waypoints. The 38 stops instead distribute the *inward* material (sayings, miracles, deathbed exchanges) across dated stations at the one fixed point (Basra), exactly as the curator's brief asked for a "still point" journey. This is by design the most stationary dataset in the atlas: 32 of 38 stops share Basra's single coordinate pair.

## The five richest episodes
1. **The lantern without a chain** — her master waking to find her praying under an unhung, unfed light that fills his house, and freeing her by morning.
2. **The desert pilgrimage** — the ass dying and reviving in the Dahna sands, and the voice comparing her hunger to Moses' shattered mountain.
3. **The Kaaba that walked out to meet her**, leaving Ibrahim ibn Adham's fourteen years of prostrations looking merely diligent next to her single-minded arrival.
4. **The torch and the pail of water** — burn Paradise, douse Hell, love God for nothing.
5. **The twelve years of undesired dates** — her sharpest, plainest statement of what servanthood actually costs, delivered from a sickbed to Sufyan al-Thawri.

## Connections to the rest of the atlas
- **`rumi.journey.json`** — the only other Sufi figure in the atlas; Rabia predates and is quoted within the later Sufi curriculum Rumi inherits (the doctrine of love-without-motive is foundational to everything from Ibn Arabi to Rumi's own "Wedding Night").
- **`muhammad.journey.json`** — shares the `julian` calendar convention and the register phrase used for scripture-adjacent hagiography; Rabia's life falls entirely within the first two centuries after the Hijra.
- **`margarita_pelagia.journey.json`** — direct shared pin at the Mount of Olives (31.7784, 35.2419): that dataset already places "brother Pelagius's" cell and revelation-at-death on the same mountain that later tradition also claims for Rabia (and, separately, for the Jewish prophetess Huldah). Three faiths' holy women converging on one door in the ground.
- The atlas's **female-mystic axis** the curator named: Rabia now sits alongside Joan of Arc, Blavatsky, Annie Besant, Hypatia/Catherine, and the Pelagia/Thecla/Marina cluster as the deliberately *inward* counter-example — nearly every other journey in the corpus is a walker's itinerary; hers is a woman who made one pilgrimage in eighty-some years and spent the rest of her life proving she didn't need to leave the room.

---

## Verification pass — 2026-07-20

`json_check.py` clean before and after (8 segments, 38 stops, 31 quoted). **Stop count and order unchanged; no stop added, removed or reordered** — every repair was made in place, so the positional alignment with `es/rabia.journey.json` is intact.

### Structure and schema
Compared field-for-field against `joan_of_arc.journey.json`: same header keys, same per-stop keys (`name`/`lat`/`lng`/`date`/`date_confidence`/`campa`/`quote`/`quote_source`/`suggested_refs`/`sources`), same null-quote convention. `register` uses an em dash where Joan uses a colon; both spellings are already in wide use across the corpus (59 comma / 58 colon / 11 em-dash), so it was left alone.

### Dates
Chronological within every segment, and across segments. The 1495 date on the Jerusalem tomb stop is a deliberate late anchor (Mujir al-Din al-'Ulaymi's *al-Uns al-Jalil*, the Jerusalem holy-places history that fixes the Mount of Olives claim) and sits last, so the sequence holds.

**Changed: 23 `date_confidence` values from `traditional` to `inferred`** — all of segments 4 ("Wonders at the Threshold"), 5 (the Hasan cycle), 6 (the Emir and the household of women) and 7 (the sickbed). The rule applied: the tradition supplies *sequence* for the narrative spine (birth, enslavement, the fall, the lantern, manumission, the desert, the one pilgrimage, the death, the dream, the tomb) and those stay `traditional`; but for the free-floating anecdote and interlocutor cycles Attar gives no chronology at all, and the years in this file are the compiler's own spacing — as the build report itself admits. Calling those `traditional` over-claimed. Nothing in the file is marked `attested`, which is correct: not one date in Rabia's life is documented.

### Coordinates — 11 distinct pairs checked, covering all 38 stops; 4 corrected (31 stops moved)
| stop(s) | was | now | why |
|---|---|---|---|
| Basra proper (25 stops) | 30.5085, 47.7835 | **30.3833, 47.7083** | 30.5085/47.7835 is *modern* Basra, founded in the 18th century near old al-Ubulla. The Basra of 636–c. 1000, the city Rabia actually lived and died in, stands ~13 km southwest at present-day al-Zubayr. `aishah.journey.json` already pins historic Basra at exactly 30.3833, 47.7083 for the Battle of the Camel; this now matches. |
| Wadi al-Batin | 28.6, 46.4 | **28.85, 46.34** | 28.6/46.4 sat ~27 km east of the actual channel. The wadi runs NE–SW from the Iraq/Kuwait border down to Hafar al-Batin (ref. 29.10, 46.56); the new point is on the channel and on the Basra–Mecca stage. |
| Ad-Dahna sands | 25.3, 45.6 | **26.4, 45.4** | 25.3/45.6 is west of the Tuwaiq escarpment, i.e. *not in the Dahna at all*. The Basra road crosses the Dahna in its northern reach before entering al-Qassim; the new point is inside the sand belt and on that stage. |
| Mount of Olives tomb | 31.7784, 35.2419 | **31.7786, 35.2447** | The maqam is the zawiya of Rabi'a al-'Adawiyya immediately southwest of the Chapel of the Ascension (31.7789, 35.24505). The old pin was ~290 m west, off the compound. |

Verified as already correct and left alone: the Kaaba (21.4225, 39.8262 — exact); the Mecca approach (21.47, 39.95 — NE of the city, where the Iraqi road arrives); the Tigris/Shatt al-Arab bank at 30.52, 47.81 (old Basra's river frontage at al-Ubulla, which is what Attar means by "the Tigris"); and the four desert/lake points west and northeast of the city (30.32/47.52, 30.3/47.5, 30.28/47.48, 30.48/47.76), all of which read correctly *relative to the corrected Basra pin*.

**Flag for a later pass, not fixed here:** `attar.journey.json` (30.5085, 47.7804, "Basra, the grave of Rabia") and `hallaj.journey.json` (30.509, 47.783) both use the modern-Basra pin. The Attar stop is a shrine and may legitimately belong at the modern site; the Hallaj stops (d. 922) probably belong at al-Zubayr. Left untouched — out of scope. Likewise `margarita_pelagia.journey.json` still carries the old Mount of Olives pin (31.7784, 35.2419) and now diverges by ~290 m from this file's shared pin.

### Quotes — 21 checked against the canon, 4 repaired, 0 nulled, 0 invented
Arberry's *Muslim Saints and Mystics* (the Rabe'a al-Adawiya chapter) was pulled in full and every Attar-sourced quote read against it. **Verified word-exact:** the Prophet's "queen among women"; the broken hand ("I am a stranger, orphaned of mother and father…"); the lantern litany; the forty-year covenant and the onions; the dying ass ("do kings so treat a woman who is a stranger and powerless?"); the eighteen thousand worlds and Moses' shattered mountain; the thief and the chaddur; "You eat their fat"; the bandage of thankfulness; "How did 'colour' come into the business?"; "come in and see the Maker"; the knife and being cut off; wax, needle and hair; "what you did fishes also do"; "this weeping is a sign of spiritual languor"; the twelve years of fresh dates; the lash of the Lord; the purchaser who disparages the wares; egoism and "I am your Lord, the Most High"; "I gazed upon Paradise"; "O soul at peace"; and the Munkar-and-Nakir dream.

**Repaired (silent elisions restored or marked; nothing was fabricated):**
- *the twenty loaves* — the tenfold prayer had been paraphrased into indirect speech; restored to Arberry's direct quotation with an ellipsis.
- *the refused proposal* — "I live in the shadow of His control." had been dropped without a mark; restored, since the campa already leans on it.
- *the purse of gold* — "Ever since I knew Him, I have turned my back upon His creatures." had been silently cut; restored.
- *Malik ibn Dinar* — the poor-and-rich clause is genuinely cut (it is Malik's interjection); an ellipsis now marks the join.

**Non-Attar quotes checked separately:** the Emir's refusal ("…that you should keep me occupied, away from Allah, even for a glance") is transmitted verbatim in this English wording across the Ibn Khallikan / Jami / Smith line — kept. The Kaaba saying ("It is the Lord of the house whom I need…") is likewise stable in the tradition — kept; note that Arberry's *abridged* Attar carries neither this nor the wandering-Kaaba scene, which is why both are correctly sourced here to the later redactions rather than to Arberry.

**Could not confirm:** the torch and the pail of water. It is universally attributed to Rabia and universally repeated, but I found no early primary attestation and the English wording varies from teller to teller — Attar's chapter carries only the doctrinally equivalent prayer ("O God, if I worship Thee for fear of Hell, burn me in Hell…"). Left standing as canon, since the register is that the canon is true, but **`quote_source` was tightened** to say so out loud: "Sufi oral tradition, widely transmitted in varying wordings; no early primary attestation."

### Campa
All 38 present tense and in register. One over-length: the Munkar-and-Nakir stop at 114 words, trimmed to 106 without losing the answer to the angels. The remaining 37 were already inside 60–110 (range now 96–110). The great episodes — the lantern without a chain, the ass revived in the Dahna, the Kaaba walking out to meet her, the torch and the water, the twelve years of undesired dates — all carry their weight; none read flat.

### Stop count
38, well above the 30 floor, so nothing was added. For the record, Attar's chapter does hold one first-rate episode the dataset omits — the spilled bowl, the broken jug, and the voice saying "My desire and thy desire can never be joined in one heart" — but adding it would have shifted every later index and broken the Spanish twin. Noted here for a future pass that regenerates both files together.
