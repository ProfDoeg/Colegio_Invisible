# rumi.journey.json — research & verification report

Traveler: Jalal al-Din Rumi (Mowlana Jalaluddin Muhammad Balkhi), 1207–1273.
Register: national mythology — the canon is true. Calendar: julian.

---

## Verification pass — 2026-07-20

Structure and canon-fidelity verified against `joan_of_arc.journey.json` as the schema and
register reference. **No stop was added, removed or reordered.** Stop count 41, segments 8,
before and after. All repairs were made in place, so the Spanish twin remains positionally
aligned (its text is now stale at the twelve stops listed below, but its indices are not).

`json_check.py` passes clean: `segments=8 stops=41 quoted=13` (was `quoted=15`; two quotes
nulled, see below). Campa word counts all inside the 60–110 band and dates chronological
within every segment, both before and after the edits — the checker enforces both.

### 1. Coordinates — 13 stops spot-checked, 6 corrected

| Stop | Was | Now | Why |
|---|---|---|---|
| Baghdad, thirty days at the tomb of Junayd | 33.3152, 44.3661 | 33.3344, 44.3747 | Was generic Baghdad centre. Junayd and Ma'ruf al-Karkhi — both named in the campa — lie in the Sheikh Ma'ruf cemetery (Maqbarat Shuniziyya) in Karkh, 33°20′03.9″N 44°22′28.9″E. The shrine-mosque was built 1215–16 and renovated 1225, so it stood when the family passed in 1219. |
| Malatya, the bread of exile | 38.3552, 38.3095 | 38.4228, 38.3656 | **The substantive fix.** The old coordinate is modern Malatya, a 19th-century foundation that did not exist in 1221. Seljuk Malatya is Battalgazi / Eski Malatya, 10 km north — where the Ulu Cami built by Ala al-Din Kayqubad in 1224 still stood until 2023. The stop's own `suggested_refs` already named Battalgazi; only the pin disagreed. |
| Aleppo, the Halawiyya | 36.2021, 37.1343 | 36.1996, 37.1560 | Was Aleppo city centre. The stop names the Halawiyya madrasa, in the al-Jalloum quarter of the old city, 36°11′58.4″N 37°09′21.4″E. |
| Konya, arrival at the sultan's invitation | 37.8719, 32.5089 | 37.8734, 32.4933 | Stop names the Alaeddin Mosque and citadel hill; that is Alaaddin Hill, ~1.4 km west of the generic Konya pin. |
| Konya, the death of the Sultan of the Learned | 37.8719, 32.5089 | 37.8706, 32.5047 | The sultan's rose garden = the site under the Green Dome, i.e. the Mevlana Museum, 37.8706/32.5047. |
| Konya, burial beneath the Green Dome | 37.8719, 32.5089 | 37.8706, 32.5047 | Same; father and son share the plot, so the two stops now share the pin. |

Checked and **left unchanged** as correct: Balkh 36.755/66.897; Nishapur 36.2064/58.7958
(medieval and modern city are effectively coincident); Mecca 21.4225/39.8262 (the Kaaba
exactly); Damascus 33.5117/36.3064 (the Umayyad Mosque exactly); Erzincan 39.75/39.4917;
Larende/Karaman 37.1759/33.2287; Meram 37.85/32.46. The remaining generic Konya stops keep
37.8719/32.5089, which sits inside the historic core and is a defensible house pin for
episodes without a single fixed address (the sugar-merchants' han, the goldsmiths' bazaar).

### 2. Dates and confidences — 2 corrected

Two dates contradicted the file's own prose and the standard chronology of the exile:

- **Erzincan** 1222-06-01 → **1221-09-01**
- **Larende (Karaman)** 1225-01-01 → **1222-09-01**

The Larende campa claims "the wandering pauses seven years" and the family is agreed to have
reached Konya in 1229; 1225 gives four years, 1222 gives seven. Encyclopaedia Iranica has the
Larende stay at "at least seven years" and Konya at 626/1229. Order within the segment is
unchanged (Malatya 1221-01 → Erzincan 1221-09 → Larende 1222-09 → Sultan Walad 1226-04).

Also removed the unsupported duration from the Malatya stop **name**: "Malatya, four years of
the bread of exile" → "Malatya, the bread of exile". Iranica assigns the disputed four years
to Erzincan (Jami), which Aflaki flatly contradicts by saying Baha al-Din refused to enter the
city at all; no source gives Malatya four years, and four years there cannot be reconciled
with seven at Larende ending in 1229.

Confidences audited and left as they stand — `traditional` throughout the hagiographic
material, `attested` reserved for the four hard dates (Baha al-Din's death 1231-02-23, Rumi's
death 1273-12-17, the burial, and the 1925 tekke closure). That distribution is honest.

Two contested dates were deliberately **not** changed:

- **Shams's disappearance, 1247-12-05.** Wikipedia and much popular writing give 5 December
  1248. The chronology that follows Franklin Lewis — the file's principal cited source — gives
  December 1247. Both are live in the scholarship; the file is internally consistent with its
  own authority and with the ten-year Salah al-Din companionship ending 1258-12-29. Changing
  it would have cascaded four stops' dates for no gain in truth. Marked `traditional`, correctly.
- **Balkh as birthplace, 1207-09-30.** Lewis and most scholars now argue for Vakhsh in
  present-day Tajikistan. The canon says Balkh, the traveler's own nisba says Balkhi, and the
  register is "the canon is true"; the pin stays at Balkh and the `suggested_refs` already say
  "traditional birth-city". Not debunked, correctly flagged.

### 3. Quotes — 9 spot-checked, 6 repaired (2 nulled)

**Nulled — could not be found in any source, hagiographic included:**

- *"What I thought was knowledge, I found to be ignorance beside what Shams has shown me."*
  (Konya, the forty days behind the locked door). The sentiment is genuinely Rumi's and the
  campa already carries it in his own image — knowledge "like carrion beside the feast" — but
  no source carries this sentence. Nulled rather than left standing as invented canon.
- *"His mistakes in speech are dearer to me than the correctness of the learned."*
  (Salah al-Din Zarkub, the second sun). The underlying fact is well attested: Zarkub was
  unlettered, mispronounced words, and Rumi deliberately took his errors into his own verse.
  The sentence itself is not attested. Nulled; the campa still tells the story.

**Restored to the canon's real wording:**

- *"I do not know, of the two, which was the lover and which the beloved."* → *"They fell at
  each other's feet, and no one knew who was the lover and who the beloved."* The transmitted
  form of Sultan Walad's line is third-person and impersonal; the first-person version put
  words in the son's mouth that the Ibtidanama does not carry.
- **Masnavi II opening.** Was *"The verse of the Masnavi was delayed. A little time was needed
  for the blood to become milk,"* sourced as "trans. Nicholson, paraphrase" — a paraphrase
  wearing a translator's name. Restored to Nicholson: *"The composition of the Masnavi has been
  delayed for a season: an interval was needed in order that the blood might turn to milk."*
- **Qur'an 37:102 on the deathbed.** Confirmed genuine — Aflaki does record Rumi reciting it in
  his last illness, together with the basin of water detail the campa uses. Aligned to the
  attested rendering: "...among those who are patiently submitting."
- **Fihi ma Fihi, the Qur'an as bride.** The quotation is real and the wording in the file is
  accurate, but it was credited to *"trans. A. J. Arberry, Discourse V"*. It is not Arberry's
  wording — it is William C. Chittick's, and I could not verify the discourse number
  (sufinama indexes the bride passage at Majlis 65, which I could not confirm against a
  printed edition). Attribution corrected to Chittick; the unverified discourse number dropped.
- **The bridle question at the Inn of the Sugar Merchants.** The exchange is canonical, but the
  file's phrasing ("quenched by one swallow") was a loose retelling presented as verbatim. The
  attested image is that Bayazid's thirst was small enough to be satisfied by a single drop
  while the Prophet's vessel could never be filled; the quote now uses that, and the
  `quote_source` says plainly "the traditional form of Rumi's answer" rather than implying a
  transcript.

**Checked and confirmed to stand as written:** Attar's *"Here comes a sea followed by an
ocean"* at Nishapur (hagiographic, and labelled as such via Dowlatshah and Aflaki); Ibn
al-Arabi's *"An ocean walking behind a lake"* in Damascus (hagiographic; no historical evidence
the meeting occurred, and the source field already says "later Mevlevi hagiographic
tradition"); the Masnavi Book I opening in Nicholson's exact wording; *"Am I a thief? Have I
stolen someone's goods?..."* — verbatim as transmitted from Aflaki.

Burhan al-Din's two verdicts (*"In learning you have surpassed your father..."* and *"Without
equal in the world..."*) I could not trace to a printed line of Aflaki, but the substance is
carried by the biographical tradition and both fields already say "Attributed to". Left
standing as tradition, not upgraded.

### 4. Campa prose

All 41 campas are present tense, in register, and inside the 60–110 word band (checker
enforced). The great episodes — the bridle in the square, the forty days behind the door, the
goldsmiths' hammers, the last night, the wedding night — are not flat. Two factual errors
inside campas were corrected without disturbing the word counts:

- "that showing is still **nine** years and one strange old wanderer away" → **thirteen**.
  Rumi mounts his father's pulpit in 1231; Shams arrives in 1244.
- the Masnavi "breaks off after some **eighteen hundred** couplets" → **four thousand**.
  Book I is 4,003 lines in Nicholson's edition; the two-year silence falls at the end of Book
  I, not a fifth of the way through it. Book II's own verse 7 dates the resumption to 662 AH.

### 5. Stop count

41 stops across 8 segments — well above the 30 threshold. No additions warranted.

### Could not confirm

- Shams's disappearance year (1247 vs 1248) — genuine scholarly disagreement, left on Lewis.
- The discourse number of the Qur'an-as-bride passage in Fihi ma Fihi.
- Verbatim sources for Burhan al-Din's two verdicts.
- Whether the two-year gap between Masnavi I and II was two years or nearer one — Nicholson
  and dar-al-masnavi say about two, Mojaddedi says almost one. Campa keeps "nearly two years".

Sources leaned on this pass: Encyclopaedia Iranica (Baha al-Din Walad, Aflaki),
footprintsofrumi chronology (following Lewis), dar-al-masnavi (Gamard), Wikipedia articles on
Rumi / Shams Tabrizi / Battalgazi / al-Halawiyah Madrasa / Sheikh Ma'ruf Cemetery / Alâeddin
Mosque, the Morgan Library's Rumi cycle notes, and the OUP blog on Rumi's death.
