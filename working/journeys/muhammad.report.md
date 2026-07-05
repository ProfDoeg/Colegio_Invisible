# The Messenger's Road — Mecca to Medina (AD 570–632)

**Traveler:** Muhammad ibn Abdullah · **Calendar:** Julian · **Register:** reverent mythography — the Quran, Sira, and sound hadith narrated as true, the revelation and wonders placed and dated as events. **Aniconism observed:** every `suggested_ref` is a site, well, mountain, mosque, manuscript, seal, or calligraphic panel — never a figural depiction of the Prophet.

**Shape:** 8 named segments, 45 stops, 30 canonical quotes (Quran suras, Bukhari/Muslim hadith, the Sira, the Farewell Sermon, the letter to Heraclius). Quotes are null wherever the canon records no words (Halima's tents, the Bahira validation as narrated indirectly, the Year of Sorrow, Mu'ta).

## Sources
- **Quran** — cited by sura/ayah for every revelation placed: Al-Fil 105 (the Elephant), Al-Alaq 96 (Iqra), Al-Isra 17:1 & 17:81, At-Tawba 9:40 (the cave) & 9:25-26 (Hunayn), Al-Anfal 8:30, Al-Baqara 2:144 (qibla), Al Imran 3:124-125 & 3:144, Al-Ahzab 33:9, Al-Fath 48:1, At-Tawba 9:108 (Quba), Maryam 19.
- **Sira** — Ibn Ishaq / Ibn Hisham, *Sirat Rasul Allah* (Guillaume trans.) for the narrative spine; Ibn Sa'd's *Tabaqat* for birth/nursing detail.
- **Hadith** — Sahih al-Bukhari (nos. 3 first revelation, 7 letter to Heraclius, 3887 the Mi'raj) and Sahih Muslim (162 the splitting of the breast & Night Journey). The Ta'if supplication via Ibn Ishaq / al-Tabarani.
- **Sites/coordinates** — Wikipedia and IslamicLandmarks/Madain Project for the traditional locations (Jabal al-Nur/Hira, Jabal Thawr, Quba, Uhud, Badr, Khaybar, Mu'ta at Mazar, Aksum/Negash, Hunayn, the Green Dome).

## Judgment calls
- **Coordinates = the traditional site the canon locates the event**, not a modern administrative centre. Hira and Thawr are the cave peaks; Badr is the wells/battlefield; the Night-Journey ascent stops (heavens, Lote-Tree, Bayt al-Ma'mur) are pinned at the Noble Rock in Jerusalem, since that is where the Mi'raj launches — celestial stations have no earthly lat/lng, so they anchor to as-Sakhrah with micro-offsets to keep them distinct on a map.
- **Dating** is Julian per the brief. Fixed anchors (Badr 13 Mar 624, Uhud 625, Trench 627, Hudaybiyya 628, Farewell Sermon 6 Mar 632, death 8 Jun 632) are marked **attested**; the Meccan childhood, the Opening of the Breast, Hira retreats, Isra/Miraj, and cave episodes are **traditional** (the tradition assigns them but scholars vary — e.g. first revelation 610, dated variously 17th/21st Ramadan). Nothing pre-Hijra can be called attested in the documentary sense; I did not overclaim.
- **The miraculous is stated as fact**, per register: the ababil turn back the elephant, the two men in white open the breast, Gabriel presses "Iqra," Buraq crosses the night, the prophets welcome him through seven heavens, the spider and dove veil the cave, angels descend at Badr, the boycott-parchment is eaten but for God's name. These are placed and dated, not hedged.

## Time-folds and geographic splits the tradition itself makes
- **The Night Journey (Isra + Mi'raj)** is the great fold: a single night carries Mecca → Jerusalem → the seven heavens → the Lote-Tree → back to Mecca. I split it into five stops (Buraq at the Kaaba, Al-Aqsa, the ascent past the prophets, the Lote-Tree/fifty-to-five, and the return implied in the Farewell arc) so the itinerary can hold what the canon compresses into one night. **His Jerusalem here faces Solomon's Temple and Christ** — the Rock of the Temple, the prophets led in prayer, the milk-not-wine of the true nature.
- **The two Openings of the Breast** — the tradition places the purification twice: in Halima's desert (childhood) and again before the Mi'raj. Both are kept, as the sources keep both.
- **Mecca is left and re-entered three times**: cast out at the Hijra, halted at Hudaybiyya, returned to as conqueror — the same Kaaba, the same qibla the community had already turned to face. **His Kaaba faces Abraham's**: the House he cleanses is the House Abraham raised, and the qibla-turn (2:144) makes that lineage the axis of prayer.

## The five richest episodes
1. **Iqra at Hira** (seg. 3) — Gabriel's threefold pressing, the first words of the Quran, the trembling flight to Khadija's cloak, and Waraqa's recognition of "the Namus that came to Moses." The hinge of the whole journey.
2. **The Isra and Mi'raj** (seg. 4) — Buraq, the prophets at Al-Aqsa, Adam→Moses→Abraham through the heavens, the Lote-Tree, and Moses sending him back to bargain the prayers from fifty to five. The richest single fold.
3. **The Cave of Thawr** (seg. 5) — Ali in the bed, the assassins' ring, the spider's web and the dove's nest, "Do not grieve; God is with us" (9:40). The turning of the Hijra.
4. **The Conquest of Mecca** (seg. 8) — the humble entry, the general pardon, the 360 idols struck down to "Truth has come and falsehood has vanished" (17:81), and Bilal — once crushed on the sand crying "One! One!" — calling the adhan from the Kaaba's roof. The arc's resolution.
5. **The Farewell Sermon at Arafat** (seg. 8) — "your blood and your property are sacred," the perfected religion (5:3), the threefold "Have I conveyed?" — the summing-up months before the death in Aisha's chamber and the grave beneath the Green Dome.

---

## Verification (2026-07-05)

Structure- and canon-fidelity pass. No debunking: theophanies, revelations, curses and miracles all stand; mythic time-folds carried on `date_confidence`, not removed.

**(1) Schema / parse.** Parses clean with python. Top-level keys (`traveler, title, years, calendar, register, segments`) and stop keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) are byte-for-byte identical to the sibling `joan_of_arc.journey.json`. Segment keys (`name, stops`) match. 8 segments, **45 stops**, 30 non-null quotes. `date_confidence` uses `{attested, traditional}` — a subset of Joan's `{attested, traditional, inferred}`, schema-compatible. All lat/lng in range; all enums valid. Stop counts per segment: 7/4/6/7/5/3/7/6.

**(2) Chronology & confidence.** Every stop is in non-decreasing date order across the whole flat sequence (0570-01-01 → 0632-06-08); no inversions. The four Isra/Mi'raj stations correctly share one date (0621-02-01 — a single night). Confidence is honest: the 11 `attested` stops are exactly the historical anchors (Badr, Uhud, Trench, Hudaybiyya, Khaybar, Mu'ta, Conquest, Hunayn, Farewell Sermon, last illness, grave); all 34 pre-Hijra / legendary / miraculous stops (elephant, Halima, opening of the breast, Bahira, Hira, Isra/Mi'raj, cave episodes, Suraqa) are `traditional`. Nothing pre-Hijra overclaimed.

**(3) Coordinates — spot-checked 11 sites, all accurate to the traditional locus:**

| Stop | Dataset | Traditional site | Verdict |
|---|---|---|---|
| Cave of Hira / Jabal al-Nur | 21.4577, 39.8613 | ~21.4576, 39.8594 | on the mountain (~200 m) ✓ |
| Cave of Thawr | 21.344, 39.857 | ~21.344, 39.857 | exact ✓ |
| Quba Mosque | 24.4392, 39.6172 | 24.4368, 39.6170 | exact ✓ |
| Badr (wells/field) | 23.7559, 38.7578 | ~23.733, 38.767 (town) | field N of town ✓ |
| Al-Aqsa / Noble Rock (×3 Mi'raj) | 31.778x, 35.235x | 31.7780, 35.2354 | exact ✓ |
| Mu'ta at Al-Mazar | 31.0522, 35.7011 | ~31.068, 35.696 | district (~2 km) ✓ |
| Aksum (Negus's court) | 14.1211, 38.7245 | Aksumite capital | capital, not Negash — matches primary ref ✓ |
| Mount Uhud | 24.5062, 39.6083 | 24.5062, 39.6083 | exact ✓ |
| Mount Arafat / Jabal al-Rahmah | 21.3549, 39.9843 | ~21.3548, 39.9838 | exact ✓ |

No coordinate corrections needed. Aniconism holds throughout `suggested_refs`: every ref is a site/well/mountain/mosque/manuscript/seal/calligraphy — no figural depiction of the Prophet (Buraq/Miraj-nama refs explicitly note the face left blank).

**(4) Quotes — spot-checked 8 against the canon, all faithful with correct citation:**
- Al-Fil **105:1-5** (elephant / ababil / eaten straw) — faithful ✓
- Al-Alaq **96:1-5** (Read... clinging clot... taught by the pen) — faithful ✓
- Al-Isra **17:1** (Glory be to Him who took His servant by night) — faithful ✓
- Bukhari **3887** Mi'raj (Jesus & John in the heavens; "Welcome, O righteous prophet and righteous brother") — faithful ✓
- Bukhari **3** Waraqa ("This is the Namus... sent to Moses"; the driving-out) — verbatim ✓
- At-Tawba **9:40** (Do not grieve; God is with us), Al-Baqara **2:144** (turn your face toward the Sacred Mosque) — correct chapter-and-verse ✓
- Death words (Bukhari, Kitab al-Maghazi via Aisha; "the highest companions" = *Rafiq al-A'la*) — faithful ✓

No paraphrase needed restoring; no quote needed nulling. `quote: null` is correctly used wherever the canon records no words (Halima, Zamzam, Abu Talib's guardianship, the boycott, Year of Sorrow, the first believers, Aqaba, Suraqa, Mu'ta, etc.).

**(5) Campa voice.** All 45 campa within the 60–110 word band; present tense, reverent throughout. The great episodes are not flat: Hira (the threefold pressing, "Read in the name of thy Lord"), the Opening of the Breast, the Mi'raj (Buraq, the prophets, the Lote-Tree, the fifty-to-five bargain), Thawr (spider and dove, "God is with us"), the Conquest (idols struck down, Bilal's adhan from the roof), and the death in Aisha's chamber all carry full weight.

**(6) Count.** 45 stops — at the floor of the 45–65 target. Coverage is already thorough across every major episode of the Sira from the Year of the Elephant to the Green Dome; no canonical gap warranted forced padding, so no stops were added.

**Result:** Repaired in place — **no edits required**. Dataset passes structure and canon-fidelity as delivered; re-validated with python (parses, 45 stops, enums/coords valid).
