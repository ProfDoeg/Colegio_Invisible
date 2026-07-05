# Nizami Ganjavi — The Five Treasures: research report

**Dataset:** `nizami.journey.json` — 26 stops, 7 named segments, 19 quotes. Calendar: Julian (AD 1141–1209). Register: reverent mythography — the Khamsa is treated as a true set of worlds, its wonders (Farhad moving the mountain, Khidr's Water of Life, the seven planetary domes) narrated as events to be placed and dated.

## The structure
The journey walks **two geographies at once**, as the brief required. Nizami barely left Ganja, so his life-stops (birth, uncle, self-schooling, marriage to Afaq, her death, the patrons, his death, the tomb) are marked `attested`/`inferred` and pinned to Ganja and Erzinjan. His *true* journeys are the five imagined worlds of the Quintet, so five segments follow the pen into the poem-settings — marked `traditional` — with real coordinates for the sites the poems name (Ctesiphon/Mada'in, Behistun, Najd, Mecca/Kaaba, the Land of Darkness). A seventh segment returns to the tomb.

## Sources
- **Biography & Khamsa overview:** Wikipedia *Nizami Ganjavi*, *Khamsa of Nizami*; Encyclopaedia Iranica *Ḵamsa of Neẓāmi*; Bodleian *Nizami Ganjavi Library*; World History Encyclopedia.
- **Per-poem:** Wikipedia *Makhzan ol-Asrar*, *Khosrow and Shirin*, *Layla and Majnun (Nizami)*, *Haft Peykar*, *Iskandarnama (Nizami)*, *Alexander the Great in Islamic tradition*; Iranica *Haft Peykar* and *Leyli o Majnun*.
- **Museum folios (suggested_refs):** LACMA (Shirin visiting Farhad at Behistun), Harvard Art Museums (Black Pavilion), Cleveland Museum of Art (White Pavilion, Friday), British Library Or. 12208, Chester Beatty Khamsa.
- **Quotes:** Dick Davis and Julie Scott Meisami translations (Khosrow/Shirin, Haft Paykar); G.H. Darab *Treasury of Mysteries* (1945); The New Criterion excerpt of Davis's Khosrow & Shirin; Goodreads verbatim Layla/Majnun quote pages; Quran 18 (al-Kahf) for Dhul-Qarnayn.

## Judgment calls
- **Afaq's name.** Scholarship is split: Vahid Dastgerdi read the Kipchak bride's name as *Afaq* ("horizon"); Said Nafisi and others read the same verse as the common noun. In this register I keep *Afaq* (the beloved of tradition) but flagged the dispute in the quote_source and worked the "horizon" double meaning into the campa.
- **Quotes.** Most Khamsa lines circulate only as prose paraphrase or loose verse translation; I attributed quotes to the poem and translator/tradition rather than inventing chapter-and-verse. The two hard-anchored quotes are the Shirin oath (Davis) and Quran 18:95–96 (Dhul-Qarnayn's wall). The others are marked as poetic/Sufi tradition. Nulls left where the canon records no speech.
- **Dates.** Composition dates follow Iranica: Makhzan ~1163–76, Khosrow/Shirin 1177–80, Layla/Majnun 1192, Iskandarnama 1194–1202, Haft Paykar 1197 (probably last-composed though placed fourth in most manuscripts). Life dates (birth 1141, death 1209) are the standard anchors, marked `attested` only for death/tomb.
- **Coordinates.** Poem-settings use the real named sites: Behistun/Bisotun (34.388, 47.437), Najd (24.291, 43.588), Kaaba (21.4225, 39.826), Ctesiphon (33.099, 44.581), Qasr-e Shirin (34.516, 45.579). The seven domes and the Land of Darkness have no fixed site, so I used the *clime* each princess comes from (India, Turkestan, Saqlab, Iran) and a far-north point for the Darkness — honest stand-ins for imagined geography.

## Time-folds / geographic splits
The dataset deliberately **folds two timelines**: the poet's mid-12th-c. composition dates and the legendary/ancient settings of the tales (Sasanian Khosrow d. 628; the semi-historical Bahram Gur d. 438; Umayyad-era Majnun; the pre-Islamic Iskandar/Alexander). I dated each poem-stop to the *composition* window (1160s–1200s) so the journey stays chronological as a walk of Nizami's pen, while the campas narrate the ancient events. The Iskandar segment splits the north into three imagined sites (Land of Darkness, the Gog-Magog wall) that no map can fix.

## The five richest episodes
1. **Farhad at Mount Behistun** — the sculptor carving a road through living rock for love of Shirin, killed by a false rumor of her death: the corpus's clearest "man moves a mountain for love and dies of a lie." Faces every doomed-artificer story in the atlas.
2. **Majnun in the desert of Najd among the wild beasts** — the fullest Sufi allegory of *fana*, the self annihilated until only the Beloved remains; "I am the veil between myself and Layla." The great annihilating-love node.
3. **The seven planetary domes of Haft Paykar** — the seven spheres made architecture, a week of color and story from Saturn's black to Venus's white; explicitly set to face the orrery of the corpus and the Dantean cosmos.
4. **Iskandar in the Land of Darkness** — the prophet-king who cannot find the Water of Life that Khidr, seeking nothing, drinks: kingship denied the one gift it cannot seize.
5. **The gift and death of Afaq** — the Kipchak bride freed and married, then lost young, her death written straight into the death of Shirin: the one place the poet's own grief and his poem's grief become a single lament.

---

## Verification (2026-07-05)

Independent structure + canon-fidelity pass. Register preserved — every mythic element (Farhad moving the mountain, Khidr and the Water of Life, the seven planetary domes, the sealed wall against Gog and Magog) stands; the deliberate two-timeline fold was checked, not flattened.

**Structure.** JSON parses. Keys match the sibling schema `joan_of_arc.journey.json` exactly at all three levels (top: `traveler/title/years/calendar/register/segments`; segment: `name/stops`; stop: `name/lat/lng/date/date_confidence/campa/quote/quote_source/suggested_refs/sources`). 26 stops in 7 segments, 19 non-null quotes — matches the summary.

**Dates.** All AD/CE positive dates; string sort = numeric sort, no BCE mis-ordering risk. Intra-segment dates are strictly chronological. The three cross-segment backward steps (Makhzan ~1165 after the life-segment's 1188; Iskandarnama 1194 after Haft Paykar 1197) are the intended treasure-order / composition-vs-setting fold documented above, not errors — segments are the Five Treasures in canonical sequence. Confidences honest: legendary poem-settings `traditional`, life-inference `inferred`, only death + tomb `attested`.

**Coordinates — spot-checked 10 against the canon's located sites:**
- Ganja city 40.683/46.360 ✓ (std 40.683/46.361); life-stops jitter within the city ✓
- Behistun 34.388/47.437 ✓ (34.386/47.435)
- Ctesiphon/Mada'in 33.099/44.581 ✓ (33.0895/44.575)
- Qasr-e Shirin 34.516/45.579 ✓ (34.516/45.580)
- Kaaba 21.4225/39.826 ✓ (21.4225/39.826)
- Najd desert 24.291/43.588 ✓ (Najd centroid, exact)
- Erzinjan/Erzincan 39.739/39.490 ✓ (39.739/39.490)
- Banu Amir lands 25.5/44.0 and Layla's grave 24.7/46.7 ✓ (northern / central Najd, honest stand-ins)
- **FIXED — Nizami Mausoleum:** was 40.618/46.450 (open country ~7 km south of the shrine); corrected to **40.684/46.433** per Wikipedia (40.68389/46.43278), the tomb on the Ganja–Baku road just outside the city.
- Haft Paykar clime stand-ins (India/Turkestan/Saqlab-Moscow/Iran) and the far-north Land of Darkness / Gog-Magog points left as marked honest stand-ins for imagined geography.

**Quotes — spot-checked 6:**
- Shirin's oath (Davis) ✓ verbatim against The New Criterion excerpt — the hard anchor holds.
- Farhad's death: event (false rumor of Shirin's death → leap from Behistun) confirmed canon; line is attributed as poetic tradition, not claimed verbatim — kept.
- Majnun's Kaaba prayer, Anushirvan-and-owls, self-reference-as-treasure: attributed to poem + tradition, not invented chapter-and-verse — kept as marked.
- **FIXED — Quran 18:95–96:** the quote read "Bring me iron and molten brass, that I may build a barrier between you and them," which conflated 18:94 (the *people* asking for a barrier) with the iron/molten-metal command of 18:95–96. Restored to canonical Yusuf Ali wording: *"Bring me blocks of iron... Then, when he had made it as fire, he said: Bring me, that I may pour over it, molten lead."* Source line updated with translator.
- Nulls left where the canon records no speech ✓.

**Campa voice.** All present-tense, reverent; the great episodes (Farhad at Behistun, Majnun in Najd / fana, the seven domes, the Land of Darkness) are vivid, not flat. **FIXED — word count:** "Layla's grave" ran 111 words (one over the 110 cap); trimmed one word to 110. All 26 campas now 60–110.

**Stop count.** 26 stops sits inside the 25–40 target; the canon is fully represented (life + all five treasures + tomb). No stops added.

Re-validated with Python after edits: parses clean, 26/7/19, all word counts in range. Three in-place repairs total (mausoleum coordinate, Quran 18:95–96 wording, one campa word count).
