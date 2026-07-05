# Zoroaster — the traditional life, c. 628–551 BC

**File:** `zoroaster.journey.json` — 7 segments, 32 stops, 15 quotes, calendar `julian_bce`, register "national mythology — the canon is true." All stops marked `traditional`: nothing in this life is *attested* in the modern sense — the register itself narrates the miraculous as fact, and the dating is the priestly reckoning, not the historian's.

## Sources
The spine is **Denkard Book VII**, the Pahlavi "life of Zarathustra," which preserves the lost Avestan Spand Nask — the nativity, the laugh, the five infant-perils, the vision on the Daiti, the seven conferences, the temptation of Ahriman, the coming to Vishtaspa. For the court miracle and the wars I leaned on the **Zardusht-nama**, **Shahnameh** (Firdausi), and the **Ayadgar i Zareran**. The doctrine and the quotes come from the **Gathas** (Yasna 28–34, 43–46, 53) — the prophet's own hymns, the only words the canon actually puts in his mouth. Encyclopaedia Iranica ("Zoroaster iv, In the Pahlavi Books"; "iii, In the Avesta"; "vii, As Perceived by Later Zoroastrians"; "Miracles i") gave the scholarly frame; Ramiyar Karanjia's priest's-eye life-story gave the traditional chronology by age (birth → 7 → 15 → 20 → 30 → 40 → 42 → 77). Gatha text: Mills (SBE 31), Insler 1975, Boyce; verified verbatim against avesta.org / mehrmazdayasnan / livius.

## Judgment calls
- **East, not west.** I set the homeland, vision and death in **Airyanem Vaejah near Balkh/Bactria** (modern scholarship's eastern Iran), and gave the **northwestern tradition** (Lake Urmia, Atropatene, Mount Sabalan, Ragha) its own stop rather than burying it — the two cradles are a genuine fold in the tradition, so I named both.
- **Dating.** The "258 years before Alexander" reckoning yields the classical c. 628–551 BC / 77-year span. I hung the internal ages off a birth at 628 BC and let the traditional age-markers set each date; BCE dates encode more-negative = earlier.
- **Quotes.** Gatha verses are used where the *theme* the stop dramatizes is what the verse actually says (43.5 recognition, 44.3–4 the cosmological questions, 30.3 the two Spirits, 28.1 the outstretched hands, 30.9 the world-renewal). The Fravarane creed ("not even if my bones be broken") is the liturgical profession, flagged as such. Where the canon records no words, `quote` is `null` — the whole nativity and the horse-miracle are narrated but unquoted, because the texts describe rather than speak them.

## Folds and gaps the tradition itself leaves
The infant-perils vary in order and number across sources (fire/wolves/oxen/horses; sometimes a river). The assassin's name is unstable — Bradres / Brātrōkrēš / Turbaratus — and the death is variously murder-at-the-altar or peaceful old age; I took the dominant altar-murder and folded the name back to the same *kind* of karapan who attacked him at birth, closing the arc. Zoroaster's wives/children are given both literally and allegorically in the texts; I kept the literal household. The Saoshyant-from-the-lake and the three ages are late/eschatological but canonical.

## The five richest episodes
1. **The laughing birth** — the only child ever to laugh at birth (even Pliny records it), the aura of light, the demons fleeing.
2. **The five infant-perils** — fire that becomes a bed of roses, the guardian oxen and stallion, the she-wolf's stopped jaws.
3. **The vision on the Daiti** — dawn, the haoma-water, Vohu Manah nine times a man's height leading his soul to Ahura Mazda; the two Spirits declared.
4. **The black horse of Vishtaspa** — four legs drawn into the belly, restored one by one as the king grants the four requests; the court kneels.
5. **The death at the fire-altar** — struck from behind at seventy-seven, hurling his rosary at the murderer who dies of it.

## Connection to the atlas
Zoroaster is the atlas's oldest **dual-cosmos** journey. His war of **Asha against Druj**, Light against the Lie, and his **Chinvat Bridge** of judgment stand directly opposite the **Dantean** cosmos (the sibling *jesus* / medieval-Christian afterlife architecture) — the same moral topography, differently mapped. His **fire-faith** is the ancient headwater of **Itten's Mazdaznan** (the Bauhaus esoteric strand), so this journey is the deep root beneath the modern theosophical figures (Gurdjieff, Keyserling, Jung, the esoteric moderns) already in the directory. Among the atlas's prophet-lives (Abraham, Jesus), Zoroaster gives the earliest full instance of the pattern the others repeat: miraculous nativity, wilderness vision, one convert, a king converted by a sign, a martyr's death, and a Saviour promised of the prophet's own seed.

---

## Verification (2026-07-05)

Structure/canon-fidelity pass. Register preserved throughout — theophanies, the laugh at birth, the five infant-perils, the vision on the Daiti, the black-horse miracle, the four wonders, the Saoshyant-from-the-lake, and the altar-death all STAND. Nothing debunked; mythic folds carried by `date_confidence`, not removed.

- **Schema.** `python json.load` passes. Top-level keys and per-stop key shape (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) are byte-identical to the sibling `joan_of_arc.journey.json`. 7 segments / 32 stops / 15 quotes.
- **Campa length.** All 32 campas fall in 90–110 words — inside the 60–110 target, none flat; the great episodes (laughing birth, infant-perils, Daiti vision, black horse, altar-death) all run near the top of the band.
- **Confidence.** All 32 `traditional`, which is honest: nothing in this life is *attested* in the modern sense and the register narrates the miracle as fact. Not a living person — the journey correctly ends with the death at the fire-altar (age 77), not the present.
- **Dates.** Numeric-BCE ordering (more-negative = earlier) verified. **Fixed one out-of-order stop:** "The seven regions / Nowruz" opened segment 7 at `-0583-03-21`, which fell *before* the preceding "Marriage to Hvovi" (`-0583-06-01`). Re-dated to the following equinox `-0582-03-21` — keeps the Nowruz/vernal-equinox framing, sits after the marriage and before the first war with Arjasp (`-0582-05-01`). Sequence now strictly monotonic across all 32 stops.
- **Coordinates** (web spot-check, 10+ distinct points). Balkh/Bactra cluster (36.75–36.76 N, 66.89–66.90 E) confirmed against Balkh at 36.756 N, 66.897 E — the whole Airyanem-Vaejah/Daiti/court/altar spine sits correctly on the ancient city. Mount Sabalan (dataset 38.301, 47.823) sits within a few km of the Savalan massif (~38.25, 47.92) — acceptable for a summit site. Mount Revand / Adur Burzen-Mihr (36.213, 57.681) sits correctly in the Rivand district by Sabzevar/Nishapur. Lake Kansaoya (31.005, 61.503) falls squarely inside the Hamun-e Helmand / Sistan lake system (30.77–31.43 N, 61.28–61.67 E). No coordinate off.
- **Quotes** (6 spot-checked against the canon). Y30.3 (two Spirits/Twins), Y46.1 (Insler, "to what land to flee"), Y28.1 (Insler, "hands outstretched"), Y43.5 (Mills, "birth of Life") all verified verbatim. **Fixed two quotes:** the two short Y43.5 instances (nativity stop, death stop) read "I *conceived* thee… *beheld thee first*," a paraphrase; restored to the canonical Mills wording "As the holy one I *recognize* thee, Mazda Ahura, when I *saw thee in the beginning* at the birth of Life," and tagged `(Mills)` to match the fuller Y43.5 already used verbatim at the seven-conferences stop.

**Result:** re-validated with `python` — parses, 32 stops, strictly chronological, 15 quotes. Repairs made in place: one date, two quote restorations. No stops added (32 is within the 30–45 target; the canon's remaining material is variant, not additional).
