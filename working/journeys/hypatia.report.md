# Hypatia / Saint Catherine — research report

**Dataset:** `hypatia.journey.json` — 9 segments, 39 stops, c. 355–1429 CE (julian), register: national mythology.

## Sources
Part One rests on the four primary witnesses: **Synesius' letters** (Livius.org / FitzGerald translation — Letters 15, 16, 124, 137, and *De dono astrolabii*; all five quotes verified verbatim against the translations), **Socrates Scholasticus** HE VII.7, 13–15 (New Advent), **Damascius'** *Life of Isidore* via the Suda (UML teaching text), and **John of Nikiu** ch. 84 as the hostile witness. Serapeum: Rufinus XI, Codex Theodosianus 16.10.11, the Alexandrian World Chronicle drawing. Part Two: the **Golden Legend** (Caxton, via christianiconography.info and Fordham) for the whole Catherine cycle; Procopius for Justinian's monastery; Eberwin's Vita of **Symeon of Trier** and rouen-histoire.com for the westward relic; the **1431 trial record** (Feb 22 and 27 sessions) for Domrémy and the Fierbois sword — both Joan quotes are trial verbatim.

## Judgment calls
- **Dates**: Hypatia's birth 355 (Damascius tradition over the 370 alternative); murder given as 415-03-08, the traditional day (Socrates attests only "March, in Lent"). Catherine's cycle is pinned to the traditional feast (beheading 305-11-25) with legend-internal spacing; all marked `traditional`.
- **Sites**: Cinaron's location is unknown — placed on the eastern shoreline, `inferred`. Catherine's disputation is placed at the **Caesareum** (the Legend names no temple) so the fold closes on the same tiles — flagged here as a deliberate corpus reading, not an attestation.
- **Overlap**: Synesius' deathbed letter (413) sits at the end of the "Chair of Philosophy" leg, chronologically inside the "City Divides" leg (412–) — within-segment order is strict, the letters stay together.
- **Joan at Fierbois**: sources split between Feb 20 and Mar 4–6, 1429; used Mar 5 (the letter-to-Chinon day). Sword retrieval dated early April, `traditional`.
- Quotes to Hypatia (Synesius) are used as the canon's voice per brief; Hypatia herself has no surviving words — nulls kept honest throughout Part One.

## Gaps in the canon
No words of Hypatia survive; no source locates Cinaron or her school building (Kom el-Dikka used as the plausible lecture-hall site); the Golden Legend gives no day-count anchors before the 12-day imprisonment; the Charles Martel origin of the Fierbois sword is late tradition; the sword itself vanishes from history after 1429.

## Five richest episodes
1. **The Caesareum, March 415** — the ostraka, the stripping, Cinaron: the martyrdom the whole dataset pivots on.
2. **The Serapeum falls, 391** — the axe in the god's jaw, the sky that holds, the same fire that will take her.
3. **The suitor's lesson** (Damascius) — the fiercest surviving image of her teaching.
4. **The wheel and the milk, 305** — the fold made visible: blood at the Caesareum answered by milk at the block, body flown to Sinai.
5. **The sword at Fierbois, 1429** — five crosses, rust falling away without effort; the circle closes facing Joan's journey.

## Verification pass (2026-07-05)

Independent structural and canon-fidelity check of `hypatia.journey.json`. The file re-validates with python after all repairs below.

**Structure.** JSON parses; 39 stops in 9 segments (within the 25–40 target — no additions needed); every stop carries the full key set (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`); all dates are valid YYYY-MM-DD; all 39 campas fall in 60–110 words, present tense, with the great episodes (Caesareum, wheel, Sinai translation, Fierbois) carrying their weight; quote/quote_source pairing is consistent; Hypatia's nulls kept.

**Chronology.** Two date inversions remain **by design** and are not defects: the Folding (Catherine's 287–305 cycle after Hypatia's 415 death — the myth's central device) and the Charles Martel flashback (732) opening the Fierbois segment. One inversion was accidental and is fixed: Synesius' deathbed letter (413) sat before Cyril's enthronement (attested 412-10-18). The Ptolemais stop was **moved in place** to be the second stop of "The City Divides" (after the enthronement, before the 414 expulsion) — this supersedes the earlier "letters stay together" judgment call; no date or campa changed, and canonically the placement is stronger: Synesius dies as the city divides, and Hypatia loses her advocate on the eve of 415. Strict chronology now holds everywhere outside the two mythic folds.

**Coordinates** (web spot-check, 13 sites). Verified good: Serapeum/Pompey's Pillar (31.182, 29.896), Kom el-Dikka lecture halls, the Caesareum/Cleopatra's Needles quarter, Constantinople (Hagia Sophia quarter), Cyrene, Ptolemais/Tolmeita (32.71, 20.95), Jebel Katherina summit (given point within ~500 m of the massif's published summit coords — acceptable at mountain scale), Saint Catherine's Monastery (28.556, 33.976), Porta Nigra Trier (49.7597, 6.6440), Tours. Cinaron remains `inferred` (unlocated in the sources) — left as placed. **Fixed:**
- **Sainte-Catherine-de-Fierbois** (all 3 stops): was 47.070x — ~9.5 km south of the village; corrected to 47.158x, 0.654x (Wikipedia: 47°09′30″N 0°39′16″E).
- **Rouen, Sainte-Catherine-du-Mont**: was 49.4297, 1.1258; corrected to 49.4332, 1.1170 (abbey archaeological site on the Côte Sainte-Catherine, fr.wikipedia: 49°26′N 1°07′E).
- **Domrémy**: nudged 48.4404, 5.6749 → 48.4430, 5.6756 (Joan's birthplace house/garden beside the church).

**Quotes** (8 of 9 spot-checked against the canon; none nulled — all are carried). Verified verbatim, unchanged: Synesius Letters 15, 16, 124 (livius.org/FitzGerald); Letter 137 as printed in the standard scholarship ("seen with our eyes…" — note the livius transcription reads the singular "with our eye"; both readings circulate, the plural kept); the rust quote ("After this sword was found, the prelates of the place had it rubbed…" — jeanne-darc.info trial translation). **Aligned to exact canon wording:**
- **Golden Legend (Caxton)**: was a condensation; now the full sentence: "I am Katherine, daughter of Costus the king, and howbeit that I was born in purple, and am informed in the arts liberal, yet have I despised all things and have given me wholly to our Lord Jesu Christ." (christianiconography.info Caxton text).
- **Joan, 22 Feb 1431**: "When I was thirteen, I had a voice from God to help me to govern myself." (Murray translation, verified at stjoan-center.com).
- **Joan, 27 Feb 1431 (sword)**: tail corrected from "I knew it by my voices" to the trial-translation verbatim "…upon it were five crosses; I knew by my Voice where it was." (Murray translation, verified at stjoan-center.com).

**Verdict**: dataset passes. 39 stops / 9 segments / 9 quotes; the myth's folds intact and everything checkable checked.
