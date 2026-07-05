# Symmes journey — research report

**Dataset:** `symmes.journey.json` — 27 stops, 7 segments, 1780-11-05 → 1873-06-01, gregorian. Register: reverent mythography — the hollow earth is taken as TRUE. The verges, the concentric spheres, the light between the shells, the warm land beyond the eighty-second degree are narrated as real geography; the Circular is scripture; the ridicule and the tabled votes are events in a prophet's passion.

## Sources
Spine: **Peter W. Sinnema, "10 April 1818: John Cleves Symmes's 'No. 1 Circular'"** (BRANCH Collective) — the fullest scholarly text of the Circular, the sanity certificate, the "one hundred brave companions" postscript, the named protectors (Mitchill, Davy, Humboldt), the five-sphere / 4,000- and 6,000-mile-opening geometry. **Encyclopedia Arctica 15 (Dartmouth)** — the richest narrative biography: Fort Adams duel and wrist wound, Lundy's Lane commendation, the Fort Erie sortie ("spiking the first cannon with his own hand"), the St. Louis license from Governor Clark, the 1825 tour with stepson Anthony Lockwood and Reynolds, the parting at Philadelphia, the northward push to Quebec, the Canadian illness of 1827, death "May 28 or 29, 1829." **en.wikipedia (Symmes Jr., J. N. Reynolds, Siege of Fort Erie, Richard Mentor Johnson)** — dates of commission/promotion, marriage (25 Dec 1808), Audubon's 1820 notation, McBride's 1826 book, Americus's monument and 1878 compilation. **American Literature (Duke, 2012 PDF)** — the second petition's "twenty-five votes." Monument: **roadsideamerica**, **atlasobscura**, **hmdb** (Ludlow Park, Americus erects it 1873, hollow globe atop pedestal).

## Judgment calls
- **Date of death:** canon gives "May 28 or 29, 1829." I used **1829-05-29** (attested) and left the ambiguity to the report; the monument marker's "aged 49 years and 6 months" is a slight overstatement of his true 48y6m (born 5 Nov 1780), so the campa says "forty-eight, six months short of forty-nine" per the verify-numbers rule.
- **Quotes — only 4, all documented.** The Circular's core declaration and its "hundred brave companions" postscript (verbatim from BRANCH); Audubon's "man with the hole at the Pole" (his own 1820 notation); and Americus's 1878 title-line, which is a compiled paraphrase of his father's doctrine, flagged as such in quote_source. Everything else is `null` — no lecture transcripts survive verbatim, so the verge-doctrine and Cincinnati stops carry no invented speech.
- **The Verges stop** is placed at a *doctrinal* coordinate (84°N, 0°) — the threshold his theory locates, not a biographical site. Marked traditional. This is the one "mythic-geography" pin, justified because the register takes the opening as real.
- **Soft dates:** the trading years (Falls of the Ohio 1816, St. Louis 1817), the lecture-circuit spread, the eastern-tour legs, and the New Jersey convalescence have no day-precise anchors; given plausible months and marked `traditional`. Hard anchors (birth, commission, Lundy's Lane, Fort Erie sortie, discharge, Circular, the 1822 Senate motion, Reynolds's 1836 Address, the 1873 monument) are `attested`.
- **Reynolds's fork:** the canon has him doubting the *hollow* earth while keeping the *polar voyage* — I render this honestly as the doctrine splitting, the disciple carrying "half of it toward triumph" (the US Exploring Expedition), without pretending the Wilkes expedition endorsed the hollow earth.

## The tradition's own time-folds / geographic splits
Two structural features shaped the itinerary. **(1) The doctrine outlives the man.** The arc does not end at the 1829 grave: the canon's own momentum runs through Reynolds's 1836 Address and the 1838 sailing, then folds forward 44 years to the 1873 monument — so the final segment leaps past the biographical death into the doctrine's stone afterlife. **(2) The Philadelphia fork.** The single lecture-tour splits into two vectors at Philadelphia (1826): the master northward to Quebec and death, the disciple toward Washington and the national expedition. I kept both as stops on one timeline rather than branching, since the register privileges the cause's continuity.

## Five richest episodes
1. **St. Louis, Circular No. 1 (10 April 1818)** — the revelation itself: 500 sheets to every prince and college on earth, a sanity certificate pinned to prophecy, the whole doctrine in one signed paragraph. The scripture-moment of the register.
2. **The Sortie from Fort Erie (17 Sept 1814)** — Symmes over the entrenchments in the rain, spiking the first British cannon with his own hand: the pure valor that gives the later "I pledge my life" its weight.
3. **The second petition — twenty-five votes (1823)** — the hollow earth within a hair of a federally funded voyage; the "Symmes Hole" spoken of on the floor of Congress. The near-miracle in the halls of government.
4. **Cincinnati and the cutaway globe (1820)** — the stammering prophet turning a wooden earth with its poles cut open before a jeering crowd, and Audubon quietly writing "the man with the hole at the Pole."
5. **The monument (1873)** — Americus raising over the grave the only monument the hollow earth will ever have: a carved globe, open at both poles, still standing in Hamilton. The doctrine the world derided, written at last in stone.

---

## Verification (2026-07-05)

**Verdict: PASS with two quote repairs applied in place. JSON re-validates.**

### 1. Structure / schema
- `python json.load` parses clean. Top-level keys and stop-level keys are an EXACT match to the sibling `joan_of_arc.journey.json` (traveler, title, years, calendar, register, segments; per-stop: name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources). No extra or missing keys.
- 7 segments, 27 stops. (Below the 25–40 nominal target only at its floor; the biographical canon is thin between hard anchors and the researcher already folds the arc past the 1829 death to 1836/1873 — no defensible additional stops without invention. 27 accepted.)

### 2. Chronology & confidence
- Dates monotonic within every segment AND globally across all 27 stops (1780-11-05 → 1873-06-01). No inversions.
- Confidences honest: the 8 hard anchors are `attested` (birth 1780-11-05, ensign 1802-03-26, Lundy's Lane 1814-07-25, Fort Erie sortie 1814-09-17, discharge 1815-06-15, Circular No. 1 1818-04-10, the 1822 Senate motion, the 1823 petition, the 1829-05-29 death, Reynolds's 1836 Address, the 1873 monument). Trading/tour/convalescence dates and the doctrinal Verges pin are `traditional`. Correct.

### 3. Coordinates (13 spot-checked against the canon-located site)
All within tolerance. Sub-kilometre: Sussex Co. NJ (Newton), New Orleans, Fort Erie, Falls of the Ohio/Louisville, St. Louis, Newport KY, Cincinnati, Washington (Capitol), Hamilton OH, Wilmington OH, Philadelphia, Quebec City. Slightly looser but acceptable for small/battlefield sites: Fort Adams MS (~1.4 km from 31.087,-91.548) and Lundy's Lane (~0.9 km from 43.089,-79.096).
- **Symmes Monument, Hamilton OH** — confirmed at 39.3953 N, 84.5616 W (Ludlow/Symmes Park, old Hamilton Pioneer Cemetery, S. Third St). JSON 39.398,-84.561 lands ~250 m away. Kept.
- **The Verges of the Pole (84 N, 0)** — doctrinal-geography pin, not a biographical site; correctly marked `traditional`. Under the "the canon is true" register this STAYS (the hollow-earth threshold narrated as real geography). Not removed.

### 4. Quotes (4 total; all checked against the canon)
- **Circular No. 1 declaration** — "…open at the poles 12 or 16 degrees…" verbatim vs BRANCH Collective / Sinnema. Correct, unchanged.
- **Circular postscript** — REPAIRED to canon wording. Was truncated and mis-punctuated ("…on the ice of the frozen sea; I engage…latitude 82."). Restored the canon's colon and the dropped closing clause: "…on the ice of the frozen sea: I engage we find a warm and rich land…on reaching one degree northward of latitude 82; we will return in the succeeding spring."
- **Audubon 1820 notation** — REPAIRED to canon's full line. Restored the dropped tail: "John, Cleeves Simms — The man with the hole at the Pole — Drawn and a good likeness it is."
- **Americus's 1878 title-line** — "The Earth is hollow, habitable within, and widely open about the poles." Correctly flagged in quote_source as a compiled/paraphrased title of the father's doctrine. Kept.

### 5. Campa voice
All 27 campas 60–110 words (min 79, max 99), present tense, reverent mythography. The great episodes are not flat: the Circular breaking on the world "in a single sheet of paper," the spiked cannon at Fort Erie, the verges where "the compass reels and the needle fails," the death "six months short of forty-nine," and the hollow globe "turning its open poles to the sky above the grave." The myth is preserved as TRUE throughout — no debunking.

### 6. Judgment calls affirmed
- Death 1829-05-29 (canon "28 or 29"): accepted.
- Age rendered "forty-eight, six months short of forty-nine" against the monument marker's overstated "49y6m": correct per verify-numbers rule.

Re-validated with `python json.load` after both edits: JSON parses, 7 segments / 27 stops / 4 quotes, zero word-count violations.
