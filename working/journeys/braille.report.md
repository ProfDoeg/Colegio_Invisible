# Louis Braille — journey report

**Traveler:** Louis Braille (1809–1852) · **Title:** *The Fingers That Read: Coupvray to the Panthéon*
**Calendar:** gregorian · **31 stops in 7 segments** · span 1809–1952 (life to pantheonization) · 2 attested quotes

## Sources
Canon here = the biographies, the school records, and the letters. Primary anchors drawn from:
- **Wikipedia, "Louis Braille"** — the fullest cited chronology (dates, professorship, publications, deathbed).
- **American Foundation for the Blind, "Life and Legacy of Louis Braille"** (afb.org) — the Coupvray childhood, the workshop accident, the village education (Abbé Palluy, schoolmaster Antoine Bécheret), and the recognition/burning narrative.
- **Musée Louis Braille, Coupvray** (museelouisbraille.com) — the physical sites: birth house (13 rue Louis Braille), Saint-Pierre baptism, the cemetery grave, the hands-relic urn and its inscription, the Panthéon transfer.
- **napoleon.org & Wikipedia "Night writing"** — Charles Barbier de la Serre, the *écriture nocturne* / sonography, the twelve-dot military cipher.
- **National Geographic; History Today; NIH/PMC "The Invention of Braille"** — the Dufau suppression and courtyard book-burning; the death.
- **IMSLP** — the 1829 *Procédé* title and printing history.

## Judgment calls
- **The awl accident (1812) and the crossing to total blindness (by ~1814)** are dated *traditional* — biographies agree he was ~3 at the accident and blind by 5, but no day/month is recorded. Coordinates put both at the birth-house workshop.
- **The Coupvray inventing-summers (1822)** are *traditional*: the image of the boy punching dots at his father's bench with the very awl-type tool is canonical in the literature and thematically load-bearing (the instrument of the wound = the instrument of the gift), but not documented to a specific summer.
- **Professorship stop** was re-dated to **1828** (répétiteur) rather than 1833 (full professor) so the segment stays chronological ahead of the 1829 publication; both dates are named in the text.
- **Saint-Vincent-de-Paul organ (1840)** is *traditional* — sources confirm Saint-Nicolas-des-Champs (1834–39, attested) firmly; the later posts "at churches all over Paris/France" are looser, so the date is a placed inference.
- **The burning (1842)** is *traditional*: sources vary between 1840 and 1842 for the bonfire; I placed it 1842, between Dufau's arrival (1840, attested) and the 1844 inauguration reversal (attested).
- The final "cell facing the knots" stop is a deliberate *inferred* coda binding braille to Barbier's cipher, Labanotation, and the quipu — the commissioning frame's own comparison, placed at the Panthéon crypt.

## Time-folds / geographic split
The signature structure is the **geographic split of the body itself**: at the 1952 centenary Coupvray kept his *hands* (sealed in an urn, its inscription quoted) while the rest went to the Panthéon — so the itinerary's final two stops occupy two places at once, and the traveler ends physically divided as a relic. A gentler fold: the arc **returns to the same coordinates repeatedly** (the birth-house workshop is the site of birth, wound, blindness, and the inventing-summers), making Coupvray both origin and, via the hands, terminus.

## The five richest episodes
1. **The awl that slips** — the three-year-old in the leather workshop; the tool that blinds him is the tool he will later use to punch the alphabet. The origin-wound.
2. **Barbier's cipher arrives (1821)** — the soldiers' twelve-dot night-writing hits the twelve-year-old "like a thunderclap"; the door he'd been feeling for opens.
3. **The six-dot cell complete (1824)** — at fifteen he folds twelve dots to six, the cell the fingertip reads at a single touch; the invention entire, never changed again.
4. **The burning (1842) and the students' revolt** — Dufau's courtyard bonfire of every book in the code; the pupils keep writing it in secret with knitting needles and forks — the corpus's oldest story of a true thing set alight and surviving.
5. **The Panthéon procession (1952)** — the coffin followed through Paris by hundreds of the blind tapping canes; Helen Keller's Sorbonne address; the hands kept back at Coupvray.

## Quotes captured
- **"I am convinced my mission on earth is accomplished."** — to Hippolyte Coltat, Dec. 1851 (deathbed, after the sacraments).
- **"The commune of Coupvray devoutly preserves in this urn the hands of the genius inventor."** — inscription on the reliquary urn, 1952.
All other campa passages leave `quote: null` (honest — the record does not preserve his words at those moments).

## Verification (2026-07-05)

Structural and canon-fidelity pass. Verdict: **PASS with 5 coordinate repairs applied in place.**

**Structure.** JSON parses. Top-level keys and per-stop keys match the sibling schema (`joan_of_arc.journey.json`) exactly — no extra or missing fields. 7 segments, 31 stops (above the 25–40 target; no additions needed). Every `campa` is 60–110 words (measured range 88–110), present-and-narrative voice, reverent register; the origin-wound (the slipping awl), Barbier's cipher "like a thunderclap," the six-dot cell at fifteen, the courtyard burning, and the divided-relic Panthéon coda all land with force. Dates are chronological within every segment (verified by string sort, which is safe for gregorian ISO dates). Note: the `years` field "1809–1852" is Braille's lifespan; stops legitimately run to 1952 (pantheonization), matching the sibling file's lifespan-of-events convention.

**Confidences** are honest: real anchors (birth 1809-01-04, baptism, departure 1819, Barbier 1821, six-dot cell 1824, professorship, 1829 *Procédé*, Saint-Nicolas-des-Champs, raphigraphe 1839, Dufau 1840, 1844 inauguration, the 1851 sacraments, death, burial, 1854 adoption, 1887 monument, 1952 exhumation/Panthéon) are `attested`; the undated childhood events (awl ~1812, blindness ~1814, school 1816, inventing-summers 1822), the Saint-Vincent-de-Paul organ, and the burning (1842, sources vary 1840–42) are `traditional`; the library, music room, Barbier's flaw, and the quipu coda are `inferred`. Consistent with the canon.

**Coordinates** web-spot-checked at 10+ stops against actual/traditional sites:
- Panthéon crypt — JSON 48.8462/2.3464 vs actual 48.8462/2.3461 — **exact**.
- Grave / exhumation, Coupvray cemetery — JSON 48.89455/2.79208 vs actual 48°53.673′N 2°47.525′E (48.8946/2.7921) — **exact**.
- Séminaire Saint-Firmin, ex-rue Saint-Victor (now rue des Écoles, 5e) — JSON 48.8489/2.3499 — **good** (~rue des Écoles).
- Boulevard des Invalides Institute (56 bd des Invalides, 75007) — JSON 48.8515/2.314 — **good**.
- Saint-Nicolas-des-Champs — JSON 48.8646/2.353 vs actual 48.8655/2.3543 — **good** (~130 m).
- Reliquary urn inscription verified (see quotes) at the Coupvray tomb.
- **FIXED — Saint-Vincent-de-Paul** was 48.8797/2.352, ~650 m north of the church at Place Franz Liszt (10e); corrected to **48.8740/2.3512**.
- **FIXED — birth-house workshop cluster** (birth, awl accident, blindness, 1822 inventing-summers) was 48.8952/2.7913, ~80 m north of the true *Maison natale*; corrected all four stops to the authoritative **48.8945/2.792** (Fr. Wikipedia / Monumentum: 48°53′40″N 2°47′31″E), which now agrees with the file's own (correct) grave coordinate a short walk away.
- Reviewed but **left as-is**: the 1878 "world after" stop is anchored at London (51.5074/-0.1278) rather than the Paris venue of the 1878 international congress. This is a deliberate diffusion node — Armitage's own city / RNIB, the Anglophone spread — and the campa does not claim the congress met in London, so it is not a canon violation. Kept.

**Quotes** — only 2 in the file, both attested and both verified:
- Deathbed, to Hippolyte Coltat, Dec. 1851 — "I am convinced my mission on earth is accomplished." Confirmed (the biographies also carry the tense variant "…has been accomplished"; the sense, speaker, and date are identical — left in the file's chosen wording).
- Reliquary urn, Coupvray, 1952 — "The commune of Coupvray devoutly preserves in this urn the hands of the genius inventor." Confirmed **verbatim** against the Musée Louis Braille text.
All other `quote` fields are `null` — honest; the canon does not record his words at those moments.

Re-validated with python after the 5 coordinate edits: JSON parses, 31 stops intact.
