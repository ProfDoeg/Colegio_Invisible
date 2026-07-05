# Gurdjieff journey — research report

**Dataset:** `gurdjieff.journey.json` — 8 segments, 62 stops, 1866–1949, gregorian.
**Register:** national mythology; *Meetings with Remarkable Men*, *Beelzebub's Tales*, *The Herald of Coming Good*, *Life Is Real Only Then, When 'I Am'*, and Ouspensky's *In Search of the Miraculous* treated as true canon.

## Sources
Primary canon: MwRM (father/Borsh/Gilgamesh/Yezidi/Pogossian/Ani/Sarmoung/Soloviev chapters, "The Material Question"); ISOTM (1915 meeting, Petersburg talks, Finland telepathy, Essentuki, Constantinople); Beelzebub ch. I (grandmother); Herald (1911 oath); Life Is Real (the three bullets: Crete 1896, Tibet 1902, Chiatura 1904). Memoir canon: de Hartmanns (escape 1917–19), Bennett *Witness* (Constantinople, 1948 crash quote, Lascaux), Hulme (the Rope, war table), Welch (the death). Web verification: gurdjieff.org, ggurdjieff.com, Wikipedia, newyorkalmanack.com — confirmed Tiflis Opera demo **22 Jun 1919**, Constantinople Jul 1920, Prieuré **1 Oct 1922**, Mansfield **9 Jan 1923**, Théâtre des Champs-Élysées **13 Dec 1923**, Carnegie Hall **3 Mar 1924**, crash **8 Jul 1924** (not Jul 5), death **29 Oct 1949**.

## Judgment calls
- **Birth date** kept at the followers' traditional 13 Jan 1866 (`traditional`); the 1877 passport is noted in the campa as part of the canon's own fog.
- **Month-precision convention:** where canon gives only a season/year, date is first-of-month with confidence `traditional` (canon names the period) or `inferred` (my sequencing). `attested` reserved for day-exact events (9 of them).
- **Sarmoung coordinates** (38.5, 70.3, upper Pyanj/Hisar) are deliberately approximate — the canon's whole point is that no map bears the name; campa says so.
- **Pre-sand Egypt map** placed at the Armenian priest's house on the Mesopotamia road (per MwRM) rather than the prompt's "bazaar"; Bitlis coords are a stand-in for the unnamed town.
- **1948 Montargis crash**: day not reliably attested anywhere I could verify; left at 1948-08-01 `traditional`.
- **Quotes** (14): only canon-recorded words; near-verbatim renderings flagged by honest `quote_source` ("as remembered," "as recorded"). Deathbed "Vous voilà dans de beaux draps" included as pupil-remembered. Rope/Mevlevi/Mansfield quotes withheld — I couldn't pin verbatim text.

## Gaps in the canon
The 1885–1911 chronology is fog by design — Gurdjieff gives almost no dates in MwRM; sequence follows the book's internal order anchored to the three dated bullets. The Lhasa years are legend (Moore calls the "Tibetan agent" identification doubtful) — kept, per register, as `traditional`. The exact 1918 mountain route Maikop→Sochi is reconstructed from de Hartmann. The last Movements class date is inferred (days before hospitalization). Burial date (3 Nov 1949) is secondary-source traditional.

## Five richest episodes
1. **The Sarmoung Monastery** — blindfolded twelve days; dances read as books via the ivory-peg apparatus; direct resonance with our dance-quipu corpus.
2. **Gilgamesh by the hearth at Kars** — the ashokh father sings the Flood; decades later the Nineveh tablets confirm the unwritten transmission. The whole project's thesis in one scene.
3. **The escape through two armies** (Essentuki→Maikop→the passes→Sochi, 1918) — papers from both powers, silk and manuscripts on pack-horses, no one lost.
4. **The 8 July 1924 crash** — the unexplained cushion under the unconscious man's head; the near-death that turns the dancer into the writer of Beelzebub at the Café de la Paix.
5. **The death and vigil** (Oct–Nov 1949) — "you are in a fine mess"; the doctor's testimony of a conscious death; the two menhirs at Avon a few hundred steps from the lost Prieuré.

---

## Verification pass (2026-07-05)

Independent structure-and-canon-fidelity check of `gurdjieff.journey.json`. The register ("national mythology — the canon is true") was respected throughout: nothing debunked, wonders left as events.

### Structure
- JSON parses; 8 segments, 62 stops (within the 45-65 target — no additions needed).
- All 62 stops carry the uniform field set (name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources).
- Dates strictly chronological, 1866-01-13 through 1949-11-03 (all Gregorian; no BC/Julian concerns).
- Campa voice: present tense throughout, none flat; 5 stops exceeded the 110-word cap (Sarmoung 115, Moscow café 116, Mansfield 115, 1924 crash 117, Avon vigil 117) and were trimmed surgically to 108-110 words with no loss of image. All 62 now in the 60-110 band.

### Coordinates (19 sites geocoded against OSM/Nominatim + web checks)
Confirmed within ~250 m: Sphinx, Holy Sepulchre, Kaaba, Tbilisi Opera, Galata Mevlevihanesi, Théâtre des Champs-Élysées, Carnegie Hall, Café de la Paix, Salle Pleyel, 6 rue des Colonels-Renard, Chiatura, Etchmiadzin, Ani, Hotel Wellington (871 7th Ave), Warwick Gardens (London 1922 stop), Essentuki, Gyumri, Prieuré des Basses-Loges (2 rue Bezout, Avon — address web-confirmed).

Fixed in place (5):
- American Hospital of Paris (death stop): 48.889, 2.259 → 48.8927, 2.2722 (was ~1.05 km west of the actual Bd Victor Hugo site).
- Avon cemetery (grave stop): 48.408, 2.734 → 48.4019, 2.728 (Cimetière d'Avon per OSM).
- Lascaux: 45.049, 1.170 → 45.0492, 1.1761 (cave itself).
- Bokhara reservoir: 39.775, 64.429 → 39.7736, 64.4205 (Lyab-i Hauz).
- Kars military cathedral: 40.608, 43.092 → 40.6113, 43.0915 (Kümbet Camii / Holy Apostles).

Left deliberately approximate, per the register: Sarmoung (38.5, 70.3), Gobi, the saint's tomb beyond Alexandropol, the 1916 Finland country house, the 1924 crash point on the Paris-Fontainebleau road (accounts name only the road).

### Quotes (all 14 checked; 8 verified against full canon texts)
Verified word-exact and left untouched: grandmother's injunction (Beelzebub, 'The Arousing of Thought'), Gilgamesh flood verse (MwRM 'My Father'), Sarmoung/Babylon parchment (MwRM 'Pogossian'), sacred-dances-as-laws (ISOTM ch. I, ballet conversation), Beelzebub declared aim (1950 ed. frontispiece wording), Bennett 1948 "Tonight you come dinner. I must make body work." (Witness), Study House aphorism, toast of the idiots, deathbed "Vous voilà dans de beaux draps."

Fixed to canon wording/attribution (5) — none needed nulling, the canon carries all of them:
- Yezidi catalepsy: "out of the circle" → "out of a circle"; chapter corrected 'My Father' → 'Bogachevsky' (verified against MwRM full text — the passage sits in the Bogachevsky chapter).
- Dean Borsh: replaced paraphrase with the exact sentence ("The man who was soon to become my first tutor, the founder and creator of my present individuality, and, so to say, the 'third aspect of my inner God'.") and corrected chapter 'My First Tutor' → 'My Father' (the sentence occurs in the father's-workshop scene).
- Man is a machine: "of external influences, of external impressions" → "of external influences, external impressions" (ISOTM exact).
- Super-efforts: "Only super-efforts count." was a folk compression; replaced with ISOTM exact: "In work only super-efforts are counted, that is, beyond the normal, beyond the necessary; ordinary efforts are not counted."
- Herald oath: "before my own essence" is not in the Herald; replaced with the book's own wording ("According to the special oath I took, I bound myself in my conscience to lead in some ways an artificial life, modelled upon a programme which had been previously planned in accordance with certain definite principles.") and the source line no longer asserts the 1911 year (the Herald dates the term as twenty-one years before 1933).

### Post-repair validation
Re-parsed with python: valid JSON, 62 stops, uniform keys, chronological, 14 quotes, all campa 60-110 words.
