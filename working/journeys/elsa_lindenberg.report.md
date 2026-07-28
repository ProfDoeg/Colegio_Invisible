# Elsa Lindenberg — report

**Dataset:** `elsa_lindenberg.journey.json` — 7 segments, 44 stops, 3 quotes, 1906–1990, gregorian.

## Sources
The spine is Courtenay Young's extended paper *On Elsa Lindenberg and Reich* (courtenay-young.co.uk, pulled in full via pdf_text.py), which synthesizes Sharaf's *Fury on Earth* (built on his 1977 Oslo interviews with Elsa), Boadella, Ollendorf's biography, Reich's *Beyond Psychology: Letters & Journals 1934–1939*, and — crucially — the Berit Heir Bunkan addendum containing the swan-dance memory, the Miriam Goldberg scene, and Elsa's last interview at Lovisenberg (1990). Supplemented by German Wikipedia (the 21 April 1933 Berufsbeamtentum dismissal, Arbeiderteatret 1935–39, the 1944 wanted list, death 6 Nov 1990), Karina & Kant *Hitler's Dancers* (training chronology, Ida Korsvold's account of the war years and rehabilitation), Spartacus Educational (the glue-pot quote), and the Geddes memoir via Woods.

## Judgment calls
- **The curator's steiner.journey.json pointer resolves to a homonym**: the only Lindenberg there is Christoph Lindenberg, Steiner's chronicler, cited in sources. No Elsa in that file; her real siblings in the atlas are reich, laban and delsarte.
- **Städtische Oper, not Staatsoper** (Karina & Kant and de.wiki beat Young's slip); Laban was at the *other* house, which I kept as a resonance, not a claim.
- **Departure date of Reich's ship**: Young says 21 Aug; I used **19 Aug 1939** to stay byte-consistent with `reich.journey.json`'s "Oslo harbor — the last ship out."
- **The 1935 abortion**: Sharaf (from Elsa) and Reich's letters conflict; per the healing model I narrated Elsa's canon (Sharaf/Edith Jacobson version) and let the campa say the canon leaves the wound "unhealed and unexplained."
- **Vienna**: Spartacus says she joined Reich in Vienna; Sharaf/Young are explicit she refused the ménage and joined him in Copenhagen — I followed the stronger canon.
- Year-only dates (birth, war-underground, Sweden, postwar stops) carry mid-year placeholders marked `inferred`; the flight-to-Sweden crossing point (Østfold border) and her studio/flat coordinates are typological Oslo sites, marked accordingly.

## Gaps / time-folds
Birth date and district unknown (Wikidata gives only 1906); her Norwegian husband of convenience is nameless in all sources; the 1945–47 persecution-to-rehabilitation dates are vague; the Goldberg confrontation is undatable ("some years later" than the fifties — placed 1968). The deepest gap is structural: **her papers are sealed** — Ida Korsvold inherited them and permits no access — so the canon of her life is written almost entirely in other people's letters. The dataset says so in the final stop.

## Five richest episodes
1. **The glue-pot nights** (Berlin 1932) — her own voice: "I got to know Willie Reich when I used to walk around Berlin at night with a pot of glue and anti-Hitler posters."
2. **The camping idyll to Lucerne** (Aug 1934) — Eva Reich's honeysuckle memory: the exile family that could not exist, existing for one summer, held together by the dancer.
3. **The hardest no** (1938) — the blackened eye, the refuge with a friend, and "It was the hardest 'no' I ever had to say."
4. **The chair and the swan** (1950s) — hip broken, teaching from a chair, she rises once and dances; "the grey duckling became a beautiful swan" and the physiotherapists wept.
5. **Lovisenberg, summer 1990** — eyes sparkling at "Willy," and the final correction: it was not the therapy that kept her from America.

## Connections in the atlas
Tightest interlock in the corpus so far: she shares six datable coordinates with **reich.journey.json** (Berlin 1932–33, Copenhagen, Malmö, Lucerne, Oslo/Drammensveien, the 19 Aug 1939 harbor) — the same harbor stop seen from the quay instead of the deck. Through Hertha Feist she is a direct Laban pupil, tying to **laban.journey.json** (whose Dartington/Jooss thread she physically walks in summer 1936, and whose Staatsoper Berlin she mirrors from the Städtische Oper). Behind both stands **delsarte.journey.json**, the grandfather of the expression-body canon. She is also the corpus's clearest case of the *refuser* — the traveler whose defining act is the journey **not** taken: the ship she does not board is her Rubicon, inverting Goethe's whole genre.

## Verification pass — 2026-07-12

**Validator.** `json_check.py` OK before and after repair: 7 segments, 44 stops, 3 quoted; no WARNs. Top-level and per-stop key set compared against `joan_of_arc.journey.json` — identical schema (traveler/title/years/calendar/register/segments; name/lat/lng/date/date_confidence/campa/quote/quote_source/suggested_refs/sources).

**Chronology.** All dates ascend within and across segments (1906 → 1990-11-06). Traveler deceased; journey correctly ends at her death, not the present. Confidences honest: attested reserved for documented events (21 Apr 1933 expulsion, Lucerne congress, 4 Aug 1939 journal, 19 Aug 1939 sailing, 9 Apr 1940 occupation, 1977 Sharaf interview, 1990 Lovisenberg interview and death); inferred/traditional used where the canon is approximate.

**Coordinates.** 16 stops spot-checked (web + gazetteer): Reichstag, Deutsche Oper/Bismarckstraße, Künstlerkolonie (Ludwig-Barnay-Platz), Stettiner Bahnhof, Copenhagen, Malmö, Sletten, Lucerne (city + lake camp), Dartington, Drammensveien 110h, Arbeidersamfundet, Karl Johans gate, Oslo harbor, Østfold border, Stockholm, Lovisenberg. Two repairs:
- **Dartington Hall** 50.448,-3.705 → **50.4515,-3.6942** (Wikipedia 50.4518,-3.6938; now matches `laban.journey.json`'s "Dartington Hall — the refuge" sibling pin).
- **Reichstag fire date** 1933-02-28 → **1933-02-27** (the fire was the night of 27 February; the campa already said "the twenty-seventh").
Drammensveien 110h kept at 59.9132,10.7034: norgeguide pins 59.9195,10.6931, but that is the *modern* no. 110 — the 2006 Henrik Ibsens gate renaming shifted numbering, and the historic 1930s no. 110 sits in the Skarpsno stretch the file already uses. Oslo-harbor stop confirmed byte-identical in coords/date with `reich.journey.json` (59.905, 10.735, 1939-08-19) — the deliberate atlas-sibling match holds.

**Quotes.** All 3 verified verbatim against canon: (1) glue-pot recollection — exact at Spartacus Educational; (2) "It was the hardest 'no' I ever had to say" — exact, Sharaf p. 254 as quoted in Courtenay Young's article (PDF re-pulled); (3) the Lovisenberg last word — exact, Berit Bunkan addendum to Young. No paraphrase drift found.

**Campa & register.** All stops 60–110 words, present tense, in the national-mythology register; the great episodes (the meeting with Annie, the hardest no, the swan from the chair, the sealed papers) carry their full weight. Canon fidelity preserved — the wound of 1935 stands "unhealed and unexplained" as the canon leaves it; the sealed-archive silence is narrated, not resolved.

**Count.** 44 stops, within the 30–45 target; no additions needed.

**Verdict.** Dataset sound. Two repairs applied in place (Dartington coordinates, Reichstag date); re-validated clean.
